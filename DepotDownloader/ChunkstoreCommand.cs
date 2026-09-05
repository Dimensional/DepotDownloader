// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace DepotDownloader
{
    /// <summary>
    /// Chunkstore command handler for all chunkstore-related operations
    /// </summary>
    public static class ChunkstoreCommand
    {
        /// <summary>
        /// Default per-CSD-file size cap: comfortably under FAT32's 4 GiB single-file limit
        /// while still large enough that a big depot doesn't fragment into hundreds of files.
        /// </summary>
        private const long DefaultMaxFileSize = 2L * 1024 * 1024 * 1024; // 2 GiB

        /// <summary>
        /// Smallest -max-file-size a user can request. Steam chunks are always capped around
        /// 1 MiB before compression/encryption, so there's no technical floor this protects
        /// against (even a much smaller cap would still hold plenty of chunks per file) - this
        /// is purely a sanity minimum matching Steam's own 1 GiB backup-piece convention, which
        /// Steam clients can read fine well above anyway. There's no upper bound: a user can set
        /// this arbitrarily large to get a single monolithic file.
        /// </summary>
        private const long MinMaxFileSize = 1L * 1024 * 1024 * 1024; // 1 GiB

        private static bool TryValidateMaxFileSize(long maxFileSize, out string error)
        {
            if (maxFileSize < MinMaxFileSize)
            {
                error = $"Error: -max-file-size must be at least 1 GiB ({MinMaxFileSize:N0} bytes) - got {maxFileSize:N0}.";
                return false;
            }

            error = null;
            return true;
        }

        /// <summary>
        /// Parses the option set shared by pack/rebuild/update (-depot/-max-file-size/-threads/
        /// -batch-size/-checkpoint-interval) and validates -max-file-size. Callers are free to
        /// parse their own extra flags before or after this call (ArgParser lookups aren't
        /// order-sensitive) and must still call parser.WarnUnconsumed() themselves once all of
        /// their own parsing - shared and command-specific - is done.
        /// </summary>
        private static bool TryParseCommonChunkOptions(
            ArgParser parser,
            out (uint? DepotId, long MaxFileSize, int MaxParallelism, int BatchSize, int CheckpointInterval) options,
            out string error)
        {
            options = (
                parser.GetNullable<uint>("-depot", "-d"),
                parser.Get(DefaultMaxFileSize, "-max-file-size"),
                parser.Get(0, "-threads"),
                parser.Get(1000, "-batch-size"),
                parser.Get(5000, "-checkpoint-interval"));

            return TryValidateMaxFileSize(options.MaxFileSize, out error);
        }

        /// <summary>
        /// Splits files under a folder into those whose name matches the given chunk-naming
        /// convention (encrypted "&lt;sha&gt;" or decrypted "&lt;sha&gt;_decrypted") for
        /// <paramref name="isEncrypted"/>, and everything else that matches the *opposite*
        /// convention instead (i.e. wrong-mode chunk files sitting in the same folder) - shared
        /// by pack's mixed-input guard and update's mismatched-mode guard.
        /// </summary>
        private static (List<string> Matching, List<string> Mismatched) PartitionChunkFilesByMode(IEnumerable<string> allFiles, bool isEncrypted)
        {
            var matching = new List<string>();
            var mismatched = new List<string>();

            foreach (var file in allFiles)
            {
                var name = Path.GetFileName(file);
                if (Chunkstore.TryGetChunkSha(name, isEncrypted, out _))
                {
                    matching.Add(file);
                }
                else if (Chunkstore.TryGetChunkSha(name, !isEncrypted, out _))
                {
                    mismatched.Add(file);
                }
            }

            return (matching, mismatched);
        }

        /// <summary>
        /// Run chunkstore command with sub-command syntax
        /// </summary>
        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            var operation = args[0].ToLowerInvariant();

            try
            {
                switch (operation)
                {
                    case "pack":
                        return await PackCommand(args[1..]);

                    case "unpack":
                        return await UnpackCommand(args[1..]);

                    case "verify":
                        return await VerifyCommand(args[1..]);

                    case "rebuild":
                        return await RebuildCommand(args[1..]);

                    case "update":
                        return await UpdateCommand(args[1..]);

                    case "stats":
                        return await StatsCommand(args[1..]);

                    default:
                        Console.WriteLine($"Unknown chunkstore operation: {operation}");
                        Console.WriteLine("Available operations: pack, unpack, verify, rebuild, update, stats");
                        Console.WriteLine("Use 'depotdownloader help chunkstore' for detailed usage.");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> PackCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore pack <input-chunks-folder> <output-chunkstore-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot <id>              Depot ID (required for new chunkstore)");
                Console.WriteLine("  -encrypted               Mark chunks as encrypted (default: auto-detect)");
                Console.WriteLine("  -decrypted               Mark chunks as decrypted (default: auto-detect)");
                Console.WriteLine("  -max-file-size <bytes>   Maximum size per CSD file (default: 2GiB, min: 1GiB)");
                Console.WriteLine("  -threads <count>         Parallel file reads (default: CPU count - 1)");
                Console.WriteLine("  -batch-size <count>      Chunks to buffer in memory (default: 1000)");
                Console.WriteLine("  -checkpoint-interval <n> Save checkpoint every N chunks (default: 5000)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore pack depot/4001/chunk/ chunkstore/ -depot 4001");
                Console.WriteLine("  depotdownloader chunkstore pack depot/4001/chunk/ chunkstore/ -depot 4001 -decrypted");
                return 1;
            }

            var inputFolder = args[0];
            var outputFolder = args[1];

            if (!Directory.Exists(inputFolder))
            {
                Console.WriteLine($"Error: Input folder does not exist: {inputFolder}");
                return 1;
            }

            // Parse options (skip the two positional folder args)
            var parser = new ArgParser(args[2..]);
            bool? isEncrypted = parser.HasFlag("-encrypted") ? true : parser.HasFlag("-decrypted") ? false : null;
            var sizeIsValid = TryParseCommonChunkOptions(parser, out var opts, out var sizeError);
            var (depotId, maxFileSize, maxParallelism, batchSize, checkpointInterval) = opts;

            parser.WarnUnconsumed();

            if (depotId == null)
            {
                Console.WriteLine("Error: -depot <id> is required for packing operation");
                return 1;
            }

            if (!sizeIsValid)
            {
                Console.WriteLine(sizeError);
                return 1;
            }

            Directory.CreateDirectory(outputFolder);

            var allFiles = Directory.GetFiles(inputFolder, "*", SearchOption.AllDirectories).ToList();

            // A chunkstore holds only one mode at a time - encrypted or decrypted, never mixed
            // (the CSM header records which). Regardless of whether -encrypted/-decrypted was given
            // explicitly, refuse to pack anything if the input folder has both types present - silently
            // packing only the matching subset would leave the other files behind with no indication.
            var hasEncrypted = allFiles.Any(f => Chunkstore.TryGetChunkSha(Path.GetFileName(f), isEncrypted: true, out _));
            var hasDecrypted = allFiles.Any(f => Chunkstore.TryGetChunkSha(Path.GetFileName(f), isEncrypted: false, out _));

            if (hasEncrypted && hasDecrypted)
            {
                Console.WriteLine("Error: Input folder contains both encrypted and decrypted chunk files.");
                Console.WriteLine("A chunkstore can only hold one type at a time. Nothing was packed - either:");
                Console.WriteLine("  - separate the two types into different input folders, or");
                Console.WriteLine("  - normalize the folder to a single mode first (decryption and re-encryption are both");
                Console.WriteLine("    round-trippable with the depot key, so converting everything to match is safe).");
                return 1;
            }

            if (isEncrypted == null)
            {
                isEncrypted = hasEncrypted;
                Console.WriteLine($"Auto-detected encryption status: {(isEncrypted.Value ? "encrypted" : "decrypted")}");
            }

            var (chunkFiles, _) = PartitionChunkFilesByMode(allFiles, isEncrypted.Value);

            Console.WriteLine($"Found {chunkFiles.Count:N0} chunk files to pack");

            if (chunkFiles.Count == 0)
            {
                Console.WriteLine("No chunk files found in input directory");
                return 1;
            }

            using var chunkstore = new Chunkstore(outputFolder, depotId, null, isEncrypted, maxFileSize);

            Console.WriteLine($"Packing {chunkFiles.Count:N0} chunks into chunkstore...");
            await chunkstore.PackAsync(chunkFiles, maxParallelism, batchSize, checkpointInterval, true);

            var stats = chunkstore.GetStats();
            Console.WriteLine();
            Console.WriteLine("Pack complete!");
            Console.WriteLine(stats);

            return 0;
        }

        private static async Task<int> UnpackCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore unpack <chunkstore-folder> <output-chunks-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot <id>              Depot ID (auto-detect if only one depot)");
                Console.WriteLine("  -threads <count>         Parallel file operations (default: CPU count - 1)");
                Console.WriteLine("  -overwrite               Overwrite existing files (default: skip existing)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore unpack chunkstore/ extracted_chunks/");
                Console.WriteLine("  depotdownloader chunkstore unpack chunkstore/ extracted_chunks/ -depot 4001 -threads 16");
                return 1;
            }

            var chunkstoreFolder = args[0];
            var outputFolder = args[1];

            if (!Directory.Exists(chunkstoreFolder))
            {
                Console.WriteLine($"Error: Chunkstore folder does not exist: {chunkstoreFolder}");
                return 1;
            }

            // Parse options (skip the two positional folder args)
            var parser = new ArgParser(args[2..]);
            var depotId = parser.GetNullable<uint>("-depot", "-d");
            var maxParallelism = parser.Get(0, "-threads");
            var skipExisting = !parser.HasFlag("-overwrite");
            parser.WarnUnconsumed();

            using var chunkstore = new Chunkstore(chunkstoreFolder, depotId);

            var stats = chunkstore.GetStats();
            Console.WriteLine($"Unpacking chunkstore: {stats}");

            await chunkstore.UnpackAllAsync(outputFolder, maxParallelism, skipExisting);

            Console.WriteLine("Unpack complete!");
            return 0;
        }

        private static async Task<int> VerifyCommand(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore verify <chunkstore-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot, -d <id>          Depot ID (auto-detect if only one depot)");
                Console.WriteLine("  -key, -k <path>          Path to depot key file");
                Console.WriteLine("  -chunks <file>           Only verify the SHA1s listed in this file (one per line,");
                Console.WriteLine("                           or first column of a CSV; '#' comments allowed)");
                Console.WriteLine("  -threads, -t <count>     Parallel validation threads (default: auto)");
                Console.WriteLine("  -verbose, -v             Show result for every chunk");
                Console.WriteLine("  -no-resume               Ignore existing checkpoint, start fresh (full-chunkstore verify only)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore verify chunkstore/");
                Console.WriteLine("  depotdownloader chunkstore verify chunkstore/ -depot 4001 -key depot.key");
                Console.WriteLine("  depotdownloader chunkstore verify chunkstore/ -chunks suspect_chunks.txt");
                return 1;
            }

            var chunkstoreFolder = args[0];

            if (!Directory.Exists(chunkstoreFolder))
            {
                Console.WriteLine($"Error: Chunkstore folder does not exist: {chunkstoreFolder}");
                return 1;
            }

            // Parse options (skip the positional folder arg)
            var parser = new ArgParser(args[1..]);
            var depotId = parser.GetNullable<uint>("-depot", "-d");
            var depotKeyPath = parser.Get<string>(null, "-key", "-k");
            var chunkListFile = parser.Get<string>(null, "-chunks");
            var maxThreads = parser.Get(0, "-threads", "-t");
            var verbose = parser.HasFlag("-verbose", "-v");
            var resume = !parser.HasFlag("-no-resume");
            parser.WarnUnconsumed();

            ValidationSummary summary;
            if (!string.IsNullOrEmpty(chunkListFile))
            {
                var chunkList = await ReadChunkListFileAsync(chunkListFile);
                if (chunkList == null)
                {
                    return 1;
                }

                Console.WriteLine($"Chunk list file: {chunkListFile} ({chunkList.Count} chunks)");
                summary = await StandaloneChunkValidator.ValidateChunkstoreChunksAsync(
                    chunkstoreFolder, chunkList, depotId, depotKeyPath, verbose, maxThreads);
            }
            else
            {
                summary = await StandaloneChunkValidator.ValidateChunkstoreAsync(
                    chunkstoreFolder, depotId, depotKeyPath, verbose, maxThreads, resume);
            }

            Console.WriteLine();
            Console.WriteLine("=== VALIDATION SUMMARY ===");
            Console.WriteLine($"Total:   {summary.TotalChunks:N0}");
            Console.WriteLine($"Valid:   {summary.ValidChunks:N0}");
            Console.WriteLine($"Invalid: {summary.InvalidChunks:N0}");
            if (summary.ErrorChunks > 0)
                Console.WriteLine($"Errors:  {summary.ErrorChunks:N0}");

            return summary.InvalidChunks > 0 || summary.ErrorChunks > 0 ? 1 : 0;
        }

        /// <summary>
        /// Reads a chunk SHA1 list for -chunks: one per line, '#' comments skipped, either a
        /// bare hex string or the first column of a comma-separated line. Returns null (after
        /// printing an error) if the file is missing, unreadable, or yields no chunks.
        /// </summary>
        private static async Task<List<string>> ReadChunkListFileAsync(string chunkListFile)
        {
            if (!File.Exists(chunkListFile))
            {
                Console.WriteLine($"Error: Chunk list file not found: {chunkListFile}");
                return null;
            }

            var chunkList = new List<string>();
            try
            {
                var lines = await File.ReadAllLinesAsync(chunkListFile);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#'))
                    {
                        continue;
                    }

                    chunkList.Add(trimmed.Contains(',') ? trimmed.Split(',')[0].Trim() : trimmed);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading chunk list file: {ex.Message}");
                return null;
            }

            if (chunkList.Count == 0)
            {
                Console.WriteLine("No chunks found in chunk list file");
                return null;
            }

            return chunkList;
        }

        private static async Task<int> RebuildCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore rebuild <chunkstore-folder> <output-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("Re-sorts every chunk in <chunkstore-folder> into a fresh, alphanumerically-ordered");
                Console.WriteLine("chunkstore at <output-folder> - the same canonical, byte-for-byte-deterministic");
                Console.WriteLine("layout a from-scratch 'pack' of the same chunk set would produce. This restores");
                Console.WriteLine("that determinism after incremental 'update' calls have appended chunks out of");
                Console.WriteLine("order. Deliberately expensive: needs up to ~2x storage transiently, since sorted");
                Console.WriteLine("offsets can't be computed without a full copy. The original is never modified or");
                Console.WriteLine("deleted - once you've confirmed the new store (e.g. with 'chunkstore verify'),");
                Console.WriteLine("replace the original yourself.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot <id>              Depot ID (auto-detect if only one depot)");
                Console.WriteLine("  -max-file-size <bytes>   Maximum size per CSD file (default: 2GiB, min: 1GiB)");
                Console.WriteLine("  -threads <count>         Parallel chunk reads (default: CPU count - 1)");
                Console.WriteLine("  -batch-size <count>      Chunks to buffer in memory (default: 1000)");
                Console.WriteLine("  -checkpoint-interval <n> Save checkpoint every N chunks (default: 5000).");
                Console.WriteLine("                           Must be > 0 when -delete-source-as-we-go is used -");
                Console.WriteLine("                           deletion is gated on a checkpoint actually being saved.");
                Console.WriteLine("  -no-resume               Re-copy every chunk instead of skipping ones already");
                Console.WriteLine("                           recorded in an existing checkpoint. Does not delete or");
                Console.WriteLine("                           reset existing output files (already-present chunks are");
                Console.WriteLine("                           still skipped on write via dedup either way).");
                Console.WriteLine("  -delete-source-as-we-go  Delete old segments from the source as soon as every");
                Console.WriteLine("                           one of their chunks is durably confirmed copied,");
                Console.WriteLine("                           instead of waiting until the whole rebuild finishes.");
                Console.WriteLine("                           Bounds storage overhead to roughly the still-pending");
                Console.WriteLine("                           portion of the source rather than the whole thing -");
                Console.WriteLine("                           but this DOES permanently delete parts of the source");
                Console.WriteLine("                           as the operation runs, not just at the end.");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore rebuild chunkstore/ chunkstore_rebuilt/ -depot 4001");
                return 1;
            }

            var sourceFolder = args[0];
            var outputFolder = args[1];

            if (!Directory.Exists(sourceFolder))
            {
                Console.WriteLine($"Error: Chunkstore folder does not exist: {sourceFolder}");
                return 1;
            }

            if (string.Equals(Path.GetFullPath(sourceFolder).TrimEnd(Path.DirectorySeparatorChar),
                               Path.GetFullPath(outputFolder).TrimEnd(Path.DirectorySeparatorChar),
                               StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Error: output folder must be different from the source chunkstore - rebuild never modifies the source in place.");
                return 1;
            }

            var parser = new ArgParser(args[2..]);
            var resume = !parser.HasFlag("-no-resume");
            var deleteSourceAsWeGo = parser.HasFlag("-delete-source-as-we-go");
            var sizeIsValid = TryParseCommonChunkOptions(parser, out var opts, out var sizeError);
            var (depotId, maxFileSize, maxParallelism, batchSize, checkpointInterval) = opts;

            parser.WarnUnconsumed();

            if (!sizeIsValid)
            {
                Console.WriteLine(sizeError);
                return 1;
            }

            if (deleteSourceAsWeGo && checkpointInterval <= 0)
            {
                Console.WriteLine("Error: -delete-source-as-we-go requires -checkpoint-interval to be greater than 0.");
                Console.WriteLine("Deletion is only ever performed right after a checkpoint save confirms chunk");
                Console.WriteLine("locations are durably recorded - with checkpointing off, nothing would ever be");
                Console.WriteLine("deleted, silently defeating the flag's purpose.");
                return 1;
            }

            if (deleteSourceAsWeGo)
            {
                Console.WriteLine("WARNING: -delete-source-as-we-go will permanently delete old segments from");
                Console.WriteLine($"  {sourceFolder}");
                Console.WriteLine("as soon as every chunk they hold is durably confirmed copied into the new");
                Console.WriteLine("store - not just at the end. If interrupted, some source segments will already");
                Console.WriteLine("be gone; this is safe (their contents are confirmed present in the new store)");
                Console.WriteLine("but is not reversible.");
                Console.WriteLine();
            }

            // deleteSourceAsWeGo needs write access to the source folder to delete files from it.
            using var source = new Chunkstore(sourceFolder, depotId, null, readOnly: !deleteSourceAsWeGo);
            var sourceStats = source.GetStats();

            if (sourceStats.TotalChunks == 0)
            {
                Console.WriteLine("Source chunkstore has no chunks - nothing to rebuild.");
                return 1;
            }

            Console.WriteLine($"Source: {sourceStats}");

            Directory.CreateDirectory(outputFolder);
            using var target = new Chunkstore(outputFolder, sourceStats.DepotId, null, source.IsEncrypted, maxFileSize);

            // For -delete-source-as-we-go, capture the source's true totals now, while it's still
            // fully intact, so a later resumed run's final completeness check has something correct
            // to compare against even after some source segments have already been deleted (a fresh
            // re-scan of source at that point would understate the original totals).
            int expectedTotalChunks;
            long expectedTotalBytes;
            var rebuildCheckpointPath = RebuildCheckpoint.GetPath(outputFolder, sourceStats.DepotId);

            // A leftover file here means an earlier -delete-source-as-we-go run against this same
            // output folder already deleted some source segments. Resuming without the flag this
            // time would fall into the plain-rebuild branch below, which computes "expected" totals
            // from a live re-scan of source - now permanently understated versus what this
            // checkpoint recorded before any deletion began, producing a false "doesn't match what
            // was expected" failure at the end. Refuse outright rather than silently mis-comparing.
            if (!deleteSourceAsWeGo && File.Exists(rebuildCheckpointPath))
            {
                Console.WriteLine($"Error: {rebuildCheckpointPath} exists, meaning a -delete-source-as-we-go");
                Console.WriteLine($"rebuild into {outputFolder} was already in progress and may have already");
                Console.WriteLine("deleted some source segments. Re-run with -delete-source-as-we-go to resume it");
                Console.WriteLine("correctly (comparing against the totals recorded before any deletion began),");
                Console.WriteLine("not without it.");
                return 1;
            }

            if (deleteSourceAsWeGo)
            {
                if (File.Exists(rebuildCheckpointPath))
                {
                    var loaded = RebuildCheckpoint.LoadFromFile(rebuildCheckpointPath);
                    expectedTotalChunks = loaded.TotalExpectedChunks;
                    expectedTotalBytes = loaded.TotalExpectedBytes;
                    Console.WriteLine($"Resuming: expecting {expectedTotalChunks:N0} chunks, {expectedTotalBytes:N0} raw bytes total (recorded before any source deletion began)");
                }
                else
                {
                    expectedTotalChunks = sourceStats.TotalChunks;
                    // Sum of indexed chunk lengths, NOT sourceStats.TotalSize (raw on-disk CSD
                    // length) - those can differ after a crash that landed between a WriteChunk's
                    // physical byte write and its checkpoint/CSM record (orphaned trailing bytes on
                    // disk that chunkIndex never learns about). Only the index-based total is a
                    // trustworthy "did we copy everything real" figure for this safety check.
                    expectedTotalBytes = source.EnumerateChunks().Sum(c => (long)c.Length);
                    new RebuildCheckpoint
                    {
                        DepotId = sourceStats.DepotId,
                        TotalExpectedChunks = expectedTotalChunks,
                        TotalExpectedBytes = expectedTotalBytes
                    }.SaveToFile(rebuildCheckpointPath);
                }
            }
            else
            {
                expectedTotalChunks = sourceStats.TotalChunks;
                expectedTotalBytes = source.EnumerateChunks().Sum(c => (long)c.Length);
            }

            await target.RebuildFromAsync(source, maxParallelism, batchSize, checkpointInterval, resume, deleteSourceAsWeGo);

            var targetStats = target.GetStats();
            var targetTotalBytes = target.EnumerateChunks().Sum(c => (long)c.Length);

            if (targetStats.TotalChunks != expectedTotalChunks || targetTotalBytes != expectedTotalBytes)
            {
                Console.WriteLine();
                Console.WriteLine("Error: rebuilt chunkstore doesn't match what was expected - not treating this as complete.");
                Console.WriteLine($"  Expected: {expectedTotalChunks:N0} chunks, {expectedTotalBytes:N0} raw bytes");
                Console.WriteLine($"  Target:   {targetStats.TotalChunks:N0} chunks, {targetTotalBytes:N0} raw bytes");
                Console.WriteLine($"The partial output at {outputFolder} was left in place for inspection - nothing extra was deleted.");
                return 1;
            }

            if (deleteSourceAsWeGo && File.Exists(rebuildCheckpointPath))
            {
                File.Delete(rebuildCheckpointPath);
            }

            Console.WriteLine();
            Console.WriteLine("Rebuild complete!");
            Console.WriteLine(targetStats);
            Console.WriteLine();
            Console.WriteLine($"This is the canonical, deterministically-sorted layout, written to {outputFolder}.");

            if (deleteSourceAsWeGo)
            {
                Console.WriteLine($"Source segments in {sourceFolder} were deleted progressively as their contents");
                Console.WriteLine("were confirmed copied; any remaining there now are stale and can be removed.");
            }
            else
            {
                Console.WriteLine("The original was not modified. Once you've confirmed the new store (e.g. with");
                Console.WriteLine("'chunkstore verify'), replace the original with it yourself.");
            }

            return 0;
        }

        private static async Task<int> UpdateCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore update <new-chunks-folder> <existing-chunkstore-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("Appends chunks from <new-chunks-folder> that aren't already present, without");
                Console.WriteLine("touching or re-sorting any existing CSD/CSM data - the cheap way to bring an");
                Console.WriteLine("existing chunkstore up to date after a game update (e.g. a handful of new");
                Console.WriteLine("chunks against a chunkstore that's already hundreds of gigabytes). The result");
                Console.WriteLine("is not alphanumerically sorted - run 'chunkstore rebuild' if you need a");
                Console.WriteLine("canonical, deterministically-ordered store (e.g. for checksumming).");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot <id>              Depot ID (auto-detect if only one depot)");
                Console.WriteLine("  -max-file-size <bytes>   Maximum size per CSD file (default: 2GiB, min: 1GiB)");
                Console.WriteLine("  -threads <count>         Parallel file reads (default: CPU count - 1)");
                Console.WriteLine("  -batch-size <count>      Chunks to buffer in memory (default: 1000)");
                Console.WriteLine("  -checkpoint-interval <n> Save checkpoint every N chunks (default: 5000)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore update depot/4001/new_chunks/ chunkstore/ -depot 4001");
                return 1;
            }

            var inputFolder = args[0];
            var outputFolder = args[1];

            if (!Directory.Exists(inputFolder))
            {
                Console.WriteLine($"Error: Input folder does not exist: {inputFolder}");
                return 1;
            }

            if (!Directory.Exists(outputFolder))
            {
                Console.WriteLine($"Error: Chunkstore folder does not exist: {outputFolder}");
                Console.WriteLine("'update' only adds to an existing chunkstore - use 'chunkstore pack' to create one first.");
                return 1;
            }

            var parser = new ArgParser(args[2..]);
            var sizeIsValid = TryParseCommonChunkOptions(parser, out var opts, out var sizeError);
            var (depotId, maxFileSize, maxParallelism, batchSize, checkpointInterval) = opts;

            parser.WarnUnconsumed();

            if (!sizeIsValid)
            {
                Console.WriteLine(sizeError);
                return 1;
            }

            // 'update' never creates a chunkstore from scratch - that's what 'pack' is for. Check
            // for an existing one up front so a typo'd or empty target folder fails clearly instead
            // of silently starting a brand new store where you didn't mean to.
            var existingCsmPattern = depotId.HasValue ? $"{depotId.Value}_*.csm" : "*_*.csm";
            if (Directory.GetFiles(outputFolder, existingCsmPattern).Length == 0)
            {
                Console.WriteLine($"Error: No existing chunkstore found in {outputFolder}" +
                                   (depotId.HasValue ? $" for depot {depotId}." : "."));
                Console.WriteLine("Use 'chunkstore pack' to create a new chunkstore first.");
                return 1;
            }

            using var chunkstore = new Chunkstore(outputFolder, depotId, null, isEncrypted: null, maxFileSize);

            // The existing store's own CSM data already establishes its encryption mode - update
            // never asks for -encrypted/-decrypted, it just has to match what's already there.
            if (chunkstore.IsEncrypted == null)
            {
                Console.WriteLine("Error: could not determine the existing chunkstore's encryption mode.");
                return 1;
            }

            var isEncrypted = chunkstore.IsEncrypted.Value;
            var allFiles = Directory.GetFiles(inputFolder, "*", SearchOption.AllDirectories).ToList();
            var (matching, mismatched) = PartitionChunkFilesByMode(allFiles, isEncrypted);

            if (mismatched.Count > 0)
            {
                Console.WriteLine($"Error: {mismatched.Count:N0} file(s) in {inputFolder} don't match this chunkstore's mode " +
                                   $"({(isEncrypted ? "encrypted" : "decrypted")}). Nothing was added - separate them out or " +
                                   "convert them to match first.");
                return 1;
            }

            if (matching.Count == 0)
            {
                Console.WriteLine("No matching chunk files found in input directory");
                return 1;
            }

            var alreadyPresentCount = matching.Count(f =>
                Chunkstore.TryGetChunkSha(Path.GetFileName(f), isEncrypted, out var sha) &&
                chunkstore.ChunkExists(Convert.FromHexString(sha)));
            var newCount = matching.Count - alreadyPresentCount;

            Console.WriteLine($"Found {matching.Count:N0} chunk files in input folder " +
                               $"({alreadyPresentCount:N0} already present, {newCount:N0} new).");

            if (newCount == 0)
            {
                Console.WriteLine("Chunkstore is already up to date - nothing to add.");
                return 0;
            }

            await chunkstore.PackAsync(matching, maxParallelism, batchSize, checkpointInterval, true);

            var stats = chunkstore.GetStats();
            Console.WriteLine();
            Console.WriteLine($"Update complete! Added {newCount:N0} new chunk(s).");
            Console.WriteLine(stats);

            return 0;
        }

        private static async Task<int> StatsCommand(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: depotdownloader chunkstore stats <chunkstore-folder> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -depot <id>              Depot ID (auto-detect if only one depot)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader chunkstore stats chunkstore/");
                Console.WriteLine("  depotdownloader chunkstore stats chunkstore/ -depot 4001");
                return 1;
            }

            var chunkstoreFolder = args[0];

            if (!Directory.Exists(chunkstoreFolder))
            {
                Console.WriteLine($"Error: Chunkstore folder does not exist: {chunkstoreFolder}");
                return 1;
            }

            // Parse options (skip the positional folder arg)
            var parser = new ArgParser(args[1..]);
            var depotId = parser.GetNullable<uint>("-depot", "-d");
            parser.WarnUnconsumed();

            using var chunkstore = new Chunkstore(chunkstoreFolder, depotId);

            var stats = chunkstore.GetStats();
            Console.WriteLine();
            Console.WriteLine("=== CHUNKSTORE STATISTICS ===");
            Console.WriteLine(stats);

            // Additional detailed stats - single pass over the chunk index rather than several
            // separate LINQ traversals (this can be millions of entries for a large store).
            var chunkCount = 0;
            long totalSize = 0;
            var minSize = int.MaxValue;
            var maxSize = int.MinValue;
            var fileDistribution = new SortedDictionary<int, int>();

            foreach (var chunk in chunkstore.EnumerateChunks())
            {
                chunkCount++;
                totalSize += chunk.Length;
                if (chunk.Length < minSize) minSize = chunk.Length;
                if (chunk.Length > maxSize) maxSize = chunk.Length;
                fileDistribution[chunk.ChunkstoreIndex] = fileDistribution.GetValueOrDefault(chunk.ChunkstoreIndex) + 1;
            }

            if (chunkCount > 0)
            {
                Console.WriteLine();
                Console.WriteLine("=== CHUNK SIZE ANALYSIS ===");
                Console.WriteLine($"Average chunk size: {(double)totalSize / chunkCount:N0} bytes");
                Console.WriteLine($"Smallest chunk:     {minSize:N0} bytes");
                Console.WriteLine($"Largest chunk:      {maxSize:N0} bytes");

                Console.WriteLine();
                Console.WriteLine("=== FILE DISTRIBUTION ===");
                foreach (var kvp in fileDistribution)
                {
                    Console.WriteLine($"File {kvp.Key}: {kvp.Value:N0} chunks");
                }
            }

            return await Task.FromResult(0);
        }

        public static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Chunkstore Command");
            Console.WriteLine();
            Console.WriteLine("The chunkstore command manages and organizes chunk storage for");
            Console.WriteLine("efficient depot operations across multiple depots.");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader chunkstore <operation> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("OPERATION DETAILS:");
            Console.WriteLine("  pack     - Create new chunkstore from loose chunk files");
            Console.WriteLine("  unpack   - Extract all chunks back to individual files");
            Console.WriteLine("  verify   - Validate chunk integrity and metadata consistency");
            Console.WriteLine("  rebuild  - Reorganize existing chunkstore for optimal ordering");
            Console.WriteLine("  update   - Cheaply append new chunks to an existing chunkstore (not re-sorted)");
            Console.WriteLine("  stats    - Display chunk count, file sizes, and storage metrics");
            Console.WriteLine();
            Console.WriteLine("BENEFITS:");
            Console.WriteLine("  • Efficient storage with automatic deduplication");
            Console.WriteLine("  • Fast chunk lookup and retrieval");
            Console.WriteLine("  • Better organization of large depot collections");
            Console.WriteLine("  • Integrity verification and validation");
            Console.WriteLine("  • Alphanumeric ordering for predictable access patterns");
            Console.WriteLine("  • Guaranteed uniqueness: each chunk SHA1 stored only once");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  # Pack loose chunks into chunkstore");
            Console.WriteLine("  depotdownloader chunkstore pack depot/4001/chunk depot/4001/chunkstore -depot 4001");
            Console.WriteLine();
            Console.WriteLine("  # Add new chunks and reorganize");
            Console.WriteLine("  depotdownloader chunkstore update depot/4001/chunkstore depot/4001/new_chunks");
            Console.WriteLine();
            Console.WriteLine("  # Reorganize existing chunkstore");
            Console.WriteLine("  depotdownloader chunkstore rebuild depot/4001/chunkstore");
            Console.WriteLine();
            Console.WriteLine("  # Verify integrity");
            Console.WriteLine("  depotdownloader chunkstore verify depot/4001/chunkstore -threads 16");
            Console.WriteLine();
            Console.WriteLine("  # Show statistics");
            Console.WriteLine("  depotdownloader chunkstore stats depot/4001/chunkstore");
            Console.WriteLine();
            Console.WriteLine("  # Extract back to loose files");
            Console.WriteLine("  depotdownloader chunkstore unpack depot/4001/chunkstore extracted_chunks/");
        }
    }
}
