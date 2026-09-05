// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Reconstruct command handler: rebuilds installed depot files entirely offline from a
    /// saved manifest, a depot key, and previously-archived chunk data (loose files or a
    /// chunkstore). The actual assembly algorithm lives in <see cref="ReconstructEngine"/>;
    /// this class only handles argument parsing and wiring, matching the other commands' shape.
    /// </summary>
    public static class ReconstructCommand
    {
        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            var parser = new ArgParser(args);

            var manifestFile = parser.Get<string>(null, "-manifest") ?? parser.Positional(0);
            if (string.IsNullOrEmpty(manifestFile))
            {
                Console.WriteLine("Error: a manifest file is required (positional argument or -manifest <file>)");
                PrintUsage();
                return 1;
            }

            if (!File.Exists(manifestFile))
            {
                Console.WriteLine($"Error: Manifest file not found: {manifestFile}");
                return 1;
            }

            var listFiles = parser.HasFlag("-list-files", "-list");

            var outputDir = parser.Get<string>(null, "-output");
            if (!listFiles && string.IsNullOrEmpty(outputDir))
            {
                Console.WriteLine("Error: -output <dir> is required");
                return 1;
            }

            var depotId = parser.GetNullable<uint>("-depot", "-d");
            var depotKeyHex = parser.Get<string>(null, "-depotkey");
            var depotKeyFile = parser.Get<string>(null, "-depotkey-file");
            var chunksDir = parser.Get<string>(null, "-chunks");
            var chunkstoreDir = parser.Get<string>(null, "-chunkstore");
            var fileListPath = parser.Get<string>(null, "-filelist");
            var inlineFiles = parser.Get<string>(null, "-files");
            var validate = parser.HasFlag("-validate");
            var maxThreads = parser.Get(0, "-threads");
            var failFast = parser.HasFlag("-fail-fast");
            var verbose = parser.HasFlag("-verbose", "-v");
            parser.WarnUnconsumed();

            if (!listFiles && !string.IsNullOrEmpty(chunksDir) && !string.IsNullOrEmpty(chunkstoreDir))
            {
                Console.WriteLine("Error: -chunks and -chunkstore are mutually exclusive - pick one chunk source");
                return 1;
            }

            // Resolve the depot key first (best-effort - it may turn out not to be needed, e.g.
            // a .manifest input plus an already-decrypted chunkstore, but almost every real case
            // needs it, and .manif4/.manif5 inputs always do to decrypt filenames - raw-saved
            // manifests store them AES-encrypted and base64-wrapped inside the zip payload, only
            // readable as real paths once DepotManifest.DecryptFilenames runs, which
            // LoadDepotManifestFromAnyFormat below does for us given a key).
            byte[] depotKey = null;
            try
            {
                var (key, resolvedDepotId) = await ManifestCommand.ResolveDepotKeyAsync(depotKeyHex, depotKeyFile, depotId, manifestFile);
                depotKey = key;
                depotId ??= resolvedDepotId;
            }
            catch (Exception ex)
            {
                // Not fatal here - a .manifest file doesn't strictly need a key to load. Whether
                // a key is actually required gets decided once we know the chunk source below.
                Console.WriteLine($"Note: could not resolve a depot key up front ({ex.Message})");
            }

            SteamKit2.DepotManifest manifest;
            try
            {
                manifest = await ManifestCommand.LoadDepotManifestFromAnyFormat(manifestFile, depotKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: Failed to load manifest: {ex.Message}");
                return 1;
            }

            depotId ??= manifest.DepotID != 0 ? manifest.DepotID : null;

            if (listFiles)
            {
                PrintFileList(manifest, verbose);
                return 0;
            }

            IChunkSource chunkSource;
            try
            {
                chunkSource = ResolveChunkSource(chunksDir, chunkstoreDir, manifestFile, depotId, depotKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }

            using (chunkSource)
            {
                var options = new ReconstructOptions
                {
                    MaxParallelism = maxThreads,
                    Validate = validate,
                    FailFast = failFast,
                    Verbose = verbose
                };

                // -filelist and -files are both "files to include" sources and combine (union) if
                // both are given, rather than one overriding the other - -files for a quick
                // one-off subset, -filelist for anything worth saving and reusing.
                if (!string.IsNullOrEmpty(fileListPath) || !string.IsNullOrEmpty(inlineFiles))
                {
                    var includeFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var includeRegexes = new List<Regex>();

                    if (!string.IsNullOrEmpty(fileListPath))
                    {
                        if (!TryMergeFileList(fileListPath, includeFiles, includeRegexes))
                        {
                            return 1;
                        }
                    }

                    if (!string.IsNullOrEmpty(inlineFiles))
                    {
                        if (!TryMergeInlineFileList(inlineFiles, includeFiles, includeRegexes))
                        {
                            return 1;
                        }
                    }

                    options.IncludeFiles = includeFiles;
                    options.IncludeRegexes = includeRegexes;
                }

                Console.WriteLine($"Reconstructing {manifest.Files.Count:N0} manifest entries to {outputDir}...");

                ReconstructSummary summary;
                try
                {
                    summary = await ReconstructEngine.RunAsync(manifest, chunkSource, outputDir, options);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return 1;
                }

                Console.WriteLine();
                Console.WriteLine("=== RECONSTRUCT SUMMARY ===");
                Console.WriteLine($"Total:              {summary.TotalFiles:N0}");
                Console.WriteLine($"Completed:          {summary.CompletedFiles:N0}");
                if (summary.FailedFiles > 0)
                    Console.WriteLine($"Failed:             {summary.FailedFiles:N0}");
                if (summary.ValidationFailures > 0)
                    Console.WriteLine($"Validation failed:  {summary.ValidationFailures:N0}");
                if (summary.SkippedSymlinks > 0)
                    Console.WriteLine($"Symlinks skipped:   {summary.SkippedSymlinks:N0}");

                return summary.FailedFiles > 0 || summary.ValidationFailures > 0 ? 1 : 0;
            }
        }

        private static IChunkSource ResolveChunkSource(string chunksDir, string chunkstoreDir, string manifestFile, uint? depotId, byte[] depotKey)
        {
            if (!string.IsNullOrEmpty(chunkstoreDir))
            {
                if (!Directory.Exists(chunkstoreDir))
                {
                    throw new DirectoryNotFoundException($"Chunkstore folder does not exist: {chunkstoreDir}");
                }

                var chunkstore = new Chunkstore(chunkstoreDir, depotId, depotKey, readOnly: true);
                if (chunkstore.IsEncrypted == true && depotKey == null)
                {
                    chunkstore.Dispose();
                    throw new InvalidOperationException("Chunkstore is encrypted but no depot key was resolved - use -depotkey or -depotkey-file");
                }

                return new ChunkstoreChunkSource(chunkstore, ownsChunkstore: true);
            }

            var looseDir = chunksDir;
            if (string.IsNullOrEmpty(looseDir))
            {
                if (depotId == null)
                {
                    throw new InvalidOperationException("No -chunks or -chunkstore given, and depot ID couldn't be determined to auto-detect one - specify one explicitly");
                }

                // Mirror the raw-archive layout's convention (depot/<id>/chunk), relative to the
                // manifest's own location if it lives under that same layout.
                var manifestDir = Path.GetDirectoryName(Path.GetFullPath(manifestFile));
                var candidate = Path.Combine(manifestDir ?? ".", "..", "chunk");
                if (!Directory.Exists(candidate))
                {
                    candidate = Path.Combine("depot", depotId.Value.ToString(), "chunk");
                }

                looseDir = candidate;
                Console.WriteLine($"Auto-detected loose chunk folder: {looseDir}");
            }

            if (!Directory.Exists(looseDir))
            {
                throw new DirectoryNotFoundException($"Chunk folder does not exist: {looseDir}");
            }

            if (depotKey == null)
            {
                throw new InvalidOperationException("Loose archived chunks are always encrypted and need a depot key - use -depotkey or -depotkey-file");
            }

            return new LooseChunkSource(looseDir, depotKey);
        }

        /// <summary>Same literal-path/"regex:"-prefix format as -filelist elsewhere in this codebase (see DownloadCommand.cs). Merges into the caller's sets rather than replacing them, so -filelist and -files can combine.</summary>
        private static bool TryMergeFileList(string fileListPath, HashSet<string> includeFiles, List<Regex> includeRegexes)
        {
            if (!Util.TryParseFileList(fileListPath, out var literals, out var regexes, out var error))
            {
                Console.WriteLine($"Error: {error}");
                return false;
            }

            includeFiles.UnionWith(literals);
            includeRegexes.AddRange(regexes);
            Console.WriteLine($"Using filelist: '{fileListPath}'.");
            return true;
        }

        /// <summary>Inline, ";"-separated equivalent of -filelist (see Util.TryParseInlineFileList) - merges into the caller's sets rather than replacing them.</summary>
        private static bool TryMergeInlineFileList(string inline, HashSet<string> includeFiles, List<Regex> includeRegexes)
        {
            if (!Util.TryParseInlineFileList(inline, out var literals, out var regexes, out var error))
            {
                Console.WriteLine($"Error: {error}");
                return false;
            }

            includeFiles.UnionWith(literals);
            includeRegexes.AddRange(regexes);
            return true;
        }

        /// <summary>
        /// Lists every file recorded in the manifest and exits, without reconstructing anything -
        /// no -output/-chunks/-chunkstore needed. Filenames come from the already-loaded manifest,
        /// which LoadDepotManifestFromAnyFormat has already decrypted (given a depot key) if this
        /// was a raw-saved .manif4/.manif5 - those store names AES-encrypted and base64-wrapped,
        /// not human-readable until decrypted. Plain (non-verbose) output is one path per line,
        /// sorted, and directly usable as a -filelist input (e.g. redirected to a file, trimmed
        /// down by hand, then passed back in with -filelist).
        /// </summary>
        private static void PrintFileList(SteamKit2.DepotManifest manifest, bool verbose)
        {
            var files = manifest.Files
                .Select(f => f.FileName.Replace('\\', '/'))
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (verbose)
            {
                foreach (var file in manifest.Files.OrderBy(f => f.FileName.Replace('\\', '/'), StringComparer.OrdinalIgnoreCase))
                {
                    var kind = file.Flags.HasFlag(EDepotFileFlag.Directory) ? "dir"
                        : file.Flags.HasFlag(EDepotFileFlag.Symlink) ? "symlink"
                        : "file";
                    Console.WriteLine($"{file.FileName.Replace('\\', '/')}  ({kind}, {file.TotalSize:N0} bytes, {file.Chunks.Count:N0} chunks)");
                }
            }
            else
            {
                foreach (var name in files)
                {
                    Console.WriteLine(name);
                }
            }

            Console.WriteLine();
            Console.WriteLine($"{files.Count:N0} file(s) total.");
        }

        public static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Reconstruct Command");
            Console.WriteLine();
            Console.WriteLine("Rebuilds installed depot files entirely offline from a saved manifest, a depot");
            Console.WriteLine("key, and previously-archived chunk data (loose files or a chunkstore).");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader reconstruct <manifest-file> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("OPTIONS:");
            Console.WriteLine("  -manifest <file>         Manifest file (alternative to the positional argument)");
            Console.WriteLine("  -output <dir>            Output directory for reconstructed files (required unless -list-files)");
            Console.WriteLine("  -depot <id>              Depot ID (for key lookup / chunk source auto-detect)");
            Console.WriteLine("  -depotkey <hex>          Depot key in hex");
            Console.WriteLine("  -depotkey-file <path>    Path to depot key file");
            Console.WriteLine("  -chunks <dir>            Loose chunk folder (default: auto-detect depot/<id>/chunk)");
            Console.WriteLine("  -chunkstore <dir>        Packed chunkstore folder (mutually exclusive with -chunks)");
            Console.WriteLine("  -filelist <file>         Only reconstruct files matching this list (literal paths");
            Console.WriteLine("                           or \"regex:<pattern>\" lines)");
            Console.WriteLine("  -files <list>            Same as -filelist, inline: \";\"-separated literal paths and/or");
            Console.WriteLine("                           \"regex:<pattern>\" entries. Combines with -filelist if both given.");
            Console.WriteLine("  -list-files, -list       List every file recorded in the manifest and exit - no");
            Console.WriteLine("                           reconstruction happens, -output/-chunks/-chunkstore aren't needed.");
            Console.WriteLine("                           Plain output is one path per line, directly reusable as -filelist");
            Console.WriteLine("                           input; add -verbose for type/size/chunk-count per file.");
            Console.WriteLine("  -validate                Verify each file's whole-content SHA1 after writing");
            Console.WriteLine("  -threads <count>         Max parallel file writers (default: CPU count - 1)");
            Console.WriteLine("  -fail-fast               Stop enqueuing further files after the first failure");
            Console.WriteLine("  -verbose, -v             Show per-file progress output (or extra columns with -list-files)");
            Console.WriteLine();
            Console.WriteLine("Every in-scope file is always rewritten from scratch - reconstruct is safe to");
            Console.WriteLine("re-run after an interruption, nothing partial is ever trusted or reused. Without");
            Console.WriteLine("-filelist/-files, every file in the manifest is in scope - from a single file up to");
            Console.WriteLine("the whole depot is just a matter of how narrow or wide that filter is.");
            Console.WriteLine();
            Console.WriteLine("A raw-saved manifest (.manif4/.manif5) stores filenames AES-encrypted and");
            Console.WriteLine("base64-wrapped, not human-readable - a depot key is required to decrypt them,");
            Console.WriteLine("for -list-files just as much as for actually reconstructing.");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -depot 4001");
            Console.WriteLine("  depotdownloader reconstruct depot/4001/manifest/123.manif5 -output game/ -depotkey-file depot/4001/4001.depotkey");
            Console.WriteLine("  depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -chunkstore chunkstore/ -validate");
            Console.WriteLine("  depotdownloader reconstruct depot/4001/manifest/123.manif5 -depotkey-file depot/4001/4001.depotkey -list-files");
            Console.WriteLine("  depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -files \"bin/game.exe;regex:^assets/.*\\.dds$\"");
        }
    }
}
