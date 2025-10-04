// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
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
                Console.WriteLine("  -max-file-size <bytes>   Maximum size per CSD file (default: 2GB)");
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

            // Parse options
            uint? depotId = null;
            bool? isEncrypted = null;
            long maxFileSize = 2L * 1024 * 1024 * 1024; // 2GB default
            int maxParallelism = 0;
            int batchSize = 1000;
            int checkpointInterval = 5000;

            for (int i = 2; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "-depot":
                        if (i + 1 < args.Length && uint.TryParse(args[i + 1], out var depot))
                        {
                            depotId = depot;
                            i++;
                        }
                        break;
                    case "-encrypted":
                        isEncrypted = true;
                        break;
                    case "-decrypted":
                        isEncrypted = false;
                        break;
                    case "-max-file-size":
                        if (i + 1 < args.Length && long.TryParse(args[i + 1], out var maxSize))
                        {
                            maxFileSize = maxSize;
                            i++;
                        }
                        break;
                    case "-threads":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out var threads))
                        {
                            maxParallelism = threads;
                            i++;
                        }
                        break;
                    case "-batch-size":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out var batch))
                        {
                            batchSize = batch;
                            i++;
                        }
                        break;
                    case "-checkpoint-interval":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out var checkpoint))
                        {
                            checkpointInterval = checkpoint;
                            i++;
                        }
                        break;
                }
            }

            if (depotId == null)
            {
                Console.WriteLine("Error: -depot <id> is required for packing operation");
                return 1;
            }

            Directory.CreateDirectory(outputFolder);

            // Get all chunk files
            var chunkFiles = Directory.GetFiles(inputFolder, "*", SearchOption.AllDirectories)
                .Where(f =>
                {
                    var name = Path.GetFileName(f);
                    return name.Length >= 40 && name.All(c => char.IsAsciiHexDigit(c) || c == '_');
                })
                .ToList();

            Console.WriteLine($"Found {chunkFiles.Count:N0} chunk files to pack");

            if (chunkFiles.Count == 0)
            {
                Console.WriteLine("No chunk files found in input directory");
                return 1;
            }

            // Auto-detect encryption if not specified
            if (isEncrypted == null)
            {
                var sampleFile = chunkFiles.First();
                var fileName = Path.GetFileName(sampleFile);
                isEncrypted = !fileName.Contains("_decrypted");
                Console.WriteLine($"Auto-detected encryption status: {(isEncrypted.Value ? "encrypted" : "decrypted")}");
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

            // Parse options
            uint? depotId = null;
            int maxParallelism = 0;
            bool skipExisting = true;

            for (int i = 2; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "-depot":
                        if (i + 1 < args.Length && uint.TryParse(args[i + 1], out var depot))
                        {
                            depotId = depot;
                            i++;
                        }
                        break;
                    case "-threads":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out var threads))
                        {
                            maxParallelism = threads;
                            i++;
                        }
                        break;
                    case "-overwrite":
                        skipExisting = false;
                        break;
                }
            }

            using var chunkstore = new Chunkstore(chunkstoreFolder, depotId);

            var stats = chunkstore.GetStats();
            Console.WriteLine($"Unpacking chunkstore: {stats}");

            await chunkstore.UnpackAllAsync(outputFolder, maxParallelism, skipExisting);

            Console.WriteLine("Unpack complete!");
            return 0;
        }

        private static async Task<int> VerifyCommand(string[] args)
        {
            Console.WriteLine("Verify command will use existing validation infrastructure");
            Console.WriteLine("For now, use: depotdownloader validate-chunkstore <path> [options]");
            return await Task.FromResult(1);
        }

        private static async Task<int> RebuildCommand(string[] args)
        {
            Console.WriteLine("Rebuild command is not yet implemented.");
            Console.WriteLine("This will unpack and repack the chunkstore for optimal ordering.");
            return await Task.FromResult(1);
        }

        private static async Task<int> UpdateCommand(string[] args)
        {
            Console.WriteLine("Update command is not yet implemented.");
            Console.WriteLine("This will add new chunks and rebuild for consistency.");
            return await Task.FromResult(1);
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

            // Parse options
            uint? depotId = null;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "-depot":
                        if (i + 1 < args.Length && uint.TryParse(args[i + 1], out var depot))
                        {
                            depotId = depot;
                            i++;
                        }
                        break;
                }
            }

            using var chunkstore = new Chunkstore(chunkstoreFolder, depotId);

            var stats = chunkstore.GetStats();
            Console.WriteLine();
            Console.WriteLine("=== CHUNKSTORE STATISTICS ===");
            Console.WriteLine(stats);

            // Additional detailed stats
            var chunks = chunkstore.EnumerateChunks().ToList();
            if (chunks.Count > 0)
            {
                var chunkSizes = chunks.Select(c => c.Length).ToList();
                var averageSize = chunkSizes.Average();
                var minSize = chunkSizes.Min();
                var maxSize = chunkSizes.Max();

                Console.WriteLine();
                Console.WriteLine("=== CHUNK SIZE ANALYSIS ===");
                Console.WriteLine($"Average chunk size: {averageSize:N0} bytes");
                Console.WriteLine($"Smallest chunk:     {minSize:N0} bytes");
                Console.WriteLine($"Largest chunk:      {maxSize:N0} bytes");

                // File distribution
                var fileDistribution = chunks.GroupBy(c => c.ChunkstoreIndex)
                    .ToDictionary(g => g.Key, g => g.Count());

                Console.WriteLine();
                Console.WriteLine("=== FILE DISTRIBUTION ===");
                foreach (var kvp in fileDistribution.OrderBy(x => x.Key))
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
            Console.WriteLine("  update   - Incremental: add new chunks + rebuild for consistency");
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
