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
    /// Command-line chunk validation utility
    /// </summary>
    public static class ChunkValidatorProgram
    {
        /// <summary>
        /// Run chunk validation from command line arguments
        /// </summary>
        /// <param name="args">Command line arguments</param>
        /// <returns>Exit code</returns>
        public static async Task<int> RunChunkValidationAsync(string[] args)
        {
            if (args.Length < 2)
            {
                PrintChunkValidationUsage();
                return 1;
            }

            var command = args[0].ToLowerInvariant();

            try
            {
                switch (command)
                {
                    case "validate-depot":
                        return await ValidateDepotCommand(args[1..]);

                    case "validate-chunk":
                        return await ValidateChunkCommand(args[1..]);

                    case "validate-chunkstore":
                        return await ValidateChunkstoreCommand(args[1..]);

                    case "validate-chunkstore-chunks":
                        return await ValidateChunkstoreChunksCommand(args[1..]);

                    default:
                        Console.WriteLine($"Unknown validation command: {command}");
                        PrintChunkValidationUsage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> ValidateDepotCommand(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: validate-depot <depot-path> [manifest-path] [-verbose] [-threads <count>]");
                return 1;
            }

            var depotPath = args[0];
            string manifestPath = null;
            var verbose = false;
            var threads = 0; // Default to auto-detect

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "-verbose" || args[i] == "-v")
                {
                    verbose = true;
                }
                else if (args[i] == "-threads" || args[i] == "-t")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out var threadCount))
                    {
                        threads = threadCount;
                        i++; // Skip the thread count argument
                    }
                }
                else if (manifestPath == null)
                {
                    manifestPath = args[i];
                }
            }

            Console.WriteLine($"Validating depot: {depotPath}");
            if (!string.IsNullOrEmpty(manifestPath))
            {
                Console.WriteLine($"Using manifest: {manifestPath}");
            }

            var summary = await StandaloneChunkValidator.ValidateDepotChunksAsync(depotPath, manifestPath, verbose, threads);

            Console.WriteLine();
            Console.WriteLine(summary);

            return summary.InvalidChunks > 0 || summary.ErrorChunks > 0 ? 1 : 0;
        }

        private static async Task<int> ValidateChunkCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: validate-chunk <chunk-file> <depot-key-file> [uncompressed-length]");
                return 1;
            }

            var chunkFile = args[0];
            var depotKeyFile = args[1];
            uint uncompressedLength = 0;

            if (args.Length > 2 && uint.TryParse(args[2], out var length))
            {
                uncompressedLength = length;
            }

            Console.WriteLine($"Validating chunk: {chunkFile}");
            Console.WriteLine($"Using depot key: {depotKeyFile}");

            var result = await StandaloneChunkValidator.ValidateSingleChunkAsync(chunkFile, depotKeyFile, uncompressedLength);

            Console.WriteLine(result);

            return result.IsValid ? 0 : 1;
        }

        private static async Task<int> ValidateChunkstoreCommand(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: validate-chunkstore <chunkstore-path> [-depot <depot-id>] [-key <depot-key-file>] [-verbose] [-threads <count>]");
                return 1;
            }

            var chunkstorePath = args[0];
            uint? depotId = null;
            string depotKeyPath = null;
            var verbose = false;
            var threads = 0; // Default to auto-detect

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "-depot" || args[i] == "-d")
                {
                    if (i + 1 < args.Length && uint.TryParse(args[i + 1], out var depot))
                    {
                        depotId = depot;
                        i++; // Skip the depot ID argument
                    }
                }
                else if (args[i] == "-key" || args[i] == "-k")
                {
                    if (i + 1 < args.Length)
                    {
                        depotKeyPath = args[i + 1];
                        i++; // Skip the key path argument
                    }
                }
                else if (args[i] == "-verbose" || args[i] == "-v")
                {
                    verbose = true;
                }
                else if (args[i] == "-threads" || args[i] == "-t")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out var threadCount))
                    {
                        threads = threadCount;
                        i++; // Skip the thread count argument
                    }
                }
            }

            Console.WriteLine($"Validating chunkstore: {chunkstorePath}");
            if (depotId.HasValue)
            {
                Console.WriteLine($"Depot ID: {depotId}");
            }
            if (!string.IsNullOrEmpty(depotKeyPath))
            {
                Console.WriteLine($"Using depot key: {depotKeyPath}");
            }

            var summary = await StandaloneChunkValidator.ValidateChunkstoreAsync(chunkstorePath, depotId, depotKeyPath, verbose, threads);

            Console.WriteLine();
            Console.WriteLine(summary);

            return summary.InvalidChunks > 0 || summary.ErrorChunks > 0 ? 1 : 0;
        }

        private static async Task<int> ValidateChunkstoreChunksCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: validate-chunkstore-chunks <chunkstore-path> <chunk-list-file> [-depot <depot-id>] [-key <depot-key-file>] [-verbose] [-threads <count>]");
                return 1;
            }

            var chunkstorePath = args[0];
            var chunkListFile = args[1];
            uint? depotId = null;
            string depotKeyPath = null;
            var verbose = false;
            var threads = 0; // Default to auto-detect

            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "-depot" || args[i] == "-d")
                {
                    if (i + 1 < args.Length && uint.TryParse(args[i + 1], out var depot))
                    {
                        depotId = depot;
                        i++; // Skip the depot ID argument
                    }
                }
                else if (args[i] == "-key" || args[i] == "-k")
                {
                    if (i + 1 < args.Length)
                    {
                        depotKeyPath = args[i + 1];
                        i++; // Skip the key path argument
                    }
                }
                else if (args[i] == "-verbose" || args[i] == "-v")
                {
                    verbose = true;
                }
                else if (args[i] == "-threads" || args[i] == "-t")
                {
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out var threadCount))
                    {
                        threads = threadCount;
                        i++; // Skip the thread count argument
                    }
                }
            }

            if (!File.Exists(chunkListFile))
            {
                Console.WriteLine($"Error: Chunk list file not found: {chunkListFile}");
                return 1;
            }

            // Read chunk list from file
            var chunkList = new List<string>();
            try
            {
                var lines = await File.ReadAllLinesAsync(chunkListFile);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (!string.IsNullOrEmpty(trimmed) && !trimmed.StartsWith("#"))
                    {
                        // Support both hex strings and comma-separated values
                        if (trimmed.Contains(','))
                        {
                            var parts = trimmed.Split(',');
                            chunkList.Add(parts[0].Trim()); // Take first column as SHA1
                        }
                        else
                        {
                            chunkList.Add(trimmed);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading chunk list file: {ex.Message}");
                return 1;
            }

            if (chunkList.Count == 0)
            {
                Console.WriteLine("No chunks found in chunk list file");
                return 1;
            }

            Console.WriteLine($"Validating chunkstore: {chunkstorePath}");
            Console.WriteLine($"Chunk list file: {chunkListFile} ({chunkList.Count} chunks)");
            if (depotId.HasValue)
            {
                Console.WriteLine($"Depot ID: {depotId}");
            }
            if (!string.IsNullOrEmpty(depotKeyPath))
            {
                Console.WriteLine($"Using depot key: {depotKeyPath}");
            }

            var summary = await StandaloneChunkValidator.ValidateChunkstoreChunksAsync(chunkstorePath, chunkList, depotId, depotKeyPath, verbose, threads);

            Console.WriteLine();
            Console.WriteLine(summary);

            return summary.InvalidChunks > 0 || summary.ErrorChunks > 0 ? 1 : 0;
        }

        /// <summary>
        /// Print comprehensive validation help information
        /// </summary>
        public static void PrintValidationHelp()
        {
            Console.WriteLine("=== DEPOT DOWNLOADER VALIDATION GUIDE ===");
            Console.WriteLine();
            Console.WriteLine("DepotDownloader supports three types of validation:");
            Console.WriteLine();

            Console.WriteLine("1. DOWNLOAD-TIME VALIDATION (-validate-chunks)");
            Console.WriteLine("   Purpose: Validate chunks as they are downloaded to ensure data integrity");
            Console.WriteLine("   Usage:   Add -validate-chunks to any download command");
            Console.WriteLine("   Impact:  Slower downloads, but ensures perfect data integrity");
            Console.WriteLine("   Action:  Automatically retries failed chunks until validation passes");
            Console.WriteLine();
            Console.WriteLine("   Examples:");
            Console.WriteLine("     depotdownloader download -app 4000 -depot 4001 -validate-chunks");
            Console.WriteLine("     depotdownloader download -manifest-csv manifests.csv -validate-chunks");
            Console.WriteLine();

            Console.WriteLine("2. POST-DOWNLOAD VALIDATION (-validate)");
            Console.WriteLine("   Purpose: Verify existing downloaded files against their checksums");
            Console.WriteLine("   Usage:   Add -validate to any download command");
            Console.WriteLine("   Impact:  Re-downloads files that fail checksum verification");
            Console.WriteLine("   Scope:   Works with installed files (not raw archives)");
            Console.WriteLine();
            Console.WriteLine("   Examples:");
            Console.WriteLine("     depotdownloader download -app 4000 -depot 4001 -validate");
            Console.WriteLine();

            Console.WriteLine("3. STANDALONE VALIDATION (validate-depot / validate-chunk / validate-chunkstore)");
            Console.WriteLine("   Purpose: Offline validation of raw depot archives, requires depot keys");
            Console.WriteLine("   Usage:   Special commands that don't require Steam login");
            Console.WriteLine("   Input:   Raw depot directories or chunkstore files created with -raw mode");
            Console.WriteLine("   Process: Decrypt -> Decompress -> Verify SHA1 hash");
            Console.WriteLine();

            PrintChunkValidationUsage();

            Console.WriteLine("WORKFLOW RECOMMENDATIONS:");
            Console.WriteLine("1. Download with raw mode to create archives:");
            Console.WriteLine("   depotdownloader download -app 4000 -depot 4001 -raw");
            Console.WriteLine();
            Console.WriteLine("2a. Validate loose files with multithreading:");
            Console.WriteLine("    depotdownloader validate-depot depot/4001 -verbose -threads 16");
            Console.WriteLine();
            Console.WriteLine("2b. OR convert to chunkstore and validate (future):");
            Console.WriteLine("    depotdownloader chunkstore pack depot/4001/chunk chunkstore/");
            Console.WriteLine("    depotdownloader validate-chunkstore chunkstore/ -verbose -threads 16");
            Console.WriteLine();
            Console.WriteLine("3. For critical data, use -validate-chunks during download:");
            Console.WriteLine("   depotdownloader download -app 4000 -depot 4001 -raw -validate-chunks");
            Console.WriteLine();

            Console.WriteLine("For general help: depotdownloader help");
        }

        private static void PrintChunkValidationUsage()
        {
            Console.WriteLine("Chunk Validation Commands:");
            Console.WriteLine();
            Console.WriteLine("For complete validation guide: depotdownloader help validation");
            Console.WriteLine();
            Console.WriteLine("COMMANDS:");
            Console.WriteLine("  validate-depot <depot-path> [manifest-path] [OPTIONS...]");
            Console.WriteLine("    Validate all chunks in a depot directory");
            Console.WriteLine();
            Console.WriteLine("  validate-chunk <chunk-file> <depot-key-file> [uncompressed-length]");
            Console.WriteLine("    Validate a single chunk file");
            Console.WriteLine();
            Console.WriteLine("  validate-chunkstore <chunkstore-path> [OPTIONS...]");
            Console.WriteLine("    Validate all chunks in a chunkstore");
            Console.WriteLine();
            Console.WriteLine("  validate-chunkstore-chunks <chunkstore-path> <chunk-list-file> [OPTIONS...]");
            Console.WriteLine("    Validate specific chunks in a chunkstore");
            Console.WriteLine();
            Console.WriteLine("OPTIONS:");
            Console.WriteLine("  -verbose, -v     Show detailed output for each chunk");
            Console.WriteLine("  -threads, -t <#> Number of threads to use (0 = auto-detect)");
            Console.WriteLine("  -depot, -d <id>  Depot ID (for chunkstore commands)");
            Console.WriteLine("  -key, -k <file>  Path to depot key file");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  depotdownloader validate-depot depot/12345 -verbose");
            Console.WriteLine("  depotdownloader validate-chunkstore chunkstore/ -threads 16");
            Console.WriteLine("  depotdownloader validate-chunk chunk.bin key.bin");
            Console.WriteLine();
            Console.WriteLine("For detailed help: depotdownloader help validation");
        }
    }
}
