// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
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

        private static void PrintChunkValidationUsage()
        {
            Console.WriteLine("Chunk Validation Commands:");
            Console.WriteLine();
            Console.WriteLine("  validate-depot <depot-path> [manifest-path] [-verbose] [-threads <count>]");
            Console.WriteLine("    Validate all chunks in a depot directory");
            Console.WriteLine("    depot-path     : Path to depot directory (e.g., 'depot/12345')");
            Console.WriteLine("    manifest-path  : Optional path to manifest file for chunk sizes");
            Console.WriteLine("    -verbose       : Show detailed output for each chunk");
            Console.WriteLine("    -threads <#>   : Number of threads to use (0 = auto-detect with overprovisioning)");
            Console.WriteLine("                     Auto-detect uses 2x CPU cores for optimal I/O + CPU utilization");
            Console.WriteLine();
            Console.WriteLine("  validate-chunk <chunk-file> <depot-key-file> [uncompressed-length]");
            Console.WriteLine("    Validate a single chunk file");
            Console.WriteLine("    chunk-file         : Path to chunk file");
            Console.WriteLine("    depot-key-file     : Path to depot key file");
            Console.WriteLine("    uncompressed-length: Expected uncompressed size (optional)");
            Console.WriteLine();
            Console.WriteLine("Threading Examples:");
            Console.WriteLine("  depotdownloader validate-depot depot/12345                    # Auto-detect (2x CPU cores)");
            Console.WriteLine("  depotdownloader validate-depot depot/12345 -threads 16        # Use 16 threads exactly");
            Console.WriteLine("  depotdownloader validate-depot depot/12345 -threads 1         # Single-threaded mode");
            Console.WriteLine("  depotdownloader validate-depot depot/12345 -verbose -threads 0 # Auto + verbose");
            Console.WriteLine();
            Console.WriteLine("Performance Notes:");
            Console.WriteLine("  • Auto-threading uses overprovisioning (more threads than CPU cores)");
            Console.WriteLine("  • Extra threads wait for I/O completion, improving overall throughput");
            Console.WriteLine("  • Similar strategy to Dolphin-Tools compression for mixed workloads");
        }
    }
}
