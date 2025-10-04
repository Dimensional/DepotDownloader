// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Standalone tool for validating depot chunks without requiring Steam connection
    /// Supports validation of both loose chunk files and chunkstore sets
    /// </summary>
    public static class StandaloneChunkValidator
    {
        #region Loose File Validation (Existing Functionality)

        /// <summary>
        /// Validate all chunks in a depot directory structure
        /// </summary>
        /// <param name="depotPath">Path to depot directory (e.g., "depot/12345")</param>
        /// <param name="manifestPath">Optional path to manifest file (currently unused - size detection is automatic)</param>
        /// <param name="verbose">Show detailed output for each chunk</param>
        /// <param name="maxThreads">Maximum number of threads to use for validation (0 = auto-detect with overprovisioning)</param>
        /// <returns>Validation summary</returns>
        public static async Task<ValidationSummary> ValidateDepotChunksAsync(string depotPath, string manifestPath = null, bool verbose = false, int maxThreads = 0)
        {
            var summary = new ValidationSummary();

            if (!Directory.Exists(depotPath))
            {
                Console.WriteLine($"Error: Depot directory not found: {depotPath}");
                return summary;
            }

            // Look for depot key
            var depotKeyPath = Directory.GetFiles(depotPath, "*.depotkey").FirstOrDefault();
            if (depotKeyPath == null)
            {
                Console.WriteLine($"Error: No depot key found in {depotPath}");
                return summary;
            }

            var depotKey = await File.ReadAllBytesAsync(depotKeyPath);
            Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");

            // Look for chunks directory
            var chunksDir = Path.Combine(depotPath, "chunk");
            if (!Directory.Exists(chunksDir))
            {
                Console.WriteLine($"Error: Chunks directory not found: {chunksDir}");
                return summary;
            }

            // Note about manifest parameter
            if (!string.IsNullOrEmpty(manifestPath))
            {
                Console.WriteLine($"Note: Manifest parameter provided but not used - chunk sizes are auto-detected");
            }

            // Find all chunk files
            var chunkFiles = Directory.GetFiles(chunksDir, "*", SearchOption.TopDirectoryOnly)
                                     .Where(f => !Path.HasExtension(f)) // Chunk files have no extension
                                     .ToList();

            summary.TotalChunks = chunkFiles.Count;

            // Smart thread count calculation (like Dolphin-Tools approach)
            if (maxThreads <= 0)
            {
                // Use overprovisioning for mixed I/O and CPU workload
                var cpuCores = Environment.ProcessorCount;

                // For chunk validation (mixed I/O + CPU), optimal is usually 1.5x to 2x CPU cores
                // This allows threads to wait for I/O while others use CPU
                maxThreads = Math.Min(cpuCores * 2, 32); // Cap at 32 to avoid excessive overhead

                Console.WriteLine($"Auto-detected thread count: {maxThreads} (CPU cores: {cpuCores}, ratio: {(double)maxThreads / cpuCores:F1}x)");
            }
            else
            {
                Console.WriteLine($"Using custom thread count: {maxThreads}");
            }

            Console.WriteLine($"Found {chunkFiles.Count} chunk files to validate using {maxThreads} threads");

            // Use thread-safe collections for results (like Python's Queue)
            var validChunks = new System.Collections.Concurrent.ConcurrentBag<string>();
            var invalidChunks = new System.Collections.Concurrent.ConcurrentBag<(string chunkId, string error)>();
            var errorChunks = new System.Collections.Concurrent.ConcurrentBag<(string chunkId, string error)>();

            // Advanced parallel validation with overprovisioning
            // Using SemaphoreSlim to control active thread count while allowing more threads to queue
            using var semaphore = new SemaphoreSlim(Environment.ProcessorCount, Environment.ProcessorCount);

            var tasks = chunkFiles.Select(async chunkFile =>
            {
                var chunkId = Path.GetFileName(chunkFile);

                // Wait for a CPU slot to become available (this is where threads wait, like in Dolphin-Tools)
                await semaphore.WaitAsync();

                try
                {
                    // ChunkValidator is thread-safe - safe to call concurrently
                    var result = await ChunkValidator.ValidateRawChunkAsync(chunkFile, depotKey, 0);

                    if (result.IsValid)
                    {
                        validChunks.Add(chunkId);
                        if (verbose)
                        {
                            // Thread-safe console output
                            lock (Console.Out)
                            {
                                Console.WriteLine($"✓ {chunkId} - Valid ({result.DecompressedSize} bytes)");
                            }
                        }
                    }
                    else
                    {
                        invalidChunks.Add((chunkId, result.ErrorMessage));
                        // Always show invalid chunks
                        lock (Console.Out)
                        {
                            Console.WriteLine($"✗ {chunkId} - {result.ErrorMessage}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    errorChunks.Add((chunkId, ex.Message));
                    // Always show error chunks
                    lock (Console.Out)
                    {
                        Console.WriteLine($"✗ {chunkId} - Error: {ex.Message}");
                    }
                }
                finally
                {
                    // Release the CPU slot for the next waiting thread
                    semaphore.Release();
                }
            });

            // Wait for all validation tasks to complete
            await Task.WhenAll(tasks);

            // Update summary with results
            summary.ValidChunks = validChunks.Count;
            summary.InvalidChunks = invalidChunks.Count;
            summary.ErrorChunks = errorChunks.Count;

            return summary;
        }

        /// <summary>
        /// Validate a single chunk file
        /// </summary>
        /// <param name="chunkFilePath">Path to chunk file</param>
        /// <param name="depotKeyPath">Path to depot key file</param>
        /// <param name="uncompressedLength">Expected uncompressed length (ignored - size is auto-detected)</param>
        /// <returns>Validation result</returns>
        public static async Task<ValidationResult> ValidateSingleChunkAsync(string chunkFilePath, string depotKeyPath, uint uncompressedLength = 0)
        {
            if (!File.Exists(depotKeyPath))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Depot key file not found: {depotKeyPath}"
                };
            }

            var depotKey = await File.ReadAllBytesAsync(depotKeyPath);

            // Use dynamic size detection (uncompressedLength parameter is ignored)
            return await ChunkValidator.ValidateRawChunkAsync(chunkFilePath, depotKey, 0);
        }

        #endregion

        #region Chunkstore Validation (New Functionality)

        /// <summary>
        /// Validates all chunks in a chunkstore
        /// </summary>
        /// <param name="chunkstorePath">Path to chunkstore folder</param>
        /// <param name="depotId">Depot ID (optional - will auto-detect if only one depot exists)</param>
        /// <param name="depotKeyPath">Path to depot key file (optional - will look for .depotkey files)</param>
        /// <param name="verbose">Show detailed output for each chunk</param>
        /// <param name="maxThreads">Maximum number of threads to use for validation (0 = auto-detect)</param>
        /// <returns>Validation summary</returns>
        public static async Task<ValidationSummary> ValidateChunkstoreAsync(
            string chunkstorePath,
            uint? depotId = null,
            string depotKeyPath = null,
            bool verbose = false,
            int maxThreads = 0)
        {
            var summary = new ValidationSummary();

            if (!Directory.Exists(chunkstorePath))
            {
                Console.WriteLine($"Error: Chunkstore directory not found: {chunkstorePath}");
                return summary;
            }

            try
            {
                // Load depot key
                byte[] depotKey = null;
                if (!string.IsNullOrEmpty(depotKeyPath))
                {
                    if (!File.Exists(depotKeyPath))
                    {
                        Console.WriteLine($"Error: Depot key file not found: {depotKeyPath}");
                        return summary;
                    }
                    depotKey = await File.ReadAllBytesAsync(depotKeyPath);
                    Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");
                }
                else
                {
                    // Look for depot key files in the chunkstore directory
                    var depotKeyFiles = Directory.GetFiles(chunkstorePath, "*.depotkey");
                    if (depotKeyFiles.Length > 0)
                    {
                        depotKey = await File.ReadAllBytesAsync(depotKeyFiles[0]);
                        Console.WriteLine($"Auto-detected depot key: {Path.GetFileName(depotKeyFiles[0])}");
                    }
                }

                // Initialize chunkstore
                using var chunkstore = new Chunkstore(chunkstorePath, depotId, depotKey);
                var stats = chunkstore.GetStats();

                Console.WriteLine($"Chunkstore loaded: {stats}");

                if (stats.TotalChunks == 0)
                {
                    Console.WriteLine("No chunks found in chunkstore");
                    return summary;
                }

                summary.TotalChunks = stats.TotalChunks;

                // Determine thread count
                if (maxThreads <= 0)
                {
                    var cpuCores = Environment.ProcessorCount;
                    maxThreads = Math.Min(cpuCores * 2, 32);
                    Console.WriteLine($"Auto-detected thread count: {maxThreads} (CPU cores: {cpuCores}, ratio: {(double)maxThreads / cpuCores:F1}x)");
                }
                else
                {
                    Console.WriteLine($"Using custom thread count: {maxThreads}");
                }

                Console.WriteLine($"Validating {stats.TotalChunks:N0} chunks from chunkstore using {maxThreads} threads");

                // Validate all chunks in parallel
                var progressCount = 0;
                var results = await ChunkValidator.ValidateAllChunkstoreChunksAsync(
                    chunkstore,
                    depotKey,
                    maxThreads,
                    progress: (validated, total) =>
                    {
                        var newCount = Interlocked.Exchange(ref progressCount, validated);
                        if (validated % 100 == 0 || validated == total || validated - newCount >= 50)
                        {
                            Console.WriteLine($"Progress: {validated:N0}/{total:N0} chunks validated ({(validated * 100.0 / total):F1}%)");
                        }
                    });

                // Process results
                foreach (var kvp in results)
                {
                    var chunkId = kvp.Key;
                    var result = kvp.Value;

                    if (result.IsValid)
                    {
                        summary.ValidChunks++;
                        if (verbose)
                        {
                            Console.WriteLine($"✓ {chunkId} - Valid ({result.DecompressedSize} bytes)");
                        }
                    }
                    else
                    {
                        summary.InvalidChunks++;
                        Console.WriteLine($"✗ {chunkId} - {result.ErrorMessage}");
                    }
                }

                return summary;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating chunkstore: {ex.Message}");
                summary.ErrorChunks = 1; // Mark as having errors
                return summary;
            }
        }

        /// <summary>
        /// Validates specific chunks in a chunkstore
        /// </summary>
        /// <param name="chunkstorePath">Path to chunkstore folder</param>
        /// <param name="chunkShaList">List of chunk SHA1 hashes to validate</param>
        /// <param name="depotId">Depot ID (optional - will auto-detect if only one depot exists)</param>
        /// <param name="depotKeyPath">Path to depot key file (optional - will look for .depotkey files)</param>
        /// <param name="verbose">Show detailed output for each chunk</param>
        /// <param name="maxThreads">Maximum number of threads to use for validation (0 = auto-detect)</param>
        /// <returns>Validation summary</returns>
        public static async Task<ValidationSummary> ValidateChunkstoreChunksAsync(
            string chunkstorePath,
            IEnumerable<string> chunkShaList,
            uint? depotId = null,
            string depotKeyPath = null,
            bool verbose = false,
            int maxThreads = 0)
        {
            var summary = new ValidationSummary();
            var chunks = chunkShaList.ToList();
            summary.TotalChunks = chunks.Count;

            if (!Directory.Exists(chunkstorePath))
            {
                Console.WriteLine($"Error: Chunkstore directory not found: {chunkstorePath}");
                return summary;
            }

            if (chunks.Count == 0)
            {
                Console.WriteLine("No chunks specified for validation");
                return summary;
            }

            try
            {
                // Load depot key
                byte[] depotKey = null;
                if (!string.IsNullOrEmpty(depotKeyPath))
                {
                    if (!File.Exists(depotKeyPath))
                    {
                        Console.WriteLine($"Error: Depot key file not found: {depotKeyPath}");
                        return summary;
                    }
                    depotKey = await File.ReadAllBytesAsync(depotKeyPath);
                    Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");
                }
                else
                {
                    // Look for depot key files in the chunkstore directory
                    var depotKeyFiles = Directory.GetFiles(chunkstorePath, "*.depotkey");
                    if (depotKeyFiles.Length > 0)
                    {
                        depotKey = await File.ReadAllBytesAsync(depotKeyFiles[0]);
                        Console.WriteLine($"Auto-detected depot key: {Path.GetFileName(depotKeyFiles[0])}");
                    }
                }

                // Initialize chunkstore
                using var chunkstore = new Chunkstore(chunkstorePath, depotId, depotKey);
                var stats = chunkstore.GetStats();

                Console.WriteLine($"Chunkstore loaded: {stats}");

                // Determine thread count
                if (maxThreads <= 0)
                {
                    var cpuCores = Environment.ProcessorCount;
                    maxThreads = Math.Min(cpuCores * 2, 32);
                    Console.WriteLine($"Auto-detected thread count: {maxThreads} (CPU cores: {cpuCores}, ratio: {(double)maxThreads / cpuCores:F1}x)");
                }
                else
                {
                    Console.WriteLine($"Using custom thread count: {maxThreads}");
                }

                Console.WriteLine($"Validating {chunks.Count:N0} specified chunks from chunkstore using {maxThreads} threads");

                // Validate specified chunks in parallel
                var progressCount = 0;
                var results = await ChunkValidator.ValidateChunkstoreChunksAsync(
                    chunkstore,
                    chunks,
                    depotKey,
                    maxThreads,
                    progress: (validated, total) =>
                    {
                        var newCount = Interlocked.Exchange(ref progressCount, validated);
                        if (validated % 100 == 0 || validated == total || validated - newCount >= 50)
                        {
                            Console.WriteLine($"Progress: {validated:N0}/{total:N0} chunks validated ({(validated * 100.0 / total):F1}%)");
                        }
                    });

                // Process results
                foreach (var kvp in results)
                {
                    var chunkId = kvp.Key;
                    var result = kvp.Value;

                    if (result.IsValid)
                    {
                        summary.ValidChunks++;
                        if (verbose)
                        {
                            Console.WriteLine($"✓ {chunkId} - Valid ({result.DecompressedSize} bytes)");
                        }
                    }
                    else
                    {
                        summary.InvalidChunks++;
                        Console.WriteLine($"✗ {chunkId} - {result.ErrorMessage}");
                    }
                }

                return summary;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating chunkstore chunks: {ex.Message}");
                summary.ErrorChunks = 1; // Mark as having errors
                return summary;
            }
        }

        #endregion
    }

    /// <summary>
    /// Summary of chunk validation results
    /// </summary>
    public class ValidationSummary
    {
        public int TotalChunks { get; set; }
        public int ValidChunks { get; set; }
        public int InvalidChunks { get; set; }
        public int ErrorChunks { get; set; }

        public double ValidPercentage => TotalChunks > 0 ? (ValidChunks / (double)TotalChunks) * 100.0 : 0.0;

        public override string ToString()
        {
            return $"Validation Summary: {ValidChunks}/{TotalChunks} valid ({ValidPercentage:F1}%), " +
                   $"{InvalidChunks} invalid, {ErrorChunks} errors";
        }
    }
}
