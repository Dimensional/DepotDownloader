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
        #region Shared Helpers

        /// <summary>
        /// Resolves the thread count to use for validation: an explicit request is used as-is,
        /// otherwise overprovisions relative to CPU count (validation is a mixed I/O + CPU
        /// workload - threads spend much of their time waiting on disk, so more threads than
        /// cores keeps CPU busy while others wait), capped to avoid excessive overhead. This is
        /// deliberately a different formula than <see cref="Util.ResolveParallelism"/> (used for
        /// chunkstore pack/rebuild/reconstruct, which are more write/CPU-bound) - not a missed
        /// consolidation, both are the right default for their own kind of workload.
        /// </summary>
        private static int ResolveValidationThreadCount(int requested)
        {
            if (requested > 0)
            {
                Console.WriteLine($"Using custom thread count: {requested}");
                return requested;
            }

            var cpuCores = Environment.ProcessorCount;
            var maxThreads = Math.Min(cpuCores * 2, 32); // Cap at 32 to avoid excessive overhead
            Console.WriteLine($"Auto-detected thread count: {maxThreads} (CPU cores: {cpuCores}, ratio: {(double)maxThreads / cpuCores:F1}x)");
            return maxThreads;
        }

        /// <summary>
        /// Resolves the depot key for a chunkstore - but only when it's actually encrypted; an
        /// unencrypted chunkstore needs no key, and none is searched for or used even if one was
        /// given. When encrypted, checks in order: an explicit -depotkey path (must exist if
        /// given), a "*.depotkey" file in the same folder as the chunkstore itself, then the
        /// default raw-download location depot/&lt;depotId&gt;/&lt;depotId&gt;.depotkey (relative
        /// to the current directory - where ArchiveDepotRawAsync/ResolveEncryptedManifestIdsAsync
        /// already save one, one level above where a chunkstore packed from that raw archive
        /// typically lives). Finding nothing when one is actually needed is reported as a clear,
        /// specific failure - the alternative is every single chunk failing individually with a
        /// confusing "unknown compression format", which is what unencrypted-looking ciphertext
        /// produces when decryption never happens.
        /// </summary>
        private static async Task<(byte[] DepotKey, bool Failed)> ResolveChunkstoreDepotKeyAsync(string chunkstorePath, string depotKeyPath, bool isEncrypted, uint depotId)
        {
            if (!isEncrypted)
            {
                return (null, false);
            }

            if (!string.IsNullOrEmpty(depotKeyPath))
            {
                if (!File.Exists(depotKeyPath))
                {
                    Console.WriteLine($"Error: Depot key file not found: {depotKeyPath}");
                    return (null, true);
                }

                var depotKey = await File.ReadAllBytesAsync(depotKeyPath);
                Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");
                return (depotKey, false);
            }

            var localKeyFiles = Directory.GetFiles(chunkstorePath, "*.depotkey");
            if (localKeyFiles.Length > 0)
            {
                var depotKey = await File.ReadAllBytesAsync(localKeyFiles[0]);
                Console.WriteLine($"Auto-detected depot key: {Path.GetFileName(localKeyFiles[0])}");
                return (depotKey, false);
            }

            var defaultKeyPath = Path.Combine("depot", depotId.ToString(), $"{depotId}.depotkey");
            if (File.Exists(defaultKeyPath))
            {
                var depotKey = await File.ReadAllBytesAsync(defaultKeyPath);
                Console.WriteLine($"Auto-detected depot key: {defaultKeyPath}");
                return (depotKey, false);
            }

            Console.WriteLine($"Error: Chunkstore is encrypted but no depot key was found. Checked: " +
                $"-depotkey (not given), {chunkstorePath} (no *.depotkey file), and {defaultKeyPath} (not found). " +
                "Every chunk would otherwise fail with a misleading \"unknown compression format\" error. " +
                "Specify -depotkey, or place the .depotkey file in one of the checked locations.");
            return (null, true);
        }

        #endregion

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

            // Find all chunk files. Chunks never have an extension, whether still encrypted
            // ("<sha>") or already decrypted ("<sha>_decrypted") - each file's own name is
            // checked per-file below, so a folder can freely mix both.
            var chunkFiles = Directory.GetFiles(chunksDir, "*", SearchOption.TopDirectoryOnly)
                                     .Where(f => !Path.HasExtension(f)) // Chunk files have no extension
                                     .ToList();

            summary.TotalChunks = chunkFiles.Count;

            // Mixing encrypted and already-decrypted chunks in the same loose folder is legal (unlike
            // a chunkstore, which must be one mode or the other) - but it's still worth surfacing, since
            // an unexpected mix in this folder is usually a sign something upstream put files here it
            // shouldn't have. Report the breakdown up front rather than letting it pass unremarked.
            var decryptedCount = chunkFiles.Count(f => Path.GetFileName(f).EndsWith("_decrypted", StringComparison.Ordinal));
            var encryptedCount = chunkFiles.Count - decryptedCount;
            if (encryptedCount > 0 && decryptedCount > 0)
            {
                Console.WriteLine($"Note: folder contains a mix of {encryptedCount} encrypted and {decryptedCount} already-decrypted chunk(s) - each is validated according to its own filename.");
            }

            // A depot key is only needed if at least one chunk here is still encrypted; a folder
            // of already-decrypted chunks (e.g. unpacked from a decrypted chunkstore) needs none.
            var needsDepotKey = encryptedCount > 0;
            byte[] depotKey = null;

            if (needsDepotKey)
            {
                var depotKeyPath = Directory.GetFiles(depotPath, "*.depotkey").FirstOrDefault();
                if (depotKeyPath == null)
                {
                    Console.WriteLine($"Error: No depot key found in {depotPath}");
                    return summary;
                }

                depotKey = await File.ReadAllBytesAsync(depotKeyPath);
                Console.WriteLine($"Using depot key: {Path.GetFileName(depotKeyPath)}");
            }
            else
            {
                Console.WriteLine("All chunks are already decrypted - no depot key needed");
            }

            maxThreads = ResolveValidationThreadCount(maxThreads);

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
                    // A loose chunk's own name says whether it's still encrypted or already
                    // decrypted - same "<sha>"/"<sha>_decrypted" convention chunkstores use.
                    var isEncrypted = !chunkId.EndsWith("_decrypted", StringComparison.Ordinal);

                    // ChunkValidator is thread-safe - safe to call concurrently
                    var result = await ChunkValidator.ValidateRawChunkAsync(chunkFile, depotKey, isEncrypted, 0);

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

            // A loose chunk's own name says whether it's still encrypted or already decrypted.
            var isEncrypted = !Path.GetFileName(chunkFilePath).EndsWith("_decrypted", StringComparison.Ordinal);

            // Use dynamic size detection (uncompressedLength parameter is ignored)
            return await ChunkValidator.ValidateRawChunkAsync(chunkFilePath, depotKey, isEncrypted, 0);
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
            int maxThreads = 0,
            bool resume = true)
        {
            var summary = new ValidationSummary();

            if (!Directory.Exists(chunkstorePath))
            {
                Console.WriteLine($"Error: Chunkstore directory not found: {chunkstorePath}");
                return summary;
            }

            try
            {
                // Initialize chunkstore first, without a key - just enough to learn whether it's
                // actually encrypted before deciding whether a depot key search is even needed.
                using var chunkstore = new Chunkstore(chunkstorePath, depotId, depotKey: null, readOnly: true);
                var stats = chunkstore.GetStats();

                Console.WriteLine($"Chunkstore loaded: {stats}");

                if (stats.TotalChunks == 0)
                {
                    Console.WriteLine("No chunks found in chunkstore");
                    return summary;
                }

                var (depotKey, keyResolutionFailed) = await ResolveChunkstoreDepotKeyAsync(chunkstorePath, depotKeyPath, stats.IsEncrypted, stats.DepotId);
                if (keyResolutionFailed)
                {
                    return summary;
                }

                summary.TotalChunks = stats.TotalChunks;

                // Load or create validation checkpoint
                var checkpointPath = ValidationCheckpoint.GetPath(chunkstorePath, stats.DepotId);
                ValidationCheckpoint checkpoint = null;

                if (resume && File.Exists(checkpointPath))
                {
                    try
                    {
                        checkpoint = ValidationCheckpoint.LoadFromFile(checkpointPath);
                        Console.WriteLine($"Resuming validation from checkpoint: {checkpoint.ValidatedCsdIndices.Count} CSD(s) already validated, " +
                                          $"{checkpoint.TotalChunksSoFar:N0}/{stats.TotalChunks:N0} chunks processed");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Could not load validation checkpoint ({ex.Message}), starting fresh");
                        checkpoint = null;
                    }
                }

                checkpoint ??= new ValidationCheckpoint { DepotId = stats.DepotId };

                // Determine thread count
                maxThreads = ResolveValidationThreadCount(maxThreads);

                Console.WriteLine($"Validating {stats.TotalChunks:N0} chunks from chunkstore using {maxThreads} threads");

                var progressCount = 0;
                var results = await ChunkValidator.ValidateAllChunkstoreChunksAsync(
                    chunkstore,
                    depotKey,
                    maxThreads,
                    progress: (validated, total) =>
                    {
                        var newCount = Interlocked.Exchange(ref progressCount, validated);
                        if (validated % 100 == 0 || validated == total || validated - newCount >= 50)
                            Console.WriteLine($"Progress: {Util.FormatProgress(validated, total)} chunks validated");
                    },
                    checkpoint: checkpoint,
                    onCsdComplete: (csdIndex, csdChecksum, currentResults) =>
                    {
                        // Update checkpoint after each CSD completes
                        if (!checkpoint.ValidatedCsdIndices.Contains(csdIndex))
                            checkpoint.ValidatedCsdIndices.Add(csdIndex);
                        checkpoint.CsdFileChecksums[csdIndex] = csdChecksum;

                        // Update running totals from the results collected so far for this CSD
                        var csdChunks = chunkstore.EnumerateChunks()
                            .Where(c => c.ChunkstoreIndex == csdIndex)
                            .Select(c => c.Sha.ToLowerInvariant())
                            .ToList();
                        foreach (var sha in csdChunks)
                        {
                            checkpoint.TotalChunksSoFar++;
                            if (currentResults.TryGetValue(sha, out var r))
                            {
                                if (r.IsValid)
                                    checkpoint.ValidChunksSoFar++;
                                else if (!checkpoint.InvalidChunks.Contains(sha))
                                    checkpoint.InvalidChunks.Add(sha);
                            }
                        }

                        checkpoint.SaveToFile(checkpointPath);
                        Console.WriteLine($"  Checkpoint saved (CSD {csdIndex} complete)");
                    });

                // Process results
                foreach (var kvp in results)
                {
                    if (kvp.Value.IsValid)
                    {
                        summary.ValidChunks++;
                        if (verbose)
                        {
                            // A chunk from a checksum-matched, checkpoint-skipped CSD is reconstructed
                            // as IsValid=true without re-decompressing it (that's the whole point of
                            // skipping), so DecompressedSize is left at its unset default here -
                            // print that honestly rather than a misleading "(0 bytes)".
                            var sizeNote = kvp.Value.DecompressedSize > 0 ? $"({kvp.Value.DecompressedSize} bytes)" : "(from checkpoint, not re-read this run)";
                            Console.WriteLine($"✓ {kvp.Key} - Valid {sizeNote}");
                        }
                    }
                    else
                    {
                        summary.InvalidChunks++;
                        Console.WriteLine($"✗ {kvp.Key} - {kvp.Value.ErrorMessage}");
                    }
                }

                // Clear checkpoint on successful completion
                if (File.Exists(checkpointPath))
                {
                    File.Delete(checkpointPath);
                    Console.WriteLine("Validation complete — checkpoint cleared");
                }

                return summary;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validating chunkstore: {ex.Message}");
                summary.ErrorChunks = 1;
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
                // Initialize chunkstore first, without a key - just enough to learn whether it's
                // actually encrypted before deciding whether a depot key search is even needed.
                using var chunkstore = new Chunkstore(chunkstorePath, depotId, depotKey: null, readOnly: true);
                var stats = chunkstore.GetStats();

                Console.WriteLine($"Chunkstore loaded: {stats}");

                var (depotKey, keyResolutionFailed) = await ResolveChunkstoreDepotKeyAsync(chunkstorePath, depotKeyPath, stats.IsEncrypted, stats.DepotId);
                if (keyResolutionFailed)
                {
                    return summary;
                }

                // Determine thread count
                maxThreads = ResolveValidationThreadCount(maxThreads);

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
                            Console.WriteLine($"Progress: {Util.FormatProgress(validated, total)} chunks validated");
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
