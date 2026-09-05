// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Standalone chunk validation utility that can work with or without Steam session
    /// Supports validation of both loose chunk files and chunkstore sets
    /// </summary>
    public static class ChunkValidator
    {
        #region Loose File Validation (Existing Functionality)

        /// <summary>
        /// Validates a raw chunk file against its filename (which is the SHA1 of the decrypted/decompressed content)
        /// This implementation mirrors the Python depot_validator.py approach exactly
        /// </summary>
        /// <param name="chunkFilePath">Path to the raw chunk file</param>
        /// <param name="depotKey">Depot key for decryption (unused, may be null, when isEncrypted is false)</param>
        /// <param name="isEncrypted">Whether this chunk is still AES-encrypted (bare "&lt;sha&gt;" filename) or
        /// already decrypted ("&lt;sha&gt;_decrypted" filename) - same convention chunkstore packing uses.</param>
        /// <param name="estimatedUncompressedLength">Optional estimated uncompressed length (auto-detected from chunk headers)</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static async Task<ValidationResult> ValidateRawChunkAsync(string chunkFilePath, byte[] depotKey, bool isEncrypted, uint estimatedUncompressedLength = 0)
        {
            if (!File.Exists(chunkFilePath))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Chunk file not found: {chunkFilePath}"
                };
            }

            if (isEncrypted && (depotKey == null || depotKey.Length != 32))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Depot key is required and must be 32 bytes"
                };
            }

            // Extract expected SHA1 from the filename, stripping "_decrypted" when that's the
            // mode - chunk files are named with their SHA1, never "<sha>_decrypted" once packed.
            var fileName = Path.GetFileName(chunkFilePath);
            if (!Chunkstore.TryGetChunkSha(fileName, isEncrypted, out var expectedChunkId))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Filename does not look like a{(isEncrypted ? "n encrypted" : " decrypted")} chunk SHA1: {fileName}"
                };
            }

            try
            {
                // Read the raw chunk data - still AES-encrypted+compressed if isEncrypted,
                // otherwise already the plain compressed payload.
                var rawChunkData = await File.ReadAllBytesAsync(chunkFilePath);

                // Process chunk exactly like the Python validator
                var result = ProcessChunkLikePython(rawChunkData, depotKey, expectedChunkId, isEncrypted);

                return result;
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Validation failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates a raw chunk file using manifest chunk data
        /// </summary>
        /// <param name="chunkFilePath">Path to the raw chunk file</param>
        /// <param name="chunkData">Chunk data from manifest</param>
        /// <param name="depotKey">Depot key for decryption</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static async Task<ValidationResult> ValidateRawChunkAsync(string chunkFilePath, DepotManifest.ChunkData chunkData, byte[] depotKey)
        {
            // Manifest-driven validation always targets live CDN chunk data, which is always encrypted.
            return await ValidateRawChunkAsync(chunkFilePath, depotKey, isEncrypted: true, chunkData.UncompressedLength);
        }

        /// <summary>
        /// Validates a chunk that's already decompressed (e.g., during download process)
        /// Uses the chunk ID from the manifest as the expected SHA1
        /// </summary>
        /// <param name="decompressedData">The decompressed chunk data</param>
        /// <param name="chunkData">Chunk data from manifest containing the expected SHA1</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static ValidationResult ValidateDecompressedChunk(ReadOnlySpan<byte> decompressedData, DepotManifest.ChunkData chunkData)
        {
            try
            {
                var actualSha1 = Util.ToHex(SHA1.HashData(decompressedData));
                var expectedSha1 = Util.ToHex(chunkData.ChunkID);

                var isValid = actualSha1 == expectedSha1;

                return new ValidationResult
                {
                    IsValid = isValid,
                    ActualSha1 = actualSha1,
                    ExpectedSha1 = expectedSha1,
                    DecompressedSize = decompressedData.Length,
                    ErrorMessage = isValid ? null : $"SHA1 mismatch: expected {expectedSha1}, got {actualSha1}"
                };
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Validation failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates a chunk that's already decompressed using a hex string chunk ID
        /// </summary>
        /// <param name="decompressedData">The decompressed chunk data</param>
        /// <param name="expectedChunkId">Expected SHA1 hash (hex string)</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static ValidationResult ValidateDecompressedChunk(ReadOnlySpan<byte> decompressedData, string expectedChunkId)
        {
            try
            {
                var actualSha1 = Util.ToHex(SHA1.HashData(decompressedData));
                var expectedSha1 = expectedChunkId.ToLowerInvariant();

                var isValid = actualSha1 == expectedSha1;

                return new ValidationResult
                {
                    IsValid = isValid,
                    ActualSha1 = actualSha1,
                    ExpectedSha1 = expectedSha1,
                    DecompressedSize = decompressedData.Length,
                    ErrorMessage = isValid ? null : $"SHA1 mismatch: expected {expectedSha1}, got {actualSha1}"
                };
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Validation failed: {ex.Message}"
                };
            }
        }

        #endregion

        #region Chunkstore Validation (New Functionality)

        /// <summary>
        /// Validates a single chunk from a chunkstore by its SHA1 hash
        /// </summary>
        /// <param name="chunkstore">The chunkstore instance to read from</param>
        /// <param name="chunkSha">SHA1 hash of the chunk to validate (as byte array)</param>
        /// <param name="depotKey">Depot key for decryption (optional if chunkstore is not encrypted)</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static ValidationResult ValidateChunkstoreChunk(Chunkstore chunkstore, byte[] chunkSha, byte[] depotKey = null)
        {
            if (chunkstore == null)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Chunkstore instance is required"
                };
            }

            try
            {
                var expectedChunkId = Util.ToHex(chunkSha);

                // Check if chunk exists in chunkstore
                if (!chunkstore.ChunkExists(chunkSha))
                {
                    return new ValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = $"Chunk {expectedChunkId} not found in chunkstore"
                    };
                }

                // Get raw chunk data from chunkstore
                var rawChunkData = chunkstore.GetChunk(chunkSha, process: false);

                // Validate the chunk. A chunkstore is either fully encrypted or fully decrypted
                // (recorded in its CSM header, never mixed) - only decrypt if it actually is one.
                return ProcessChunkLikePython(rawChunkData, depotKey, expectedChunkId, chunkstore.IsEncrypted.GetValueOrDefault());
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Chunkstore validation failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates a single chunk from a chunkstore by its SHA1 hash (hex string)
        /// </summary>
        /// <param name="chunkstore">The chunkstore instance to read from</param>
        /// <param name="chunkShaHex">SHA1 hash of the chunk to validate (as hex string)</param>
        /// <param name="depotKey">Depot key for decryption (optional if chunkstore is not encrypted)</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static ValidationResult ValidateChunkstoreChunk(Chunkstore chunkstore, string chunkShaHex, byte[] depotKey = null)
        {
            try
            {
                var chunkSha = Convert.FromHexString(chunkShaHex);
                return ValidateChunkstoreChunk(chunkstore, chunkSha, depotKey);
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Invalid hex string: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates multiple chunks from a chunkstore in parallel
        /// </summary>
        /// <param name="chunkstore">The chunkstore instance to read from</param>
        /// <param name="chunkShaList">List of SHA1 hashes to validate (as hex strings)</param>
        /// <param name="depotKey">Depot key for decryption (optional if chunkstore is not encrypted)</param>
        /// <param name="maxParallelism">Maximum number of parallel validation operations (0 = auto-detect)</param>
        /// <param name="progress">Optional progress callback (validated count, total count)</param>
        /// <returns>Dictionary mapping chunk SHA1 to validation results</returns>
        public static async Task<Dictionary<string, ValidationResult>> ValidateChunkstoreChunksAsync(
            Chunkstore chunkstore,
            IEnumerable<string> chunkShaList,
            byte[] depotKey = null,
            int maxParallelism = 0,
            Action<int, int> progress = null)
        {
            if (chunkstore == null)
            {
                throw new ArgumentNullException(nameof(chunkstore));
            }

            maxParallelism = Util.ResolveParallelism(maxParallelism);

            var results = new Dictionary<string, ValidationResult>();
            var chunks = chunkShaList.ToList();
            var validatedCount = 0;
            var lockObj = new object();

            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

            await Parallel.ForEachAsync(chunks, options, (chunkShaHex, ct) =>
            {
                var result = ValidateChunkstoreChunk(chunkstore, chunkShaHex, depotKey);

                lock (lockObj)
                {
                    results[chunkShaHex.ToLowerInvariant()] = result;
                    validatedCount++;
                    progress?.Invoke(validatedCount, chunks.Count);
                }

                return ValueTask.CompletedTask;
            });

            return results;
        }

        /// <summary>
        /// Validates all chunks in a chunkstore, processing one CSD file at a time.
        /// Supports resuming an interrupted validation via a checkpoint file.
        /// </summary>
        /// <param name="chunkstore">The chunkstore instance to validate</param>
        /// <param name="depotKey">Depot key for decryption (optional if chunkstore is not encrypted)</param>
        /// <param name="maxParallelism">Maximum number of parallel validation operations (0 = auto-detect)</param>
        /// <param name="progress">Optional progress callback (validated count, total count)</param>
        /// <param name="checkpoint">Optional validation checkpoint for resume support</param>
        /// <param name="onCsdComplete">Called after each CSD is fully validated, with the CSD index, its file checksum, and the current results dictionary</param>
        /// <returns>Dictionary mapping chunk SHA1 to validation results</returns>
        public static async Task<Dictionary<string, ValidationResult>> ValidateAllChunkstoreChunksAsync(
            Chunkstore chunkstore,
            byte[] depotKey = null,
            int maxParallelism = 0,
            Action<int, int> progress = null,
            ValidationCheckpoint checkpoint = null,
            Action<int, string, Dictionary<string, ValidationResult>> onCsdComplete = null)
        {
            if (chunkstore == null)
            {
                throw new ArgumentNullException(nameof(chunkstore));
            }

            maxParallelism = Util.ResolveParallelism(maxParallelism);

            // Group chunks by CSD index, preserving order within each CSD
            var byCsd = chunkstore.EnumerateChunks()
                .GroupBy(c => c.ChunkstoreIndex)
                .OrderBy(g => g.Key)
                .ToList();

            var totalChunks = byCsd.Sum(g => g.Count());
            var results = new Dictionary<string, ValidationResult>(totalChunks, StringComparer.OrdinalIgnoreCase);
            var validatedCount = 0;

            // Seed results and counter from checkpoint for already-completed CSDs
            if (checkpoint != null)
            {
                validatedCount = checkpoint.TotalChunksSoFar;
                foreach (var invalidSha in checkpoint.InvalidChunks)
                {
                    results[invalidSha] = new ValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "Failed in previous run (loaded from checkpoint)"
                    };
                }
            }

            foreach (var csdGroup in byCsd)
            {
                var csdIndex = csdGroup.Key;
                var csdPath = chunkstore.GetCsdPath(csdIndex);

                // Check if this CSD was already validated in a prior run
                if (checkpoint != null && checkpoint.ValidatedCsdIndices.Contains(csdIndex))
                {
                    if (csdPath != null && File.Exists(csdPath))
                    {
                        var currentFingerprint = GetCsdFingerprint(csdPath);
                        if (checkpoint.CsdFileChecksums.TryGetValue(csdIndex, out var savedFingerprint) &&
                            currentFingerprint == savedFingerprint)
                        {
                            Console.WriteLine($"  CSD {csdIndex}: skipping (validated in previous run, unchanged since)");

                            // The checkpoint only ever records previously-INVALID chunks (kept small
                            // on purpose). Reconstruct this CSD's full result set for the final
                            // summary without re-validating: any chunk not already in `results` was
                            // therefore valid last time, and the checksum match proves the file
                            // hasn't changed since.
                            foreach (var sha in csdGroup.Select(c => c.Sha))
                            {
                                var key = sha.ToLowerInvariant();
                                if (!results.ContainsKey(key))
                                {
                                    results[key] = new ValidationResult { IsValid = true };
                                }
                            }

                            progress?.Invoke(validatedCount, totalChunks);
                            continue;
                        }
                        else
                        {
                            Console.WriteLine($"  CSD {csdIndex}: re-validating (checksum mismatch — file may have changed)");
                        }
                    }
                }

                Console.WriteLine($"  Validating CSD {csdIndex} ({csdGroup.Count():N0} chunks)...");

                var csdChunks = csdGroup.Select(c => c.Sha).ToList();
                var lockObj = new object();
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

                await Parallel.ForEachAsync(csdChunks, options, (chunkShaHex, ct) =>
                {
                    var result = ValidateChunkstoreChunk(chunkstore, chunkShaHex, depotKey);
                    lock (lockObj)
                    {
                        results[chunkShaHex.ToLowerInvariant()] = result;
                        validatedCount++;
                        progress?.Invoke(validatedCount, totalChunks);
                    }

                    return ValueTask.CompletedTask;
                });

                // Notify caller that this CSD is complete (for checkpoint saving)
                if (onCsdComplete != null)
                {
                    var fingerprint = csdPath != null && File.Exists(csdPath)
                        ? GetCsdFingerprint(csdPath)
                        : string.Empty;
                    onCsdComplete(csdIndex, fingerprint, results);
                }
            }

            return results;
        }

        /// <summary>
        /// Cheap (length, last-write-time) fingerprint used only to detect whether a CSD file has
        /// changed since a previous validation run - not a content hash. Every chunk in the file
        /// already gets a real SHA1 integrity check whenever it isn't skipped via this fingerprint
        /// matching, so this only needs to answer "does this look like the same file", not
        /// cryptographically prove it. A full-file SHA1 was used here previously and was
        /// computed unconditionally after every CSD, on every run (not just when resuming) -
        /// effectively a second full read pass over data just read chunk-by-chunk moments earlier,
        /// and the actual cause of a real multi-CSD store pausing for a long time between CSDs.
        /// </summary>
        private static string GetCsdFingerprint(string path)
        {
            var fi = new FileInfo(path);
            return $"{fi.Length}:{fi.LastWriteTimeUtc.Ticks}";
        }

        #endregion

        #region Shared Processing Logic

        /// <summary>
        /// Decrypts, decompresses, and reports whether the result's SHA1 matches
        /// <paramref name="expectedChunkId"/> - via <see cref="Chunkstore.DecryptAndDecompress"/>,
        /// the same core used by chunkstore reads and reconstruction, so validation results can
        /// never silently diverge from what an actual read/reconstruct would produce.
        /// </summary>
        /// <param name="rawData">The chunk's stored bytes - AES-encrypted+compressed if
        /// <paramref name="isEncrypted"/>, otherwise already-decrypted compressed data.</param>
        /// <param name="isEncrypted">Whether this chunk needs AES decryption before decompression.
        /// A decrypted chunk (or any chunk with no depot key available) skips straight to
        /// decompression.</param>
        private static ValidationResult ProcessChunkLikePython(byte[] rawData, byte[] depotKey, string expectedChunkId, bool isEncrypted)
        {
            try
            {
                var decompressed = Chunkstore.DecryptAndDecompress(rawData, isEncrypted, depotKey, expectedChunkId);

                var actualSha1 = Util.ToHex(SHA1.HashData(decompressed));
                var expectedSha1 = expectedChunkId.ToLowerInvariant();
                var isValid = actualSha1 == expectedSha1;

                return new ValidationResult
                {
                    IsValid = isValid,
                    ActualSha1 = actualSha1,
                    ExpectedSha1 = expectedSha1,
                    DecompressedSize = decompressed.Length,
                    CompressedSize = rawData.Length,
                    ErrorMessage = isValid ? null : $"SHA1 mismatch: expected {expectedSha1}, got {actualSha1}"
                };
            }
            catch (Exception ex)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Chunk processing failed: {ex.Message}"
                };
            }
        }

        #endregion
    }

    /// <summary>
    /// Result of chunk validation
    /// </summary>
    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string ActualSha1 { get; set; }
        public string ExpectedSha1 { get; set; }
        public int DecompressedSize { get; set; }
        public int CompressedSize { get; set; }
        public string ErrorMessage { get; set; }

        public override string ToString()
        {
            if (IsValid)
            {
                return $"✓ Valid - SHA1: {ActualSha1} ({DecompressedSize} bytes decompressed)";
            }
            else
            {
                return $"✗ Invalid - {ErrorMessage}";
            }
        }
    }
}
