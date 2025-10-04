// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;
using SevenZip;
using ZstdSharp;

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
        /// <param name="depotKey">Depot key for decryption</param>
        /// <param name="estimatedUncompressedLength">Optional estimated uncompressed length (auto-detected from chunk headers)</param>
        /// <returns>ValidationResult with success status and details</returns>
        public static async Task<ValidationResult> ValidateRawChunkAsync(string chunkFilePath, byte[] depotKey, uint estimatedUncompressedLength = 0)
        {
            if (!File.Exists(chunkFilePath))
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"Chunk file not found: {chunkFilePath}"
                };
            }

            if (depotKey == null || depotKey.Length != 32)
            {
                return new ValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Depot key is required and must be 32 bytes"
                };
            }

            try
            {
                // Extract expected SHA1 from filename (chunk files are named with their SHA1)
                var expectedChunkId = Path.GetFileNameWithoutExtension(chunkFilePath);

                // Read the raw encrypted chunk data
                var rawChunkData = await File.ReadAllBytesAsync(chunkFilePath);

                // Process chunk exactly like the Python validator
                var result = ProcessChunkLikePython(rawChunkData, depotKey, expectedChunkId);

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
            return await ValidateRawChunkAsync(chunkFilePath, depotKey, chunkData.UncompressedLength);
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
                var actualSha1 = Convert.ToHexString(SHA1.HashData(decompressedData)).ToLowerInvariant();
                var expectedSha1 = Convert.ToHexString(chunkData.ChunkID).ToLowerInvariant();

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
                var actualSha1 = Convert.ToHexString(SHA1.HashData(decompressedData)).ToLowerInvariant();
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
                var expectedChunkId = Convert.ToHexString(chunkSha).ToLowerInvariant();

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

                // Validate the chunk
                return ProcessChunkLikePython(rawChunkData, depotKey, expectedChunkId);
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

            if (maxParallelism <= 0)
            {
                maxParallelism = Math.Max(1, Environment.ProcessorCount - 1);
            }

            var results = new Dictionary<string, ValidationResult>();
            var chunks = chunkShaList.ToList();
            var validatedCount = 0;
            var lockObj = new object();

            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

            await Parallel.ForEachAsync(chunks, options, async (chunkShaHex, ct) =>
            {
                await Task.Run(() =>
                {
                    var result = ValidateChunkstoreChunk(chunkstore, chunkShaHex, depotKey);

                    lock (lockObj)
                    {
                        results[chunkShaHex.ToLowerInvariant()] = result;
                        validatedCount++;
                        progress?.Invoke(validatedCount, chunks.Count);
                    }
                }, ct);
            });

            return results;
        }

        /// <summary>
        /// Validates all chunks in a chunkstore
        /// </summary>
        /// <param name="chunkstore">The chunkstore instance to validate</param>
        /// <param name="depotKey">Depot key for decryption (optional if chunkstore is not encrypted)</param>
        /// <param name="maxParallelism">Maximum number of parallel validation operations (0 = auto-detect)</param>
        /// <param name="progress">Optional progress callback (validated count, total count)</param>
        /// <returns>Dictionary mapping chunk SHA1 to validation results</returns>
        public static async Task<Dictionary<string, ValidationResult>> ValidateAllChunkstoreChunksAsync(
            Chunkstore chunkstore,
            byte[] depotKey = null,
            int maxParallelism = 0,
            Action<int, int> progress = null)
        {
            if (chunkstore == null)
            {
                throw new ArgumentNullException(nameof(chunkstore));
            }

            // Get all chunk SHA1s from the chunkstore
            var allChunks = chunkstore.EnumerateChunks().Select(c => c.Sha).ToList();

            return await ValidateChunkstoreChunksAsync(chunkstore, allChunks, depotKey, maxParallelism, progress);
        }

        #endregion

        #region Shared Processing Logic

        /// <summary>
        /// Process a chunk exactly like the Python depot_validator.py
        /// </summary>
        private static ValidationResult ProcessChunkLikePython(byte[] encryptedData, byte[] depotKey, string expectedChunkId)
        {
            try
            {
                // Step 1: Decrypt the chunk data (same AES process as SteamKit2)
                using var aes = Aes.Create();
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Key = depotKey;

                if (encryptedData.Length < 16)
                {
                    throw new InvalidDataException("Chunk data too small to contain IV");
                }

                // First 16 bytes are ECB-encrypted IV
                Span<byte> iv = stackalloc byte[16];
                aes.DecryptEcb(encryptedData.AsSpan(0, 16), iv, PaddingMode.None);

                // Decrypt the rest with CBC + PKCS7
                var encryptedPayload = encryptedData.AsSpan(16);
                var decryptedBuffer = new byte[encryptedPayload.Length]; // Over-allocate for PKCS7
                var decryptedLength = aes.DecryptCbc(encryptedPayload, iv, decryptedBuffer, PaddingMode.PKCS7);

                if (decryptedLength < 4)
                {
                    throw new InvalidDataException("Decrypted data too small to determine compression type");
                }

                var decrypted = decryptedBuffer.AsSpan(0, decryptedLength);

                // Step 2: Determine compression type and decompress (exactly like Python)
                byte[] decompressed;
                int decompressedSize;

                if (decrypted.Length >= 3 &&
                    decrypted[0] == (byte)'V' && decrypted[1] == (byte)'Z' && decrypted[2] == (byte)'a') // VZa - LZMA
                {
                    // LZMA: size is in footer at offset -6 to -2 (little endian)
                    if (decrypted.Length < 17) // Need header + footer + some data
                        throw new InvalidDataException("LZMA chunk too small");

                    var expectedSize = BitConverter.ToInt32(decrypted[^6..^2]);
                    Console.WriteLine($"Testing (LZMA) from chunk {expectedChunkId}, Size: {expectedSize}");

                    // LZMA properties are at offset 7-11 (5 bytes)
                    var lzmaProps = decrypted[7..12].ToArray();

                    // LZMA payload is between header and footer: offset 12 to (length - 10)
                    var compressedPayload = decrypted[12..^10];

                    decompressed = new byte[expectedSize];

                    try
                    {
                        // Use SevenZip LZMA decoder (similar to SteamKit2's approach but using standard API)
                        var decoder = new SevenZip.Compression.LZMA.Decoder();

                        // Set properties exactly like VZipUtil does
                        // Property byte is at offset 0, dictionary size at offset 1-4 (little endian)
                        var propertyBits = lzmaProps[0];
                        var dictionarySize = BitConverter.ToUInt32(lzmaProps, 1);

                        // Create property array for standard SevenZip API
                        byte[] properties = [propertyBits,
                            (byte)(dictionarySize), (byte)(dictionarySize >> 8),
                            (byte)(dictionarySize >> 16), (byte)(dictionarySize >> 24)];

                        decoder.SetDecoderProperties(properties);

                        // Decode with known input/output sizes
                        using var inputStream = new MemoryStream(compressedPayload.ToArray());
                        using var outputStream = new MemoryStream(decompressed);

                        decoder.Code(inputStream, outputStream, compressedPayload.Length, expectedSize, null);
                        decompressedSize = (int)outputStream.Position;

                        if (decompressedSize != expectedSize)
                        {
                            throw new InvalidDataException($"LZMA decompressed size mismatch: expected {expectedSize}, got {decompressedSize}");
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException($"LZMA decompression failed: {ex.Message}");
                    }
                }
                else if (decrypted.Length >= 4 &&
                         decrypted[0] == (byte)'V' && decrypted[1] == (byte)'S' && decrypted[2] == (byte)'Z' && decrypted[3] == (byte)'a') // VSZa - Zstd
                {
                    // Zstandard: size is at offset -11 to -7 (little endian)
                    if (decrypted.Length < 23) // Need header + footer + some data
                        throw new InvalidDataException("Zstd chunk too small");

                    var expectedSize = BitConverter.ToInt32(decrypted[^11..^7]);
                    Console.WriteLine($"Testing (Zstandard) from chunk {expectedChunkId}, Size: {expectedSize}");

                    // Verify CRC32 consistency (header at offset 4-7, footer at offset -15 to -11)
                    var headerCrc = BitConverter.ToUInt32(decrypted[4..8]);
                    var footerCrc = BitConverter.ToUInt32(decrypted[^15..^11]);
                    if (headerCrc != footerCrc)
                    {
                        throw new InvalidDataException($"Zstd CRC32 mismatch: header={headerCrc:X8}, footer={footerCrc:X8}");
                    }

                    // Verify footer signature "zsv"
                    if (decrypted[^3] != (byte)'z' || decrypted[^2] != (byte)'s' || decrypted[^1] != (byte)'v')
                    {
                        throw new InvalidDataException("Invalid Zstd footer signature");
                    }

                    // Zstd payload: skip 8-byte header, 15-byte footer
                    var compressedPayload = decrypted[8..^15];
                    decompressed = new byte[expectedSize];

                    try
                    {
                        // Use ZstdSharp for decompression
                        using var decompressor = new ZstdSharp.Decompressor();
                        var actualSize = decompressor.Unwrap(compressedPayload, decompressed);

                        if (actualSize != expectedSize)
                        {
                            throw new InvalidDataException($"Zstd decompressed size mismatch: expected {expectedSize}, got {actualSize}");
                        }

                        decompressedSize = actualSize;
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException($"Zstd decompression failed: {ex.Message}");
                    }
                }
                else if (decrypted.Length >= 4 &&
                         decrypted[0] == (byte)'P' && decrypted[1] == (byte)'K' &&
                         decrypted[2] == 0x03 && decrypted[3] == 0x04) // ZIP
                {
                    Console.WriteLine($"Testing (ZIP) from chunk {expectedChunkId}");

                    // ZIP: Let .NET handle decompression automatically
                    try
                    {
                        using var zipStream = new MemoryStream(decrypted.ToArray());
                        using var zip = new ZipArchive(zipStream, ZipArchiveMode.Read);

                        if (zip.Entries.Count != 1)
                            throw new InvalidDataException($"Expected 1 ZIP entry, found {zip.Entries.Count}");

                        using var entryStream = zip.Entries[0].Open();
                        using var decompressedStream = new MemoryStream();
                        entryStream.CopyTo(decompressedStream);

                        decompressed = decompressedStream.ToArray();
                        decompressedSize = decompressed.Length;
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException($"ZIP decompression failed: {ex.Message}");
                    }
                }
                else
                {
                    // Unknown compression format
                    var headerHex = Convert.ToHexString(decrypted[0..Math.Min(4, decrypted.Length)]);
                    throw new InvalidDataException($"Unknown compression format: {headerHex}");
                }

                // Step 3: Validate SHA1 hash (exactly like Python)
                var actualSha1 = Convert.ToHexString(SHA1.HashData(decompressed.AsSpan(0, decompressedSize))).ToLowerInvariant();
                var expectedSha1 = expectedChunkId.ToLowerInvariant();

                var isValid = actualSha1 == expectedSha1;

                return new ValidationResult
                {
                    IsValid = isValid,
                    ActualSha1 = actualSha1,
                    ExpectedSha1 = expectedSha1,
                    DecompressedSize = decompressedSize,
                    CompressedSize = encryptedData.Length,
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
