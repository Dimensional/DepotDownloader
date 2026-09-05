// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using SevenZip;
using ZstdSharp;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Metadata for a single chunk in the chunkstore
    /// </summary>
    public readonly struct ChunkMetadata
    {
        public string Sha { get; init; }
        public int ChunkstoreIndex { get; init; }
        public long Offset { get; init; }
        public int Length { get; init; }
    }

    /// <summary>
    /// Serializable checkpoint data for crash recovery
    /// </summary>
    [ProtoContract]
    public class ChunkstoreCheckpoint
    {
        [ProtoMember(1)]
        public uint DepotId { get; set; }

        [ProtoMember(2)]
        public bool IsEncrypted { get; set; }

        [ProtoMember(3)]
        public int CurrentFileIndex { get; set; }

        [ProtoMember(4)]
        public long CurrentFileSize { get; set; }

        [ProtoMember(5)]
        public Dictionary<string, ChunkMetadataProto> ChunkIndex { get; set; }

        // ProtoMember 6 ("ChunksPerFile") used to duplicate ChunkIndex's data as a hand-synced
        // per-CSD list purely for ordered CSM generation - removed since it's one query away
        // (chunkIndex.Values.Where(...).OrderBy(...)) and was persisted redundantly on every
        // checkpoint save. An older checkpoint file with that field is read fine (protobuf-net
        // ignores unknown members); it's just no longer written.

        [ProtoContract]
        public class ChunkMetadataProto
        {
            [ProtoMember(1)]
            public string Sha { get; set; }

            [ProtoMember(2)]
            public int ChunkstoreIndex { get; set; }

            [ProtoMember(3)]
            public long Offset { get; set; }

            [ProtoMember(4)]
            public int Length { get; set; }
        }
    }

    /// <summary>
    /// Manages Steam chunkstore files (CSD/CSM pairs) for efficient chunk storage and retrieval.
    /// Implements the Steam Chunk File System (SCFS) format.
    /// </summary>
    public class Chunkstore : IDisposable
    {
        private readonly string folder;
        private uint? depot;
        private readonly byte[] depotKey;
        private bool? isEncrypted;
        private readonly long maxFileSize;

        private readonly List<(string csdPath, string csmPath)> files = new();
        private string currentCsd;
        private string currentCsm;
        private int currentFileIndex;
        private long currentFileSize;

        // Native .NET collections - much faster than SQLite for this use case
        private readonly ConcurrentDictionary<string, ChunkMetadata> chunkIndex = new(StringComparer.OrdinalIgnoreCase);

        // Per-segment chunks, in write (= offset) order, purely as an in-memory index for fast CSM
        // writes - NOT persisted in the checkpoint (unlike an earlier version of this field): it's
        // fully derivable from chunkIndex, so persisting it too was pure redundancy. Kept in memory
        // anyway because deriving it on every CSM write (chunkIndex.Values.Where(...).OrderBy(...))
        // costs O(chunk count) *per segment*, i.e. O(N*segments) over a whole pack/rebuild - a real
        // cost for a large depot. Rebuilt with one O(N) pass whenever chunkIndex is loaded/replaced
        // wholesale (initial CSM parse, checkpoint load); appended to incrementally by WriteChunk.
        private readonly List<List<ChunkMetadata>> chunksPerFile = new();

        // Lock for write operations ONLY - reads are lock-free
        private readonly object writeLock = new();

        private const uint SCFS_MAGIC = 0x53434653; // "SCFS"
        private const uint SCFS_VERSION = 0x00000014;
        private const uint SCFS_ENCRYPTED = 0x00000003;
        private const uint SCFS_DECRYPTED = 0x00000002;

        /// <summary>
        /// Initializes a new instance of the Chunkstore class.
        /// </summary>
        /// <param name="folder">Path to the folder containing chunkstore files</param>
        /// <param name="depot">Depot ID (optional, will be auto-detected if only one depot exists)</param>
        /// <param name="depotKey">Depot decryption key for encrypted chunkstores</param>
        /// <param name="isEncrypted">Whether the chunkstore contains encrypted chunks</param>
        /// <param name="maxFileSize">Maximum size per CSD file (default: 2GB)</param>
        /// <param name="readOnly">If true, suppresses checkpoint writes (use for validation/read-only access)</param>
        public Chunkstore(string folder, uint? depot = null, byte[] depotKey = null, bool? isEncrypted = null, long maxFileSize = 2L * 1024 * 1024 * 1024, bool readOnly = false)
        {
            this.folder = folder ?? throw new ArgumentNullException(nameof(folder));
            this.depot = depot;
            this.depotKey = depotKey;
            this.isEncrypted = isEncrypted;
            this.maxFileSize = maxFileSize;

            if (!Directory.Exists(folder))
            {
                throw new DirectoryNotFoundException($"Folder {folder} does not exist");
            }

            // Load existing chunkstore files
            LoadExistingFiles(readOnly);
        }

        private string CheckpointPath => Path.Combine(folder, $"{depot}_checkpoint.bin");

        private void LoadExistingFiles(bool readOnly = false)
        {
            // Auto-detect depot if not specified
            if (depot == null)
            {
                var depotIds = new HashSet<uint>();
                foreach (var file in Directory.EnumerateFiles(folder, "*.csm"))
                {
                    var filename = Path.GetFileName(file);
                    if (uint.TryParse(filename.Split('_')[0], out var depotId))
                    {
                        depotIds.Add(depotId);
                    }
                }

                if (depotIds.Count == 1)
                {
                    depot = depotIds.First();
                }
                else if (depotIds.Count > 1)
                {
                    throw new InvalidOperationException(
                        $"Multiple depots found in folder {folder}: {string.Join(", ", depotIds)}. " +
                        "Please specify the depot ID explicitly.");
                }
                else
                {
                    // No existing files, that's okay
                    return;
                }
            }

            // Try to load checkpoint first (faster than parsing CSM files)
            if (File.Exists(CheckpointPath))
            {
                try
                {
                    if (LoadCheckpointUnsafe())
                    {
                        Console.WriteLine($"Loaded checkpoint: {chunkIndex.Count:N0} chunks indexed");

                        // Verify CSM files match checkpoint
                        var expectedFiles = files.Count;
                        var actualFiles = Directory.GetFiles(folder, $"{depot}_*.csm").Length;

                        if (expectedFiles == actualFiles)
                        {
                            Console.WriteLine("Checkpoint validated successfully");
                            return; // Checkpoint is good, skip CSM parsing
                        }
                        else
                        {
                            Console.WriteLine($"Warning: Checkpoint file count mismatch (expected {expectedFiles}, found {actualFiles}). Rebuilding from CSM files...");
                            // Fall through to rebuild from CSM
                            chunkIndex.Clear();
                            files.Clear();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Failed to load checkpoint: {ex.Message}. Rebuilding from CSM files...");
                    chunkIndex.Clear();
                    files.Clear();
                }
            }

            // Load existing CSD/CSM pairs (fallback or initial load). Ignore, rather than crash on,
            // any file that happens to match the glob but doesn't follow the expected
            // "{depot}_depotcache_<N>.csm" naming (a manual backup, a Windows "(1)"-suffixed copy,
            // etc.) - one stray file shouldn't take down every command that opens this chunkstore.
            var csmFiles = Directory.EnumerateFiles(folder, $"{depot}_*.csm")
                .Select(f =>
                {
                    var lastPart = Path.GetFileNameWithoutExtension(f).Split('_')[^1];
                    var parsed = int.TryParse(lastPart, NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx) ? idx : (int?)null;
                    return (Path: f, Index: parsed);
                })
                .Where(x =>
                {
                    if (x.Index == null)
                    {
                        Console.WriteLine($"Warning: Ignoring unrecognized file in chunkstore folder (doesn't match the expected '{{depot}}_depotcache_<N>.csm' naming): {Path.GetFileName(x.Path)}");
                    }
                    return x.Index != null;
                })
                .OrderBy(x => x.Index!.Value)
                .Select(x => x.Path)
                .ToList();

            foreach (var csmPath in csmFiles)
            {
                var baseName = Path.GetFileNameWithoutExtension(csmPath);
                var csdPath = Path.Combine(folder, baseName + ".csd");

                if (File.Exists(csdPath))
                {
                    files.Add((csdPath, csmPath));
                    chunksPerFile.Add([]);
                }
            }

            if (files.Count > 0)
            {
                // Check encryption consistency
                CheckEncryptionConsistency();

                // Parse metadata from CSM files
                Console.WriteLine("Building index from CSM files...");
                for (int i = 0; i < files.Count; i++)
                {
                    ParseCsmMetadata(files[i].csmPath, i + 1);
                    if ((i + 1) % 10 == 0 || i == files.Count - 1)
                    {
                        Console.WriteLine($"Indexed {i + 1}/{files.Count} CSM files ({chunkIndex.Count:N0} chunks)");
                    }
                }

                // Update current file tracking
                currentFileIndex = files.Count;
                (currentCsd, currentCsm) = files[^1];
                currentFileSize = new FileInfo(currentCsd).Length;

                // Save checkpoint after initial load for future faster startups
                if (!readOnly)
                {
                    SaveCheckpointUnsafe();
                    Console.WriteLine("Initial checkpoint saved");
                }
            }
        }

        private void CheckEncryptionConsistency()
        {
            foreach (var (_, csmPath) in files)
            {
                using var stream = File.OpenRead(csmPath);
                using var reader = new BinaryReader(stream);

                // Read magic bytes individually
                var magic1 = reader.ReadByte();
                var magic2 = reader.ReadByte();
                var magic3 = reader.ReadByte();
                var magic4 = reader.ReadByte();

                if (magic1 != (byte)'S' || magic2 != (byte)'C' || magic3 != (byte)'F' || magic4 != (byte)'S')
                {
                    throw new InvalidDataException($"Not a valid CSM file: {csmPath}");
                }

                reader.ReadUInt32(); // version
                var encryptionFlag = reader.ReadUInt32();
                var fileIsEncrypted = encryptionFlag == SCFS_ENCRYPTED;

                if (isEncrypted == null)
                {
                    isEncrypted = fileIsEncrypted;
                }
                else if (isEncrypted != fileIsEncrypted)
                {
                    throw new InvalidDataException(
                        $"Encryption mismatch in file {csmPath}. " +
                        $"Expected {(isEncrypted.Value ? "encrypted" : "decrypted")}.");
                }
            }
        }

        private void ParseCsmMetadata(string csmPath, int chunkstoreIndex)
        {
            using var stream = File.OpenRead(csmPath);
            using var reader = new BinaryReader(stream);

            // Read and validate magic bytes individually
            var magic1 = reader.ReadByte();
            var magic2 = reader.ReadByte();
            var magic3 = reader.ReadByte();
            var magic4 = reader.ReadByte();

            if (magic1 != (byte)'S' || magic2 != (byte)'C' || magic3 != (byte)'F' || magic4 != (byte)'S')
            {
                throw new InvalidDataException($"Not a valid CSM file: {csmPath}");
            }

            reader.ReadUInt32(); // version
            reader.ReadUInt32(); // encryption flag (already validated in CheckEncryptionConsistency)

            // Read depot ID and chunk count
            var depotId = reader.ReadUInt32();
            var chunkCount = reader.ReadUInt32();

            if (depot != null && depot.Value != depotId)
            {
                throw new InvalidDataException(
                    $"Depot ID mismatch in file {csmPath}. Expected {depot}, found {depotId}.");
            }

            // Read chunk metadata
            for (int i = 0; i < chunkCount; i++)
            {
                var sha = reader.ReadBytes(20);
                var offset = reader.ReadInt64();
                reader.ReadUInt32(); // reserved
                var length = reader.ReadInt32();

                var shaHex = Util.ToHex(sha);
                var metadata = new ChunkMetadata
                {
                    Sha = shaHex,
                    ChunkstoreIndex = chunkstoreIndex,
                    Offset = offset,
                    Length = length
                };

                chunkIndex[shaHex] = metadata;
                chunksPerFile[chunkstoreIndex - 1].Add(metadata);
            }
        }

        /// <summary>
        /// Whether this chunkstore's chunks are AES-encrypted (as they are when downloaded for raw
        /// archival), or already decrypted. A single chunkstore (CSD/CSM set) is always one or the
        /// other - the CSM header records it and mixed content is never allowed. Null only before
        /// the mode has been established (e.g. a brand new, still-empty chunkstore).
        /// </summary>
        public bool? IsEncrypted => isEncrypted;

        /// <summary>
        /// Checks if a chunk with the given SHA1 exists in the chunkstore.
        /// </summary>
        public bool ChunkExists(byte[] sha)
        {
            var shaHex = Util.ToHex(sha);
            return chunkIndex.ContainsKey(shaHex);
        }

        /// <summary>
        /// Extracts the lowercase SHA1 hex from a loose chunk file's name for the given encryption
        /// mode, or returns false if the name doesn't match. Decrypted chunks are named
        /// "&lt;sha&gt;_decrypted" when stored loosely; encrypted chunks are named just "&lt;sha&gt;".
        /// A chunkstore only ever holds one mode - this rejects a name in the wrong mode's format
        /// rather than guessing, since the two are never mixed within one CSD/CSM set.
        /// </summary>
        public static bool TryGetChunkSha(string fileName, bool isEncrypted, out string sha)
        {
            const string DecryptedSuffix = "_decrypted";

            sha = fileName;

            if (!isEncrypted)
            {
                if (!sha.EndsWith(DecryptedSuffix, StringComparison.Ordinal))
                {
                    sha = null;
                    return false;
                }

                sha = sha[..^DecryptedSuffix.Length];
            }
            else if (sha.EndsWith(DecryptedSuffix, StringComparison.Ordinal))
            {
                sha = null;
                return false;
            }

            if (sha.Length != 40 || !sha.All(char.IsAsciiHexDigit))
            {
                sha = null;
                return false;
            }

            sha = sha.ToLowerInvariant();
            return true;
        }

        /// <summary>
        /// Retrieves a chunk by its SHA1 hash.
        /// </summary>
        /// <param name="sha">SHA1 hash of the chunk</param>
        /// <param name="process">Whether to decrypt and decompress the chunk</param>
        /// <returns>The chunk data</returns>
        public byte[] GetChunk(byte[] sha, bool process = false)
        {
            var shaHex = Util.ToHex(sha);

            if (!chunkIndex.TryGetValue(shaHex, out var metadata))
            {
                throw new KeyNotFoundException($"Chunk {shaHex} not found");
            }

            var (csdPath, _) = files[metadata.ChunkstoreIndex - 1];

            using var fileStream = File.OpenRead(csdPath);
            fileStream.Seek(metadata.Offset, SeekOrigin.Begin);

            var buffer = new byte[metadata.Length];
            fileStream.ReadExactly(buffer);

            if (process)
            {
                return ProcessChunk(shaHex, buffer);
            }

            return buffer;
        }

        /// <summary>
        /// Retrieves multiple chunks in parallel for file reconstruction.
        /// </summary>
        public async Task<Dictionary<string, byte[]>> GetChunksAsync(IEnumerable<byte[]> shaList, bool process = false, int maxParallelism = 0)
        {
            maxParallelism = Util.ResolveParallelism(maxParallelism);

            var results = new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            var failures = new ConcurrentDictionary<string, Exception>(StringComparer.OrdinalIgnoreCase);
            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

            // The per-item work below is entirely synchronous (file I/O + CPU decrypt/decompress);
            // Parallel.ForEachAsync already gives up to MaxDegreeOfParallelism concurrent bodies on
            // pool threads on its own, so wrapping this in a nested Task.Run would only add a
            // second, pointless thread-pool scheduling hop per item with no added concurrency.
            await Parallel.ForEachAsync(shaList, options, (sha, ct) =>
            {
                var shaHex = Util.ToHex(sha);
                try
                {
                    var data = GetChunk(sha, process);
                    results[shaHex] = data;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error retrieving chunk {shaHex}: {ex.Message}");
                    failures[shaHex] = ex;
                }

                return ValueTask.CompletedTask;
            });

            // Surface partial failure rather than silently returning a dictionary with fewer
            // entries than requested - a caller indexing by the original SHA list has no other
            // way to tell "not requested" from "failed" apart.
            if (!failures.IsEmpty)
            {
                throw new AggregateException(
                    $"Failed to retrieve {failures.Count:N0} of {results.Count + failures.Count:N0} requested chunks.",
                    failures.Values);
            }

            return results.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        private byte[] ProcessChunk(string shaHex, byte[] content) =>
            ProcessChunkStatic(shaHex, content, isEncrypted == true, depotKey);

        /// <summary>
        /// Decrypts (if applicable) and decompresses raw chunk bytes, auto-detecting the
        /// compression format (LZMA/ZIP/Zstandard) by magic bytes, then verifies the result's
        /// SHA1 matches <paramref name="shaHex"/>, throwing if it doesn't. This is the single
        /// decrypt/decompress core shared by chunkstore reads and loose-file reconstruction - do
        /// not duplicate it. A caller that needs to *report* a mismatch rather than throw on one
        /// (chunk validation) should call <see cref="DecryptAndDecompress"/> directly instead and
        /// compare the hash itself.
        /// </summary>
        internal static byte[] ProcessChunkStatic(string shaHex, byte[] content, bool isEncrypted, byte[] depotKey)
        {
            var decompressed = DecryptAndDecompress(content, isEncrypted, depotKey, shaHex);

            // Verify SHA1
            using var sha1 = SHA1.Create();
            var calculatedSha = Util.ToHex(sha1.ComputeHash(decompressed));

            if (calculatedSha != shaHex)
            {
                throw new InvalidDataException(
                    $"SHA1 mismatch for chunk {shaHex}: expected {shaHex}, got {calculatedSha}");
            }

            return decompressed;
        }

        /// <summary>
        /// Decrypts (if applicable) and decompresses raw chunk bytes, auto-detecting the
        /// compression format (LZMA/ZIP/Zstandard) by magic bytes. Does NOT verify the result's
        /// SHA1 - the shared core beneath both <see cref="ProcessChunkStatic"/> (hard-fails on a
        /// mismatch) and <see cref="ChunkValidator"/>'s chunk validation (reports a mismatch as a
        /// result rather than throwing on it).
        /// </summary>
        internal static byte[] DecryptAndDecompress(byte[] content, bool isEncrypted, byte[] depotKey, string chunkIdForErrors = null)
        {
            // Decrypt if necessary
            if (isEncrypted && depotKey != null)
            {
                content = DecryptChunk(content, depotKey);

                if (content.Length < 4)
                {
                    throw new InvalidDataException(chunkIdForErrors != null
                        ? $"Decrypted data too small to determine compression type for chunk {chunkIdForErrors}"
                        : "Decrypted data too small to determine compression type");
                }
            }

            // Decompress based on format
            if (content.Length >= 3 && content[0] == 'V' && content[1] == 'Z' && content[2] == 'a')
            {
                // LZMA format
                return DecompressLZMA(content);
            }

            if (content.Length >= 4 && content[0] == 'P' && content[1] == 'K' && content[2] == 0x03 && content[3] == 0x04)
            {
                // ZIP format
                return DecompressZip(content);
            }

            if (content.Length >= 4 && content[0] == 'V' && content[1] == 'S' && content[2] == 'Z' && content[3] == 'a')
            {
                // Zstandard format
                return DecompressZstd(content);
            }

            throw new InvalidDataException(chunkIdForErrors != null
                ? $"Unknown compression format for chunk {chunkIdForErrors}"
                : "Unknown compression format");
        }

        private static byte[] DecompressLZMA(ReadOnlySpan<byte> data)
        {
            if (data.Length < 17) // Need header + footer + some data
                throw new InvalidDataException("LZMA chunk too small");

            var expectedSize = BitConverter.ToInt32(data[^6..^2]);
            var lzmaProps = data[7..12].ToArray();
            var compressedPayload = data[12..^10];

            var decompressed = new byte[expectedSize];

            var decoder = new SevenZip.Compression.LZMA.Decoder();
            var propertyBits = lzmaProps[0];
            var dictionarySize = BitConverter.ToUInt32(lzmaProps, 1);

            byte[] properties = [propertyBits,
                (byte)(dictionarySize), (byte)(dictionarySize >> 8),
                (byte)(dictionarySize >> 16), (byte)(dictionarySize >> 24)];

            decoder.SetDecoderProperties(properties);

            using var inputStream = new MemoryStream(compressedPayload.ToArray());
            using var outputStream = new MemoryStream(decompressed);

            decoder.Code(inputStream, outputStream, compressedPayload.Length, expectedSize, null);

            if (outputStream.Position != expectedSize)
            {
                throw new InvalidDataException($"LZMA decompressed size mismatch: expected {expectedSize}, got {outputStream.Position}");
            }

            return decompressed;
        }

        private static byte[] DecompressZip(ReadOnlySpan<byte> data)
        {
            using var zipStream = new MemoryStream(data.ToArray());
            using var zip = new ZipArchive(zipStream, ZipArchiveMode.Read);

            if (zip.Entries.Count != 1)
                throw new InvalidDataException($"Expected 1 ZIP entry, found {zip.Entries.Count}");

            using var entryStream = zip.Entries[0].Open();
            using var decompressedStream = new MemoryStream();
            entryStream.CopyTo(decompressedStream);

            return decompressedStream.ToArray();
        }

        private static byte[] DecompressZstd(ReadOnlySpan<byte> data)
        {
            if (data.Length < 23) // Need header + footer + some data
                throw new InvalidDataException("Zstd chunk too small");

            var expectedSize = BitConverter.ToInt32(data[^11..^7]);

            // Verify CRC32 consistency
            var headerCrc = BitConverter.ToUInt32(data[4..8]);
            var footerCrc = BitConverter.ToUInt32(data[^15..^11]);
            if (headerCrc != footerCrc)
            {
                throw new InvalidDataException($"Zstd CRC32 mismatch: header={headerCrc:X8}, footer={footerCrc:X8}");
            }

            // Verify footer signature "zsv"
            if (data[^3] != (byte)'z' || data[^2] != (byte)'s' || data[^1] != (byte)'v')
            {
                throw new InvalidDataException("Invalid Zstd footer signature");
            }

            var compressedPayload = data[8..^15];
            var decompressed = new byte[expectedSize];

            using var decompressor = new ZstdSharp.Decompressor();
            var actualSize = decompressor.Unwrap(compressedPayload, decompressed);

            if (actualSize != expectedSize)
            {
                throw new InvalidDataException($"Zstd decompressed size mismatch: expected {expectedSize}, got {actualSize}");
            }

            return decompressed;
        }

        private static byte[] DecryptChunk(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Key = key;

            if (data.Length < 16)
            {
                throw new InvalidDataException("Chunk data too small to contain IV");
            }

            // Decrypt the first 16 bytes (IV) with ECB
            Span<byte> iv = stackalloc byte[16];
            aes.DecryptEcb(data.AsSpan(0, 16), iv, PaddingMode.None);

            // Decrypt the rest with CBC + PKCS7
            var encryptedPayload = data.AsSpan(16);
            var decryptedBuffer = new byte[encryptedPayload.Length];
            var decryptedLength = aes.DecryptCbc(encryptedPayload, iv, decryptedBuffer, PaddingMode.PKCS7);

            return decryptedBuffer[..decryptedLength];
        }

        /// <summary>
        /// Writes a chunk to the chunkstore.
        /// Thread-safe: Multiple threads can call this concurrently.
        /// </summary>
        /// <param name="sha">SHA1 hash of the chunk</param>
        /// <param name="content">Chunk data (encrypted and compressed)</param>
        /// <returns>True if the chunk was written, false if it already existed</returns>
        public bool WriteChunk(byte[] sha, byte[] content)
        {
            var shaHex = Util.ToHex(sha);

            // Fast check without lock (if already exists, skip immediately)
            if (chunkIndex.ContainsKey(shaHex))
            {
                return false;
            }

            // CRITICAL SECTION: Only one thread can write at a time
            lock (writeLock)
            {
                // Double-check after acquiring lock (another thread might have added it)
                if (chunkIndex.ContainsKey(shaHex))
                {
                    return false;
                }

                // Create new file if necessary
                if (currentCsd == null || currentFileSize + content.Length > maxFileSize)
                {
                    CreateNewFileUnsafe(); // Already inside lock
                }

                // Write to CSD file
                long offset;
                using (var stream = File.Open(currentCsd, FileMode.Append, FileAccess.Write))
                {
                    offset = stream.Position;
                    stream.Write(content);
                    currentFileSize += content.Length;
                }

                // Add to indexes
                var metadata = new ChunkMetadata
                {
                    Sha = shaHex,
                    ChunkstoreIndex = currentFileIndex,
                    Offset = offset,
                    Length = content.Length
                };

                chunkIndex[shaHex] = metadata;
                chunksPerFile[currentFileIndex - 1].Add(metadata);

                return true;
            }
        }

        /// <summary>
        /// Saves the current chunkstore state to a checkpoint file for crash recovery.
        /// Thread-safe: Uses writeLock to ensure consistency.
        /// Call this periodically during packing operations to enable resume capability.
        /// </summary>
        public void SaveCheckpoint()
        {
            lock (writeLock)
            {
                SaveCheckpointUnsafe();
            }
        }

        private void SaveCheckpointUnsafe()
        {
            if (depot == null)
            {
                throw new InvalidOperationException("Cannot save checkpoint without depot ID");
            }

            var checkpoint = new ChunkstoreCheckpoint
            {
                DepotId = depot.Value,
                IsEncrypted = isEncrypted ?? false,
                CurrentFileIndex = currentFileIndex,
                CurrentFileSize = currentFileSize,
                ChunkIndex = chunkIndex.ToDictionary(
                    kvp => kvp.Key,
                    kvp => new ChunkstoreCheckpoint.ChunkMetadataProto
                    {
                        Sha = kvp.Value.Sha,
                        ChunkstoreIndex = kvp.Value.ChunkstoreIndex,
                        Offset = kvp.Value.Offset,
                        Length = kvp.Value.Length
                    })
            };

            CheckpointFile.Save(CheckpointPath, checkpoint);
        }

        /// <summary>
        /// Loads checkpoint data from disk to resume interrupted operations.
        /// Thread-safe: Uses writeLock for consistency.
        /// </summary>
        /// <returns>True if checkpoint was loaded, false if no checkpoint exists</returns>
        public bool LoadCheckpoint()
        {
            if (!File.Exists(CheckpointPath))
            {
                return false;
            }

            lock (writeLock)
            {
                return LoadCheckpointUnsafe();
            }
        }

        private bool LoadCheckpointUnsafe()
        {
            if (!File.Exists(CheckpointPath))
            {
                return false;
            }

            try
            {
                var checkpoint = CheckpointFile.Load<ChunkstoreCheckpoint>(CheckpointPath);

                // Restore state
                depot = checkpoint.DepotId;
                isEncrypted = checkpoint.IsEncrypted;
                currentFileIndex = checkpoint.CurrentFileIndex;
                currentFileSize = checkpoint.CurrentFileSize;

                chunkIndex.Clear();
                foreach (var kvp in checkpoint.ChunkIndex)
                {
                    var proto = kvp.Value;
                    chunkIndex[kvp.Key] = new ChunkMetadata
                    {
                        Sha = proto.Sha,
                        ChunkstoreIndex = proto.ChunkstoreIndex,
                        Offset = proto.Offset,
                        Length = proto.Length
                    };
                }

                // Restore file list
                files.Clear();
                for (int i = 1; i <= currentFileIndex; i++)
                {
                    var baseName = $"{depot}_depotcache_{i}";
                    var csdPath = Path.Combine(folder, baseName + ".csd");
                    var csmPath = Path.Combine(folder, baseName + ".csm");
                    files.Add((csdPath, csmPath));
                }

                // Update current file tracking
                if (files.Count > 0)
                {
                    (currentCsd, currentCsm) = files[currentFileIndex - 1];
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to load checkpoint: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Deletes the checkpoint file after successful completion.
        /// </summary>
        public void ClearCheckpoint()
        {
            if (File.Exists(CheckpointPath))
            {
                File.Delete(CheckpointPath);
                Console.WriteLine("Checkpoint cleared");
            }
        }
        /// <summary>
        /// Writes or updates CSM metadata files.
        /// Thread-safe: Can be called concurrently.
        /// </summary>
        /// <param name="index">Specific chunkstore index to write, or null for all</param>
        public void WriteCSM(int? index = null)
        {
            lock (writeLock)
            {
                if (index.HasValue)
                {
                    WriteSingleCSMUnsafe(index.Value);
                }
                else
                {
                    for (int i = 1; i <= files.Count; i++)
                    {
                        WriteSingleCSMUnsafe(i);
                    }
                }
            }
        }

        private void WriteSingleCSMUnsafe(int index)
        {
            var (_, csmPath) = files[index - 1];
            // O(1) lookup via chunksPerFile rather than scanning/filtering the whole chunkIndex -
            // this runs once per segment during every pack/rebuild, so an O(total chunks) scan
            // here would make the whole operation O(total chunks * segment count).
            var chunks = chunksPerFile[index - 1].OrderBy(c => c.Offset).ToList();

            using var stream = File.Open(csmPath, FileMode.Open, FileAccess.Write);
            using var writer = new BinaryWriter(stream);

            // Seek past header
            writer.BaseStream.Seek(12, SeekOrigin.Begin);

            // Write depot ID and chunk count
            writer.Write(depot ?? 0);
            writer.Write(chunks.Count);

            // Write chunk metadata (already sorted by offset for consistency)
            foreach (var chunk in chunks)
            {
                writer.Write(Convert.FromHexString(chunk.Sha));
                writer.Write(chunk.Offset);
                writer.Write(0u); // reserved
                writer.Write(chunk.Length);
            }
        }

        private void WriteSingleCSM(int index)
        {
            lock (writeLock)
            {
                WriteSingleCSMUnsafe(index);
            }
        }
        /// <summary>
        /// Packs loose chunk files into the chunkstore.
        /// Chunks are written in SHA1 alphanumeric order for consistency.
        /// Thread-safe: Multiple threads can call Pack concurrently (each with different file lists).
        /// </summary>
        /// <param name="chunkFiles">List of chunk file paths (filenames should be SHA1 hashes)</param>
        public void Pack(IEnumerable<string> chunkFiles)
        {
            // Sort files by SHA1 (extracted from filename) before writing
            // This ensures chunks are written in alphanumeric order even with multithreading
            var sortedFiles = chunkFiles
                .Select(filePath =>
                {
                    if (!File.Exists(filePath))
                    {
                        throw new FileNotFoundException($"File not found: {filePath}");
                    }

                    var fileName = Path.GetFileName(filePath);

                    if (!TryGetChunkSha(fileName, isEncrypted.GetValueOrDefault(), out var sha))
                    {
                        throw new InvalidOperationException($"Invalid SHA1 filename: {fileName}");
                    }

                    return new { FilePath = filePath, Sha = sha, FileName = fileName };
                })
                .OrderBy(f => f.Sha, StringComparer.OrdinalIgnoreCase) // Sort by SHA1
                .ToList();

            // Write chunks in sorted order
            foreach (var file in sortedFiles)
            {
                var content = File.ReadAllBytes(file.FilePath);
                var shaBytes = Convert.FromHexString(file.Sha);

                if (WriteChunk(shaBytes, content)) // WriteChunk is thread-safe
                {
                    Console.WriteLine($"Packed: {file.FileName}");
                }
                else
                {
                    Console.WriteLine($"Skipped (duplicate): {file.FileName}");
                }
            }

            // Finalize current CSM
            if (currentFileIndex > 0)
            {
                WriteCSM(currentFileIndex); // WriteCSM is thread-safe
            }
        }

        /// <summary>
        /// Packs loose chunk files into the chunkstore with ordered parallel processing.
        /// Files are sorted by SHA1, then written in order with parallel file I/O.
        /// Supports automatic checkpointing for crash recovery and resume capability.
        /// This is the recommended method for bulk packing operations.
        /// </summary>
        /// <param name="chunkFiles">List of chunk file paths (filenames should be SHA1 hashes)</param>
        /// <param name="maxParallelism">Maximum number of parallel file reads (default: CPU count - 1)</param>
        /// <param name="batchSize">Number of chunks to buffer in memory at once (default: 1000)</param>
        /// <param name="checkpointInterval">Save checkpoint every N chunks (0 to disable, default: 5000)</param>
        /// <param name="resumeFromCheckpoint">Try to resume from existing checkpoint (default: true)</param>
        public async Task PackAsync(
            IEnumerable<string> chunkFiles,
            int maxParallelism = 0,
            int batchSize = 1000,
            int checkpointInterval = 5000,
            bool resumeFromCheckpoint = true)
        {
            maxParallelism = Util.ResolveParallelism(maxParallelism);

            // Try to resume from checkpoint
            HashSet<string> processedChunks = null;
            if (resumeFromCheckpoint && chunkIndex.Count > 0)
            {
                Console.WriteLine($"Resuming from checkpoint with {chunkIndex.Count:N0} already-processed chunks");
                processedChunks = chunkIndex.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            }

            // Step 1: Validate and sort all files by SHA1 (fast, no I/O)
            var sortedFiles = chunkFiles
                .Select(filePath =>
                {
                    if (!File.Exists(filePath))
                    {
                        throw new FileNotFoundException($"File not found: {filePath}");
                    }

                    var fileName = Path.GetFileName(filePath);

                    if (!TryGetChunkSha(fileName, isEncrypted.GetValueOrDefault(), out var sha))
                    {
                        throw new InvalidOperationException($"Invalid SHA1 filename: {fileName}");
                    }

                    return new ChunkFile
                    {
                        FilePath = filePath,
                        Sha = sha,
                        FileName = fileName
                    };
                })
                .OrderBy(f => f.Sha, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Filter out already processed chunks if resuming
            if (processedChunks != null)
            {
                var originalCount = sortedFiles.Count;
                sortedFiles = sortedFiles.Where(f => !processedChunks.Contains(f.Sha)).ToList();
                Console.WriteLine($"Skipping {originalCount - sortedFiles.Count:N0} already-processed chunks from checkpoint");
            }

            if (sortedFiles.Count == 0)
            {
                Console.WriteLine("No chunks to pack (all already processed)");
                return;
            }

            Console.WriteLine($"Packing {sortedFiles.Count:N0} chunks in alphanumeric order...");

            // Step 2: Process in batches with periodic checkpointing
            var totalChunks = sortedFiles.Count;
            var packedCount = 0;
            var skippedCount = 0;
            var checkpointCounter = 0;
            var lastCheckpointTime = DateTime.Now;

            for (int i = 0; i < totalChunks; i += batchSize)
            {
                var batch = sortedFiles.Skip(i).Take(batchSize).ToList();

                // Step 2a: Read batch in parallel
                var chunkData = new (string Sha, byte[] Content, string FileName)[batch.Count];
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

                await Parallel.ForEachAsync(batch.Select((f, idx) => (f, idx)), options, (item, ct) =>
                {
                    var (file, index) = item;

                    // Skip if already exists (fast check without loading file)
                    if (ChunkExists(Convert.FromHexString(file.Sha)))
                    {
                        chunkData[index] = (file.Sha, null, file.FileName);
                    }
                    else
                    {
                        var content = File.ReadAllBytes(file.FilePath);
                        chunkData[index] = (file.Sha, content, file.FileName);
                    }

                    return ValueTask.CompletedTask;
                });

                // Step 2b: Write batch sequentially in sorted order
                foreach (var (sha, content, fileName) in chunkData)
                {
                    if (content == null)
                    {
                        skippedCount++;
                        continue;
                    }

                    var shaBytes = Convert.FromHexString(sha);
                    if (WriteChunk(shaBytes, content))
                    {
                        packedCount++;
                        checkpointCounter++;

                        if (packedCount % 100 == 0)
                        {
                            Console.WriteLine($"Packed {Util.FormatProgress(packedCount, totalChunks)} chunks");
                        }

                        // Save checkpoint periodically (by count or time)
                        if (checkpointInterval > 0 && (
                            checkpointCounter >= checkpointInterval ||
                            (DateTime.Now - lastCheckpointTime).TotalMinutes >= 5))
                        {
                            Console.WriteLine("Saving checkpoint...");
                            SaveCheckpoint();
                            checkpointCounter = 0;
                            lastCheckpointTime = DateTime.Now;
                            Console.WriteLine($"Checkpoint saved ({chunkIndex.Count:N0} chunks indexed)");
                        }
                    }
                    else
                    {
                        skippedCount++;
                    }
                }
            }

            // Finalize current CSM
            if (currentFileIndex > 0)
            {
                Console.WriteLine("Writing CSM metadata...");
                WriteCSM(currentFileIndex);
            }

            // Save final checkpoint then immediately clear it on success
            if (checkpointInterval > 0)
            {
                Console.WriteLine("Saving final checkpoint...");
                SaveCheckpoint();
                Console.WriteLine("Clearing checkpoint (operation complete)...");
                ClearCheckpoint();
            }

            Console.WriteLine($"Pack complete: {packedCount:N0} packed, {skippedCount:N0} skipped");
            Console.WriteLine($"Total chunks in chunkstore: {chunkIndex.Count:N0}");
        }

        /// <summary>
        /// Copies every chunk from <paramref name="source"/> into this chunkstore in ascending
        /// SHA1 order, producing the canonical, deterministic on-disk layout - the same layout a
        /// from-scratch <see cref="PackAsync"/> of the same chunk set would produce. Used by
        /// 'chunkstore rebuild' to restore that property after incremental <see cref="WriteChunk"/>
        /// calls (e.g. via 'update') have appended chunks out of order. Copies raw (still
        /// encrypted/compressed) bytes directly - no decrypt/decompress needed, since rebuild
        /// never touches chunk content, only its position. Mirrors PackAsync's
        /// batching/parallel-read/checkpoint shape, reading from another chunkstore's
        /// <see cref="GetChunk"/> instead of loose files on disk.
        /// </summary>
        public async Task RebuildFromAsync(
            Chunkstore source,
            int maxParallelism = 0,
            int batchSize = 1000,
            int checkpointInterval = 5000,
            bool resumeFromCheckpoint = true,
            bool deleteSourceAsWeGo = false)
        {
            maxParallelism = Util.ResolveParallelism(maxParallelism);

            // Snapshot the source's chunk index once - EnumerateChunks() does a full
            // ConcurrentDictionary copy, and both uses below (segment membership, sort order) only
            // need this one snapshot; source is never mutated during a rebuild copy.
            var sourceChunks = source.EnumerateChunks().ToList();

            // Per-old-segment chunk membership (metadata only - SHA1s, not bytes) and the set of
            // segments already deleted. Only needed for deleteSourceAsWeGo, but building it is
            // cheap even for a large store.
            Dictionary<int, List<string>> sourceChunksBySegment = null;
            HashSet<int> deletedSegments = null;
            if (deleteSourceAsWeGo)
            {
                sourceChunksBySegment = sourceChunks
                    .GroupBy(c => c.ChunkstoreIndex)
                    .ToDictionary(g => g.Key, g => g.Select(c => c.Sha).ToList());
                deletedSegments = [];
            }

            // Try to resume from checkpoint (loaded automatically by the constructor if this
            // target folder already has partial state from an earlier, interrupted attempt).
            HashSet<string> processedChunks = null;
            if (resumeFromCheckpoint && chunkIndex.Count > 0)
            {
                Console.WriteLine($"Resuming from checkpoint with {chunkIndex.Count:N0} already-copied chunks");
                processedChunks = chunkIndex.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            }

            // A crash could have landed after a segment became logically complete (its chunks are
            // all in this already-loaded target state) but before it was physically deleted. This
            // is a crash-recovery hygiene check, not a "resume the copy" decision - it must run
            // whenever there's pre-existing target state, even if the caller passed -no-resume for
            // the copy loop itself (that flag only affects which chunks get re-read, never whether
            // an already-drained source segment is safe to clean up).
            if (deleteSourceAsWeGo && chunkIndex.Count > 0)
            {
                DeleteDrainedSourceSegments(source, sourceChunksBySegment, deletedSegments);

                // The sweep above may have just deleted a source segment whose chunks are already
                // recorded here. -no-resume's "re-copy everything, don't trust the checkpoint" idea
                // is fundamentally unsafe combined with this flag once any deletion has happened -
                // there's nothing left to re-read. Chunks already in this index must always be
                // skipped in this mode, regardless of resumeFromCheckpoint.
                if (processedChunks == null)
                {
                    Console.WriteLine($"Note: -no-resume does not apply to the {chunkIndex.Count:N0} chunks already recorded here - " +
                        "-delete-source-as-we-go may have already deleted their only source copy, so they can't be re-read regardless.");
                    processedChunks = chunkIndex.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
                }
            }

            var sortedShas = sourceChunks
                .Select(c => c.Sha)
                .OrderBy(sha => sha, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (processedChunks != null)
            {
                var originalCount = sortedShas.Count;
                sortedShas = sortedShas.Where(sha => !processedChunks.Contains(sha)).ToList();
                Console.WriteLine($"Skipping {originalCount - sortedShas.Count:N0} already-copied chunks from checkpoint");
            }

            if (sortedShas.Count == 0)
            {
                Console.WriteLine("No chunks to copy (all already copied)");
                return;
            }

            Console.WriteLine($"Copying {sortedShas.Count:N0} chunks in alphanumeric order...");

            // Pairs every checkpoint save with the deletion sweep it gates, structurally rather
            // than by convention - a future new checkpoint-save call site (a different trigger, an
            // early-exit path) gets the pairing for free just by calling this instead of
            // SaveCheckpoint() directly, instead of having to remember to add the "if
            // (deleteSourceAsWeGo) DeleteDrainedSourceSegments(...)" that follows it by hand.
            void SaveCheckpointAndDrain()
            {
                SaveCheckpoint();
                if (deleteSourceAsWeGo)
                {
                    DeleteDrainedSourceSegments(source, sourceChunksBySegment, deletedSegments);
                }
            }

            var totalChunks = sortedShas.Count;
            var copiedCount = 0;
            var skippedCount = 0;
            var checkpointCounter = 0;
            var lastCheckpointTime = DateTime.Now;

            for (var i = 0; i < totalChunks; i += batchSize)
            {
                var batch = sortedShas.Skip(i).Take(batchSize).ToList();

                // Step 1: Read batch in parallel from the source chunkstore
                var chunkData = new (string Sha, byte[] Content)[batch.Count];
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

                await Parallel.ForEachAsync(batch.Select((sha, idx) => (sha, idx)), options, (item, ct) =>
                {
                    var (sha, index) = item;

                    // Skip if already copied (fast check, e.g. duplicate SHA races across batches)
                    if (ChunkExists(Convert.FromHexString(sha)))
                    {
                        chunkData[index] = (sha, null);
                    }
                    else
                    {
                        var content = source.GetChunk(Convert.FromHexString(sha), process: false);
                        chunkData[index] = (sha, content);
                    }

                    return ValueTask.CompletedTask;
                });

                // Step 2: Write batch sequentially in sorted order
                foreach (var (sha, content) in chunkData)
                {
                    if (content == null)
                    {
                        skippedCount++;
                        continue;
                    }

                    var shaBytes = Convert.FromHexString(sha);
                    if (WriteChunk(shaBytes, content))
                    {
                        // Before this chunk's only other copy can ever be deleted, confirm the
                        // bytes that landed in the new CSD actually match what was read - this
                        // catches a bad write (truncation, disk error), not pre-existing archive
                        // corruption (that's chunkstore verify's job, and would need a depot key
                        // to check - a raw byte comparison doesn't).
                        if (deleteSourceAsWeGo)
                        {
                            var metadata = chunkIndex[sha];
                            var (writtenCsdPath, _) = files[metadata.ChunkstoreIndex - 1];
                            byte[] readBack;
                            using (var verifyStream = File.OpenRead(writtenCsdPath))
                            {
                                verifyStream.Seek(metadata.Offset, SeekOrigin.Begin);
                                readBack = new byte[metadata.Length];
                                verifyStream.ReadExactly(readBack);
                            }

                            if (!readBack.AsSpan().SequenceEqual(content))
                            {
                                throw new InvalidDataException(
                                    $"Post-write verification failed for chunk {sha}: bytes read back from " +
                                    "the new chunkstore don't match what was written. Aborting before any " +
                                    "source data is deleted.");
                            }
                        }

                        copiedCount++;
                        checkpointCounter++;

                        if (copiedCount % 100 == 0)
                        {
                            Console.WriteLine($"Copied {Util.FormatProgress(copiedCount, totalChunks)} chunks");
                        }

                        if (checkpointInterval > 0 && (
                            checkpointCounter >= checkpointInterval ||
                            (DateTime.Now - lastCheckpointTime).TotalMinutes >= 5))
                        {
                            Console.WriteLine("Saving checkpoint...");
                            // Only now that the checkpoint recording their new location is durably
                            // on disk is it safe to delete any old segment that's fully drained -
                            // deleting right after WriteChunk (before this) would risk losing data
                            // that's physically written but has no surviving record of where.
                            SaveCheckpointAndDrain();
                            checkpointCounter = 0;
                            lastCheckpointTime = DateTime.Now;
                            Console.WriteLine($"Checkpoint saved ({chunkIndex.Count:N0} chunks indexed)");
                        }
                    }
                    else
                    {
                        skippedCount++;
                    }
                }
            }

            // Finalize current CSM
            if (currentFileIndex > 0)
            {
                Console.WriteLine("Writing CSM metadata...");
                WriteCSM(currentFileIndex);
            }

            // Save final checkpoint then immediately clear it on success
            if (checkpointInterval > 0)
            {
                Console.WriteLine("Saving final checkpoint...");
                SaveCheckpointAndDrain();

                Console.WriteLine("Clearing checkpoint (operation complete)...");
                ClearCheckpoint();
            }

            Console.WriteLine($"Rebuild copy complete: {copiedCount:N0} copied, {skippedCount:N0} skipped");
            Console.WriteLine($"Total chunks in chunkstore: {chunkIndex.Count:N0}");
        }

        /// <summary>
        /// Deletes any old source segment whose every chunk is now confirmed present in this
        /// (target) chunkstore's chunk index - called only right after that index has just been
        /// durably checkpointed, never immediately after an individual WriteChunk, so a segment
        /// is never removed based on state that could still vanish in a crash. Failing to delete
        /// a given segment (e.g. a permissions error) is logged and skipped, not fatal - the copy
        /// itself is already correct either way, this only affects how much space gets reclaimed.
        /// </summary>
        private void DeleteDrainedSourceSegments(Chunkstore source, Dictionary<int, List<string>> sourceChunksBySegment, HashSet<int> deletedSegments)
        {
            foreach (var (segmentIndex, shas) in sourceChunksBySegment)
            {
                if (deletedSegments.Contains(segmentIndex) || !shas.All(chunkIndex.ContainsKey))
                {
                    continue;
                }

                try
                {
                    var csdPath = source.GetCsdPath(segmentIndex);
                    var csmPath = csdPath != null ? Path.ChangeExtension(csdPath, ".csm") : null;

                    if (csdPath != null && File.Exists(csdPath))
                    {
                        File.Delete(csdPath);
                    }

                    if (csmPath != null && File.Exists(csmPath))
                    {
                        File.Delete(csmPath);
                    }

                    deletedSegments.Add(segmentIndex);
                    Console.WriteLine($"Deleted drained source segment {segmentIndex} (all {shas.Count:N0} chunks confirmed in new store)");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: failed to delete drained source segment {segmentIndex}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Packs a single chunk file into the chunkstore.
        /// Useful for incremental additions or when processing files one at a time.
        /// </summary>
        /// <param name="chunkFile">Path to the chunk file</param>
        /// <returns>True if packed, false if skipped (already exists)</returns>
        public bool PackSingle(string chunkFile)
        {
            if (!File.Exists(chunkFile))
            {
                throw new FileNotFoundException($"File not found: {chunkFile}");
            }

            var fileName = Path.GetFileName(chunkFile);

            if (!TryGetChunkSha(fileName, isEncrypted.GetValueOrDefault(), out var sha))
            {
                throw new InvalidOperationException($"Invalid SHA1 filename: {fileName}");
            }

            var shaBytes = Convert.FromHexString(sha);

            // Quick check before reading file
            if (ChunkExists(shaBytes))
            {
                Console.WriteLine($"Skipped (duplicate): {fileName}");
                return false;
            }

            var content = File.ReadAllBytes(chunkFile);

            if (WriteChunk(shaBytes, content))
            {
                Console.WriteLine($"Packed: {fileName}");
                return true;
            }

            return false;
        }

        private class ChunkFile
        {
            public string FilePath { get; init; }
            public string Sha { get; init; }
            public string FileName { get; init; }
        }
        /// <summary>
        /// Unpacks all chunks to loose files with parallel I/O.
        /// Optimized for bulk unpacking operations.
        /// </summary>
        /// <param name="outputFolder">Destination folder</param>
        /// <param name="maxParallelism">Maximum parallel operations (default: CPU count - 1)</param>
        /// <param name="skipExisting">Skip files that already exist (default: true)</param>
        public async Task UnpackAllAsync(string outputFolder, int maxParallelism = 0, bool skipExisting = true)
        {
            Directory.CreateDirectory(outputFolder);

            maxParallelism = Util.ResolveParallelism(maxParallelism);

            var allChunks = chunkIndex.Values.ToList();
            Console.WriteLine($"Unpacking {allChunks.Count} chunks...");

            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };
            var unpackedCount = 0;
            var skippedCount = 0;
            var lockObj = new object();

            await Parallel.ForEachAsync(allChunks, options, (chunk, ct) =>
            {
                var fileName = chunk.Sha;
                if (!isEncrypted.GetValueOrDefault())
                {
                    fileName += "_decrypted";
                }

                var outputPath = Path.Combine(outputFolder, fileName);

                if (skipExisting && File.Exists(outputPath))
                {
                    lock (lockObj)
                    {
                        skippedCount++;
                        if ((unpackedCount + skippedCount) % 100 == 0)
                        {
                            Console.WriteLine($"Progress: {Util.FormatProgress(unpackedCount + skippedCount, allChunks.Count)}");
                        }
                    }
                }
                else
                {
                    try
                    {
                        var (csdPath, _) = files[chunk.ChunkstoreIndex - 1];

                        // Each thread gets its own file handle
                        using var input = File.OpenRead(csdPath);
                        input.Seek(chunk.Offset, SeekOrigin.Begin);

                        var buffer = new byte[chunk.Length];
                        input.ReadExactly(buffer);

                        // Write atomically using temp file
                        var tempPath = outputPath + ".tmp";
                        File.WriteAllBytes(tempPath, buffer);
                        File.Move(tempPath, outputPath, overwrite: true);

                        lock (lockObj)
                        {
                            unpackedCount++;
                            if (unpackedCount % 100 == 0)
                            {
                                Console.WriteLine($"Unpacked {Util.FormatProgress(unpackedCount, allChunks.Count)} chunks");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error unpacking {fileName}: {ex.Message}");
                    }
                }

                return ValueTask.CompletedTask;
            });

            Console.WriteLine($"Unpack complete: {unpackedCount} unpacked, {skippedCount} skipped");
        }

        /// <summary>
        /// Unpacks specific chunks by SHA1 hash with parallel I/O.
        /// Optimized for selective unpacking operations.
        /// </summary>
        /// <param name="outputFolder">Destination folder</param>
        /// <param name="shaList">List of SHA1 hashes to unpack</param>
        /// <param name="maxParallelism">Maximum parallel operations (default: CPU count - 1)</param>
        /// <param name="skipExisting">Skip files that already exist (default: true)</param>
        public async Task UnpackAsync(string outputFolder, IEnumerable<string> shaList, int maxParallelism = 0, bool skipExisting = true)
        {
            Directory.CreateDirectory(outputFolder);

            maxParallelism = Util.ResolveParallelism(maxParallelism);

            // Filter to only chunks that exist
            var chunksToUnpack = shaList
                .Select(sha => sha.ToLowerInvariant())
                .Where(sha => chunkIndex.ContainsKey(sha))
                .Select(sha => chunkIndex[sha])
                .ToList();

            var requestedCount = shaList.Count();
            var foundCount = chunksToUnpack.Count;

            if (foundCount < requestedCount)
            {
                Console.WriteLine($"Warning: {requestedCount - foundCount} requested chunks not found in chunkstore");
            }

            if (foundCount == 0)
            {
                Console.WriteLine("No chunks to unpack");
                return;
            }

            Console.WriteLine($"Unpacking {foundCount} chunks...");

            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };
            var unpackedCount = 0;
            var skippedCount = 0;
            var lockObj = new object();

            await Parallel.ForEachAsync(chunksToUnpack, options, (chunk, ct) =>
            {
                var fileName = chunk.Sha;
                if (!isEncrypted.GetValueOrDefault())
                {
                    fileName += "_decrypted";
                }

                var outputPath = Path.Combine(outputFolder, fileName);

                if (skipExisting && File.Exists(outputPath))
                {
                    lock (lockObj) { skippedCount++; }
                }
                else
                {
                    try
                    {
                        var (csdPath, _) = files[chunk.ChunkstoreIndex - 1];

                        using var input = File.OpenRead(csdPath);
                        input.Seek(chunk.Offset, SeekOrigin.Begin);

                        var buffer = new byte[chunk.Length];
                        input.ReadExactly(buffer);

                        // Write atomically
                        var tempPath = outputPath + ".tmp";
                        File.WriteAllBytes(tempPath, buffer);
                        File.Move(tempPath, outputPath, overwrite: true);

                        lock (lockObj)
                        {
                            unpackedCount++;
                            Console.WriteLine($"Unpacked: {fileName} ({unpackedCount}/{foundCount})");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error unpacking {fileName}: {ex.Message}");
                    }
                }

                return ValueTask.CompletedTask;
            });

            Console.WriteLine($"Unpack complete: {unpackedCount} unpacked, {skippedCount} skipped");
        }

        /// <summary>
        /// Unpacks a single chunk file into the chunkstore.
        /// Useful for incremental additions or when processing files one at a time.
        /// </summary>
        /// <param name="chunkFile">Path to the chunk file</param>
        /// <returns>True if unpacked, false if not found or skipped</returns>
        public bool UnpackSingle(string outputFolder, string sha)
        {
            Directory.CreateDirectory(outputFolder);

            sha = sha.ToLowerInvariant();
            if (!chunkIndex.TryGetValue(sha, out var chunk))
            {
                Console.WriteLine($"Chunk not found: {sha}");
                return false;
            }

            var fileName = chunk.Sha;
            if (!isEncrypted.GetValueOrDefault())
            {
                fileName += "_decrypted";
            }

            var outputPath = Path.Combine(outputFolder, fileName);

            if (File.Exists(outputPath))
            {
                Console.WriteLine($"Skipped (already exists): {fileName}");
                return false;
            }

            try
            {
                var (csdPath, _) = files[chunk.ChunkstoreIndex - 1];

                using var input = File.OpenRead(csdPath);
                input.Seek(chunk.Offset, SeekOrigin.Begin);

                var buffer = new byte[chunk.Length];
                input.ReadExactly(buffer);

                // Write atomically
                var tempPath = outputPath + ".tmp";
                File.WriteAllBytes(tempPath, buffer);
                File.Move(tempPath, outputPath, overwrite: true);

                Console.WriteLine($"Unpacked: {fileName}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error unpacking {fileName}: {ex.Message}");
                return false;
            }
        }

        private void CreateNewFile()
        {
            lock (writeLock)
            {
                CreateNewFileUnsafe();
            }
        }

        private void CreateNewFileUnsafe()
        {
            // Finalize current CSM if exists
            if (currentFileIndex > 0)
            {
                WriteSingleCSMUnsafe(currentFileIndex);
            }

            if (isEncrypted == null)
            {
                throw new InvalidOperationException("Encryption status must be set before creating chunkstore files");
            }

            currentFileIndex++;
            var baseName = $"{depot}_depotcache_{currentFileIndex}";
            currentCsd = Path.Combine(folder, baseName + ".csd");
            currentCsm = Path.Combine(folder, baseName + ".csm");
            files.Add((currentCsd, currentCsm));
            chunksPerFile.Add([]);
            currentFileSize = 0;

            // Create empty CSD file
            File.Create(currentCsd).Dispose();

            // Write CSM header
            using var stream = File.Create(currentCsm);
            using var writer = new BinaryWriter(stream);

            // Write magic bytes in correct order (big-endian)
            writer.Write((byte)'S');
            writer.Write((byte)'C');
            writer.Write((byte)'F');
            writer.Write((byte)'S');
            writer.Write(SCFS_VERSION);
            writer.Write(isEncrypted == true ? SCFS_ENCRYPTED : SCFS_DECRYPTED);
        }

        /// <summary>
        /// Enumerates all chunks in the chunkstore for validation purposes.
        /// </summary>
        /// <returns>Enumerable of chunk metadata</returns>
        public IEnumerable<ChunkMetadata> EnumerateChunks()
        {
            return chunkIndex.Values;
        }

        /// <summary>
        /// Returns the path to the CSD file for the given 1-based index, or null if it doesn't exist.
        /// </summary>
        public string GetCsdPath(int index)
        {
            if (index < 1 || index > files.Count)
                return null;
            return files[index - 1].csdPath;
        }

        /// <summary>
        /// Gets detailed statistics about the chunkstore.
        /// </summary>
        public ChunkstoreStats GetStats()
        {
            var totalSize = files.Sum(f => new FileInfo(f.csdPath).Length);

            return new ChunkstoreStats
            {
                DepotId = depot ?? 0,
                IsEncrypted = isEncrypted ?? false,
                FileCount = files.Count,
                TotalChunks = chunkIndex.Count,
                TotalSize = totalSize
            };
        }

        public void Dispose()
        {
            // No resources to dispose with native collections
        }
    }

    public class ChunkstoreStats
    {
        public uint DepotId { get; init; }
        public bool IsEncrypted { get; init; }
        public int FileCount { get; init; }
        public int TotalChunks { get; init; }
        public long TotalSize { get; init; }

        public override string ToString()
        {
            return $"Chunkstore(depot={DepotId}, encrypted={IsEncrypted}, " +
                   $"files={FileCount}, chunks={TotalChunks:N0}, size={TotalSize:N0} bytes)";
        }
    }
}
