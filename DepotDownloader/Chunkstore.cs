// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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

        [ProtoMember(6)]
        public List<ChunkList> ChunksPerFile { get; set; }

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

        [ProtoContract]
        public class ChunkList
        {
            [ProtoMember(1)]
            public List<ChunkMetadataProto> Chunks { get; set; } = new();
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
        private readonly List<List<ChunkMetadata>> chunksPerFile = new(); // For ordered CSM generation

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
        public Chunkstore(string folder, uint? depot = null, byte[] depotKey = null, bool? isEncrypted = null, long maxFileSize = 2L * 1024 * 1024 * 1024)
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
            LoadExistingFiles();
        }

        private string CheckpointPath => Path.Combine(folder, $"{depot}_checkpoint.bin");

        private void LoadExistingFiles()
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
                            chunksPerFile.Clear();
                            files.Clear();
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Failed to load checkpoint: {ex.Message}. Rebuilding from CSM files...");
                    chunkIndex.Clear();
                    chunksPerFile.Clear();
                    files.Clear();
                }
            }

            // Load existing CSD/CSM pairs (fallback or initial load)
            var csmFiles = Directory.EnumerateFiles(folder, $"{depot}_*.csm")
                .OrderBy(f =>
                {
                    var parts = Path.GetFileNameWithoutExtension(f).Split('_');
                    return int.Parse(parts[^1]);
                })
                .ToList();

            foreach (var csmPath in csmFiles)
            {
                var baseName = Path.GetFileNameWithoutExtension(csmPath);
                var csdPath = Path.Combine(folder, baseName + ".csd");

                if (File.Exists(csdPath))
                {
                    files.Add((csdPath, csmPath));
                    chunksPerFile.Add(new List<ChunkMetadata>());
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
                SaveCheckpointUnsafe();
                Console.WriteLine("Initial checkpoint saved");
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

            var fileChunks = chunksPerFile[chunkstoreIndex - 1];

            // Read chunk metadata
            for (int i = 0; i < chunkCount; i++)
            {
                var sha = reader.ReadBytes(20);
                var offset = reader.ReadInt64();
                reader.ReadUInt32(); // reserved
                var length = reader.ReadInt32();

                var shaHex = Convert.ToHexString(sha).ToLowerInvariant();
                var metadata = new ChunkMetadata
                {
                    Sha = shaHex,
                    ChunkstoreIndex = chunkstoreIndex,
                    Offset = offset,
                    Length = length
                };

                chunkIndex[shaHex] = metadata;
                fileChunks.Add(metadata);
            }
        }

        /// <summary>
        /// Checks if a chunk with the given SHA1 exists in the chunkstore.
        /// </summary>
        public bool ChunkExists(byte[] sha)
        {
            var shaHex = Convert.ToHexString(sha).ToLowerInvariant();
            return chunkIndex.ContainsKey(shaHex);
        }

        /// <summary>
        /// Retrieves a chunk by its SHA1 hash.
        /// </summary>
        /// <param name="sha">SHA1 hash of the chunk</param>
        /// <param name="process">Whether to decrypt and decompress the chunk</param>
        /// <returns>The chunk data</returns>
        public byte[] GetChunk(byte[] sha, bool process = false)
        {
            var shaHex = Convert.ToHexString(sha).ToLowerInvariant();

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
            if (maxParallelism <= 0)
            {
                maxParallelism = Math.Max(1, Environment.ProcessorCount - 1);
            }

            var results = new ConcurrentDictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };

            await Parallel.ForEachAsync(shaList, options, async (sha, ct) =>
            {
                await Task.Run(() =>
                {
                    var shaHex = Convert.ToHexString(sha).ToLowerInvariant();
                    try
                    {
                        var data = GetChunk(sha, process);
                        results[shaHex] = data;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error retrieving chunk {shaHex}: {ex.Message}");
                    }
                }, ct);
            });

            return results.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        private byte[] ProcessChunk(string shaHex, byte[] content)
        {
            // Decrypt if necessary
            if (isEncrypted == true && depotKey != null)
            {
                content = DecryptChunk(content, depotKey);
            }

            // Decompress based on format
            byte[] decompressed;
            if (content.Length >= 3 && content[0] == 'V' && content[1] == 'Z' && content[2] == 'a')
            {
                // LZMA format
                decompressed = DecompressLZMA(content);
            }
            else if (content.Length >= 4 && content[0] == 'P' && content[1] == 'K' && content[2] == 0x03 && content[3] == 0x04)
            {
                // ZIP format
                decompressed = DecompressZip(content);
            }
            else if (content.Length >= 4 && content[0] == 'V' && content[1] == 'S' && content[2] == 'Z' && content[3] == 'a')
            {
                // Zstandard format
                decompressed = DecompressZstd(content);
            }
            else
            {
                throw new InvalidDataException($"Unknown compression format for chunk {shaHex}");
            }

            // Verify SHA1
            using var sha1 = SHA1.Create();
            var calculatedSha = Convert.ToHexString(sha1.ComputeHash(decompressed)).ToLowerInvariant();

            if (calculatedSha != shaHex)
            {
                throw new InvalidDataException(
                    $"SHA1 mismatch for chunk {shaHex}: expected {shaHex}, got {calculatedSha}");
            }

            return decompressed;
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
            var shaHex = Convert.ToHexString(sha).ToLowerInvariant();

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
                    }),
                ChunksPerFile = chunksPerFile.Select(list =>
                    new ChunkstoreCheckpoint.ChunkList
                    {
                        Chunks = list.Select(c => new ChunkstoreCheckpoint.ChunkMetadataProto
                        {
                            Sha = c.Sha,
                            ChunkstoreIndex = c.ChunkstoreIndex,
                            Offset = c.Offset,
                            Length = c.Length
                        }).ToList()
                    }).ToList()
            };

            var tempPath = CheckpointPath + ".tmp";

            // Write to temp file first (atomic operation)
            using (var fs = File.Create(tempPath))
            using (var ds = new DeflateStream(fs, CompressionMode.Compress))
            {
                Serializer.Serialize(ds, checkpoint);
            }

            // Atomic replace (survives crashes during write)
            File.Move(tempPath, CheckpointPath, overwrite: true);
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
                ChunkstoreCheckpoint checkpoint;
                using (var fs = File.OpenRead(CheckpointPath))
                using (var ds = new DeflateStream(fs, CompressionMode.Decompress))
                {
                    checkpoint = Serializer.Deserialize<ChunkstoreCheckpoint>(ds);
                }

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

                chunksPerFile.Clear();
                foreach (var chunkList in checkpoint.ChunksPerFile)
                {
                    chunksPerFile.Add(chunkList.Chunks.Select(proto => new ChunkMetadata
                    {
                        Sha = proto.Sha,
                        ChunkstoreIndex = proto.ChunkstoreIndex,
                        Offset = proto.Offset,
                        Length = proto.Length
                    }).ToList());
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
            var chunks = chunksPerFile[index - 1];

            using var stream = File.Open(csmPath, FileMode.Open, FileAccess.Write);
            using var writer = new BinaryWriter(stream);

            // Seek past header
            writer.BaseStream.Seek(12, SeekOrigin.Begin);

            // Write depot ID and chunk count
            writer.Write(depot ?? 0);
            writer.Write(chunks.Count);

            // Write chunk metadata (sorted by offset for consistency)
            foreach (var chunk in chunks.OrderBy(c => c.Offset))
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
                    var sha = fileName;

                    // Remove _decrypted suffix if present
                    if (!isEncrypted.GetValueOrDefault() && sha.EndsWith("_decrypted"))
                    {
                        sha = sha[..^"_decrypted".Length];
                    }

                    // Validate SHA1 format
                    if (sha.Length != 40 || !sha.All(c => char.IsAsciiHexDigit(c)))
                    {
                        throw new InvalidOperationException($"Invalid SHA1 filename: {fileName}");
                    }

                    return new { FilePath = filePath, Sha = sha.ToLowerInvariant(), FileName = fileName };
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
            if (maxParallelism <= 0)
            {
                maxParallelism = Math.Max(1, Environment.ProcessorCount - 1);
            }

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
                    var sha = fileName;

                    // Remove _decrypted suffix if present
                    if (!isEncrypted.GetValueOrDefault() && sha.EndsWith("_decrypted"))
                    {
                        sha = sha[..^"_decrypted".Length];
                    }

                    // Validate SHA1 format
                    if (sha.Length != 40 || !sha.All(c => char.IsAsciiHexDigit(c)))
                    {
                        throw new InvalidOperationException($"Invalid SHA1 filename: {fileName}");
                    }

                    return new ChunkFile
                    {
                        FilePath = filePath,
                        Sha = sha.ToLowerInvariant(),
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

                await Parallel.ForEachAsync(batch.Select((f, idx) => (f, idx)), options, async (item, ct) =>
                {
                    await Task.Run(() =>
                    {
                        var (file, index) = item;

                        // Skip if already exists (fast check without loading file)
                        if (ChunkExists(Convert.FromHexString(file.Sha)))
                        {
                            chunkData[index] = (file.Sha, null, file.FileName);
                            return;
                        }

                        var content = File.ReadAllBytes(file.FilePath);
                        chunkData[index] = (file.Sha, content, file.FileName);
                    }, ct);
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
                            Console.WriteLine($"Packed {packedCount:N0}/{totalChunks:N0} chunks ({(packedCount * 100.0 / totalChunks):F1}%)");
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
            var sha = fileName;

            // Remove _decrypted suffix if present
            if (!isEncrypted.GetValueOrDefault() && sha.EndsWith("_decrypted"))
            {
                sha = sha[..^"_decrypted".Length];
            }

            // Validate SHA1 format
            if (sha.Length != 40 || !sha.All(c => char.IsAsciiHexDigit(c)))
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

            if (maxParallelism <= 0)
            {
                maxParallelism = Math.Max(1, Environment.ProcessorCount - 1);
            }

            var allChunks = chunkIndex.Values.ToList();
            Console.WriteLine($"Unpacking {allChunks.Count} chunks...");

            var options = new ParallelOptions { MaxDegreeOfParallelism = maxParallelism };
            var unpackedCount = 0;
            var skippedCount = 0;
            var lockObj = new object();

            await Parallel.ForEachAsync(allChunks, options, async (chunk, ct) =>
            {
                await Task.Run(() =>
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
                                Console.WriteLine($"Progress: {unpackedCount + skippedCount}/{allChunks.Count} ({((unpackedCount + skippedCount) * 100.0 / allChunks.Count):F1}%)");
                            }
                        }
                        return;
                    }

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
                                Console.WriteLine($"Unpacked {unpackedCount}/{allChunks.Count} chunks ({(unpackedCount * 100.0 / allChunks.Count):F1}%)");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error unpacking {fileName}: {ex.Message}");
                    }
                }, ct);
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

            if (maxParallelism <= 0)
            {
                maxParallelism = Math.Max(1, Environment.ProcessorCount - 1);
            }

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

            await Parallel.ForEachAsync(chunksToUnpack, options, async (chunk, ct) =>
            {
                await Task.Run(() =>
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
                        return;
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
                }, ct);
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
            chunksPerFile.Add(new List<ChunkMetadata>());
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
