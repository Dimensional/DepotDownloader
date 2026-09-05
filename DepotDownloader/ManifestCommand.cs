// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    /// <summary>
    /// Manifest command handler for offline manifest operations
    /// </summary>
    public static class ManifestCommand
    {
        // JSON model matching the debug format from BuildManifestDebugModel (for reading only)
        private class DebugManifestJson
        {
            public uint depot_id { get; set; }
            public ulong gid { get; set; }
            public DateTime creation_time { get; set; }
            public bool filenames_encrypted { get; set; }
            public int version { get; set; }
            public ulong total_uncompressed_size { get; set; }
            public ulong total_compressed_size { get; set; }
            public List<FileMapping> mappings { get; set; }

            public class FileMapping
            {
                public string encryptedName { get; set; }
                public string decryptedName { get; set; }
                public ulong size { get; set; }
                public int flags { get; set; }
                public string sha_content { get; set; }
                public string sha_filename { get; set; }
                public List<ChunkInfo> chunks { get; set; }
            }

            public class ChunkInfo
            {
                public string sha { get; set; }
                public uint crc { get; set; }
                public ulong offset { get; set; }
                public uint cb_compressed { get; set; }
                public uint cb_original { get; set; }
            }
        }

        // Unified manifest representation for comparison
        private class ManifestData
        {
            public uint DepotId { get; set; }
            public ulong ManifestId { get; set; }
            public DateTime CreationTime { get; set; }
            public bool FilenamesEncrypted { get; set; }
            public int Version { get; set; }
            public ulong TotalUncompressedSize { get; set; }
            public ulong TotalCompressedSize { get; set; }
            public List<FileEntry> Files { get; set; }

            public class FileEntry
            {
                public string EncryptedName { get; set; }
                public string FileName { get; set; }
                public ulong Size { get; set; }
                public string Hash { get; set; }
                public string FilenameHash { get; set; }
                public int Flags { get; set; }
                public List<ChunkEntry> Chunks { get; set; }
            }

            public class ChunkEntry
            {
                public string ChunkId { get; set; }
                public uint Checksum { get; set; }
                public ulong Offset { get; set; }
                public uint CompressedLength { get; set; }
                public uint UncompressedLength { get; set; }
            }
        }

        /// <summary>
        /// Load a manifest from any supported format and convert to unified representation
        /// </summary>
        private static async Task<ManifestData> LoadManifestFromAnyFormat(string filePath, byte[] depotKey = null)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            // JSON format
            if (extension == ".json")
            {
                var jsonText = await File.ReadAllTextAsync(filePath);
                var debugJson = JsonSerializer.Deserialize<DebugManifestJson>(jsonText);

                return new ManifestData
                {
                    DepotId = debugJson.depot_id,
                    ManifestId = debugJson.gid,
                    CreationTime = debugJson.creation_time,
                    FilenamesEncrypted = debugJson.filenames_encrypted,
                    Version = debugJson.version,
                    TotalUncompressedSize = debugJson.total_uncompressed_size,
                    TotalCompressedSize = debugJson.total_compressed_size,
                    Files = debugJson.mappings.Select(m => new ManifestData.FileEntry
                    {
                        EncryptedName = m.encryptedName,
                        FileName = m.decryptedName,
                        Size = m.size,
                        Hash = m.sha_content,
                        FilenameHash = m.sha_filename,
                        Flags = m.flags,
                        Chunks = m.chunks?.Select(c => new ManifestData.ChunkEntry
                        {
                            ChunkId = c.sha,
                            Checksum = c.crc,
                            Offset = c.offset,
                            CompressedLength = c.cb_compressed,
                            UncompressedLength = c.cb_original
                        }).ToList() ?? new List<ManifestData.ChunkEntry>()
                    }).ToList()
                };
            }

            // Compressed manifest format (.manif4, .manif5)
            if (extension == ".manif4" || extension == ".manif5")
            {
                if (depotKey == null || depotKey.Length == 0)
                {
                    throw new Exception("Depot key is required to decrypt .manif4/.manif5 files. Use -depotkey or ensure depot key file exists.");
                }

                var zipBytes = await File.ReadAllBytesAsync(filePath);
                var result = ParseManifestZipBytes(zipBytes, depotKey);

                return ConvertDepotManifestToData(result.Manifest, result.EncryptedNames, result.Version);
            }

            // Decrypted binary manifest format (.manifest)
            if (extension == ".manifest")
            {
                var manifest = DepotManifest.LoadFromFile(filePath);
                return ConvertDepotManifestToData(manifest);
            }

            throw new Exception($"Unsupported manifest format: {extension}. Supported: .json, .manifest, .manif4, .manif5");
        }

        /// <summary>
        /// Load a manifest from disk as a real <see cref="DepotManifest"/> (chunk-level detail intact),
        /// rather than the diff-oriented <see cref="ManifestData"/> DTO <see cref="LoadManifestFromAnyFormat"/>
        /// builds. Used by commands that need to walk actual chunks (e.g. reconstruct), not just compare
        /// file listings. Supports ".manifest" (decrypted binary) and ".manif4"/".manif5" (raw CDN zip,
        /// requires the depot key to decrypt filenames) - not ".json", which is a lossy debug view.
        /// </summary>
        internal static async Task<DepotManifest> LoadDepotManifestFromAnyFormat(string filePath, byte[] depotKey = null)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();

            if (extension == ".manifest")
            {
                return DepotManifest.LoadFromFile(filePath);
            }

            if (extension == ".manif4" || extension == ".manif5")
            {
                if (depotKey == null || depotKey.Length == 0)
                {
                    throw new Exception("Depot key is required to decrypt .manif4/.manif5 files. Use -depotkey or ensure depot key file exists.");
                }

                var zipBytes = await File.ReadAllBytesAsync(filePath);
                return ParseManifestZipBytes(zipBytes, depotKey).Manifest;
            }

            throw new Exception($"Unsupported manifest format for reconstruct: {extension}. Supported: .manifest, .manif4, .manif5");
        }

        /// <summary>
        /// Parse result from manifest zip bytes
        /// </summary>
        internal class ParsedManifestResult
        {
            public DepotManifest Manifest { get; set; }
            public List<string> EncryptedNames { get; set; }
            public int Version { get; set; }
        }

        /// <summary>
        /// Parse compressed manifest zip bytes (same as ContentDownloader logic)
        /// Captures encrypted filenames before decryption
        /// </summary>
        internal static ParsedManifestResult ParseManifestZipBytes(byte[] zipBytes, byte[] depotKey)
        {
            const uint V4_MAGIC = 0x16349781;

            byte[] payloadBytes;

            using (var msZip = new MemoryStream(zipBytes, writable: false))
            using (var zip = new ZipArchive(msZip, ZipArchiveMode.Read, leaveOpen: false))
            {
                if (zip.Entries.Count == 0)
                    throw new InvalidDataException("Manifest zip did not contain any entries");

                using var entryStream = zip.Entries[0].Open();
                using var msPayload = new MemoryStream();
                entryStream.CopyTo(msPayload);
                payloadBytes = msPayload.ToArray();
            }

            // Detect version from magic header
            var detectedVersion = 5;
            if (payloadBytes.Length >= 4)
            {
                var header = BitConverter.ToUInt32(payloadBytes, 0);
                detectedVersion = header == V4_MAGIC ? 4 : 5;
            }

            DepotManifest parsed;
            using (var ms = new MemoryStream(payloadBytes, writable: false))
            {
                parsed = DepotManifest.Deserialize(ms);
            }

            // Capture encrypted names BEFORE decryption
            var encryptedNames = parsed.Files.Select(f => f.FileName).ToList();

            if (depotKey != null && depotKey.Length > 0)
            {
                try
                {
                    parsed.DecryptFilenames(depotKey);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to decrypt filenames: {ex.Message}");
                }
            }

            return new ParsedManifestResult
            {
                Manifest = parsed,
                EncryptedNames = encryptedNames,
                Version = detectedVersion
            };
        }

        /// <summary>
        /// Convert DepotManifest to our unified format with encrypted names and filename hashes
        /// </summary>
        private static ManifestData ConvertDepotManifestToData(DepotManifest manifest, List<string> encryptedNames = null, int version = 5)
        {
            return new ManifestData
            {
                DepotId = manifest.DepotID,
                ManifestId = manifest.ManifestGID,
                CreationTime = manifest.CreationTime,
                FilenamesEncrypted = manifest.FilenamesEncrypted,
                Version = version,
                TotalUncompressedSize = manifest.TotalUncompressedSize,
                TotalCompressedSize = manifest.TotalCompressedSize,
                Files = manifest.Files.Select((f, i) => new ManifestData.FileEntry
                {
                    EncryptedName = (encryptedNames != null && i < encryptedNames.Count) ? encryptedNames[i] : null,
                    FileName = f.FileName,
                    Size = f.TotalSize,
                    Hash = f.FileHash != null ? Util.ToHex(f.FileHash) : null,
                    FilenameHash = ComputeFilenameHash(f.FileName),
                    Flags = (int)f.Flags,
                    Chunks = f.Chunks.Select(c => new ManifestData.ChunkEntry
                    {
                        ChunkId = Util.ToHex(c.ChunkID),
                        Checksum = c.Checksum,
                        Offset = c.Offset,
                        CompressedLength = c.CompressedLength,
                        UncompressedLength = c.UncompressedLength
                    }).ToList()
                }).ToList()
            };
        }

        /// <summary>
        /// Compute SHA1 hash of normalized filename (same as BuildManifestDebugModel)
        /// </summary>
        private static string ComputeFilenameHash(string filename)
        {
            if (string.IsNullOrEmpty(filename))
                return null;

            // Normalize: replace / with \ and convert to lowercase
            var normalized = filename.Replace('/', '\\').ToLowerInvariant();
            var bytes = System.Text.Encoding.UTF8.GetBytes(normalized);
            var hash = SHA1.HashData(bytes);
            return Util.ToHex(hash);
        }

        /// <summary>
        /// Resolve a depot decryption key for a .manif4/.manif5 file, in priority order:
        /// an explicit hex key, an explicit key file, or an auto-detected key file based on
        /// a "depot/&lt;id&gt;/..." segment found in one of the given manifest file paths.
        /// Returns the resolved key together with the depot ID it was found/used under.
        /// </summary>
        internal static async Task<(byte[] Key, uint? DepotId)> ResolveDepotKeyAsync(string depotKeyHex, string depotKeyFile, uint? depotId, params string[] manifestFilePaths)
        {
            if (!string.IsNullOrEmpty(depotKeyHex))
            {
                try
                {
                    var key = Convert.FromHexString(depotKeyHex);
                    Console.WriteLine("Using provided depot key (hex)");
                    return (key, depotId);
                }
                catch (FormatException ex)
                {
                    throw new Exception($"Invalid depot key hex: {ex.Message}");
                }
            }

            if (!string.IsNullOrEmpty(depotKeyFile))
            {
                if (!File.Exists(depotKeyFile))
                {
                    throw new Exception($"Depot key file not found: {depotKeyFile}");
                }

                var key = await File.ReadAllBytesAsync(depotKeyFile);
                Console.WriteLine($"Loaded depot key from: {depotKeyFile}");
                return (key, depotId);
            }

            // Auto-detect depot ID from a manifest path (e.g., depot/848452/manifest/...)
            if (!depotId.HasValue)
            {
                foreach (var path in manifestFilePaths)
                {
                    var pathParts = Path.GetFullPath(path).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                    for (var i = 0; i < pathParts.Length - 1; i++)
                    {
                        if (pathParts[i].Equals("depot", StringComparison.OrdinalIgnoreCase)
                            && uint.TryParse(pathParts[i + 1], out var detectedDepotId))
                        {
                            depotId = detectedDepotId;
                            Console.WriteLine($"Auto-detected depot ID from path: {depotId}");
                            break;
                        }
                    }

                    if (depotId.HasValue) break;
                }
            }

            if (!depotId.HasValue)
            {
                throw new Exception(".manif4/.manif5 files require -depot <id>, -depotkey <hex>, or -depotkey-file <path> (could not determine depot ID from file path)");
            }

            var depotKeyPath = Path.Combine("depot", depotId.Value.ToString(), $"{depotId.Value}.depotkey");
            if (!File.Exists(depotKeyPath))
            {
                throw new Exception($"Depot key file not found: {depotKeyPath}. Provide depot key using -depotkey <hex>, -depotkey-file <path>, or ensure depot key file exists");
            }

            var loadedKey = await File.ReadAllBytesAsync(depotKeyPath);
            Console.WriteLine($"Loaded depot key from: {depotKeyPath}");
            return (loadedKey, depotId);
        }

        /// <summary>
        /// Run manifest command with sub-command syntax
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
                    case "extract":
                        return await ExtractCommand(args[1..]);

                    case "diff":
                    case "compare":
                        return await DiffCommand(args[1..]);

                    default:
                        Console.WriteLine($"Unknown manifest operation: {operation}");
                        Console.WriteLine("Available operations: extract, diff");
                        Console.WriteLine("Use 'depotdownloader help manifest' for detailed usage.");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static async Task<int> ExtractCommand(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: depotdownloader manifest extract <manifest-file> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("Extracts encrypted/binary manifests to readable JSON format.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -manifest <file>         Manifest file path (alternative to positional)");
                Console.WriteLine("  -depot <id>              Depot ID (for .manif4/.manif5 key lookup)");
                Console.WriteLine("  -depotkey <hex>          Depot decryption key in hex (for .manif4/.manif5)");
                Console.WriteLine("  -depotkey-file <path>    Path to depot key file (for .manif4/.manif5)");
                Console.WriteLine("  -output <file>           Output JSON file path (default: <manifest-file>.json)");
                Console.WriteLine();
                Console.WriteLine("SUPPORTED INPUT FORMATS:");
                Console.WriteLine("  .manifest       - Decrypted binary manifest");
                Console.WriteLine("  .manif4/.manif5 - Compressed encrypted manifest (requires depot key)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader manifest extract 848452_123456.manifest -output debug.json");
                Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depot 848452");
                Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depotkey ABCD1234...");
                Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depotkey-file my-keys/848452.key");
                return 1;
            }

            var parser = new ArgParser(args);

            var manifestFile = parser.Get<string>(null, "-manifest") ?? parser.Positional(0);
            var outputFile = parser.Get<string>(null, "-output");
            var depotId = parser.GetNullable<uint>("-depot", "-d");
            var depotKeyHex = parser.Get<string>(null, "-depotkey");
            var depotKeyFile = parser.Get<string>(null, "-depotkey-file");

            parser.WarnUnconsumed();

            if (string.IsNullOrEmpty(manifestFile))
            {
                Console.WriteLine("Error: No manifest file specified");
                return 1;
            }

            if (!File.Exists(manifestFile))
            {
                Console.WriteLine($"Error: Manifest file not found: {manifestFile}");
                return 1;
            }

            // Load depot key if needed for .manif4/.manif5 files
            byte[] depotKey = null;
            var extension = Path.GetExtension(manifestFile).ToLowerInvariant();
            if (extension == ".manif4" || extension == ".manif5")
            {
                (depotKey, depotId) = await ResolveDepotKeyAsync(depotKeyHex, depotKeyFile, depotId, manifestFile);
            }

            // Default output file
            if (string.IsNullOrEmpty(outputFile))
            {
                outputFile = Path.ChangeExtension(manifestFile, ".extracted.json");
            }

            Console.WriteLine($"Loading manifest from: {manifestFile}");

            // Load the manifest
            ManifestData manifest;
            try
            {
                manifest = await LoadManifestFromAnyFormat(manifestFile, depotKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading manifest: {ex.Message}");
                return 1;
            }

            Console.WriteLine($"Manifest ID: {manifest.ManifestId}");
            Console.WriteLine($"Depot ID: {manifest.DepotId}");
            Console.WriteLine($"Creation Time: {manifest.CreationTime}");
            Console.WriteLine($"Total Files: {manifest.Files.Count}");

            // Build JSON structure matching BuildManifestDebugModel format exactly
            var manifestData = new
            {
                depot_id = manifest.DepotId,
                gid = manifest.ManifestId,
                creation_time = manifest.CreationTime,
                filenames_encrypted = manifest.FilenamesEncrypted,
                version = manifest.Version,
                total_uncompressed_size = manifest.TotalUncompressedSize,
                total_compressed_size = manifest.TotalCompressedSize,
                mappings = manifest.Files.Select(f => new
                {
                    encryptedName = f.EncryptedName,
                    decryptedName = f.FileName,
                    size = f.Size,
                    flags = f.Flags,
                    sha_content = f.Hash,
                    sha_filename = f.FilenameHash,
                    chunks = f.Chunks.Select(c => new
                    {
                        sha = c.ChunkId,
                        crc = c.Checksum,
                        offset = c.Offset,
                        cb_original = c.UncompressedLength,
                        cb_compressed = c.CompressedLength
                    }).ToList()
                }).ToList()
            };

            // Serialize to JSON (always prettified)
            // Note: Do NOT use JsonNamingPolicy.CamelCase - we already have snake_case property names
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            await File.WriteAllTextAsync(outputFile, JsonSerializer.Serialize(manifestData, options));

            Console.WriteLine($"Manifest extracted to: {outputFile}");
            Console.WriteLine("Done!");

            return 0;
        }

        private static async Task<int> DiffCommand(string[] args)
        {
            if (args.Length < 2 && !args.Any(a => a.Equals("-old", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("Usage: depotdownloader manifest diff <old-manifest> <new-manifest> [OPTIONS...]");
                Console.WriteLine("   or: depotdownloader manifest diff -old <file> -new <file> [OPTIONS...]");
                Console.WriteLine();
                Console.WriteLine("Compares two manifests and displays differences to console.");
                Console.WriteLine();
                Console.WriteLine("OPTIONS:");
                Console.WriteLine("  -old <file>              Old/original manifest file");
                Console.WriteLine("  -new <file>              New/updated manifest file");
                Console.WriteLine("  -depot <id>              Depot ID (for .manif4/.manif5 key lookup)");
                Console.WriteLine("  -depotkey <hex>          Depot decryption key in hex (for .manif4/.manif5)");
                Console.WriteLine("  -depotkey-file <path>    Path to depot key file (for .manif4/.manif5)");
                Console.WriteLine("  -verbose, -v             Show detailed list of all file changes");
                Console.WriteLine("  -output <file>           Save detailed diff as JSON file (optional)");
                Console.WriteLine();
                Console.WriteLine("SUPPORTED INPUT FORMATS:");
                Console.WriteLine("  .json           - Extracted debug JSON");
                Console.WriteLine("  .manifest       - Decrypted binary manifest");
                Console.WriteLine("  .manif4/.manif5 - Compressed encrypted manifest (requires depot key)");
                Console.WriteLine();
                Console.WriteLine("EXAMPLES:");
                Console.WriteLine("  depotdownloader manifest diff old.json new.json");
                Console.WriteLine("  depotdownloader manifest diff old.json new.json -verbose");
                Console.WriteLine("  depotdownloader manifest diff v1.manif5 v2.manif5 -depot 848452");
                Console.WriteLine("  depotdownloader manifest diff -old v1.manif5 -new v2.manif5 -depotkey ABCD1234... -output changes.json");
                Console.WriteLine("  depotdownloader manifest diff v1.manif5 v2.manif5 -depotkey-file my-keys/848452.key");
                return 1;
            }

            var parser = new ArgParser(args);

            var oldManifestFile = parser.Get<string>(null, "-old") ?? parser.Positional(0);
            var newManifestFile = parser.Get<string>(null, "-new") ?? parser.Positional(1);
            var outputFile = parser.Get<string>(null, "-output");
            var depotId = parser.GetNullable<uint>("-depot", "-d");
            var depotKeyHex = parser.Get<string>(null, "-depotkey");
            var depotKeyFile = parser.Get<string>(null, "-depotkey-file");
            var verbose = parser.HasFlag("-verbose", "-v");

            parser.WarnUnconsumed();

            if (string.IsNullOrEmpty(oldManifestFile) || string.IsNullOrEmpty(newManifestFile))
            {
                Console.WriteLine("Error: Both old and new manifest files must be specified");
                return 1;
            }

            if (!File.Exists(oldManifestFile))
            {
                Console.WriteLine($"Error: Old manifest file not found: {oldManifestFile}");
                return 1;
            }

            if (!File.Exists(newManifestFile))
            {
                Console.WriteLine($"Error: New manifest file not found: {newManifestFile}");
                return 1;
            }

            // Load depot key if needed for .manif4/.manif5 files
            byte[] depotKey = null;
            var oldExt = Path.GetExtension(oldManifestFile).ToLowerInvariant();
            var newExt = Path.GetExtension(newManifestFile).ToLowerInvariant();
            var needsKey = oldExt == ".manif4" || oldExt == ".manif5" || newExt == ".manif4" || newExt == ".manif5";

            if (needsKey)
            {
                (depotKey, depotId) = await ResolveDepotKeyAsync(depotKeyHex, depotKeyFile, depotId, oldManifestFile, newManifestFile);
            }

            Console.WriteLine($"Loading old manifest from: {oldManifestFile}");
            ManifestData oldManifest;
            try
            {
                oldManifest = await LoadManifestFromAnyFormat(oldManifestFile, depotKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading old manifest: {ex.Message}");
                return 1;
            }

            Console.WriteLine($"Loading new manifest from: {newManifestFile}");
            ManifestData newManifest;
            try
            {
                newManifest = await LoadManifestFromAnyFormat(newManifestFile, depotKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading new manifest: {ex.Message}");
                return 1;
            }

            Console.WriteLine();
            Console.WriteLine($"Old Manifest ID: {oldManifest.ManifestId} ({oldManifest.Files.Count} files)");
            Console.WriteLine($"New Manifest ID: {newManifest.ManifestId} ({newManifest.Files.Count} files)");
            Console.WriteLine("Calculating differences...");

            // Build file lookup dictionaries
            var oldFiles = oldManifest.Files.ToDictionary(f => f.FileName, f => f);
            var newFiles = newManifest.Files.ToDictionary(f => f.FileName, f => f);

            // Find added, removed, and modified files
            var addedFiles = newFiles.Keys.Except(oldFiles.Keys).ToList();
            var removedFiles = oldFiles.Keys.Except(newFiles.Keys).ToList();
            var commonFiles = oldFiles.Keys.Intersect(newFiles.Keys).ToList();

            var modifiedFiles = new List<string>();
            var unchangedFiles = new List<string>();

            foreach (var fileName in commonFiles)
            {
                var oldFile = oldFiles[fileName];
                var newFile = newFiles[fileName];

                // Compare file hash or size to detect changes
                bool isModified = oldFile.Size != newFile.Size ||
                                  oldFile.Hash != newFile.Hash;

                if (isModified)
                    modifiedFiles.Add(fileName);
                else
                    unchangedFiles.Add(fileName);
            }

            Console.WriteLine();
            Console.WriteLine($"Added:     {addedFiles.Count} files");
            Console.WriteLine($"Removed:   {removedFiles.Count} files");
            Console.WriteLine($"Modified:  {modifiedFiles.Count} files");
            Console.WriteLine($"Unchanged: {unchangedFiles.Count} files");

            // Show verbose output if requested
            if (verbose)
            {
                if (addedFiles.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine($"ADDED FILES ({addedFiles.Count}):");
                    foreach (var fileName in addedFiles.OrderBy(f => f))
                    {
                        var file = newFiles[fileName];
                        Console.WriteLine($"  + {fileName} ({file.Size:N0} bytes)");
                    }
                }

                if (removedFiles.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine($"REMOVED FILES ({removedFiles.Count}):");
                    foreach (var fileName in removedFiles.OrderBy(f => f))
                    {
                        var file = oldFiles[fileName];
                        Console.WriteLine($"  - {fileName} ({file.Size:N0} bytes)");
                    }
                }

                if (modifiedFiles.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine($"MODIFIED FILES ({modifiedFiles.Count}):");
                    foreach (var fileName in modifiedFiles.OrderBy(f => f))
                    {
                        var oldFile = oldFiles[fileName];
                        var newFile = newFiles[fileName];
                        var sizeDelta = (long)newFile.Size - (long)oldFile.Size;
                        var sizeChange = sizeDelta >= 0 ? $"+{sizeDelta:N0}" : $"{sizeDelta:N0}";
                        Console.WriteLine($"  * {fileName} ({oldFile.Size:N0} -> {newFile.Size:N0} bytes, {sizeChange})");
                    }
                }
            }

            // Save to file only if -output was specified
            if (!string.IsNullOrEmpty(outputFile))
            {
                // Build diff structure
                var diffData = new
                {
                    DepotId = depotId ?? oldManifest.DepotId,
                    OldManifest = new
                    {
                        ManifestId = oldManifest.ManifestId,
                        CreationTime = oldManifest.CreationTime,
                        TotalFiles = oldManifest.Files.Count,
                        TotalUncompressedSize = oldManifest.TotalUncompressedSize,
                        TotalCompressedSize = oldManifest.TotalCompressedSize
                    },
                    NewManifest = new
                    {
                        ManifestId = newManifest.ManifestId,
                        CreationTime = newManifest.CreationTime,
                        TotalFiles = newManifest.Files.Count,
                        TotalUncompressedSize = newManifest.TotalUncompressedSize,
                        TotalCompressedSize = newManifest.TotalCompressedSize
                    },
                    Summary = new
                    {
                        AddedCount = addedFiles.Count,
                        RemovedCount = removedFiles.Count,
                        ModifiedCount = modifiedFiles.Count,
                        UnchangedCount = unchangedFiles.Count,
                        TotalSizeChange = (long)newManifest.TotalUncompressedSize - (long)oldManifest.TotalUncompressedSize
                    },
                    AddedFiles = addedFiles.Select(fileName =>
                    {
                        var file = newFiles[fileName];
                        return new
                        {
                            FileName = fileName,
                            Size = file.Size,
                            Hash = file.Hash
                        };
                    }).ToList(),
                    RemovedFiles = removedFiles.Select(fileName =>
                    {
                        var file = oldFiles[fileName];
                        return new
                        {
                            FileName = fileName,
                            Size = file.Size,
                            Hash = file.Hash
                        };
                    }).ToList(),
                    ModifiedFiles = modifiedFiles.Select(fileName =>
                    {
                        var oldFile = oldFiles[fileName];
                        var newFile = newFiles[fileName];
                        return new
                        {
                            FileName = fileName,
                            OldSize = oldFile.Size,
                            NewSize = newFile.Size,
                            SizeDelta = (long)newFile.Size - (long)oldFile.Size,
                            OldHash = oldFile.Hash,
                            NewHash = newFile.Hash
                        };
                    }).ToList()
                };

                // Serialize to JSON (always prettified)
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };

                await File.WriteAllTextAsync(outputFile, JsonSerializer.Serialize(diffData, options));
                Console.WriteLine();
                Console.WriteLine($"Detailed diff saved to: {outputFile}");
            }

            Console.WriteLine();
            Console.WriteLine("Done!");

            return 0;
        }

        public static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Manifest Command - Offline manifest analysis and comparison");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader manifest <operation> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("OPERATIONS:");
            Console.WriteLine("  extract              Extract encrypted/binary manifests to readable JSON");
            Console.WriteLine("  diff, compare        Compare two manifests and show differences (console output)");
            Console.WriteLine();
            Console.WriteLine("SUPPORTED FORMATS:");
            Console.WriteLine("  .json               Extracted debug JSON (for diff only)");
            Console.WriteLine("  .manifest           Decrypted binary manifest");
            Console.WriteLine("  .manif4/.manif5     Compressed encrypted manifest (requires depot key)");
            Console.WriteLine();
            Console.WriteLine("EXTRACT USAGE:");
            Console.WriteLine("  depotdownloader manifest extract <manifest-file> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("  Converts encrypted/binary manifests to readable JSON format.");
            Console.WriteLine();
            Console.WriteLine("  OPTIONS:");
            Console.WriteLine("    -depot <id>          Depot ID (for .manif4/.manif5 key lookup)");
            Console.WriteLine("    -depotkey <hex>      Depot key in hex (for .manif4/.manif5)");
            Console.WriteLine("    -depotkey-file <path> Path to custom depot key file");
            Console.WriteLine("    -output <file>       Output JSON file (default: <manifest>.json)");
            Console.WriteLine();
            Console.WriteLine("DIFF USAGE:");
            Console.WriteLine("  depotdownloader manifest diff <old-manifest> <new-manifest> [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("  Compares two manifests and displays differences to console.");
            Console.WriteLine();
            Console.WriteLine("  OPTIONS:");
            Console.WriteLine("    -depot <id>          Depot ID (for .manif4/.manif5 key lookup)");
            Console.WriteLine("    -depotkey <hex>      Depot key in hex (for .manif4/.manif5)");
            Console.WriteLine("    -depotkey-file <path> Path to custom depot key file");
            Console.WriteLine("    -verbose, -v         Show detailed list of all file changes");
            Console.WriteLine("    -output <file>       Save detailed diff as JSON file (optional)");
            Console.WriteLine();
            Console.WriteLine("DEPOT KEY:");
            Console.WriteLine("  For .manif4/.manif5 files, depot key is loaded from: depot/<depot-id>/<depot-id>.depotkey");
            Console.WriteLine("  Or provide it directly using -depotkey <hex> or -depotkey-file <path>");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  # Extract encrypted manifest to JSON");
            Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depot 848452");
            Console.WriteLine();
            Console.WriteLine("  # Extract using custom depot key file location");
            Console.WriteLine("  depotdownloader manifest extract 123456.manif5 -depotkey-file my-keys/848452.key");
            Console.WriteLine();
            Console.WriteLine("  # Extract decrypted binary manifest");
            Console.WriteLine("  depotdownloader manifest extract 848452_123456.manifest -output debug.json");
            Console.WriteLine();
            Console.WriteLine("  # Compare two manifests (console output)");
            Console.WriteLine("  depotdownloader manifest diff old.json new.json");
            Console.WriteLine();
            Console.WriteLine("  # Compare with verbose output showing all file changes");
            Console.WriteLine("  depotdownloader manifest diff old.json new.json -verbose");
            Console.WriteLine();
            Console.WriteLine("  # Compare encrypted manifests and save detailed diff to file");
            Console.WriteLine("  depotdownloader manifest diff v1.manif5 v2.manif5 -depot 848452 -output changes.json");
        }
    }
}
