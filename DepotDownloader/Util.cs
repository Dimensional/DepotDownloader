// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;

namespace DepotDownloader
{
    static class Util
    {
        public static string GetSteamOS()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "windows";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return "macos";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "linux";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
            {
                // Return linux as freebsd steam client doesn't exist yet
                return "linux";
            }

            return "unknown";
        }

        public static string GetSteamArch()
        {
            return Environment.Is64BitOperatingSystem ? "64" : "32";
        }

        public static string ReadPassword()
        {
            ConsoleKeyInfo keyInfo;
            var password = new StringBuilder();

            do
            {
                keyInfo = Console.ReadKey(true);

                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        Console.Write("\b \b");
                    }

                    continue;
                }

                /* Printable ASCII characters only */
                var c = keyInfo.KeyChar;
                if (c >= ' ' && c <= '~')
                {
                    password.Append(c);
                    Console.Write('*');
                }
            } while (keyInfo.Key != ConsoleKey.Enter);

            return password.ToString();
        }

        // Validate a file against Steam3 Chunk data
        public static List<DepotManifest.ChunkData> ValidateSteam3FileChecksums(FileStream fs, DepotManifest.ChunkData[] chunkdata)
        {
            var neededChunks = new List<DepotManifest.ChunkData>();

            foreach (var data in chunkdata)
            {
                fs.Seek((long)data.Offset, SeekOrigin.Begin);

                var adler = AdlerHash(fs, (int)data.UncompressedLength);
                if (!adler.SequenceEqual(BitConverter.GetBytes(data.Checksum)))
                {
                    neededChunks.Add(data);
                }
            }

            return neededChunks;
        }

        public static byte[] AdlerHash(Stream stream, int length)
        {
            uint a = 0, b = 0;
            for (var i = 0; i < length; i++)
            {
                var c = (uint)stream.ReadByte();

                a = (a + c) % 65521;
                b = (b + a) % 65521;
            }

            return BitConverter.GetBytes(a | (b << 16));
        }

        public static byte[] FileSHAHash(string filename)
        {
            using (var fs = File.Open(filename, FileMode.Open))
            using (var sha = SHA1.Create())
            {
                var output = sha.ComputeHash(fs);

                return output;
            }
        }

        public static DepotManifest LoadManifestFromFile(string directory, uint depotId, ulong manifestId, bool badHashWarning)
        {
            // Try loading Steam format manifest first.
            var filename = Path.Combine(directory, string.Format("{0}_{1}.manifest", depotId, manifestId));

            if (File.Exists(filename))
            {
                byte[] expectedChecksum;

                try
                {
                    expectedChecksum = File.ReadAllBytes(filename + ".sha");
                }
                catch (IOException)
                {
                    expectedChecksum = null;
                }

                var currentChecksum = FileSHAHash(filename);

                if (expectedChecksum != null && expectedChecksum.SequenceEqual(currentChecksum))
                {
                    return DepotManifest.LoadFromFile(filename);
                }
                else if (badHashWarning)
                {
                    Console.WriteLine("Manifest {0} on disk did not match the expected checksum.", manifestId);
                }
            }

            // Try converting legacy manifest format.
            filename = Path.Combine(directory, string.Format("{0}_{1}.bin", depotId, manifestId));

            if (File.Exists(filename))
            {
                byte[] expectedChecksum;

                try
                {
                    expectedChecksum = File.ReadAllBytes(filename + ".sha");
                }
                catch (IOException)
                {
                    expectedChecksum = null;
                }

                byte[] currentChecksum;
                var oldManifest = ProtoManifest.LoadFromFile(filename, out currentChecksum);

                if (oldManifest != null && (expectedChecksum == null || !expectedChecksum.SequenceEqual(currentChecksum)))
                {
                    oldManifest = null;

                    if (badHashWarning)
                    {
                        Console.WriteLine("Manifest {0} on disk did not match the expected checksum.", manifestId);
                    }
                }

                if (oldManifest != null)
                {
                    return oldManifest.ConvertToSteamManifest(depotId);
                }
            }

            return null;
        }

        public static bool SaveManifestToFile(string directory, DepotManifest manifest)
        {
            try
            {
                var filename = Path.Combine(directory, string.Format("{0}_{1}.manifest", manifest.DepotID, manifest.ManifestGID));
                manifest.SaveToFile(filename);
                File.WriteAllBytes(filename + ".sha", FileSHAHash(filename));
                return true; // If serialization completes without throwing an exception, return true
            }
            catch (Exception)
            {
                return false; // Return false if an error occurs
            }
        }

        public static byte[] DecodeHexString(string hex)
        {
            if (hex == null)
                return null;

            var chars = hex.Length;
            var bytes = new byte[chars / 2];

            for (var i = 0; i < chars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return bytes;
        }

        /// <summary>
        /// Lowercase hex encoding, invariant of culture - the canonical form used everywhere a
        /// SHA1/chunk-id is printed or compared as a string in this codebase. Use this instead of
        /// hand-rolling Convert.ToHexString(...).ToLower()/.ToLowerInvariant() or
        /// BitConverter.ToString(...).Replace("-", "") at each call site.
        /// </summary>
        public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

        /// <summary>
        /// The "threads unspecified" default used consistently across chunkstore/validation/
        /// reconstruction parallelism - leaves one core free rather than oversubscribing. Pass the
        /// user-requested value (0/negative means "unspecified"); returns it unchanged otherwise.
        /// </summary>
        public static int ResolveParallelism(int requested) =>
            requested > 0 ? requested : Math.Max(1, Environment.ProcessorCount - 1);

        private const string FileListRegexPrefix = "regex:";

        /// <summary>
        /// Core of the "-filelist" entry syntax, shared by the file-based and inline parsers
        /// below: each entry is either a literal relative path (backslashes normalized to forward
        /// slashes) or a "regex:&lt;pattern&gt;"-prefixed regular expression (case-insensitive).
        /// Blank/whitespace-only entries are ignored.
        /// </summary>
        private static void ParseFileListEntries(IEnumerable<string> entries, HashSet<string> literals, List<Regex> regexes)
        {
            foreach (var raw in entries)
            {
                var entry = raw.Trim();
                if (entry.Length == 0)
                    continue;

                if (entry.StartsWith(FileListRegexPrefix))
                {
                    regexes.Add(new Regex(entry[FileListRegexPrefix.Length..], RegexOptions.Compiled | RegexOptions.IgnoreCase));
                }
                else
                {
                    literals.Add(entry.Replace('\\', '/'));
                }
            }
        }

        /// <summary>
        /// Parses a "-filelist"-style file: non-blank lines are either literal relative paths
        /// or "regex:&lt;pattern&gt;"-prefixed regular expressions - see <see cref="ParseFileListEntries"/>.
        /// Same format shared by "download -filelist" and "reconstruct -filelist" - callers decide
        /// for themselves whether a parse failure should warn-and-continue or abort, so this only
        /// reports success/failure plus a message.
        /// </summary>
        public static bool TryParseFileList(string path, out HashSet<string> literals, out List<Regex> regexes, out string error)
        {
            literals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            regexes = [];
            error = null;

            if (!File.Exists(path))
            {
                error = $"Filelist not found: {path}";
                return false;
            }

            try
            {
                ParseFileListEntries(File.ReadAllLines(path), literals, regexes);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Parses an inline, semicolon-separated file list - same literal-path/"regex:"-prefix
        /// syntax as -filelist's file format (see <see cref="ParseFileListEntries"/>), one entry
        /// per ";"-separated item instead of one per line. For a quick one-off subset that isn't
        /// worth writing to a separate list file. Semicolon rather than comma specifically because
        /// a regex entry legitimately contains commas (e.g. a "{2,4}" quantifier).
        /// </summary>
        public static bool TryParseInlineFileList(string inline, out HashSet<string> literals, out List<Regex> regexes, out string error)
        {
            literals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            regexes = [];
            error = null;

            try
            {
                ParseFileListEntries(inline.Split(';'), literals, regexes);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Formats a "done/total (percent%)" progress fragment, e.g. "1,234/5,000 (24.7%)" - the
        /// count/percentage shape repeated across chunkstore pack/rebuild/unpack and validation
        /// progress lines. Callers still supply their own leading verb/noun ("Packed ", " chunks").
        /// </summary>
        public static string FormatProgress(long done, long total) =>
            $"{done:N0}/{total:N0} ({(total > 0 ? done * 100.0 / total : 0):F1}%)";

        public static string FormatProgress(ulong done, ulong total) => FormatProgress((long)done, (long)total);

        /// <summary>
        /// Decrypts using AES/ECB/PKCS7
        /// </summary>
        public static byte[] SymmetricDecryptECB(byte[] input, byte[] key)
        {
            using var aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            using var aesTransform = aes.CreateDecryptor(key, null);
            var output = aesTransform.TransformFinalBlock(input, 0, input.Length);

            return output;
        }
    }
}
