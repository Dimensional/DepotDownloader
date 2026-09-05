// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.IO;
using System.IO.Compression;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Shared save/load for the small protobuf-backed checkpoint files used across this project
    /// (chunkstore pack/rebuild progress, chunk validation progress, delete-source-as-we-go
    /// totals). Deflate-compressed and written to a "{path}.tmp" file that's atomically moved into
    /// place, so a crash mid-write can never leave a corrupt or partially-written checkpoint behind
    /// for the next run to trip over.
    /// </summary>
    internal static class CheckpointFile
    {
        public static T Load<T>(string path)
        {
            using var fs = File.OpenRead(path);
            using var ds = new DeflateStream(fs, CompressionMode.Decompress);
            return Serializer.Deserialize<T>(ds);
        }

        public static void Save<T>(string path, T value)
        {
            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            using (var ds = new DeflateStream(fs, CompressionMode.Compress))
                Serializer.Serialize(ds, value);

            File.Move(tmp, path, overwrite: true);
        }
    }
}
