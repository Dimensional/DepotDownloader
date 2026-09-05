// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.IO;
using System.IO.Compression;
using System.Threading;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Shared save/load for the small protobuf-backed checkpoint files used across this project
    /// (chunkstore pack/rebuild progress, chunk validation progress, delete-source-as-we-go
    /// totals, the workshop catalog). Deflate-compressed and written to a "{path}.tmp" file that's
    /// atomically moved into place, so a crash mid-write can never leave a corrupt or
    /// partially-written checkpoint behind for the next run to trip over.
    /// </summary>
    internal static class CheckpointFile
    {
        public static T Load<T>(string path)
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    using var fs = File.OpenRead(path);
                    using var ds = new DeflateStream(fs, CompressionMode.Decompress);
                    return Serializer.Deserialize<T>(ds);
                }
                // Only the open/read step, never Deserialize's own exceptions - a genuinely
                // corrupt/garbled file fails to parse with something else entirely (see
                // WorkshopCatalog.LoadOrCreate's corruption guard), and that should still surface
                // immediately, not get masked by retrying. This retry exists for the same
                // transient-collision window as Save's below: a read landing in the same instant
                // as another process's File.Move overwriting this same path.
                catch (Exception ex) when (attempt < TransientRetryAttempts && ex is IOException or UnauthorizedAccessException)
                {
                    Thread.Sleep(TimeSpan.FromMilliseconds(200 * attempt));
                }
            }
        }

        public static void Save<T>(string path, T value)
        {
            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            using (var ds = new DeflateStream(fs, CompressionMode.Compress))
                Serializer.Serialize(ds, value);

            MoveWithRetry(tmp, path);
        }

        // Bounded, not infinite - a genuinely permanent problem (real permissions denial, a
        // process holding an exclusive lock forever) should still surface as an error after a
        // couple of seconds, not hang. Shared by both Load's and Save's retry loops below.
        private const int TransientRetryAttempts = 5;

        /// <summary>
        /// A brief, bounded retry around the final rename - confirmed in practice (a real
        /// multi-hour "workshop bootstrap" run hit UnauthorizedAccessException here and crashed
        /// the whole process outright) that something else briefly having the destination file
        /// open for reading is a real condition on Windows, not hypothetical: running "workshop
        /// status" concurrently opens this same file via Load's File.OpenRead, and File.Move's
        /// overwrite lands in the same instant often enough to matter on a checkpoint saved this
        /// frequently. Unlike a genuine permissions problem, this resolves itself within
        /// milliseconds (the read finishes), so a handful of short retries is the fix - not a
        /// crash, and not a reason to avoid checking status while a long run is in progress.
        /// </summary>
        private static void MoveWithRetry(string tmp, string path)
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(tmp, path, overwrite: true);
                    return;
                }
                catch (Exception ex) when (attempt < TransientRetryAttempts && ex is IOException or UnauthorizedAccessException)
                {
                    Thread.Sleep(TimeSpan.FromMilliseconds(200 * attempt));
                }
            }
        }
    }
}
