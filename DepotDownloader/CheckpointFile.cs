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
    /// totals). Deflate-compressed and written to a "{path}.tmp" file that's atomically moved into
    /// place, so a crash mid-write can never leave a corrupt or partially-written checkpoint
    /// behind for the next run to trip over. The workshop catalog used this too until it moved to
    /// a SQLite database (see WorkshopCatalogDb) specifically to get past the whole-file-rewrite
    /// cost this pattern always carries - some of this class's own retry tuning below was
    /// originally motivated by real problems hit there, kept here because the remaining consumers
    /// can still hit the same class of transient collision, just typically at smaller file sizes.
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
                // corrupt/garbled file fails to parse with something else entirely, and that
                // should still surface immediately, not get masked by retrying. This retry exists
                // for the same
                // transient-collision window as Save's below: a read landing in the same instant
                // as another process's File.Move overwriting this same path.
                catch (Exception ex) when (attempt < TransientRetryAttempts && ex is IOException or UnauthorizedAccessException)
                {
                    WarnIfSlow(path, attempt);
                    Thread.Sleep(TimeSpan.FromMilliseconds(RetryBackoffMs * attempt));
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
        // process holding an exclusive lock forever) should still surface as an error, not hang
        // forever. Shared by both Load's and Save's retry loops below.
        //
        // Widened from an original 5 attempts/200ms step (~2s total) after that budget proved too
        // short in practice on a large real file (back when the workshop catalog itself was still
        // one of these - a catalog storing full history for 1M+ items reached tens-to-hundreds of
        // MB, and something else briefly holding it open - an antivirus scan of a large newly-
        // written binary, a backup/cloud-sync tool, or a concurrent read of the same file - could
        // plausibly take longer than 2 seconds to release it at that size; confirmed by a real
        // crash here before this was widened). 10 attempts/500ms step sums to ~22.5s - long enough
        // for a slow scan/sync/large read to clear, still bounded so a truly stuck lock surfaces
        // as an error within well under a minute rather than hanging.
        private const int TransientRetryAttempts = 10;
        private const int RetryBackoffMs = 500;

        /// <summary>
        /// A brief, bounded retry around the final rename - confirmed in practice (a real
        /// multi-hour run against one of this project's checkpoint files hit
        /// UnauthorizedAccessException here and crashed the whole process outright) that something
        /// else briefly having the destination file open for reading is a real condition on
        /// Windows, not hypothetical: a concurrent read via Load's File.OpenRead and File.Move's
        /// overwrite can land in the same instant often enough to matter on a checkpoint saved
        /// this frequently. Unlike a genuine permissions problem, this resolves itself once
        /// whatever else has the file open finishes, so a bounded series of retries is the fix -
        /// not a crash, and not a reason to avoid reading a checkpoint while a long run using it
        /// is in progress.
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
                    WarnIfSlow(path, attempt);
                    Thread.Sleep(TimeSpan.FromMilliseconds(RetryBackoffMs * attempt));
                }
            }
        }

        // Printed once, only if this is taking noticeably longer than the ordinary case - so a
        // long-running operation doesn't look silently hung while waiting out a slow antivirus
        // scan or sync tool, without spamming a line per attempt for the common, sub-second case.
        private static void WarnIfSlow(string path, int attempt)
        {
            if (attempt == 3)
            {
                Console.WriteLine($"Note: waiting for something else to release a lock on {path} (retrying)...");
            }
        }
    }
}
