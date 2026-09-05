// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.Collections.Generic;
using System.IO;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Serializable checkpoint for resuming interrupted chunkstore validation.
    /// Tracks validation state at CSD-file granularity, with a checksum of each
    /// completed CSD so that a resume can detect if the file changed on disk.
    /// </summary>
    [ProtoContract]
    public class ValidationCheckpoint
    {
        /// <summary>Depot ID this checkpoint belongs to.</summary>
        [ProtoMember(1)]
        public uint DepotId { get; set; }

        /// <summary>
        /// CSD indices (1-based) that have been fully validated.
        /// On resume, any index present here is skipped.
        /// </summary>
        [ProtoMember(2)]
        public HashSet<int> ValidatedCsdIndices { get; set; } = [];

        /// <summary>
        /// SHA1 hash of each completed CSD file at validation time, keyed by CSD index.
        /// Used to detect if the file has changed since the checkpoint was written,
        /// which would invalidate the cached result.
        /// </summary>
        [ProtoMember(3)]
        public Dictionary<int, string> CsdFileChecksums { get; set; } = [];

        /// <summary>
        /// Invalid chunk SHA1s collected across all validated CSDs so far.
        /// Preserved across resumes so the final report is always complete.
        /// </summary>
        [ProtoMember(4)]
        public HashSet<string> InvalidChunks { get; set; } = [];

        /// <summary>Total valid chunks counted so far (across completed CSDs).</summary>
        [ProtoMember(5)]
        public int ValidChunksSoFar { get; set; }

        /// <summary>Total chunks counted so far (across completed CSDs).</summary>
        [ProtoMember(6)]
        public int TotalChunksSoFar { get; set; }

        // ----------------------------------------------------------------
        // Persistence helpers
        // ----------------------------------------------------------------

        public static string GetPath(string chunkstoreFolder, uint depotId)
            => Path.Combine(chunkstoreFolder, $"{depotId}_validation.checkpoint");

        public static ValidationCheckpoint LoadFromFile(string path) => CheckpointFile.Load<ValidationCheckpoint>(path);

        public void SaveToFile(string path) => CheckpointFile.Save(path, this);
    }
}
