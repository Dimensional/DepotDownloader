// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.IO;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Small persisted record of what a "-delete-source-as-we-go" rebuild originally set out to
    /// copy, captured once from the source chunkstore while it's still fully intact - before any
    /// resumed run's plain re-scan of the source folder would understate reality (segments already
    /// deleted by an earlier partial run are, correctly, no longer visible there). The final
    /// completeness check compares against this instead of a live re-scan of a possibly-diminished
    /// source, so it can't produce a false failure purely because a resume happened.
    /// </summary>
    [ProtoContract]
    public class RebuildCheckpoint
    {
        [ProtoMember(1)]
        public uint DepotId { get; set; }

        /// <summary>Total chunk count in the source chunkstore at the moment this mode first ran.</summary>
        [ProtoMember(2)]
        public int TotalExpectedChunks { get; set; }

        /// <summary>Total raw (on-disk, still encrypted/compressed) chunk bytes at that same moment.</summary>
        [ProtoMember(3)]
        public long TotalExpectedBytes { get; set; }

        public static string GetPath(string outputFolder, uint depotId)
            => Path.Combine(outputFolder, $"{depotId}_rebuild.checkpoint");

        public static RebuildCheckpoint LoadFromFile(string path) => CheckpointFile.Load<RebuildCheckpoint>(path);

        public void SaveToFile(string path) => CheckpointFile.Save(path, this);
    }
}
