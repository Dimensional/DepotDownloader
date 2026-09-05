// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using ProtoBuf;

namespace DepotDownloader
{
    /// <summary>
    /// Which download path a workshop item actually needs - the exact same distinction
    /// DownloadPubfileRawAsync already makes per-item (file_url present -> direct-URL "ancient"
    /// UGC; otherwise hcontent_file is a real depot manifest ID). Confirmed empirically: items
    /// from 2012 still come back with a populated file_url, and hcontent_file is populated too
    /// but is just the CDN handle embedded in that URL, NOT a depot manifest ID - treating it as
    /// one (e.g. handing it to a raw depot-manifest download) would be a real bug, not a
    /// harmless no-op. Unknown is the default for a brand-new/never-classified entry and is
    /// treated the same as AncientUgc by "poll" (always re-check rather than trust ManifestId).
    /// </summary>
    [ProtoContract]
    public enum WorkshopItemKind
    {
        Unknown = 0,
        ChunkBased = 1,
        AncientUgc = 2,
    }

    /// <summary>
    /// One tracked workshop item's last-known state, as recorded by "workshop bootstrap"/"poll".
    /// ManifestId/TimeUpdated mirror Steam's own PublishedFileDetails.hcontent_file/time_updated
    /// at LastSeenAt - not a full version history (see "manifest list -workshop" for the
    /// per-item change history via GetChangeHistory instead, or the ugc/&lt;appid&gt;/&lt;id&gt;/_meta.json
    /// sidecar that DownloadPubfileRawAsync itself already maintains for AncientUgc items). Title
    /// is cached here specifically so polling never needs a per-item GetDetails round-trip just to
    /// build a download filename - GetItemChanges (the poll RPC) does not return it.
    /// </summary>
    [ProtoContract]
    public class WorkshopCatalogItem
    {
        [ProtoMember(1)]
        public ulong PublishedFileId { get; set; }

        [ProtoMember(2)]
        public string Title { get; set; }

        /// <summary>Meaningful only when Kind == ChunkBased - a real depot manifest ID for
        /// AncientUgc items, this is just Steam's CDN content handle (see WorkshopItemKind).</summary>
        [ProtoMember(3)]
        public ulong ManifestId { get; set; }

        [ProtoMember(4)]
        public uint TimeUpdated { get; set; }

        /// <summary>Unix time this entry was last confirmed current (bootstrap pass or poll delta).</summary>
        [ProtoMember(5)]
        public uint LastSeenAt { get; set; }

        [ProtoMember(6)]
        public WorkshopItemKind Kind { get; set; } = WorkshopItemKind.Unknown;

        /// <summary>Informational only (AncientUgc items) - the actual download always goes
        /// through DownloadPubfileRawAsync, which fetches this fresh rather than trusting a
        /// possibly-stale cached URL.</summary>
        [ProtoMember(7)]
        public string FileUrl { get; set; }
    }

    /// <summary>
    /// Per-app persistent state for the workshop bootstrap+poll feature: a protobuf/Deflate-
    /// backed dictionary of every known item (see <see cref="WorkshopCatalogItem"/>), plus
    /// bootstrap progress and the poll watermark. Uses the same atomic tmp+move save as every
    /// other checkpoint in this project (see <see cref="CheckpointFile"/>) - this file is written
    /// far more often than a chunkstore checkpoint (every bootstrap page, every poll), so a crash
    /// mid-write must never corrupt it or silently roll it back.
    ///
    /// Deliberately protobuf, not JSON, unlike the ancient-UGC sidecars (_meta.json) or
    /// download_records.json - a real app's workshop can be millions of items (depot 4000 alone
    /// is ~2 million), and re-serializing a multi-hundred-MB JSON dictionary on every poll cycle
    /// would make "poll" anything but cheap. Use "workshop status" to inspect this file's contents
    /// rather than reading it directly.
    /// </summary>
    [ProtoContract]
    public class WorkshopCatalog
    {
        [ProtoMember(1)]
        public uint AppId { get; set; }

        [ProtoMember(2)]
        public Dictionary<ulong, WorkshopCatalogItem> Items { get; set; } = [];

        /// <summary>EPublishedFileQueryType used for bootstrap - kept so a resumed bootstrap
        /// can't silently continue with a different sort/filter than it started with.</summary>
        [ProtoMember(3)]
        [DefaultValue(21u)] // k_PublishedFileQueryType_RankedByLastUpdatedDate - see protobuf-net PBN0020
        public uint QueryType { get; set; } = 21;

        [ProtoMember(4)]
        public bool BootstrapCompleted { get; set; }

        /// <summary>QueryFiles next_cursor to resume an interrupted bootstrap from. Null/empty
        /// once BootstrapCompleted, or before bootstrap has ever run.</summary>
        [ProtoMember(5)]
        [DefaultValue("*")] // see protobuf-net PBN0020
        public string BootstrapCursor { get; set; } = "*";

        [ProtoMember(6)]
        public uint BootstrapStartedAt { get; set; }

        [ProtoMember(7)]
        public uint BootstrapCompletedAt { get; set; }

        /// <summary>QueryFiles' own reported total as of the first bootstrap page - a moving
        /// target on a live workshop, kept only as a rough progress denominator.</summary>
        [ProtoMember(8)]
        public uint BootstrapTotalAsOfStart { get; set; }

        /// <summary>The last_time_updated to pass on the next poll. Advanced only to a poll
        /// response's own update_time - never to "now" - so a poll can't silently skip a window
        /// it never actually asked Steam about.</summary>
        [ProtoMember(9)]
        public uint LastWatermark { get; set; }

        [ProtoMember(10)]
        public uint LastPolledAt { get; set; }

        /// <summary>EResult.ToString() of the most recent poll - "Ignored" here means the
        /// watermark fell outside whatever window GetItemChanges will currently honor (empirically
        /// observed somewhere between 96h and 7 days on depot 4000; see README) and the catalog
        /// needs a fresh bootstrap pass, not a retry.</summary>
        [ProtoMember(11)]
        public string LastPollResult { get; set; }

        public static string GetPath(string outputRoot, uint appId)
            => Path.Combine(outputRoot, "depot", appId.ToString(), "workshop_catalog.bin");

        public static WorkshopCatalog LoadOrCreate(string path, uint appId)
        {
            if (File.Exists(path))
            {
                return CheckpointFile.Load<WorkshopCatalog>(path);
            }

            return new WorkshopCatalog { AppId = appId };
        }

        public void Save(string path) => CheckpointFile.Save(path, this);
    }
}
