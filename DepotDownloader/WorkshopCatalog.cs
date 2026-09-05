// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
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
    /// One entry from PublishedFile.GetChangeHistory, as recorded into a catalog item's
    /// <see cref="WorkshopCatalogItem.History"/>. ManifestId is a real depot manifest ID for
    /// ChunkBased items, or just Steam's CDN content handle for AncientUgc ones (see
    /// WorkshopItemKind) - never a URL either way; an ancient item's old versions are discoverable
    /// this way but not necessarily re-downloadable (see README).
    /// </summary>
    [ProtoContract]
    public class WorkshopHistoryEntry
    {
        [ProtoMember(1)]
        public uint Timestamp { get; set; }

        [ProtoMember(2)]
        public ulong ManifestId { get; set; }

        [ProtoMember(3)]
        public string ChangeDescription { get; set; }
    }

    /// <summary>
    /// One tracked workshop item's state, as recorded by "workshop bootstrap"/"poll".
    /// ManifestId/TimeUpdated mirror Steam's own PublishedFileDetails.hcontent_file/time_updated
    /// at LastSeenAt - the CURRENT version only. History is the full picture: every version
    /// GetChangeHistory reports, fetched by default so an item that updated more than once between
    /// two polls doesn't silently lose the versions in between (poll's own GetItemChanges delta
    /// only ever reports "this changed since X," never each intermediate step). Because
    /// GetChangeHistory has no "since" filter of its own (see Steam3Session.GetChangeHistory),
    /// every fetch - whether triggered by this item changing, or a backfill sweep - retrieves and
    /// overwrites the WHOLE history; there's no incremental merge logic to get wrong, and no stored
    /// state that could make a fetch trust stale data instead of just re-fetching it.
    ///
    /// HistoryComplete is NOT a "verified forever, stop checking" flag - it only records whether
    /// THE LAST TIME this item was touched by bootstrap/poll, that touch was "-shallow" or not.
    /// It never gates whether a future touch re-fetches: bootstrap fetches for every genuinely new
    /// item, and poll fetches for every item its own GetItemChanges delta reports changed,
    /// regardless of this flag's current value - so a change is never missed because History
    /// looked "complete" already. Its only two actual jobs are (1) telling
    /// BackfillIncompleteHistoryAsync which items still need a first/catch-up fetch (an item that
    /// hasn't changed since a "-shallow" touch has nothing new to learn from a plain re-fetch until
    /// it changes again - GetChangeHistory would just return the same thing - so the sweep targets
    /// exactly those), and (2) surfacing in "status"/"status -list" which items' History might be
    /// incomplete. An older catalog saved before these two fields existed loads them at their
    /// protobuf zero-value defaults (empty list, false) - equivalent to every item in it having
    /// been recorded "-shallow", so it backfills the same way rather than needing a rebuild.
    /// </summary>
    [ProtoContract]
    public class WorkshopCatalogItem
    {
        [ProtoMember(1)]
        public ulong PublishedFileId { get; set; }

        /// <summary>Cached here specifically so polling never needs a per-item GetDetails
        /// round-trip just to build a download filename - GetItemChanges (the poll RPC) does not
        /// return it.</summary>
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

        /// <summary>Every version GetChangeHistory reported as of the last time it was actually
        /// fetched (see LastSeenAt) - oldest first. Only as current as that last fetch; nothing
        /// here is re-verified except by fetching again (see HistoryComplete).</summary>
        [ProtoMember(8)]
        public List<WorkshopHistoryEntry> History { get; set; } = [];

        /// <summary>Whether the LAST bootstrap/poll touch of this item was a full GetChangeHistory
        /// fetch (true) or a "-shallow" one that skipped it (false) - a shallow-tracking marker,
        /// not a permanent "verified, never needs checking again" stamp. It does not prevent a
        /// future change from being caught: poll always re-fetches full history for any item its
        /// own GetItemChanges delta reports changed, and bootstrap always fetches for any genuinely
        /// new item, regardless of what this flag currently says. Its actual job is narrower - it's
        /// what BackfillIncompleteHistoryAsync checks to find items that still need a first/catch-up
        /// fetch (nothing to gain from re-fetching one that hasn't changed since its last shallow
        /// touch, until it changes again - which the change-triggered fetch above already handles).</summary>
        [ProtoMember(9)]
        public bool HistoryComplete { get; set; }
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

        /// <summary>EPublishedFileQueryType used for bootstrap - pinned on a fresh catalog's first
        /// bootstrap call and never changed after (see BootstrapWorkshopCatalogAsync), so a resumed
        /// bootstrap can't silently continue with a different sort/filter - and hence a
        /// BootstrapCursor - than it started with. This C#/wire-format default of 21
        /// (RankedByLastUpdatedDate) is deliberately NOT changed to match "workshop bootstrap"'s
        /// current CLI default (1, RankedByPublicationDate - confirmed empirically more stable
        /// under concurrent workshop activity, see README) - protobuf-net omits a field from the
        /// wire entirely when it equals [DefaultValue], so changing this value would silently
        /// misread any already-saved catalog that happens to have QueryType == 21 (the vast
        /// majority, from before this default changed) as 1 instead. The CLI default is what
        /// actually governs a genuinely new catalog's starting query-type; this is only ever a
        /// momentary placeholder before that first real assignment.</summary>
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

        /// <summary>The lowest time_created seen so far this bootstrap walk - i.e. how far into
        /// the RankedByPublicationDate ranking (descending, newest first) the walk has reached, in
        /// terms of the one thing that's actually meaningful and durable about that ranking rather
        /// than BootstrapCursor's opaque, unverified-lifetime token. Purely a recovery anchor:
        /// BootstrapCursor is still what a normal resume uses, this is never read by the ordinary
        /// path. Its only job is enabling "workshop bootstrap -reset-cursor" to re-enter the walk
        /// close to where it left off (via date_range_created, bounded at this value) instead of
        /// from the very newest item, if BootstrapCursor is ever confirmed to have stopped working
        /// - not yet observed to happen, but nothing durably recorded which item was last reached
        /// otherwise. Meaningless (left at 0) under any query-type other than
        /// RankedByPublicationDate, since only that ranking's sort key is stable enough to bound a
        /// re-entry point by.</summary>
        [ProtoMember(12)]
        public uint LastRecordedCreationTime { get; set; }

        public static string GetPath(string outputRoot, uint appId)
            => Path.Combine(outputRoot, "depot", appId.ToString(), "workshop_catalog.bin");

        public static WorkshopCatalog LoadOrCreate(string path, uint appId)
        {
            if (File.Exists(path))
            {
                // CheckpointFile.Save only ever renames a fully-written ".tmp" over the real path,
                // so a crash mid-write can never leave a torn/partial file here - what's on disk is
                // always either the previous fully-valid save or the new one, never a mix. The
                // remaining realistic risk is post-write corruption (disk bit-rot, a manual edit) or
                // a schema mismatch (an older/newer build's catalog). protobuf-net's wire format is
                // self-describing (field number + wire type per field), so garbled bytes fail to
                // parse rather than silently landing in the wrong typed field - but surface that as
                // a clear, actionable message instead of a raw ProtoException stack trace.
                try
                {
                    return CheckpointFile.Load<WorkshopCatalog>(path);
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException(
                        $"Workshop catalog at '{path}' could not be read (it may be corrupt, truncated, or from an " +
                        $"incompatible version). Delete it and re-run 'workshop bootstrap' to rebuild it - this app's " +
                        $"downloaded content is not affected, only the tracking catalog. Underlying error: {ex.Message}",
                        ex);
                }
            }

            return new WorkshopCatalog { AppId = appId };
        }

        public void Save(string path) => CheckpointFile.Save(path, this);
    }
}
