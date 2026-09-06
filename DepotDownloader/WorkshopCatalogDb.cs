// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

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
    public enum WorkshopItemKind
    {
        Unknown = 0,
        ChunkBased = 1,
        AncientUgc = 2,
    }

    /// <summary>
    /// One entry from PublishedFile.GetChangeHistory, as recorded into a catalog item's history.
    /// ManifestId is a real depot manifest ID for ChunkBased items, or just Steam's CDN content
    /// handle for AncientUgc ones (see WorkshopItemKind) - never a URL either way; an ancient
    /// item's old versions are discoverable this way but not necessarily re-downloadable (see
    /// README).
    /// </summary>
    public class WorkshopHistoryEntry
    {
        public uint Timestamp { get; set; }
        public ulong ManifestId { get; set; }
        public string ChangeDescription { get; set; }
    }

    /// <summary>
    /// One tracked workshop item's state, as recorded by "workshop bootstrap"/"poll"/"refresh".
    /// ManifestId/TimeUpdated mirror Steam's own PublishedFileDetails.hcontent_file/time_updated
    /// at LastSeenAt - the CURRENT version only.
    ///
    /// HistoryCount/HistoryComplete are always populated by any read (they're plain columns on
    /// this item's own database row); History itself - the actual entry list - is populated only
    /// by calls that specifically asked for it (WorkshopCatalogDb.TryGetItem always does; QueryList
    /// only does when told to), since materializing every item's full history just to answer "how
    /// many items are chunk-based" would defeat the point of storing it separately in the first
    /// place. HistoryComplete is NOT a "verified forever, stop checking" flag - it only records
    /// whether THE LAST TIME this item was touched by bootstrap/poll, that touch fetched full
    /// history or was "-shallow". It never gates whether a future touch re-fetches: bootstrap
    /// fetches for every genuinely new item, and poll fetches for every item its own
    /// GetItemChanges delta reports changed, regardless of this flag's current value - so a change
    /// is never missed because history looked "complete" already. Its only two actual jobs are
    /// (1) telling the backfill sweep which items still need a first/catch-up fetch, and (2)
    /// surfacing in "status"/"status -list" which items' history might be incomplete.
    /// </summary>
    public class WorkshopCatalogItem
    {
        public ulong PublishedFileId { get; set; }

        /// <summary>Cached here specifically so polling never needs a per-item GetDetails
        /// round-trip just to build a download filename - GetItemChanges (the poll RPC) does not
        /// return it.</summary>
        public string Title { get; set; }

        /// <summary>Meaningful only when Kind == ChunkBased - a real depot manifest ID for
        /// AncientUgc items, this is just Steam's CDN content handle (see WorkshopItemKind).</summary>
        public ulong ManifestId { get; set; }

        public uint TimeUpdated { get; set; }

        /// <summary>Unix time this entry was last confirmed current (bootstrap pass, poll delta,
        /// or refresh).</summary>
        public uint LastSeenAt { get; set; }

        public WorkshopItemKind Kind { get; set; } = WorkshopItemKind.Unknown;

        /// <summary>Informational only (AncientUgc items) - the actual download always goes
        /// through DownloadPubfileRawAsync, which fetches this fresh rather than trusting a
        /// possibly-stale cached URL.</summary>
        public string FileUrl { get; set; }

        public bool HistoryComplete { get; set; }

        /// <summary>Always accurate regardless of whether History itself was loaded - see this
        /// class's own doc comment.</summary>
        public int HistoryCount { get; set; }

        /// <summary>Every version GetChangeHistory reported as of the last time it was actually
        /// fetched (see LastSeenAt) - oldest first. Only populated when specifically requested -
        /// see this class's own doc comment and HistoryCount.</summary>
        public List<WorkshopHistoryEntry> History { get; set; } = [];

        /// <summary>Set by "workshop refresh" (PublishedFileDetails.banned) - Steam moderation
        /// removed this item. Unlike everything else bootstrap/poll record, this can only be
        /// learned by asking about this specific ID directly via GetDetails: a banned item simply
        /// stops appearing in QueryFiles pages and GetItemChanges deltas, indistinguishable from
        /// any other reason an item might not show up there. Not touched by bootstrap or poll -
        /// only "workshop refresh" ever sets this (or clears it, if a later refresh finds the ban
        /// lifted).</summary>
        public bool Banned { get; set; }

        /// <summary>PublishedFileDetails.ban_reason, if Banned - whatever text (if any) Steam
        /// moderation attached, not otherwise interpreted.</summary>
        public string BanReason { get; set; }

        /// <summary>PublishedFileDetails.visibility, raw (0 observed for a normal public item on
        /// depot 4000). Steam's published SDK documents ERemoteStoragePublishedFileVisibility as
        /// 0=Public, 1=FriendsOnly, 2=Private, 3=Unlisted - not independently re-verified against
        /// this project's own testing, so treat any nonzero value as "not public" rather than
        /// leaning on the exact number. Set only by "workshop refresh", same as Banned/BanReason -
        /// a non-public item (made friends-only/private/unlisted by its own author) is a second,
        /// distinct reason an item can vanish from bootstrap/poll without ever being banned.</summary>
        public uint Visibility { get; set; }

        /// <summary>Set by "workshop refresh" when GetDetails returns EResult.FileNotFound (9)
        /// for this ID - confirmed live (a real refresh run against a large, actively-moderated
        /// catalog) to mean the item is gone outright, not just banned or made private/unlisted
        /// (those still resolve normally, with Banned/Visibility set instead - see there). The
        /// strongest removal signal available, but still only ever learned by asking about this
        /// specific ID directly; bootstrap/poll never set or clear it. Cleared automatically if a
        /// later refresh finds the ID resolving again.</summary>
        public bool Deleted { get; set; }
    }

    /// <summary>
    /// Per-app persistent state for the workshop bootstrap+poll+refresh feature - a SQLite
    /// database (one file per app, same "depot/&lt;appid&gt;/" layout as everything else), WAL
    /// mode.
    ///
    /// This replaces an earlier design where the whole catalog was one protobuf/Deflate blob,
    /// rewritten in full on every checkpoint via CheckpointFile's atomic tmp+move save. That
    /// worked but didn't scale: measured directly against a real ~2M-item/119MB catalog, a single
    /// full-file save took 6.6-6.7s, a cost that scaled with total catalog size rather than with
    /// how much actually changed, and a checkpoint cadence sized for a small catalog turned out to
    /// spend more time re-writing already-saved data than doing useful work once the catalog got
    /// large (see BackfillIncompleteHistoryAsync's own history for exactly this happening). It was
    /// also pure write amplification on real storage - rewriting ~120MB to persist a few hundred
    /// KB of actual change is a genuine concern on an NVMe with finite total-bytes-written life.
    ///
    /// WAL mode fixes both problems at the source rather than by tuning a checkpoint interval:
    /// a write only appends the changed pages to a separate "-wal" file - an UPDATE touching one
    /// row costs roughly one row's worth of I/O, not the whole database - and it allows exactly
    /// one writer plus unlimited concurrent readers with neither blocking the other, which is also
    /// the direct fix for the concurrent-reader crash CheckpointFile needed retry logic for (see
    /// its own history) - that failure mode is structurally impossible here. Meta fields (bootstrap
    /// cursor, poll watermark, etc.) are held in memory and flushed via SaveMeta() - now a single
    /// tiny row UPDATE, not a full rewrite, so nothing here still needs the old "checkpoint every N
    /// items" throttling; every meta flush and every per-item write is already durable and cheap
    /// on its own.
    ///
    /// The file itself is directly queryable with any standard SQLite tool (the sqlite3 CLI, DB
    /// Browser for SQLite, etc.) - a real upgrade over an opaque protobuf blob for anyone wanting
    /// to inspect or build on top of this data beyond what "workshop status" itself prints.
    /// </summary>
    public sealed class WorkshopCatalogDb : IDisposable
    {
        private readonly SqliteConnection _connection;

        public uint AppId { get; }

        public uint QueryType { get; set; }
        public bool BootstrapCompleted { get; set; }
        public string BootstrapCursor { get; set; }
        public uint BootstrapStartedAt { get; set; }
        public uint BootstrapCompletedAt { get; set; }
        public uint BootstrapTotalAsOfStart { get; set; }
        public uint LastWatermark { get; set; }
        public uint LastPolledAt { get; set; }
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
        public uint LastRecordedCreationTime { get; set; }

        private WorkshopCatalogDb(SqliteConnection connection, uint appId)
        {
            _connection = connection;
            AppId = appId;
        }

        public static string GetPath(string outputRoot, uint appId)
            => Path.Combine(outputRoot, "depot", appId.ToString(), "workshop_catalog.db");

        public static WorkshopCatalogDb Open(string outputRoot, uint appId)
        {
            var path = GetPath(outputRoot, appId);
            Directory.CreateDirectory(Path.GetDirectoryName(path));

            var connection = new SqliteConnection($"Data Source={path}");
            connection.Open();

            using (var pragma = connection.CreateCommand())
            {
                // NORMAL is the standard WAL pairing - safe against a crashed process; even a full
                // power loss risks only the last uncommitted transaction, never corruption. This
                // project already accepts an equivalent "lose the last bit of unsaved progress"
                // tradeoff elsewhere (e.g. every periodic checkpoint that came before this).
                pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;";
                pragma.ExecuteNonQuery();
            }

            EnsureSchema(connection, appId);

            var db = new WorkshopCatalogDb(connection, appId);
            db.LoadMeta();
            return db;
        }

        private static void EnsureSchema(SqliteConnection connection, uint appId)
        {
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = """
                    CREATE TABLE IF NOT EXISTS catalog_meta (
                        AppId INTEGER NOT NULL,
                        QueryType INTEGER NOT NULL DEFAULT 21,
                        BootstrapCompleted INTEGER NOT NULL DEFAULT 0,
                        BootstrapCursor TEXT NOT NULL DEFAULT '*',
                        BootstrapStartedAt INTEGER NOT NULL DEFAULT 0,
                        BootstrapCompletedAt INTEGER NOT NULL DEFAULT 0,
                        BootstrapTotalAsOfStart INTEGER NOT NULL DEFAULT 0,
                        LastWatermark INTEGER NOT NULL DEFAULT 0,
                        LastPolledAt INTEGER NOT NULL DEFAULT 0,
                        LastPollResult TEXT,
                        LastRecordedCreationTime INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS items (
                        PublishedFileId INTEGER PRIMARY KEY,
                        Title TEXT,
                        ManifestId INTEGER NOT NULL DEFAULT 0,
                        TimeUpdated INTEGER NOT NULL DEFAULT 0,
                        LastSeenAt INTEGER NOT NULL DEFAULT 0,
                        Kind INTEGER NOT NULL DEFAULT 0,
                        FileUrl TEXT,
                        HistoryComplete INTEGER NOT NULL DEFAULT 0,
                        HistoryCount INTEGER NOT NULL DEFAULT 0,
                        Banned INTEGER NOT NULL DEFAULT 0,
                        BanReason TEXT,
                        Visibility INTEGER NOT NULL DEFAULT 0,
                        Deleted INTEGER NOT NULL DEFAULT 0
                    );
                    -- No index on Kind: only 3 possible values, so a full secondary index over
                    -- every row buys query filtering almost nothing (a table scan is already
                    -- nearly as fast) while still costing real space at scale - measured directly
                    -- at ~2M rows: dropping it (plus a VACUUM to actually reclaim the space)
                    -- saved roughly 13% of the database's total size on top of what VACUUM alone
                    -- recovered. The partial indexes below are worth keeping - they cover a small,
                    -- genuinely selective slice of rows (HistoryComplete=0/Banned=1/Deleted=1),
                    -- unlike Kind's near-even 3-way split across the whole table.
                    CREATE INDEX IF NOT EXISTS idx_items_incomplete ON items(HistoryComplete) WHERE HistoryComplete = 0;
                    CREATE INDEX IF NOT EXISTS idx_items_banned ON items(Banned) WHERE Banned = 1;
                    CREATE INDEX IF NOT EXISTS idx_items_deleted ON items(Deleted) WHERE Deleted = 1;

                    CREATE TABLE IF NOT EXISTS history (
                        PublishedFileId INTEGER NOT NULL REFERENCES items(PublishedFileId) ON DELETE CASCADE,
                        OrdinalIndex INTEGER NOT NULL,
                        Timestamp INTEGER NOT NULL,
                        ManifestId INTEGER NOT NULL,
                        ChangeDescription TEXT,
                        PRIMARY KEY (PublishedFileId, OrdinalIndex)
                    ) WITHOUT ROWID;
                    """;
                cmd.ExecuteNonQuery();
            }

            using (var check = connection.CreateCommand())
            {
                check.CommandText = "SELECT COUNT(*) FROM catalog_meta";
                var count = (long)check.ExecuteScalar();
                if (count == 0)
                {
                    using var insert = connection.CreateCommand();
                    insert.CommandText = "INSERT INTO catalog_meta (AppId) VALUES (@appId)";
                    insert.Parameters.AddWithValue("@appId", appId);
                    insert.ExecuteNonQuery();
                }
            }
        }

        private void LoadMeta()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT QueryType, BootstrapCompleted, BootstrapCursor, BootstrapStartedAt, BootstrapCompletedAt,
                       BootstrapTotalAsOfStart, LastWatermark, LastPolledAt, LastPollResult, LastRecordedCreationTime
                FROM catalog_meta LIMIT 1
                """;
            using var reader = cmd.ExecuteReader();
            reader.Read();
            QueryType = (uint)reader.GetInt64(0);
            BootstrapCompleted = reader.GetInt64(1) != 0;
            BootstrapCursor = reader.GetString(2);
            BootstrapStartedAt = (uint)reader.GetInt64(3);
            BootstrapCompletedAt = (uint)reader.GetInt64(4);
            BootstrapTotalAsOfStart = (uint)reader.GetInt64(5);
            LastWatermark = (uint)reader.GetInt64(6);
            LastPolledAt = (uint)reader.GetInt64(7);
            LastPollResult = reader.IsDBNull(8) ? null : reader.GetString(8);
            LastRecordedCreationTime = (uint)reader.GetInt64(9);
        }

        /// <summary>Flushes the in-memory meta fields (bootstrap cursor, poll watermark, etc.) to
        /// their single database row - a small, cheap UPDATE regardless of catalog size, unlike
        /// the old design's full-catalog rewrite. Cheap enough that callers no longer need to
        /// throttle how often this runs (see this class's own doc comment) - call it once per
        /// page/batch/delta, not on a counted interval.</summary>
        public void SaveMeta()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                UPDATE catalog_meta SET
                    QueryType = @queryType, BootstrapCompleted = @bootstrapCompleted, BootstrapCursor = @bootstrapCursor,
                    BootstrapStartedAt = @bootstrapStartedAt, BootstrapCompletedAt = @bootstrapCompletedAt,
                    BootstrapTotalAsOfStart = @bootstrapTotalAsOfStart, LastWatermark = @lastWatermark,
                    LastPolledAt = @lastPolledAt, LastPollResult = @lastPollResult,
                    LastRecordedCreationTime = @lastRecordedCreationTime
                """;
            cmd.Parameters.AddWithValue("@queryType", QueryType);
            cmd.Parameters.AddWithValue("@bootstrapCompleted", BootstrapCompleted ? 1 : 0);
            cmd.Parameters.AddWithValue("@bootstrapCursor", BootstrapCursor ?? "*");
            cmd.Parameters.AddWithValue("@bootstrapStartedAt", BootstrapStartedAt);
            cmd.Parameters.AddWithValue("@bootstrapCompletedAt", BootstrapCompletedAt);
            cmd.Parameters.AddWithValue("@bootstrapTotalAsOfStart", BootstrapTotalAsOfStart);
            cmd.Parameters.AddWithValue("@lastWatermark", LastWatermark);
            cmd.Parameters.AddWithValue("@lastPolledAt", LastPolledAt);
            cmd.Parameters.AddWithValue("@lastPollResult", (object)LastPollResult ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@lastRecordedCreationTime", LastRecordedCreationTime);
            cmd.ExecuteNonQuery();
        }

        /// <summary>Starts an explicit transaction spanning multiple UpsertItem/ReplaceHistory
        /// calls - NOT used by bootstrap/poll/refresh (see this class's own doc comment: every
        /// write there commits immediately and independently, on purpose). Exists for genuine
        /// bulk loads only - a one-time catalog migration inserting ~2M rows would otherwise pay
        /// per-row commit overhead for no durability benefit, since the whole import is either
        /// finished or safely re-run from scratch, not something resumed mid-way.</summary>
        public SqliteTransaction BeginTransaction() => _connection.BeginTransaction();

        /// <summary>Inserts or fully overwrites one item's row - Title/Kind/ManifestId/etc, plus
        /// whatever HistoryComplete/HistoryCount the caller's object currently holds (a carried-
        /// forward, unchanged value writes back unchanged - harmless and cheap, since this never
        /// touches the history child table). Only ReplaceHistory touches actual history rows -
        /// deliberately separate, so an item update that isn't accompanied by a fresh history
        /// fetch (e.g. poll carrying forward an unrelated item's existing history) costs one small
        /// row write, not a rewrite of that item's whole history list too. <paramref
        /// name="transaction"/> is null for every normal caller (auto-commits immediately); only a
        /// bulk-load helper (see BeginTransaction) passes one in.</summary>
        public void UpsertItem(WorkshopCatalogItem item, SqliteTransaction transaction = null)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = transaction;
            cmd.CommandText = """
                INSERT INTO items (PublishedFileId, Title, ManifestId, TimeUpdated, LastSeenAt, Kind, FileUrl,
                                    HistoryComplete, HistoryCount, Banned, BanReason, Visibility, Deleted)
                VALUES (@id, @title, @manifestId, @timeUpdated, @lastSeenAt, @kind, @fileUrl,
                        @historyComplete, @historyCount, @banned, @banReason, @visibility, @deleted)
                ON CONFLICT(PublishedFileId) DO UPDATE SET
                    Title = excluded.Title, ManifestId = excluded.ManifestId, TimeUpdated = excluded.TimeUpdated,
                    LastSeenAt = excluded.LastSeenAt, Kind = excluded.Kind, FileUrl = excluded.FileUrl,
                    HistoryComplete = excluded.HistoryComplete, HistoryCount = excluded.HistoryCount,
                    Banned = excluded.Banned, BanReason = excluded.BanReason, Visibility = excluded.Visibility,
                    Deleted = excluded.Deleted
                """;
            cmd.Parameters.AddWithValue("@id", (long)item.PublishedFileId);
            cmd.Parameters.AddWithValue("@title", (object)item.Title ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@manifestId", (long)item.ManifestId);
            cmd.Parameters.AddWithValue("@timeUpdated", item.TimeUpdated);
            cmd.Parameters.AddWithValue("@lastSeenAt", item.LastSeenAt);
            cmd.Parameters.AddWithValue("@kind", (int)item.Kind);
            cmd.Parameters.AddWithValue("@fileUrl", (object)item.FileUrl ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@historyComplete", item.HistoryComplete ? 1 : 0);
            cmd.Parameters.AddWithValue("@historyCount", item.HistoryCount);
            cmd.Parameters.AddWithValue("@banned", item.Banned ? 1 : 0);
            cmd.Parameters.AddWithValue("@banReason", (object)item.BanReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@visibility", item.Visibility);
            cmd.Parameters.AddWithValue("@deleted", item.Deleted ? 1 : 0);
            cmd.ExecuteNonQuery();
        }

        /// <summary>The only thing that ever touches the history child table - a full delete+
        /// reinsert of one item's history list (matching GetChangeHistory's own "no since filter,
        /// every fetch is the whole list" contract - see WorkshopCatalogItem's doc comment) plus
        /// updating that item's HistoryComplete/HistoryCount columns. history may be null/empty
        /// (backfill/bootstrap's "-shallow" seed path, or a fetch that came back with nothing).
        /// <paramref name="transaction"/> is null for every normal caller, in which case this runs
        /// its own transaction spanning just these three statements; a bulk-load helper (see
        /// BeginTransaction) passes its own in instead, so this becomes part of that larger one -
        /// SQLite only allows one active transaction per connection, so this must join the
        /// caller's rather than starting a second, which would throw.</summary>
        public void ReplaceHistory(ulong publishedFileId, List<WorkshopHistoryEntry> history, bool complete, SqliteTransaction transaction = null)
        {
            var ownTransaction = transaction == null;
            transaction ??= _connection.BeginTransaction();

            using (var del = _connection.CreateCommand())
            {
                del.Transaction = transaction;
                del.CommandText = "DELETE FROM history WHERE PublishedFileId = @id";
                del.Parameters.AddWithValue("@id", (long)publishedFileId);
                del.ExecuteNonQuery();
            }

            if (history is { Count: > 0 })
            {
                using var ins = _connection.CreateCommand();
                ins.Transaction = transaction;
                ins.CommandText = """
                    INSERT INTO history (PublishedFileId, OrdinalIndex, Timestamp, ManifestId, ChangeDescription)
                    VALUES (@id, @ordinal, @timestamp, @manifestId, @description)
                    """;
                var idParam = ins.Parameters.Add("@id", SqliteType.Integer);
                var ordinalParam = ins.Parameters.Add("@ordinal", SqliteType.Integer);
                var timestampParam = ins.Parameters.Add("@timestamp", SqliteType.Integer);
                var manifestParam = ins.Parameters.Add("@manifestId", SqliteType.Integer);
                var descParam = ins.Parameters.Add("@description", SqliteType.Text);

                idParam.Value = (long)publishedFileId;
                for (var i = 0; i < history.Count; i++)
                {
                    ordinalParam.Value = i;
                    timestampParam.Value = history[i].Timestamp;
                    manifestParam.Value = (long)history[i].ManifestId;
                    descParam.Value = (object)history[i].ChangeDescription ?? DBNull.Value;
                    ins.ExecuteNonQuery();
                }
            }

            using (var upd = _connection.CreateCommand())
            {
                upd.Transaction = transaction;
                upd.CommandText = "UPDATE items SET HistoryComplete = @complete, HistoryCount = @count WHERE PublishedFileId = @id";
                upd.Parameters.AddWithValue("@complete", complete ? 1 : 0);
                upd.Parameters.AddWithValue("@count", history?.Count ?? 0);
                upd.Parameters.AddWithValue("@id", (long)publishedFileId);
                upd.ExecuteNonQuery();
            }

            if (ownTransaction)
            {
                transaction.Commit();
                transaction.Dispose();
            }
        }

        /// <summary>Always includes the full History list (unlike QueryList's default) - every
        /// caller of this is a single bounded lookup (poll's per-changed-item carry-forward,
        /// refresh's per-batch lookup), never a whole-catalog scan, so the extra join here costs
        /// nothing at the scale it's actually used at.</summary>
        public bool TryGetItem(ulong publishedFileId, out WorkshopCatalogItem item)
        {
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = """
                    SELECT PublishedFileId, Title, ManifestId, TimeUpdated, LastSeenAt, Kind, FileUrl,
                           HistoryComplete, HistoryCount, Banned, BanReason, Visibility, Deleted
                    FROM items WHERE PublishedFileId = @id
                    """;
                cmd.Parameters.AddWithValue("@id", (long)publishedFileId);
                using var reader = cmd.ExecuteReader();
                if (!reader.Read())
                {
                    item = null;
                    return false;
                }

                item = ReadItem(reader);
            }

            item.History = LoadHistory(publishedFileId);
            return true;
        }

        private List<WorkshopHistoryEntry> LoadHistory(ulong publishedFileId)
        {
            var entries = new List<WorkshopHistoryEntry>();
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT Timestamp, ManifestId, ChangeDescription FROM history WHERE PublishedFileId = @id ORDER BY OrdinalIndex";
            cmd.Parameters.AddWithValue("@id", (long)publishedFileId);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                entries.Add(new WorkshopHistoryEntry
                {
                    Timestamp = (uint)reader.GetInt64(0),
                    ManifestId = (ulong)reader.GetInt64(1),
                    ChangeDescription = reader.IsDBNull(2) ? null : reader.GetString(2),
                });
            }
            return entries;
        }

        private static WorkshopCatalogItem ReadItem(SqliteDataReader reader) => new()
        {
            PublishedFileId = (ulong)reader.GetInt64(0),
            Title = reader.IsDBNull(1) ? null : reader.GetString(1),
            ManifestId = (ulong)reader.GetInt64(2),
            TimeUpdated = (uint)reader.GetInt64(3),
            LastSeenAt = (uint)reader.GetInt64(4),
            Kind = (WorkshopItemKind)reader.GetInt32(5),
            FileUrl = reader.IsDBNull(6) ? null : reader.GetString(6),
            HistoryComplete = reader.GetInt64(7) != 0,
            HistoryCount = reader.GetInt32(8),
            Banned = reader.GetInt64(9) != 0,
            BanReason = reader.IsDBNull(10) ? null : reader.GetString(10),
            Visibility = (uint)reader.GetInt64(11),
            Deleted = reader.GetInt64(12) != 0,
        };

        public int ItemCount()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM items";
            return Convert.ToInt32((long)cmd.ExecuteScalar());
        }

        /// <summary>One aggregate query replacing what used to be an in-memory scan over every
        /// item - see this class's own doc comment for why that scan (and the full-catalog load
        /// it required) was the thing worth eliminating.</summary>
        public (int Total, int ChunkBased, int AncientUgc, int Unknown, int HistoryComplete) GetStats()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*),
                       COUNT(*) FILTER (WHERE Kind = 1),
                       COUNT(*) FILTER (WHERE Kind = 2),
                       COUNT(*) FILTER (WHERE Kind = 0),
                       COUNT(*) FILTER (WHERE HistoryComplete = 1)
                FROM items
                """;
            using var reader = cmd.ExecuteReader();
            reader.Read();
            return (reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2), reader.GetInt32(3), reader.GetInt32(4));
        }

        /// <summary>All known IDs, ascending - the same order "status -list"/"refresh" have always
        /// used so two runs walk in a stable, repeatable sequence. Just the IDs (plain integers),
        /// not full item objects - "refresh" over a multi-million-item catalog needs its candidate
        /// list, not everything else that comes with it.</summary>
        public List<ulong> GetAllIds()
        {
            var ids = new List<ulong>();
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT PublishedFileId FROM items ORDER BY PublishedFileId";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                ids.Add((ulong)reader.GetInt64(0));
            }
            return ids;
        }

        /// <summary>Up to <paramref name="limit"/> IDs still marked HistoryComplete == 0 - what the
        /// backfill sweep works through. Index-backed (see the partial index in EnsureSchema), so
        /// this stays cheap even once the vast majority of a large catalog is already complete.</summary>
        public List<ulong> GetIncompleteHistoryIds(int limit)
        {
            var ids = new List<ulong>();
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT PublishedFileId FROM items WHERE HistoryComplete = 0 LIMIT @limit";
            cmd.Parameters.AddWithValue("@limit", limit);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                ids.Add((ulong)reader.GetInt64(0));
            }
            return ids;
        }

        public int CountIncompleteHistory()
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM items WHERE HistoryComplete = 0";
            return Convert.ToInt32((long)cmd.ExecuteScalar());
        }

        /// <summary>
        /// "status -list"'s query: onlyIds/kindFilter/bannedOnly/deletedOnly are pushed down as
        /// real, indexed SQL WHERE clauses - a genuine improvement over the old design, which had
        /// to load the entire catalog into memory as full objects before it could filter anything.
        /// nameFilter (an arbitrary .NET regex) can't be translated to SQL, so it's applied in C#
        /// as each row streams past - still never materializing more than one row at a time before
        /// deciding whether to keep it, unlike loading everything up front. Never loads History
        /// itself (only the always-available HistoryCount/HistoryComplete columns) - a caller that
        /// needs full history for a few displayed rows (see "-show-history") should call
        /// FillHistory on just those, not have every matching row pay for it here.
        /// </summary>
        public List<WorkshopCatalogItem> QueryList(HashSet<ulong> onlyIds, WorkshopItemKind? kindFilter, System.Text.RegularExpressions.Regex nameFilter, bool bannedOnly, bool deletedOnly)
        {
            var where = new List<string>();
            var parameters = new List<SqliteParameter>();

            if (onlyIds is { Count: > 0 })
            {
                var names = onlyIds.Select((id, i) => $"@only{i}").ToList();
                where.Add($"PublishedFileId IN ({string.Join(",", names)})");
                parameters.AddRange(onlyIds.Select((id, i) => new SqliteParameter(names[i], (long)id)));
            }
            if (kindFilter != null)
            {
                where.Add("Kind = @kind");
                parameters.Add(new SqliteParameter("@kind", (int)kindFilter.Value));
            }
            if (bannedOnly)
            {
                where.Add("Banned = 1");
            }
            if (deletedOnly)
            {
                where.Add("Deleted = 1");
            }

            var whereClause = where.Count > 0 ? $"WHERE {string.Join(" AND ", where)}" : "";

            var results = new List<WorkshopCatalogItem>();
            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = $"""
                    SELECT PublishedFileId, Title, ManifestId, TimeUpdated, LastSeenAt, Kind, FileUrl,
                           HistoryComplete, HistoryCount, Banned, BanReason, Visibility, Deleted
                    FROM items {whereClause} ORDER BY PublishedFileId
                    """;
                foreach (var p in parameters)
                {
                    cmd.Parameters.Add(p);
                }

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var item = ReadItem(reader);
                    if (nameFilter != null && !nameFilter.IsMatch(item.Title ?? string.Empty))
                    {
                        continue;
                    }
                    results.Add(item);
                }
            }

            return results;
        }

        /// <summary>Populates History for one already-fetched item - the follow-up half of
        /// QueryList's own doc comment. Meant for a small, already-bounded set of rows (e.g. what
        /// "-show-history" is about to print), not a whole matching set.</summary>
        public void FillHistory(WorkshopCatalogItem item) => item.History = LoadHistory(item.PublishedFileId);

        public void Dispose()
        {
            // Folds the WAL back into the main file and truncates it on a clean close, so a
            // finished run doesn't leave a large "-wal" file lingering between invocations.
            try
            {
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException)
            {
                // Best-effort - a failed checkpoint here just means the next Open() (or SQLite
                // itself, on its own auto-checkpoint schedule) does it instead. Not worth losing
                // whatever error is already in flight (if any) over.
            }

            _connection.Dispose();
        }
    }
}
