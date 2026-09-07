// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

// "workshop bootstrap"/"poll": a two-phase automatic-update-tracking pipeline covering an app's
// entire workshop - both chunk-based items (depot ID == app ID) and ancient/direct-URL UGC items
// (see WorkshopItemKind in WorkshopCatalogDb.cs - see README). Bootstrap walks PublishedFile.
// QueryFiles once to record every item's current state; poll then calls PublishedFile.
// GetItemChanges to find just what changed since last time, and archives only those via
// DownloadPubfileRawAsync - the same per-item entry point "download -workshop -raw" uses, so both
// kinds land through their already-correct dispatch rather than being re-implemented here (see
// Steam3Session.GetItemChanges/QueryFiles for the empirically-confirmed access/range restrictions
// this relies on).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.Internal;

namespace DepotDownloader
{
    static partial class ContentDownloader
    {
        #region Workshop Catalog (bootstrap + poll)

        // A page-request every ~250ms is a deliberate pace, not a minimum - QueryFiles has no
        // documented rate limit, but hammering it back-to-back with zero delay (as this loop
        // originally did) is exactly the kind of behavior that gets an anonymous session throttled
        // on a sustained multi-hour walk. Modest compared to raw manifest downloads' own 500ms
        // per-new-manifest throttle, since a metadata-only page fetch is much cheaper than a real
        // manifest download to begin with.
        private static readonly TimeSpan WorkshopApiPacingDelay = TimeSpan.FromMilliseconds(250);

        /// <summary>
        /// Retries a transient network failure (confirmed in practice: an unhandled
        /// TaskCanceledException from a unified-messages call crashed a real multi-hour bootstrap
        /// run outright) with exponential backoff, up to maxAttempts. On the final attempt the
        /// exception is left to propagate rather than retried again - callers further up (the
        /// bootstrap/poll/download entry points) catch that and exit gracefully with progress
        /// already saved, rather than this helper retrying forever on something that may not be
        /// transient at all.
        /// </summary>
        private static async Task<T> WithTransientRetryAsync<T>(string operationName, Func<Task<T>> action, int maxAttempts = 5)
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    return await action();
                }
                catch (Exception ex) when (attempt < maxAttempts && IsTransientNetworkException(ex))
                {
                    var delay = TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, attempt)));
                    Console.WriteLine($"  {operationName} failed ({ex.GetType().Name}: {ex.Message}) - retrying in {delay.TotalSeconds:F0}s (attempt {attempt}/{maxAttempts})...");
                    await Task.Delay(delay);
                }
            }
        }

        private static bool IsTransientNetworkException(Exception ex) =>
            ex is TaskCanceledException or OperationCanceledException or System.Net.Http.HttpRequestException;

        /// <summary>
        /// Titles are free-form user text and can legitimately contain control characters -
        /// confirmed live against two real depot 4000 items whose titles end in a literal
        /// newline (U+000A). Steam's own workshop page hides this via ordinary HTML whitespace
        /// collapsing; a raw Console.WriteLine has no such collapsing and renders it as an actual
        /// line break, visually breaking a single-line log entry or a "status -list" table row.
        /// Display-only - never applied to what's actually stored, so the catalog stays byte-for-
        /// byte accurate to what Steam returned. Deliberately NOT applied to History entries'
        /// ChangeDescription (see "-show-history"): that field is free-form prose that can be
        /// genuinely, intentionally multi-paragraph (a real change note recorded earlier this
        /// project's life reads fine, arguably better, with its own newlines left alone) - a title
        /// is different, structurally meant to be one line, since Steam's own UI never shows it as
        /// more than that.
        /// </summary>
        private static string SanitizeTitleForDisplay(string title)
        {
            if (string.IsNullOrEmpty(title))
            {
                return title;
            }

            var sb = new System.Text.StringBuilder(title.Length);
            foreach (var c in title)
            {
                sb.Append(c switch
                {
                    '\n' => "\\n",
                    '\r' => "\\r",
                    '\t' => "\\t",
                    _ when char.IsControl(c) => $"\\u{(int)c:x4}",
                    _ => c.ToString(),
                });
            }
            return sb.ToString();
        }

        public static async Task<int> BootstrapWorkshopCatalogAsync(uint appId, string outputRoot, uint pageSize, uint maxItems, uint queryType, bool manifestsOnly = false, bool shallow = false, uint backfillBatch = 200, bool resetCursor = false)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);

            if (resetCursor)
            {
                // Recovery path, not something a normal resume ever needs - BootstrapCursor's real
                // lifetime under Steam isn't confirmed (see README), so if it's ever found to have
                // genuinely stopped working, this re-enters the walk near where it left off instead
                // of restarting from the newest item, using LastRecordedCreationTime as a bound
                // (see QueryFiles' dateRangeCreatedEnd param) - every already-recorded item (and
                // its history) is kept regardless.
                if (catalog.BootstrapCompleted)
                {
                    Console.WriteLine("This catalog's bootstrap is already marked complete - there's no cursor to reset.");
                    return 1;
                }

                catalog.BootstrapCursor = "*";
                Console.WriteLine(catalog.LastRecordedCreationTime > 0
                    ? $"Cursor reset - re-entering the walk bounded at time_created <= {catalog.LastRecordedCreationTime} ({DateTimeOffset.FromUnixTimeSeconds(catalog.LastRecordedCreationTime):u}). {catalog.ItemCount():N0} already-recorded items are kept."
                    : $"Cursor reset, but no recorded creation-time anchor exists (query-type isn't RankedByPublicationDate, or nothing was recorded under it yet) - this will restart from the newest item. {catalog.ItemCount():N0} already-recorded items are still kept.");
                catalog.SaveMeta();
            }

            // Runs once per invocation, regardless of whether bootstrap itself is complete yet -
            // resuming an in-progress walk only fetches history for items newly reached from here
            // on (see below), it doesn't revisit ones already recorded on an earlier run (including
            // an entire catalog recorded before these fields existed, which loads with every item
            // marked incomplete - see WorkshopCatalogItem). This is what actually reaches those
            // without needing to delete anything and start over.
            if (!shallow)
            {
                await BackfillIncompleteHistoryAsync(catalog, backfillBatch);
            }

            if (catalog.BootstrapCompleted)
            {
                Console.WriteLine($"Bootstrap already completed for app {appId} ({catalog.ItemCount():N0} items recorded).");
                Console.WriteLine($"Delete {WorkshopCatalogDb.GetPath(outputRoot, appId)} to force a full re-bootstrap, or run 'workshop poll' to pick up changes since.");
                return 0;
            }

            if (catalog.BootstrapStartedAt == 0)
            {
                // Only pinned on a genuinely fresh start - this was previously overwritten
                // unconditionally on every invocation (a real bug found while checking how safe it
                // would be to change the default query-type below: a resumed walk's BootstrapCursor
                // is only meaningful relative to the ranking it was issued under, so silently
                // repointing an in-progress walk at a different query-type - whether from an
                // explicit -query-type or just a changed default - could have produced undefined
                // pagination behavior, not a clean switch).
                catalog.QueryType = queryType;
                catalog.BootstrapStartedAt = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }
            else if (catalog.QueryType != queryType)
            {
                Console.WriteLine($"Note: this catalog's walk started under query-type {catalog.QueryType} - ignoring the different -query-type {queryType} passed here (a resumed cursor is only valid under its original ranking). Delete the catalog to restart under a different query-type.");
            }

            var recordedCount = catalog.ItemCount();
            Console.WriteLine($"Bootstrapping workshop catalog for app {appId} (resuming at {recordedCount:N0} items already recorded)...");

            if (manifestsOnly)
            {
                // Each item costs its own manifest-request round trip (plus ArchiveDepotRawAsync's
                // existing 500ms-per-new-manifest throttle for chunk-based items) - fine for a
                // small/moderate workshop, but at depot 4000's ~2 million items that throttle alone
                // is well over a week sequential. Not something to let run unbounded by accident.
                Console.WriteLine("-manifests-only requested: every item in this walk will also have its manifest fetched/UGC metadata logged, not just recorded in the catalog. This is far slower than a catalog-only bootstrap - consider -max-items for a large workshop.");
            }

            if (!shallow)
            {
                // Full history is the default specifically so an item that updates more than once
                // between checks never silently loses the versions in between - but for a brand-new
                // item during THIS walk, that's one extra GetChangeHistory round trip PER ITEM on
                // top of the existing per-PAGE pacing, not per-page - at depot 4000's ~2M items,
                // ~250ms of pacing alone per item is multiple days. -shallow skips this (items are
                // marked history-incomplete and get backfilled gradually by later bootstrap/poll
                // runs instead, a handful at a time) - worth using for a first walk of a huge,
                // never-before-bootstrapped workshop.
                Console.WriteLine("Full history (GetChangeHistory) will also be fetched for every new item during this walk - safe for a modest workshop, but adds a full extra round-trip PER ITEM. Pass -shallow to skip this for a large workshop's first bootstrap (items are marked history-incomplete and backfilled gradually afterward instead).");
            }

            var safetyPageBudget = int.MaxValue;

            try
            {
                while (true)
                {
                    // Only passed on a genuinely fresh/reset entry point ("*"), not on every
                    // ongoing page - a real bug found live: passing it on every request alongside
                    // an already-advancing cursor doesn't change which items come back (the cursor
                    // already only returns items at-or-before its own position), but it DOES change
                    // body.total, which reflects the count matching the whole query INCLUDING this
                    // bound - since LastRecordedCreationTime keeps shrinking as the walk progresses,
                    // total shrank right along with it every page, misleadingly (confirmed: it
                    // never affected which items were recorded, since the pagination loop below
                    // never reads body.total at all - purely a progress-display bug, not a
                    // correctness one, but a real one).
                    var dateRangeCreatedEnd = catalog.QueryType == 1 && catalog.LastRecordedCreationTime > 0 && catalog.BootstrapCursor == "*"
                        ? catalog.LastRecordedCreationTime
                        : (uint?)null;
                    var (result, body) = await WithTransientRetryAsync("QueryFiles",
                        () => steam3.QueryFiles(appId, catalog.BootstrapCursor, pageSize, catalog.QueryType, dateRangeCreatedEnd));

                    if (result != EResult.OK || body == null)
                    {
                        Console.WriteLine($"QueryFiles failed: {result}. Progress saved - re-run the same command to resume.");
                        catalog.SaveMeta();
                        return 1;
                    }

                    if (catalog.BootstrapTotalAsOfStart == 0)
                    {
                        catalog.BootstrapTotalAsOfStart = body.total;
                        // total/pageSize is a live/moving target on a churning workshop (items can
                        // be added/removed mid-walk) - this is only a generous backstop against an
                        // infinite loop from an API misbehavior, not a real progress estimate.
                        safetyPageBudget = (int)(body.total / Math.Max(1u, pageSize)) * 3 + 1000;
                    }

                    var now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    foreach (var d in body.publishedfiledetails)
                    {
                        // Same classification DownloadPubfileRawAsync itself uses - file_url wins
                        // first. Confirmed empirically that ancient (2012-era) items still have
                        // hcontent_file populated too, but it's just the CDN handle embedded in
                        // that URL, not a depot manifest ID - Kind is what keeps "poll" from
                        // confusing them.
                        var kind = !string.IsNullOrEmpty(d.file_url) ? WorkshopItemKind.AncientUgc : WorkshopItemKind.ChunkBased;

                        var item = new WorkshopCatalogItem
                        {
                            PublishedFileId = d.publishedfileid,
                            Title = d.title,
                            Kind = kind,
                            FileUrl = kind == WorkshopItemKind.AncientUgc ? d.file_url : null,
                            ManifestId = d.hcontent_file,
                            TimeUpdated = d.time_updated,
                            LastSeenAt = now,
                        };
                        catalog.UpsertItem(item);
                        recordedCount++;

                        // Recovery anchor only - see WorkshopCatalogDb.LastRecordedCreationTime.
                        // Only meaningful under the stable ranking (time_created never reorders
                        // under it, unlike time_updated) - tracking this under query-type 21 would
                        // record a boundary a later date_range_created-bounded re-entry can't
                        // actually trust, so don't bother.
                        if (catalog.QueryType == 1 && (catalog.LastRecordedCreationTime == 0 || d.time_created < catalog.LastRecordedCreationTime))
                        {
                            catalog.LastRecordedCreationTime = d.time_created;
                        }

                        if (!shallow)
                        {
                            await FetchAndRecordHistoryAsync(catalog, d.publishedfileid);
                            await Task.Delay(WorkshopApiPacingDelay);
                        }
                        else
                        {
                            // Seed with just the one entry already known for free (no extra call) -
                            // still marked incomplete regardless, since a single current snapshot
                            // can't tell us whether other versions exist in between.
                            catalog.ReplaceHistory(d.publishedfileid, [new WorkshopHistoryEntry { Timestamp = d.time_updated, ManifestId = d.hcontent_file }], complete: false);
                        }

                        if (manifestsOnly)
                        {
                            try
                            {
                                // Reuses "d" (already fetched by this page's QueryFiles call)
                                // rather than the single-argument overload, which would
                                // redundantly re-fetch the same PublishedFileDetails via
                                // GetPublishedFileDetails per item - doubling an already-expensive
                                // walk. Manifest-only for ChunkBased (RawDownloadOptions.DryRun),
                                // metadata-logged-not-fetched for AncientUgc (see
                                // DownloadWebFileToUGCAsync's dryRun handling).
                                await DownloadPubfileRawAsync(d.publishedfileid, d, new RawDownloadOptions { OutputRoot = outputRoot, DryRun = true });
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"    Warning: manifest/metadata fetch failed for {d.publishedfileid}: {ex.Message}");
                            }
                        }
                    }

                    Console.WriteLine($"  {recordedCount:N0} items recorded so far (of ~{body.total:N0} reported by Steam)...");

                    // Compare against the cursor we just queried WITH (not the previous
                    // request's) - this is what actually detects "the server stopped advancing".
                    var donePaging = string.IsNullOrEmpty(body.next_cursor)
                        || body.next_cursor == catalog.BootstrapCursor
                        || body.publishedfiledetails.Count == 0;

                    if (donePaging)
                    {
                        catalog.BootstrapCompleted = true;
                        catalog.BootstrapCompletedAt = now;
                        catalog.SaveMeta();
                        Console.WriteLine($"Bootstrap complete: {recordedCount:N0} items recorded for app {appId}.");
                        return 0;
                    }

                    catalog.BootstrapCursor = body.next_cursor;

                    if (maxItems > 0 && recordedCount >= maxItems)
                    {
                        catalog.SaveMeta();
                        Console.WriteLine($"Reached -max-items {maxItems} - stopping early (bootstrap NOT marked complete; re-run without -max-items to continue).");
                        return 0;
                    }

                    // Every item upserted above is already durably written on its own (see
                    // WorkshopCatalogDb's own doc comment) - unlike the old design, there's no
                    // separate "checkpoint" of item data left to throttle. This only flushes the
                    // small meta row (cursor/recovery anchor/etc), which is cheap enough now to do
                    // every page rather than counting pages between saves.
                    catalog.SaveMeta();

                    if (--safetyPageBudget <= 0)
                    {
                        Console.WriteLine("Warning: page count far exceeded the expected total - stopping to avoid an unbounded loop. Progress saved; re-run to resume, or investigate before continuing.");
                        return 1;
                    }

                    // Deliberate pacing, not a rate-limit workaround we've confirmed exists - see
                    // WorkshopApiPacingDelay.
                    await Task.Delay(WorkshopApiPacingDelay);
                }
            }
            catch (Exception ex) when (IsTransientNetworkException(ex))
            {
                // WithTransientRetryAsync's own retries are exhausted, or -manifests-only's
                // DownloadPubfileRawAsync call threw one directly (that path isn't retried itself
                // - a single item's manifest fetch failing is already just logged and skipped
                // there, this only catches a genuinely unrecoverable one escaping that try/catch
                // too). Progress is saved regardless - the whole point of resumable bootstrap is
                // that this is a "re-run the same command" situation, not a crash.
                Console.WriteLine($"Bootstrap stopped after repeated {ex.GetType().Name}s - this looks like throttling or a sustained network issue, not a bug in what's been recorded so far.");
                catalog.SaveMeta();
                Console.WriteLine($"Progress saved ({recordedCount:N0} items) - re-run the same command to resume.");
                return 1;
            }
        }

        public static async Task<int> PollWorkshopCatalogAsync(uint appId, string outputRoot, bool dryRun, bool manifestsOnly = false, bool shallow = false, uint backfillBatch = 200, bool catalogOnly = false)
        {
            outputRoot = ResolveOutputRoot(outputRoot);

            if (!File.Exists(WorkshopCatalogDb.GetPath(outputRoot, appId)))
            {
                Console.WriteLine($"No catalog found for app {appId} at {WorkshopCatalogDb.GetPath(outputRoot, appId)}.");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' first.");
                return 1;
            }

            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);

            if (!catalog.BootstrapCompleted)
            {
                Console.WriteLine("Warning: bootstrap has not finished for this app yet - polling now only ever sees items already recorded plus whatever changes after the watermark below. Consider finishing 'workshop bootstrap' first.");
            }

            var since = catalog.LastWatermark > 0 ? catalog.LastWatermark : catalog.BootstrapStartedAt;
            if (since == 0)
            {
                since = 1;
            }

            Console.WriteLine($"Polling app {appId} for changes since {since} ({DateTimeOffset.FromUnixTimeSeconds(since):u})...");

            EResult result;
            CPublishedFile_GetItemChanges_Response body;
            try
            {
                (result, body) = await WithTransientRetryAsync("GetItemChanges", () => steam3.GetItemChanges(appId, since));
            }
            catch (Exception ex) when (IsTransientNetworkException(ex))
            {
                Console.WriteLine($"Poll stopped after repeated {ex.GetType().Name}s - this looks like throttling or a sustained network issue. The watermark was not advanced, so a re-run will ask about the same window again.");
                return 1;
            }
            catalog.LastPolledAt = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            catalog.LastPollResult = result.ToString();

            if (result == EResult.Ignored)
            {
                catalog.SaveMeta();
                Console.WriteLine("Result: Ignored - the watermark is older than GetItemChanges will currently honor (empirically somewhere between 96h and 7 days on a high-churn app - see README).");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' again to catch up (it resumes/refreshes the existing catalog) - this also resets the watermark.");
                return 2;
            }

            if (result != EResult.OK || body == null)
            {
                catalog.SaveMeta();
                Console.WriteLine($"GetItemChanges failed: {result}");
                return 1;
            }

            Console.WriteLine($"{body.workshop_items.Count:N0} item(s) reported changed.");

            var downloaded = 0;
            var failed = 0;

            foreach (var change in body.workshop_items)
            {
                catalog.TryGetItem(change.published_file_id, out var existing);
                var isNew = existing == null;

                // True preview: no network calls beyond GetItemChanges itself, no catalog
                // mutation, nothing persisted - reports using only what's already in memory. A
                // real bug lived here previously: this used to fall through to the same
                // catalog write / reclassification call / watermark advance / meta save as a
                // real poll, differing only in skipping the actual archive step - so running
                // "-dry-run" then a real poll later would silently never re-see or archive
                // whatever it had "previewed," since the watermark had already moved past it and
                // the catalog already held its new ManifestId.
                if (dryRun)
                {
                    var skipDry = existing?.Kind == WorkshopItemKind.ChunkBased && existing.ManifestId == change.manifest_id;
                    if (!skipDry)
                    {
                        Console.WriteLine($"  {(isNew ? "NEW" : "CHANGED")} {change.published_file_id} \"{SanitizeTitleForDisplay(existing?.Title) ?? $"unknown_{change.published_file_id}"}\" [{existing?.Kind ?? WorkshopItemKind.Unknown}]");
                    }
                    continue;
                }

                var title = existing?.Title;
                var kind = existing?.Kind ?? WorkshopItemKind.Unknown;
                var fileUrl = existing?.FileUrl;

                // GetItemChanges doesn't return a title, file_url, or anything else that
                // classifies the item, so re-classifying costs an extra round-trip - only worth
                // paying for items we've never seen before, OR ones not already confirmed
                // ChunkBased. That second case matters: an ancient/direct-URL item could
                // conceivably be replaced by a chunk-based one on some future update (unconfirmed
                // either way - not something to assume won't happen), and a ChunkBased item is
                // for all practical purposes never going to revert to ancient - so re-checking
                // anything not already confirmed ChunkBased is what actually catches that
                // transition instead of leaving a stale Kind cached forever. Same file_url-first
                // classification as bootstrap/DownloadPubfileRawAsync.
                PublishedFileDetails freshDetails = null;

                if (isNew || kind != WorkshopItemKind.ChunkBased)
                {
                    try
                    {
                        freshDetails = await steam3.GetPublishedFileDetails(change.published_file_id);
                        title = freshDetails?.title;
                        fileUrl = freshDetails?.file_url;
                        kind = !string.IsNullOrEmpty(fileUrl) ? WorkshopItemKind.AncientUgc : WorkshopItemKind.ChunkBased;
                    }
                    catch
                    {
                        // Fall through to the placeholders below - still worth attempting the
                        // download itself, which will do its own (more reliable) lookup.
                    }
                }

                title ??= $"unknown_{change.published_file_id}";

                // GetItemChanges' own manifest_id is only trustworthy as a "did content actually
                // move" shortcut for a confirmed ChunkBased item - for AncientUgc/Unknown, the
                // field's meaning under a direct-URL item isn't confirmed (see WorkshopItemKind),
                // so always re-check instead. DownloadPubfileRawAsync's own TimeUpdated-based
                // sidecar for ancient items already makes a no-op re-check cheap when nothing
                // actually changed.
                var skip = kind == WorkshopItemKind.ChunkBased
                    && existing != null
                    && existing.ManifestId == change.manifest_id;

                // History carried forward, not reset - a fresh fetch below (unless -shallow)
                // overwrites both the entries and these two fields for real; -shallow explicitly
                // marks incomplete instead, even if it happened to look complete before (a
                // reported change is itself reason enough not to trust the old history anymore).
                var newItem = new WorkshopCatalogItem
                {
                    PublishedFileId = change.published_file_id,
                    Title = title,
                    Kind = kind,
                    FileUrl = fileUrl,
                    ManifestId = change.manifest_id,
                    TimeUpdated = change.time_updated,
                    LastSeenAt = catalog.LastPolledAt,
                    HistoryCount = existing?.HistoryCount ?? 0,
                    HistoryComplete = !shallow && (existing?.HistoryComplete ?? false),
                };
                catalog.UpsertItem(newItem);

                if (skip)
                {
                    // Steam counted it as "changed" (could be a metadata-only edit) but the
                    // manifest we'd archive by didn't move - nothing new to download, and (since
                    // nothing about the archived content changed) nothing new to backfill either.
                    continue;
                }

                Console.WriteLine($"  {(isNew ? "NEW" : "CHANGED")} {change.published_file_id} \"{SanitizeTitleForDisplay(title)}\" [{kind}]");

                // Full history by default - GetItemChanges only ever says "this changed since X,"
                // never how many times or through what intermediate versions, so without this an
                // item that updated more than once between polls would silently lose everything
                // but its latest state. No incremental fetch exists (see ReplaceHistory) - this
                // always re-fetches and overwrites the whole list, whether or not it was already
                // complete.
                if (!shallow)
                {
                    await FetchAndRecordHistoryAsync(catalog, change.published_file_id);
                    await Task.Delay(WorkshopApiPacingDelay);
                }

                // -catalog-only stops here, the same way bootstrap's plain default does: the
                // catalog entry (and, unless -shallow, its full history) is already recorded
                // above - what's skipped is the archive step below, not the catalog update
                // itself. This is the one poll mode with no network cost proportional to file
                // size, only to item count - useful for tracking a workshop's changes without
                // committing to storing its content.
                if (!catalogOnly)
                {
                    try
                    {
                        // Deliberately the same per-item entry point "download -workshop -raw"
                        // uses, not a hand-rolled DownloadAppRawAsync call - it does its own
                        // file_url/hcontent_file dispatch internally, so both ChunkBased and
                        // AncientUgc items land correctly without duplicating that logic here.
                        // Reuse freshDetails when the reclassification step above already
                        // fetched it, rather than fetching the same PublishedFileDetails twice.
                        // manifestsOnly maps to RawDownloadOptions.DryRun - manifest-only for
                        // ChunkBased, metadata-logged-not-fetched for AncientUgc (see
                        // DownloadWebFileToUGCAsync).
                        var options = new RawDownloadOptions { OutputRoot = outputRoot, DryRun = manifestsOnly };
                        if (freshDetails != null)
                        {
                            await DownloadPubfileRawAsync(change.published_file_id, freshDetails, options);
                        }
                        else
                        {
                            await DownloadPubfileRawAsync(change.published_file_id, options);
                        }
                        downloaded++;
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        Console.WriteLine($"    ERROR downloading {change.published_file_id}: {ex.Message}");
                    }
                }
                else
                {
                    downloaded++;
                }
            }

            // Nothing below this point runs for -dry-run: no watermark advance, no backfill
            // sweep, no meta save - a dry run must leave the catalog byte-for-byte as it found
            // it, or a later real poll could silently never re-see (and so never archive)
            // whatever this one "previewed."
            if (!dryRun)
            {
                // Advance only to what GetItemChanges itself reported, never to "now" - so a poll
                // can never silently skip a window it didn't actually ask Steam about.
                catalog.LastWatermark = body.update_time;
                catalog.SaveMeta();

                // Beyond this poll's own delta, also chip away at any items still marked
                // history-incomplete from an earlier "-shallow" pass - not just the ones this
                // particular poll happened to touch. Bounded (-backfill-batch) so this can't turn
                // an otherwise-cheap poll into a long sweep by accident.
                if (!shallow)
                {
                    await BackfillIncompleteHistoryAsync(catalog, backfillBatch);
                }
            }

            var verb = catalogOnly ? "Recorded catalog entries for" : manifestsOnly ? "Recorded manifests/metadata for" : "Downloaded";
            Console.WriteLine(dryRun
                ? $"Dry run: {body.workshop_items.Count:N0} item(s) would be checked/downloaded - nothing was actually fetched."
                : $"{verb} {downloaded:N0} item(s), {failed:N0} failed. Watermark advanced to {catalog.LastWatermark} ({DateTimeOffset.FromUnixTimeSeconds(catalog.LastWatermark):u}).");

            return failed > 0 ? 1 : 0;
        }

        /// <summary>
        /// "workshop refresh" - re-verifies already-known catalog entries directly against
        /// PublishedFile.GetDetails, batched, instead of relying on bootstrap's ranking walk or
        /// poll's GetItemChanges delta to notice anything. Exists for two things neither of those
        /// can do: (1) correcting a stale or wrong title/kind/manifest handle for an item that's
        /// still perfectly resolvable but wasn't caught by either mechanism, and (2) positively
        /// detecting a removal - an item Steam moderation banned, or its own author made
        /// private/unlisted - which simply stops appearing in QueryFiles pages and GetItemChanges
        /// deltas with no signal distinguishing it from any other reason an item might not show up
        /// there. GetDetails answers about a specific ID directly, so it's the only one of the
        /// three RPCs this feature can be built on.
        ///
        /// Confirmed anonymous-friendly (same GetDetails RPC ad-hoc "download -workshop" already
        /// uses without a login) - unlike "poll", this never requires -username. Purely a metadata
        /// pass - it never downloads content, same as bootstrap's own plain default.
        /// </summary>
        public static async Task<int> RefreshWorkshopCatalogAsync(uint appId, string outputRoot, HashSet<ulong> onlyIds, uint batchSize, uint maxItems)
        {
            outputRoot = ResolveOutputRoot(outputRoot);

            if (!File.Exists(WorkshopCatalogDb.GetPath(outputRoot, appId)))
            {
                Console.WriteLine($"No catalog found for app {appId} at {WorkshopCatalogDb.GetPath(outputRoot, appId)}.");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' first.");
                return 1;
            }

            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);

            // Sorted for the same reason "status -list" is: two runs (or a run resumed via
            // -max-items) walk IDs in a stable, repeatable order rather than whatever order the
            // database happened to return them in.
            var ids = catalog.GetAllIds();
            if (onlyIds is { Count: > 0 })
            {
                ids = ids.Where(onlyIds.Contains).ToList();
            }
            if (maxItems > 0 && ids.Count > (int)maxItems)
            {
                ids = ids.Take((int)maxItems).ToList();
            }

            if (ids.Count == 0)
            {
                Console.WriteLine("Nothing to refresh - no matching items in the catalog.");
                return 0;
            }

            Console.WriteLine($"Refreshing {ids.Count:N0} item(s) in batches of {batchSize}...");

            var checkedCount = 0;
            var changedCount = 0;
            var newlyBanned = 0;
            var newlyDeleted = 0;
            var unresolved = 0;
            var now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            for (var offset = 0; offset < ids.Count; offset += (int)batchSize)
            {
                var batchIds = ids.Skip(offset).Take((int)batchSize).ToList();

                var (result, details) = await WithTransientRetryAsync("GetDetails",
                    () => steam3.GetPublishedFileDetailsBatch(batchIds));

                if (result != EResult.OK || details == null)
                {
                    // Nothing buffered in memory to lose here - every item already checked this
                    // run was already durably written as it was processed (see UpsertItem).
                    Console.WriteLine($"GetDetails failed for the batch starting at offset {offset}: {result}. Everything checked so far is already saved - re-run with the same -only/-max-items (or none) to pick up where this left off; already-corrected entries are simply re-verified, not duplicated.");
                    return 1;
                }

                var byId = details.ToDictionary(d => d.publishedfileid);

                foreach (var id in batchIds)
                {
                    checkedCount++;

                    if (!catalog.TryGetItem(id, out var item))
                    {
                        continue; // shouldn't happen - every id here came from the catalog itself
                    }

                    byId.TryGetValue(id, out var d);
                    var resultCode = d != null ? (EResult)d.result : (EResult?)null;

                    if (d == null || resultCode != EResult.OK)
                    {
                        unresolved++;

                        // Confirmed live against a real, actively-moderated 2M-item catalog:
                        // FileNotFound (9) is what a genuinely deleted item's own entry looks like
                        // here - distinct from banned/private, which come back OK with
                        // Banned/Visibility set instead (see the "changed" branch below). Only
                        // this specific, confirmed result marks Deleted - "no entry returned at
                        // all" is a different, unconfirmed case, not worth treating the same on a
                        // guess.
                        if (resultCode == EResult.FileNotFound && !item.Deleted)
                        {
                            item.Deleted = true;
                            catalog.UpsertItem(item);
                            changedCount++;
                            newlyDeleted++;
                            Console.WriteLine($"  DELETED {id} \"{SanitizeTitleForDisplay(item.Title)}\"");
                        }
                        else
                        {
                            var code = d != null ? resultCode.ToString() : "no entry returned";
                            Console.WriteLine($"  {id} \"{SanitizeTitleForDisplay(item.Title)}\" - did not resolve ({code})");
                        }

                        continue;
                    }

                    var wasBanned = item.Banned;
                    var wasDeleted = item.Deleted;
                    var kind = !string.IsNullOrEmpty(d.file_url) ? WorkshopItemKind.AncientUgc : WorkshopItemKind.ChunkBased;
                    var fileUrl = kind == WorkshopItemKind.AncientUgc ? d.file_url : null;
                    // Normalized before comparing AND storing - GetDetails returns "" for a
                    // non-banned item, but every existing catalog entry predates this field and
                    // loads it at its own zero-value default (null); treating those as distinct
                    // would flag nearly every item as "changed" on its first-ever refresh even
                    // when nothing real differs (caught live: a real refresh against known-good
                    // items reported all three as "corrected" purely from this null-vs-"" gap).
                    var banReason = string.IsNullOrEmpty(d.ban_reason) ? null : d.ban_reason;

                    var changed = item.Title != d.title
                        || item.Kind != kind
                        || item.FileUrl != fileUrl
                        || item.ManifestId != d.hcontent_file
                        || item.Banned != d.banned
                        || item.BanReason != banReason
                        || item.Visibility != d.visibility
                        || wasDeleted;

                    item.Title = d.title;
                    item.Kind = kind;
                    item.FileUrl = fileUrl;
                    item.ManifestId = d.hcontent_file;
                    item.TimeUpdated = d.time_updated;
                    item.Banned = d.banned;
                    item.BanReason = banReason;
                    item.Visibility = d.visibility;
                    item.Deleted = false;
                    item.LastSeenAt = now;
                    // History untouched either way - UpsertItem never writes history rows itself
                    // (see its own doc comment), so item.HistoryComplete/HistoryCount (already
                    // loaded as-is by TryGetItem) just write back unchanged.
                    catalog.UpsertItem(item);

                    if (changed)
                    {
                        changedCount++;
                        if (d.banned && !wasBanned)
                        {
                            newlyBanned++;
                            Console.WriteLine($"  BANNED {id} \"{SanitizeTitleForDisplay(d.title)}\"{(string.IsNullOrEmpty(d.ban_reason) ? "" : $" - {d.ban_reason}")}");
                        }
                        else if (wasDeleted)
                        {
                            Console.WriteLine($"  RESTORED {id} \"{SanitizeTitleForDisplay(d.title)}\" - a previous refresh had found this deleted; it resolves again now.");
                        }
                        else
                        {
                            Console.WriteLine($"  CORRECTED {id} \"{SanitizeTitleForDisplay(d.title)}\"");
                        }
                    }
                }

                Console.WriteLine($"  {checkedCount:N0} of {ids.Count:N0} checked...");

                await Task.Delay(WorkshopApiPacingDelay);
            }

            Console.WriteLine($"Refresh complete: {checkedCount:N0} checked, {changedCount:N0} corrected ({newlyBanned:N0} newly banned, {newlyDeleted:N0} newly deleted), {unresolved:N0} did not resolve at all this run.");

            return 0;
        }

        public static int PrintWorkshopCatalogStatus(uint appId, string outputRoot)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalogDb.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                return 1;
            }

            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);
            var (total, chunkBased, ancientUgc, unknownKind, historyComplete) = catalog.GetStats();

            Console.WriteLine($"App:                {catalog.AppId}");
            Console.WriteLine($"Catalog path:       {catalogPath}");
            Console.WriteLine($"Items recorded:     {total:N0}  (chunk-based: {chunkBased:N0}, ancient UGC: {ancientUgc:N0}, unclassified: {unknownKind:N0})");
            Console.WriteLine($"Full history known: {historyComplete:N0} of {total:N0}" +
                (historyComplete < total ? " - the rest will backfill gradually on future bootstrap/poll runs (see -backfill-batch)." : ""));
            Console.WriteLine($"Bootstrap complete: {catalog.BootstrapCompleted}");
            Console.WriteLine($"Query type:         {catalog.QueryType}" +
                (catalog.QueryType == 1 ? " (RankedByPublicationDate - stable)" : catalog.QueryType == 21 ? " (RankedByLastUpdatedDate - NOT stable under concurrent activity, see README)" : ""));

            if (catalog.LastRecordedCreationTime != 0)
            {
                Console.WriteLine($"Recovery anchor:    time_created <= {catalog.LastRecordedCreationTime} ({DateTimeOffset.FromUnixTimeSeconds(catalog.LastRecordedCreationTime):u}) - see -reset-cursor");
            }

            if (!catalog.BootstrapCompleted && catalog.BootstrapStartedAt != 0)
            {
                Console.WriteLine($"Bootstrap resumes at cursor: {catalog.BootstrapCursor}");
            }

            if (catalog.BootstrapStartedAt != 0)
            {
                Console.WriteLine($"Bootstrap started:  {DateTimeOffset.FromUnixTimeSeconds(catalog.BootstrapStartedAt):u}");
            }

            if (catalog.BootstrapCompletedAt != 0)
            {
                Console.WriteLine($"Bootstrap finished: {DateTimeOffset.FromUnixTimeSeconds(catalog.BootstrapCompletedAt):u}");
            }

            if (catalog.LastPolledAt != 0)
            {
                Console.WriteLine($"Last polled:        {DateTimeOffset.FromUnixTimeSeconds(catalog.LastPolledAt):u} (result: {catalog.LastPollResult})");
                Console.WriteLine($"Current watermark:  {catalog.LastWatermark} ({DateTimeOffset.FromUnixTimeSeconds(catalog.LastWatermark):u})");
            }
            else
            {
                Console.WriteLine("Last polled:        never");
            }

            return 0;
        }

        /// <summary>
        /// "workshop status -list" - the actual per-item view of the catalog. Without this, the
        /// only way to see what bootstrap/poll actually recorded was the aggregate counts above or
        /// opening the SQLite database directly (a real option now, unlike the old protobuf/Deflate
        /// blob - see WorkshopCatalogDb - but still not what most people want for a quick look).
        /// Sorted by PublishedFileId so two snapshots of the same catalog print identically and
        /// diff cleanly.
        /// </summary>
        public static int PrintWorkshopCatalogList(uint appId, string outputRoot, HashSet<ulong> onlyIds, WorkshopItemKind? kindFilter, Regex nameFilter, bool bannedOnly, bool deletedOnly, bool showHistory, uint limit)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalogDb.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                return 1;
            }

            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);

            var matching = catalog.QueryList(onlyIds, kindFilter, nameFilter, bannedOnly, deletedOnly);
            var shown = limit == 0 ? matching : matching.Take((int)limit).ToList();

            Console.WriteLine($"{"PublishedFileId",-20} {"Kind",-11} {"ManifestId",-20} {"TimeUpdated",-20} {"LastSeenAt",-20} {"History",-9} Title");
            foreach (var item in shown)
            {
                var updated = item.TimeUpdated == 0 ? "-" : DateTimeOffset.FromUnixTimeSeconds(item.TimeUpdated).ToString("u");
                var seen = item.LastSeenAt == 0 ? "-" : DateTimeOffset.FromUnixTimeSeconds(item.LastSeenAt).ToString("u");
                // "N (complete)" once a real GetChangeHistory fetch has landed and is trusted
                // gap-free; "N? (partial)" for anything recorded "-shallow" or from before these
                // fields existed - N there is just whatever's known so far (often just the current
                // version), not a real total.
                var hist = item.HistoryComplete ? $"{item.HistoryCount} (complete)" : $"{item.HistoryCount}? (partial)";
                // Only ever populated by "workshop refresh" - never touched by bootstrap/poll.
                var tag = item.Deleted ? " [DELETED]" : item.Banned ? " [BANNED]" : item.Visibility != 0 ? " [NOT PUBLIC]" : "";
                Console.WriteLine($"{item.PublishedFileId,-20} {item.Kind,-11} {item.ManifestId,-20} {updated,-20} {seen,-20} {hist,-16} {SanitizeTitleForDisplay(item.Title)}{tag}");

                // Verbose by design - only worth combining with a tight filter (-only a handful of
                // IDs, or a narrow -name) rather than a whole-catalog listing. Oldest first,
                // matching GetChangeHistory's own order - so this reads top-to-bottom as "how this
                // item evolved," not reversed. Fetched here, one row at a time, rather than as
                // part of the main query above - see QueryList's own doc comment for why.
                if (showHistory)
                {
                    catalog.FillHistory(item);
                    if (item.History.Count == 0)
                    {
                        Console.WriteLine("    (no history recorded yet)");
                    }
                    else
                    {
                        foreach (var entry in item.History)
                        {
                            var when = entry.Timestamp == 0 ? "-" : DateTimeOffset.FromUnixTimeSeconds(entry.Timestamp).ToString("u");
                            var desc = string.IsNullOrEmpty(entry.ChangeDescription) ? "" : $" - {entry.ChangeDescription}";
                            Console.WriteLine($"    {when}  manifest {entry.ManifestId}{desc}");
                        }
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine(shown.Count < matching.Count
                ? $"Showing {shown.Count:N0} of {matching.Count:N0} matching item(s) - pass -limit 0 to print all, or narrow with -only/-kind/-name."
                : $"{matching.Count:N0} matching item(s).");

            return 0;
        }

        /// <summary>
        /// Every historical entry for one item, fully paginated - most items have far fewer
        /// changes than one page, but this doesn't assume that. Returns an empty list (rather than
        /// throwing) on any failure, since a single item's history being unavailable shouldn't
        /// abort a whole catalog-wide "download -history" walk.
        /// </summary>
        private static async Task<List<CPublishedFile_GetChangeHistory_Response.ChangeLog>> GetFullChangeHistoryAsync(ulong publishedFileId)
        {
            var all = new List<CPublishedFile_GetChangeHistory_Response.ChangeLog>();
            uint startIndex = 0;
            const uint pageSize = 100;

            try
            {
                while (true)
                {
                    var (result, body) = await WithTransientRetryAsync("GetChangeHistory",
                        () => steam3.GetChangeHistory(publishedFileId, startIndex, pageSize));
                    if (result != EResult.OK || body == null || body.changes.Count == 0)
                    {
                        break;
                    }

                    all.AddRange(body.changes);
                    startIndex += (uint)body.changes.Count;

                    if (all.Count >= body.total)
                    {
                        break;
                    }

                    await Task.Delay(WorkshopApiPacingDelay);
                }
            }
            catch
            {
                // Retries (see WithTransientRetryAsync) already exhausted - best-effort beyond
                // that, fall through with whatever was gathered before the failure.
            }

            return all;
        }

        /// <summary>
        /// Fetches an item's full history via GetChangeHistory and persists it directly via
        /// ReplaceHistory - the shared mechanism bootstrap and poll both use, whether this is an
        /// item's very first history fetch or a backfill of a previously "-shallow" one. Always a
        /// full overwrite, never a merge (GetChangeHistory has no "since" filter of its own, so
        /// every fetch returns the complete list anyway - see WorkshopCatalogItem's doc comment).
        /// Does nothing (returns false) when GetChangeHistory came back empty - a real item always
        /// has at least its own creation as one entry, so an empty result means the fetch failed
        /// (already retried internally) rather than "genuinely no history"; leaving the item's
        /// existing HistoryComplete/history untouched lets a later run retry instead of wrongly
        /// trusting a blank list as the truth.
        /// </summary>
        private static async Task<bool> FetchAndRecordHistoryAsync(WorkshopCatalogDb catalog, ulong publishedFileId)
        {
            var changes = await GetFullChangeHistoryAsync(publishedFileId);
            if (changes.Count == 0)
            {
                return false;
            }

            var entries = changes
                .OrderBy(c => c.timestamp)
                .Select(c => new WorkshopHistoryEntry
                {
                    Timestamp = c.timestamp,
                    ManifestId = c.manifest_id,
                    ChangeDescription = c.change_description,
                })
                .ToList();
            catalog.ReplaceHistory(publishedFileId, entries, complete: true);
            return true;
        }

        /// <summary>
        /// Sweeps up to <paramref name="batchSize"/> catalog items still marked
        /// HistoryComplete == false (from a prior "-shallow" bootstrap/poll pass, or an item that
        /// predates these fields entirely) and fetches their full history. Bounded per call - a
        /// large backlog (e.g. an entire workshop shallow-bootstrapped up front) is worked off
        /// gradually across repeated bootstrap/poll runs instead of turning the very next one into
        /// an unbounded multi-day sweep by accident. batchSize == 0 disables this entirely (a
        /// caller-facing "-backfill-batch 0", distinct from "-shallow" - the latter also skips
        /// fetching history for brand-new/changed items this run, this only skips the extra sweep
        /// over already-recorded incomplete ones).
        ///
        /// No periodic checkpoint logic here (unlike an earlier version of this function) - each
        /// FetchAndRecordHistoryAsync call already persists itself immediately via ReplaceHistory,
        /// so there's nothing left to buffer or throttle saving. A crash mid-sweep loses at most
        /// whichever single item's fetch was in flight, not a batch of already-fetched-but-unsaved
        /// ones.
        /// </summary>
        private static async Task BackfillIncompleteHistoryAsync(WorkshopCatalogDb catalog, uint batchSize)
        {
            if (batchSize == 0)
            {
                return;
            }

            var candidates = catalog.GetIncompleteHistoryIds((int)batchSize);
            if (candidates.Count == 0)
            {
                return;
            }

            Console.WriteLine($"Backfilling full history for {candidates.Count:N0} item(s) still marked incomplete...");

            var fetched = 0;
            foreach (var id in candidates)
            {
                if (await FetchAndRecordHistoryAsync(catalog, id))
                {
                    fetched++;
                }

                await Task.Delay(WorkshopApiPacingDelay);
            }

            var remaining = catalog.CountIncompleteHistory();
            Console.WriteLine(remaining > 0
                ? $"Backfill: {fetched:N0}/{candidates.Count:N0} succeeded this pass. {remaining:N0} item(s) still incomplete - will continue on future runs."
                : $"Backfill: {fetched:N0}/{candidates.Count:N0} succeeded this pass. No incomplete items remain.");
        }

        /// <summary>
        /// Archives one item, shared by both the catalog-driven and ad-hoc download entry points
        /// below. Without history: current version only, same as a normal "download -workshop
        /// -raw" per item. With history, for a ChunkBased item: walks GetChangeHistory and
        /// downloads EVERY historical manifest_id, not just current - Steam retains old depot
        /// chunk data by design, so this is genuinely retrievable (a 404 on a very old manifest's
        /// chunks is possible - see the CDN cold-storage note elsewhere in this codebase - but not
        /// expected to be the norm). With history, for an AncientUgc item: necessarily best-effort
        /// - a GetChangeHistory entry there is only ever a timestamp + content handle, never a
        /// URL, and Steam's GetDetails only ever exposes the CURRENT file_url, so an old ancient
        /// version can be discovered/logged (multiple entries) but not necessarily re-downloaded.
        /// Only the current version is actually fetched for those regardless of -history; a note
        /// is printed when an ancient item's history has more than one entry, since that's the
        /// case where something real is known to exist but isn't reachable through this API.
        ///
        /// Always a LIVE GetChangeHistory call when history is requested here - deliberately never
        /// trusts a catalog's cached History/HistoryComplete, even when it looks complete. This is
        /// the "-history" download path's own long-standing contract (get every version, right
        /// now), and a cached list could predate the current moment by as long as it's been since
        /// the last bootstrap/poll touched this item - reusing it here would risk silently missing
        /// a version Steam added since. The returned FetchedHistory is what THIS call just learned
        /// live, for a caller to persist back into the catalog if it wants to (a nice side benefit,
        /// not something this method relies on for correctness).
        /// </summary>
        private static async Task<(int Downloaded, int Failed, List<WorkshopHistoryEntry> FetchedHistory)> ArchiveWorkshopItemAsync(uint appId, ulong publishedFileId, string title, WorkshopItemKind kind, ulong currentManifestId, bool history, RawDownloadOptions options)
        {
            var downloaded = 0;
            var failed = 0;

            if (history && kind == WorkshopItemKind.ChunkBased)
            {
                var changes = await GetFullChangeHistoryAsync(publishedFileId);
                var fetchedHistory = ToHistoryEntries(changes);

                if (changes.Count == 0)
                {
                    Console.WriteLine($"  {publishedFileId} \"{SanitizeTitleForDisplay(title)}\": no change history available, falling back to current version");
                    changes = [new CPublishedFile_GetChangeHistory_Response.ChangeLog { manifest_id = currentManifestId }];
                }
                else
                {
                    Console.WriteLine($"  {publishedFileId} \"{SanitizeTitleForDisplay(title)}\": {changes.Count} historical version(s)");
                }

                foreach (var change in changes)
                {
                    try
                    {
                        await DownloadAppRawAsync(appId, [(appId, change.manifest_id)], DEFAULT_BRANCH, null, null, null, false, options, publishedFileId.ToString(), title);
                        downloaded++;
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        Console.WriteLine($"    ERROR downloading manifest {change.manifest_id} for {publishedFileId}: {ex.Message}");
                    }
                }

                return (downloaded, failed, fetchedHistory);
            }

            List<WorkshopHistoryEntry> fetchedAncientHistory = null;
            if (history && kind == WorkshopItemKind.AncientUgc)
            {
                var changes = await GetFullChangeHistoryAsync(publishedFileId);
                fetchedAncientHistory = ToHistoryEntries(changes);

                if (changes.Count > 1)
                {
                    Console.WriteLine($"  Note: {publishedFileId} \"{SanitizeTitleForDisplay(title)}\" has {changes.Count} historical versions, but only the current one is retrievable - Steam doesn't expose old direct-URL content through this API (see README).");
                }
            }

            try
            {
                // Current-only path - either kind, or -history's AncientUgc fallback.
                await DownloadPubfileRawAsync(publishedFileId, options);
                downloaded++;
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine($"    ERROR downloading {publishedFileId}: {ex.Message}");
            }

            return (downloaded, failed, fetchedAncientHistory);
        }

        /// <summary>Maps a raw GetChangeHistory page into catalog-storage form, oldest first. Null
        /// (not empty) when the fetch came back with nothing - see FetchAndRecordHistoryAsync for
        /// why that distinction matters (empty means "fetch failed," not "genuinely no history").</summary>
        private static List<WorkshopHistoryEntry> ToHistoryEntries(List<CPublishedFile_GetChangeHistory_Response.ChangeLog> changes)
        {
            if (changes == null || changes.Count == 0)
            {
                return null;
            }

            return changes
                .OrderBy(c => c.timestamp)
                .Select(c => new WorkshopHistoryEntry { Timestamp = c.timestamp, ManifestId = c.manifest_id, ChangeDescription = c.change_description })
                .ToList();
        }

        /// <summary>
        /// Inserts/updates one item's entry directly into its own app's catalog - what makes
        /// "workshop download -workshop &lt;id&gt;..." (ad-hoc, no prior bootstrap needed) still
        /// contribute to that app's tracked state, not just fetch content and forget it happened.
        /// <paramref name="history"/> is whatever ArchiveWorkshopItemAsync already fetched live for
        /// this same call (via its own -history handling) - reused here so an ad-hoc "-history"
        /// pull doesn't pay for a second GetChangeHistory round trip just to record what the first
        /// one already learned. Null/empty means this pass didn't fetch history, so the entry is
        /// recorded incomplete like any other freshly-seen item.
        /// </summary>
        private static void UpsertCatalogEntry(string outputRoot, PublishedFileDetails details, WorkshopItemKind kind, List<WorkshopHistoryEntry> history = null)
        {
            using var catalog = WorkshopCatalogDb.Open(outputRoot, details.consumer_appid);

            catalog.UpsertItem(new WorkshopCatalogItem
            {
                PublishedFileId = details.publishedfileid,
                Title = details.title,
                Kind = kind,
                FileUrl = kind == WorkshopItemKind.AncientUgc ? details.file_url : null,
                ManifestId = details.hcontent_file,
                TimeUpdated = details.time_updated,
                LastSeenAt = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                HistoryCount = history?.Count ?? 0,
                HistoryComplete = history is { Count: > 0 },
            });

            if (history is { Count: > 0 })
            {
                catalog.ReplaceHistory(details.publishedfileid, history, complete: true);
            }

            Console.WriteLine($"  Recorded {details.publishedfileid} into app {details.consumer_appid}'s catalog ({WorkshopCatalogDb.GetPath(outputRoot, details.consumer_appid)}).");
        }

        /// <summary>
        /// The bridge from "bootstrap/poll tracked what exists" to "actually archive the content" -
        /// this is the catalog-driven form: walks an app's existing catalog (optionally filtered
        /// to onlyIds) and archives each item. Requires "workshop bootstrap" to have already run
        /// for this app. See DownloadWorkshopItemsAdHocAsync for the other form (specific IDs,
        /// no prior bootstrap needed - what replaces the old workshop-related "download" options).
        /// </summary>
        public static async Task<int> DownloadWorkshopCatalogAsync(uint appId, string outputRoot, bool history, HashSet<ulong> onlyIds, bool manifestsOnly, uint maxItems)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalogDb.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' first.");
                return 1;
            }

            using var catalog = WorkshopCatalogDb.Open(outputRoot, appId);

            if (!catalog.BootstrapCompleted)
            {
                Console.WriteLine("Warning: bootstrap has not finished for this app - this only covers what's been recorded so far.");
            }

            var items = catalog.QueryList(onlyIds, null, null, false, false);

            var options = new RawDownloadOptions { OutputRoot = outputRoot, DryRun = manifestsOnly };
            var processed = 0;
            var downloaded = 0;
            var failed = 0;

            foreach (var item in items)
            {
                if (maxItems > 0 && processed >= maxItems)
                {
                    Console.WriteLine($"Reached -max-items {maxItems} - stopping (re-run to continue with the rest of the catalog).");
                    break;
                }
                processed++;

                var (d, f, fetchedHistory) = await ArchiveWorkshopItemAsync(appId, item.PublishedFileId, item.Title, item.Kind, item.ManifestId, history, options);
                downloaded += d;
                failed += f;

                if (fetchedHistory != null)
                {
                    catalog.ReplaceHistory(item.PublishedFileId, fetchedHistory, complete: true);
                }
            }

            var verb = manifestsOnly ? "Recorded manifests/metadata for" : "Downloaded";
            Console.WriteLine($"{verb} {downloaded:N0} item/version(s) across {processed:N0} catalog entries, {failed:N0} failed.");

            return failed > 0 ? 1 : 0;
        }

        /// <summary>
        /// The other form of "actually archive the content": specific workshop IDs, resolved and
        /// downloaded directly without requiring "workshop bootstrap" to have ever run for their
        /// app(s) first - what replaces "download -workshop"/"-pubfile"/"-ugc" (still handles a
        /// mixed list spanning different apps, same as those did). Each resolved item is also
        /// upserted into its own app's catalog as a side effect, so ad-hoc pulls still contribute
        /// to that app's tracked state rather than being invisible to a later "workshop poll".
        /// </summary>
        public static async Task<int> DownloadWorkshopItemsAdHocAsync(List<ulong> publishedFileIds, string outputRoot, bool history, bool manifestsOnly)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var options = new RawDownloadOptions { OutputRoot = outputRoot, DryRun = manifestsOnly };
            var downloaded = 0;
            var failed = 0;

            foreach (var id in publishedFileIds)
            {
                PublishedFileDetails details = null;
                try
                {
                    details = await steam3.GetPublishedFileDetails(id);
                }
                catch
                {
                    // Fall through to the legacy UGC-handle fallback below - matches
                    // DownloadWorkshopItemRawAsync's own resolution order exactly.
                }

                if (details == null)
                {
                    try
                    {
                        // No PublishedFileDetails means nothing to classify or record with - this
                        // id only resolves as a legacy UGC handle, so it can't be tied to a
                        // specific app's catalog the way every other path here can.
                        await DownloadUGCRawAsync(id, options);
                        downloaded++;
                        Console.WriteLine($"  {id}: resolved via legacy UGC lookup - not recorded in any catalog (no PublishedFileDetails available)");
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        Console.WriteLine($"    ERROR downloading {id}: {ex.Message}");
                    }

                    continue;
                }

                var kind = !string.IsNullOrEmpty(details.file_url) ? WorkshopItemKind.AncientUgc : WorkshopItemKind.ChunkBased;

                var (d, f, fetchedHistory) = await ArchiveWorkshopItemAsync(details.consumer_appid, id, details.title, kind, details.hcontent_file, history, options);
                downloaded += d;
                failed += f;

                UpsertCatalogEntry(outputRoot, details, kind, fetchedHistory);
            }

            var verb = manifestsOnly ? "Recorded manifests/metadata for" : "Downloaded";
            Console.WriteLine($"{verb} {downloaded:N0} item/version(s), {failed:N0} failed.");

            return failed > 0 ? 1 : 0;
        }

        #endregion
    }
}
