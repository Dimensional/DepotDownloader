// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

// "workshop bootstrap"/"poll": a two-phase automatic-update-tracking pipeline covering an app's
// entire workshop - both chunk-based items (depot ID == app ID) and ancient/direct-URL UGC items
// (see WorkshopItemKind in WorkshopCatalog.cs - see README). Bootstrap walks PublishedFile.
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

        public static async Task<int> BootstrapWorkshopCatalogAsync(uint appId, string outputRoot, uint pageSize, uint maxItems, uint queryType, bool manifestsOnly = false)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalog.GetPath(outputRoot, appId);
            Directory.CreateDirectory(Path.GetDirectoryName(catalogPath));

            var catalog = WorkshopCatalog.LoadOrCreate(catalogPath, appId);

            if (catalog.BootstrapCompleted)
            {
                Console.WriteLine($"Bootstrap already completed for app {appId} ({catalog.Items.Count:N0} items recorded).");
                Console.WriteLine($"Delete {catalogPath} to force a full re-bootstrap, or run 'workshop poll' to pick up changes since.");
                return 0;
            }

            catalog.QueryType = queryType;
            if (catalog.BootstrapStartedAt == 0)
            {
                catalog.BootstrapStartedAt = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }

            Console.WriteLine($"Bootstrapping workshop catalog for app {appId} (resuming at {catalog.Items.Count:N0} items already recorded)...");

            if (manifestsOnly)
            {
                // Each item costs its own manifest-request round trip (plus ArchiveDepotRawAsync's
                // existing 500ms-per-new-manifest throttle for chunk-based items) - fine for a
                // small/moderate workshop, but at depot 4000's ~2 million items that throttle alone
                // is well over a week sequential. Not something to let run unbounded by accident.
                Console.WriteLine("-manifests-only requested: every item in this walk will also have its manifest fetched/UGC metadata logged, not just recorded in the catalog. This is far slower than a catalog-only bootstrap - consider -max-items for a large workshop.");
            }

            var pagesSinceSave = 0;
            var safetyPageBudget = int.MaxValue;

            try
            {
                while (true)
                {
                    var (result, body) = await WithTransientRetryAsync("QueryFiles",
                        () => steam3.QueryFiles(appId, catalog.BootstrapCursor, pageSize, queryType));

                    if (result != EResult.OK || body == null)
                    {
                        Console.WriteLine($"QueryFiles failed: {result}. Progress saved - re-run the same command to resume.");
                        catalog.Save(catalogPath);
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

                        catalog.Items[d.publishedfileid] = new WorkshopCatalogItem
                        {
                            PublishedFileId = d.publishedfileid,
                            Title = d.title,
                            Kind = kind,
                            FileUrl = kind == WorkshopItemKind.AncientUgc ? d.file_url : null,
                            ManifestId = d.hcontent_file,
                            TimeUpdated = d.time_updated,
                            LastSeenAt = now,
                        };

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

                    Console.WriteLine($"  {catalog.Items.Count:N0} items recorded so far (of ~{body.total:N0} reported by Steam)...");

                    // Compare against the cursor we just queried WITH (not the previous
                    // request's) - this is what actually detects "the server stopped advancing".
                    var donePaging = string.IsNullOrEmpty(body.next_cursor)
                        || body.next_cursor == catalog.BootstrapCursor
                        || body.publishedfiledetails.Count == 0;

                    if (donePaging)
                    {
                        catalog.BootstrapCompleted = true;
                        catalog.BootstrapCompletedAt = now;
                        catalog.Save(catalogPath);
                        Console.WriteLine($"Bootstrap complete: {catalog.Items.Count:N0} items recorded for app {appId}.");
                        return 0;
                    }

                    catalog.BootstrapCursor = body.next_cursor;

                    if (maxItems > 0 && catalog.Items.Count >= maxItems)
                    {
                        catalog.Save(catalogPath);
                        Console.WriteLine($"Reached -max-items {maxItems} - stopping early (bootstrap NOT marked complete; re-run without -max-items to continue).");
                        return 0;
                    }

                    // Every 5 pages (not 20) - a real multi-hour run losing more than ~500 items'
                    // worth of already-fetched-but-unsaved progress to an interruption is a real
                    // cost at this data's scale; the write itself is cheap (small protobuf+deflate
                    // file).
                    if (++pagesSinceSave >= 5)
                    {
                        catalog.Save(catalogPath);
                        pagesSinceSave = 0;
                    }

                    if (--safetyPageBudget <= 0)
                    {
                        catalog.Save(catalogPath);
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
                catalog.Save(catalogPath);
                Console.WriteLine($"Progress saved ({catalog.Items.Count:N0} items) - re-run the same command to resume.");
                return 1;
            }
        }

        public static async Task<int> PollWorkshopCatalogAsync(uint appId, string outputRoot, bool dryRun, bool manifestsOnly = false)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalog.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' first.");
                return 1;
            }

            var catalog = WorkshopCatalog.LoadOrCreate(catalogPath, appId);

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
                catalog.Save(catalogPath);
                Console.WriteLine("Result: Ignored - the watermark is older than GetItemChanges will currently honor (empirically somewhere between 96h and 7 days on a high-churn app - see README).");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' again to catch up (it resumes/refreshes the existing catalog) - this also resets the watermark.");
                return 2;
            }

            if (result != EResult.OK || body == null)
            {
                catalog.Save(catalogPath);
                Console.WriteLine($"GetItemChanges failed: {result}");
                return 1;
            }

            Console.WriteLine($"{body.workshop_items.Count:N0} item(s) reported changed.");

            var downloaded = 0;
            var failed = 0;

            foreach (var change in body.workshop_items)
            {
                catalog.Items.TryGetValue(change.published_file_id, out var existing);
                var isNew = existing == null;
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

                catalog.Items[change.published_file_id] = new WorkshopCatalogItem
                {
                    PublishedFileId = change.published_file_id,
                    Title = title,
                    Kind = kind,
                    FileUrl = fileUrl,
                    ManifestId = change.manifest_id,
                    TimeUpdated = change.time_updated,
                    LastSeenAt = catalog.LastPolledAt,
                };

                if (skip)
                {
                    // Steam counted it as "changed" (could be a metadata-only edit) but the
                    // manifest we'd archive by didn't move - nothing new to download.
                    continue;
                }

                Console.WriteLine($"  {(isNew ? "NEW" : "CHANGED")} {change.published_file_id} \"{title}\" [{kind}]");

                if (dryRun)
                {
                    continue;
                }

                try
                {
                    // Deliberately the same per-item entry point "download -workshop -raw" uses,
                    // not a hand-rolled DownloadAppRawAsync call - it does its own file_url/
                    // hcontent_file dispatch internally, so both ChunkBased and AncientUgc items
                    // land correctly without duplicating that logic here. Reuse freshDetails when
                    // the reclassification step above already fetched it, rather than fetching the
                    // same PublishedFileDetails twice. manifestsOnly maps to RawDownloadOptions.
                    // DryRun - manifest-only for ChunkBased, metadata-logged-not-fetched for
                    // AncientUgc (see DownloadWebFileToUGCAsync).
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

            // Advance only to what GetItemChanges itself reported, never to "now" - so a poll can
            // never silently skip a window it didn't actually ask Steam about.
            catalog.LastWatermark = body.update_time;
            catalog.Save(catalogPath);

            var verb = manifestsOnly ? "Recorded manifests/metadata for" : "Downloaded";
            Console.WriteLine(dryRun
                ? $"Dry run: {body.workshop_items.Count:N0} item(s) would be checked/downloaded - nothing was actually fetched."
                : $"{verb} {downloaded:N0} item(s), {failed:N0} failed. Watermark advanced to {catalog.LastWatermark} ({DateTimeOffset.FromUnixTimeSeconds(catalog.LastWatermark):u}).");

            return failed > 0 ? 1 : 0;
        }

        public static int PrintWorkshopCatalogStatus(uint appId, string outputRoot)
        {
            outputRoot = ResolveOutputRoot(outputRoot);
            var catalogPath = WorkshopCatalog.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                return 1;
            }

            var catalog = WorkshopCatalog.LoadOrCreate(catalogPath, appId);

            var chunkBased = 0;
            var ancientUgc = 0;
            var unknownKind = 0;
            foreach (var item in catalog.Items.Values)
            {
                switch (item.Kind)
                {
                    case WorkshopItemKind.ChunkBased: chunkBased++; break;
                    case WorkshopItemKind.AncientUgc: ancientUgc++; break;
                    default: unknownKind++; break;
                }
            }

            Console.WriteLine($"App:                {catalog.AppId}");
            Console.WriteLine($"Catalog path:       {catalogPath}");
            Console.WriteLine($"Items recorded:     {catalog.Items.Count:N0}  (chunk-based: {chunkBased:N0}, ancient UGC: {ancientUgc:N0}, unclassified: {unknownKind:N0})");
            Console.WriteLine($"Bootstrap complete: {catalog.BootstrapCompleted}");

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
        /// </summary>
        private static async Task<(int Downloaded, int Failed)> ArchiveWorkshopItemAsync(uint appId, ulong publishedFileId, string title, WorkshopItemKind kind, ulong currentManifestId, bool history, RawDownloadOptions options)
        {
            var downloaded = 0;
            var failed = 0;

            if (history && kind == WorkshopItemKind.ChunkBased)
            {
                var changes = await GetFullChangeHistoryAsync(publishedFileId);
                if (changes.Count == 0)
                {
                    Console.WriteLine($"  {publishedFileId} \"{title}\": no change history available, falling back to current version");
                    changes = [new CPublishedFile_GetChangeHistory_Response.ChangeLog { manifest_id = currentManifestId }];
                }
                else
                {
                    Console.WriteLine($"  {publishedFileId} \"{title}\": {changes.Count} historical version(s)");
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

                return (downloaded, failed);
            }

            if (history && kind == WorkshopItemKind.AncientUgc)
            {
                var changes = await GetFullChangeHistoryAsync(publishedFileId);
                if (changes.Count > 1)
                {
                    Console.WriteLine($"  Note: {publishedFileId} \"{title}\" has {changes.Count} historical versions, but only the current one is retrievable - Steam doesn't expose old direct-URL content through this API (see README).");
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

            return (downloaded, failed);
        }

        /// <summary>
        /// Inserts/updates one item's entry directly into its own app's catalog - what makes
        /// "workshop download -workshop &lt;id&gt;..." (ad-hoc, no prior bootstrap needed) still
        /// contribute to that app's tracked state, not just fetch content and forget it happened.
        /// </summary>
        private static void UpsertCatalogEntry(string outputRoot, PublishedFileDetails details, WorkshopItemKind kind)
        {
            var catalogPath = WorkshopCatalog.GetPath(outputRoot, details.consumer_appid);
            Directory.CreateDirectory(Path.GetDirectoryName(catalogPath));
            var catalog = WorkshopCatalog.LoadOrCreate(catalogPath, details.consumer_appid);

            catalog.Items[details.publishedfileid] = new WorkshopCatalogItem
            {
                PublishedFileId = details.publishedfileid,
                Title = details.title,
                Kind = kind,
                FileUrl = kind == WorkshopItemKind.AncientUgc ? details.file_url : null,
                ManifestId = details.hcontent_file,
                TimeUpdated = details.time_updated,
                LastSeenAt = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };

            catalog.Save(catalogPath);
            Console.WriteLine($"  Recorded {details.publishedfileid} into app {details.consumer_appid}'s catalog ({catalogPath}).");
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
            var catalogPath = WorkshopCatalog.GetPath(outputRoot, appId);

            if (!File.Exists(catalogPath))
            {
                Console.WriteLine($"No catalog found for app {appId} at {catalogPath}.");
                Console.WriteLine($"Run 'workshop bootstrap -app {appId}' first.");
                return 1;
            }

            var catalog = WorkshopCatalog.LoadOrCreate(catalogPath, appId);

            if (!catalog.BootstrapCompleted)
            {
                Console.WriteLine("Warning: bootstrap has not finished for this app - this only covers what's been recorded so far.");
            }

            var items = catalog.Items.Values.OrderBy(i => i.PublishedFileId).AsEnumerable();
            if (onlyIds != null && onlyIds.Count > 0)
            {
                items = items.Where(i => onlyIds.Contains(i.PublishedFileId));
            }

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

                var (d, f) = await ArchiveWorkshopItemAsync(appId, item.PublishedFileId, item.Title, item.Kind, item.ManifestId, history, options);
                downloaded += d;
                failed += f;
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

                var (d, f) = await ArchiveWorkshopItemAsync(details.consumer_appid, id, details.title, kind, details.hcontent_file, history, options);
                downloaded += d;
                failed += f;

                UpsertCatalogEntry(outputRoot, details, kind);
            }

            var verb = manifestsOnly ? "Recorded manifests/metadata for" : "Downloaded";
            Console.WriteLine($"{verb} {downloaded:N0} item/version(s), {failed:N0} failed.");

            return failed > 0 ? 1 : 0;
        }

        #endregion
    }
}
