// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DepotDownloader
{
    /// <summary>
    /// "workshop bootstrap"/"poll"/"download"/"status" - the single place all workshop
    /// acquisition AND recording happens (this is where the old workshop-related "download"
    /// flags moved to). Covers both chunk-based items (depot ID == app ID) and
    /// ancient/direct-URL UGC items (see WorkshopItemKind) - built on SteamKit2's PublishedFile.
    /// QueryFiles/GetItemChanges/GetChangeHistory unified-messages RPCs. See
    /// ContentDownloader.WorkshopTracker.cs for the actual bootstrap/poll/download logic and
    /// WorkshopCatalog.cs for the persisted state, and the README for the empirically-confirmed
    /// access/timing restrictions this depends on.
    /// </summary>
    static class WorkshopCommand
    {
        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            var operation = args[0].ToLowerInvariant();
            var rest = args[1..];

            switch (operation)
            {
                case "bootstrap":
                    return await BootstrapAsync(rest);

                case "poll":
                    return await PollAsync(rest);

                case "download":
                    return await DownloadAsync(rest);

                case "status":
                    return StatusAsync(rest);

                default:
                    Console.WriteLine($"Unknown workshop operation: {operation}");
                    PrintUsage();
                    return 1;
            }
        }

        private static async Task<int> BootstrapAsync(string[] args)
        {
            var parser = new ArgParser(args);

            var appId = parser.GetNullable<uint>("-app", "-appid");
            var pageSize = parser.Get<uint>(100, "-page-size");
            var maxItems = parser.Get<uint>(0, "-max-items");
            var queryType = parser.Get<uint>(1, "-query-type"); // k_PublishedFileQueryType_RankedByPublicationDate - see BootstrapWorkshopCatalogAsync
            var manifestsOnly = parser.HasFlag("-manifests-only", "-raw-dry-run");
            var shallow = parser.HasFlag("-shallow");
            var backfillBatch = parser.Get<uint>(200, "-backfill-batch");
            var resetCursor = parser.HasFlag("-reset-cursor");
            var output = parser.Get<string>(null, "-output", "-dir");
            var username = parser.Get<string>(null, "-username", "-user");
            var password = parser.Get<string>(null, "-password", "-pass");
            var rememberPassword = parser.HasFlag("-remember-password");
            parser.WarnUnconsumed();

            if (appId == null)
            {
                Console.WriteLine("Usage: depotdownloader workshop bootstrap -app <appid> [-page-size 100] [-max-items N] [-manifests-only] [-shallow] [-backfill-batch 200] [-reset-cursor] [-output <dir>] [-username <user> [-remember-password]]");
                return 1;
            }

            if (!LogOn(username, password, rememberPassword))
            {
                return 1;
            }

            try
            {
                return await ContentDownloader.BootstrapWorkshopCatalogAsync(appId.Value, output, pageSize, maxItems, queryType, manifestsOnly, shallow, backfillBatch, resetCursor);
            }
            finally
            {
                LogOff(rememberPassword);
            }
        }

        private static async Task<int> PollAsync(string[] args)
        {
            var parser = new ArgParser(args);

            var appId = parser.GetNullable<uint>("-app", "-appid");
            var output = parser.Get<string>(null, "-output", "-dir");
            var dryRun = parser.HasFlag("-dry-run");
            var manifestsOnly = parser.HasFlag("-manifests-only", "-raw-dry-run");
            var catalogOnly = parser.HasFlag("-catalog-only");
            var shallow = parser.HasFlag("-shallow");
            var backfillBatch = parser.Get<uint>(200, "-backfill-batch");
            var username = parser.Get<string>(null, "-username", "-user");
            var password = parser.Get<string>(null, "-password", "-pass");
            var rememberPassword = parser.HasFlag("-remember-password");
            parser.WarnUnconsumed();

            if (appId == null)
            {
                Console.WriteLine("Usage: depotdownloader workshop poll -app <appid> [-dry-run | -manifests-only | -catalog-only] [-shallow] [-backfill-batch 200] [-output <dir>] [-username <user> [-remember-password]]");
                return 1;
            }

            if (username == null)
            {
                Console.WriteLine("Note: GetItemChanges is confirmed to reject anonymous logins (EResult.AccessDenied). Proceeding anonymously anyway, but expect it to fail without -username.");
            }

            if (!LogOn(username, password, rememberPassword))
            {
                return 1;
            }

            try
            {
                return await ContentDownloader.PollWorkshopCatalogAsync(appId.Value, output, dryRun, manifestsOnly, shallow, backfillBatch, catalogOnly);
            }
            finally
            {
                LogOff(rememberPassword);
            }
        }

        private static async Task<int> DownloadAsync(string[] args)
        {
            var parser = new ArgParser(args);

            // Every valued flag resolved before anything else - GetList below would otherwise
            // risk swallowing an unrelated later flag's own token (see ArgParser's Positional/
            // GetList caveats documented on the class itself).
            var appId = parser.GetNullable<uint>("-app", "-appid");
            var workshopIds = parser.GetList<ulong>("-workshop");
            var history = parser.HasFlag("-history");
            var manifestsOnly = parser.HasFlag("-manifests-only", "-raw-dry-run");
            var maxItems = parser.Get<uint>(0, "-max-items");
            var onlyRaw = parser.Get<string>(null, "-only");
            var output = parser.Get<string>(null, "-output", "-dir");
            var username = parser.Get<string>(null, "-username", "-user");
            var password = parser.Get<string>(null, "-password", "-pass");
            var rememberPassword = parser.HasFlag("-remember-password");
            parser.WarnUnconsumed();

            var hasAdHocIds = workshopIds.Count > 0;

            if (appId == null && !hasAdHocIds)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("  depotdownloader workshop download -app <appid> [-history] [-only <id,id2,...>] [-max-items N] [-manifests-only] [OPTIONS...]");
                Console.WriteLine("  depotdownloader workshop download -workshop <id> [<id>...] [-history] [-manifests-only] [OPTIONS...]");
                Console.WriteLine("(No CSV input - a list of bare IDs has no tracking data. Run 'workshop bootstrap' to build a real catalog instead, then 'workshop download -app <appid>'.)");
                return 1;
            }

            if (appId != null && hasAdHocIds)
            {
                Console.WriteLine("Error: -app (catalog-driven) and -workshop (ad-hoc) are mutually exclusive - use one or the other.");
                return 1;
            }

            if (!LogOn(username, password, rememberPassword))
            {
                return 1;
            }

            try
            {
                if (hasAdHocIds)
                {
                    return await ContentDownloader.DownloadWorkshopItemsAdHocAsync(workshopIds, output, history, manifestsOnly);
                }

                HashSet<ulong> onlyIds = null;
                if (!string.IsNullOrWhiteSpace(onlyRaw))
                {
                    onlyIds = [];
                    foreach (var part in onlyRaw.Split(','))
                    {
                        if (ulong.TryParse(part.Trim(), out var id))
                        {
                            onlyIds.Add(id);
                        }
                    }
                }

                return await ContentDownloader.DownloadWorkshopCatalogAsync(appId.Value, output, history, onlyIds, manifestsOnly, maxItems);
            }
            finally
            {
                LogOff(rememberPassword);
            }
        }

        private static int StatusAsync(string[] args)
        {
            var parser = new ArgParser(args);

            var appId = parser.GetNullable<uint>("-app", "-appid");
            var output = parser.Get<string>(null, "-output", "-dir");
            var list = parser.HasFlag("-list");
            var kindRaw = parser.Get<string>(null, "-kind");
            var onlyRaw = parser.Get<string>(null, "-only");
            var nameRaw = parser.Get<string>(null, "-name");
            var limit = parser.Get<uint>(200, "-limit");
            parser.WarnUnconsumed();

            if (appId == null)
            {
                Console.WriteLine("Usage: depotdownloader workshop status -app <appid> [-output <dir>]");
                Console.WriteLine("       depotdownloader workshop status -app <appid> -list [-kind chunk|ancient|unknown] [-only <id,id2,...>] [-name <pattern>] [-limit N]");
                return 1;
            }

            var statusResult = ContentDownloader.PrintWorkshopCatalogStatus(appId.Value, output);
            if (!list || statusResult != 0)
            {
                return statusResult;
            }

            WorkshopItemKind? kindFilter = null;
            if (!string.IsNullOrWhiteSpace(kindRaw))
            {
                switch (kindRaw.Trim().ToLowerInvariant())
                {
                    case "chunk" or "chunkbased" or "chunk-based": kindFilter = WorkshopItemKind.ChunkBased; break;
                    case "ancient" or "ancientugc" or "ancient-ugc" or "ugc": kindFilter = WorkshopItemKind.AncientUgc; break;
                    case "unknown" or "unclassified": kindFilter = WorkshopItemKind.Unknown; break;
                    default:
                        Console.WriteLine($"Error: unrecognized -kind '{kindRaw}' - expected chunk, ancient, or unknown.");
                        return 1;
                }
            }

            HashSet<ulong> onlyIds = null;
            if (!string.IsNullOrWhiteSpace(onlyRaw))
            {
                onlyIds = [];
                foreach (var part in onlyRaw.Split(','))
                {
                    if (ulong.TryParse(part.Trim(), out var id))
                    {
                        onlyIds.Add(id);
                    }
                }
            }

            Regex nameFilter = null;
            if (!string.IsNullOrWhiteSpace(nameRaw))
            {
                try
                {
                    // Plain text works as an ordinary case-insensitive substring search (IsMatch,
                    // not a full-string match), and it's real regex - "Mario|Samus|Metroid" finds
                    // any of several names in one pass without needing a separate multi-term flag.
                    nameFilter = new Regex(nameRaw, RegexOptions.IgnoreCase);
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Error: invalid -name pattern '{nameRaw}': {ex.Message}");
                    return 1;
                }
            }

            Console.WriteLine();
            return ContentDownloader.PrintWorkshopCatalogList(appId.Value, output, onlyIds, kindFilter, nameFilter, limit);
        }

        private static bool LogOn(string username, string password, bool rememberPassword)
        {
            AccountSettingsStore.LoadFromFile("account.config");
            ContentDownloader.Config.RememberPassword = rememberPassword;

            if (username != null && password == null && (!rememberPassword || !AccountSettingsStore.Instance.LoginTokens.ContainsKey(username)))
            {
                Console.Write($"Enter account password for \"{username}\": ");
                password = Util.ReadPassword();
                Console.WriteLine();
            }

            if (!ContentDownloader.InitializeSteam3(username, password))
            {
                Console.WriteLine("Failed to log on to Steam3.");
                return false;
            }

            return true;
        }

        private static void LogOff(bool rememberPassword)
        {
            if (rememberPassword)
            {
                AccountSettingsStore.Save();
            }

            ContentDownloader.ShutdownSteam3();
        }

        public static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Workshop acquisition and tracking, in one place - both chunk-based items (depot ID ==");
            Console.WriteLine("app ID) and ancient/direct-URL UGC items. Replaces the old workshop-related \"download\"");
            Console.WriteLine("options (moved here as \"workshop download\"). No bare-ID-list input beyond a short");
            Console.WriteLine("ad-hoc \"-workshop\" list, though - it carries no tracking data, so use the catalog");
            Console.WriteLine("instead (\"bootstrap\" then \"download -app\") for anything larger.");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader workshop bootstrap -app <appid> [OPTIONS...]");
            Console.WriteLine("  depotdownloader workshop poll -app <appid> [OPTIONS...]");
            Console.WriteLine("  depotdownloader workshop download -app <appid> [OPTIONS...]");
            Console.WriteLine("  depotdownloader workshop download -workshop <id> [<id>...] [OPTIONS...]");
            Console.WriteLine("  depotdownloader workshop status -app <appid> [-output <dir>] [-list [OPTIONS...]]");
            Console.WriteLine();
            Console.WriteLine("BOOTSTRAP - one-time (per app), walks the entire workshop via QueryFiles to record");
            Console.WriteLine("            every item's current state (classifying each one chunk-based vs. ancient");
            Console.WriteLine("            UGC as it goes). CATALOG-ONLY by default - it records metadata, it does");
            Console.WriteLine("            not download any manifest/chunk/UGC content; that's \"download\", below.");
            Console.WriteLine("            Expensive for a large workshop (millions of items for a popular app) but");
            Console.WriteLine("            resumable if interrupted - re-run the same command to continue. Anonymous.");
            Console.WriteLine("  -page-size <n>     Items per QueryFiles page (default 100)");
            Console.WriteLine("  -max-items <n>     Stop after at least this many items (testing; leaves bootstrap");
            Console.WriteLine("                     unmarked-complete so a later run continues normally)");
            Console.WriteLine("  -query-type <n>    EPublishedFileQueryType (default 1 = RankedByPublicationDate - a");
            Console.WriteLine("                     stable ranking under concurrent workshop activity, since an");
            Console.WriteLine("                     item's creation time never changes; confirmed empirically that");
            Console.WriteLine("                     value 21 = RankedByLastUpdatedDate is NOT stable this way and");
            Console.WriteLine("                     is no longer the default - see README)");
            Console.WriteLine("  -manifests-only    Also fetch every item's manifest (chunk-based) or log its");
            Console.WriteLine("                     metadata without fetching content (ancient UGC) during this");
            Console.WriteLine("                     walk, not just record it in the catalog. MUCH slower - each");
            Console.WriteLine("                     new manifest costs its own request plus a 500ms throttle, so");
            Console.WriteLine("                     a workshop the size of depot 4000's (~2M items) would take");
            Console.WriteLine("                     well over a week. Pair with -max-items unless the workshop is");
            Console.WriteLine("                     small, or just use \"download\" for what's actually changed.");
            Console.WriteLine("  -shallow           Skip fetching each item's full GetChangeHistory during this");
            Console.WriteLine("                     walk (the default is to fetch it, so an item that updated more");
            Console.WriteLine("                     than once between checks doesn't silently lose the versions in");
            Console.WriteLine("                     between). Items are marked history-incomplete and backfilled");
            Console.WriteLine("                     gradually by later runs instead (see -backfill-batch). Full");
            Console.WriteLine("                     history costs a whole extra round-trip PER ITEM, not per page -");
            Console.WriteLine("                     worth using for a huge workshop's very first bootstrap.");
            Console.WriteLine("  -backfill-batch <n> Items to backfill full history for per run when this catalog");
            Console.WriteLine("                     already has some marked incomplete (default 200; 0 disables the");
            Console.WriteLine("                     sweep). Bounded so a large backlog is worked off gradually");
            Console.WriteLine("                     across runs, not all in one - runs even after bootstrap has");
            Console.WriteLine("                     already completed, so re-running it later still makes progress.");
            Console.WriteLine("  -reset-cursor      Recovery only - not needed for a normal resume. If the saved");
            Console.WriteLine("                     BootstrapCursor is ever confirmed to have stopped working");
            Console.WriteLine("                     (unconfirmed whether/when this can happen - see README), this");
            Console.WriteLine("                     resets it to start a fresh query, bounded by the lowest");
            Console.WriteLine("                     time_created already recorded so it re-enters near where the");
            Console.WriteLine("                     old cursor left off instead of from the newest item. Every");
            Console.WriteLine("                     already-recorded item is kept either way.");
            Console.WriteLine();
            Console.WriteLine("DOWNLOAD - the actual content-acquisition step, in two forms:");
            Console.WriteLine("  -app <appid>       Catalog-driven: walk an app's existing catalog (from bootstrap/");
            Console.WriteLine("                     poll) and archive its items. Requires \"bootstrap\" to have run.");
            Console.WriteLine("    -only <id,id2,...>  Restrict to specific catalog IDs instead of the whole thing");
            Console.WriteLine("    -max-items <n>       Stop after this many catalog entries (resumable - re-run)");
            Console.WriteLine("  -workshop <id> [<id>...]   Ad-hoc: specific IDs, resolved and downloaded directly -");
            Console.WriteLine("                             no prior bootstrap needed. A mixed list can span apps.");
            Console.WriteLine("                             Also records what it downloads into that item's own");
            Console.WriteLine("                             app's catalog as a side effect - a one-off ad-hoc pull");
            Console.WriteLine("                             still contributes to that app's tracked state, so a");
            Console.WriteLine("                             later \"poll\" isn't starting blind. For anything beyond");
            Console.WriteLine("                             a handful of IDs, prefer \"bootstrap\" + \"-app\" instead -");
            Console.WriteLine("                             a bare ID list carries no tracking data.");
            Console.WriteLine("  -history           Download EVERY historical version via GetChangeHistory, not just");
            Console.WriteLine("                     current - for chunk-based items only; Steam retains old depot");
            Console.WriteLine("                     chunk data by design. For ancient UGC, history is discoverable");
            Console.WriteLine("                     (multiple entries logged) but not necessarily re-downloadable -");
            Console.WriteLine("                     Steam only ever exposes the CURRENT direct-URL content.");
            Console.WriteLine("  -manifests-only    Manifest-only for chunk-based items (no chunk data), metadata-");
            Console.WriteLine("                     only for ancient UGC (no file content) - does real work and");
            Console.WriteLine("                     updates records, just skips the large/expensive payload");
            Console.WriteLine();
            Console.WriteLine("POLL - cheap and repeatable, whether run by hand as a one-off \"checkup\" or from a");
            Console.WriteLine("       scheduled task/cron - the same command serves both. Asks GetItemChanges for");
            Console.WriteLine("       everything changed since the catalog's watermark, and archives just those");
            Console.WriteLine("       items the same way \"download -app\" would, so both chunk-based and ancient-");
            Console.WriteLine("       UGC items land correctly without re-implementing that dispatch here.");
            Console.WriteLine("       REQUIRES an authenticated login - anonymous is confirmed to be rejected.");
            Console.WriteLine("       last_time_updated can't be arbitrarily old either - confirmed working 96h");
            Console.WriteLine("       back, confirmed rejected (EResult.Ignored) 7 days back on a high-churn app;");
            Console.WriteLine("       poll at least every couple of days. A rejected poll prints instructions to");
            Console.WriteLine("       re-run bootstrap rather than treating it as a fatal error.");
            Console.WriteLine("       Full history is fetched by default for every changed item, same reasoning as");
            Console.WriteLine("       bootstrap's own -shallow above - GetItemChanges only ever says \"this changed");
            Console.WriteLine("       since X,\" never how many times, so without it an item updated twice between");
            Console.WriteLine("       two polls would silently lose the version in between. Cheap here since poll's");
            Console.WriteLine("       delta set is normally a tiny fraction of the whole catalog.");
            Console.WriteLine("  -dry-run           Report what would be checked/downloaded - fetches and changes");
            Console.WriteLine("                     nothing: no catalog update, no watermark advance, no backfill");
            Console.WriteLine("                     sweep. Safe to run repeatedly before a real poll.");
            Console.WriteLine("  -catalog-only      Update the catalog (and, unless -shallow, full history) for");
            Console.WriteLine("                     every changed item exactly as a real poll would, but never call");
            Console.WriteLine("                     the archive step - no manifest fetch, no content/chunk download.");
            Console.WriteLine("                     The poll equivalent of bootstrap's own plain (no-flags) default.");
            Console.WriteLine("  -manifests-only    Same meaning as on \"download\" above");
            Console.WriteLine("  -shallow           Same meaning as on \"bootstrap\" above - also skips this poll's");
            Console.WriteLine("                     -backfill-batch sweep of any items still marked incomplete");
            Console.WriteLine("  -backfill-batch <n> Same meaning as on \"bootstrap\" above - runs after this poll's");
            Console.WriteLine("                     own delta, so a poll schedule doubles as steady backfill progress");
            Console.WriteLine();
            Console.WriteLine("STATUS - summary counts by default. Add -list for the actual per-item view (there is");
            Console.WriteLine("         no other way to inspect a catalog - workshop_catalog.bin is protobuf/Deflate,");
            Console.WriteLine("         not a text format meant to be opened directly). Sorted by ID for stable,");
            Console.WriteLine("         diffable output across runs.");
            Console.WriteLine("  -list              Print each matching item: ID, kind, manifest ID, last update/seen");
            Console.WriteLine("                     time, history entry count + complete/partial, title");
            Console.WriteLine("    -kind <k>            Filter: chunk, ancient, or unknown");
            Console.WriteLine("    -only <id,id2,...>   Filter to specific IDs");
            Console.WriteLine("    -name <pattern>      Filter by title - a case-insensitive regex (.NET syntax),");
            Console.WriteLine("                         so plain text matches as a substring and \"Mario|Samus|");
            Console.WriteLine("                         Metroid\" matches any of several names in one pass");
            Console.WriteLine("    -limit <n>           Cap rows printed (default 200; 0 = no limit)");
            Console.WriteLine();
            Console.WriteLine("COMMON OPTIONS:");
            Console.WriteLine("  -output <dir>      Root output directory (default: current directory, same as");
            Console.WriteLine("                     \"download -raw\" - catalog and manifests land under depot/<appid>/)");
            Console.WriteLine("  -username <user>   Steam account (bootstrap/ad-hoc download can run anonymously;");
            Console.WriteLine("                     poll cannot - see above)");
            Console.WriteLine("  -remember-password Save a login token for reuse on the next run");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine("  depotdownloader workshop bootstrap -app 4000");
            Console.WriteLine("  depotdownloader workshop download -app 4000                      # current version of everything tracked");
            Console.WriteLine("  depotdownloader workshop download -app 4000 -history -only 2956730580");
            Console.WriteLine("  depotdownloader workshop download -workshop 123456 789012        # ad-hoc, no bootstrap needed");
            Console.WriteLine("  depotdownloader workshop poll -app 4000 -username myaccount -remember-password");
            Console.WriteLine("  depotdownloader workshop status -app 4000");
            Console.WriteLine("  depotdownloader workshop status -app 4000 -list -kind ancient -limit 50");
            Console.WriteLine("  depotdownloader workshop status -app 4000 -list -name \"Mario|Samus|Metroid\"");
        }
    }
}
