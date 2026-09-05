// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    /// <summary>
    /// Download command handler for all download-related operations
    /// </summary>
    public static class DownloadCommand
    {
        enum OperationMode
        {
            Invalid,
            App,
            ManifestCsv,
        }

        /// <summary>
        /// Run download command with new sub-command syntax
        /// </summary>
        public static async Task<int> RunAsync(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            return await RunDownloadLogic(args);
        }

        /// <summary>
        /// Run download with legacy syntax (for backward compatibility)
        /// </summary>
        public static async Task<int> RunLegacyAsync(string[] args)
        {
            return await RunDownloadLogic(args);
        }

        private static async Task<int> RunDownloadLogic(string[] args)
        {
            AccountSettingsStore.LoadFromFile("account.config");

            var parser = new ArgParser(args);

            if (parser.HasFlag("-debug"))
            {
                DebugLog.Enabled = true;
                DebugLog.AddListener((category, message) =>
                {
                    Console.WriteLine("[{0}] {1}", category, message);
                });

                var httpEventListener = new HttpDiagnosticEventListener();
            }

            var username = parser.Get<string>(null, "-username", "-user");
            var password = parser.Get<string>(null, "-password", "-pass");
            ContentDownloader.Config.RememberPassword = parser.HasFlag("-remember-password");
            ContentDownloader.Config.UseQrCode = parser.HasFlag("-qr");
            ContentDownloader.Config.SkipAppConfirmation = parser.HasFlag("-no-mobile");

            if (username == null)
            {
                if (ContentDownloader.Config.RememberPassword && !ContentDownloader.Config.UseQrCode)
                {
                    Console.WriteLine("Error: -remember-password can not be used without -username or -qr.");
                    return 1;
                }
            }
            else if (ContentDownloader.Config.UseQrCode)
            {
                Console.WriteLine("Error: -qr can not be used with -username.");
                return 1;
            }

            ContentDownloader.Config.DownloadManifestOnly = parser.HasFlag("-manifest-only");

            var cellId = parser.Get(-1, "-cellid");
            if (cellId == -1)
            {
                cellId = 0;
            }

            ContentDownloader.Config.CellID = cellId;

            var fileList = parser.Get<string>(null, "-filelist");

            if (fileList != null)
            {
                if (Util.TryParseFileList(fileList, out var literals, out var regexes, out var filelistError))
                {
                    ContentDownloader.Config.UsingFileList = true;
                    ContentDownloader.Config.FilesToDownload = literals;
                    ContentDownloader.Config.FilesToDownloadRegex = regexes;
                    Console.WriteLine("Using filelist: '{0}'.", fileList);
                }
                else
                {
                    Console.WriteLine("Warning: Unable to load filelist: {0}", filelistError);
                }
            }

            ContentDownloader.Config.InstallDirectory = parser.Get<string>(null, "-dir");

            ContentDownloader.Config.VerifyAll = parser.HasFlag("-verify-all", "-verify_all", "-validate");
            ContentDownloader.Config.ValidateDownloadedChunks = parser.HasFlag("-validate-chunks", "-validate-downloaded-chunks");

            ContentDownloader.Config.MaxDownloads = parser.Get(8, "-max-downloads");

            if (parser.HasFlag("-use-lancache"))
            {
                await SteamKit2.CDN.Client.DetectLancacheServerAsync();
                if (SteamKit2.CDN.Client.UseLancacheServer)
                {
                    Console.WriteLine("Detected Lancache server! Downloads will be directed through the Lancache.");

                    // Increasing the number of concurrent downloads when the cache is detected since the downloads will likely
                    // be served much faster than over the internet.  Steam internally has this behavior as well.
                    if (!parser.HasFlag("-max-downloads"))
                    {
                        ContentDownloader.Config.MaxDownloads = 25;
                    }
                }
            }

            ContentDownloader.Config.LoginID = parser.HasFlag("-loginid") ? parser.Get<uint>(0, "-loginid") : null;

            // Raw archive options
            var rawMode = parser.HasFlag("-raw");
            var rawDebugJson = parser.HasFlag("-raw-debug-json", "-emit-debug-manifest-json");
            var rawOutput = parser.Get<string>(null, "-raw-output");
            var rawRespectFileFilters = parser.HasFlag("-raw-respect-filelist");
            var rawVerifyChunkSha1 = parser.HasFlag("-raw-verify-chunks", "-raw-verify-sha1");
            var rawNoSkipExisting = parser.HasFlag("-raw-no-skip-existing");
            var rawDryRun = parser.HasFlag("-raw-dry-run", "-raw-manifests-only");

            var appId = parser.Get(ContentDownloader.INVALID_APP_ID, "-app");
            var manifestCsvPath = parser.Get<string>(null, "-manifest-csv");

            // Old workshop-related flags all moved to the "workshop" command - matched here (not
            // printed by name below) purely to redirect anyone still typing the old syntax.
            if (parser.HasFlag("-workshop", "-workshop-csv", "-pubfile", "-ugc"))
            {
                Console.WriteLine("Error: Workshop downloading has moved to the 'workshop' command:");
                Console.WriteLine("  depotdownloader workshop download -workshop <id> [<id>...]   (ad-hoc, a few IDs)");
                Console.WriteLine("  depotdownloader workshop bootstrap -app <appid>              (for anything more -");
                Console.WriteLine("  depotdownloader workshop download -app <appid>               a tracked catalog,");
                Console.WriteLine("                                                               not a bare ID list)");
                Console.WriteLine("See 'depotdownloader help workshop' for details (bootstrap/poll/download/status).");
                return 1;
            }

            // Determine operation mode and validate arguments
            var operationMode = DetermineOperationMode(appId, manifestCsvPath);
            if (operationMode == OperationMode.Invalid)
            {
                return 1;
            }

            // Auto-enable raw mode for scenarios that would cause file collisions
            var autoRawReason = DetermineAutoRawMode(operationMode, parser);
            if (!string.IsNullOrEmpty(autoRawReason))
            {
                if (!rawMode)
                {
                    Console.WriteLine("Auto-enabling raw mode: {0}", autoRawReason);
                    rawMode = true;
                }
            }

            // Mode-specific argument validation
            if (!ValidateArgumentsForMode(operationMode, parser))
            {
                return 1;
            }

            // Built once here (after auto-raw-mode detection above may have flipped rawMode) and
            // passed down as a single object instead of re-parsing/re-constructing an identical
            // RawDownloadOptions from the same 6 loose values in each of the three modes below.
            // Null exactly when rawMode is off, so callers can check "rawOptions != null" instead
            // of threading a separate rawMode bool alongside it.
            var rawOptions = rawMode ? new ContentDownloader.RawDownloadOptions
            {
                OutputRoot = rawOutput,
                EmitDebugManifestJson = rawDebugJson,
                RespectFileFilters = rawRespectFileFilters,
                VerifyChunkSha1 = rawVerifyChunkSha1,
                SkipExisting = !rawNoSkipExisting,
                DryRun = rawDryRun,
            } : null;

            if (operationMode == OperationMode.ManifestCsv)
            {
                return await ProcessManifestCsvDownload(parser, manifestCsvPath, rawOptions, username, password);
            }
            else // OperationMode.App
            {
                return await ProcessAppDownload(parser, appId, rawOptions, username, password);
            }
        }

        private static async Task<int> ProcessManifestCsvDownload(ArgParser parser, string manifestCsvPath, ContentDownloader.RawDownloadOptions rawOptions, string username, string password)
        {
            if (InitializeSteam(username, password))
            {
                try
                {
                    await ProcessManifestCsvDownloadInternal(manifestCsvPath, rawOptions, parser).ConfigureAwait(false);
                }
                catch (Exception ex) when (
                    ex is ContentDownloaderException
                    || ex is OperationCanceledException)
                {
                    Console.WriteLine(ex.Message);
                    return 1;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                    throw;
                }
                finally
                {
                    ContentDownloader.ShutdownSteam3();
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return 1;
            }

            return 0;
        }

        private static async Task<int> ProcessAppDownload(ArgParser parser, uint appId, ContentDownloader.RawDownloadOptions rawOptions, string username, string password)
        {
            var branch = parser.Get<string>(null, "-branch", "-beta") ?? ContentDownloader.DEFAULT_BRANCH;
            ContentDownloader.Config.BetaPassword = parser.Get<string>(null, "-branchpassword", "-betapassword");
            var branchExplicit = parser.HasFlag("-branch", "-beta");

            if (!string.IsNullOrEmpty(ContentDownloader.Config.BetaPassword) && !branchExplicit)
            {
                Console.WriteLine("Error: Cannot specify -branchpassword when -branch is not specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllPlatforms = parser.HasFlag("-all-platforms");

            var os = parser.Get<string>(null, "-os");

            if (ContentDownloader.Config.DownloadAllPlatforms && !string.IsNullOrEmpty(os))
            {
                Console.WriteLine("Error: Cannot specify -os when -all-platforms is specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllArchs = parser.HasFlag("-all-archs");

            var arch = parser.Get<string>(null, "-osarch");

            if (ContentDownloader.Config.DownloadAllArchs && !string.IsNullOrEmpty(arch))
            {
                Console.WriteLine("Error: Cannot specify -osarch when -all-archs is specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllLanguages = parser.HasFlag("-all-languages");
            var language = parser.Get<string>(null, "-language");

            if (ContentDownloader.Config.DownloadAllLanguages && !string.IsNullOrEmpty(language))
            {
                Console.WriteLine("Error: Cannot specify -language when -all-languages is specified.");
                return 1;
            }

            var lv = parser.HasFlag("-lowviolence");

            var depotManifestIds = new List<(uint, ulong)>();
            var isUGC = false;

            var depotIdList = parser.GetList<uint>("-depot");
            var manifestIdList = parser.GetList<ulong>("-manifest");
            var manifestEncList = parser.GetList<string>("-manifest-enc");

            if (manifestIdList.Count > 0)
            {
                if (depotIdList.Count == manifestIdList.Count)
                {
                    var zippedDepotManifest = depotIdList.Zip(manifestIdList, (depotId, manifestId) => (depotId, manifestId));
                    depotManifestIds.AddRange(zippedDepotManifest);
                }
                else if (depotIdList.Count == 1)
                {
                    // Support 1 depot with many manifests
                    var onlyDepot = depotIdList[0];
                    foreach (var mid in manifestIdList)
                    {
                        depotManifestIds.Add((onlyDepot, mid));
                    }
                }
                else
                {
                    Console.WriteLine("Error: -manifest requires either one id for every -depot specified, or a single -depot with multiple -manifest ids.");
                    return 1;
                }
            }
            else if (depotManifestIds.Count == 0)
            {
                depotManifestIds.AddRange(depotIdList.Select(depotId => (depotId, ContentDownloader.INVALID_MANIFEST_ID)));
            }

            // Parse -manifest-enc parameters before initializing Steam
            List<(uint depotId, string enc)> encPairs = null;
            if (manifestEncList.Count > 0)
            {
                if (depotIdList.Count == manifestEncList.Count)
                {
                    encPairs = depotIdList.Zip(manifestEncList, (d, e) => (d, e)).ToList();
                }
                else if (depotIdList.Count == 1)
                {
                    encPairs = manifestEncList.Select(e => (depotIdList[0], e)).ToList();
                }
                else
                {
                    Console.WriteLine("Error: -manifest-enc requires either one id for every -depot specified, or a single -depot with multiple -manifest-enc ids.");
                    return 1;
                }
            }

            parser.WarnUnconsumed();

            if (InitializeSteam(username, password))
            {
                try
                {
                    // Resolve encrypted manifest ids AFTER Steam is initialized
                    if (encPairs != null)
                    {
                        var outputRootForKeys = rawOptions?.OutputRoot ?? ContentDownloader.Config.InstallDirectory;
                        try
                        {
                            var resolved = await ContentDownloader.ResolveEncryptedManifestIdsAsync(appId, encPairs, branch, outputRootForKeys).ConfigureAwait(false);
                            depotManifestIds.AddRange(resolved);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("Error resolving -manifest-enc ids: {0}", ex.Message);
                            return 1;
                        }
                    }

                    if (rawOptions != null)
                    {
                        await ContentDownloader.DownloadAppRawAsync(appId, depotManifestIds, branch, os, arch, language, lv, rawOptions).ConfigureAwait(false);
                    }
                    else
                    {
                        await ContentDownloader.DownloadAppAsync(appId, depotManifestIds, branch, os, arch, language, lv, isUGC).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (
                    ex is ContentDownloaderException
                    || ex is OperationCanceledException)
                {
                    Console.WriteLine(ex.Message);
                    return 1;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                    throw;
                }
                finally
                {
                    ContentDownloader.ShutdownSteam3();
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return 1;
            }

            return 0;
        }

        // Parse a simple CSV with header: AppID,DepotID,ManifestID,Branch,Release Date
        // Values are not quoted and separated by commas
        private static IEnumerable<(uint AppID, uint DepotID, ulong ManifestID, string Branch, DateTime ReleaseDate)> ReadManifestCsv(string path)
        {
            using var reader = new StreamReader(File.OpenRead(path));

            string line;
            bool headerSkipped = false;
            var culture = CultureInfo.InvariantCulture;

            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (!headerSkipped)
                {
                    headerSkipped = true;
                    // If it's not a header line, attempt to parse it anyway
                    if (line.StartsWith("AppID,DepotID,ManifestID", StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                var parts = line.Split(',');
                if (parts.Length < 5)
                    continue;

                if (!uint.TryParse(parts[0], NumberStyles.Integer, culture, out var appId))
                    continue;
                if (!uint.TryParse(parts[1], NumberStyles.Integer, culture, out var depotId))
                    continue;
                if (!ulong.TryParse(parts[2], NumberStyles.Integer, culture, out var manifestId))
                    continue;
                var branch = parts[3].Trim();

                // Release Date may have commas in exotic locales, but SteamDB export uses English like "25 June 2025 19:15:08"
                var dateStr = string.Join(',', parts.Skip(4)).Trim();
                if (!DateTime.TryParse(dateStr, culture, DateTimeStyles.AssumeLocal, out var release))
                {
                    // Try a couple of common formats explicitly
                    var formats = new[] { "d MMMM yyyy HH:mm:ss", "dd MMMM yyyy HH:mm:ss", "d MMM yyyy HH:mm:ss", "dd MMM yyyy HH:mm:ss" };
                    if (!DateTime.TryParseExact(dateStr, formats, culture, DateTimeStyles.AssumeLocal, out release))
                        continue;
                }

                yield return (appId, depotId, manifestId, branch, release);
            }
        }

        private static async Task ProcessManifestCsvDownloadInternal(string manifestCsvPath, ContentDownloader.RawDownloadOptions rawOptions, ArgParser parser)
        {
            var manifestCsvAll = parser.HasFlag("-manifest-csv-all");
            var branch = parser.Get<string>(null, "-branch", "-beta") ?? ContentDownloader.DEFAULT_BRANCH;
            var branchExplicit = parser.HasFlag("-branch", "-beta");
            var os = parser.Get<string>(null, "-os");
            var arch = parser.Get<string>(null, "-osarch");
            var language = parser.Get<string>(null, "-language");
            var lv = parser.HasFlag("-lowviolence");

            parser.WarnUnconsumed();

            // Group CSV data by AppID
            var csvGroups = ReadManifestCsv(manifestCsvPath)
                .GroupBy(r => r.AppID)
                .ToList();

            if (csvGroups.Count == 0)
            {
                Console.WriteLine("Error: No valid rows found in manifest CSV file.");
                return;
            }

            foreach (var appGroup in csvGroups)
            {
                var appId = appGroup.Key;
                var csvRows = appGroup.ToList();

                Console.WriteLine("Processing app {0} with {1} manifest entries", appId, csvRows.Count);

                var depotsToUse = csvRows.Select(r => r.DepotID).Distinct().ToList();

                if (manifestCsvAll)
                {
                    var csvAllGroups = new Dictionary<string, List<(uint depotId, ulong manifestId)>>(StringComparer.OrdinalIgnoreCase);

                    foreach (var depotId in depotsToUse)
                    {
                        var depotRows = csvRows.Where(r => r.DepotID == depotId);

                        // Only filter by branch if explicitly specified; otherwise include all branches
                        if (branchExplicit)
                        {
                            depotRows = depotRows.Where(r => string.Equals(r.Branch, branch, StringComparison.OrdinalIgnoreCase));
                        }

                        foreach (var row in depotRows.OrderByDescending(r => r.ReleaseDate))
                        {
                            if (!csvAllGroups.TryGetValue(row.Branch, out var list))
                            {
                                list = new List<(uint, ulong)>();
                                csvAllGroups[row.Branch] = list;
                            }
                            list.Add((depotId, row.ManifestID));
                        }
                    }

                    if (csvAllGroups.Count == 0 || csvAllGroups.All(kv => kv.Value.Count == 0))
                    {
                        Console.WriteLine("Warning: -manifest-csv-all did not yield any manifest ids for app {0}.", appId);
                        continue;
                    }

                    foreach (var kv in csvAllGroups)
                    {
                        var grpBranch = kv.Key;
                        var pairs = kv.Value;
                        Console.WriteLine("Downloading {0} manifests for app {1}, branch '{2}'...", pairs.Count, appId, grpBranch);
                        await ContentDownloader.DownloadAppRawAsync(appId, pairs, grpBranch, os, arch, language, lv, rawOptions).ConfigureAwait(false);
                    }
                }
                else
                {
                    // Default behavior: latest per depot, filtered by branch (explicitly specified only)
                    var depotManifestIds = new List<(uint, ulong)>();
                    foreach (var depotId in depotsToUse)
                    {
                        var candidates = csvRows.Where(r => r.DepotID == depotId);
                        if (branchExplicit)
                        {
                            candidates = candidates.Where(r => string.Equals(r.Branch, branch, StringComparison.OrdinalIgnoreCase));
                        }
                        var row = candidates.OrderByDescending(r => r.ReleaseDate).FirstOrDefault();
                        if (row.ManifestID == 0)
                        {
                            Console.WriteLine("Warning: No matching CSV entry found for depot {0}{1}", depotId, branchExplicit ? $" (branch='{branch}')" : "");
                            continue;
                        }
                        depotManifestIds.Add((depotId, row.ManifestID));
                    }

                    if (depotManifestIds.Count == 0)
                    {
                        Console.WriteLine("Warning: -manifest-csv did not yield any manifest ids for app {0}.", appId);
                        continue;
                    }

                    if (rawOptions != null)
                    {
                        await ContentDownloader.DownloadAppRawAsync(appId, depotManifestIds, branch, os, arch, language, lv, rawOptions).ConfigureAwait(false);
                    }
                    else
                    {
                        await ContentDownloader.DownloadAppAsync(appId, depotManifestIds, branch, os, arch, language, lv, false).ConfigureAwait(false);
                    }
                }
            }
        }

        static bool InitializeSteam(string username, string password)
        {
            if (!ContentDownloader.Config.UseQrCode)
            {
                if (username != null && password == null && (!ContentDownloader.Config.RememberPassword || !AccountSettingsStore.Instance.LoginTokens.ContainsKey(username)))
                {
                    if (AccountSettingsStore.Instance.LoginTokens.ContainsKey(username))
                    {
                        Console.WriteLine($"Account \"{username}\" has stored credentials. Did you forget to specify -remember-password?");
                    }

                    do
                    {
                        Console.Write("Enter account password for \"{0}\": ", username);
                        if (Console.IsInputRedirected)
                        {
                            password = Console.ReadLine();
                        }
                        else
                        {
                            // Avoid console echoing of password
                            password = Util.ReadPassword();
                        }

                        Console.WriteLine();
                    } while (string.Empty == password);
                }
                else if (username == null)
                {
                    Console.WriteLine("No username given. Using anonymous account with dedicated server subscription.");
                }
            }

            if (!string.IsNullOrEmpty(password))
            {
                const int MAX_PASSWORD_SIZE = 64;

                if (password.Length > MAX_PASSWORD_SIZE)
                {
                    Console.Error.WriteLine($"Warning: Password is longer than {MAX_PASSWORD_SIZE} characters, which is not supported by Steam.");
                }

                if (!password.All(char.IsAscii))
                {
                    Console.Error.WriteLine("Warning: Password contains non-ASCII characters, which is not supported by Steam.");
                }
            }

            return ContentDownloader.InitializeSteam3(username, password);
        }

        private static OperationMode DetermineOperationMode(uint appId, string manifestCsvPath)
        {
            var hasApp = appId != ContentDownloader.INVALID_APP_ID;
            var hasManifestCsv = !string.IsNullOrWhiteSpace(manifestCsvPath);

            // Count how many primary modes are specified
            var modeCount = (hasApp ? 1 : 0) + (hasManifestCsv ? 1 : 0);

            if (modeCount == 0)
            {
                Console.WriteLine("Error: Must specify one of: -app, -manifest-csv");
                Console.WriteLine("(Workshop downloads have moved to the 'workshop' command - see 'depotdownloader help workshop'.)");
                Console.WriteLine("Use 'depotdownloader help download' for usage information.");
                return OperationMode.Invalid;
            }

            if (modeCount > 1)
            {
                Console.WriteLine("Error: Cannot combine -app and -manifest-csv.");
                Console.WriteLine("These are mutually exclusive operation modes:");
                Console.WriteLine("  -app: Download from specific Steam application");
                Console.WriteLine("  -manifest-csv: Download from CSV manifest data");
                return OperationMode.Invalid;
            }

            // Return the appropriate mode
            if (hasApp) return OperationMode.App;
            if (hasManifestCsv) return OperationMode.ManifestCsv;

            return OperationMode.Invalid;
        }

        private static bool ValidateArgumentsForMode(OperationMode mode, ArgParser parser)
        {
            switch (mode)
            {
                case OperationMode.App:
                    // App mode: Cannot use manifest CSV
                    if (parser.HasFlag("-manifest-csv") || parser.HasFlag("-manifest-csv-all"))
                    {
                        Console.WriteLine("Error: -manifest-csv cannot be used with -app mode.");
                        return false;
                    }
                    break;

                case OperationMode.ManifestCsv:
                    // Manifest CSV mode: Cannot use app-specific depot/manifest args
                    if (parser.HasFlag("-depot"))
                    {
                        Console.WriteLine("Error: -depot cannot be used with -manifest-csv mode.");
                        Console.WriteLine("Depot IDs should be specified in the CSV file.");
                        return false;
                    }
                    if (parser.HasFlag("-manifest"))
                    {
                        Console.WriteLine("Error: -manifest cannot be used with -manifest-csv mode.");
                        Console.WriteLine("Manifest IDs should be specified in the CSV file.");
                        return false;
                    }
                    break;
            }

            return true;
        }

        // Detect scenarios that would cause file collisions and auto-enable raw mode
        private static string DetermineAutoRawMode(OperationMode mode, ArgParser parser)
        {
            switch (mode)
            {
                case OperationMode.ManifestCsv:
                    // CSV mode always implies multiple manifests, so always require raw
                    return "CSV mode always downloads multiple manifests to prevent file overwrites";

                case OperationMode.App:
                    // Check if we have multiple manifests for the same depot
                    var depotIdList = parser.GetList<uint>("-depot");
                    var manifestIdList = parser.GetList<ulong>("-manifest");

                    if (manifestIdList.Count > 1)
                    {
                        if (depotIdList.Count == 1)
                        {
                            // Single depot with multiple manifests
                            return $"downloading {manifestIdList.Count} manifests from depot {depotIdList[0]} would overwrite files";
                        }
                        else if (depotIdList.Count == manifestIdList.Count)
                        {
                            // Check for duplicate depots in the list
                            var duplicateDepots = depotIdList.GroupBy(x => x).Where(g => g.Count() > 1).Select(g => g.Key);
                            if (duplicateDepots.Any())
                            {
                                return $"multiple manifests specified for depot(s) {string.Join(", ", duplicateDepots)} would overwrite files";
                            }
                        }
                    }
                    break;
            }

            return null; // No auto-raw needed
        }

        public static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Download Command - Steam Content Download Tool");
            Console.WriteLine();
            Console.WriteLine("USAGE:");
            Console.WriteLine("  depotdownloader download [OPTIONS...]");
            Console.WriteLine();
            Console.WriteLine("DOWNLOAD MODES (mutually exclusive):");
            Console.WriteLine();
            Console.WriteLine("App-based downloading:");
            Console.WriteLine("  -app <id>                - the AppID to download");
            Console.WriteLine("  -depot <id>              - the DepotID to download");
            Console.WriteLine("  -manifest <id>           - manifest id of content to download (requires -depot)");
            Console.WriteLine("  -manifest-enc <hex>      - encrypted manifest id (hex, requires -branch and key)");
            Console.WriteLine();
            Console.WriteLine("Manifest CSV downloading:");
            Console.WriteLine("  -manifest-csv <file>     - load manifest data from CSV file");
            Console.WriteLine("                             CSV format: AppID,DepotID,ManifestID,Branch,Release Date");
            Console.WriteLine("  -manifest-csv-all        - select ALL rows per depot (auto-enables raw mode)");
            Console.WriteLine();
            Console.WriteLine("Workshop items - moved to the 'workshop' command:");
            Console.WriteLine("  depotdownloader workshop download -workshop <id> [<id>...]   (ad-hoc, a few IDs)");
            Console.WriteLine("  depotdownloader workshop bootstrap -app <appid>               (tracked catalog for");
            Console.WriteLine("  depotdownloader workshop download -app <appid>                anything CSV-sized)");
            Console.WriteLine("  (also handles automatic update tracking - see 'depotdownloader help workshop')");
            Console.WriteLine();
            Console.WriteLine("AUTHENTICATION:");
            Console.WriteLine("  -username <user>         - Steam account username for restricted content");
            Console.WriteLine("  -password <pass>         - Steam account password");
            Console.WriteLine("  -remember-password       - remember password for subsequent logins");
            Console.WriteLine("  -qr                      - display QR code for Steam mobile app login");
            Console.WriteLine("  -no-mobile               - prefer 2FA code over mobile app prompt");
            Console.WriteLine();
            Console.WriteLine("FILTERING & OUTPUT:");
            Console.WriteLine($"  -branch <name>           - download from specified branch (default: {ContentDownloader.DEFAULT_BRANCH})");
            Console.WriteLine("  -branchpassword <pass>   - branch password if applicable");
            Console.WriteLine("  -os <os>                 - operating system (windows, macos, linux)");
            Console.WriteLine("  -osarch <arch>           - architecture (32, 64)");
            Console.WriteLine("  -language <lang>         - language (default: english)");
            Console.WriteLine("  -all-platforms           - download all platform-specific depots");
            Console.WriteLine("  -all-archs               - download all architecture-specific depots");
            Console.WriteLine("  -all-languages           - download all language-specific depots");
            Console.WriteLine("  -lowviolence             - download low violence depots");
            Console.WriteLine("  -dir <path>              - output directory for downloaded files");
            Console.WriteLine("  -filelist <file>         - file containing list of files to download");
            Console.WriteLine();
            Console.WriteLine("VALIDATION:");
            Console.WriteLine("  -validate                - verify existing files against checksums");
            Console.WriteLine("  -validate-chunks         - validate chunks during download (slower but safer)");
            Console.WriteLine("  -manifest-only           - download only human-readable manifests");
            Console.WriteLine();
            Console.WriteLine("RAW ARCHIVE MODE:");
            Console.WriteLine("  -raw                     - save raw manifests and chunks (no file installation)");
            Console.WriteLine("  -raw-output <dir>        - output directory for raw archives");
            Console.WriteLine("  -raw-debug-json          - write debug JSON for each manifest");
            Console.WriteLine("  -raw-respect-filelist    - only include files matching -filelist");
            Console.WriteLine("  -raw-verify-chunks       - verify chunk SHA1 hashes after download");
            Console.WriteLine("  -raw-no-skip-existing    - overwrite existing chunks");
            Console.WriteLine("  -raw-dry-run             - download manifests only, no chunks");
            Console.WriteLine();
            Console.WriteLine("ADVANCED:");
            Console.WriteLine("  -cellid <id>             - override CDN CellID");
            Console.WriteLine("  -max-downloads <num>     - concurrent downloads (default: 8)");
            Console.WriteLine("  -loginid <id>            - unique Steam LogonID for multiple instances");
            Console.WriteLine("  -use-lancache            - force downloads through Lancache");
            Console.WriteLine("  -debug                   - enable debug output");
            Console.WriteLine();
            Console.WriteLine("EXAMPLES:");
            Console.WriteLine();
            Console.WriteLine("  # Download app in raw format");
            Console.WriteLine("  depotdownloader download -app 4000 -depot 4001 -raw");
            Console.WriteLine();
            Console.WriteLine("  # Download specific manifest with validation");
            Console.WriteLine("  depotdownloader download -app 4000 -depot 4001 -manifest 123456789 -validate-chunks");
            Console.WriteLine();
            Console.WriteLine("  # Download workshop items (see 'depotdownloader help workshop')");
            Console.WriteLine("  depotdownloader workshop download -workshop 123456 789012");
            Console.WriteLine();
            Console.WriteLine("  # Download from manifest CSV");
            Console.WriteLine("  depotdownloader download -manifest-csv manifests.csv -raw");
            Console.WriteLine();
            Console.WriteLine("  # Download all manifests from CSV for specific branch");
            Console.WriteLine("  depotdownloader download -manifest-csv manifests.csv -manifest-csv-all -branch dev");
            Console.WriteLine();
            Console.WriteLine("NOTES:");
            Console.WriteLine("  • Raw mode is auto-enabled for CSV downloads and multiple manifests");
            Console.WriteLine("  • Use -raw mode for archival purposes or when processing multiple manifests");
            Console.WriteLine("  • Validation options help ensure download integrity at the cost of speed");
            Console.WriteLine("  • For offline validation of raw downloads: depotdownloader help validation");
            Console.WriteLine();
        }
    }
}
