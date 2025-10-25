// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        private static bool[] consumedArgs;

        enum OperationMode
        {
            Invalid,
            App,
            ManifestCsv,
            Workshop
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

            consumedArgs = new bool[args.Length];

            if (HasParameter(args, "-debug"))
            {
                DebugLog.Enabled = true;
                DebugLog.AddListener((category, message) =>
                {
                    Console.WriteLine("[{0}] {1}", category, message);
                });

                var httpEventListener = new HttpDiagnosticEventListener();
            }

            var username = GetParameter<string>(args, "-username") ?? GetParameter<string>(args, "-user");
            var password = GetParameter<string>(args, "-password") ?? GetParameter<string>(args, "-pass");
            ContentDownloader.Config.RememberPassword = HasParameter(args, "-remember-password");
            ContentDownloader.Config.UseQrCode = HasParameter(args, "-qr");
            ContentDownloader.Config.SkipAppConfirmation = HasParameter(args, "-no-mobile");

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

            ContentDownloader.Config.DownloadManifestOnly = HasParameter(args, "-manifest-only");

            var cellId = GetParameter(args, "-cellid", -1);
            if (cellId == -1)
            {
                cellId = 0;
            }

            ContentDownloader.Config.CellID = cellId;

            var fileList = GetParameter<string>(args, "-filelist");

            if (fileList != null)
            {
                const string RegexPrefix = "regex:";

                try
                {
                    ContentDownloader.Config.UsingFileList = true;
                    ContentDownloader.Config.FilesToDownload = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    ContentDownloader.Config.FilesToDownloadRegex = [];

                    var files = await File.ReadAllLinesAsync(fileList);

                    foreach (var fileEntry in files)
                    {
                        if (string.IsNullOrWhiteSpace(fileEntry))
                        {
                            continue;
                        }

                        if (fileEntry.StartsWith(RegexPrefix))
                        {
                            var rgx = new Regex(fileEntry[RegexPrefix.Length..], RegexOptions.Compiled | RegexOptions.IgnoreCase);
                            ContentDownloader.Config.FilesToDownloadRegex.Add(rgx);
                        }
                        else
                        {
                            ContentDownloader.Config.FilesToDownload.Add(fileEntry.Replace('\\', '/'));
                        }
                    }

                    Console.WriteLine("Using filelist: '{0}'.", fileList);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Warning: Unable to load filelist: {0}", ex);
                }
            }

            ContentDownloader.Config.InstallDirectory = GetParameter<string>(args, "-dir");

            ContentDownloader.Config.VerifyAll = HasParameter(args, "-verify-all") || HasParameter(args, "-verify_all") || HasParameter(args, "-validate");
            ContentDownloader.Config.ValidateDownloadedChunks = HasParameter(args, "-validate-chunks") || HasParameter(args, "-validate-downloaded-chunks");

            if (HasParameter(args, "-use-lancache"))
            {
                await SteamKit2.CDN.Client.DetectLancacheServerAsync();
                if (SteamKit2.CDN.Client.UseLancacheServer)
                {
                    Console.WriteLine("Detected Lancache server! Downloads will be directed through the Lancache.");

                    // Increasing the number of concurrent downloads when the cache is detected since the downloads will likely
                    // be served much faster than over the internet.  Steam internally has this behavior as well.
                    if (!HasParameter(args, "-max-downloads"))
                    {
                        ContentDownloader.Config.MaxDownloads = 25;
                    }
                }
            }

            ContentDownloader.Config.MaxDownloads = GetParameter(args, "-max-downloads", 8);
            ContentDownloader.Config.LoginID = HasParameter(args, "-loginid") ? GetParameter<uint>(args, "-loginid") : null;

            // Raw archive options
            var rawMode = HasParameter(args, "-raw");
            var rawDebugJson = HasParameter(args, "-raw-debug-json") || HasParameter(args, "-emit-debug-manifest-json");
            var rawOutput = GetParameter<string>(args, "-raw-output");
            var rawRespectFileFilters = HasParameter(args, "-raw-respect-filelist");
            var rawVerifyChunkSha1 = HasParameter(args, "-raw-verify-chunks") || HasParameter(args, "-raw-verify-sha1");
            var rawNoSkipExisting = HasParameter(args, "-raw-no-skip-existing");
            var rawDryRun = HasParameter(args, "-raw-dry-run") || HasParameter(args, "-raw-manifests-only");

            var appId = GetParameter(args, "-app", ContentDownloader.INVALID_APP_ID);
            var manifestCsvPath = GetParameter<string>(args, "-manifest-csv");
            var workshopCsvPath = GetParameter<string>(args, "-workshop-csv");
            var workshopIds = GetParameterList<ulong>(args, "-workshop");

            // Legacy pubfile and ugc support - redirect to workshop mode
            var pubFile = GetParameter(args, "-pubfile", ContentDownloader.INVALID_MANIFEST_ID);
            var ugcId = GetParameter(args, "-ugc", ContentDownloader.INVALID_MANIFEST_ID);
            if (pubFile != ContentDownloader.INVALID_MANIFEST_ID)
            {
                workshopIds.Add(pubFile);
                Console.WriteLine("Note: -pubfile is deprecated, treating as workshop item {0}", pubFile);
            }
            if (ugcId != ContentDownloader.INVALID_MANIFEST_ID)
            {
                workshopIds.Add(ugcId);
                Console.WriteLine("Note: -ugc is deprecated, treating as workshop item {0}", ugcId);
            }

            // Determine operation mode and validate arguments
            var operationMode = DetermineOperationMode(appId, manifestCsvPath, workshopCsvPath, workshopIds.Count > 0);
            if (operationMode == OperationMode.Invalid)
            {
                return 1;
            }

            // Auto-enable raw mode for scenarios that would cause file collisions
            var autoRawReason = DetermineAutoRawMode(operationMode, args);
            if (!string.IsNullOrEmpty(autoRawReason))
            {
                if (!rawMode)
                {
                    Console.WriteLine("Auto-enabling raw mode: {0}", autoRawReason);
                    rawMode = true;
                }
            }

            // Mode-specific argument validation
            if (!ValidateArgumentsForMode(operationMode, args))
            {
                return 1;
            }

            if (operationMode == OperationMode.Workshop)
            {
                return await ProcessWorkshopDownload(args, rawMode, rawDebugJson, rawOutput, rawRespectFileFilters, rawVerifyChunkSha1, rawNoSkipExisting, rawDryRun, workshopCsvPath, workshopIds, username, password);
            }
            else if (operationMode == OperationMode.ManifestCsv)
            {
                return await ProcessManifestCsvDownload(args, manifestCsvPath, rawMode, rawDebugJson, rawOutput, rawRespectFileFilters, rawVerifyChunkSha1, rawNoSkipExisting, rawDryRun, username, password);
            }
            else // OperationMode.App
            {
                return await ProcessAppDownload(args, appId, rawMode, rawDebugJson, rawOutput, rawRespectFileFilters, rawVerifyChunkSha1, rawNoSkipExisting, rawDryRun, username, password);
            }
        }

        private static async Task<int> ProcessWorkshopDownload(string[] args, bool rawMode, bool rawDebugJson, string rawOutput, bool rawRespectFileFilters, bool rawVerifyChunkSha1, bool rawNoSkipExisting, bool rawDryRun, string workshopCsvPath, List<ulong> workshopIds, string username, string password)
        {
            PrintUnconsumedArgs(args);

            if (InitializeSteam(username, password))
            {
                int exitStatus = 0;
                try
                {
                    var rawOptions = rawMode ? new ContentDownloader.RawDownloadOptions
                    {
                        Enabled = true,
                        OutputRoot = rawOutput,
                        EmitDebugManifestJson = rawDebugJson,
                        RespectFileFilters = rawRespectFileFilters,
                        VerifyChunkSha1 = rawVerifyChunkSha1,
                        SkipExisting = !rawNoSkipExisting,
                        DryRun = rawDryRun,
                    } : null;

                    if (!string.IsNullOrEmpty(workshopCsvPath))
                    {
                        // Process workshop CSV
                        var workshopCsvIds = ReadWorkshopCsv(workshopCsvPath);
                        foreach (var workshopId in workshopCsvIds)
                        {
                            try
                            {
                                if (rawMode)
                                {
                                    await ContentDownloader.DownloadWorkshopItemRawAsync(0, workshopId, rawOptions).ConfigureAwait(false);
                                }
                                else
                                {
                                    await ContentDownloader.DownloadWorkshopItemAsync(0, workshopId).ConfigureAwait(false);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Error downloading workshop item {0}: {1}", workshopId, ex.Message);
                                exitStatus++;
                            }
                        }
                    }
                    else
                    {
                        // Process individual workshop IDs
                        foreach (var workshopId in workshopIds)
                        {
                            try
                            {
                                if (rawMode)
                                {
                                    await ContentDownloader.DownloadWorkshopItemRawAsync(0, workshopId, rawOptions).ConfigureAwait(false);
                                }
                                else
                                {
                                    await ContentDownloader.DownloadWorkshopItemAsync(0, workshopId).ConfigureAwait(false);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Error downloading workshop item {0}: {1}", workshopId, ex.Message);
                                exitStatus++;
                            }
                        }
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

                return exitStatus;
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return 1;
            }
        }

        private static async Task<int> ProcessManifestCsvDownload(string[] args, string manifestCsvPath, bool rawMode, bool rawDebugJson, string rawOutput, bool rawRespectFileFilters, bool rawVerifyChunkSha1, bool rawNoSkipExisting, bool rawDryRun, string username, string password)
        {
            // PrintUnconsumedArgs(args);

            if (InitializeSteam(username, password))
            {
                try
                {
                    var rawOptions = new ContentDownloader.RawDownloadOptions
                    {
                        Enabled = true,
                        OutputRoot = rawOutput,
                        EmitDebugManifestJson = rawDebugJson,
                        RespectFileFilters = rawRespectFileFilters,
                        VerifyChunkSha1 = rawVerifyChunkSha1,
                        SkipExisting = !rawNoSkipExisting,
                        DryRun = rawDryRun,
                    };

                    await ProcessManifestCsvDownloadInternal(manifestCsvPath, rawMode, rawOptions, args).ConfigureAwait(false);
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

        private static async Task<int> ProcessAppDownload(string[] args, uint appId, bool rawMode, bool rawDebugJson, string rawOutput, bool rawRespectFileFilters, bool rawVerifyChunkSha1, bool rawNoSkipExisting, bool rawDryRun, string username, string password)
        {
            var branch = GetParameter<string>(args, "-branch") ?? GetParameter<string>(args, "-beta") ?? ContentDownloader.DEFAULT_BRANCH;
            ContentDownloader.Config.BetaPassword = GetParameter<string>(args, "-branchpassword") ?? GetParameter<string>(args, "-betapassword");
            var branchExplicit = HasParameter(args, "-branch") || HasParameter(args, "-beta");

            if (!string.IsNullOrEmpty(ContentDownloader.Config.BetaPassword) && string.IsNullOrEmpty(branch))
            {
                Console.WriteLine("Error: Cannot specify -branchpassword when -branch is not specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllPlatforms = HasParameter(args, "-all-platforms");

            var os = GetParameter<string>(args, "-os");

            if (ContentDownloader.Config.DownloadAllPlatforms && !string.IsNullOrEmpty(os))
            {
                Console.WriteLine("Error: Cannot specify -os when -all-platforms is specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllArchs = HasParameter(args, "-all-archs");

            var arch = GetParameter<string>(args, "-osarch");

            if (ContentDownloader.Config.DownloadAllArchs && !string.IsNullOrEmpty(arch))
            {
                Console.WriteLine("Error: Cannot specify -osarch when -all-archs is specified.");
                return 1;
            }

            ContentDownloader.Config.DownloadAllLanguages = HasParameter(args, "-all-languages");
            var language = GetParameter<string>(args, "-language");

            if (ContentDownloader.Config.DownloadAllLanguages && !string.IsNullOrEmpty(language))
            {
                Console.WriteLine("Error: Cannot specify -language when -all-languages is specified.");
                return 1;
            }

            var lv = HasParameter(args, "-lowviolence");

            var depotManifestIds = new List<(uint, ulong)>();
            var isUGC = false;

            var depotIdList = GetParameterList<uint>(args, "-depot");
            var manifestIdList = GetParameterList<ulong>(args, "-manifest");
            var manifestEncList = GetParameterList<string>(args, "-manifest-enc");

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

            // Process encrypted manifest ids if provided; resolve them to decrypted gids using current -branch
            if (manifestEncList.Count > 0)
            {
                List<(uint depotId, string enc)> encPairs;
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

                // Resolve encrypted gids to decrypted manifest ids
                var outputRootForKeys = rawMode ? (rawOutput ?? ContentDownloader.Config.InstallDirectory) : ContentDownloader.Config.InstallDirectory;
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

            PrintUnconsumedArgs(args);

            if (InitializeSteam(username, password))
            {
                try
                {
                    if (rawMode)
                    {
                        var rawOptions = new ContentDownloader.RawDownloadOptions
                        {
                            Enabled = true,
                            OutputRoot = rawOutput,
                            EmitDebugManifestJson = rawDebugJson,
                            RespectFileFilters = rawRespectFileFilters,
                            VerifyChunkSha1 = rawVerifyChunkSha1,
                            SkipExisting = !rawNoSkipExisting,
                            DryRun = rawDryRun,
                        };

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

        private static async Task ProcessManifestCsvDownloadInternal(string manifestCsvPath, bool rawMode, ContentDownloader.RawDownloadOptions rawOptions, string[] args)
        {
            var manifestCsvAll = HasParameter(args, "-manifest-csv-all");
            var branch = GetParameter<string>(args, "-branch") ?? GetParameter<string>(args, "-beta") ?? ContentDownloader.DEFAULT_BRANCH;
            var branchExplicit = HasParameter(args, "-branch") || HasParameter(args, "-beta");
            var os = GetParameter<string>(args, "-os");
            var arch = GetParameter<string>(args, "-osarch");
            var language = GetParameter<string>(args, "-language");
            var lv = HasParameter(args, "-lowviolence");

            PrintUnconsumedArgs(args);

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

                    if (rawMode)
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

        private static IEnumerable<ulong> ReadWorkshopCsv(string path)
        {
            using var reader = new StreamReader(File.OpenRead(path));
            var culture = CultureInfo.InvariantCulture;
            string line;
            bool headerSkipped = false;

            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (!headerSkipped)
                {
                    headerSkipped = true;
                    // Skip header if it looks like one
                    if (line.StartsWith("WorkshopID", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("Workshop", StringComparison.OrdinalIgnoreCase))
                        continue;
                }

                // Try to parse as workshop ID (first column or entire line)
                var parts = line.Split(',');
                var workshopIdStr = parts[0].Trim();

                if (ulong.TryParse(workshopIdStr, NumberStyles.Integer, culture, out var workshopId))
                {
                    yield return workshopId;
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

        static int IndexOfParam(string[] args, string param)
        {
            for (var x = 0; x < args.Length; ++x)
            {
                if (args[x].Equals(param, StringComparison.OrdinalIgnoreCase))
                {
                    consumedArgs[x] = true;
                    return x;
                }
            }

            return -1;
        }

        static bool HasParameter(string[] args, string param)
        {
            return IndexOfParam(args, param) > -1;
        }

        static T GetParameter<T>(string[] args, string param, T defaultValue = default)
        {
            var index = IndexOfParam(args, param);

            if (index == -1 || index == (args.Length - 1))
                return defaultValue;

            var strParam = args[index + 1];

            var converter = TypeDescriptor.GetConverter(typeof(T));
            if (converter != null)
            {
                consumedArgs[index + 1] = true;
                return (T)converter.ConvertFromString(strParam);
            }

            return default;
        }

        static List<T> GetParameterList<T>(string[] args, string param)
        {
            var list = new List<T>();
            var index = IndexOfParam(args, param);

            if (index == -1 || index == (args.Length - 1))
                return list;

            index++;

            while (index < args.Length)
            {
                var strParam = args[index];

                if (strParam[0] == '-') break;

                var converter = TypeDescriptor.GetConverter(typeof(T));
                if (converter != null)
                {
                    consumedArgs[index] = true;
                    list.Add((T)converter.ConvertFromString(strParam));
                }

                index++;
            }

            return list;
        }

        static void PrintUnconsumedArgs(string[] args)
        {
            var printError = false;

            for (var index = 0; index < consumedArgs.Length; index++)
            {
                if (!consumedArgs[index])
                {
                    printError = true;
                    Console.Error.WriteLine($"Argument #{index + 1} {args[index]} was not used.");
                }
            }

            if (printError)
            {
                Console.Error.WriteLine("Make sure you specified the arguments correctly. Check --help for correct arguments.");
                Console.Error.WriteLine();
            }
        }

        private static OperationMode DetermineOperationMode(uint appId, string manifestCsvPath, string workshopCsvPath, bool hasWorkshopIds)
        {
            var hasApp = appId != ContentDownloader.INVALID_APP_ID;
            var hasManifestCsv = !string.IsNullOrWhiteSpace(manifestCsvPath);
            var hasWorkshopCsv = !string.IsNullOrWhiteSpace(workshopCsvPath);
            var hasWorkshop = hasWorkshopIds || hasWorkshopCsv;

            // Count how many primary modes are specified
            var modeCount = (hasApp ? 1 : 0) + (hasManifestCsv ? 1 : 0) + (hasWorkshop ? 1 : 0);

            if (modeCount == 0)
            {
                Console.WriteLine("Error: Must specify one of: -app, -manifest-csv, -workshop, or -workshop-csv");
                Console.WriteLine("Use 'depotdownloader help download' for usage information.");
                return OperationMode.Invalid;
            }

            if (modeCount > 1)
            {
                Console.WriteLine("Error: Cannot combine -app, -manifest-csv, and workshop modes.");
                Console.WriteLine("These are mutually exclusive operation modes:");
                Console.WriteLine("  -app: Download from specific Steam application");
                Console.WriteLine("  -manifest-csv: Download from CSV manifest data");
                Console.WriteLine("  -workshop/-workshop-csv: Download workshop items");
                return OperationMode.Invalid;
            }

            // Return the appropriate mode
            if (hasApp) return OperationMode.App;
            if (hasManifestCsv) return OperationMode.ManifestCsv;
            if (hasWorkshop) return OperationMode.Workshop;

            return OperationMode.Invalid;
        }

        private static bool ValidateArgumentsForMode(OperationMode mode, string[] args)
        {
            switch (mode)
            {
                case OperationMode.App:
                    // App mode: Cannot use manifest CSV or workshop CSV
                    if (HasParameter(args, "-manifest-csv") || HasParameter(args, "-manifest-csv-all") || HasParameter(args, "-workshop-csv"))
                    {
                        Console.WriteLine("Error: -manifest-csv and -workshop-csv cannot be used with -app mode.");
                        return false;
                    }
                    break;

                case OperationMode.ManifestCsv:
                    // Manifest CSV mode: Cannot use app-specific depot/manifest args or workshop args
                    if (HasParameter(args, "-depot"))
                    {
                        Console.WriteLine("Error: -depot cannot be used with -manifest-csv mode.");
                        Console.WriteLine("Depot IDs should be specified in the CSV file.");
                        return false;
                    }
                    if (HasParameter(args, "-manifest"))
                    {
                        Console.WriteLine("Error: -manifest cannot be used with -manifest-csv mode.");
                        Console.WriteLine("Manifest IDs should be specified in the CSV file.");
                        return false;
                    }
                    if (HasParameter(args, "-workshop"))
                    {
                        Console.WriteLine("Error: -workshop cannot be used with -manifest-csv mode.");
                        return false;
                    }
                    if (HasParameter(args, "-workshop-csv"))
                    {
                        Console.WriteLine("Error: -workshop-csv cannot be used with -manifest-csv mode.");
                        return false;
                    }
                    break;

                case OperationMode.Workshop:
                    // Workshop mode: Cannot use app, depot, manifest, or manifest CSV args
                    if (HasParameter(args, "-depot"))
                    {
                        Console.WriteLine("Error: -depot cannot be used with workshop mode.");
                        return false;
                    }
                    if (HasParameter(args, "-manifest"))
                    {
                        Console.WriteLine("Error: -manifest cannot be used with workshop mode.");
                        return false;
                    }
                    if (HasParameter(args, "-manifest-csv"))
                    {
                        Console.WriteLine("Error: -manifest-csv cannot be used with workshop mode.");
                        return false;
                    }
                    if (HasParameter(args, "-manifest-csv-all"))
                    {
                        Console.WriteLine("Error: -manifest-csv-all cannot be used with workshop mode.");
                        return false;
                    }
                    break;
            }

            return true;
        }

        // Detect scenarios that would cause file collisions and auto-enable raw mode
        private static string DetermineAutoRawMode(OperationMode mode, string[] args)
        {
            switch (mode)
            {
                case OperationMode.ManifestCsv:
                    // CSV mode always implies multiple manifests, so always require raw
                    return "CSV mode always downloads multiple manifests to prevent file overwrites";

                case OperationMode.App:
                    // Check if we have multiple manifests for the same depot
                    var depotIdList = GetParameterList<uint>(args, "-depot");
                    var manifestIdList = GetParameterList<ulong>(args, "-manifest");

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

                case OperationMode.Workshop:
                    // Workshop mode doesn't typically have the same collision issues since each item goes to its own location
                    // But if using workshop CSV with many items, user might want raw mode for archival
                    var workshopCsvPath = GetParameter<string>(args, "-workshop-csv");
                    if (!string.IsNullOrEmpty(workshopCsvPath))
                    {
                        // Let user decide for workshop CSV - they might want normal processing
                        return null;
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
            Console.WriteLine("Workshop downloading:");
            Console.WriteLine("  -workshop <id> [<id>...] - one or more Workshop item IDs to download");
            Console.WriteLine("  -workshop-csv <file>     - load workshop IDs from CSV file");
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
            Console.WriteLine("  # Download workshop items");
            Console.WriteLine("  depotdownloader download -workshop 123456 789012");
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
