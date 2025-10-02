// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    class ContentDownloaderException(string value) : Exception(value)
    {
    }

    static class ContentDownloader
    {
        public const uint INVALID_APP_ID = uint.MaxValue;
        public const uint INVALID_DEPOT_ID = uint.MaxValue;
        public const ulong INVALID_MANIFEST_ID = ulong.MaxValue;
        public const string DEFAULT_BRANCH = "public";

        public static DownloadConfig Config = new();

        private static Steam3Session steam3;
        private static CDNClientPool cdnPool;

        private const string DEFAULT_DOWNLOAD_DIR = "depots";
        private const string CONFIG_DIR = ".DepotDownloader";
        private static readonly string STAGING_DIR = Path.Combine(CONFIG_DIR, "staging");

        private sealed class DepotDownloadInfo(
            uint depotid, uint appId, ulong manifestId, string branch,
            string installDir, byte[] depotKey)
        {
            public uint DepotId { get; } = depotid;
            public uint AppId { get; } = appId;
            public ulong ManifestId { get; } = manifestId;
            public string Branch { get; } = branch;
            public string InstallDir { get; } = installDir;
            public byte[] DepotKey { get; } = depotKey;
        }

        static bool CreateDirectories(uint depotId, uint depotVersion, out string installDir)
        {
            installDir = null;
            try
            {
                if (string.IsNullOrWhiteSpace(Config.InstallDirectory))
                {
                    Directory.CreateDirectory(DEFAULT_DOWNLOAD_DIR);

                    var depotPath = Path.Combine(DEFAULT_DOWNLOAD_DIR, depotId.ToString());
                    Directory.CreateDirectory(depotPath);

                    installDir = Path.Combine(depotPath, depotVersion.ToString());
                    Directory.CreateDirectory(installDir);

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
                else
                {
                    Directory.CreateDirectory(Config.InstallDirectory);

                    installDir = Config.InstallDirectory;

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        static bool TestIsFileIncluded(string filename)
        {
            if (!Config.UsingFileList)
                return true;

            filename = filename.Replace('\\', '/');

            if (Config.FilesToDownload.Contains(filename))
            {
                return true;
            }

            foreach (var rgx in Config.FilesToDownloadRegex)
            {
                var m = rgx.Match(filename);

                if (m.Success)
                    return true;
            }

            return false;
        }

        static async Task<bool> AccountHasAccess(uint appId, uint depotId)
        {
            if (steam3 == null || steam3.steamUser.SteamID == null || (steam3.Licenses == null && steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser))
                return false;

            IEnumerable<uint> licenseQuery;
            if (steam3.steamUser.SteamID.AccountType == EAccountType.AnonUser)
            {
                licenseQuery = [17906];
            }
            else
            {
                licenseQuery = steam3.Licenses.Select(x => x.PackageID).Distinct();
            }

            await steam3.RequestPackageInfo(licenseQuery);

            foreach (var license in licenseQuery)
            {
                if (steam3.PackageInfo.TryGetValue(license, out var package) && package != null)
                {
                    if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;

                    if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;
                }
            }

            // Check if this app is free to download without a license
            var info = GetSteam3AppSection(appId, EAppInfoSection.Common);
            if (info != null && info["FreeToDownload"].AsBoolean())
                return true;

            return false;
        }

        internal static KeyValue GetSteam3AppSection(uint appId, EAppInfoSection section)
        {
            if (steam3 == null || steam3.AppInfo == null)
            {
                return null;
            }

            if (!steam3.AppInfo.TryGetValue(appId, out var app) || app == null)
            {
                return null;
            }

            var appinfo = app.KeyValues;
            var section_key = section switch
            {
                EAppInfoSection.Common => "common",
                EAppInfoSection.Extended => "extended",
                EAppInfoSection.Config => "config",
                EAppInfoSection.Depots => "depots",
                _ => throw new NotImplementedException(),
            };
            var section_kv = appinfo.Children.Where(c => c.Name == section_key).FirstOrDefault();
            return section_kv;
        }

        static uint GetSteam3AppBuildNumber(uint appId, string branch)
        {
            if (appId == INVALID_APP_ID)
                return 0;


            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var branches = depots["branches"];
            var node = branches[branch];

            if (node == KeyValue.Invalid)
                return 0;

            var buildid = node["buildid"];

            if (buildid == KeyValue.Invalid)
                return 0;

            return uint.Parse(buildid.Value);
        }

        static uint GetSteam3DepotProxyAppId(uint depotId, uint appId)
        {
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var depotChild = depots[depotId.ToString()];

            if (depotChild == KeyValue.Invalid)
                return INVALID_APP_ID;

            if (depotChild["depotfromapp"] == KeyValue.Invalid)
                return INVALID_APP_ID;

            return depotChild["depotfromapp"].AsUnsignedInteger();
        }

        static async Task<ulong> GetSteam3DepotManifest(uint depotId, uint appId, string branch)
        {
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var depotChild = depots[depotId.ToString()];

            if (depotChild == KeyValue.Invalid)
                return INVALID_MANIFEST_ID;

            // Shared depots can either provide manifests, or leave you relying on their parent app.
            // It seems that with the latter, "sharedinstall" will exist (and equals 2 in the one existance I know of).
            // Rather than relay on the unknown sharedinstall key, just look for manifests. Test cases: 111710, 346680.
            if (depotChild["manifests"] == KeyValue.Invalid && depotChild["depotfromapp"] != KeyValue.Invalid)
            {
                var otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
                if (otherAppId == appId)
                {
                    // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                    Console.WriteLine("App {0}, Depot {1} has depotfromapp of {2}!",
                        appId, depotId, otherAppId);
                    return INVALID_MANIFEST_ID;
                }

                await steam3.RequestAppInfo(otherAppId);

                return await GetSteam3DepotManifest(depotId, otherAppId, branch);
            }

            var manifests = depotChild["manifests"];

            if (manifests.Children.Count == 0)
                return INVALID_MANIFEST_ID;

            var node = manifests[branch]["gid"];

            // Non passworded branch, found the manifest
            if (node.Value != null)
                return ulong.Parse(node.Value);

            // If we requested public branch and it had no manifest, nothing to do
            if (string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
                return INVALID_MANIFEST_ID;

            // Either the branch just doesn't exist, or it has a password
            if (string.IsNullOrEmpty(Config.BetaPassword))
            {
                Console.WriteLine($"Branch {branch} for depot {depotId} was not found, either it does not exist or it has a password.");
                return INVALID_MANIFEST_ID;
            }

            if (!steam3.AppBetaPasswords.ContainsKey(branch))
            {
                // Submit the password to Steam now to get encryption keys
                await steam3.CheckAppBetaPassword(appId, Config.BetaPassword);

                if (!steam3.AppBetaPasswords.ContainsKey(branch))
                {
                    Console.WriteLine($"Error: Password was invalid for branch {branch} (or the branch does not exist)");
                    return INVALID_MANIFEST_ID;
                }
            }

            // Got the password, request private depot section
            // TODO: We're probably repeating this request for every depot?
            var privateDepotSection = await steam3.GetPrivateBetaDepotSection(appId, branch);

            // Now repeat the same code to get the manifest gid from depot section
            depotChild = privateDepotSection[depotId.ToString()];

            if (depotChild == KeyValue.Invalid)
                return INVALID_MANIFEST_ID;

            manifests = depotChild["manifests"];

            if (manifests.Children.Count == 0)
                return INVALID_MANIFEST_ID;

            node = manifests[branch]["gid"];

            if (node.Value == null)
                return INVALID_MANIFEST_ID;

            return ulong.Parse(node.Value);
        }

        static string GetAppName(uint appId)
        {
            var info = GetSteam3AppSection(appId, EAppInfoSection.Common);
            if (info == null)
                return string.Empty;

            return info["name"].AsString();
        }

        public static bool InitializeSteam3(string username, string password)
        {
            string loginToken = null;

            if (username != null && Config.RememberPassword)
            {
                _ = AccountSettingsStore.Instance.LoginTokens.TryGetValue(username, out loginToken);
            }

            steam3 = new Steam3Session(
                new SteamUser.LogOnDetails
                {
                    Username = username,
                    Password = loginToken == null ? password : null,
                    ShouldRememberPassword = Config.RememberPassword,
                    AccessToken = loginToken,
                    LoginID = Config.LoginID ?? 0x534B32, // "SK2"
                }
            );

            if (!steam3.WaitForCredentials())
            {
                Console.WriteLine("Unable to get steam3 credentials.");
                return false;
            }

            Task.Run(steam3.TickCallbacks);

            return true;
        }

        public static void ShutdownSteam3()
        {
            if (steam3 == null)
                return;

            steam3.Disconnect();
        }

        public static async Task DownloadPubfileAsync(uint appId, ulong publishedFileId)
        {
            var details = await steam3.GetPublishedFileDetails(appId, publishedFileId);

            if (!string.IsNullOrEmpty(details?.file_url))
            {
                // Ancient UGC - direct URL download to UGC folder
                await DownloadWebFileToUGCAsync(appId, publishedFileId, details.filename, details.file_url, details.file_size.ToString());
            }
            else if (details?.hcontent_file > 0)
            {
                // Modern UGC - manifest-based content, use consumer_appid as depot
                Console.WriteLine("Retrieved data for workshop item {0}: '{1}' for app {2}", publishedFileId, details.title, details.consumer_appid);
                await DownloadAppAsync(details.consumer_appid, new List<(uint, ulong)> { (details.consumer_appid, details.hcontent_file) }, DEFAULT_BRANCH, null, null, null, false, true, publishedFileId.ToString(), details.title);
            }
            else
            {
                Console.WriteLine("Unable to locate manifest ID for published file {0}", publishedFileId);
            }
        }

        public static async Task DownloadUGCAsync(uint appId, ulong ugcId)
        {
            SteamCloud.UGCDetailsCallback details = null;

            if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser)
            {
                details = await steam3.GetUGCDetails(ugcId);
            }
            else
            {
                Console.WriteLine($"Unable to query UGC details for {ugcId} from an anonymous account");
            }

            if (!string.IsNullOrEmpty(details?.URL))
            {
                // Ancient UGC - direct URL download to UGC folder
                await DownloadWebFileToUGCAsync(appId, ugcId, details.FileName, details.URL, details.FileSize.ToString());
            }
            else
            {
                // Modern UGC - manifest-based content
                await DownloadAppAsync(appId, [(appId, ugcId)], DEFAULT_BRANCH, null, null, null, false, true, ugcId.ToString(), details?.FileName);
            }
        }

        private static async Task DownloadWebFileToUGCAsync(uint appId, ulong workshopId, string fileName, string url, string fileSize)
        {
            // Create UGC directory structure organized by app ID (like Python script)
            var ugcDir = Path.Combine("ugc", appId.ToString());
            Directory.CreateDirectory(ugcDir);

            // Sanitize workshop title for filename use (like Python script)
            string safeFileName;
            if (!string.IsNullOrEmpty(fileName))
            {
                var safeName = string.Concat(fileName.Where(c => char.IsLetterOrDigit(c) || " -_".Contains(c))).Trim();
                safeName = safeName.Replace(' ', '_');
                safeFileName = $"{workshopId}_{safeName}";
            }
            else
            {
                safeFileName = workshopId.ToString();
            }

            var destPath = Path.Combine(ugcDir, safeFileName);

            // Check if file already exists
            if (File.Exists(destPath))
            {
                Console.WriteLine("UGC file already exists: {0}", destPath);
                RecordUGCDownload(workshopId, url, fileName, destPath, appId, "exists", fileSize);
                return;
            }

            Console.WriteLine("Downloading UGC workshop item {0}: '{1}'", workshopId, fileName ?? "Unknown");
            Console.WriteLine("URL: {0}", url);

            try
            {
                using var client = HttpClientFactory.CreateHttpClient();
                Console.WriteLine("Downloading {0}", safeFileName);

                var response = await client.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Failed to download UGC file: HTTP {0}", response.StatusCode);
                    return;
                }

                using var responseStream = await response.Content.ReadAsStreamAsync();
                using var fileStream = File.Create(destPath);
                await responseStream.CopyToAsync(fileStream);

                Console.WriteLine("Downloaded UGC file to {0}", destPath);
                RecordUGCDownload(workshopId, url, fileName, destPath, appId, "downloaded", fileSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error downloading UGC file: {0}", ex.Message);
            }
        }

        private static void RecordUGCDownload(ulong workshopId, string fileUrl, string title, string destPath, uint appId, string status, string fileSize)
        {
            // Record UGC download information to a tracking file (like Python script)
            var ugcDir = "ugc";
            Directory.CreateDirectory(ugcDir);

            var recordsFile = Path.Combine(ugcDir, "download_records.json");
            var records = new Dictionary<string, List<object>>();

            if (File.Exists(recordsFile))
            {
                try
                {
                    var json = File.ReadAllText(recordsFile);
                    records = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, List<object>>>(json) ?? new Dictionary<string, List<object>>();
                }
                catch
                {
                    records = new Dictionary<string, List<object>>();
                }
            }

            var appIdStr = appId.ToString();
            if (!records.ContainsKey(appIdStr))
            {
                records[appIdStr] = new List<object>();
            }

            // Check if record already exists and update, otherwise add new
            var existingIndex = -1;
            for (int i = 0; i < records[appIdStr].Count; i++)
            {
                if (records[appIdStr][i] is JsonElement element &&
                    element.TryGetProperty("workshop_id", out var idProp) &&
                    idProp.GetUInt64() == workshopId)
                {
                    existingIndex = i;
                    break;
                }
            }

            var record = new
            {
                workshop_id = workshopId,
                title = title ?? "Unknown",
                file_url = fileUrl,
                file_path = destPath,
                status = status,
                file_size = File.Exists(destPath) ? new FileInfo(destPath).Length.ToString() : fileSize,
                timestamp = DateTime.Now.ToString("O")
            };

            if (existingIndex >= 0)
            {
                records[appIdStr][existingIndex] = record;
            }
            else
            {
                records[appIdStr].Add(record);
            }

            try
            {
                var json = System.Text.Json.JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(recordsFile, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Could not save UGC download record: {0}", ex.Message);
            }
        }

        private static async Task DownloadWebFile(uint appId, string fileName, string url)
        {
            if (!CreateDirectories(appId, 0, out var installDir))
            {
                Console.WriteLine("Error: Unable to create install directories!");
                return;
            }

            var stagingDir = Path.Combine(installDir, STAGING_DIR);
            var fileStagingPath = Path.Combine(stagingDir, fileName);
            var fileFinalPath = Path.Combine(installDir, fileName);

            Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath));
            Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath));

            using (var file = File.OpenWrite(fileStagingPath))
            using (var client = HttpClientFactory.CreateHttpClient())
            {
                Console.WriteLine("Downloading {0}", fileName);
                var responseStream = await client.GetStreamAsync(url);
                await responseStream.CopyToAsync(file);
            }

            if (File.Exists(fileFinalPath))
            {
                File.Delete(fileFinalPath);
            }

            File.Move(fileStagingPath, fileFinalPath);
        }

        public static async Task DownloadAppAsync(uint appId, List<(uint depotId, ulong manifestId)> depotManifestIds, string branch, string os, string arch, string language, bool lv, bool isUgc, string workshopId = null, string workshopName = null)
        {
            cdnPool = new CDNClientPool(steam3, appId);

            // Load our configuration data containing the depots currently installed
            var configPath = Config.InstallDirectory;
            if (string.IsNullOrWhiteSpace(configPath))
            {
                configPath = DEFAULT_DOWNLOAD_DIR;
            }

            Directory.CreateDirectory(Path.Combine(configPath, CONFIG_DIR));
            DepotConfigStore.LoadFromFile(Path.Combine(configPath, CONFIG_DIR, "depot.config"));

            await steam3?.RequestAppInfo(appId);

            if (!await AccountHasAccess(appId, appId))
            {
                if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser && await steam3.RequestFreeAppLicense(appId))
                {
                    Console.WriteLine("Obtained FreeOnDemand license for app {0}", appId);

                    // Fetch app info again in case we didn't get it fully without a license.
                    await steam3.RequestAppInfo(appId, true);
                }
                else
                {
                    var contentName = GetAppName(appId);
                    throw new ContentDownloaderException(string.Format("App {0} ({1}) is not available from this account.", appId, contentName));
                }
            }

            var hasSpecificDepots = depotManifestIds.Count > 0;
            var depotIdsFound = new List<uint>();
            var depotIdsExpected = depotManifestIds.Select(x => x.depotId).ToList();
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);

            if (isUgc)
            {
                var workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
                if (workshopDepot != 0 && !depotIdsExpected.Contains(workshopDepot))
                {
                    depotIdsExpected.Add(workshopDepot);
                    depotManifestIds = depotManifestIds.Select(pair => (workshopDepot, pair.manifestId)).ToList();
                }

                depotIdsFound.AddRange(depotIdsExpected);
            }
            else
            {
                Console.WriteLine("Using app branch: '{0}'.", branch);

                if (depots != null)
                {
                    foreach (var depotSection in depots.Children)
                    {
                        var id = INVALID_DEPOT_ID;
                        if (depotSection.Children.Count == 0)
                            continue;

                        if (!uint.TryParse(depotSection.Name, out id))
                            continue;

                        if (hasSpecificDepots && !depotIdsExpected.Contains(id))
                            continue;

                        if (!hasSpecificDepots)
                        {
                            var depotConfig = depotSection["config"];
                            if (depotConfig != KeyValue.Invalid)
                            {
                                if (!Config.DownloadAllPlatforms &&
                                    depotConfig["oslist"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                                {
                                    var oslist = depotConfig["oslist"].Value.Split(',');
                                    if (Array.IndexOf(oslist, os ?? Util.GetSteamOS()) == -1)
                                        continue;
                                }

                                if (!Config.DownloadAllArchs &&
                                    depotConfig["osarch"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["osarch"].Value))
                                {
                                    var depotArch = depotConfig["osarch"].Value;
                                    if (depotArch != (arch ?? Util.GetSteamArch()))
                                        continue;
                                }

                                if (!Config.DownloadAllLanguages &&
                                    depotConfig["language"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["language"].Value))
                                {
                                    var depotLang = depotConfig["language"].Value;
                                    if (depotLang != (language ?? "english"))
                                        continue;
                                }

                                if (!lv &&
                                    depotConfig["lowviolence"] != KeyValue.Invalid &&
                                    depotConfig["lowviolence"].AsBoolean())
                                    continue;
                            }
                        }

                        depotIdsFound.Add(id);

                        if (!hasSpecificDepots)
                            depotManifestIds.Add((id, INVALID_MANIFEST_ID));
                    }
                }

                if (depotManifestIds.Count == 0 && !hasSpecificDepots)
                {
                    throw new ContentDownloaderException(string.Format("Couldn't find any depots to download for app {0}", appId));
                }

                if (depotIdsFound.Count < depotIdsExpected.Count)
                {
                    var remainingDepotIds = depotIdsExpected.Except(depotIdsFound);
                    throw new ContentDownloaderException(string.Format("Depot {0} not listed for app {1}", string.Join(", ", remainingDepotIds), appId));
                }
            }

            var infos = new List<DepotDownloadInfo>();

            foreach (var (depotId, manifestId) in depotManifestIds)
            {
                var info = await GetDepotInfo(depotId, appId, manifestId, branch);
                if (info != null)
                {
                    infos.Add(info);
                }
            }

            Console.WriteLine();

            try
            {
                await DownloadSteam3Async(infos).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("App {0} was not completely downloaded.", appId);
                throw;
            }
        }

        static async Task<DepotDownloadInfo> GetDepotInfo(uint depotId, uint appId, ulong manifestId, string branch, bool createInstallDirs = true)
        {
            if (steam3 != null && appId != INVALID_APP_ID)
            {
                await steam3.RequestAppInfo(appId);
            }

            if (!await AccountHasAccess(appId, depotId))
            {
                Console.WriteLine("Depot {0} is not available from this account.", depotId);

                return null;
            }

            if (manifestId == INVALID_MANIFEST_ID)
            {
                manifestId = await GetSteam3DepotManifest(depotId, appId, branch);
                if (manifestId == INVALID_MANIFEST_ID && !string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Warning: Depot {0} does not have branch named \"{1}\". Trying {2} branch.", depotId, branch, DEFAULT_BRANCH);
                    branch = DEFAULT_BRANCH;
                    manifestId = await GetSteam3DepotManifest(depotId, appId, branch);
                }

                if (manifestId == INVALID_MANIFEST_ID)
                {
                    Console.WriteLine("Depot {0} missing public subsection or manifest section.", depotId);
                    return null;
                }
            }

            await steam3.RequestDepotKey(depotId, appId);
            if (!steam3.DepotKeys.TryGetValue(depotId, out var depotKey))
            {
                Console.WriteLine("No valid depot key for {0}, unable to download.", depotId);
                return null;
            }

            var uVersion = GetSteam3AppBuildNumber(appId, branch);

            string installDir;
            if (createInstallDirs)
            {
                if (!CreateDirectories(depotId, uVersion, out installDir))
                {
                    Console.WriteLine("Error: Unable to create install directories!");
                    return null;
                }
            }
            else
            {
                // Raw mode does not install files; avoid creating default/staging/config directories
                installDir = string.Empty;
            }

            // For depots that are proxied through depotfromapp, we still need to resolve the proxy app id, unless the app is freetodownload
            var containingAppId = appId;
            var proxyAppId = GetSteam3DepotProxyAppId(depotId, appId);
            if (proxyAppId != INVALID_APP_ID)
            {
                var common = GetSteam3AppSection(appId, EAppInfoSection.Common);
                if (common == null || !common["FreeToDownload"].AsBoolean())
                {
                    containingAppId = proxyAppId;
                }
            }

            return new DepotDownloadInfo(depotId, containingAppId, manifestId, branch, installDir, depotKey);
        }

        private class ChunkMatch(DepotManifest.ChunkData oldChunk, DepotManifest.ChunkData newChunk)
        {
            public DepotManifest.ChunkData OldChunk { get; } = oldChunk;
            public DepotManifest.ChunkData NewChunk { get; } = newChunk;
        }

        private class DepotFilesData
        {
            public DepotDownloadInfo depotDownloadInfo;
            public DepotDownloadCounter depotCounter;
            public string stagingDir;
            public DepotManifest manifest;
            public DepotManifest previousManifest;
            public List<DepotManifest.FileData> filteredFiles;
            public HashSet<string> allFileNames;
        }

        private class FileStreamData
        {
            public FileStream fileStream;
            public SemaphoreSlim fileLock;
            public int chunksToDownload;
        }

        private class GlobalDownloadCounter
        {
            public ulong completeDownloadSize;
            public ulong totalBytesCompressed;
            public ulong totalBytesUncompressed;
        }

        private class DepotDownloadCounter
        {
            public ulong completeDownloadSize;
            public ulong sizeDownloaded;
            public ulong depotBytesCompressed;
            public ulong depotBytesUncompressed;
        }

        private class ChunkProgressTracker
        {
            public ulong Total;
            public ulong Downloaded;
            public ulong Skipped;
            public ulong Completed => Downloaded + Skipped;
            private readonly object _lockObject = new object();
            private DateTime _lastUpdate = DateTime.MinValue;

            public void IncrementDownloaded()
            {
                Interlocked.Increment(ref Downloaded);
                UpdateProgress();
            }

            public void IncrementSkipped()
            {
                Interlocked.Increment(ref Skipped);
                UpdateProgress();
            }

            private void UpdateProgress()
            {
                lock (_lockObject)
                {
                    var now = DateTime.Now;
                    var completed = Completed;

                    // Update Ansi progress bar
                    if (Total > 0)
                    {
                        Ansi.Progress(completed, Total);
                    }

                    // Also show text progress every 100 chunks or every 2 seconds for slower downloads
                    if (completed % 100 == 0 ||
                        completed == Total ||
                        (now - _lastUpdate).TotalSeconds >= 2)
                    {
                        var percentage = Total > 0 ? (completed * 100.0) / Total : 0;
                        Console.Write($"\rProgress: {completed}/{Total} chunks ({percentage:F1}%) - {Downloaded} downloaded, {Skipped} skipped");
                        _lastUpdate = now;

                        // Only add newline if we're done
                        if (completed == Total)
                        {
                            Console.WriteLine();
                        }
                    }
                }
            }

            public void ShowFinalStats(uint depotId)
            {
                // Clear the progress line and show final stats
                Console.Write("\r" + new string(' ', 80) + "\r"); // Clear line
                Console.WriteLine("Depot {0} - {1}/{2} chunks processed ({3} downloaded, {4} skipped)",
                    depotId, Completed, Total, Downloaded, Skipped);
            }
        }

        private static async Task DownloadSteam3Async(List<DepotDownloadInfo> depots)
        {
            Ansi.Progress(Ansi.ProgressState.Indeterminate);

            await cdnPool.UpdateServerList();

            var cts = new CancellationTokenSource();
            var downloadCounter = new GlobalDownloadCounter();
            var depotsToDownload = new List<DepotFilesData>(depots.Count);
            var allFileNamesAllDepots = new HashSet<string>();

            // First, fetch all the manifests for each depot (including previous manifests) and perform the initial setup
            foreach (var depot in depots)
            {
                var depotFileData = await ProcessDepotManifestAndFiles(cts, depot, downloadCounter);

                if (depotFileData != null)
                {
                    depotsToDownload.Add(depotFileData);
                    allFileNamesAllDepots.UnionWith(depotFileData.allFileNames);
                }

                cts.Token.ThrowIfCancellationRequested();
            }

            // If we're about to write all the files to the same directory, we will need to first de-duplicate any files by path
            // This is in last-depot-wins order, from Steam or the list of depots supplied by the user
            if (!string.IsNullOrWhiteSpace(Config.InstallDirectory) && depotsToDownload.Count > 0)
            {
                var claimedFileNames = new HashSet<string>();

                for (var i = depotsToDownload.Count - 1; i >= 0; i--)
                {
                    // For each depot, remove all files from the list that have been claimed by a later depot
                    depotsToDownload[i].filteredFiles.RemoveAll(file => claimedFileNames.Contains(file.FileName));

                    claimedFileNames.UnionWith(depotsToDownload[i].allFileNames);
                }
            }

            foreach (var depotFileData in depotsToDownload)
            {
                await DownloadSteam3AsyncDepotFiles(cts, downloadCounter, depotFileData, allFileNamesAllDepots);
            }

            Ansi.Progress(Ansi.ProgressState.Hidden);

            Console.WriteLine("Total downloaded: {0} bytes ({1} bytes uncompressed) from {2} depots",
                downloadCounter.totalBytesCompressed, downloadCounter.totalBytesUncompressed, depots.Count);
        }

        private static async Task<DepotFilesData> ProcessDepotManifestAndFiles(CancellationTokenSource cts, DepotDownloadInfo depot, GlobalDownloadCounter downloadCounter)
        {
            var depotCounter = new DepotDownloadCounter();

            Console.WriteLine("Processing depot {0}", depot.DepotId);

            DepotManifest oldManifest = null;
            DepotManifest newManifest = null;
            var configDir = Path.Combine(depot.InstallDir, CONFIG_DIR);

            var lastManifestId = INVALID_MANIFEST_ID;
            DepotConfigStore.Instance.InstalledManifestIDs.TryGetValue(depot.DepotId, out lastManifestId);

            // In case we have an early exit, this will force equiv of verifyall next run.
            DepotConfigStore.Instance.InstalledManifestIDs[depot.DepotId] = INVALID_MANIFEST_ID;
            DepotConfigStore.Save();

            if (lastManifestId != INVALID_MANIFEST_ID)
            {
                // We only have to show this warning if the old manifest ID was different
                var badHashWarning = (lastManifestId != depot.ManifestId);
                oldManifest = Util.LoadManifestFromFile(configDir, depot.DepotId, lastManifestId, badHashWarning);
            }

            if (lastManifestId == depot.ManifestId && oldManifest != null)
            {
                newManifest = oldManifest;
                Console.WriteLine("Already have manifest {0} for depot {1}.", depot.ManifestId, depot.DepotId);
            }
            else
            {
                newManifest = Util.LoadManifestFromFile(configDir, depot.DepotId, depot.ManifestId, true);

                if (newManifest != null)
                {
                    Console.WriteLine("Already have manifest {0} for depot {1}.", depot.ManifestId, depot.DepotId);
                }
                else
                {
                    Console.WriteLine($"Downloading depot {depot.DepotId} manifest");

                    ulong manifestRequestCode = 0;
                    var manifestRequestCodeExpiration = DateTime.MinValue;

                    do
                    {
                        cts.Token.ThrowIfCancellationRequested();

                        Server connection = null;

                        try
                        {
                            connection = cdnPool.GetConnection();

                            string cdnToken = null;
                            if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                            {
                                var result = await authTokenCallbackPromise.Task;
                                cdnToken = result.Token;
                            }

                            var now = DateTime.Now;

                            // In order to download this manifest, we need the current manifest request code
                            // The manifest request code is only valid for a specific period in time
                            if (manifestRequestCode == 0 || now >= manifestRequestCodeExpiration)
                            {
                                manifestRequestCode = await steam3.GetDepotManifestRequestCodeAsync(
                                    depot.DepotId,
                                    depot.AppId,
                                    depot.ManifestId,
                                    depot.Branch);
                                // This code will hopefully be valid for one period following the issuing period
                                manifestRequestCodeExpiration = now.Add(TimeSpan.FromMinutes(5));

                                // If we could not get the manifest code, this is a fatal error
                                if (manifestRequestCode == 0)
                                {
                                    cts.Cancel();
                                }
                            }

                            DebugLog.WriteLine("ContentDownloader",
                                "Downloading manifest {0} from {1} with {2}",
                                depot.ManifestId,
                                connection,
                                cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                            newManifest = await cdnPool.CDNClient.DownloadManifestAsync(
                                depot.DepotId,
                                depot.ManifestId,
                                manifestRequestCode,
                                connection,
                                depot.DepotKey,
                                cdnPool.ProxyServer,
                                cdnToken).ConfigureAwait(false);

                            cdnPool.ReturnConnection(connection);
                        }
                        catch (TaskCanceledException)
                        {
                            Console.WriteLine("Connection timeout downloading depot manifest {0} {1}. Retrying.", depot.DepotId, depot.ManifestId);
                        }
                        catch (SteamKitWebRequestException e)
                        {
                            // If the CDN returned 403, attempt to get a cdn auth if we didn't yet
                            if (e.StatusCode == HttpStatusCode.Forbidden && !steam3.CDNAuthTokens.ContainsKey((depot.DepotId, connection.Host)))
                            {
                                await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                                cdnPool.ReturnConnection(connection);

                                continue;
                            }

                            cdnPool.ReturnBrokenConnection(connection);

                            if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                            {
                                Console.WriteLine("Encountered {2} for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId, (int)e.StatusCode);
                                break;
                            }

                            if (e.StatusCode == HttpStatusCode.NotFound)
                            {
                                Console.WriteLine("Encountered 404 for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId);
                                break;
                            }

                            Console.WriteLine("Encountered error downloading depot manifest {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.StatusCode);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (Exception e)
                        {
                            cdnPool.ReturnBrokenConnection(connection);
                            Console.WriteLine("Encountered error downloading manifest for depot {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.Message);
                        }
                    } while (newManifest == null);

                    if (newManifest == null)
                    {
                        Console.WriteLine("\nUnable to download manifest {0} for depot {1}", depot.ManifestId, depot.DepotId);
                        cts.Cancel();
                    }

                    // Throw the cancellation exception if requested so that this task is marked failed
                    cts.Token.ThrowIfCancellationRequested();

                    Util.SaveManifestToFile(configDir, newManifest);
                }
            }

            Console.WriteLine("Manifest {0} ({1})", depot.ManifestId, newManifest.CreationTime);

            if (Config.DownloadManifestOnly)
            {
                DumpManifestToTextFile(depot, newManifest);
                return null;
            }

            var stagingDir = Path.Combine(depot.InstallDir, STAGING_DIR);

            var filesAfterExclusions = newManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).ToList();
            var allFileNames = new HashSet<string>(filesAfterExclusions.Count);

            // Pre-process
            filesAfterExclusions.ForEach(file =>
            {
                allFileNames.Add(file.FileName);

                var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                var fileStagingPath = Path.Combine(stagingDir, file.FileName);

                if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                {
                    Directory.CreateDirectory(fileFinalPath);
                    Directory.CreateDirectory(fileStagingPath);
                }
                else
                {
                    // Some manifests don't explicitly include all necessary directories
                    Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath));

                    downloadCounter.completeDownloadSize += file.TotalSize;
                    depotCounter.completeDownloadSize += file.TotalSize;
                }
            });

            return new DepotFilesData
            {
                depotDownloadInfo = depot,
                depotCounter = depotCounter,
                stagingDir = stagingDir,
                manifest = newManifest,
                previousManifest = oldManifest,
                filteredFiles = filesAfterExclusions,
                allFileNames = allFileNames
            };
        }

        private static async Task DownloadSteam3AsyncDepotFiles(CancellationTokenSource cts,
            GlobalDownloadCounter downloadCounter, DepotFilesData depotFilesData, HashSet<string> allFileNamesAllDepots)
        {
            var depot = depotFilesData.depotDownloadInfo;
            var depotCounter = depotFilesData.depotCounter;

            Console.WriteLine("Downloading depot {0}", depot.DepotId);

            var files = depotFilesData.filteredFiles.Where(f => !f.Flags.HasFlag(EDepotFileFlag.Directory)).ToArray();
            var networkChunkQueue = new ConcurrentQueue<(FileStreamData fileStreamData, DepotManifest.FileData fileData, DepotManifest.ChunkData chunk)>();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Config.MaxDownloads,
                CancellationToken = cts.Token
            };

            await Parallel.ForEachAsync(files, parallelOptions, async (file, cancellationToken) =>
            {
                await Task.Yield();
                DownloadSteam3AsyncDepotFile(cts, downloadCounter, depotFilesData, file, networkChunkQueue);
            });

            await Parallel.ForEachAsync(networkChunkQueue, parallelOptions, async (q, cancellationToken) =>
            {
                await DownloadSteam3AsyncDepotFileChunk(
                    cts, downloadCounter, depotFilesData,
                    q.fileData, q.fileStreamData, q.chunk
                );
            });

            // Check for deleted files if updating the depot.
            if (depotFilesData.previousManifest != null)
            {
                var previousFilteredFiles = depotFilesData.previousManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).Select(f => f.FileName).ToHashSet();

                // Check if we are writing to a single output directory. If not, each depot folder is managed independently
                if (string.IsNullOrWhiteSpace(Config.InstallDirectory))
                {
                    // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names
                    previousFilteredFiles.ExceptWith(depotFilesData.allFileNames);
                }
                else
                {
                    // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names across all depots being downloaded
                    previousFilteredFiles.ExceptWith(allFileNamesAllDepots);
                }

                foreach (var existingFileName in previousFilteredFiles)
                {
                    var fileFinalPath = Path.Combine(depot.InstallDir, existingFileName);

                    if (!File.Exists(fileFinalPath))
                        continue;

                    File.Delete(fileFinalPath);
                    Console.WriteLine("Deleted {0}", fileFinalPath);
                }
            }

            DepotConfigStore.Instance.InstalledManifestIDs[depot.DepotId] = depot.ManifestId;
            DepotConfigStore.Save();

            Console.WriteLine("Depot {0} - Downloaded {1} bytes ({2} bytes uncompressed)", depot.DepotId, depotCounter.depotBytesCompressed, depotCounter.depotBytesUncompressed);
        }

        private static void DownloadSteam3AsyncDepotFile(
            CancellationTokenSource cts,
            GlobalDownloadCounter downloadCounter,
            DepotFilesData depotFilesData,
            DepotManifest.FileData file,
            ConcurrentQueue<(FileStreamData, DepotManifest.FileData, DepotManifest.ChunkData)> networkChunkQueue)
        {
            cts.Token.ThrowIfCancellationRequested();

            var depot = depotFilesData.depotDownloadInfo;
            var stagingDir = depotFilesData.stagingDir;
            var depotDownloadCounter = depotFilesData.depotCounter;
            var oldProtoManifest = depotFilesData.previousManifest;
            DepotManifest.FileData oldManifestFile = null;
            if (oldProtoManifest != null)
            {
                oldManifestFile = oldProtoManifest.Files.SingleOrDefault(f => f.FileName == file.FileName);
            }

            var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
            var fileStagingPath = Path.Combine(stagingDir, file.FileName);

            // This may still exist if the previous run exited before cleanup
            if (File.Exists(fileStagingPath))
            {
                File.Delete(fileStagingPath);
            }

            List<DepotManifest.ChunkData> neededChunks;
            var fi = new FileInfo(fileFinalPath);
            var fileDidExist = fi.Exists;
            if (!fileDidExist)
            {
                Console.WriteLine("Pre-allocating {0}", fileFinalPath);

                // create new file. need all chunks
                using var fs = File.Create(fileFinalPath);
                try
                {
                    fs.SetLength((long)file.TotalSize);
                }
                catch (IOException ex)
                {
                    throw new ContentDownloaderException(string.Format("Failed to allocate file {0}: {1}", fileFinalPath, ex.Message));
                }

                neededChunks = new List<DepotManifest.ChunkData>(file.Chunks);
            }
            else
            {
                // open existing
                if (oldManifestFile != null)
                {
                    neededChunks = [];

                    var hashMatches = oldManifestFile.FileHash.SequenceEqual(file.FileHash);
                    if (Config.VerifyAll || !hashMatches)
                    {
                        // we have a version of this file, but it doesn't fully match what we want
                        if (Config.VerifyAll)
                        {
                            Console.WriteLine("Validating {0}", fileFinalPath);
                        }

                        var matchingChunks = new List<ChunkMatch>();

                        foreach (var chunk in file.Chunks)
                        {
                            var oldChunk = oldManifestFile.Chunks.FirstOrDefault(c => c.ChunkID.SequenceEqual(chunk.ChunkID));
                            if (oldChunk != null)
                            {
                                matchingChunks.Add(new ChunkMatch(oldChunk, chunk));
                            }
                            else
                            {
                                neededChunks.Add(chunk);
                            }
                        }

                        var orderedChunks = matchingChunks.OrderBy(x => x.OldChunk.Offset);

                        var copyChunks = new List<ChunkMatch>();

                        using (var fsOld = File.Open(fileFinalPath, FileMode.Open))
                        {
                            foreach (var match in orderedChunks)
                            {
                                fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                var adler = Util.AdlerHash(fsOld, (int)match.OldChunk.UncompressedLength);
                                if (!adler.SequenceEqual(BitConverter.GetBytes(match.OldChunk.Checksum)))
                                {
                                    neededChunks.Add(match.NewChunk);
                                }
                                else
                                {
                                    copyChunks.Add(match);
                                }
                            }
                        }

                        if (!hashMatches || neededChunks.Count > 0)
                        {
                            File.Move(fileFinalPath, fileStagingPath);

                            using (var fsOld = File.Open(fileStagingPath, FileMode.Open))
                            {
                                using var fs = File.Open(fileFinalPath, FileMode.Create);
                                try
                                {
                                    fs.SetLength((long)file.TotalSize);
                                }
                                catch (IOException ex)
                                {
                                    throw new ContentDownloaderException(string.Format("Failed to resize file to expected size {0}: {1}", fileFinalPath, ex.Message));
                                }

                                foreach (var match in copyChunks)
                                {
                                    fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                    var tmp = new byte[match.OldChunk.UncompressedLength];
                                    fsOld.ReadExactly(tmp);

                                    fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
                                    fs.Write(tmp, 0, tmp.Length);
                                }
                            }

                            File.Delete(fileStagingPath);
                        }
                    }
                }
                else
                {
                    // No old manifest or file not in old manifest. We must validate.

                    using var fs = File.Open(fileFinalPath, FileMode.Open);
                    if ((ulong)fi.Length != file.TotalSize)
                    {
                        try
                        {
                            fs.SetLength((long)file.TotalSize);
                        }
                        catch (IOException ex)
                        {
                            throw new ContentDownloaderException(string.Format("Failed to allocate file {0}: {1}", fileFinalPath, ex.Message));
                        }
                    }

                    Console.WriteLine("Validating {0}", fileFinalPath);
                    neededChunks = Util.ValidateSteam3FileChecksums(fs, [.. file.Chunks.OrderBy(x => x.Offset)]);
                }

                if (neededChunks.Count == 0)
                {
                    lock (depotDownloadCounter)
                    {
                        depotDownloadCounter.sizeDownloaded += file.TotalSize;
                        Console.WriteLine("{0,6:#00.00}% {1}", (depotDownloadCounter.sizeDownloaded / (float)depotDownloadCounter.completeDownloadSize) * 100.0f, fileFinalPath);
                    }

                    lock (downloadCounter)
                    {
                        downloadCounter.completeDownloadSize -= file.TotalSize;
                    }

                    return;
                }

                var sizeOnDisk = (file.TotalSize - (ulong)neededChunks.Select(x => (long)x.UncompressedLength).Sum());
                lock (depotDownloadCounter)
                {
                    depotDownloadCounter.sizeDownloaded += sizeOnDisk;
                }

                lock (downloadCounter)
                {
                    downloadCounter.completeDownloadSize -= sizeOnDisk;
                }
            }

            var fileIsExecutable = file.Flags.HasFlag(EDepotFileFlag.Executable);
            if (fileIsExecutable && (!fileDidExist || oldManifestFile == null || !oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable)))
            {
                PlatformUtilities.SetExecutable(fileFinalPath, true);
            }
            else if (!fileIsExecutable && oldManifestFile != null && oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable))
            {
                PlatformUtilities.SetExecutable(fileFinalPath, false);
            }

            var fileStreamData = new FileStreamData
            {
                fileStream = null,
                fileLock = new SemaphoreSlim(1),
                chunksToDownload = neededChunks.Count
            };

            foreach (var chunk in neededChunks)
            {
                networkChunkQueue.Enqueue((fileStreamData, file, chunk));
            }
        }

        private static async Task DownloadSteam3AsyncDepotFileChunk(
            CancellationTokenSource cts,
            GlobalDownloadCounter downloadCounter,
            DepotFilesData depotFilesData,
            DepotManifest.FileData file,
            FileStreamData fileStreamData,
            DepotManifest.ChunkData chunk)
        {
            cts.Token.ThrowIfCancellationRequested();

            var depot = depotFilesData.depotDownloadInfo;
            var depotDownloadCounter = depotFilesData.depotCounter;

            var chunkID = Convert.ToHexString(chunk.ChunkID).ToLowerInvariant();

            var written = 0;
            // Fix: When depot key is provided, CDN client decompresses the chunk, so buffer needs UncompressedLength
            var chunkBuffer = ArrayPool<byte>.Shared.Rent((int)chunk.UncompressedLength);

            try
            {
                do
                {
                    cts.Token.ThrowIfCancellationRequested();

                    Server connection = null;

                    try
                    {
                        connection = cdnPool.GetConnection();

                        string cdnToken = null;
                        if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                        {
                            var result = await authTokenCallbackPromise.Task;
                            cdnToken = result.Token;
                        }

                        DebugLog.WriteLine("ContentDownloader", "Downloading chunk {0} from {1} with {2}", chunkID, connection, cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                        written = await cdnPool.CDNClient.DownloadDepotChunkAsync(
                            depot.DepotId,
                            chunk,
                            connection,
                            chunkBuffer,
                            depot.DepotKey,
                            cdnPool.ProxyServer,
                            cdnToken).ConfigureAwait(false);

                        cdnPool.ReturnConnection(connection);

                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Connection timeout downloading chunk {0}", chunkID);
                        cdnPool.ReturnBrokenConnection(connection);
                    }
                    catch (SteamKitWebRequestException e)
                    {

                        if (e.StatusCode == HttpStatusCode.Forbidden &&
                            (!steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise) || !authTokenCallbackPromise.Task.IsCompleted))
                        {
                            await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                            cdnPool.ReturnConnection(connection);

                            continue;
                        }

                        cdnPool.ReturnBrokenConnection(connection);

                        if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                        {
                            Console.WriteLine("Encountered {2} for chunk {0}. Aborting.", chunkID, (int)e.StatusCode);
                            break;
                        }

                        Console.WriteLine("Encountered error downloading chunk {0}: {1}", chunkID, e.StatusCode);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        cdnPool.ReturnBrokenConnection(connection);
                        Console.WriteLine("Encountered unexpected error downloading chunk {0}: {1}", chunkID, e.Message);
                    }
                } while (written == 0);

                if (written == 0)
                {
                    Console.WriteLine("Failed to find any server with chunk {0} for depot {1}. Aborting.", chunkID, depot.DepotId);
                    cts.Cancel();
                }

                // Throw the cancellation exception if requested so that this task is marked failed
                cts.Token.ThrowIfCancellationRequested();

                try
                {
                    await fileStreamData.fileLock.WaitAsync().ConfigureAwait(false);

                    if (fileStreamData.fileStream == null)
                    {
                        var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                        fileStreamData.fileStream = File.Open(fileFinalPath, FileMode.Open);
                    }

                    fileStreamData.fileStream.Seek((long)chunk.Offset, SeekOrigin.Begin);
                    await fileStreamData.fileStream.WriteAsync(chunkBuffer.AsMemory(0, written), cts.Token);
                }
                finally
                {
                    fileStreamData.fileLock.Release();
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunkBuffer);
            }

            var remainingChunks = Interlocked.Decrement(ref fileStreamData.chunksToDownload);
            if (remainingChunks == 0)
            {
                fileStreamData.fileStream?.Dispose();
                fileStreamData.fileLock.Dispose();
            }

            ulong sizeDownloaded = 0;
            lock (depotDownloadCounter)
            {
                sizeDownloaded = depotDownloadCounter.sizeDownloaded + (ulong)written;
                depotDownloadCounter.sizeDownloaded = sizeDownloaded;
                depotDownloadCounter.depotBytesCompressed += chunk.CompressedLength;
                depotDownloadCounter.depotBytesUncompressed += chunk.UncompressedLength;
            }

            lock (downloadCounter)
            {
                downloadCounter.totalBytesCompressed += chunk.CompressedLength;
                downloadCounter.totalBytesUncompressed += chunk.UncompressedLength;

                Ansi.Progress(downloadCounter.totalBytesUncompressed, downloadCounter.completeDownloadSize);
            }

            if (remainingChunks == 0)
            {
                var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                Console.WriteLine("{0,6:#00.00}% {1}", (sizeDownloaded / (float)depotDownloadCounter.completeDownloadSize) * 100.0f, fileFinalPath);
            }
        }

        class ChunkIdComparer : IEqualityComparer<byte[]>
        {
            public bool Equals(byte[] x, byte[] y)
            {
                if (ReferenceEquals(x, y)) return true;
                if (x == null || y == null) return false;
                return x.SequenceEqual(y);
            }

            public int GetHashCode(byte[] obj)
            {
                ArgumentNullException.ThrowIfNull(obj);

                // ChunkID is SHA-1, so we can just use the first 4 bytes
                return BitConverter.ToInt32(obj, 0);
            }
        }

        static void DumpManifestToTextFile(DepotDownloadInfo depot, DepotManifest manifest)
        {
            var txtManifest = Path.Combine(depot.InstallDir, $"manifest_{depot.DepotId}_{depot.ManifestId}.txt");
            using var sw = new StreamWriter(txtManifest);

            sw.WriteLine($"Content Manifest for Depot {depot.DepotId} ");
            sw.WriteLine();
            sw.WriteLine($"Manifest ID / date     : {depot.ManifestId} / {manifest.CreationTime} ");

            var uniqueChunks = new HashSet<byte[]>(new ChunkIdComparer());

            foreach (var file in manifest.Files)
            {
                foreach (var chunk in file.Chunks)
                {
                    uniqueChunks.Add(chunk.ChunkID);
                }
            }

            sw.WriteLine($"Total number of files  : {manifest.Files.Count} ");
            sw.WriteLine($"Total number of chunks : {uniqueChunks.Count} ");
            sw.WriteLine($"Total bytes on disk    : {manifest.TotalUncompressedSize} ");
            sw.WriteLine($"Total bytes compressed : {manifest.TotalCompressedSize} ");
            sw.WriteLine();
            sw.WriteLine();
            sw.WriteLine("          Size Chunks File SHA                                 Flags Name");

            foreach (var file in manifest.Files)
            {
                var sha1Hash = Convert.ToHexString(file.FileHash).ToLower();
                sw.WriteLine($"{file.TotalSize,14:d} {file.Chunks.Count,6:d} {sha1Hash} {(int)file.Flags,5:x} {file.FileName}");
            }
        }

        // ---------------------- RAW ARCHIVE SUPPORT ----------------------

        public sealed class RawDownloadOptions
        {
            public bool Enabled { get; init; } = true;
            public string OutputRoot { get; init; }
            public bool VerifyChunkSha1 { get; init; } = false;
            public bool SkipExisting { get; init; } = true;
            public bool RespectFileFilters { get; init; } = false;
            public bool EmitDebugManifestJson { get; init; } = false;
            public bool DryRun { get; init; } = false;
        }

        public static async Task DownloadAppRawAsync(
            uint appId,
            List<(uint depotId, ulong manifestId)> depotManifestIds,
            string branch,
            string os,
            string arch,
            string language,
            bool lv,
            RawDownloadOptions options,
            string workshopId = null,
            string workshopName = null)
        {
            if (options == null || !options.Enabled)
            {
                await DownloadAppAsync(appId, depotManifestIds, branch, os, arch, language, lv, false);
                return;
            }

            cdnPool = new CDNClientPool(steam3, appId);

            var outputRoot = options.OutputRoot;
            if (string.IsNullOrWhiteSpace(outputRoot))
            {
                outputRoot = string.IsNullOrWhiteSpace(Config.InstallDirectory) ? DEFAULT_DOWNLOAD_DIR : Config.InstallDirectory;
            }
            Directory.CreateDirectory(outputRoot);

            await steam3?.RequestAppInfo(appId);

            if (!await AccountHasAccess(appId, appId))
            {
                if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser && await steam3.RequestFreeAppLicense(appId))
                {
                    Console.WriteLine("Obtained FreeOnDemand license for app {0}", appId);
                    await steam3.RequestAppInfo(appId, true);
                }
                else
                {
                    var contentName = GetAppName(appId);
                    throw new ContentDownloaderException(string.Format("App {0} ({1}) is not available from this account.", appId, contentName));
                }
            }

            // Skip depot validation for raw mode when we have explicit manifest IDs
            // This allows CSV-based downloads of historical/unlisted depots
            var hasExplicitManifests = depotManifestIds.Count > 0 && depotManifestIds.All(x => x.manifestId != INVALID_MANIFEST_ID);

            if (!hasExplicitManifests)
            {
                // Discover depots similar to normal flow
                var hasSpecificDepots = depotManifestIds.Count > 0;
                var depotIdsFound = new List<uint>();
                var depotIdsExpected = depotManifestIds.Select(x => x.depotId).ToList();
                var depotsSection = GetSteam3AppSection(appId, EAppInfoSection.Depots);

                Console.WriteLine("Using app branch: '{0}'.", branch);

                if (depotsSection != null)
                {
                    foreach (var depotSection in depotsSection.Children)
                    {
                        if (depotSection.Children.Count == 0)
                            continue;

                        if (!uint.TryParse(depotSection.Name, out var id))
                            continue;

                        if (hasSpecificDepots && !depotIdsExpected.Contains(id))
                            continue;

                        if (!hasSpecificDepots)
                        {
                            var depotConfig = depotSection["config"];
                            if (depotConfig != KeyValue.Invalid)
                            {
                                if (!Config.DownloadAllPlatforms &&
                                    depotConfig["oslist"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                                {
                                    var oslist = depotConfig["oslist"].Value.Split(',');
                                    if (Array.IndexOf(oslist, os ?? Util.GetSteamOS()) == -1)
                                        continue;
                                }

                                if (!Config.DownloadAllArchs &&
                                    depotConfig["osarch"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["osarch"].Value))
                                {
                                    var depotArch = depotConfig["osarch"].Value;
                                    if (depotArch != (arch ?? Util.GetSteamArch()))
                                        continue;
                                }

                                if (!Config.DownloadAllLanguages &&
                                    depotConfig["language"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["language"].Value))
                                {
                                    var depotLang = depotConfig["language"].Value;
                                    if (depotLang != (language ?? "english"))
                                        continue;
                                }

                                if (!lv &&
                                    depotConfig["lowviolence"] != KeyValue.Invalid &&
                                    depotConfig["lowviolence"].AsBoolean())
                                    continue;
                            }
                        }

                        depotIdsFound.Add(id);

                        if (!hasSpecificDepots)
                            depotManifestIds.Add((id, INVALID_MANIFEST_ID));
                    }
                }

                if (depotManifestIds.Count == 0 && !hasSpecificDepots)
                {
                    throw new ContentDownloaderException(string.Format("Couldn't find any depots to download for app {0}", appId));
                }

                if (depotIdsFound.Count < depotIdsExpected.Count)
                {
                    var remainingDepotIds = depotIdsExpected.Except(depotIdsFound);
                    throw new ContentDownloaderException(string.Format("Depot {0} not listed for app {1}", string.Join(", ", remainingDepotIds), appId));
                }
            }
            else
            {
                Console.WriteLine("Using app branch: '{0}' (skipping depot validation for explicit manifests).", branch);
            }

            var infos = new List<DepotDownloadInfo>();
            foreach (var (depotId, manifestId) in depotManifestIds)
            {
                var info = await GetDepotInfo(depotId, appId, manifestId, branch, createInstallDirs: false);
                if (info != null)
                {
                    infos.Add(info);
                }
            }

            await cdnPool.UpdateServerList();

            var cts = new CancellationTokenSource();

            foreach (var depot in infos)
            {
                // Keep session alive between depot downloads
                //await KeepSessionAlive(depot.AppId);
                await ArchiveDepotRawAsync(cts, depot, outputRoot, options, workshopId, workshopName);
            }
        }

        private static async Task ArchiveDepotRawAsync(CancellationTokenSource cts, DepotDownloadInfo depot, string outputRoot, RawDownloadOptions options, string workshopId, string workshopName)
        {
            Console.WriteLine("Archiving raw CDN content for depot {0}", depot.DepotId);

            // For raw mode, use a cleaner directory structure: depot/{depotId}/
            // Instead of the standard depots/depot/{depotId}/ structure used by normal downloads
            var depotRoot = Path.Combine("depot", depot.DepotId.ToString());
            var manifestsDir = Path.Combine(depotRoot, "manifest");
            var chunksDir = Path.Combine(depotRoot, "chunk");
            var debugDir = Path.Combine(depotRoot, "debug");

            Directory.CreateDirectory(manifestsDir);
            Directory.CreateDirectory(chunksDir);
            if (options.EmitDebugManifestJson)
                Directory.CreateDirectory(debugDir);

            // Attempt to preload branch key from disk into session cache (if not present)
            string Sanitize(string name)
            {
                foreach (var ch in Path.GetInvalidFileNameChars())
                    name = name.Replace(ch, '_');
                return name;
            }

            if (!string.IsNullOrWhiteSpace(depot.Branch))
            {
                var branchKeyName = $"{Sanitize(depot.Branch)}_Password.branchkey";
                var branchKeyPath = Path.Combine(depotRoot, branchKeyName);
                if (File.Exists(branchKeyPath) && !steam3.AppBetaPasswords.ContainsKey(depot.Branch))
                {
                    try
                    {
                        var keyBytes = await File.ReadAllBytesAsync(branchKeyPath, cts.Token);
                        steam3.AppBetaPasswords[depot.Branch] = keyBytes;
                        Console.WriteLine("Loaded branch key for '{0}' from {1}", depot.Branch, branchKeyName);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Warning: Failed to read branch key at {0}: {1}", branchKeyPath, ex.Message);
                    }
                }
            }

            // If we have a beta password configured and the branch key is not cached, request and save it
            if (!string.IsNullOrEmpty(Config.BetaPassword) && !string.IsNullOrWhiteSpace(depot.Branch) && !steam3.AppBetaPasswords.ContainsKey(depot.Branch))
            {
                try
                {
                    await steam3.CheckAppBetaPassword(depot.AppId, Config.BetaPassword);
                    if (steam3.AppBetaPasswords.TryGetValue(depot.Branch, out var keyBytes))
                    {
                        var branchKeyName = $"{Sanitize(depot.Branch)}_Password.branchkey";
                        var branchKeyPath = Path.Combine(depotRoot, branchKeyName);
                        await File.WriteAllBytesAsync(branchKeyPath, keyBytes, cts.Token);
                        Console.WriteLine("Saved branch key for '{0}' to {1}", depot.Branch, branchKeyName);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Warning: Failed to retrieve/save branch key for '{0}': {1}", depot.Branch, ex.Message);
                }
            }

            // Download or reuse raw manifest zip
            RawManifestResult raw;
            string manifestFileName;

            // If this is a workshop file, use workshop ID and name in the manifest filename (like Python script)
            if (!string.IsNullOrEmpty(workshopId) && !string.IsNullOrEmpty(workshopName))
            {
                var safeName = string.Concat(workshopName.Where(c => char.IsLetterOrDigit(c) || " -_".Contains(c))).Trim();
                safeName = safeName.Replace(' ', '_');
                manifestFileName = $"{workshopId}_{safeName}_{depot.ManifestId}";
            }
            else
            {
                manifestFileName = depot.ManifestId.ToString();
            }

            var manifestV5Path = Path.Combine(manifestsDir, $"{manifestFileName}.manif5");
            var manifestV4Path = Path.Combine(manifestsDir, $"{manifestFileName}.manif4");
            if (File.Exists(manifestV5Path) || File.Exists(manifestV4Path))
            {
                // Keep session alive while processing existing files
                //await KeepSessionAlive(depot.AppId);

                if (options.DryRun)
                {
                    Console.WriteLine("Dry run: existing manifest for depot found: {0}", depot.ManifestId);
                }
                else
                {
                    Console.WriteLine("Reusing existing manifest for depot {0}", depot.DepotId);
                }
                var existingPath = File.Exists(manifestV5Path) ? manifestV5Path : manifestV4Path;
                raw = await LoadRawManifestFromDiskAsync(existingPath, depot, cts.Token);
            }
            else
            {
                // Keep session alive before downloading new manifest
                //await KeepSessionAlive(depot.AppId);

                // Add delay in downloading the manifests to avoid hammering the CDN
                await Task.Delay(500, cts.Token);
                raw = await DownloadRawManifestZipAndDetectAsync(cts, depot);
                var finalManifestPath = Path.Combine(manifestsDir, $"{manifestFileName}.manif{raw.Version}");
                await File.WriteAllBytesAsync(finalManifestPath, raw.ZipBytes, cts.Token);
            }

            // Optional: emit debug json for the manifest
            if (options.EmitDebugManifestJson)
            {
                var debugJsonPath = Path.Combine(debugDir, $"{manifestFileName}.{raw.Version}.json");
                if (!File.Exists(debugJsonPath))
                {
                    var debugModel = BuildManifestDebugModel(depot.DepotId, raw.ParsedManifest, raw.Version, raw.EncryptedNames);
                    await File.WriteAllTextAsync(debugJsonPath, System.Text.Json.JsonSerializer.Serialize(debugModel, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }), cts.Token);
                }
            }

            // Save depot key as '<depotId>.depotkey'
            var depotKeyPath = Path.Combine(depotRoot, $"{depot.DepotId}.depotkey");
            if (!File.Exists(depotKeyPath))
            {
                await File.WriteAllBytesAsync(depotKeyPath, depot.DepotKey, cts.Token);
            }

            if (options.DryRun)
            {
                Console.WriteLine("Depot {0} - dry run complete (manifest saved, no chunks downloaded)", depot.DepotId);
                return;
            }

            // Decide which chunks to save
            IEnumerable<DepotManifest.FileData> filesToUse = raw.ParsedManifest.Files;
            if (options.RespectFileFilters && Config.UsingFileList)
            {
                filesToUse = filesToUse.Where(f => TestIsFileIncluded(f.FileName));
            }

            var unique = new HashSet<byte[]>(new ChunkIdComparer());
            var chunks = new List<DepotManifest.ChunkData>();
            foreach (var f in filesToUse)
            {
                foreach (var ch in f.Chunks)
                {
                    if (unique.Add(ch.ChunkID))
                    {
                        chunks.Add(ch);
                    }
                }
            }

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Config.MaxDownloads,
                CancellationToken = cts.Token
            };

            var progressTracker = new ChunkProgressTracker
            {
                Total = (ulong)chunks.Count
            };

            Console.WriteLine("Depot {0} - processing {1} chunks...", depot.DepotId, progressTracker.Total);
            Ansi.Progress(Ansi.ProgressState.Default, 0);

            await Parallel.ForEachAsync(chunks, parallelOptions, async (chunk, token) =>
            {
                await DownloadChunkToArchiveAsync(cts, depot, chunk, chunksDir, options, progressTracker);
            });

            Ansi.Progress(Ansi.ProgressState.Hidden);
            progressTracker.ShowFinalStats(depot.DepotId);

            Console.WriteLine("Depot {0} - raw archive complete", depot.DepotId);
        }

        // Helper result for raw manifest download/detection
        private sealed class RawManifestResult
        {
            public required byte[] ZipBytes { get; init; }
            public required byte[] PayloadBytes { get; init; }
            public required int Version { get; init; }
            public required DepotManifest ParsedManifest { get; init; }
            public required List<string> EncryptedNames { get; init; }
        }

        // Build CDN URI similar to SteamKit's BuildCommand
        private static Uri BuildCdnUri(Server server, string command, string query, Server proxyServer)
        {
            var uriBuilder = new UriBuilder
            {
                Scheme = server.Protocol == Server.ConnectionProtocol.HTTP ? "http" : "https",
                Host = server.VHost,
                Port = server.Port,
                Path = command,
                Query = query ?? string.Empty,
            };

            if (proxyServer != null && proxyServer.UseAsProxy && proxyServer.ProxyRequestPathTemplate != null)
            {
                var pathTemplate = proxyServer.ProxyRequestPathTemplate;
                pathTemplate = pathTemplate.Replace("%host%", uriBuilder.Host, StringComparison.Ordinal);
                pathTemplate = pathTemplate.Replace("%path%", $"/{uriBuilder.Path}", StringComparison.Ordinal);
                uriBuilder.Scheme = proxyServer.Protocol == Server.ConnectionProtocol.HTTP ? "http" : "https";
                uriBuilder.Host = proxyServer.VHost;
                uriBuilder.Port = proxyServer.Port;
                uriBuilder.Path = pathTemplate;
            }

            return uriBuilder.Uri;
        }

        // Download the raw manifest zip, detect version from payload magic (0x16349781), and parse manifest from payload
        private static async Task<RawManifestResult> DownloadRawManifestZipAndDetectAsync(CancellationTokenSource cts, DepotDownloadInfo depot)
        {
            const uint V4_MAGIC = 0x16349781;

            byte[] zipBytes = null;
            byte[] payloadBytes = null;
            DepotManifest parsed = null;
            int detectedVersion = 5;
            List<string> encryptedNames = null;

            ulong manifestRequestCode = 0;
            var manifestRequestCodeExpiration = DateTime.MinValue;

            do
            {
                cts.Token.ThrowIfCancellationRequested();

                Server connection = null;

                try
                {
                    connection = cdnPool.GetConnection();

                    string cdnToken = null;
                    if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                    {
                        var result = await authTokenCallbackPromise.Task;
                        cdnToken = result.Token;
                    }

                    // ADD DELAY HERE - after connection but before request
                    // This distributes timing across parallel downloads
                    await Task.Delay(Random.Shared.Next(100, 1000), cts.Token);

                    var now = DateTime.Now;

                    if (manifestRequestCode == 0 || now >= manifestRequestCodeExpiration)
                    {
                        manifestRequestCode = await steam3.GetDepotManifestRequestCodeAsync(
                            depot.DepotId,
                            depot.AppId,
                            depot.ManifestId,
                            depot.Branch);
                        manifestRequestCodeExpiration = now.Add(TimeSpan.FromMinutes(5));

                        if (manifestRequestCode == 0)
                        {
                            cts.Cancel();
                        }
                    }

                    // Build the request URL similar to SteamKit2
                    const uint MANIFEST_VERSION = 5;
                    string path;
                    if (manifestRequestCode > 0)
                        path = $"depot/{depot.DepotId}/manifest/{depot.ManifestId}/{MANIFEST_VERSION}/{manifestRequestCode}";
                    else
                        path = $"depot/{depot.DepotId}/manifest/{depot.ManifestId}/{MANIFEST_VERSION}";

                    var requestUri = BuildCdnUri(connection, path, cdnToken, cdnPool.ProxyServer);

                    using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

                    using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    using var response = await HttpClientFactory.CreateHttpClient().SendAsync(
                        request,
                        HttpCompletionOption.ResponseHeadersRead,
                        connectCts.Token).ConfigureAwait(false);

                    if (!response.IsSuccessStatusCode)
                    {
                        throw new SteamKitWebRequestException($"Response status code does not indicate success: {(int)response.StatusCode} ({response.ReasonPhrase}).", response);
                    }

                    using (var bodyCts = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
                    {
                        zipBytes = await response.Content.ReadAsByteArrayAsync(bodyCts.Token).ConfigureAwait(false);
                    }

                    // We got the raw zip, now unzip and read the single entry payload
                    using (var msZip = new MemoryStream(zipBytes, writable: false))
                    using (var zip = new ZipArchive(msZip, ZipArchiveMode.Read, leaveOpen: false))
                    {
                        if (zip.Entries.Count == 0)
                            throw new InvalidDataException("Manifest zip did not contain any entries");

                        using var entryStream = zip.Entries[0].Open();
                        using var msPayload = new MemoryStream();
                        await entryStream.CopyToAsync(msPayload, cts.Token).ConfigureAwait(false);
                        payloadBytes = msPayload.ToArray();
                    }

                    // Detect version by first 4 bytes in payload
                    if (payloadBytes.Length >= 4)
                    {
                        uint header = BitConverter.ToUInt32(payloadBytes, 0);
                        if (header == V4_MAGIC)
                            detectedVersion = 4;
                        else
                            detectedVersion = 5;
                    }

                    // Parse manifest from payload for further processing (and decrypt filenames if we can)
                    using (var ms = new MemoryStream(payloadBytes, writable: false))
                    {
                        parsed = DepotManifest.Deserialize(ms);
                    }

                    // Capture original names as they appear in the manifest before decryption (encrypted for v5)
                    encryptedNames = parsed.Files.Select(f => f.FileName).ToList();

                    if (depot.DepotKey != null && depot.DepotKey.Length > 0)
                    {
                        try { parsed.DecryptFilenames(depot.DepotKey); } catch { /* ignore */ }
                    }

                    cdnPool.ReturnConnection(connection);
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("Connection timeout downloading depot manifest {0} {1}. Retrying.", depot.DepotId, depot.ManifestId);
                }
                catch (SteamKitWebRequestException e)
                {

                    if (e.StatusCode == HttpStatusCode.Forbidden &&
                        (!steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise) || !authTokenCallbackPromise.Task.IsCompleted))
                    {
                        await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                        cdnPool.ReturnConnection(connection);
                        continue;
                    }

                    cdnPool.ReturnBrokenConnection(connection);

                    if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                    {
                        Console.WriteLine("Encountered {2} for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId, (int)e.StatusCode);
                        break;
                    }

                    if (e.StatusCode == HttpStatusCode.NotFound)
                    {
                        Console.WriteLine("Encountered 404 for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId);
                        break;
                    }

                    // ADD EXPONENTIAL BACKOFF FOR ERRORS
                    if (e.StatusCode == HttpStatusCode.ServiceUnavailable ||
                        e.StatusCode == HttpStatusCode.NotFound)
                    {
                        var delay = Random.Shared.Next(500, 2000);
                        await Task.Delay(delay, cts.Token);
                    }

                    Console.WriteLine("Encountered error downloading depot manifest {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.StatusCode);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    cdnPool.ReturnBrokenConnection(connection);
                    Console.WriteLine("Encountered error downloading manifest for depot {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.Message);
                }
            } while (parsed == null || zipBytes == null || payloadBytes == null);

            if (parsed == null || zipBytes == null || payloadBytes == null)
            {
                Console.WriteLine("\nUnable to download manifest {0} for depot {1}", depot.ManifestId, depot.DepotId);
                cts.Cancel();
                cts.Token.ThrowIfCancellationRequested();
            }

            return new RawManifestResult
            {
                ZipBytes = zipBytes,
                PayloadBytes = payloadBytes,
                Version = detectedVersion,
                ParsedManifest = parsed,
                EncryptedNames = encryptedNames ?? new List<string>()
            };
        }

        private static RawManifestResult ParseManifestZipBytes(byte[] zipBytes, DepotDownloadInfo depot)
        {
            const uint V4_MAGIC = 0x16349781;

            byte[] payloadBytes;
            DepotManifest parsed;
            int detectedVersion = 5;

            using (var msZip = new MemoryStream(zipBytes, writable: false))
            using (var zip = new ZipArchive(msZip, ZipArchiveMode.Read, leaveOpen: false))
            {
                if (zip.Entries.Count == 0)
                    throw new InvalidDataException("Manifest zip did not contain any entries");

                using var entryStream = zip.Entries[0].Open();
                using var msPayload = new MemoryStream();
                entryStream.CopyTo(msPayload);
                payloadBytes = msPayload.ToArray();
            }

            if (payloadBytes.Length >= 4)
            {
                uint header = BitConverter.ToUInt32(payloadBytes, 0);
                detectedVersion = header == V4_MAGIC ? 4 : 5;
            }

            using (var ms = new MemoryStream(payloadBytes, writable: false))
            {
                parsed = DepotManifest.Deserialize(ms);
            }

            var encryptedNames = parsed.Files.Select(f => f.FileName).ToList();

            if (depot.DepotKey != null && depot.DepotKey.Length > 0)
            {
                try { parsed.DecryptFilenames(depot.DepotKey); } catch { /* ignore */ }
            }

            return new RawManifestResult
            {
                ZipBytes = zipBytes,
                PayloadBytes = payloadBytes,
                Version = detectedVersion,
                ParsedManifest = parsed,
                EncryptedNames = encryptedNames
            };
        }

        private static async Task<RawManifestResult> LoadRawManifestFromDiskAsync(string path, DepotDownloadInfo depot, CancellationToken ct)
        {
            var zip = await File.ReadAllBytesAsync(path, ct);
            return ParseManifestZipBytes(zip, depot);
        }

        private static object BuildManifestDebugModel(uint depotId, DepotManifest manifest, int version, List<string> encryptedNames)
        {
            string Hex(byte[] bytes) => bytes == null ? null : Convert.ToHexString(bytes).ToLowerInvariant();

            // Pair encrypted names with files by index (order preserved through decryption)
            var pairs = manifest.Files.Select((f, i) => new { File = f, Encrypted = (encryptedNames != null && i < encryptedNames.Count) ? encryptedNames[i] : null });

            return new
            {
                depot_id = depotId,
                gid = manifest.ManifestGID,
                creation_time = manifest.CreationTime,
                filenames_encrypted = manifest.FilenamesEncrypted,
                version = version,
                total_uncompressed_size = manifest.TotalUncompressedSize,
                total_compressed_size = manifest.TotalCompressedSize,
                mappings = pairs.Select(p => new
                {
                    encryptedName = p.Encrypted,
                    decryptedName = p.File.FileName,
                    size = p.File.TotalSize,
                    flags = (int)p.File.Flags,
                    sha_content = Hex(p.File.FileHash),
                    // v4-like filename hash from normalized path
                    sha_filename = Hex(SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(p.File.FileName.Replace('/', '\\').ToLowerInvariant()))),
                    chunks = p.File.Chunks.Select(c => new
                    {
                        sha = Hex(c.ChunkID),
                        crc = c.Checksum,
                        offset = c.Offset,
                        cb_original = c.UncompressedLength,
                        cb_compressed = c.CompressedLength
                    })
                })
            };
        }

        private static async Task DownloadChunkToArchiveAsync(
            CancellationTokenSource cts,
            DepotDownloadInfo depot,
            DepotManifest.ChunkData chunk,
            string chunksRoot,
            RawDownloadOptions options,
            ChunkProgressTracker progressTracker)
        {
            var chunkID = Convert.ToHexString(chunk.ChunkID).ToLowerInvariant();
            var chunkPath = Path.Combine(chunksRoot, chunkID);

            if (options.SkipExisting && File.Exists(chunkPath))
            {
                var fi = new FileInfo(chunkPath);
                if ((ulong)fi.Length == chunk.CompressedLength)
                {
                    if (options.VerifyChunkSha1)
                    {
                        using var fs = File.OpenRead(chunkPath);
                        var sha = SHA1.HashData(fs);
                        var shaHex = Convert.ToHexString(sha).ToLowerInvariant();
                        if (shaHex == chunkID)
                        {
                            progressTracker.IncrementSkipped();
                            return;
                        }
                    }
                    else
                    {
                        progressTracker.IncrementSkipped();
                        return;
                    }
                }
            }

            var written = 0;
            var buffer = ArrayPool<byte>.Shared.Rent((int)chunk.CompressedLength);

            try
            {
                do
                {
                    cts.Token.ThrowIfCancellationRequested();

                    Server connection = null;
                    try
                    {
                        connection = cdnPool.GetConnection();

                        string cdnToken = null;
                        if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                        {
                            var result = await authTokenCallbackPromise.Task;
                            cdnToken = result.Token;
                        }

                        // ADD DELAY HERE - after connection but before request
                        // This distributes timing across parallel downloads
                        // await Task.Delay(Random.Shared.Next(100, 800), cts.Token);

                        DebugLog.WriteLine("ContentDownloader", "Downloading chunk {0} from {1} with {2}", chunkID, connection, cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                        written = await cdnPool.CDNClient.DownloadDepotChunkAsync(
                            depot.DepotId,
                            chunk,
                            connection,
                            buffer,
                            null, // Pass null depot key to get raw compressed data
                            cdnPool.ProxyServer,
                            cdnToken).ConfigureAwait(false);

                        cdnPool.ReturnConnection(connection);

                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Connection timeout downloading chunk {0}", chunkID);
                        cdnPool.ReturnBrokenConnection(connection);
                    }
                    catch (SteamKitWebRequestException e)
                    {

                        if (e.StatusCode == HttpStatusCode.Forbidden &&
                            (!steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise) || !authTokenCallbackPromise.Task.IsCompleted))
                        {
                            await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                            cdnPool.ReturnConnection(connection);

                            continue;
                        }

                        cdnPool.ReturnBrokenConnection(connection);

                        if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                        {
                            Console.WriteLine("Encountered {2} for chunk {0}. Aborting.", chunkID, (int)e.StatusCode);
                            break;
                        }

                        // ADD EXPONENTIAL BACKOFF FOR ERRORS
                        if (e.StatusCode == HttpStatusCode.ServiceUnavailable ||
                            e.StatusCode == HttpStatusCode.NotFound)
                        {
                            var delay = Random.Shared.Next(500, 2000);
                            await Task.Delay(delay, cts.Token);
                        }

                        Console.WriteLine("Encountered error downloading chunk {0}: {1}", chunkID, e.StatusCode);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        cdnPool.ReturnBrokenConnection(connection);
                        Console.WriteLine("Encountered unexpected error downloading chunk {0}: {1}", chunkID, e.Message);
                    }
                } while (written == 0);

                if (written == 0)
                {
                    Console.WriteLine("Failed to download chunk {0} for depot {1}. Aborting.", chunkID, depot.DepotId);
                    cts.Cancel();
                }

                cts.Token.ThrowIfCancellationRequested();

                using var fs = File.Open(chunkPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                await fs.WriteAsync(buffer.AsMemory(0, written), cts.Token);

                if (options.VerifyChunkSha1)
                {
                    fs.Position = 0;
                    var sha = SHA1.HashData(fs);
                    var shaHex = Convert.ToHexString(sha).ToLowerInvariant();
                    if (shaHex != chunkID)
                    {
                        Console.WriteLine("Warning: SHA1 mismatch for chunk {0}.", chunkID);
                    }
                }

                progressTracker.IncrementDownloaded();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public static async Task<List<(uint depotId, ulong manifestId)>> ResolveEncryptedManifestIdsAsync(
            uint appId,
            List<(uint depotId, string encHex)> encrypted,
            string branch,
            string outputRootForKeys)
        {
            if (string.IsNullOrWhiteSpace(branch))
                branch = DEFAULT_BRANCH;

            // Ensure server list is ready for any beta password operations
            cdnPool ??= new CDNClientPool(steam3, appId);
            await steam3?.RequestAppInfo(appId);

            // Attempt to load branch key from disk if not present
            async Task EnsureBranchKeyAsync(uint depotId)
            {
                if (steam3.AppBetaPasswords.ContainsKey(branch))
                    return;

                // Branch key file lives at raw depot root: depot/{depotId}/
                var depotRoot = Path.Combine("depot", depotId.ToString());
                var branchKeyName = $"{Sanitize(branch)}_Password.branchkey";
                var branchKeyPath = Path.Combine(depotRoot, branchKeyName);
                if (File.Exists(branchKeyPath))
                {
                    try
                    {
                        var keyBytes = await File.ReadAllBytesAsync(branchKeyPath);
                        steam3.AppBetaPasswords[branch] = keyBytes;
                        Console.WriteLine("Loaded branch key for '{0}' from {1}", branch, branchKeyName);
                        return;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Warning: Failed to read branch key at {0}: {1}", branchKeyPath, ex.Message);
                    }
                }

                if (!string.IsNullOrEmpty(Config.BetaPassword))
                {
                    await steam3.CheckAppBetaPassword(appId, Config.BetaPassword);
                    if (steam3.AppBetaPasswords.TryGetValue(branch, out var key))
                    {
                        // Save for reuse
                        Directory.CreateDirectory(depotRoot);
                        await File.WriteAllBytesAsync(branchKeyPath, key);
                        Console.WriteLine("Saved branch key for '{0}' to {1}", branch, branchKeyName);
                    }
                }
            }

            var result = new List<(uint depotId, ulong manifestId)>();

            foreach (var (depotId, encHex) in encrypted)
            {
                await EnsureBranchKeyAsync(depotId);

                if (!steam3.AppBetaPasswords.TryGetValue(branch, out var keyBytes))
                {
                    throw new ContentDownloaderException($"No branch key available for '{branch}'. Provide -branchpassword or place {Sanitize(branch)}_Password.branchkey next to the depot.");
                }

                // Encrypted manifest IDs are hex strings, decrypt with AES-256-ECB using branch key
                var encBytes = Util.DecodeHexString(encHex);
                if (encBytes == null)
                {
                    throw new ContentDownloaderException($"Invalid -manifest-enc hex: {encHex}");
                }

                try
                {
                    var dec = Util.SymmetricDecryptECB(encBytes, keyBytes);
                    // Steam stores manifest GID as 64-bit unsigned Little Endian in decrypted blob (first 8 bytes)
                    if (dec.Length < 8)
                        throw new InvalidDataException("Decrypted manifest id blob too short");

                    var gid = BitConverter.ToUInt64(dec, 0);
                    result.Add((depotId, gid));
                }
                catch (Exception ex)
                {
                    throw new ContentDownloaderException($"Failed to decrypt manifest id for depot {depotId}: {ex.Message}");
                }
            }

            return result;

            static string Sanitize(string name)
            {
                foreach (var ch in Path.GetInvalidFileNameChars())
                    name = name.Replace(ch, '_');
                return name;
            }
        }

        public static async Task DownloadPubfileRawAsync(uint appId, ulong publishedFileId, RawDownloadOptions options)
        {
            var details = await steam3.GetPublishedFileDetails(appId, publishedFileId);

            if (!string.IsNullOrEmpty(details?.file_url))
            {
                // Ancient UGC - direct URL download to UGC folder (raw mode doesn't change this)
                await DownloadWebFileToUGCAsync(appId, publishedFileId, details.filename, details.file_url, details.file_size.ToString());
            }
            else if (details?.hcontent_file > 0)
            {
                // Modern UGC - manifest-based content, use raw archiving
                Console.WriteLine("Retrieved data for workshop item {0}: '{1}' for app {2}", publishedFileId, details.title, details.consumer_appid);
                await DownloadAppRawAsync(details.consumer_appid, new List<(uint, ulong)> { (details.consumer_appid, details.hcontent_file) }, DEFAULT_BRANCH, null, null, null, false, options, publishedFileId.ToString(), details.title);
            }
            else
            {
                Console.WriteLine("Unable to locate manifest ID for published file {0}", publishedFileId);
            }
        }

        public static async Task DownloadUGCRawAsync(uint appId, ulong ugcId, RawDownloadOptions options)
        {
            SteamCloud.UGCDetailsCallback details = null;

            if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser)
            {
                details = await steam3.GetUGCDetails(ugcId);
            }
            else
            {
                Console.WriteLine($"Unable to query UGC details for {ugcId} from an anonymous account");
            }

            if (!string.IsNullOrEmpty(details?.URL))
            {
                // Ancient UGC - direct URL download to UGC folder (raw mode doesn't change this)
                await DownloadWebFileToUGCAsync(appId, ugcId, details.FileName, details.URL, details.FileSize.ToString());
            }
            else
            {
                // Modern UGC - manifest-based content, use raw archiving
                await DownloadAppRawAsync(appId, [(appId, ugcId)], DEFAULT_BRANCH, null, null, null, false, options, ugcId.ToString(), details?.FileName);
            }
        }

        public static async Task DownloadWorkshopItemAsync(uint appId, ulong workshopId)
        {
            // Try to get published file details first
            try
            {
                var details = await steam3.GetPublishedFileDetails(appId, workshopId);
                if (details != null)
                {
                    await DownloadPubfileAsync(appId, workshopId);
                    return;
                }
            }
            catch
            {
                // Fall back to UGC
            }

            // Try UGC if published file failed
            await DownloadUGCAsync(appId, workshopId);
        }

        public static async Task DownloadWorkshopItemRawAsync(uint appId, ulong workshopId, RawDownloadOptions options)
        {
            // Try to get published file details first
            try
            {
                var details = await steam3.GetPublishedFileDetails(appId, workshopId);
                if (details != null)
                {
                    await DownloadPubfileRawAsync(appId, workshopId, options);
                    return;
                }
            }
            catch
            {
                // Fall back to UGC
            }

            // Try UGC if published file failed
            await DownloadUGCRawAsync(appId, workshopId, options);
        }

        // Add simple session keepalive for long operations
        private static DateTime lastSessionActivity = DateTime.Now;

        // Call this periodically during long operations to keep session alive
        private static async Task KeepSessionAlive(uint? appId = null)
        {
            // Only check every 60 seconds to avoid spam
            if (DateTime.Now - lastSessionActivity < TimeSpan.FromSeconds(60))
                return;

            if (steam3?.IsLoggedOn == true)
            {
                // Simple keepalive - request app info for a known app to keep session active
                try
                {
                    var targetAppId = appId ?? 753;
                    await steam3.RequestAppInfo(targetAppId, true);
                    lastSessionActivity = DateTime.Now;
                }
                catch
                {
                    // Ignore errors, just don't update lastSessionActivity
                }
            }
        }
    }
}
