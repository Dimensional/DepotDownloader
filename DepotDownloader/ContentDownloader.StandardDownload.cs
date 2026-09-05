// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    static partial class ContentDownloader
    {
        #region Standard Download

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
                var info = await GetDepotInfo(depotId, appId, manifestId, branch, workshopId: isUgc ? workshopId : null);
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

        static async Task<DepotDownloadInfo> GetDepotInfo(uint depotId, uint appId, ulong manifestId, string branch, bool createInstallDirs = true, string workshopId = null)
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

                // Workshop/UGC items share one app-wide "workshopdepot" depot id, so without this
                // every item would collide into the same installDir - and a later item's
                // file-diff-against-previous-manifest logic could delete files that belong to an
                // earlier, unrelated item. Nest each item under its own subfolder instead.
                if (!string.IsNullOrEmpty(workshopId))
                {
                    installDir = Path.Combine(installDir, workshopId);
                    Directory.CreateDirectory(installDir);
                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
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

        private sealed record ChunkRetryEntry(DepotManifest.ChunkData Chunk, int Failures, DateTime RetryAfter = default);

        private class ChunkProgressTracker
        {
            public ulong Total;
            public ulong Downloaded;
            public ulong Skipped;
            public ulong Failed;
            public ulong Completed => Downloaded + Skipped + Failed;
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

            public void IncrementFailed()
            {
                Interlocked.Increment(ref Failed);
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
                        Console.Write($"\rProgress: {Util.FormatProgress(completed, Total)} chunks - {Downloaded} downloaded, {Skipped} skipped, {Failed} failed");
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
                Console.WriteLine("Depot {0} - {1}/{2} chunks processed ({3} downloaded, {4} skipped, {5} failed)",
                    depotId, Completed, Total, Downloaded, Skipped, Failed);
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
                            var action = await HandleCdnRequestExceptionAsync(e, connection, depot.AppId, depot.DepotId, cts.Token);

                            if (action == CdnFailureAction.RetryImmediately)
                                continue;

                            if (action == CdnFailureAction.Abort)
                            {
                                Console.WriteLine("Encountered {2} for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId, (int)e.StatusCode);
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

            var chunkID = Util.ToHex(chunk.ChunkID);

            var written = 0;
            var attempts = 0;
            var chunkBuffer = ArrayPool<byte>.Shared.Rent((int)chunk.UncompressedLength);

            try
            {
                do
                {
                    cts.Token.ThrowIfCancellationRequested();
                    attempts++;

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

                        // Optional validation during download
                        if (written > 0 && Config.ValidateDownloadedChunks)
                        {
                            var validationResult = ChunkValidator.ValidateDecompressedChunk(
                                chunkBuffer.AsSpan(0, written),
                                chunk);

                            if (!validationResult.IsValid)
                            {
                                Console.WriteLine("Warning: Downloaded chunk {0} failed validation: {1}",
                                    chunkID, validationResult.ErrorMessage);
                                written = 0; // Force retry
                                // Treat like a bad server response - rotate away from this connection
                                // instead of retrying the same one that just served corrupt bytes.
                                cdnPool.ReturnBrokenConnection(connection);
                                continue;
                            }
                        }

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
                        // notFoundIsFatal: false - chunk data for very old releases can be in cold
                        // storage and briefly 404 until Steam promotes it; a later retry succeeds
                        // (the shared helper backs off on 404 here the same as it does for 503).
                        var action = await HandleCdnRequestExceptionAsync(e, connection, depot.AppId, depot.DepotId, cts.Token, notFoundIsFatal: false);

                        if (action == CdnFailureAction.RetryImmediately)
                            continue;

                        if (action == CdnFailureAction.Abort)
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
                    // Generous backstop: chunk data for very old releases can need several
                    // retries while Steam promotes it out of cold storage, so this only exists to
                    // stop a chunk failing for some other, truly ongoing reason from retrying
                    // forever - it should never trigger during legitimate cold-storage recovery.
                } while (written == 0 && attempts < MaxTransientChunkAttempts);

                if (written == 0)
                {
                    if (attempts >= MaxTransientChunkAttempts)
                        Console.WriteLine("Chunk {0} still failing after {1} attempts.", chunkID, attempts);

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
                var sha1Hash = Util.ToHex(file.FileHash);
                sw.WriteLine($"{file.TotalSize,14:d} {file.Chunks.Count,6:d} {sha1Hash} {(int)file.Flags,5:x} {file.FileName}");
            }
        }

        #endregion
    }
}
