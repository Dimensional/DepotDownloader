// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    static partial class ContentDownloader
    {
        #region Raw Download

        public sealed class RawDownloadOptions
        {
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
            if (options == null)
            {
                await DownloadAppAsync(appId, depotManifestIds, branch, os, arch, language, lv, false);
                return;
            }

            cdnPool = new CDNClientPool(steam3, appId);

            var outputRoot = ResolveOutputRoot(options.OutputRoot);
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

            // IMPORTANT: make cancellation per-depot so one failure won't cancel the entire app or CSV batch
            foreach (var depot in infos)
            {
                using var cts = new CancellationTokenSource();
                try
                {
                    await ArchiveDepotRawAsync(cts, depot, outputRoot, options, workshopId, workshopName);
                }
                catch (ContentDownloaderException ex)
                {
                    Console.WriteLine("Warning: Skipping depot {0} manifest {1}: {2}", depot.DepotId, depot.ManifestId, ex.Message);
                    // continue with next manifest
                }
                catch (OperationCanceledException ex)
                {
                    Console.WriteLine("Warning: Operation cancelled for depot {0} manifest {1}: {2}", depot.DepotId, depot.ManifestId, ex.Message);
                    // continue with next manifest
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Warning: Unexpected error archiving depot {0} manifest {1}: {2}", depot.DepotId, depot.ManifestId, ex.Message);
                    // continue with next manifest
                }
            }
        }

        private static async Task ArchiveDepotRawAsync(CancellationTokenSource cts, DepotDownloadInfo depot, string outputRoot, RawDownloadOptions options, string workshopId, string workshopName)
        {
            Console.WriteLine("Archiving raw CDN content for depot {0}", depot.DepotId);

            // For raw mode, use a cleaner directory structure: depot/{depotId}/
            // Instead of the standard depots/depot/{depotId}/ structure used by normal downloads
            var depotRoot = Path.Combine(outputRoot, "depot", depot.DepotId.ToString());
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
                var branchKeyName = $"{Sanitize(depot.Branch)}.branchkey";
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
                        var branchKeyName = $"{Sanitize(depot.Branch)}.branchkey";
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

            var progressTracker = new ChunkProgressTracker
            {
                Total = (ulong)chunks.Count
            };

            Console.WriteLine("Depot {0} - processing {1} chunks...", depot.DepotId, progressTracker.Total);
            Ansi.Progress(Ansi.ProgressState.Default, 0);

            // Sliding retry queue: workers pull one entry at a time. On a transient failure the
            // chunk is re-enqueued at the back with an incremented attempt count, up to the
            // generous shared MaxTransientChunkAttempts backstop - same understanding as the
            // standard downloader's per-chunk loop, which retries far past any small fixed cap
            // (chunk data for very old releases can sit in cold storage and 404/503 for a while
            // before a retry succeeds). A permanent failure (401/403) gives up immediately
            // instead, same as standard - but only on that one chunk, not the whole batch (unlike
            // standard, which cancels the entire download on a permanent chunk failure; a single
            // inaccessible chunk out of a large raw archive shouldn't sink everything else in it).
            // The channel is marked complete only after every entry has either succeeded or given
            // up for good, so all worker slots stay busy with forward-progressing work.
            var channel = Channel.CreateUnbounded<ChunkRetryEntry>(new UnboundedChannelOptions
            {
                SingleWriter = false,
                SingleReader = false,
            });

            foreach (var chunk in chunks)
                await channel.Writer.WriteAsync(new ChunkRetryEntry(chunk, 0), cts.Token);

            var pending = chunks.Count;

            var workerTasks = Enumerable.Range(0, Config.MaxDownloads).Select(_ => Task.Run(async () =>
            {
                await foreach (var entry in channel.Reader.ReadAllAsync(cts.Token))
                {
                    cts.Token.ThrowIfCancellationRequested();

                    // If this chunk was re-enqueued after a failure, wait until it is eligible
                    // for retry so we don't immediately hammer the same CDN endpoint again.
                    if (entry.RetryAfter != default)
                    {
                        var delay = entry.RetryAfter - DateTime.UtcNow;
                        if (delay > TimeSpan.Zero)
                            await Task.Delay(delay, cts.Token);
                    }

                    ChunkAttemptResult result;
                    try
                    {
                        result = await TryDownloadChunkToArchiveAsync(cts, depot, entry.Chunk, chunksDir, options, progressTracker);
                    }
                    catch (OperationCanceledException)
                    {
                        // CTS was cancelled (e.g. auth failure on another chunk). Count this
                        // chunk as failed so pending reaches zero and the channel closes cleanly.
                        var chunkID = Util.ToHex(entry.Chunk.ChunkID);
                        Console.WriteLine("Chunk {0} abandoned due to cancellation.", chunkID);
                        progressTracker.IncrementFailed();
                        if (Interlocked.Decrement(ref pending) == 0)
                            channel.Writer.TryComplete();
                        return;
                    }
                    catch (Exception e)
                    {
                        // Unexpected escape from TryDownloadChunkToArchiveAsync — treat as a
                        // transient failure so the chunk is not silently dropped from pending,
                        // and gets another attempt rather than being permanently abandoned.
                        var chunkID = Util.ToHex(entry.Chunk.ChunkID);
                        Console.WriteLine("Chunk {0} encountered unexpected worker error: {1}", chunkID, e.Message);
                        result = ChunkAttemptResult.TransientFailure;
                    }

                    if (result == ChunkAttemptResult.Success)
                    {
                        // Decrement and close channel when all work is done
                        if (Interlocked.Decrement(ref pending) == 0)
                            channel.Writer.TryComplete();
                    }
                    else if (result == ChunkAttemptResult.PermanentFailure)
                    {
                        var chunkID = Util.ToHex(entry.Chunk.ChunkID);
                        Console.WriteLine("Chunk {0} permanently failed and will not be retried.", chunkID);
                        progressTracker.IncrementFailed();
                        if (Interlocked.Decrement(ref pending) == 0)
                            channel.Writer.TryComplete();
                    }
                    else
                    {
                        // Transient failure: back to the end of the queue for another attempt
                        // later - same understanding as the standard downloader's chunk loop,
                        // which also retries well past what a fixed small cap would allow (chunk
                        // data for very old releases can need several attempts before Steam
                        // serves it from cold storage). Bounded only by the same generous,
                        // effectively-never-hit-legitimately backstop standard now shares too -
                        // this chunk keeps failing on this batch but doesn't sink the rest of it,
                        // unlike a genuine permanent failure elsewhere in standard's loop.
                        var nextAttempts = entry.Failures + 1;
                        if (nextAttempts >= MaxTransientChunkAttempts)
                        {
                            var chunkID = Util.ToHex(entry.Chunk.ChunkID);
                            Console.WriteLine("Chunk {0} still failing after {1} attempts and will not be retried further.", chunkID, nextAttempts);
                            progressTracker.IncrementFailed();
                            if (Interlocked.Decrement(ref pending) == 0)
                                channel.Writer.TryComplete();
                        }
                        else if (!channel.Writer.TryWrite(new ChunkRetryEntry(entry.Chunk, nextAttempts, DateTime.UtcNow.AddSeconds(5))))
                        {
                            // Channel already closed (cancellation race) - count as failed
                            // instead of retrying into a dead channel.
                            var chunkID = Util.ToHex(entry.Chunk.ChunkID);
                            Console.WriteLine("Chunk {0} could not be re-enqueued (channel closed).", chunkID);
                            progressTracker.IncrementFailed();
                            if (Interlocked.Decrement(ref pending) == 0)
                                channel.Writer.TryComplete();
                        }
                    }
                }
            }, cts.Token)).ToArray();

            await Task.WhenAll(workerTasks);

            // Drain any chunks still sitting in the channel that workers never got to pick up
            // (e.g. CTS was cancelled while entries were queued but undequeued).
            while (channel.Reader.TryRead(out var unprocessed))
            {
                var chunkID = Util.ToHex(unprocessed.Chunk.ChunkID);
                Console.WriteLine("Chunk {0} not processed (operation cancelled).", chunkID);
                progressTracker.IncrementFailed();
            }

            Ansi.Progress(Ansi.ProgressState.Hidden);
            progressTracker.ShowFinalStats(depot.DepotId);

            if (progressTracker.Failed > 0)
                Console.WriteLine("Warning: {0} chunk(s) could not be downloaded for depot {1} (permanent error, or {2} attempts exhausted).", progressTracker.Failed, depot.DepotId, MaxTransientChunkAttempts);

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
                    // await Task.Delay(Random.Shared.Next(100, 1000), cts.Token);

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
            } while (parsed == null || zipBytes == null || payloadBytes == null);

            if (parsed == null || zipBytes == null || payloadBytes == null)
            //{
            //    Console.WriteLine("\nUnable to download manifest {0} for depot {1}", depot.ManifestId, depot.DepotId);
            //    cts.Cancel();
            //    cts.Token.ThrowIfCancellationRequested();
            //}
            {
                // Do NOT cancel shared operations; fail this manifest only
                throw new ContentDownloaderException($"Unable to download manifest {depot.ManifestId} for depot {depot.DepotId}");
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
            string Hex(byte[] bytes) => bytes == null ? null : Util.ToHex(bytes);

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

        // Single-attempt chunk download. Returns true on success, false if the caller should
        // re-enqueue the chunk for a later retry. Only returns false for transient errors;
        // permanent errors (auth failure) still cancel the CTS as before.
        // Outcome of a single chunk download attempt. Mirrors the standard downloader's
        // do-while chunk loop: everything retries (the sliding retry queue keeps re-enqueuing
        // indefinitely, same as standard's unbounded loop), except PermanentFailure (401/403 -
        // the same case standard's loop `break`s out on) which the caller gives up on right away.
        private enum ChunkAttemptResult { Success, TransientFailure, PermanentFailure }

        private static async Task<ChunkAttemptResult> TryDownloadChunkToArchiveAsync(
            CancellationTokenSource cts,
            DepotDownloadInfo depot,
            DepotManifest.ChunkData chunk,
            string chunksRoot,
            RawDownloadOptions options,
            ChunkProgressTracker progressTracker)
        {
            var chunkID = Util.ToHex(chunk.ChunkID);
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
                        var shaHex = Util.ToHex(sha);
                        if (shaHex == chunkID)
                        {
                            progressTracker.IncrementSkipped();
                            return ChunkAttemptResult.Success;
                        }
                    }
                    else
                    {
                        progressTracker.IncrementSkipped();
                        return ChunkAttemptResult.Success;
                    }
                }
            }

            var buffer = ArrayPool<byte>.Shared.Rent((int)chunk.CompressedLength);
            try
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
                    var written = await cdnPool.CDNClient.DownloadDepotChunkAsync(
                        depot.DepotId,
                        chunk,
                        connection,
                        buffer,
                        null, // Pass null depot key to get raw compressed data
                        cdnPool.ProxyServer,
                        cdnToken).ConfigureAwait(false);

                    cdnPool.ReturnConnection(connection);

                    using var fs = File.Open(chunkPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                    await fs.WriteAsync(buffer.AsMemory(0, written), cts.Token);

                    if (options.VerifyChunkSha1)
                    {
                        fs.Position = 0;
                        var sha = SHA1.HashData(fs);
                        var shaHex = Util.ToHex(sha);
                        if (shaHex != chunkID)
                            Console.WriteLine("Warning: SHA1 mismatch for chunk {0}.", chunkID);
                    }

                    progressTracker.IncrementDownloaded();
                    return ChunkAttemptResult.Success;
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("Connection timeout downloading chunk {0}", chunkID);
                    cdnPool.ReturnBrokenConnection(connection);
                    return ChunkAttemptResult.TransientFailure;
                }
                catch (SteamKitWebRequestException e)
                {
                    // notFoundIsFatal: false - chunk data for very old releases can be in cold
                    // storage and briefly 404 until Steam promotes it; a later retry succeeds.
                    // Same understanding as the standard downloader's chunk loop: everything
                    // retries except a genuine 401/403, which gives up immediately here too.
                    var action = await HandleCdnRequestExceptionAsync(e, connection, depot.AppId, depot.DepotId, cts.Token, notFoundIsFatal: false);

                    if (action != CdnFailureAction.RetryImmediately)
                        Console.WriteLine("Encountered error downloading chunk {0}: {1}", chunkID, e.StatusCode);

                    return action == CdnFailureAction.Abort ? ChunkAttemptResult.PermanentFailure : ChunkAttemptResult.TransientFailure;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    cdnPool.ReturnBrokenConnection(connection);
                    Console.WriteLine("Encountered unexpected error downloading chunk {0}: {1}", chunkID, e.Message);
                    return ChunkAttemptResult.TransientFailure;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        #endregion
    }
}
