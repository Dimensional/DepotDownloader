// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    static partial class ContentDownloader
    {
        #region Utilities

        /// <summary>
        /// Generous backstop on how many times a single chunk may be retried after a transient
        /// CDN failure (503, or a 404 <see cref="HandleCdnRequestExceptionAsync"/> treated as
        /// non-fatal) before either downloader gives up on it. Chunk data for very old releases
        /// can need several retries while Steam promotes it out of cold storage, so this is
        /// deliberately large - it exists only to stop a chunk that's failing for some other,
        /// truly ongoing reason from retrying forever, not to bound legitimate cold-storage
        /// recovery. Shared by both raw (ContentDownloader.RawDownload.cs) and standard
        /// (ContentDownloader.StandardDownload.cs) chunk download loops so they can't drift.
        /// </summary>
        internal const int MaxTransientChunkAttempts = 200;

        /// <summary>
        /// Resolves an output root for raw archive placement (-raw-output) and encrypted-manifest
        /// branch-key storage: an explicit request wins, otherwise -dir/Config.InstallDirectory,
        /// otherwise the current directory. Deliberately NOT DEFAULT_DOWNLOAD_DIR ("depots") - that
        /// constant is the *standard* (processed) download's install-root name and has never been
        /// the raw/preservation convention, which has always been a bare ./depot/&lt;id&gt; (see
        /// ManifestCommand.cs's depot-key path, ReconstructCommand.cs's chunk-folder auto-detect).
        /// Falling back to it here silently moved the with-no-flags-given default to
        /// ./depots/depot/&lt;id&gt; the first time this parameter actually took effect - caught
        /// after the fact, not intended.
        /// </summary>
        internal static string ResolveOutputRoot(string requested) =>
            !string.IsNullOrWhiteSpace(requested) ? requested :
            !string.IsNullOrWhiteSpace(Config.InstallDirectory) ? Config.InstallDirectory :
            ".";

        /// <summary>
        /// What a caller should do after <see cref="HandleCdnRequestExceptionAsync"/> has
        /// processed a failed CDN request.
        /// </summary>
        internal enum CdnFailureAction
        {
            /// <summary>A CDN auth token was just requested; retry the same request right away.</summary>
            RetryImmediately,
            /// <summary>Transient error (already backed off briefly for 503); caller may retry.</summary>
            Retry,
            /// <summary>Permanent error (401/403 with a token already in hand, or a 404 the caller
            /// says can't mean "not promoted from cold storage yet"); caller should give up on this item.</summary>
            Abort,
        }

        /// <summary>
        /// Uniformly handles a <see cref="SteamKitWebRequestException"/> raised from a CDN
        /// request - manifest or chunk, raw or standard download. Shared by all four call sites
        /// so the auth-token-retry race, connection lifecycle, and status-code classification
        /// can't drift out of sync between them the way they had.
        ///
        /// On a 403 with no completed CDN auth token yet, requests one and signals immediate
        /// retry. Otherwise marks the connection broken and classifies the status: 401/403 are
        /// permanent; a 503, or a 404 when <paramref name="notFoundIsFatal"/> is false, gets a
        /// short randomized backoff before signalling retry; everything else retries without delay.
        ///
        /// <paramref name="notFoundIsFatal"/> defaults to true (matches manifest downloads: a
        /// missing manifest ID is a real error). Chunk downloads pass false - chunk data for very
        /// old game releases can live in cold storage and 404 for a while until Steam promotes it
        /// to hot storage, where a later retry succeeds against the exact same request.
        /// </summary>
        internal static async Task<CdnFailureAction> HandleCdnRequestExceptionAsync(
            SteamKitWebRequestException e,
            Server connection,
            uint appId,
            uint depotId,
            CancellationToken ct,
            bool notFoundIsFatal = true)
        {
            if (e.StatusCode == HttpStatusCode.Forbidden &&
                (!steam3.CDNAuthTokens.TryGetValue((depotId, connection.Host), out var authTokenPromise) || !authTokenPromise.Task.IsCompleted))
            {
                await steam3.RequestCDNAuthToken(appId, depotId, connection);
                cdnPool.ReturnConnection(connection);
                return CdnFailureAction.RetryImmediately;
            }

            cdnPool.ReturnBrokenConnection(connection);

            if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                return CdnFailureAction.Abort;

            if (e.StatusCode == HttpStatusCode.NotFound && notFoundIsFatal)
                return CdnFailureAction.Abort;

            if (e.StatusCode == HttpStatusCode.ServiceUnavailable || e.StatusCode == HttpStatusCode.NotFound)
            {
                // For NotFound this only reaches here when notFoundIsFatal is false - back off
                // the same as a 503 rather than hammering cold storage while it's promoted.
                await Task.Delay(Random.Shared.Next(500, 2000), ct);
            }

            return CdnFailureAction.Retry;
        }

        public static async Task<List<(uint depotId, ulong manifestId)>> ResolveEncryptedManifestIdsAsync(
            uint appId,
            List<(uint depotId, string encHex)> encrypted,
            string branch,
            string outputRootForKeys)
        {
            if (string.IsNullOrWhiteSpace(branch))
                branch = DEFAULT_BRANCH;

            outputRootForKeys = ResolveOutputRoot(outputRootForKeys);

            // Ensure server list is ready for any beta password operations
            cdnPool ??= new CDNClientPool(steam3, appId);
            await steam3?.RequestAppInfo(appId);

            // Attempt to load branch key from disk if not present
            async Task EnsureBranchKeyAsync(uint depotId)
            {
                if (steam3.AppBetaPasswords.ContainsKey(branch))
                    return;

                // Branch key file lives at raw depot root: {outputRootForKeys}/depot/{depotId}/
                var depotRoot = Path.Combine(outputRootForKeys, "depot", depotId.ToString());
                var branchKeyName = $"{Sanitize(branch)}.branchkey";
                var branchKeyPath = Path.Combine(depotRoot, branchKeyName);
                if (File.Exists(branchKeyPath))
                {
                    try
                    {
                        var keyBytes = await File.ReadAllBytesAsync(branchKeyPath);
                        steam3.AppBetaPasswords[branch] = keyBytes;
                        Console.WriteLine("Loaded branch key for '{0}' from {1}", branch, branchKeyName);
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
                    throw new ContentDownloaderException($"No branch key available for '{branch}'. Provide -branchpassword or place {Sanitize(branch)}.branchkey next to the depot.");
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

        private static async Task SaveBranchKeyToDiskAsync(uint depotId, string branch)
        {
            if (!steam3.AppBetaPasswords.TryGetValue(branch, out var keyBytes))
                return;

            try
            {
                var depotRoot = Path.Combine("depot", depotId.ToString());
                Directory.CreateDirectory(depotRoot);

                var branchKeyName = $"{SanitizeFilename(branch)}.branchkey";
                var branchKeyPath = Path.Combine(depotRoot, branchKeyName);

                // Skip if branch key already exists
                if (File.Exists(branchKeyPath))
                {
                    Console.WriteLine("Branch key for '{0}' already exists at {1}", branch, branchKeyName);
                    return;
                }

                await File.WriteAllBytesAsync(branchKeyPath, keyBytes);
                Console.WriteLine("Saved branch key for '{0}' to {1}", branch, branchKeyName);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Failed to save branch key for '{0}': {1}", branch, ex.Message);
            }
        }

        private static string SanitizeFilename(string name)
        {
            foreach (var ch in Path.GetInvalidFileNameChars())
                name = name.Replace(ch, '_');
            return name;
        }

        #endregion
    }
}
