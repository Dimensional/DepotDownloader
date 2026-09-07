// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.Internal;

namespace DepotDownloader
{
    static partial class ContentDownloader
    {
        #region Workshop and UGC

        private static async Task ProcessPublishedFileAsync(ulong publishedFileId, List<(ulong PublishedFileId, PublishedFileDetails Details)> collectedFiles)
        {
            var details = await steam3.GetPublishedFileDetails(publishedFileId);
            var fileType = (EWorkshopFileType)details.file_type;

            if (fileType == EWorkshopFileType.Collection)
            {
                foreach (var child in details.children)
                {
                    await ProcessPublishedFileAsync(child.publishedfileid, collectedFiles);
                }
            }
            else if (SupportedWorkshopFileTypes.Contains(fileType))
            {
                collectedFiles.Add((publishedFileId, details));
            }
            else
            {
                Console.WriteLine("Published file {0} has unsupported file type {1}. Skipping file", publishedFileId, fileType);
            }
        }

        public static async Task DownloadPubfileAsync(ulong publishedFileId)
        {
            var collectedFiles = new List<(ulong PublishedFileId, PublishedFileDetails Details)>();
            await ProcessPublishedFileAsync(publishedFileId, collectedFiles);

            foreach (var (pubFileId, details) in collectedFiles)
            {
                if (!string.IsNullOrEmpty(details?.file_url))
                {
                    // Ancient UGC - direct URL download to UGC folder
                    await DownloadWebFileToUGCAsync(details.consumer_appid, pubFileId, details.title, details.filename, details.file_url, details.file_size.ToString(), details.time_updated);
                }
                else if (details?.hcontent_file > 0)
                {
                    // Modern UGC - manifest-based content, use consumer_appid as depot
                    Console.WriteLine("Retrieved data for workshop item {0}: '{1}' for app {2}", pubFileId, SanitizeTitleForDisplay(details.title), details.consumer_appid);
                    await DownloadAppAsync(details.consumer_appid, new List<(uint, ulong)> { (details.consumer_appid, details.hcontent_file) }, DEFAULT_BRANCH, null, null, null, false, true, pubFileId.ToString(), details.title);
                }
                else
                {
                    Console.WriteLine("Unable to locate manifest ID for published file {0}", pubFileId);
                }
            }
        }

        public static async Task DownloadUGCAsync(ulong ugcId)
        {
            SteamCloud.UGCDetailsCallback details = null;

            if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser)
            {
                details = await steam3.GetUGCDetails(ugcId);
            }
            else
            {
                Console.WriteLine($"Unable to query UGC details for {ugcId} from an anonymous account");
                return;
            }

            if (!string.IsNullOrEmpty(details?.URL))
            {
                // Ancient UGC - direct URL download to UGC folder. SteamCloud.UGCDetailsCallback
                // has no title or update-timestamp (unlike PublishedFileDetails below) - update
                // detection just won't have a signal to work with on this fallback path.
                await DownloadWebFileToUGCAsync(details.AppID, ugcId, title: null, details.FileName, details.URL, details.FileSize.ToString(), timeUpdated: 0);
            }
            else if (details != null)
            {
                // Modern UGC - manifest-based content
                await DownloadAppAsync(details.AppID, [(details.AppID, ugcId)], DEFAULT_BRANCH, null, null, null, false, true, ugcId.ToString(), details.FileName);
            }
            else
            {
                Console.WriteLine($"Unable to locate UGC details for {ugcId}");
            }
        }

        public static async Task DownloadPubfileRawAsync(ulong publishedFileId, RawDownloadOptions options)
        {
            var details = await steam3.GetPublishedFileDetails(publishedFileId);
            await DownloadPubfileRawAsync(publishedFileId, details, options);
        }

        /// <summary>
        /// Same as the single-argument overload, but for a caller that already has this item's
        /// PublishedFileDetails on hand (bootstrap's QueryFiles page, or poll's reclassification
        /// fetch) - avoids a redundant GetPublishedFileDetails round-trip per item, which matters
        /// at the scale "workshop bootstrap -manifests-only" operates at.
        /// </summary>
        public static async Task DownloadPubfileRawAsync(ulong publishedFileId, PublishedFileDetails details, RawDownloadOptions options)
        {
            if (!string.IsNullOrEmpty(details?.file_url))
            {
                // Ancient UGC - direct URL download to UGC folder. options.DryRun ("-raw-dry-run"/
                // "-manifests-only" from the workshop tracker) still applies here even though
                // there's no manifest/chunk split for a direct-URL file the way there is for depot
                // chunks - see DownloadWebFileToUGCAsync's dryRun handling for what it means here
                // (log the item's current metadata without fetching its content).
                await DownloadWebFileToUGCAsync(details.consumer_appid, publishedFileId, details.title, details.filename, details.file_url, details.file_size.ToString(), details.time_updated, options.DryRun);
            }
            else if (details?.hcontent_file > 0)
            {
                // Modern UGC - manifest-based content, use raw archiving
                Console.WriteLine("Retrieved data for workshop item {0}: '{1}' for app {2}", publishedFileId, SanitizeTitleForDisplay(details.title), details.consumer_appid);
                await DownloadAppRawAsync(details.consumer_appid, new List<(uint, ulong)> { (details.consumer_appid, details.hcontent_file) }, DEFAULT_BRANCH, null, null, null, false, options, publishedFileId.ToString(), details.title);
            }
            else
            {
                Console.WriteLine("Unable to locate manifest ID for published file {0}", publishedFileId);
            }
        }

        public static async Task DownloadUGCRawAsync(ulong ugcId, RawDownloadOptions options)
        {
            PublishedFileDetails details = null;

            if (steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser)
            {
                details = await steam3.GetPublishedFileDetails(ugcId);
            }
            else
            {
                Console.WriteLine($"Unable to query UGC details for {ugcId} from an anonymous account");
                return;
            }

            if (!string.IsNullOrEmpty(details?.file_url))
            {
                // Ancient UGC - direct URL download to UGC folder (see the identical comment in
                // DownloadPubfileRawAsync above re: options.DryRun)
                await DownloadWebFileToUGCAsync(details.consumer_appid, ugcId, details.title, details.filename, details.file_url, details.file_size.ToString(), details.time_updated, options.DryRun);
            }
            else if (details != null)
            {
                // Modern UGC - manifest-based content, use raw archiving
                await DownloadAppRawAsync(details.consumer_appid, [(details.consumer_appid, ugcId)], DEFAULT_BRANCH, null, null, null, false, options, ugcId.ToString(), details.filename);
            }
            else
            {
                Console.WriteLine($"Unable to locate UGC details for {ugcId}");
            }
        }

        // One version of an ancient (direct-URL) UGC item, as recorded in its per-item sidecar.
        // A workshop item can be updated after it's first archived, and an update is not
        // guaranteed to keep the same internal filename - TimeUpdated (Steam's own timestamp,
        // independent of the file's name/URL) is what actually distinguishes versions here.
        private sealed class UgcVersionRecord
        {
            public uint TimeUpdated { get; set; }
            public string Title { get; set; }
            public string Filename { get; set; }
            public string FileUrl { get; set; }
            public string RelativePath { get; set; }
            public string FileSize { get; set; }
            public string Sha1 { get; set; }
            public string Status { get; set; }
            public string DownloadedAt { get; set; }
        }

        // Sanitizes one path segment for filesystem safety without collapsing the segment
        // boundary itself - unlike the old whole-string filter, this preserves the real
        // directory structure an item's internal filename may contain (e.g. "creation/foo.main"
        // stays a real subfolder, instead of becoming an unrecognizable flattened blob).
        private static string SanitizeUgcPathSegment(string segment)
        {
            if (string.IsNullOrEmpty(segment))
                return segment;

            var invalid = Path.GetInvalidFileNameChars();
            var sanitized = new string(segment.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
            return sanitized.TrimEnd('.', ' ');
        }

        private static string BuildUgcRelativePath(ulong workshopId, string internalFileName)
        {
            if (string.IsNullOrWhiteSpace(internalFileName))
                return workshopId.ToString();

            var segments = internalFileName.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries)
                .Select(SanitizeUgcPathSegment)
                .Where(s => !string.IsNullOrEmpty(s))
                .ToArray();

            return segments.Length > 0 ? Path.Combine(segments) : workshopId.ToString();
        }

        private static List<UgcVersionRecord> LoadUgcHistory(string sidecarPath)
        {
            if (!File.Exists(sidecarPath))
                return [];

            try
            {
                var json = File.ReadAllText(sidecarPath);
                return JsonSerializer.Deserialize<List<UgcVersionRecord>>(json) ?? [];
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Could not read UGC version history at {0}: {1}", sidecarPath, ex.Message);
                return [];
            }
        }

        private static void SaveUgcHistory(string sidecarPath, List<UgcVersionRecord> history)
        {
            try
            {
                var json = JsonSerializer.Serialize(history, new JsonSerializerOptions { WriteIndented = true });
                var tempPath = sidecarPath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, sidecarPath, overwrite: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Could not save UGC version history to {0}: {1}", sidecarPath, ex.Message);
            }
        }

        // Downloads an "ancient" UGC item - one served from a direct file_url rather than
        // manifest/chunk storage. title is the human-readable workshop title (purely for display
        // and the sidecar; not guaranteed unique or stable, never used for the on-disk path).
        // internalFileName is the item's actual stored name/relative path, used to build the real
        // on-disk layout so the result can be recognized/restored (e.g. copied into a Steam
        // library) later. Both come from the same PublishedFileDetails lookup where available;
        // the older SteamCloud.UGCDetailsCallback fallback has no title or update-timestamp, so
        // callers pass null/0 for those and this still works, just without update-detection.
        private static async Task DownloadWebFileToUGCAsync(uint appId, ulong workshopId, string title, string internalFileName, string url, string fileSize, uint timeUpdated, bool dryRun = false)
        {
            var itemDir = Path.Combine("ugc", appId.ToString(), workshopId.ToString());
            Directory.CreateDirectory(itemDir);

            var relativePath = BuildUgcRelativePath(workshopId, internalFileName);
            var destPath = Path.Combine(itemDir, relativePath);
            var sidecarPath = Path.Combine(itemDir, "_meta.json");

            var history = LoadUgcHistory(sidecarPath);
            var latest = history.Count > 0 ? history[^1] : null;

            if (latest != null && latest.TimeUpdated == timeUpdated && File.Exists(destPath))
            {
                Console.WriteLine("UGC file already exists: {0}", destPath);
                latest.Status = "exists";
                latest.DownloadedAt = DateTime.Now.ToString("O");
                SaveUgcHistory(sidecarPath, history);
                RecordUGCDownload(workshopId, url, title, internalFileName, destPath, appId, "exists", fileSize, timeUpdated);
                return;
            }

            if (dryRun)
            {
                // No manifest/chunk split exists for a direct-URL file the way there is for depot
                // chunks - the closest equivalent to "-raw-dry-run" here is recording the item's
                // current metadata (title/filename/URL/reported size/TimeUpdated) without actually
                // fetching its content, so a workshop-tracker "manifests-only" pass still leaves a
                // real, inspectable record of every ancient item it saw, not just the ones it
                // fully downloaded. latest.TimeUpdated == timeUpdated but the file itself missing
                // (destPath not found above) still falls through to here and logs again - that's
                // deliberate, since dry-run mode never actually writes destPath in the first place.
                Console.WriteLine("Dry run: logging UGC item {0} ('{1}') - metadata recorded, content not downloaded", workshopId, SanitizeTitleForDisplay(title) ?? internalFileName ?? "Unknown");

                if (latest == null || latest.TimeUpdated != timeUpdated)
                {
                    history.Add(new UgcVersionRecord
                    {
                        TimeUpdated = timeUpdated,
                        Title = title,
                        Filename = internalFileName,
                        FileUrl = url,
                        RelativePath = null,
                        FileSize = fileSize, // as reported by Steam - never verified against actual bytes in dry-run mode
                        Sha1 = null,
                        Status = "logged",
                        DownloadedAt = DateTime.Now.ToString("O"),
                    });
                    SaveUgcHistory(sidecarPath, history);
                }

                RecordUGCDownload(workshopId, url, title, internalFileName, destPath: null, appId, "logged", fileSize, timeUpdated);
                return;
            }

            if (latest != null && latest.TimeUpdated != timeUpdated)
            {
                Console.WriteLine(
                    "Workshop item {0} was updated since the last download (previous file: '{1}', new file: '{2}') - keeping the previous version, saving the new one alongside it.",
                    workshopId, latest.Filename ?? "(unknown)", internalFileName ?? "(unknown)");
            }

            Console.WriteLine("Downloading UGC workshop item {0}: '{1}'", workshopId, SanitizeTitleForDisplay(title) ?? internalFileName ?? "Unknown");
            Console.WriteLine("URL: {0}", url);

            var destDir = Path.GetDirectoryName(destPath);
            if (!string.IsNullOrEmpty(destDir))
                Directory.CreateDirectory(destDir);

            // Download to a staging path and only move it into place once the full body has been
            // written - an interrupted direct write would otherwise leave a truncated file at
            // destPath that the File.Exists check above mistakes for a completed download forever.
            var tempPath = destPath + ".tmp";

            try
            {
                using var client = HttpClientFactory.CreateHttpClient();
                Console.WriteLine("Downloading {0}", relativePath);

                var response = await client.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine("Failed to download UGC file: HTTP {0}", response.StatusCode);
                    return;
                }

                using (var responseStream = await response.Content.ReadAsStreamAsync())
                using (var fileStream = File.Create(tempPath))
                {
                    await responseStream.CopyToAsync(fileStream);
                }

                string sha1Hex;
                using (var fs = File.OpenRead(tempPath))
                    sha1Hex = Util.ToHex(SHA1.HashData(fs));

                File.Move(tempPath, destPath, overwrite: true);

                Console.WriteLine("Downloaded UGC file to {0}", destPath);

                var actualSize = File.Exists(destPath) ? new FileInfo(destPath).Length.ToString() : fileSize;
                history.Add(new UgcVersionRecord
                {
                    TimeUpdated = timeUpdated,
                    Title = title,
                    Filename = internalFileName,
                    FileUrl = url,
                    RelativePath = relativePath,
                    FileSize = actualSize,
                    Sha1 = sha1Hex,
                    Status = "downloaded",
                    DownloadedAt = DateTime.Now.ToString("O"),
                });
                SaveUgcHistory(sidecarPath, history);

                RecordUGCDownload(workshopId, url, title, internalFileName, destPath, appId, "downloaded", actualSize, timeUpdated);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error downloading UGC file: {0}", ex.Message);
                try { File.Delete(tempPath); } catch { /* best effort cleanup */ }
            }
        }

        // Central overview of every UGC download across all apps - kept alongside each item's own
        // durable per-item sidecar (UgcVersionRecord/_meta.json) rather than instead of it, so a
        // corrupted or deleted download_records.json never loses a version history that the
        // sidecar right next to the actual file still has.
        private static void RecordUGCDownload(ulong workshopId, string fileUrl, string title, string filename, string destPath, uint appId, string status, string fileSize, uint timeUpdated)
        {
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
                filename = filename,
                time_updated = timeUpdated,
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

        #endregion
    }
}
