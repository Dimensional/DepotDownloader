// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
                    await DownloadWebFileToUGCAsync(details.consumer_appid, pubFileId, details.filename, details.file_url, details.file_size.ToString());
                }
                else if (details?.hcontent_file > 0)
                {
                    // Modern UGC - manifest-based content, use consumer_appid as depot
                    Console.WriteLine("Retrieved data for workshop item {0}: '{1}' for app {2}", pubFileId, details.title, details.consumer_appid);
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
                // Ancient UGC - direct URL download to UGC folder
                await DownloadWebFileToUGCAsync(details.AppID, ugcId, details.FileName, details.URL, details.FileSize.ToString());
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

            if (!string.IsNullOrEmpty(details?.file_url))
            {
                // Ancient UGC - direct URL download to UGC folder (raw mode doesn't change this)
                await DownloadWebFileToUGCAsync(details.consumer_appid, publishedFileId, details.title, details.file_url, details.file_size.ToString());
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
                // Ancient UGC - direct URL download to UGC folder (raw mode doesn't change this)
                await DownloadWebFileToUGCAsync(details.consumer_appid, ugcId, details.title, details.file_url, details.file_size.ToString());
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

        public static async Task DownloadWorkshopItemAsync(ulong workshopId)
        {
            // Try to get published file details first - only the lookup itself falls back to UGC
            // on failure; a real download error below must propagate, not be masked by a confusing
            // secondary UGC-path failure on an id that legitimately is a published file.
            PublishedFileDetails details = null;
            try
            {
                details = await steam3.GetPublishedFileDetails(workshopId);
            }
            catch
            {
                // Fall back to UGC
            }

            if (details != null)
            {
                await DownloadPubfileAsync(workshopId);
                return;
            }

            // Try UGC if published file lookup failed
            await DownloadUGCAsync(workshopId);
        }

        public static async Task DownloadWorkshopItemRawAsync(ulong workshopId, RawDownloadOptions options)
        {
            // Try to get published file details first - only the lookup itself falls back to UGC
            // on failure; a real download error below must propagate, not be masked by a confusing
            // secondary UGC-path failure on an id that legitimately is a published file.
            PublishedFileDetails details = null;
            try
            {
                details = await steam3.GetPublishedFileDetails(workshopId);
            }
            catch
            {
                // Fall back to UGC
            }

            if (details != null)
            {
                await DownloadPubfileRawAsync(workshopId, options);
                return;
            }

            // Try UGC if published file lookup failed
            await DownloadUGCRawAsync(workshopId, options);
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

            // Download to a staging path and only move it into place once the full body has been
            // written - an interrupted direct write would otherwise leave a truncated file at
            // destPath that the File.Exists check above mistakes for a completed download forever.
            var tempPath = destPath + ".tmp";

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

                using (var responseStream = await response.Content.ReadAsStreamAsync())
                using (var fileStream = File.Create(tempPath))
                {
                    await responseStream.CopyToAsync(fileStream);
                }

                File.Move(tempPath, destPath, overwrite: true);

                Console.WriteLine("Downloaded UGC file to {0}", destPath);
                RecordUGCDownload(workshopId, url, fileName, destPath, appId, "downloaded", fileSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error downloading UGC file: {0}", ex.Message);
                try { File.Delete(tempPath); } catch { /* best effort cleanup */ }
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

        #endregion
    }
}
