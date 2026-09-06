// One-time migration tool: converts an old protobuf/Deflate "workshop_catalog.bin" (see
// LegacyCatalog.cs) into the new SQLite-backed "workshop_catalog.db" DepotDownloader itself now
// reads/writes (see DepotDownloader/WorkshopCatalogDb.cs). NOT part of the shipped product and NOT
// wired into DepotDownloader's own CLI - deliberately a separate, standalone tool, run by hand,
// once, per catalog that predates the SQLite switch. Safe to re-run: it never touches or deletes
// the source .bin, and overwrites/rebuilds the destination .db from scratch every time rather than
// trying to merge into a possibly-partial one from an interrupted previous attempt.

using System.IO.Compression;
using DepotDownloader;
using MigrateWorkshopCatalog;
using ProtoBuf;

if (args.Length != 3)
{
    Console.WriteLine("Usage: MigrateWorkshopCatalog <path-to-old-workshop_catalog.bin> <appid> <output-root>");
    Console.WriteLine();
    Console.WriteLine("<output-root> is the same root you pass DepotDownloader's own -output (or the");
    Console.WriteLine("current directory it defaults to) - the new workshop_catalog.db is written to");
    Console.WriteLine("<output-root>/depot/<appid>/workshop_catalog.db, exactly where DepotDownloader");
    Console.WriteLine("itself will look for it from then on.");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine("  MigrateWorkshopCatalog D:\\steam\\depot\\4000\\workshop_catalog.bin 4000 D:\\steam");
    return 1;
}

var oldPath = args[0];
if (!uint.TryParse(args[1], out var appId))
{
    Console.WriteLine($"Error: '{args[1]}' is not a valid app ID.");
    return 1;
}
var outputRoot = args[2];

if (!File.Exists(oldPath))
{
    Console.WriteLine($"Error: '{oldPath}' does not exist.");
    return 1;
}

var newPath = WorkshopCatalogDb.GetPath(outputRoot, appId);
if (File.Exists(newPath))
{
    Console.WriteLine($"Error: '{newPath}' already exists - delete it first if you want to re-run this migration from scratch (the old .bin is never modified either way, so nothing is lost by doing so).");
    return 1;
}

Console.WriteLine($"Reading legacy catalog from {oldPath}...");
LegacyWorkshopCatalog old;
{
    using var fs = File.OpenRead(oldPath);
    using var ds = new DeflateStream(fs, CompressionMode.Decompress);
    old = Serializer.Deserialize<LegacyWorkshopCatalog>(ds);
}

if (old.AppId != 0 && old.AppId != appId)
{
    Console.WriteLine($"Warning: the catalog file itself records AppId {old.AppId}, which doesn't match the {appId} passed on the command line. Proceeding with {appId} (matches DepotDownloader's own convention of trusting the folder/argument over the file's internal field), but double-check this is the catalog you meant.");
}

Console.WriteLine($"Loaded {old.Items.Count:N0} item(s). Writing to {newPath}...");

using var db = WorkshopCatalogDb.Open(outputRoot, appId);

db.QueryType = old.QueryType;
db.BootstrapCompleted = old.BootstrapCompleted;
db.BootstrapCursor = old.BootstrapCursor;
db.BootstrapStartedAt = old.BootstrapStartedAt;
db.BootstrapCompletedAt = old.BootstrapCompletedAt;
db.BootstrapTotalAsOfStart = old.BootstrapTotalAsOfStart;
db.LastWatermark = old.LastWatermark;
db.LastPolledAt = old.LastPolledAt;
db.LastPollResult = old.LastPollResult;
db.LastRecordedCreationTime = old.LastRecordedCreationTime;
db.SaveMeta();

// One transaction for the whole bulk load (see WorkshopCatalogDb.BeginTransaction's own doc
// comment) - this is the one place in the whole project that's actually appropriate for, since
// this entire import either finishes or gets thrown away and re-run from the untouched source
// file, unlike every other caller's "each write must survive an interruption independently" need.
using var transaction = db.BeginTransaction();

var migrated = 0;
var withHistory = 0;
foreach (var (id, oldItem) in old.Items)
{
    var newItem = new WorkshopCatalogItem
    {
        PublishedFileId = id,
        Title = oldItem.Title,
        ManifestId = oldItem.ManifestId,
        TimeUpdated = oldItem.TimeUpdated,
        LastSeenAt = oldItem.LastSeenAt,
        Kind = (WorkshopItemKind)(int)oldItem.Kind,
        FileUrl = oldItem.FileUrl,
        HistoryComplete = oldItem.HistoryComplete,
        HistoryCount = oldItem.History?.Count ?? 0,
        Banned = oldItem.Banned,
        BanReason = oldItem.BanReason,
        Visibility = oldItem.Visibility,
        Deleted = oldItem.Deleted,
    };
    db.UpsertItem(newItem, transaction);

    if (oldItem.History is { Count: > 0 })
    {
        var entries = oldItem.History.Select(h => new WorkshopHistoryEntry
        {
            Timestamp = h.Timestamp,
            ManifestId = h.ManifestId,
            ChangeDescription = h.ChangeDescription,
        }).ToList();
        db.ReplaceHistory(id, entries, oldItem.HistoryComplete, transaction);
        withHistory++;
    }

    migrated++;
    if (migrated % 50_000 == 0)
    {
        Console.WriteLine($"  {migrated:N0} of {old.Items.Count:N0} migrated...");
    }
}

Console.WriteLine("Committing (this can take a moment for a large catalog)...");
transaction.Commit();

Console.WriteLine($"Done: {migrated:N0} item(s) migrated ({withHistory:N0} with recorded history).");

var finalCount = db.ItemCount();
Console.WriteLine(finalCount == old.Items.Count
    ? $"Verified: new database has {finalCount:N0} item(s), matching the source exactly."
    : $"WARNING: new database has {finalCount:N0} item(s), but the source had {old.Items.Count:N0} - something is wrong, do not delete the old .bin.");

Console.WriteLine();
Console.WriteLine($"The old file at {oldPath} was not modified or deleted - keep it until you've");
Console.WriteLine("confirmed 'workshop status'/'status -list' against the new catalog look right.");

return 0;
