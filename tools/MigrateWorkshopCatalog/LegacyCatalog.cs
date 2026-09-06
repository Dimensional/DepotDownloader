// One-time migration tool only - NOT part of the shipped DepotDownloader product. These classes
// are a frozen, self-contained copy of the workshop catalog's old protobuf/Deflate wire format
// (as it existed immediately before the SQLite migration - see DepotDownloader/WorkshopCatalogDb.cs
// for the new format and the reasoning behind switching), kept here only so this tool can read an
// old "workshop_catalog.bin" without requiring the main project to carry protobuf attributes it no
// longer needs. Every [ProtoMember] number and [DefaultValue] below must match the original
// exactly, or an existing real .bin file will silently misread.

using System.Collections.Generic;
using System.ComponentModel;
using ProtoBuf;

namespace MigrateWorkshopCatalog;

[ProtoContract]
public enum LegacyWorkshopItemKind
{
    Unknown = 0,
    ChunkBased = 1,
    AncientUgc = 2,
}

[ProtoContract]
public class LegacyWorkshopHistoryEntry
{
    [ProtoMember(1)]
    public uint Timestamp { get; set; }

    [ProtoMember(2)]
    public ulong ManifestId { get; set; }

    [ProtoMember(3)]
    public string ChangeDescription { get; set; }
}

[ProtoContract]
public class LegacyWorkshopCatalogItem
{
    [ProtoMember(1)]
    public ulong PublishedFileId { get; set; }

    [ProtoMember(2)]
    public string Title { get; set; }

    [ProtoMember(3)]
    public ulong ManifestId { get; set; }

    [ProtoMember(4)]
    public uint TimeUpdated { get; set; }

    [ProtoMember(5)]
    public uint LastSeenAt { get; set; }

    [ProtoMember(6)]
    public LegacyWorkshopItemKind Kind { get; set; } = LegacyWorkshopItemKind.Unknown;

    [ProtoMember(7)]
    public string FileUrl { get; set; }

    [ProtoMember(8)]
    public List<LegacyWorkshopHistoryEntry> History { get; set; } = [];

    [ProtoMember(9)]
    public bool HistoryComplete { get; set; }

    [ProtoMember(10)]
    public bool Banned { get; set; }

    [ProtoMember(11)]
    public string BanReason { get; set; }

    [ProtoMember(12)]
    public uint Visibility { get; set; }

    [ProtoMember(13)]
    public bool Deleted { get; set; }
}

[ProtoContract]
public class LegacyWorkshopCatalog
{
    [ProtoMember(1)]
    public uint AppId { get; set; }

    [ProtoMember(2)]
    public Dictionary<ulong, LegacyWorkshopCatalogItem> Items { get; set; } = [];

    [ProtoMember(3)]
    [DefaultValue(21u)]
    public uint QueryType { get; set; } = 21;

    [ProtoMember(4)]
    public bool BootstrapCompleted { get; set; }

    [ProtoMember(5)]
    [DefaultValue("*")]
    public string BootstrapCursor { get; set; } = "*";

    [ProtoMember(6)]
    public uint BootstrapStartedAt { get; set; }

    [ProtoMember(7)]
    public uint BootstrapCompletedAt { get; set; }

    [ProtoMember(8)]
    public uint BootstrapTotalAsOfStart { get; set; }

    [ProtoMember(9)]
    public uint LastWatermark { get; set; }

    [ProtoMember(10)]
    public uint LastPolledAt { get; set; }

    [ProtoMember(11)]
    public string LastPollResult { get; set; }

    [ProtoMember(12)]
    public uint LastRecordedCreationTime { get; set; }
}
