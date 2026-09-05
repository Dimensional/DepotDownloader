DepotDownloader
===============

Steam depot downloader utilizing the SteamKit2 library. Supports .NET 9

This program must be run from a console, it has no GUI.

## Installation

### Directly from GitHub

~~Download a binary from [the releases page](https://github.com/SteamRE/DepotDownloader/releases/latest).~~

### via Windows Package Manager CLI (aka winget)

~~On Windows, [winget](https://github.com/microsoft/winget-cli) users can download and install
the latest Terminal release by installing the `SteamRE.DepotDownloader`
package:~~

**NOT FOR THIS FORK**
```powershell
winget install --exact --id SteamRE.DepotDownloader
```

### via Homebrew

~~On macOS, [Homebrew](https://brew.sh) users can download and install the latest release by running the following commands:~~

**NOT FOR THIS FORK**
```shell
brew tap steamre/tools
brew install depotdownloader
```

## Usage Overview

DepotDownloader uses a command-based interface. The general syntax is:

```
depotdownloader <COMMAND> [OPTIONS...]
```

### Available Commands

- **`download`** - Download Steam content (apps, depots, workshop items)
- **`list-depots`** - List branches per depot from a CSV (no download required)
- **`validate-depot`** - Validate all chunks in a depot directory (offline)
- **`validate-chunk`** - Validate a single chunk file (offline)
- **`validate-chunkstore`** - Validate all chunks in a chunkstore (offline)
- **`validate-chunkstore-chunks`** - Validate specific chunks in a chunkstore (offline)
- **`reconstruct`** - Rebuild installed files offline from a manifest + archived chunks
- **`chunkstore`** - Pack/unpack/verify/stats/update/rebuild for chunk storage

For help on a specific command:
```
depotdownloader help <command>
```

For example:
```
depotdownloader help download
depotdownloader help validation
```

---

## Download Command

The `download` command is the primary way to download Steam content.

### Basic Syntax

```
depotdownloader download [OPTIONS...]
```

### Download Modes

DepotDownloader supports three mutually exclusive download modes:

#### 1. App-based Downloading
Download specific apps and depots from Steam.

```bash
depotdownloader download -app <id> [-depot <id>] [-manifest <id>] [OPTIONS...]
```

**Examples:**
```bash
# Download the latest version of an app
depotdownloader download -app 730

# Download a specific depot
depotdownloader download -app 730 -depot 731

# Download a specific manifest version
depotdownloader download -app 730 -depot 731 -manifest 7617088375292372759
```

#### 2. Manifest CSV Downloading
Download from a CSV file containing manifest data. This is useful for archiving multiple manifests.

**CSV Format:** `AppID,DepotID,ManifestID,Branch,Release Date`

```bash
depotdownloader download -manifest-csv <file> [OPTIONS...]
```

**Examples:**
```bash
# Download latest manifest per depot from CSV
depotdownloader download -manifest-csv manifests.csv

# Download ALL manifests from CSV (auto-enables raw mode)
depotdownloader download -manifest-csv manifests.csv -manifest-csv-all

# Download manifests for specific branch
depotdownloader download -manifest-csv manifests.csv -branch dev
```

#### 3. Workshop Downloading

Moved to the `workshop` command (`workshop download`), alongside automatic update tracking -
see [Workshop Update Tracking](#workshop-update-tracking) below. `download` no longer accepts any
workshop-related options at all; it prints a redirect to the new location. Note there's no bare
ID-list input under `workshop download` beyond a short ad-hoc `-workshop` list, either - a list
like that carries no tracking data, so anything larger should go through `workshop bootstrap` +
`-app` instead (see below).

```bash
depotdownloader workshop download -workshop 1885082371 770604181014286929
```

### Authentication Options

Parameter | Description
----------|------------
`-username <user>` | Steam account username for restricted content
`-password <pass>` | Steam account password (will be prompted if not provided)
`-remember-password` | Store login token for subsequent logins (use with `-username`)
`-qr` | Display QR code for Steam mobile app login
`-no-mobile` | Prefer entering 2FA code instead of mobile app prompt
`-loginid <#>` | Unique 32-bit Steam LogonID (required for multiple concurrent instances)

**Examples:**
```bash
# Login with username (password will be prompted)
depotdownloader download -app 730 -username myuser

# Login with password on command line
depotdownloader download -app 730 -username myuser -password mypass

# Remember password for future runs
depotdownloader download -app 730 -username myuser -remember-password

# Use QR code login
depotdownloader download -app 730 -qr
```

### Filtering & Selection Options

Parameter | Description
----------|------------
`-branch <name>` | Download from specified branch (default: `public`)
`-branchpassword <pass>` | Branch password if applicable
`-os <os>` | Operating system (`windows`, `macos`, `linux`)
`-osarch <arch>` | Architecture (`32`, `64`)
`-language <lang>` | Language (default: `english`)
`-all-platforms` | Download all platform-specific depots
`-all-archs` | Download all architecture-specific depots
`-all-languages` | Download all language-specific depots
`-lowviolence` | Download low violence depots
`-filelist <file>` | Text file containing list of files to download (prefix with `regex:` for regex patterns)

**Examples:**
```bash
# Download Linux version
depotdownloader download -app 730 -os linux

# Download specific branch
depotdownloader download -app 730 -branch beta -branchpassword secretpass

# Download specific files only
depotdownloader download -app 730 -filelist myfiles.txt

# Download all platforms
depotdownloader download -app 730 -all-platforms
```

### Output & Directory Options

Parameter | Description
----------|------------
`-dir <path>` | Output directory for downloaded files
`-manifest-only` | Download only human-readable manifests (no content)

**Examples:**
```bash
# Download to specific directory
depotdownloader download -app 730 -dir "C:\Games\CSGO"

# Download manifest only
depotdownloader download -app 730 -depot 731 -manifest-only
```

### Validation Options

Parameter | Description
----------|------------
`-validate` | Verify existing files against checksums (re-downloads if needed)
`-validate-chunks` | Validate chunks during download (slower but ensures integrity)

**Examples:**
```bash
# Validate existing files
depotdownloader download -app 730 -validate

# Validate chunks as they download
depotdownloader download -app 730 -validate-chunks
```

### Raw Archive Mode

Raw mode saves manifests and chunks in their original encrypted/compressed form for archival purposes.

Parameter | Description
----------|------------
`-raw` | Save raw manifests and chunks (no file installation)
`-raw-output <dir>` | Output directory for raw archives
`-raw-debug-json` | Write debug JSON for each manifest
`-raw-respect-filelist` | Only include files matching `-filelist`
`-raw-verify-chunks` | Verify chunk SHA1 hashes after download
`-raw-no-skip-existing` | Overwrite existing chunks
`-raw-dry-run` | Download manifests only, skip chunks

For a workshop item, `-raw-dry-run` now also applies to ancient/direct-URL UGC content, not just
chunk-based depot manifests (fixed - it previously had no effect there and always did a full
download regardless of the flag): the item's current metadata (title/filename/URL/reported size/
`time_updated`) is logged into its `ugc/<appid>/<id>/_meta.json` sidecar and `download_records.json`
with `"status": "logged"`, without fetching the actual file content.

**Note:** Raw mode is automatically enabled for CSV downloads and when downloading multiple manifests to prevent file overwrites.

**Examples:**
```bash
# Download in raw archive format
depotdownloader download -app 4000 -depot 4001 -raw

# Download with chunk verification
depotdownloader download -app 4000 -depot 4001 -raw -raw-verify-chunks

# Dry run (manifests only)
depotdownloader download -app 4000 -depot 4001 -raw-dry-run

# Download all manifests from CSV in raw mode
depotdownloader download -manifest-csv manifests.csv -manifest-csv-all
```

### Advanced Options

Parameter | Description
----------|------------
`-cellid <#>` | Override CDN CellID
`-max-downloads <#>` | Maximum concurrent chunk downloads (default: 8)
`-use-lancache` | Force downloads through Lancache (auto-detects Lancache server)
`-debug` | Enable verbose debug output
`-manifest-enc <hex>` | Encrypted manifest ID (requires `-branch` and depot key)

**Examples:**
```bash
# Increase concurrent downloads
depotdownloader download -app 730 -max-downloads 16

# Use Lancache
depotdownloader download -app 730 -use-lancache

# Enable debug logging
depotdownloader download -app 730 -debug
```

---

## List Depots Command

Display branches per depot from a CSV file without downloading.

### Syntax

```bash
depotdownloader list-depots <manifest.csv>
```

### Examples

```bash
# List all branches in a manifest CSV
depotdownloader list-depots manifests.csv
```

**Output:**
```
Branches by Depot (grouped by DepotID):

Depot 4001:
  - public
  - beta
- dev

Depot 4002:
  - public
```

---

## Validation Commands

DepotDownloader provides powerful offline validation tools for raw depot archives.

### Validation Overview

There are three types of validation:

1. **Download-time validation** (`-validate-chunks`) - Validates chunks as they download
2. **Post-download validation** (`-validate`) - Validates installed files against checksums
3. **Standalone validation** - Offline validation of raw archives (commands below)

### validate-depot

Validate all chunks in a depot directory.

```bash
depotdownloader validate-depot <depot-path> [manifest-path] [OPTIONS...]
```

**Options:**
- `-verbose`, `-v` - Show detailed output for each chunk
- `-threads <#>`, `-t <#>` - Number of threads (0 = auto-detect)

**Examples:**
```bash
# Validate depot with auto-detected threads
depotdownloader validate-depot depot/4001

# Validate with 16 threads and verbose output
depotdownloader validate-depot depot/4001 -verbose -threads 16
```

### validate-chunk

Validate a single chunk file.

```bash
depotdownloader validate-chunk <chunk-file> <depot-key-file> [uncompressed-length]
```

**Examples:**
```bash
# Validate a single chunk
depotdownloader validate-chunk chunk/abc123.bin depot/4001/4001.depotkey
```

### validate-chunkstore

Validate all chunks in a chunkstore.

```bash
depotdownloader validate-chunkstore <chunkstore-path> [OPTIONS...]
```

**Options:**
- `-depot <id>`, `-d <id>` - Depot ID (auto-detects if only one depot)
- `-key <file>`, `-k <file>` - Path to depot key file
- `-verbose`, `-v` - Show detailed output
- `-threads <#>`, `-t <#>` - Number of threads

**Examples:**
```bash
# Validate chunkstore
depotdownloader validate-chunkstore chunkstore/ -threads 16

# Validate with specific depot
depotdownloader validate-chunkstore chunkstore/ -depot 4001 -key depot/4001/4001.depotkey
```

### validate-chunkstore-chunks

Validate specific chunks in a chunkstore from a file list.

```bash
depotdownloader validate-chunkstore-chunks <chunkstore-path> <chunk-list-file> [OPTIONS...]
```

**Options:** Same as `validate-chunkstore`

**Examples:**
```bash
# Validate chunks from list
depotdownloader validate-chunkstore-chunks chunkstore/ chunks.txt -verbose
```

For comprehensive validation help:
```bash
depotdownloader help validation
```

---

## Chunkstore Command

Pack loose chunks (as produced by `download -raw`) into a chunkstore (a CSD/CSM pair) for
efficient, deduplicated storage of a depot's chunks, and manage that storage.

A single chunkstore always holds one encryption mode - either all chunks encrypted (as
downloaded from the CDN) or all already decrypted, never a mix; this is recorded in the
chunkstore's own metadata and enforced when packing.

### pack

Create or add to a chunkstore from loose chunk files.

```bash
depotdownloader chunkstore pack <input-chunks-folder> <output-chunkstore-folder> [OPTIONS...]
```

**Options:**
- `-depot <id>` - Depot ID (required for a new chunkstore)
- `-encrypted` / `-decrypted` - Mark chunks as encrypted/decrypted (default: auto-detect)
- `-max-file-size <bytes>` - Maximum size per CSD file (default: 2GB)
- `-threads <count>` - Parallel file reads (default: CPU count - 1)
- `-batch-size <count>` - Chunks to buffer in memory (default: 1000)
- `-checkpoint-interval <n>` - Save checkpoint every N chunks (default: 5000)

**Examples:**
```bash
depotdownloader chunkstore pack depot/4001/chunk/ chunkstore/ -depot 4001
depotdownloader chunkstore pack depot/4001/chunk/ chunkstore/ -depot 4001 -decrypted
```

### unpack

Extract chunks from a chunkstore back to individual loose files.

```bash
depotdownloader chunkstore unpack <chunkstore-folder> <output-chunks-folder> [OPTIONS...]
```

**Options:**
- `-depot <id>` - Depot ID (auto-detects if only one depot)
- `-threads <count>` - Parallel file operations (default: CPU count - 1)
- `-overwrite` - Overwrite existing files (default: skip existing)

**Examples:**
```bash
depotdownloader chunkstore unpack chunkstore/ extracted_chunks/
depotdownloader chunkstore unpack chunkstore/ extracted_chunks/ -depot 4001 -threads 16
```

### verify

Validate chunk integrity by reading each chunk from the CSD via the CSM's metadata,
decrypting (if the chunkstore is encrypted) and decompressing it, and checking the result
against its SHA1 name. This is also available under the `validate-chunkstore` /
`validate-chunkstore-chunks` command names, which are aliases for `chunkstore verify`.

```bash
depotdownloader chunkstore verify <chunkstore-folder> [OPTIONS...]
```

**Options:**
- `-depot, -d <id>` - Depot ID (auto-detects if only one depot)
- `-key, -k <path>` - Path to depot key file
- `-chunks <file>` - Only verify the SHA1s listed in this file (one per line, or first
  column of a CSV; `#` comments allowed)
- `-threads, -t <count>` - Parallel validation threads (default: auto)
- `-verbose, -v` - Show result for every chunk
- `-no-resume` - Ignore existing checkpoint, start fresh

**Examples:**
```bash
depotdownloader chunkstore verify chunkstore/
depotdownloader chunkstore verify chunkstore/ -depot 4001 -key depot.key
depotdownloader chunkstore verify chunkstore/ -chunks suspect_chunks.txt
```

### stats

Display chunk count, file sizes, and storage metrics for a chunkstore.

```bash
depotdownloader chunkstore stats <chunkstore-folder> [OPTIONS...]
```

**Options:**
- `-depot <id>` - Depot ID (auto-detects if only one depot)

**Examples:**
```bash
depotdownloader chunkstore stats chunkstore/
depotdownloader chunkstore stats chunkstore/ -depot 4001
```

### update

Cheaply appends chunks from a folder to an existing chunkstore - the way to bring a store up
to date after a game update. Only chunks not already present are added; existing CSD/CSM data
is never touched or re-sorted, so the storage cost is proportional to what's actually new, not
to the size of the store already on disk (a 400GB store gaining 5 new chunks costs ~5 chunks,
not another 400GB). The result is **not** alphanumerically sorted - see `rebuild` below.

```bash
depotdownloader chunkstore update <new-chunks-folder> <existing-chunkstore-folder> [OPTIONS...]
```

**Options:**
- `-depot <id>` - Depot ID (auto-detects if only one depot)
- `-max-file-size <bytes>` - Maximum size per CSD file (default: 2GiB, min: 1GiB)
- `-threads <count>` - Parallel file reads (default: CPU count - 1)
- `-batch-size <count>` - Chunks to buffer in memory (default: 1000)
- `-checkpoint-interval <n>` - Save checkpoint every N chunks (default: 5000)

Requires an existing chunkstore at the target (use `pack` to create one first); refuses if the
input folder contains chunks that don't match the store's own encryption mode.

**Examples:**
```bash
depotdownloader chunkstore update depot/4001/new_chunks/ chunkstore/ -depot 4001
```

### rebuild

Re-sorts every chunk in a chunkstore into a fresh, alphanumerically-ordered copy - the same
canonical, byte-for-byte-deterministic layout a from-scratch `pack` of the same chunk set would
produce. This is what restores that determinism after incremental `update` calls have appended
chunks out of order (relevant e.g. for checksumming a chunkstore the way No-Intro checksums a
canonical ROM file). Deliberately expensive: since sorted offsets can't be computed without a
full copy, it needs up to ~2x storage transiently. The original is never modified or deleted -
once you've confirmed the new store (e.g. with `verify`), replace the original yourself.

```bash
depotdownloader chunkstore rebuild <chunkstore-folder> <output-folder> [OPTIONS...]
```

**Options:**
- `-depot <id>` - Depot ID (auto-detects if only one depot)
- `-max-file-size <bytes>` - Maximum size per CSD file (default: 2GiB, min: 1GiB)
- `-threads <count>` - Parallel chunk reads (default: CPU count - 1)
- `-batch-size <count>` - Chunks to buffer in memory (default: 1000)
- `-checkpoint-interval <n>` - Save checkpoint every N chunks (default: 5000)
- `-no-resume` - Ignore an existing partial rebuild, start fresh
- `-delete-source-as-we-go` - Delete old segments from the source as soon as every chunk they
  hold is durably confirmed copied, instead of waiting until the whole rebuild finishes. Bounds
  storage overhead to roughly the still-pending portion of the source rather than the whole
  store - but this **permanently deletes parts of the source while the operation runs**, not
  just at the end. Safe to interrupt and resume (deletion only ever happens after a checkpoint
  confirming those chunks is durably saved, and a fresh post-write byte comparison runs before
  anything old is removed), but it's a fundamentally different risk profile than the default
  (which never touches the source at all) - opt in deliberately.

**Examples:**
```bash
depotdownloader chunkstore rebuild chunkstore/ chunkstore_rebuilt/ -depot 4001
depotdownloader chunkstore rebuild chunkstore/ chunkstore_rebuilt/ -depot 4001 -delete-source-as-we-go
```

For more details:
```bash
depotdownloader help chunkstore
```

---

## Reconstruct Command

Rebuilds installed depot files entirely offline from a saved manifest, a depot key, and
previously-archived chunk data (loose files from `download -raw`, or a packed chunkstore).
No Steam connection required.

Every in-scope file is always rewritten from scratch - reconstruct never trusts or reuses
partial output, so it's always safe to re-run after an interruption.

```bash
depotdownloader reconstruct <manifest-file> [OPTIONS...]
```

**Options:**
- `-manifest <file>` - Manifest file (alternative to the positional argument)
- `-output <dir>` - Output directory for reconstructed files (required unless `-list-files`)
- `-depot <id>` - Depot ID (for key lookup / chunk source auto-detect)
- `-depotkey <hex>` / `-depotkey-file <path>` - Depot key
- `-chunks <dir>` - Loose chunk folder (default: auto-detect `depot/<id>/chunk`)
- `-chunkstore <dir>` - Packed chunkstore folder (mutually exclusive with `-chunks`)
- `-filelist <file>` - Only reconstruct files matching this list (literal paths or
  `regex:<pattern>` lines, same format as `download -filelist`)
- `-files <list>` - Inline equivalent of `-filelist`: a `;`-separated list of literal paths
  and/or `regex:<pattern>` entries (`;` rather than `,` since a regex can itself contain
  commas, e.g. a `{2,4}` quantifier). Combines with `-filelist` if both are given.
- `-list-files` (alias `-list`) - List every file recorded in the manifest and exit - no
  reconstruction happens, so `-output`/`-chunks`/`-chunkstore` aren't needed. Plain output is
  one path per line, sorted, directly reusable as `-filelist` input; add `-verbose` for each
  file's type/size/chunk count.
- `-validate` - Verify each file's whole-content SHA1 against the manifest after writing
- `-threads <count>` - Max parallel file writers (default: CPU count - 1)
- `-fail-fast` - Stop enqueuing further files after the first failure
- `-verbose`, `-v` - Show per-file progress output (or extra columns with `-list-files`)

Without `-filelist`/`-files`, every file in the manifest is in scope - reconstructing the
whole depot versus a single file is just a matter of how narrow that filter is. A raw-saved
manifest (`.manif4`/`.manif5`) stores filenames AES-encrypted and base64-wrapped, not
human-readable, until decrypted with the depot key - required for `-list-files` just as much
as for actually reconstructing.

**Examples:**
```bash
# Loose chunks, auto-detecting the depot key and chunk folder
depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -depot 4001

# From a chunkstore, with post-write validation
depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -chunkstore chunkstore/ -validate

# Only specific files, from a saved list
depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -depot 4001 -filelist important_files.txt

# See what's in a manifest before deciding what to reconstruct
depotdownloader reconstruct depot/4001/manifest/123.manif5 -depotkey-file depot/4001/4001.depotkey -list-files

# Just one file, without writing a filelist for it
depotdownloader reconstruct depot/4001/manifest/123.manifest -output game/ -depot 4001 -files "bin/game.exe"
```

For more details:
```bash
depotdownloader help reconstruct
```

---

## Workshop Update Tracking

The single place all workshop acquisition and tracking happens - replaces the old workshop-related
`download` options (moved here as `workshop download`) and adds automatic update tracking across
**an entire app's workshop**, covering both storage kinds:
- **Chunk-based** items (depot ID == app ID, the modern format most current workshop content uses)
- **Ancient UGC** items (direct-URL content, some dating back to 2012) - these still show up in the
  same `QueryFiles`/`GetItemChanges` sweep as everything else, so there's no separate walk needed,
  but they need different handling to archive correctly (see below).

Built on SteamKit2 unified-messages calls, not the public Steamworks Web API:

- **`PublishedFile.QueryFiles`** - the same backend the workshop browse page itself uses. Works
  anonymously. Used by `bootstrap` to walk an entire app's workshop once.
- **`PublishedFile.GetItemChanges`** - a per-app delta feed: "everything changed since this
  timestamp," each entry already carrying its new content handle. Used by `poll`. **Requires an
  authenticated login - anonymous is confirmed to always return `EResult.AccessDenied`.**
- **`PublishedFile.GetChangeHistory`** - one item's full changelog (every historical content
  handle + timestamp). Works anonymously, for both kinds. Used by `download -history`.

```bash
depotdownloader workshop bootstrap -app <appid> [OPTIONS...]
depotdownloader workshop download -app <appid> [OPTIONS...]
depotdownloader workshop download -workshop <id> [<id>...] [OPTIONS...]
depotdownloader workshop poll -app <appid> [OPTIONS...]
depotdownloader workshop status -app <appid> [-output <dir>] [-list [-kind chunk|ancient|unknown] [-only <id,id2,...>] [-limit N]]
```

**Bootstrap** (one-time per app, resumable): pages through the entire workshop via `QueryFiles`
and records every item's current content handle/title/update time into `depot/<appid>/workshop_catalog.bin`,
classifying each one chunk-based vs. ancient-UGC as it goes (same `file_url`-present check
`workshop download` itself uses - confirmed empirically that a genuinely ancient item's
`hcontent_file` field is still populated, but it's just the CDN handle embedded in its `file_url`,
not a depot manifest ID; the classification is what keeps this from confusing the two). **Catalog-
only by default** - it records metadata, it does not download any manifest/chunk/UGC content;
that's `download`'s job (`-manifests-only` below is the opt-in exception, for prefetching manifests
during the same walk). Expensive for a large workshop regardless - depot 4000 (Garry's Mod) alone
reports **~2 million items** (independently corroborated: a several-months-old third-party scrape
of the same workshop already found ~1.9M, consistent with organic growth since) - but safe to
interrupt and re-run; it resumes from its last saved page rather than restarting, checkpointing
every 5 pages.

A real multi-hour run against depot 4000 hit a sustained `TaskCanceledException` after roughly
15,000 items - almost certainly Steam throttling a long burst of back-to-back `QueryFiles` calls,
since the loop originally had no pacing between pages at all (confirmed independently: the same
workshop's own third-party scraper needed to handle the same throttling). Fixed with exponential
backoff (up to 5 attempts) around every `QueryFiles`/`GetItemChanges`/`GetChangeHistory` call, a
deliberate ~250ms pace between pages, and a graceful exit (progress saved, clear message) if
retries are still exhausted - a `TaskCanceledException` crashing the whole process outright, losing
whatever hadn't been checkpointed yet, was a real bug, not expected/acceptable behavior.

**⚠ `QueryFiles`'s ranking choice matters more than it looks for a long scan of a live workshop -
confirmed empirically, not documented anywhere.** The original choice, `query_type` 21
(`RankedByLastUpdatedDate`), returns items **descending** by `time_updated` (most-recently-updated
first) - a live scan against depot 4000 showed timestamps falling from ~19:29 UTC on page 1 to
~18:52 UTC on page 3, confirming the direction. The problem: that ranking is NOT stable while the
workshop keeps changing. An item updated *while* the scan is still running jumps toward the front
of the ranking (it's now more recent than most of what's already been ranked) - observed directly
as an out-of-order, much-newer timestamp appearing mid-page during a real scan. Since bootstrap
walks a ranking forward exactly once via `next_cursor` and never revisits earlier pages, an item
updated concurrently with a multi-hour/multi-day scan could land in a position already passed and
go unrecorded by that particular run.

**Fixed by switching the default to `query_type` 1 (`RankedByPublicationDate`)** instead - an
item's creation time never changes once it exists, so this ranking is completely stable regardless
of concurrent activity elsewhere. Confirmed directly: in the same kind of live scan, an item whose
`time_updated` had clearly just changed (moments before being observed) still landed in its exact
correct sorted position by `time_created`, undisturbed - unlike `time_updated`-based ranking, where
the same kind of live update visibly displaced an item's position. Also confirmed descending
(newest-published first) - direction doesn't matter for this property, only that the sort key
itself is immutable does. `-query-type` still accepts either value (or others) if there's ever a
reason to override it.

This does NOT mean a resumed bootstrap catches everything unconditionally, even under the stable
ranking - a **brand-new** item published while a scan is already past the "newest" end of the
ranking lands ahead of wherever the walk currently is, in territory it won't revisit (the walk only
moves toward older content). That's not a bug specific to either query-type; it's inherent to any
single forward-only pass over a live, *growing* list, and it's exactly why bootstrap-once-then-
poll-regularly is the actual design rather than bootstrap alone - `poll`'s `GetItemChanges` doesn't
care about ranking position at all (a new item's `time_updated` is "now," so it surfaces as `NEW` in
poll's own delta), so it independently closes this gap as long as it runs within the confirmed
96h-7-day window.

**A catalog's `QueryType` is pinned on its first-ever bootstrap call and never changes after** -
this was a real, separate bug found while checking whether it'd be safe to change the default:
`QueryType` was previously overwritten on *every* invocation regardless of whether the walk was
brand new or resuming, and the actual `QueryFiles` call used the raw CLI parameter rather than the
pinned value - so silently resuming an in-progress walk with a different `-query-type` than it
started with (including just from a changed default, as just happened here) could have paged
through an already-issued cursor under an entirely different ranking, with undefined results. Fixed
so a resume always uses the catalog's own recorded `QueryType`, printing a note (and ignoring the
mismatch) if a different `-query-type` is passed than what's on record. **There's no in-place way
to switch an in-progress catalog's ranking** - a resumed cursor only means anything relative to the
ranking it came from, so catching up to the new default requires deleting that app's catalog and
re-bootstrapping from scratch (safe/idempotent either way, since the catalog is keyed by ID - just
a time cost for whatever was already scanned).

**Interleaving `bootstrap` and `poll` on the same catalog is always safe**, including pausing a
multi-day bootstrap to run poll and resuming it afterward - a natural way to keep a huge workshop's
walk from leaving too large a gap before anything gets checked for recent changes. The two share no
mutable state capable of interfering with each other: `BootstrapCursor`/`BootstrapCompleted` are
written in exactly one place (`BootstrapWorkshopCatalogAsync`) and poll never touches them, while
poll only ever writes `catalog.Items[id] = ...` - a plain overwrite by `PublishedFileId`, safe
regardless of whether bootstrap already recorded that same id, will later re-visit it, or never
will. Bootstrap's cursor is an opaque, Steam-issued continuation token bound to the ranking
(`time_created`, immutable), not a count of items known locally - so nothing poll does to the local
catalog (recording a change, adding a brand-new item) can shift what that cursor means or where
bootstrap resumes. This isn't just reasoning: the same live test that confirmed the ranking's
stability above showed an item visibly updated *during* the scan still sitting in its exact correct
position - direct evidence that a poll-triggered update can't move anything bootstrap is walking.

**Full history is fetched by default, not just each item's current state** - both `bootstrap` and
`poll` also call `GetChangeHistory` per item and store the complete result (every version, oldest
first) on the catalog entry. This exists specifically because `GetItemChanges`' delta only ever
says "this changed since X," never how many times or through what intermediate versions - without
it, an item that updated twice between two polls would silently lose the version in between. There
is no incremental fetch - `GetChangeHistory` has no "since" filter of its own, so every fetch
(fresh or backfilled) retrieves and overwrites the WHOLE history; nothing here is a merge.

For a brand-new item this costs one extra round-trip PER ITEM, not per page - at depot 4000's ~2M
items, the ~250ms pacing alone adds up to multiple days on top of bootstrap's existing cost. Pass
**`-shallow`** to skip it for a huge workshop's first walk: items are recorded with just their
current version and marked history-incomplete, to be picked up later rather than paid for up front.
Poll defaults to full history too, but it's normally cheap there since a poll's delta set is a tiny
fraction of the whole catalog - `-shallow` on poll additionally skips that run's backfill sweep
(below), not just the per-item fetch.

Incomplete items backfill two ways, and it's worth understanding both since neither is a "confirm
everything, then continue" gate:
- **Organically, for anything that keeps changing**: whenever `poll`'s own `GetItemChanges` delta
  reports an item changed, it *always* does a full `GetChangeHistory` fetch and overwrite for that
  item, regardless of what `HistoryComplete` currently says - a changed report is itself the reason
  a stale flag would be wrong, so nothing here ever trusts the flag to decide whether to re-check.
  This is also why an item that keeps updating never needs the sweep below at all.
- **Via a bounded sweep, for anything that's gone quiet**: an item recorded `-shallow` that never
  updates again would never appear in any future poll delta, so nothing would ever organically
  revisit it. `-backfill-batch <n>` (default 200; 0 disables it) is a separate pass, run once at
  the *start* of every `bootstrap` or `poll` invocation (whether or not `-shallow` was passed to
  scrape brand-new items in the same run), that fetches full history for up to `n` items still
  marked incomplete. It is a per-run CAP, not a "keep going until none remain" loop - with e.g.
  285,000 items left incomplete and the default batch of 200, clearing the whole backlog this way
  takes on the order of 1,400+ separate invocations (a large `-backfill-batch` does more per run,
  at the cost of that run taking longer). The one case where a single invocation really does behave
  like "just the backfill, nothing else" is once `bootstrap` has already fully completed - there's
  no more paging left to do, so that run's only work *is* the sweep.
- An older catalog saved before `History`/`HistoryComplete` existed loads them at their protobuf
  zero-value defaults (empty list, `false`) - equivalent to every item in it having been recorded
  `-shallow`, so it backfills the same way. **No rebuild or deletion is required** for an existing
  catalog to pick this up; confirmed live against a real, in-progress 285,000-item app-4000 catalog
  predating this feature.

**Download** - the actual content-acquisition step, in two forms:
- **Catalog-driven** (`-app <appid>`): walks an app's existing catalog (built by `bootstrap`/`poll`)
  and archives its items - optionally narrowed with `-only <id,id2,...>`, or capped with
  `-max-items <n>` for a large catalog processed incrementally across several runs.
- **Ad-hoc** (`-workshop <id>...`): specific IDs, resolved and downloaded directly - no prior
  `bootstrap` needed, and a mixed list can span different apps, same as the old `download -workshop`
  did. Each resolved item is also upserted into its own app's catalog as a side effect, so even a
  one-off pull still contributes to that app's tracked state rather than being invisible to a later
  `poll`. There's deliberately no bare-file/CSV variant of this - a list like that carries no
  tracking data, so anything beyond a handful of IDs should go through the catalog-driven form
  above instead (`bootstrap` once, then `download -app`).

Either form archives through `DownloadPubfileRawAsync`/`DownloadAppRawAsync` - the same underlying
dispatch a plain raw download always used - so chunk-based items land at
`depot/<appid>/manifest/<workshopId>_<title>_<manifestId>` exactly as before, and ancient items go
through the existing UGC direct-download path, including its own `TimeUpdated`-based per-item
sidecar (`ugc/<appid>/<id>/_meta.json`) - so re-checking an unchanged ancient item is safe and
cheap, not a wasted re-download.

`-history` downloads **every** historical version via `GetChangeHistory`, not just current - for
chunk-based items this is genuinely retrievable (Steam retains old depot chunk data by design; a
404 on a very old manifest's chunks is possible - see the CDN cold-storage note elsewhere in this
codebase - but not expected to be the norm). For ancient UGC, `-history` is necessarily best-effort:
a `GetChangeHistory` entry there is only ever a timestamp + content handle, never a URL, and Steam's
`GetDetails` only ever exposes the CURRENT `file_url` - so an old ancient version can be discovered
and logged (multiple entries) but not necessarily re-downloaded; only the current version is
actually fetched for those regardless of `-history`, with a note printed when one has more than one
historical entry.

**Poll** (cheap and repeatable - the same command serves both a manual one-off "checkup" and a
scheduled task/cron, deliberately not two separate commands that could drift apart): asks
`GetItemChanges` for everything changed since the catalog's watermark, then archives just those
items the same way `download -app` would. The watermark only ever advances to what `GetItemChanges`
itself reports back, never to "now," so a poll can't silently skip a window it never actually asked
about.

Item classification isn't assumed permanent: whether an ancient item could ever be replaced by a
chunk-based one on some future update is unconfirmed either way, so `poll` re-classifies any
changed item that isn't already confirmed `ChunkBased` rather than trusting a cached `Kind`
forever - a real `ChunkBased` item skips the extra check (that direction of transition isn't a
practical concern), but anything still `AncientUgc`/`Unknown` gets re-verified on every change
that touches it.

**⚠ `GetItemChanges`'s time window is not unlimited - confirmed empirically, not documented
anywhere (it isn't part of the public Steamworks Web API at all):**
- Anonymous login: always `AccessDenied`, regardless of parameters.
- Authenticated: a `last_time_updated` **96 hours** in the past succeeded; **7 days** back was
  rejected with `EResult.Ignored` (confirmed to not be a result-size limit - reducing
  `num_items_max` down to 50 didn't help). The real cutoff sits somewhere in that 4-7 day range
  and was only tested against one high-churn app (Garry's Mod) - it may be tighter, looser, or
  scale with an app's own churn on a different app. **Poll at least every 2-3 days** to stay
  comfortably inside the confirmed-working zone.
- `poll` treats a rejected watermark as "re-run bootstrap," not a fatal error - it prints that
  instruction and exits rather than retrying the same request.

**Options (bootstrap):**
- `-page-size <n>` - Items per `QueryFiles` page (default 100)
- `-max-items <n>` - Stop after at least this many items (testing - leaves bootstrap
  unmarked-complete so a later run continues normally)
- `-query-type <n>` - `EPublishedFileQueryType` (default 1 = `RankedByPublicationDate` - see above
  for why 21 = `RankedByLastUpdatedDate` was the original but unsafe choice)
- `-manifests-only` (alias `-raw-dry-run`) - Also fetch each item's manifest (chunk-based) or log
  its metadata without fetching content (ancient UGC) during this same walk, instead of leaving
  that for a future `download`/`poll` to handle. Reuses the `PublishedFileDetails` this pass
  already fetched from `QueryFiles`, so it doesn't cost a second lookup per item - but the
  manifest-request round trip itself (plus `-raw`'s existing 500ms-per-new-manifest throttle) adds
  up fast: a workshop the size of depot 4000's would take **well over a week**. Pair with
  `-max-items` unless the workshop is genuinely small, or just use `download`/`poll` for what's
  actually changed.
- `-shallow` - Skip fetching full `GetChangeHistory` per item during this walk (see above)
- `-backfill-batch <n>` - Items to backfill full history for per run (default 200; 0 disables) -
  see above

**Options (download):**
- `-history` - Every historical version, not just current (see above)
- `-only <id,id2,...>` - Catalog-driven mode only: restrict to specific IDs
- `-max-items <n>` - Catalog-driven mode only: stop after this many entries (resumable)
- `-manifests-only` (alias `-raw-dry-run`) - Manifest-only for chunk-based items (no chunk data),
  metadata-only for ancient UGC (no file content, `"status": "logged"` in its sidecar) - does real
  work and updates records, just skips the large/expensive payload

**Options (poll):**
- `-dry-run` - Report what would be checked/downloaded - fetches nothing at all, not even a manifest
- `-manifests-only` - Same meaning as on `download` above
- `-shallow` - Same meaning as on `bootstrap` above - also skips this run's `-backfill-batch` sweep
- `-backfill-batch <n>` - Same meaning as on `bootstrap` above (runs after this poll's own delta)

**Common options:** `-output <dir>`, `-username`/`-remember-password` (bootstrap and ad-hoc
`download` can run anonymously; catalog-driven `download` inherits whatever the items themselves
require; `poll` cannot run anonymously - see above).

**Inspecting a catalog:** `status` alone prints only aggregate counts (including how many items
have full history known vs. still incomplete) - `workshop_catalog.bin` is protobuf/Deflate, not a
format meant to be opened directly, so `status -list` is the actual way to see what got recorded
(one row per item: ID, kind, manifest/content handle, last-update/last-seen time, a `History`
column showing entry count + whether it's complete or partial, title). Sorted by ID, not dictionary
order, so two snapshots print identically and diff cleanly. Defaults to the first 200 matching rows
(`-limit 0` for all); narrow with `-kind chunk|ancient|unknown` and/or `-only <id,id2,...>`. On
load, a corrupt/truncated/incompatible-version catalog fails loudly with a clear message rather
than silently misreading it - protobuf-net's wire format is self-describing (field number + wire
type per field), so garbled bytes fail to parse rather than landing in the wrong typed field, and
`CheckpointFile`'s atomic tmp+move save (the same pattern this project uses everywhere else) means
a crash mid-write can never leave a torn file behind in the first place - what's on disk is always
either the previous complete save or the new one, never a mix.

A brand-new item discovered only via `poll`/ad-hoc `download` (not previously seen during
`bootstrap`) costs one extra `GetDetails` call to classify it (chunk-based vs. ancient) and learn
its title, since `GetItemChanges` returns neither - this should be rare relative to updates on
already-known items.

### Planned: standalone poll daemon

`poll` today is a single non-interactive pass with a clean exit code (0 success, 1 error, 2 =
"watermark rejected, re-bootstrap"), specifically so it's already schedulable as-is - point cron/
Task Scheduler/systemd timer at it for any one app today.

A dedicated, separate process (not part of the main `depotdownloader` binary) is the planned real
solution for tracking many apps at once: something that reads a small config listing tracked app
IDs and a poll interval, then loops calling the same underlying catalog/poll logic in-process on
its own schedule - a persistent service rather than an externally-scheduled one-shot per app. Not
built yet; `poll` itself already carries all the logic such a daemon would call into, so building
it is a wrapper/scheduling exercise, not a redesign.

**Examples:**
```bash
depotdownloader workshop bootstrap -app 4000
depotdownloader workshop bootstrap -app 4000 -max-items 500 -manifests-only  # small test slice, with manifests
depotdownloader workshop download -app 4000                                 # current version of everything tracked
depotdownloader workshop download -app 4000 -history -only 2956730580       # full version history, one item
depotdownloader workshop download -workshop 123456 789012                   # ad-hoc, no bootstrap needed
depotdownloader workshop poll -app 4000 -username myaccount -remember-password
depotdownloader workshop status -app 4000
depotdownloader workshop status -app 4000 -list -kind ancient -limit 50      # inspect the actual items
```

---

## Legacy Compatibility

The old argument format (without sub-commands) is still supported but deprecated:

```bash
# Old format (deprecated)
depotdownloader -app 730 -depot 731

# New format (recommended)
depotdownloader download -app 730 -depot 731
```

---

## Frequently Asked Questions

### Why am I prompted to enter a 2-factor code every time I run the app?

Your 2-factor code authenticates a Steam session. Use `-remember-password` with your `-username` to persist the login token:

```bash
depotdownloader download -app 730 -username myuser -remember-password
```

### Can I run DepotDownloader while logged into Steam?

Any connection to Steam will be closed if they share a LoginID. Specify a different LoginID with `-loginid`:

```bash
depotdownloader download -app 730 -loginid 12345
```

### Why doesn't my password containing special characters work?

If your password contains special characters, you may need to escape them for your shell. Alternatively, omit the `-password` parameter and you'll be prompted to enter it interactively:

```bash
depotdownloader download -app 730 -username myuser
# Password will be prompted securely
```

### I am getting error 401 or no manifest code returned for old manifests

Try logging in with a Steam account. Anonymous accounts may not have access to old manifests:

```bash
depotdownloader download -app 730 -depot 731 -manifest 12345 -username myuser
```

Steam allows developers to block downloading old manifests, in which case no manifest code is returned even when parameters are correct.

### Why am I getting slow download speeds and frequent connection timeouts?

When downloading old builds, CDN cache servers may not have chunks readily available. Try increasing `-max-downloads`:

```bash
depotdownloader download -app 730 -depot 731 -max-downloads 16
```

### How do I download historical/old versions of games?

Use the `-manifest` parameter with a specific manifest ID:

```bash
depotdownloader download -app 730 -depot 731 -manifest 7617088375292372759
```

To archive multiple versions, use a manifest CSV file:

```bash
depotdownloader download -manifest-csv manifests.csv -manifest-csv-all
```

### How do I validate downloaded content?

For installed files, use `-validate`:
```bash
depotdownloader download -app 730 -validate
```

For raw archives, use the standalone validation commands:
```bash
depotdownloader validate-depot depot/4001 -verbose -threads 16
```

For maximum integrity during download:
```bash
depotdownloader download -app 730 -raw -validate-chunks
```

---

## Examples

### Basic Downloads

```bash
# Download latest version of an app
depotdownloader download -app 730

# Download with authentication
depotdownloader download -app 730 -username myuser -remember-password

# Download specific depot and manifest
depotdownloader download -app 730 -depot 731 -manifest 7617088375292372759
```

### Raw Archive Mode

```bash
# Download in raw format for archival
depotdownloader download -app 4000 -depot 4001 -raw

# Download with verification
depotdownloader download -app 4000 -depot 4001 -raw -raw-verify-chunks

# Download from CSV in raw mode
depotdownloader download -manifest-csv manifests.csv -manifest-csv-all
```

### Workshop Downloads

```bash
# Ad-hoc, a few specific items - see the "workshop" command (Workshop Update Tracking, below)
depotdownloader workshop download -workshop 123456 789012

# A whole app's workshop, tracked - build the catalog once, then download from it
depotdownloader workshop bootstrap -app 4000
depotdownloader workshop download -app 4000
```

### Validation

```bash
# Validate depot offline
depotdownloader validate-depot depot/4001 -verbose -threads 16

# Validate during download
depotdownloader download -app 730 -validate-chunks

# Validate installed files
depotdownloader download -app 730 -validate
```

### Advanced Usage

```bash
# Download multiple platforms
depotdownloader download -app 730 -all-platforms

# Download with file filtering
depotdownloader download -app 730 -filelist important_files.txt

# Download with Lancache
depotdownloader download -app 730 -use-lancache -max-downloads 25

# Download all historical versions from CSV
depotdownloader download -manifest-csv manifests.csv -manifest-csv-all -branch public
```

---

## Getting Help

For general help:
```bash
depotdownloader help
```

For command-specific help:
```bash
depotdownloader help download
depotdownloader help validation
depotdownloader help chunkstore
```

For version information:
```bash
depotdownloader version
