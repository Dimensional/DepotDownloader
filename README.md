DepotDownloader
===============

Steam depot downloader utilizing the SteamKit2 library. Supports .NET 9

This program must be run from a console, it has no GUI.

## Installation

### Directly from GitHub

Download a binary from [the releases page](https://github.com/SteamRE/DepotDownloader/releases/latest).

### via Windows Package Manager CLI (aka winget)

On Windows, [winget](https://github.com/microsoft/winget-cli) users can download and install
the latest Terminal release by installing the `SteamRE.DepotDownloader`
package:

```powershell
winget install --exact --id SteamRE.DepotDownloader
```

### via Homebrew

On macOS, [Homebrew](https://brew.sh) users can download and install the latest release by running the following commands:

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
- **`reconstruct`** - Process raw chunks into installed files [Coming Soon]
- **`chunkstore`** - Manage chunk storage and deduplication [Coming Soon]

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
Download Steam Workshop items.

```bash
depotdownloader download -workshop <id> [<id>...] [OPTIONS...]
depotdownloader download -workshop-csv <file> [OPTIONS...]
```

**Examples:**
```bash
# Download workshop items by ID
depotdownloader download -workshop 1885082371 770604181014286929

# Download workshop items from CSV
depotdownloader download -workshop-csv workshop_items.csv
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

## Chunkstore Command (Coming Soon)

Manage and organize chunk storage for efficient depot operations.

### Planned Operations

```bash
depotdownloader chunkstore pack <input-folder> <output-folder> [OPTIONS...]
depotdownloader chunkstore unpack <chunkstore-folder> <output-folder> [OPTIONS...]
depotdownloader chunkstore stats <chunkstore-folder> [OPTIONS...]
depotdownloader chunkstore verify <chunkstore-folder> [OPTIONS...]
depotdownloader chunkstore rebuild <chunkstore-folder> [OPTIONS...]
depotdownloader chunkstore update <chunkstore-folder> <new-chunks-folder> [OPTIONS...]
```

For more details:
```bash
depotdownloader help chunkstore
```

---

## Reconstruct Command (Coming Soon)

Process raw depot chunks into installed files.

### Planned Usage

```bash
depotdownloader reconstruct <depot-path> [OPTIONS...]
```

For more details:
```bash
depotdownloader help reconstruct
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
# Download workshop items
depotdownloader download -workshop 123456 789012

# Download from CSV
depotdownloader download -workshop-csv workshop_items.csv
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
