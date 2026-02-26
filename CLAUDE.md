# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Xbox Collection Tracker (XCT) — single-file Python tool (`XCT.py`, ~15,300 lines) that authenticates with Xbox Live, fetches game library data via multiple Microsoft APIs, enriches with catalog metadata, and generates a self-contained HTML explorer page. Supports multiple Xbox accounts. Also includes Xbox hard drive tools, CDN scraping/sync, CDN download/install utilities, GFWL game downloading, and Windows gaming repair tools.

## Dependencies & Running

```bash
pip install -r requirements.txt    # ecdsa + pip_system_certs (Windows)
python XCT.py                      # Interactive menu
python XCT.py <gamertag>           # Refresh token + process specific account
python XCT.py --all                # Refresh all tokens + process all accounts
python XCT.py add                  # Add new account (device code flow)
python XCT.py extract [file]       # Extract token from HAR file
python XCT.py build                # Rebuild HTML from cached data (no network)
python XCT.py preview              # Generate blank HTML only (UI testing, no account data)
python XCT.py --no-update ...      # Skip GitHub update check (combine with any other arg)
```

There are no tests or linting configured. `debug.log` is auto-written every run — mirrors stdout plus Python version, CWD, and args. First place to look for tracebacks.

## Architecture

### Auth — Device-Bound (EC P-256, primary)
1. **MSA Token** — Device code flow or refresh via `login.live.com`
2. **EC P-256 Key** — Generated per-device, persisted in `xbox_auth_state.json`
3. **Device Token** (`get_device_token`) — Registers device at `device.auth.xboxlive.com` with ProofOfPossession signing
4. **SISU Authorize** (`sisu_authorize`) — Gets User + Title + Auth tokens from `sisu.xboxlive.com/authorize`
5. **XSTS Tokens** (`get_xsts_token_device_bound`) — Two XSTS tokens with device claims: `xboxlive.com` RP (TitleHub) and `mp.microsoft.com` RP (Collections API)
6. **XBL3.0 Tokens** — Saved to `auth_token.txt` and `auth_token_xl.txt`

`RequestSigner` class handles EC P-256 ProofOfPossession signatures. Falls back to non-device-bound flow if `ecdsa` is not installed (only TitleHub works).

### Token Lifecycle
Tokens expire after ~16 hours. Auto-refresh triggers proactively when token age exceeds 12 hours (`_is_token_expired`), and reactively on 401 errors. Token refresh clears all cached API responses via `clear_api_cache()`.

### Library Pipeline (`process_account`)
1. **Auth** (`read_auth_token`) — Reads XBL3.0 token from account directory
2. **Entitlements** (`fetch_entitlements`) — Collections API (~5000 items) + TitleHub (~1000 items), merged in "Both" mode
3. **Catalog Enrichment** — Primary: `catalog.gamepass.com/v3/products` (single POST). Fallback: `displaycatalog.md.mp.microsoft.com/v7.0` (batched, 20 IDs/req)
4. **Merge** (`merge_library`) — Combines entitlement records with catalog data
5. **Scan History** — `compute_changelog` diffs against previous scan, `save_scan` writes timestamped snapshot to `history/`
6. **Output** — `build_html_template` generates static HTML, `write_data_js` writes data as JS constants (`LIB`, `GP`, `PH`, `MKT`, `HISTORY`, `DEFAULT_FLAGS`, `ACCOUNTS`, `RATES`, `GC_FACTOR`)

### Marketplace Pipeline (`process_marketplace` / `process_marketplace_all_regions`)
Fetches Xbox store catalog via DynamicChannels (`fetch_dynamic_channel`) from `bronze.xboxservices.com`, enriches with catalog metadata, and optionally fetches regional prices across 10 markets.

### Discovery Pipeline
- **Web Browse** (`fetch_browse_all` / `fetch_browse_all_regions`) — Crawls Xbox store browse pages for all products
- **TitleHub Scan** (`scan_titlehub_coarse`) — Batch-probes TitleHub ID ranges to discover hidden/delisted titles
- **Content Access** (`fetch_contentaccess`) — Finds Xbox 360 backward-compatible titles

### Combined Index (`build_index`)
Merges all per-account libraries into a single combined `accounts/XCT.html` + `accounts/data.js`. Each account also gets its own `accounts/{gamertag}/XCT.html` + `data.js`.

### Xbox Hard Drive Tool (`process_xbox_hd_tool`, menu `[v]`)
Raw disk access via `\\.\PhysicalDriveN` on Windows. Reads/writes MBR, GPT, NTFS structures directly. Key operations:
- **Analyze** — Reads MBR signature, GPT headers, partition entries, NTFS boot sector
- **PC/Xbox mode conversion** — Rewrites MBR signature (`0x55AA` ↔ `0x99CC`) and GPT partition type GUID with full CRC recalculation (primary + backup GPT)
- **Mount/Unmount** — Hides partition type GUID to prevent Windows NTFS corruption on read-only mount
- **Format** — Creates Xbox-format GPT (non-standard: `PartitionEntryStart=3`, `NumberOfPartEntries=1`, `FirstUsableLBA=4`)
- **Install XVC** — Raw NTFS parser (MFT traversal, data run decoding, fixup arrays) to scrape CDN links from `.xvs` files
- **GPT snapshot/restore** — Saves sectors 0-3 + backup GPT; byte-for-byte restore

Key NTFS functions: `_ntfs_read_boot_sector`, `_ntfs_apply_fixup`, `_ntfs_parse_attributes`, `_ntfs_decode_data_runs`, `_ntfs_read_mft_record`, `_ntfs_collect_mft_runs`

### USB Drive Scanner (`scan_usb_drive` / `build_usb_db`)
Scans Xbox external drive's `.xvs` files for installed game packages. Captures CDN URLs, build versions, content IDs, package sizes, prior-version data. Saves to `usb_db.json`.

### CDN Version Discovery (`process_cdn_version_discovery`, menu `[w]` submenu)
Probes Xbox CDN (`assets.xboxlive.com`) for game package versions. Includes snapshot comparison, WU Catalog integration, and direct CDN download.

### MS Store CDN Installer (`process_store_packages`, menu `[y]`)
Fetches direct CDN links from `fe3cr.delivery.mp.microsoft.com` (Windows Update SOAP API). Accepts ProductId, CategoryId, PackageFamilyName, or store URL. Supports RP/Retail/WIF/WIS rings. Downloads and optionally installs `.appx`/`.msixbundle` packages.

### CDN Sync (`process_cdn_sync`, menu `[S]`)
Community CDN package database. Uploads local `CDN.json` entries to the Freshdex shared database, downloads entries from other contributors, merges into local `CDN.json`. Points system rewards new unique game+version contributions. Config in `cdn_sync_config.json`, per-entry source tracking in `cdn_sync_meta.json`, operation history in `cdn_sync_log.json`.

### PC CDN Scraper (`process_pc_cdn_scrape` / `scan_pc_games`, menu `[T]`)
Scrapes CDN links from locally installed Windows PC games. Auto-detects drives with `\XboxGames\` directories, reads `.xvs` package metadata. Also reads `MicrosoftGame.Config` and `appxmanifest.xml` for Title ID, publisher, executable name. Merges into `CDN.json`.

### GFWL Downloader (`process_gfwl_download`, menu `[O]`)
Downloads Games for Windows - LIVE packages from `download-ssl.xbox.com`. Uses `gfwl_links.json` (244 titles, 1,775 packages). Extracts with 7-Zip and launches installer.

### GFWL Key Recovery (`recover_gfwl_keys`, menu `[P]`)
Recovers GFWL product keys from `Token.bin` files using Windows DPAPI decryption. Includes 312 GFWL title name mappings.

### Windows Gaming Repair (`menu [Q]`) / Store Reset (`menu [R]`)
PowerShell-based repair tools: re-register Xbox app packages, reset Gaming Services, restart Xbox services. Store reset launches `wsreset.exe`.

### Regional Pricing
Price comparison across 10 regions (AR, BR, TR, IS, NG, TW, NZ, CO, HK, US). Exchange rates convert to "Gift Card USD" using `GC_FACTOR = 0.81`.

## Key Implementation Details

- **Global path state**: `set_account_paths(gamertag)` sets module-level path globals (`AUTH_TOKEN_FILE`, `ENTITLEMENTS_FILE`, etc.) to the current account's directory. Must be called before any per-account operations.
- **HTTP helpers**: `api_request()` handles retries with exponential backoff on 429/5xx. `msa_request()` handles MSA auth calls. `_signed_request()` adds EC P-256 ProofOfPossession signatures.
- **Caching**: All API responses cached as JSON with 1-hour TTL (`CACHE_MAX_AGE = 3600`). `is_cache_fresh()` checks file age.
- **HTML output**: `build_html_template()` (line ~3167) returns a large Python string containing all HTML, CSS, and JS — no separate template files. Data is loaded from a separate `data.js` file via `<script src>`. Edit the frontend entirely within this function.
- **Data output**: `write_data_js()` (line ~5117) writes library data as JS constants to `data.js`. Includes `LIB`, `GP`, `PH`, `MKT`, `HISTORY`, `DEFAULT_FLAGS`, `ACCOUNTS`, `RATES`, `GC_FACTOR`, plus CDN sync data (`CDN_DB`, `CDN_LEADERBOARD`, `CDN_SYNC_LOG`, `CDN_SYNC_META`).
- **Community tags**: `tags.json` maps product IDs to flags (delisted/indie/demo). Loaded at startup into `DEFAULT_FLAGS` dict, embedded in `data.js` output.
- **Interactive menu**: `interactive_menu()` (line ~14721) is the main loop. Uses single-letter keys `[a]`–`[z]` plus `[0]` to quit.
- **Raw disk I/O**: `_hd_open_read`/`_hd_open_write` use `CreateFileW` via `ctypes` for direct sector access. Requires admin.
- **GUID encoding**: Xbox GPT uses mixed-endian GUID format. `_hd_encode_guid()`/`_hd_format_guid()` handle conversion.
- **Windows Update SOAP**: `_fe3_get_cookie`, `_fe3_sync_updates`, `_fe3_get_url` implement the WU SOAP protocol for package resolution.

## Key Endpoints

- **Collections API** (`collections.mp.microsoft.com/v7.0`) — Full entitlements, requires device-bound token
- **TitleHub** (`titlehub.xboxlive.com`) — Game metadata (names, images, platforms, GP status, achievements)
- **Catalog v3** (`catalog.gamepass.com/v3/products`) — Rich metadata, single POST call
- **Display Catalog** (`displaycatalog.md.mp.microsoft.com/v7.0`) — Legacy fallback catalog
- **DynamicChannels** (`bronze.xboxservices.com`) — Marketplace channel listings
- **WU Delivery** (`fe3cr.delivery.mp.microsoft.com`) — MS Store package CDN links via SOAP
- **Xbox CDN** (`assets{N}.xboxlive.com`) — Game package downloads
- **GFWL CDN** (`download-ssl.xbox.com`) — GFWL package downloads
- **Freshdex CDN Sync** (`cdn.freshdex.app/api/v1`) — Community CDN package database

## File Layout

```
XCT.py                     # Everything: auth, API calls, HTML generation, disk tools (~15,300 lines)
xbox_auth.py               # Standalone auth helper (legacy, not used by main flow)
tags.json                  # Community game tags (delisted, indie, demo flags)
gfwl_links.json            # GFWL package database (244 titles, 1,775 packages)
requirements.txt           # Python deps (ecdsa, pip_system_certs)
accounts.json              # Account registry: gamertag → {uhs} (auto-generated)
exchange_rates.json        # Cached exchange rates (auto-generated)
usb_db.json                # Xbox USB drive scan data (auto-generated)
CDN.json                   # Scraped CDN package data (auto-generated)
cdn_sync_config.json       # CDN sync username + API key (auto-generated)
cdn_sync_meta.json         # Per-entry source tracking (auto-generated)
cdn_sync_log.json          # Sync operation history (auto-generated)
cdn_leaderboard_cache.json # Leaderboard cache (auto-generated)
version.txt                # Current version string; checked against GitHub on startup
endpoints.json             # API reference doc (documentation only, not loaded by XCT.py)
debug.log                  # Auto-written each run
accounts/
  XCT.html + data.js       # Combined (all accounts)
  {gamertag}/
    XCT.html + data.js     # Per-account
    auth_token.txt          # XBL3.0 token (mp.microsoft.com RP)
    auth_token_xl.txt       # XBL3.0 token (xboxlive.com RP)
    xuid.txt                # Xbox User ID
    xbox_auth_state.json    # MSA refresh token + EC P-256 key + device ID
    *.json                  # Cached API responses (1-hour TTL)
    history/                # Timestamped scan snapshots for changelog
```

## Key Constants

- `VERSION` — Current version string (also in `version.txt`)
- `CLIENT_ID` / `SCOPE` — MSA app credentials for device-code auth
- `PLATFORM_MAP` — Maps Microsoft platform identifiers to display names
- `GP_COLLECTIONS` — Game Pass collection UUIDs → display names
- `MARKETPLACE_CHANNELS` — DynamicChannel names → display labels
- `PRICE_REGIONS` — Market codes → locale/currency/symbol info
- `GFWL_71_TIDS` — Set of 71 GFWL achievement game title IDs
- `GITHUB_RAW_BASE` / `UPDATE_FILES` — Auto-update: checks `version.txt`, downloads `[XCT.py, xbox_auth.py, requirements.txt, tags.json, gfwl_links.json]`

## Versioning Convention

- Feature releases: `x.x` (e.g. 1.4, 1.5)
- Bugfix releases: `x.x.x` (e.g. 1.4.1)
- Always bump version in: `XCT.py` (`VERSION` constant), `version.txt`, `README.md` (header + new changelog section at top)
- Bugfix changelog section goes above the feature section (most recent first)
