# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Single-file Python tool (`XCT.py`, ~7000 lines) that handles Xbox Live authentication, fetches your game library via TitleHub and Collections APIs, enriches with catalog metadata, then generates a self-contained HTML explorer page. Supports multiple Xbox accounts.

## Dependencies

- Python 3.7+
- `ecdsa` — EC P-256 signing for device-bound auth
- `pip_system_certs` — Windows-only, fixes SSL cert issues by using OS certificate store

Install: `pip install -r requirements.txt`

The `ecdsa` package enables device-bound XSTS tokens required for the Collections API. Without it, only TitleHub (simple auth) works.

## Running

```bash
python XCT.py                    # Interactive menu
python XCT.py <gamertag>         # Refresh token + process specific account
python XCT.py --all              # Refresh all tokens + process all accounts
python XCT.py add               # Add new account (device code flow)
python XCT.py extract [file]    # Extract token from HAR file
python XCT.py build             # Rebuild HTML from cached data (no network)
```

There are no tests or linting configured in this project.

## Architecture

### Auth — Device-Bound (EC P-256, primary)
1. **MSA Token** — Device code flow or refresh via `login.live.com`
2. **EC P-256 Key** — Generated per-device, persisted in `xbox_auth_state.json`
3. **Device Token** (`get_device_token`) — Registers device at `device.auth.xboxlive.com` with ProofOfPossession signing
4. **SISU Authorize** (`sisu_authorize`) — Gets User + Title + Auth tokens from `sisu.xboxlive.com/authorize`
5. **XSTS Tokens** (`get_xsts_token_device_bound`) — Two XSTS tokens with device claims: `xboxlive.com` RP (TitleHub) and `mp.microsoft.com` RP (Collections API)
6. **XBL3.0 Tokens** — Saved to `auth_token.txt` and `auth_token_xl.txt`

The device-bound flow signs all requests with an EC P-256 key (`RequestSigner` class), producing XSTS tokens with device claims required by Collections API. Falls back to non-device-bound flow if `ecdsa` is not installed (only TitleHub works).

### Token Lifecycle
Tokens expire after ~16 hours. Auto-refresh triggers proactively when token age exceeds 12 hours (`_is_token_expired`), and reactively on 401 errors. Token refresh clears all cached API responses via `clear_api_cache()`.

### Library Pipeline (`process_account`)
1. **Auth** (`read_auth_token`) — Reads XBL3.0 token from account directory
2. **Entitlements** (`fetch_entitlements`) — Collections API (~5000 items with purchase metadata) + TitleHub (~1000 items with game metadata), merged in "Both" mode
3. **Catalog Enrichment** — Primary: `catalog.gamepass.com/v3/products` (single POST, all IDs). Fallback: `displaycatalog.md.mp.microsoft.com/v7.0` (batched, 20 IDs/req)
4. **Merge** (`merge_library`) — Combines entitlement records with catalog data into unified library items
5. **Scan History** — `compute_changelog` diffs against previous scan, `save_scan` writes timestamped snapshot to `history/` subdirectory
6. **Output** — `build_html_template` generates static HTML, `write_data_js` writes data as JS constants (`LIB`, `GP`, `PH`, `MKT`, `HISTORY`, `DEFAULT_FLAGS`, `ACCOUNTS`, `RATES`, `GC_FACTOR`)

### Marketplace Pipeline (`process_marketplace` / `process_marketplace_all_regions`)
Fetches Xbox store catalog via DynamicChannels (`fetch_dynamic_channel`) from `bronze.xboxservices.com`, enriches with catalog metadata, and optionally fetches regional prices across 10 markets.

### Discovery Pipeline
- **Web Browse** (`fetch_browse_all` / `fetch_browse_all_regions`) — Crawls Xbox store browse pages for all products
- **TitleHub Scan** (`scan_titlehub_coarse`) — Batch-probes TitleHub ID ranges to discover hidden/delisted titles
- **Content Access** (`fetch_contentaccess`) — Finds Xbox 360 backward-compatible titles via content access API

### Combined Index (`build_index`)
Merges all per-account libraries into a single combined `accounts/XCT.html` + `accounts/data.js` page. Each account also gets its own `accounts/{gamertag}/XCT.html` + `data.js`.

### Key Endpoints
- **Collections API** (`collections.mp.microsoft.com/v7.0`) — Full entitlements, requires device-bound token
- **TitleHub** (`titlehub.xboxlive.com`) — Game metadata (names, images, platforms, GP status, achievements)
- **Catalog v3** (`catalog.gamepass.com/v3/products`) — Rich metadata, single POST call
- **Game Pass Subscriptions** (`catalog.gamepass.com/subscriptions`) — Public, no auth
- **Display Catalog** (`displaycatalog.md.mp.microsoft.com/v7.0`) — Legacy fallback catalog
- **DynamicChannels** (`bronze.xboxservices.com`) — Marketplace channel listings
- **Exchange Rates** (`open.er-api.com/v6/latest/USD`) — Free currency conversion

### Regional Pricing
Price comparison across 10 regions (AR, BR, TR, IS, NG, TW, NZ, CO, HK, US). Fetches actual Xbox regional prices via `catalog.gamepass.com/v3/products` with different `market` parameters. Exchange rates convert to "Gift Card USD" using `GC_FACTOR = 0.81`.

## File Layout

```
XCT.py                  # Everything: auth, API calls, HTML generation (~7000 lines)
xbox_auth.py            # Standalone auth helper (legacy, not used by main flow)
tags.json               # Community game tags (delisted, indie, demo flags)
requirements.txt        # Python deps (ecdsa, pip_system_certs)
accounts.json           # Account registry: gamertag → {uhs} (auto-generated)
exchange_rates.json     # Cached exchange rates (auto-generated)
accounts/
  XCT.html              # Combined HTML page (all accounts)
  data.js               # Combined library data (JS constants)
  {gamertag}/
    XCT.html            # Per-account HTML page
    data.js             # Per-account data
    auth_token.txt      # XBL3.0 token (mp.microsoft.com RP)
    auth_token_xl.txt   # XBL3.0 token (xboxlive.com RP)
    xuid.txt            # Xbox User ID
    xbox_auth_state.json # MSA refresh token + EC P-256 key + device ID
    *.json              # Cached API responses (1-hour TTL)
    history/            # Timestamped scan snapshots for changelog
```

## Key Implementation Details

- **Global path state**: `set_account_paths(gamertag)` sets module-level path globals (`AUTH_TOKEN_FILE`, `ENTITLEMENTS_FILE`, etc.) to the current account's directory. Must be called before any per-account operations.
- **HTTP helpers**: `api_request()` handles retries with exponential backoff on 429/5xx. `msa_request()` handles MSA auth calls. `_signed_request()` adds EC P-256 ProofOfPossession signatures.
- **Caching**: All API responses cached as JSON with 1-hour TTL (`CACHE_MAX_AGE = 3600`). `is_cache_fresh()` checks file age.
- **HTML output**: `build_html_template()` returns a large HTML string (~1300 lines of embedded HTML/CSS/JS). Data is loaded from a separate `data.js` file via `<script src>`.
- **Community tags**: `tags.json` maps product IDs to flags (delisted/indie/demo). Loaded at startup into `DEFAULT_FLAGS` dict, embedded in `data.js` output.
- **Interactive menu**: `interactive_menu()` is the main loop. Always entered after CLI arg processing (if any).

## Key Constants

- `CLIENT_ID` / `SCOPE` — MSA app credentials for device-code auth
- `PLATFORM_MAP` — Maps Microsoft platform identifiers to display names
- `GP_COLLECTIONS` — Game Pass collection UUIDs → display names
- `MARKETPLACE_CHANNELS` — DynamicChannel names → display labels
- `PRICE_REGIONS` — Market codes → locale/currency/symbol info
