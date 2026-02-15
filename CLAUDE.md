# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Single-file Python tool (`xbox_library.py`) that fetches Xbox/Microsoft Store entitlements and Game Pass catalog data, then generates a self-contained HTML explorer page. Uses only Python 3.7+ stdlib (no pip dependencies).

## Running

```bash
python xbox_library.py
```

Requires `auth_token.txt` in the same directory containing an `XBL3.0` authentication token. The script auto-opens the generated HTML in the default browser.

## Architecture

The script executes a linear pipeline in `main()`:

1. **Auth** (`read_auth_token`) — Reads XBL3.0 token from `auth_token.txt`
2. **Entitlements** (`fetch_entitlements`) — Paginated POST to Microsoft Collections API (`collections.mp.microsoft.com/v7.0`), returns all owned items
3. **Display Catalog** (`fetch_display_catalog`) — Fetches product metadata (titles, prices, images, platforms) from `displaycatalog.md.mp.microsoft.com/v7.0` in batches of 20 IDs, using `ThreadPoolExecutor(max_workers=10)`. Runs twice: GB market (full metadata) and US market (prices only)
4. **Merge** (`merge_library`) — Combines entitlement records with GB and US catalog data into unified library items
5. **Game Pass** (`fetch_gamepass_catalog` + `fetch_gamepass_details`) — Fetches Game Pass collection IDs from `catalog.gamepass.com/sigls/v2`, then resolves catalog details for items not already in the library
6. **HTML Generation** (`build_html`) — Builds a single HTML file with embedded CSS/JS containing two tabs: "My Library" and "Game Pass Catalog", with filtering, sorting, grid/list views, and a detail modal

## Caching

All API responses are cached as JSON files in the script directory with a 1-hour TTL (`CACHE_MAX_AGE = 3600`). Delete the JSON files to force a re-fetch:
- `entitlements.json` — Raw entitlement data
- `catalog_gb.json` / `catalog_us.json` — Display Catalog responses per market
- `gamepass.json` / `gamepass_details.json` — Game Pass catalog and resolved details
- `_gp_catalog_gb_tmp.json` / `_gp_catalog_us_tmp.json` — Temp files for GP-only catalog fetches

## Output

`xbox_library.html` — Self-contained HTML page with all data embedded as JSON in `<script>` tags (variables `LIB` and `GP`). The HTML includes client-side filtering/sorting and uses `localStorage` key `xboxLibFlags` for user-flagged items.

## Key Constants

- `PLATFORM_MAP` — Maps Microsoft platform identifiers to display names (e.g., `Windows.Xbox` → `Xbox One`)
- `GP_COLLECTIONS` — Game Pass collection UUIDs mapped to display names
- `api_request()` — Central HTTP function with retry logic (exponential backoff on 429/5xx errors)
