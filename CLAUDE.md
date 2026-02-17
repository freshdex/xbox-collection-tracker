# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Single-file Python tool (`XCT.py`) that handles Xbox Live authentication, fetches your game library via TitleHub and Collections APIs, enriches with catalog metadata, then generates a self-contained HTML explorer page.

## Dependencies

- Python 3.7+
- `ecdsa` — EC P-256 signing for device-bound auth (`pip install ecdsa`)

The `ecdsa` package enables device-bound XSTS tokens which are required for the Collections API to return data. Without it, only TitleHub (simple auth) works.

## Running

```bash
python XCT.py                    # Interactive menu
python XCT.py <gamertag>         # Refresh token + process specific account
python XCT.py --all              # Refresh all tokens + process all accounts
python XCT.py add               # Add new account (device code flow)
python XCT.py extract [file]    # Extract token from HAR file
```

Accounts are stored under `accounts/{gamertag}/` with auth tokens, cached API data, and generated HTML per account.

### Interactive Menu

When run with no arguments, shows a unified menu:
- Numbered accounts — pick one to refresh its token and build its library
- Catalog options: `[G]` Game Pass, `[M]` Marketplace, `[P]` Regional Prices, `[N]` New Games, `[C]` Coming Soon, `[F]` Game Demos (stubs, endpoints TBD)
- `[A]` — Add new account via device code flow
- `[R]` — Refresh token for an existing account
- `[D]` — Delete an account
- `[*]` — Process all accounts (refresh + build)
- `[Q]` — Quit

If no accounts exist, jumps straight to the add flow.

Note: Catalog options (Game Pass, etc.) are global, not per-account. Picking an account number only processes that account's owned library.

## Architecture

The script combines authentication and library building in a single file:

### Auth — Device-Bound (EC P-256, primary)
1. **MSA Token** — Device code flow or refresh via `login.live.com`
2. **EC P-256 Key** — Generated per-device, persisted in `xbox_auth_state.json`
3. **Device Token** (`get_device_token`) — Registers device at `device.auth.xboxlive.com` with ProofOfPossession signing
4. **SISU Authorize** (`sisu_authorize`) — Gets User + Title + Auth tokens from `sisu.xboxlive.com/authorize`
5. **XSTS Tokens** (`get_xsts_token_device_bound`) — Two XSTS tokens with device claims: `xboxlive.com` RP (TitleHub) and `mp.microsoft.com` RP (Collections API)
6. **XBL3.0 Tokens** — Saved to `auth_token.txt` and `auth_token_xl.txt`

The device-bound flow signs all requests with an EC P-256 key (`RequestSigner` class), producing XSTS tokens with device claims required by Collections API.

### Auth — Simple (fallback, no ecdsa)
Falls back to non-device-bound flow if `ecdsa` is not installed. Only TitleHub works; Collections API returns 0 items.

### Auth (HAR extraction)
- `har_extract()` — Parses `.har` files for XBL3.0 tokens, prompts for gamertag label, saves to account directory

### Library Pipeline (in `process_account`)
1. **Auth** (`read_auth_token`) — Reads XBL3.0 token from `accounts/{gamertag}/auth_token.txt`
2. **Library** (`fetch_entitlements`) — Collections API (~5000 items with purchase metadata) + TitleHub (~1000 items with game metadata), merged in "Both" mode
3. **Catalog Enrichment** — Primary: `catalog.gamepass.com/v3/products` (single POST, all IDs). Fallback: `displaycatalog.md.mp.microsoft.com/v7.0` (batched, 20 IDs/req)
4. **Merge** (`merge_library`) — Combines entitlement records with catalog data into unified library items
5. **HTML Generation** (`build_html`) — Builds a single HTML file with embedded CSS/JS

### Key Endpoints
- **Collections API** (`collections.mp.microsoft.com/v7.0`) — Full entitlements list, requires device-bound token
- **TitleHub** (`titlehub.xboxlive.com`) — Game metadata (names, images, platforms, GP status, achievements)
- **Catalog v3** (`catalog.gamepass.com/v3/products`) — Rich metadata for ALL product types (not just GP), single call
- **Game Pass Subscriptions** (`catalog.gamepass.com/subscriptions`) — Public, no auth, all GP tiers
- **Display Catalog** (`displaycatalog.md.mp.microsoft.com/v7.0`) — Legacy fallback catalog
- **Exchange Rates** (`open.er-api.com/v6/latest/USD`) — Free currency conversion for regional pricing

### Regional Pricing
The marketplace tab supports price comparison across 10 regions: Argentina, Brazil, Turkey, Iceland, Nigeria, Taiwan, New Zealand, Colombia, Hong Kong, and USA. Uses `catalog.gamepass.com/v3/products` with different `market` parameters to fetch actual Xbox regional prices (not currency conversions). Exchange rates from `open.er-api.com` convert each to a "Gift Card USD" value using a 0.81 factor (cheap gift card rate). Cached per-region as `prices_{cc}.json` in the account directory.

## Multi-Account Support

- `accounts.json` — Registry mapping gamertag to metadata (uhs)
- `accounts/{gamertag}/` — Per-account directory containing:
  - `auth_token.txt` — XBL3.0 token (mp.microsoft.com RP, for Collections API)
  - `auth_token_xl.txt` — XBL3.0 token (xboxlive.com RP, for TitleHub)
  - `xuid.txt` — User's Xbox User ID
  - `xbox_auth_state.json` — MSA refresh token + EC P-256 key + device ID
  - `entitlements.json`, `catalog_gb.json`, `catalog_us.json`, etc. — Cached API responses
  - `XCT.html` — Generated HTML output

## Caching

All API responses are cached as JSON files in the account directory with a 1-hour TTL (`CACHE_MAX_AGE = 3600`). Token refresh clears cached files automatically via `clear_api_cache()`.

## Output

`accounts/{gamertag}/XCT.html` — Self-contained HTML page with all data embedded as JSON in `<script>` tags (variables `LIB` and `GP`). The HTML includes client-side filtering/sorting and uses `localStorage` key `xboxLibFlags_{gamertag}` for user-flagged items.

## Key Constants

- `CLIENT_ID` / `SCOPE` — MSA app credentials for device-code auth
- `PLATFORM_MAP` — Maps Microsoft platform identifiers to display names (e.g., `Windows.Xbox` → `Xbox One`)
- `GP_COLLECTIONS` — Game Pass collection UUIDs mapped to display names
- `api_request()` — Library HTTP function with retry logic (exponential backoff on 429/5xx errors)
- `msa_request()` — Auth HTTP function for MSA token operations
- `RequestSigner` — EC P-256 ECDSA request signer for Xbox device-bound auth
