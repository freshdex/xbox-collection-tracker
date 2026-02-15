# Xbox Collection Tracker

Fetches your Xbox/Microsoft Store entitlements and Game Pass catalog, then generates a self-contained HTML explorer page with filtering, sorting, and pricing info in both GBP and USD.

## Requirements

- Python 3.7+ (stdlib only, no pip packages needed)

## Setup

### Getting your XBL3.0 Auth Token

Run the included auth helper:

```bash
python xbox_auth.py
```

This will:
1. Open your browser to the Microsoft login page
2. Sign in with your Microsoft/Xbox account
3. The browser redirects to a local server that captures the auth code automatically
4. The script exchanges it for an XBL3.0 token and saves it to `auth_token.txt`

No Azure app registration or extra dependencies needed — it uses the same public Xbox Live client ID as the official Xbox app.

> **Note:** Tokens expire after a few hours. Re-run `python xbox_auth.py` to get a fresh one.

## Usage

```bash
python xbox_library.py
```

The script will:
1. Read your auth token from `auth_token.txt`
2. Fetch all your entitlements (paginated)
3. Fetch Display Catalog details for GB and US markets
4. Fetch the Game Pass catalog
5. Generate `xbox_library.html` and open it in your browser

API responses are cached as JSON files for 1 hour. Delete the `.json` files to force a re-fetch.

## Output

`xbox_library.html` — a self-contained page with two tabs:

- **My Library** — all your entitlements with filters for status, type, category, platform, publisher, release year, and purchase year
- **Game Pass Catalog** — full Game Pass listing showing which games you already own
