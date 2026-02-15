# Xbox Collection Tracker

Fetches your Xbox/Microsoft Store entitlements and Game Pass catalog, then generates a self-contained HTML explorer page with filtering, sorting, and pricing info in both GBP and USD.

## Requirements

- Python 3.7+ (stdlib only, no pip packages needed)

## Setup

### Getting your XBL3.0 Auth Token

The Collections API requires a token with device authentication claims, which can only be captured from the Xbox app via MITM proxy (e.g. [mitmproxy](https://mitmproxy.org/)).

1. Set up mitmproxy on your PC and route your Android/iOS device through it
2. Open the Xbox app on your device — it will make authenticated API calls
3. Export the capture as a HAR file and place it in this directory
4. Run the auth helper:

```bash
python xbox_auth.py
```

It auto-detects `.har` files, extracts all XBL3.0 tokens, and picks the one used for `collections.mp.microsoft.com`. You can also specify a file: `python xbox_auth.py mycapture.har`

> **Note:** Tokens expire after a few hours. Recapture and re-run when needed.

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
