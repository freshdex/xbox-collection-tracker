# Xbox Collection Tracker

Fetches your Xbox/Microsoft Store entitlements and Game Pass catalog, then generates a self-contained HTML explorer page with filtering, sorting, and pricing info in both GBP and USD.

## Requirements

- Python 3.7+ (stdlib only, no pip packages needed)

## Setup

### Getting your XBL3.0 Auth Token

The script authenticates using an XBL3.0 token from the Microsoft Collections API. To obtain one:

1. Open your browser and go to [xbox.com](https://www.xbox.com) — make sure you're signed in to your Microsoft account.
2. Open Developer Tools (F12) and go to the **Network** tab.
3. Visit [your Microsoft order history](https://account.microsoft.com/billing/orders) or browse the Xbox store, and look for requests to `collections.mp.microsoft.com`.
4. Find a request with an `Authorization` header — the value will start with `XBL3.0 x=`.
5. Copy the **entire** `Authorization` header value (including the `XBL3.0 x=` prefix).

### Saving the token

Create a file called `auth_token.txt` in the project root and paste the full token as a single line:

```
XBL3.0 x=1234567890;eyJlbmMiOi...rest_of_token
```

> **Note:** Tokens expire after a few hours. If you get authentication errors, repeat the steps above to get a fresh token.

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
