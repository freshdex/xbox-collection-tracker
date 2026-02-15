# Xbox Collection Tracker

Fetches your Xbox/Microsoft Store entitlements and Game Pass catalog, then generates a self-contained HTML explorer page with filtering, sorting, and pricing info in both GBP and USD.

## Requirements

- Python 3.7+ (stdlib only, no pip packages needed)

## Setup

### Getting your XBL3.0 Auth Token

The script authenticates using an XBL3.0 token. There are two ways to get one:

#### Option A: Extract from browser cookie (easiest)

1. Go to [microsoft.com/store](https://www.microsoft.com/store) in Chrome or Edge and sign in with your Xbox account.
2. Open DevTools (F12) > **Console** tab.
3. Paste this and press Enter:
   ```js
   copy(JSON.parse(unescape(document.cookie.split('; ').find(c => c.startsWith('XBXXtkhttp://xboxlive.com=')).split('=').slice(1).join('='))).Token)
   ```
4. The token is now on your clipboard.

> If you get an error, make sure you're signed in and on a `microsoft.com` page.

#### Option B: Browser DevTools Network tab

1. Open [xbox.com/en-GB/games/all-games](https://www.xbox.com/en-GB/games/all-games) and sign in.
2. Open DevTools (F12) > **Network** tab.
3. In the filter bar, type `xbl` or `authorization` to narrow results.
4. Browse around or click on games — look for requests to any `*.xboxlive.com` or `*.mp.microsoft.com` domain.
5. Click a request, go to **Headers**, and find the `Authorization` header starting with `XBL3.0 x=`.
6. Copy the **entire** value.

### Saving the token

Paste the full token into `auth_token.txt` (already included in the repo) as a single line:

```
XBL3.0 x=1234567890;eyJlbmMiOi...rest_of_token
```

> **Note:** Tokens expire after a few hours. If you get authentication errors, grab a fresh one.

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
