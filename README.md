# Xbox Collection Tracker (XCT)

**v1.2**

Track your Xbox game library across multiple accounts. See every game you own, what it's worth, what's on Game Pass, compare regional prices, and browse the full Xbox Marketplace — all in one page you can open in your browser.

## What's New in v1.2

- **DLC nesting under parent games** — Games with DLC now show a green "+" button on their thumbnail in list view. Click to expand and see all DLC nested underneath the parent game. A badge shows the DLC count next to the title. Grid view stays flat.
- **DLC filter dropdown** — New "DLC: All / Has DLC / No DLC" filter in the library toolbar to show only games with DLC or only standalone items.
- **DLC shown by default** — The Type filter now includes DLC (Durable) checked by default so DLC items are visible on load.
- **Wider title column** — The title column in list view now flexes to fill available space, making full titles and badges (DLC, GP, etc.) visible.
- **Tab bar cleanup** — "Game Pass Catalog" tab shortened to "Game Pass". Currency dropdown and version label moved closer to the tabs.

## Setup (first time)

### 1. Install Python

You need Python installed on your computer. If you don't have it:

- **Windows:** Go to https://www.python.org/downloads/ and click the big yellow download button. During install, **tick the box that says "Add Python to PATH"** — this is important.
- **Mac:** Open Terminal and run `brew install python3`, or download from the link above.

To check if Python is installed, open a terminal (Command Prompt on Windows, Terminal on Mac) and type:
```
python --version
```
You should see something like `Python 3.11.5`. Any version 3.7 or higher works.

### 2. Download XCT

Download this repository and extract it to a folder, or clone it with git:
```
git clone https://github.com/freshdex/xbox-collection-tracker.git
```

### 3. Install dependencies

Open a terminal, navigate to the XCT folder, and run:
```
pip install -r requirements.txt
```

This installs `ecdsa`, which is needed for full Xbox authentication. Without it, XCT still works but can only see a limited set of your games.

### 4. Run it

```
python XCT.py
```

On first run, it will ask you to add an Xbox account. Follow the on-screen instructions — you'll get a code to enter at a Microsoft login page in your browser. After signing in, XCT saves your login so you don't need to do this again.

### 5. Open the output

Once processing finishes, XCT opens an HTML file in your browser automatically. You can also find it at `accounts/XCT.html` — just double-click it any time to view your library.

---

## How to use

Run `python XCT.py` to open the interactive menu. Pick an option by typing its letter or number and pressing Enter.

### Menu options

| Option | What it does |
|--------|-------------|
| **1, 2, 3...** | Process a specific account (refreshes token + rebuilds library) |
| **A** | Add a new Xbox account |
| **R** | Refresh an existing account's login token |
| **D** | Delete an account |
| **\*** | Process all accounts at once |
| **X** | Clear all cached data and rescan everything from scratch |
| **B** | Rebuild HTML from cached data (no internet needed) |
| **Q** | Quit |

### Scan endpoints

| Option | What it does |
|--------|-------------|
| **E** | Collections API only scan |
| **T** | TitleHub only scan |
| **S** | Content Access scan (finds Xbox 360 backward-compatible titles) |

### Catalogs

| Option | What it does |
|--------|-------------|
| **G** | Game Pass catalog |
| **M** | Full Marketplace scan (all channels, GB region) |
| **L** | Full Marketplace scan (all channels, all 11 regions) |
| **P** | Regional Prices (enrich existing marketplace data with price comparison) |
| **N** | New Games catalog |
| **C** | Coming Soon catalog |
| **F** | Game Demos catalog |

### Discovery

| Option | What it does |
|--------|-------------|
| **W** | Web Browse catalog (US only) |
| **Z** | Web Browse catalog (all 7 regions — catches region exclusives) |
| **H** | TitleHub ID scan (discovers hidden/delisted titles) |
| **Y** | Full discovery (Marketplace + Browse + TitleHub, all regions) |

### Command line shortcuts

```
python XCT.py add                # Add new account
python XCT.py extract            # Extract token from a HAR file
python XCT.py <gamertag>         # Process a specific account
python XCT.py --all              # Process all accounts
python XCT.py build              # Rebuild HTML without fetching data
```

---

## The HTML page

The generated page (`accounts/XCT.html`) has six tabs:

### Library

Your complete game collection across all accounts. Shows total counts, game values, and DLC values.

**Filters** let you narrow down by platform (Xbox Series X|S, Xbox One, Xbox 360, PC), publisher, developer, release year, purchase year, status, type, listing status, and more. Use the search box to find specific games.

**Game Pass dropdown** filters by ownership and Game Pass status: All, Owned, Owned + on Game Pass, Game Pass Not Owned, or Game Pass + Owned.

**Views:** Switch between grid view (box art cards) and list view (table with sortable columns) using the toggle in the top right.

**Right-click** any game to flag it as delisted, demo, or indie. **Click** any game to see full details, pricing, and a store link.

### Marketplace

Browse the Xbox Marketplace. Filter by channel, type, platform, and publisher. Shows Game Pass badges and owned status on each item.

**Regional pricing:** Each item shows the cheapest region to buy from (gift card USD). Click an item to see the full price comparison table across all 10 regions with local prices converted to gift-card-adjusted USD (0.81 factor).

### Game Pass

The full Game Pass catalog with filters for Recently Added and Most Popular. Shows which games you already own.

### Play History

Games you've played but don't own — disc games, trials, rentals, and other played titles from TitleHub.

### Scan Log

History of your scans showing what changed each time (games added, removed, or modified).

### Gamertags

Per-account stats table showing item counts, game/DLC counts, and total values for each gamertag.

---

## Regional pricing

The marketplace supports price comparison across 10 regions: Argentina, Brazil, Turkey, Iceland, Nigeria, Taiwan, New Zealand, Colombia, Hong Kong, and USA. Prices are fetched directly from Xbox catalog endpoints per region (not currency conversions). Exchange rates from a free API convert each price to a "Gift Card USD" value using a 0.81 factor to account for discounted gift card purchasing.

Use `[P]` to enrich existing marketplace data with regional prices, or `[M]`/`[L]` which include regional pricing automatically.

---

## Auto token refresh

Tokens expire after approximately 16 hours. XCT proactively checks token age before any operation and auto-refreshes if the token is older than 12 hours. If a 401 error is encountered mid-operation, XCT will also auto-refresh and retry.

---

## Troubleshooting

**"python is not recognized"** — Python isn't installed or wasn't added to PATH. Reinstall Python and make sure to tick "Add Python to PATH" during setup. On Windows you can also try `py XCT.py` instead.

**"No module named ecdsa"** — Run `pip install -r requirements.txt` (or `pip install ecdsa`) to install the required package.

**SSL certificate errors / "CERTIFICATE_VERIFY_FAILED"** — Python on Windows uses its own certificate bundle which can be outdated. Running `pip install -r requirements.txt` installs `pip_system_certs` which fixes this by using your Windows certificates instead. If you already installed dependencies before this fix existed, run `pip install pip_system_certs` to add it.

**Token expired / auth errors** — Select your account from the menu or use `[R]` to refresh its token. Tokens should auto-refresh, but if the refresh token itself has expired, you may need to re-add the account with `[A]`.

**0 items from Collections API** — Make sure `ecdsa` is installed. Without it, the tool falls back to a simpler auth method that can't access the Collections API.

**Cache showing old data** — Use `[X]` from the menu to clear all caches and rescan from scratch.

---

## File structure

```
XCT.py                  # Main script
xbox_auth.py            # Standalone auth helper
tags.json               # Community game tags (delisted, indie, etc.)
requirements.txt        # Python dependencies
accounts.json           # Account registry (auto-generated)
exchange_rates.json     # Cached exchange rates (auto-generated)
accounts/
  XCT.html              # Combined HTML page (all accounts)
  data.js               # Combined library data
  {gamertag}/
    XCT.html            # Per-account HTML page
    data.js             # Per-account library data
    *.json              # Cached API responses (1-hour TTL)
    auth_token.txt      # Auth tokens
    xbox_auth_state.json # Saved login credentials
```

## Community Tags

`tags.json` contains community-contributed flags for delisted games, indie titles, and demos. To contribute, edit the file and submit a pull request. Each entry needs the product ID (found in the detail modal) and the game title.

## Credits

Xbox Collection Tracker by Freshdex
