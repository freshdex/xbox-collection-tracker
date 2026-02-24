# Xbox Collection Tracker (XCT)

Track your Xbox game library across multiple accounts. See every game you own, what it's worth, what's on Game Pass, compare regional prices, and browse the full Xbox Marketplace — all in one page you can open in your browser.

## What's New in v1.7

- **Raw NTFS CDN Scraper — no mount, no conversion, no risk** — The `[E] Scrape CDN Links` tool in the Xbox Hard Drive menu now reads .xvs files directly from raw disk sectors using a built-in NTFS parser (MFT traversal, data run decoding, fixup arrays). Your Xbox drive **never needs to be converted to PC mode or mounted** — the scraper opens the physical disk read-only, walks the MFT, and extracts every .xvs file's CDN URLs, build versions, content IDs, and package metadata. Zero writes to the drive, zero risk of Windows NTFS corruption. Just plug in your Xbox drive, pick it, and scrape.
- **Deleted XVC recovery** — When scraping CDN links, you can now opt to include deleted MFT records. Xbox doesn't zero out .xvs files when you uninstall a game — the MFT record is simply marked as not-in-use, but the data stays on disk until overwritten by a new install. Enabling this option recovers CDN links for games you've previously uninstalled, giving you download URLs for packages that are no longer installed on the drive. The more free space on your drive, the more deleted games you can recover.
- **Multi-version CDN archive** — CDN.json now preserves every version of a game package across rescans. When a game updates and the buildId changes, the old version is archived into a `versions` array while the latest version stays at the top level. The HTML detail modal shows a full **Version History** section with decoded version numbers, platform, size, scrape date, and direct CDN download links for every archived version.
- **CDN filter dropdown** — New filter in the Collection tab toolbar: `CDN: All / Has CDN Links / No CDN Links / Multiple Versions`. Quickly find which games in your library have archived CDN packages, and which ones have multiple version snapshots.
- **CDN version badges** — The XBOX/CDN badge on each game now shows a version count when multiple versions are archived, e.g. `XBOX(3)`.
- **Fix CDN section alignment in detail modal** — The Xbox/CDN Package section in the game detail popup no longer has misaligned labels and values.
- **Fix Gamertag field in detail modal** — The Gamertag row was rendering raw JavaScript instead of the actual gamertag list. Fixed.

## What's New in v1.6.3

- **Fix Xbox 360 platform filter** — Xbox 360 backward-compatible titles from Content Access API were marked as not owned, so the default "Owned" filter hid all 336 Xbox 360 games. Fixed: all library items are now correctly marked as owned.
- **Ring scan speedup** — "Scan all rings" now resolves WuCategoryId and cookie once, queries all 4 rings in parallel, and skips download URL resolution. ~80 sequential HTTP calls reduced to ~6.
- **Xbox Apps & Utilities `[X]`** — New preset list in the MS Store CDN Installer with 10 Xbox-related apps (Xbox app, Game Bar, Identity Provider, Accessories, etc.) and their ProductIds.
- **Scan all rings default** — Pressing Enter at the ring prompt now scans all rings (previously required typing `*`).
- **AppxPackage install fix** — `.eappxbundle` files (Xbox-only encrypted bundles) are now skipped during PC install. Dependencies are passed to all main packages, not just the first.
- **B = Back everywhere** — All interactive prompts now consistently use `[B]` for back/cancel.
- **"Library" → "Collection"** — All user-facing text renamed from "Library" to "Collection" (tab label, search placeholder, tooltips, CLI messages). Internal code unchanged.
- **New menu options** — Added `[I]` Xbox CDN Installer and `[U]` Hard Delist Installer placeholders. Reordered Utilities section.

## What's New in v1.6.2

- **Fix Display Catalog crash** — The API sometimes returns `null` for array fields (Images, Packages, etc.), causing "'NoneType' object is not iterable" errors during catalog enrichment. Fixed with null-safe iteration.
- **Export filename** — Exported JSON now includes the top gamertag and GT count in the filename (e.g. `xct_export_Play_Jamsesh_52gt_2026-02-22.json`).
- **Consistent terminology** — All user-facing "Account" labels renamed to "Gamertag" across CLI and HTML.
- **Reorganized menu** — Gamertag management options (add, refresh, delete, rescan) moved under the Gamertags section header.
- **HTML title** — Browser tab now shows "Xbox Collection Tracker vX.X.X by Freshdex".

## What's New in v1.6.1

- **Import storage fix** — Switched from localStorage (5MB limit) to IndexedDB for imported library data, so large collections import without errors.
- **Import gamertag dropdown** — All gamertags from an import now appear individually in the Gamertag filter dropdown, grouped under labeled sections ("Import #1: label") with inline remove buttons.
- **Import remove confirmation** — Removing an import now shows a confirmation dialog with the collection name and item count.

## What's New in v1.6

- **Library Import/Export** — Share your Xbox game collection without exposing credentials. Export your library as a JSON file (excludes Game Pass-only entitlements, strips large fields for size). Import collections from others — imported items appear alongside your own in the same filters, dropdowns, and grid/list views with a subtle "imported" badge. Manage imports from a dedicated Imports tab.

## What's New in v1.5

- **MS Store Package Fetcher `[O]`** — Fetches direct CDN download links for any Microsoft Store app or game (including delisted titles) directly from Microsoft's delivery CDN (`fe3cr.delivery.mp.microsoft.com`). No third-party proxy — talks to the Windows Update SOAP API directly. Accepts ProductId, CategoryId (WuCategoryId), PackageFamilyName, or a store URL. Supports all rings (RP, Retail, WIF, WIS). Downloads `.appx`, `.appxbundle`, `.msix`, `.msixbundle` and `.BlockMap` files directly. Includes **Freshdex Database** — browse all PC/Windows games from your combined library across all accounts with letter, year, genre, and search filters. Also accessible via `[O]` inside the `[K]` CDN discovery submenu.

## What's New in v1.4.2

- **Update check runs first** — The GitHub version check now runs before any other script code, so bugs in the main script (like the v1.4.1 `.json` issue) can no longer prevent users from auto-updating.
- **`gfwl_links.json` included in updates** — The auto-updater now also downloads `gfwl_links.json` when updating, keeping the GFWL package database in sync.

## What's New in v1.4.1

- **Bundled `gfwl_links.json`** — GFWL package data (246 titles, 1,775 packages) is now included in the repo so `[J]` works out of the box for new users without needing a separate build step.
- **Fix GFWL tab not appearing after rebuild** — The HTML tab guard used `window.GFWL` which doesn't work for `const` declarations in modern browsers. Fixed to use `typeof GFWL === 'undefined'`.
- **GFWL manifest links use `download-ssl.xbox.com`** — Manifest badge links in the GFWL HTML tab now point to `download-ssl.xbox.com` (bypasses Akamai ACL that blocks `download.xbox.com`).
- **Robust HTML init** — Wrapped the page initialisation chain in `try/catch` so a JS error in one section (e.g. missing library data) no longer prevents the GFWL tab from rendering.

## What's New in v1.4

- **GFWL Game Downloader `[J]`** — Downloads Games for Windows - LIVE packages directly from Microsoft's CDN (`download-ssl.xbox.com`). Lists all 71 GFWL achievement games with package counts and sizes. Select a game, choose which packages to download, and XCT automatically extracts with 7-Zip and launches the installer (`Game.msi` / `Setup.exe`).
  - Package types are labelled: **Base** (main installer), **DLC**, **Content** (game data chunks for games with no standard installer), **Trailer** (bonus video bundled alongside games that have a Base installer), **Config** (tiny license blobs).
  - Falls back to an alternate CDN suffix format when the stored offer ID returns 404.
  - Downloads resume automatically if interrupted.
  - Default download folder: `gfwl_downloads/` inside the XCT directory.
- **GFWL tab in HTML** — The generated HTML page now includes a searchable GFWL tab showing all 71 achievement games with manifest link badges per package (green = Base, blue = DLC/Pack). Includes Legend of the Galactic Heroes (`銀河英雄伝説`, title ID `424107DF`).

## What's New in v1.3

- **Xbox USB Drive Scanner** — Scans an Xbox external drive and indexes all installed game packages from `.xvs` files. Captures CDN URLs, build versions, content IDs, package sizes, and prior-version data. Accessible via `[U]` in the menu.
- **USB database `[I]`** — Saves all scanned USB drive metadata to `usb_db.json`. Auto-snapshots the previous state before each rescan so you can diff before/after a game update.
- **USB badges in HTML** — Games present on your USB drive show a **USB** badge in list and grid view. The detail modal shows a dedicated USB section with content ID, build version, and direct CDN download links.
- **CDN version discovery `[K]`** — New utility menu for probing the Xbox CDN:
  - `[D]` **Download current packages** — Direct CDN download of any installed game package (bypasses the Xbox console entirely). Supports selecting individual games or the full library.
  - `[C]` **Compare snapshots** — Diffs two USB DB scans to detect games that updated (planUUID changed), then probes the old CDN path for the prior-version package.
  - `[A]` **CDN sweep** — Fast sweep of all games probing prior-version URLs from XVS data.
  - `[W]` **Windows Update Catalog** — Queries `displaycatalog.mp.microsoft.com` for each game's WuCategoryId, then searches the Microsoft Update Catalog for historical update entries. WuCategoryId is cached in `usb_db.json`.
  - `[S]` **Select game** — Verbose per-game CDN probe.
  - `[R]` **Refresh WU links** — Re-fetches fresh download links for a WuCategoryId.
- **Xbox Drive Converter `[V]`** — Converts an Xbox external drive's MBR signature between Xbox mode (`0x99 0xCC`) and PC mode (`0x55 0xAA`). Also triggers a Disk Management rescan. Equivalent to the XboxOneStorageConverter app, built directly into XCT.
- **Accounts sub-menu** — With many accounts, the main menu no longer lists every gamertag. Press `[0]` to open the account picker showing all accounts with token age, or type a number directly.

## What's New in v1.2

- **DLC nesting under parent games** — Games with DLC now show a green "+" button on their thumbnail in list view. Click to expand and see all DLC nested underneath the parent game. A badge shows the DLC count next to the title. Grid view stays flat.
- **DLC filter dropdown** — New "DLC: All / Has DLC / No DLC" filter in the library toolbar to show only games with DLC or only standalone items.
- **DLC shown by default** — The Type filter now includes DLC (Durable) checked by default so DLC items are visible on load.
- **Wider title column** — The title column in list view now flexes to fill available space, making full titles and badges (DLC, GP, etc.) visible.
- **Tab bar cleanup** — "Game Pass Catalog" tab shortened to "Game Pass". Currency dropdown and version label moved closer to the tabs.
- **Auto-update** — XCT checks GitHub for newer versions on startup and prompts you to update if one is available.

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
