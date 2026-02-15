#!/usr/bin/env python3
"""
Xbox Library Explorer - Consolidated Tool
==========================================
Fetches your Xbox/Microsoft Store entitlements, resolves catalog details
(titles, prices, images, platforms) for both GBP and USD markets, pulls
the Game Pass catalog, and builds a self-contained HTML explorer page.

Requirements:
  - Python 3.7+ (stdlib only)
  - auth_token.txt in the same directory containing your XBL3.0 token

Usage:
  python xbox_library.py
"""

import json
import ssl
import urllib.request
import urllib.error
import sys
import io
import time
import os
import webbrowser
import concurrent.futures

# ---------------------------------------------------------------------------
# Fix stdout encoding on Windows so Unicode doesn't explode
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Paths - everything relative to this script's directory
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_TOKEN_FILE    = os.path.join(SCRIPT_DIR, "auth_token.txt")
ENTITLEMENTS_FILE  = os.path.join(SCRIPT_DIR, "entitlements.json")
CATALOG_GB_FILE    = os.path.join(SCRIPT_DIR, "catalog_gb.json")
CATALOG_US_FILE    = os.path.join(SCRIPT_DIR, "catalog_us.json")
GAMEPASS_FILE      = os.path.join(SCRIPT_DIR, "gamepass.json")
GAMEPASS_DETAIL_FILE = os.path.join(SCRIPT_DIR, "gamepass_details.json")
OUTPUT_HTML_FILE   = os.path.join(SCRIPT_DIR, "xbox_library.html")

# How old (in seconds) a cached file can be before we re-fetch
CACHE_MAX_AGE = 3600  # 1 hour

# SSL context for all HTTPS calls
SSL_CTX = ssl.create_default_context()

# Platform name mapping from SKU PlatformDependencies
PLATFORM_MAP = {
    "Windows.Xbox":             "Xbox One",
    "Windows.Desktop":          "PC",
    "Windows.Universal":        "PC/Xbox",
    "Windows.Mobile":           "Windows Phone",
    "Windows.WindowsPhone8x":   "Windows Phone",
    "Windows.WindowsPhone7x":   "Windows Phone",
    "Windows.Team":             "Surface Hub",
    "Windows.Holographic":      "HoloLens",
}

# Game Pass collection IDs
GP_COLLECTIONS = {
    "fdd9e2a7-0fee-49f6-ad69-4354098401ff": "All Game Pass Games",
    "f6f1f99f-9b49-4ccd-b3bf-4d9767a77f5e": "Recently Added",
    "29a81209-df6f-41fd-a528-2ae6b91f719c": "Most Popular",
}


# ===========================================================================
# Helper utilities
# ===========================================================================

def banner():
    """Print a startup banner."""
    print("=" * 64)
    print("  Xbox Library Explorer - Consolidated Tool")
    print("=" * 64)
    print()
    print("  This script will:")
    print("    1. Read XBL3.0 auth token from auth_token.txt")
    print("    2. Fetch all entitlements (paginated)")
    print("    3. Fetch Display Catalog details (GB + US markets)")
    print("    4. Fetch Game Pass catalog + details")
    print("    5. Build a self-contained HTML explorer")
    print()
    print(f"  Output: {OUTPUT_HTML_FILE}")
    print("=" * 64)
    print()


def is_cache_fresh(filepath):
    """Return True if filepath exists and is younger than CACHE_MAX_AGE."""
    if not os.path.isfile(filepath):
        return False
    age = time.time() - os.path.getmtime(filepath)
    return age < CACHE_MAX_AGE


def save_json(filepath, data):
    """Write data to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def load_json(filepath):
    """Load data from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def api_request(url, method="GET", headers=None, body=None, retries=3):
    """
    Make an HTTPS request, returning parsed JSON.
    Retries on transient errors.
    """
    hdrs = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                wait = 2 ** attempt
                print(f"    HTTP {e.code} on {url[:80]}... retry in {wait}s")
                time.sleep(wait)
                continue
            print(f"    HTTP {e.code} on {url[:80]}... {err_body[:200]}")
            return None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            print(f"    Error on {url[:80]}...: {e}")
            return None
    return None


# ===========================================================================
# Step 1: Read auth token
# ===========================================================================

def read_auth_token():
    """Read the XBL3.0 auth token from file."""
    if not os.path.isfile(AUTH_TOKEN_FILE):
        print(f"ERROR: {AUTH_TOKEN_FILE} not found.")
        print("  Please create this file with your XBL3.0 auth token.")
        sys.exit(1)
    with open(AUTH_TOKEN_FILE, "r") as f:
        token = f.read().strip()
    if not token:
        print("ERROR: auth_token.txt is empty.")
        sys.exit(1)
    print(f"[+] Auth token loaded ({len(token)} chars)")
    return token


# ===========================================================================
# Step 2: Fetch entitlements
# ===========================================================================

def fetch_entitlements(auth_token):
    """Fetch all entitlements from the Collections API, handling pagination."""
    if is_cache_fresh(ENTITLEMENTS_FILE):
        items = load_json(ENTITLEMENTS_FILE)
        print(f"[+] Entitlements loaded from cache ({len(items)} items)")
        return items

    print("[*] Fetching entitlements from Collections API...")
    url = "https://collections.mp.microsoft.com/v7.0/collections/query"
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
    }
    base_body = {
        "beneficiaries": [],
        "market": "GB",
        "entitlementFilters": [],
        "excludeDuplicates": True,
        "expandSatisfiedBy": False,
        "maxPageSize": 1000,
        "validityType": "All",
        "productSkuIds": [],
    }

    all_items = []
    page = 0
    continuation = None

    while True:
        page += 1
        body = dict(base_body)
        if continuation:
            body["continuationToken"] = continuation

        data = api_request(url, method="POST", headers=headers, body=body)
        if data is None:
            print("  ERROR: Failed to fetch entitlements page. Aborting.")
            break

        items = data.get("items", [])
        for item in items:
            all_items.append({
                "productId":       item.get("productId", ""),
                "productKind":     item.get("productKind", ""),
                "status":          item.get("status", ""),
                "acquiredDate":    (item.get("acquiredDate") or "")[:10],
                "startDate":       (item.get("startDate") or "")[:10],
                "endDate":         (item.get("endDate") or "")[:10],
                "isTrial":         item.get("isTrial", False),
                "skuType":         item.get("skuType", ""),
                "skuId":           item.get("skuId", ""),
                "purchasedCountry": item.get("purchasedCountry", ""),
                "quantity":        item.get("quantity", 1),
            })

        continuation = data.get("continuationToken")
        print(f"  Page {page}: {len(items)} items (total: {len(all_items)})")
        if not continuation:
            break

    print(f"[+] Total entitlements: {len(all_items)}")
    save_json(ENTITLEMENTS_FILE, all_items)
    return all_items


# ===========================================================================
# Step 3: Fetch Display Catalog (combined pass per market)
# ===========================================================================

def extract_catalog_data(product, market="GB"):
    """
    Extract catalog fields from a single Display Catalog product.
    For GB market: extracts everything (title, description, images, prices, etc.)
    For US market: extracts only USD prices.
    """
    result = {}
    pid = product.get("ProductId", "")

    lp = product.get("LocalizedProperties", [])
    lp0 = lp[0] if lp else {}

    if market == "GB":
        # -- Title, description, developer, publisher --
        result["title"] = lp0.get("ProductTitle", "")
        result["description"] = lp0.get("ShortDescription", "")
        result["developer"] = lp0.get("DeveloperName", "")
        result["publisher"] = lp0.get("PublisherName", "")

        # -- Images: find BoxArt and Hero/SuperHeroArt --
        images = lp0.get("Images", [])
        box_art = ""
        hero_art = ""
        for img in images:
            purpose = img.get("ImagePurpose", "")
            uri = img.get("Uri", "")
            if uri and not uri.startswith("http"):
                uri = "https:" + uri
            if purpose == "BoxArt" and not box_art:
                box_art = uri
            elif purpose in ("SuperHeroArt", "Hero") and not hero_art:
                hero_art = uri
        result["boxArt"] = box_art
        result["heroImage"] = hero_art
        result["image"] = box_art or hero_art

        # -- Properties: Category, IsDemo --
        props = product.get("Properties", {})
        result["category"] = props.get("Category", "")
        result["isDemo"] = props.get("IsDemo", False)

    # -- DisplaySkuAvailabilities: prices, trial, platforms, releaseDate --
    skus = product.get("DisplaySkuAvailabilities", [])

    best_msrp = 0
    best_list = 0
    currency = "GBP" if market == "GB" else "USD"
    has_trial_sku = False
    has_purchase_sku = False
    platforms = set()
    release_date = ""

    for sku_entry in skus:
        sku_obj = sku_entry.get("Sku", {})
        sku_props = sku_obj.get("Properties", {})
        is_trial_sku = sku_props.get("IsTrial", False)
        if is_trial_sku:
            has_trial_sku = True

        # Packages -> PlatformDependencies
        if market == "GB":
            for pkg in sku_props.get("Packages", []):
                for pdep in pkg.get("PlatformDependencies", []):
                    pname = pdep.get("PlatformName", "")
                    mapped = PLATFORM_MAP.get(pname, pname)
                    if mapped:
                        platforms.add(mapped)

        avails = sku_entry.get("Availabilities", [])
        for avail in avails:
            # Price
            omd = avail.get("OrderManagementData", {})
            price_info = omd.get("Price", {})
            msrp = price_info.get("MSRP", 0) or 0
            list_price = price_info.get("ListPrice", 0) or 0
            cc = price_info.get("CurrencyCode", "")

            expected_cc = "GBP" if market == "GB" else "USD"
            if cc == expected_cc:
                if msrp > 0 and (best_msrp == 0 or msrp < best_msrp):
                    best_msrp = msrp
                if list_price > 0 and (best_list == 0 or list_price < best_list):
                    best_list = list_price
                if not is_trial_sku and msrp > 0:
                    has_purchase_sku = True

            # Release date
            if market == "GB":
                avail_props = avail.get("Properties", {})
                ord_str = avail_props.get("OriginalReleaseDate", "")
                if ord_str and not release_date:
                    release_date = ord_str[:10]

    if market == "GB":
        result["priceGBP"] = best_msrp
        result["currentPriceGBP"] = best_list
        result["hasTrialSku"] = has_trial_sku
        result["hasPurchaseSku"] = has_purchase_sku
        result["platforms"] = sorted(platforms)
        result["releaseDate"] = release_date
    else:
        result["priceUSD"] = best_msrp
        result["currentPriceUSD"] = best_list

    return pid, result


def fetch_catalog_batch(product_ids, market, lang):
    """Fetch a single batch of up to 20 product IDs from Display Catalog."""
    ids_str = ",".join(product_ids)
    url = (
        f"https://displaycatalog.md.mp.microsoft.com/v7.0/products"
        f"?bigIds={ids_str}&market={market}&languages={lang}"
    )
    headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
    }
    data = api_request(url, method="GET", headers=headers)
    if data is None:
        return {}

    results = {}
    for product in data.get("Products", []):
        pid, info = extract_catalog_data(product, market)
        if pid:
            results[pid] = info
    return results


def fetch_display_catalog(product_ids, market, lang, cache_file, label):
    """
    Fetch Display Catalog data for all product_ids in batches of 20,
    using ThreadPoolExecutor for parallelism.
    """
    if is_cache_fresh(cache_file):
        catalog = load_json(cache_file)
        print(f"[+] {label} loaded from cache ({len(catalog)} products)")
        return catalog

    print(f"[*] Fetching {label} for {len(product_ids)} products...")

    # Deduplicate
    unique_ids = list(dict.fromkeys(product_ids))

    # Batch into groups of 20
    batches = []
    for i in range(0, len(unique_ids), 20):
        batches.append(unique_ids[i:i + 20])

    catalog = {}
    completed = 0
    total = len(batches)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(fetch_catalog_batch, batch, market, lang): batch
            for batch in batches
        }
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                batch_result = future.result()
                catalog.update(batch_result)
            except Exception as e:
                print(f"    Batch error: {e}")
            if completed % 20 == 0 or completed == total:
                print(f"  {label}: {completed}/{total} batches done ({len(catalog)} products)")

    print(f"[+] {label}: {len(catalog)} products resolved")
    save_json(cache_file, catalog)
    return catalog


# ===========================================================================
# Step 4: Merge entitlements + catalog into library data
# ===========================================================================

def merge_library(entitlements, catalog_gb, catalog_us):
    """Combine entitlement data with GB and US catalog data."""
    library = []
    for ent in entitlements:
        pid = ent["productId"]
        gb = catalog_gb.get(pid, {})
        us = catalog_us.get(pid, {})

        item = {
            # Entitlement fields
            "productId":       pid,
            "productKind":     ent.get("productKind", ""),
            "status":          ent.get("status", ""),
            "acquiredDate":    ent.get("acquiredDate", ""),
            "startDate":       ent.get("startDate", ""),
            "endDate":         ent.get("endDate", ""),
            "isTrial":         ent.get("isTrial", False) or ent.get("skuType", "") == "Trial",
            "skuType":         ent.get("skuType", ""),
            "skuId":           ent.get("skuId", ""),
            "purchasedCountry": ent.get("purchasedCountry", ""),
            "quantity":        ent.get("quantity", 1),
            # Catalog fields (GB)
            "title":           gb.get("title", ""),
            "description":     gb.get("description", ""),
            "developer":       gb.get("developer", ""),
            "publisher":       gb.get("publisher", ""),
            "image":           gb.get("image", ""),
            "boxArt":          gb.get("boxArt", ""),
            "heroImage":       gb.get("heroImage", ""),
            "category":        gb.get("category", ""),
            "releaseDate":     gb.get("releaseDate", ""),
            "priceGBP":        gb.get("priceGBP", 0),
            "currentPriceGBP": gb.get("currentPriceGBP", 0),
            "platforms":       gb.get("platforms", []),
            "isDemo":          gb.get("isDemo", False),
            # USD prices
            "priceUSD":        us.get("priceUSD", 0),
            "currentPriceUSD": us.get("currentPriceUSD", 0),
            # Game Pass flag (set later)
            "onGamePass":      False,
        }
        library.append(item)
    return library


# ===========================================================================
# Step 5: Fetch Game Pass catalog
# ===========================================================================

def fetch_gamepass_catalog():
    """Fetch Game Pass collection IDs from the sigls API."""
    if is_cache_fresh(GAMEPASS_FILE):
        data = load_json(GAMEPASS_FILE)
        print(f"[+] Game Pass catalog loaded from cache ({len(data.get('items', {}))} product IDs)")
        return data

    print("[*] Fetching Game Pass catalog...")

    # product_id -> set of collection names
    product_collections = {}

    for coll_id, coll_name in GP_COLLECTIONS.items():
        url = (
            f"https://catalog.gamepass.com/sigls/v2"
            f"?id={coll_id}&language=en-GB&market=GB"
        )
        data = api_request(url, method="GET", headers={
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json",
        })
        if data is None:
            print(f"  WARNING: Failed to fetch '{coll_name}'")
            continue

        count = 0
        for entry in data:
            pid = entry.get("id", "")
            if pid and len(pid) == 12:
                if pid not in product_collections:
                    product_collections[pid] = []
                product_collections[pid].append(coll_name)
                count += 1
        print(f"  {coll_name}: {count} products")

    result = {
        "items": product_collections,
        "fetchedAt": time.time(),
    }
    print(f"[+] Game Pass: {len(product_collections)} unique product IDs")
    save_json(GAMEPASS_FILE, result)
    return result


def fetch_gamepass_details(gp_data, existing_catalog_gb, existing_catalog_us):
    """
    Fetch catalog details for Game Pass items not already in the library catalogs.
    Returns a dict of { productId: { title, publisher, etc. } }
    """
    if is_cache_fresh(GAMEPASS_DETAIL_FILE):
        details = load_json(GAMEPASS_DETAIL_FILE)
        print(f"[+] Game Pass details loaded from cache ({len(details)} products)")
        return details

    gp_pids = list(gp_data.get("items", {}).keys())
    # Find IDs not already resolved
    need_gb = [pid for pid in gp_pids if pid not in existing_catalog_gb]
    need_us = [pid for pid in gp_pids if pid not in existing_catalog_us]

    print(f"[*] Game Pass details: {len(need_gb)} need GB catalog, {len(need_us)} need US catalog")

    # Fetch GB data for missing
    gb_new = {}
    if need_gb:
        gb_new = fetch_display_catalog(
            need_gb, "GB", "en-GB",
            os.path.join(SCRIPT_DIR, "_gp_catalog_gb_tmp.json"),
            "GP Display Catalog (GB)"
        )

    # Fetch US data for missing
    us_new = {}
    if need_us:
        us_new = fetch_display_catalog(
            need_us, "US", "en-US",
            os.path.join(SCRIPT_DIR, "_gp_catalog_us_tmp.json"),
            "GP Display Catalog (US)"
        )

    # Merge everything: existing + new
    all_gb = dict(existing_catalog_gb)
    all_gb.update(gb_new)
    all_us = dict(existing_catalog_us)
    all_us.update(us_new)

    # Build Game Pass details
    details = {}
    product_collections = gp_data.get("items", {})
    for pid, colls in product_collections.items():
        gb = all_gb.get(pid, {})
        us = all_us.get(pid, {})
        details[pid] = {
            "productId":    pid,
            "title":        gb.get("title", ""),
            "description":  gb.get("description", ""),
            "developer":    gb.get("developer", ""),
            "publisher":    gb.get("publisher", ""),
            "boxArt":       gb.get("boxArt", ""),
            "heroImage":    gb.get("heroImage", ""),
            "image":        gb.get("image", ""),
            "category":     gb.get("category", ""),
            "releaseDate":  gb.get("releaseDate", ""),
            "platforms":    gb.get("platforms", []),
            "priceGBP":     gb.get("priceGBP", 0),
            "priceUSD":     us.get("priceUSD", 0),
            "productType":  gb.get("category", ""),
            "collections":  colls,
            "owned":        False,  # will be set during merge
        }

    print(f"[+] Game Pass details resolved: {len(details)} products")
    save_json(GAMEPASS_DETAIL_FILE, details)
    return details


# ===========================================================================
# Step 6: Build HTML
# ===========================================================================

def build_html(library, gp_items, gp_owned_count, gp_not_owned_count):
    """Build the self-contained HTML page."""

    # -- Generate dropdown options from library data --

    # Publishers
    pub_counts = {}
    for x in library:
        p = x.get("publisher") or ""
        if p:
            pub_counts[p] = pub_counts.get(p, 0) + 1
    top_publishers = sorted(pub_counts.items(), key=lambda kv: -kv[1])
    pub_options = "".join(
        f'<option value="{p}">{p} ({c})</option>' for p, c in top_publishers
    )

    # Categories
    cat_counts = {}
    for x in library:
        c = x.get("category") or ""
        if c:
            cat_counts[c] = cat_counts.get(c, 0) + 1
    cat_options = "".join(
        f'<option value="{c}">{c} ({n})</option>'
        for c, n in sorted(cat_counts.items(), key=lambda kv: -kv[1])
    )

    # Platforms
    plat_counts = {}
    for x in library:
        for p in x.get("platforms", []):
            plat_counts[p] = plat_counts.get(p, 0) + 1
    plat_options = "".join(
        f'<option value="{p}">{p} ({c})</option>'
        for p, c in sorted(plat_counts.items(), key=lambda kv: -kv[1])
    )

    # Release years
    release_years = sorted(set(
        x.get("releaseDate", "")[:4]
        for x in library
        if (x.get("releaseDate") or "")[:4].isdigit()
        and x.get("releaseDate", "")[:4] < "2800"
    ), reverse=True)
    ry_options = "".join(f'<option value="{y}">{y}</option>' for y in release_years)

    # Acquired years
    acquired_years = sorted(set(
        x.get("acquiredDate", "")[:4]
        for x in library
        if (x.get("acquiredDate") or "")[:4].isdigit()
    ), reverse=True)
    ay_options = "".join(f'<option value="{y}">{y}</option>' for y in acquired_years)

    # -- Serialize data --
    lib_json = json.dumps(library, ensure_ascii=False)
    gp_json  = json.dumps(gp_items, ensure_ascii=False)

    # -- Build the full HTML --
    html = (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="UTF-8">\n'
        '<title>Xbox Complete Library Explorer</title>\n'
        '<style>\n'
        '*{margin:0;padding:0;box-sizing:border-box}\n'
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0}\n"
        '.tabs{display:flex;background:#111;border-bottom:2px solid #107c10;position:sticky;top:0;z-index:100}\n'
        '.tab{padding:12px 20px;cursor:pointer;color:#888;font-size:14px;font-weight:500;border-bottom:3px solid transparent;transition:all .2s;white-space:nowrap}\n'
        '.tab:hover{color:#ccc;background:#1a1a1a}\n'
        '.tab.active{color:#107c10;border-bottom-color:#107c10;background:#0a0a0a}\n'
        '.tab .cnt{font-size:11px;color:#555;margin-left:4px}\n'
        '.tab.active .cnt{color:#107c10}\n'
        '.section{display:none;padding:16px}\n'
        '.section.active{display:block}\n'
        'h2{color:#107c10;margin-bottom:4px;font-size:20px}\n'
        '.sub{color:#666;margin-bottom:12px;font-size:13px}\n'
        '.filters{margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}\n'
        '.filters input{padding:7px 12px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:13px;width:280px}\n'
        '.filters select{padding:7px 10px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:12px}\n'
        '.pill{padding:5px 12px;border:1px solid #333;background:#1a1a1a;color:#aaa;border-radius:16px;cursor:pointer;font-size:11px}\n'
        '.pill.active{background:#107c10;border-color:#107c10;color:#fff}\n'
        '.pill:hover{background:#222}\n'
        '.cbar{color:#666;font-size:12px;margin-bottom:8px}\n'
        '.cbar span{color:#107c10;font-weight:bold}\n'
        '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}\n'
        '.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;overflow:hidden;cursor:pointer;transition:all .2s}\n'
        '.card:hover{border-color:#107c10;transform:translateY(-1px);box-shadow:0 3px 10px rgba(16,124,16,.12)}\n'
        '.card-img{width:100%;height:150px;object-fit:cover;background:#222}\n'
        '.card-body{padding:10px}\n'
        '.card-name{font-weight:600;font-size:14px;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.card-meta{font-size:11px;color:#666;margin-bottom:4px}\n'
        '.card-desc{font-size:11px;color:#888;line-height:1.4;max-height:2.8em;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}\n'
        '.card-badges{display:flex;gap:3px;flex-wrap:wrap;margin-top:6px}\n'
        '.badge{font-size:10px;padding:2px 6px;border-radius:10px;font-weight:500}\n'
        '.badge.series{background:#1a3a1a;color:#4caf50}\n'
        '.badge.one{background:#1a2a3a;color:#42a5f5}\n'
        '.badge.x360{background:#3a3a1a;color:#ffd54f}\n'
        '.badge.mobile{background:#3a1a3a;color:#ce93d8}\n'
        '.badge.pc{background:#1a3a3a;color:#4dd0e1}\n'
        '.badge.ach{background:#2a2a1a;color:#ffb74d}\n'
        '.badge.owned{background:#1a3a1a;color:#4caf50}\n'
        '.badge.new{background:#3a1a1a;color:#f44336}\n'
        '.badge.gp{background:#1a2a1a;color:#76ff03}\n'
        '.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:200;justify-content:center;align-items:center}\n'
        '.modal-overlay.active{display:flex}\n'
        '.modal{background:#1a1a1a;border:1px solid #333;border-radius:10px;max-width:650px;width:95%;max-height:90vh;overflow-y:auto}\n'
        '.modal-hero{width:100%;height:220px;object-fit:cover;background:#222}\n'
        '.modal-body{padding:16px}\n'
        '.modal-close{float:right;background:#333;border:none;color:#ccc;width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:16px;margin:8px}\n'
        '.modal-close:hover{background:#444}\n'
        '.modal-title{font-size:20px;font-weight:700;margin-bottom:4px}\n'
        '.modal-pub{color:#888;font-size:13px;margin-bottom:10px}\n'
        '.modal-desc{color:#bbb;font-size:13px;line-height:1.5;margin-bottom:12px}\n'
        '.modal-info{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;margin-bottom:12px}\n'
        '.modal-info .lbl{color:#666}\n'
        '.modal-info .val{color:#ccc}\n'
        '.modal-info a{color:#107c10}\n'
        '.ach-list{margin-top:10px}\n'
        '.ach-list h3{color:#ffb74d;font-size:13px;margin-bottom:6px}\n'
        '.ach-item{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #222;font-size:12px}\n'
        '.ach-item .gs{color:#ffb74d;font-weight:bold;min-width:35px}\n'
        '.lib-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}\n'
        '.lib-card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:6px;padding:8px;display:flex;gap:8px;transition:border-color .2s}\n'
        '.lib-card:hover{border-color:#107c10}\n'
        '.lib-card img{width:50px;height:50px;object-fit:cover;border-radius:3px;flex-shrink:0;background:#222}\n'
        '.lib-card .info{flex:1;min-width:0}\n'
        '.lib-card .ln{font-weight:600;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.lib-card .lm{font-size:10px;color:#666}\n'
        '.lib-card .lp{font-size:11px;font-weight:600;margin-top:2px}\n'
        '.lib-card .lp .gbp{color:#4caf50}\n'
        '.lib-card .lp .usd{color:#42a5f5}\n'
        '.s-active{color:#4caf50}.s-expired{color:#ff9800}.s-revoked{color:#f44336}\n'
        '.val-summary{display:inline-block;margin-left:8px;font-size:12px;color:#888}\n'
        '.val-summary .gbp{color:#4caf50;font-weight:bold}\n'
        '.val-summary .usd{color:#42a5f5;font-weight:bold}\n'
        '.view-toggle{display:flex;gap:2px;margin-left:auto}\n'
        '.view-btn{padding:5px 8px;border:1px solid #333;background:#1a1a1a;color:#888;cursor:pointer;font-size:13px;line-height:1}\n'
        '.view-btn:first-child{border-radius:6px 0 0 6px}\n'
        '.view-btn:last-child{border-radius:0 6px 6px 0}\n'
        '.view-btn.active{background:#107c10;border-color:#107c10;color:#fff}\n'
        '.view-btn:hover:not(.active){background:#222}\n'
        '.list-view{display:flex;flex-direction:column;gap:1px}\n'
        '.list-view .lv-head{display:grid;grid-template-columns:40px 1.2fr 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:6px 10px;background:#161616;border-bottom:1px solid #333;font-size:11px;font-weight:600;color:#888;position:sticky;top:45px;z-index:10}\n'
        '.list-view .lv-row{display:grid;grid-template-columns:40px 1.2fr 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:5px 10px;background:#1a1a1a;border-bottom:1px solid #1e1e1e;align-items:center;cursor:pointer;font-size:12px;transition:background .15s}\n'
        '.list-view .lv-row:hover{background:#222}\n'
        '.list-view .lv-row img{width:36px;height:36px;object-fit:cover;border-radius:3px;background:#222}\n'
        '.list-view .lv-title{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:500}\n'
        '.list-view .lv-pub{color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.list-view .lv-type{color:#888}\n'
        '.list-view .lv-gbp{color:#4caf50;font-weight:600;text-align:right}\n'
        '.list-view .lv-usd{color:#42a5f5;font-weight:600;text-align:right}\n'
        '.list-view .lv-status{text-align:center}\n'
        '.gp-list .lv-head{grid-template-columns:50px 1fr 160px 120px 90px 90px 80px}\n'
        '.gp-list .lv-row{grid-template-columns:50px 1fr 160px 120px 90px 90px 80px}\n'
        '#ctx-menu{display:none;position:fixed;background:#222;border:1px solid #444;border-radius:6px;z-index:300;min-width:160px;box-shadow:0 4px 16px rgba(0,0,0,.5);overflow:hidden}\n'
        '.ctx-opt{padding:8px 12px;cursor:pointer;font-size:12px;color:#ddd}\n'
        '.ctx-opt:hover{background:#333}\n'
        '.badge.trial{background:#3a2a1a;color:#ff9800}\n'
        '.badge.demo{background:#3a1a2a;color:#e91e63}\n'
        '.badge.flagged{background:#3a3a1a;color:#ffd54f}\n'
        '</style>\n'
        '</head>\n'
        '<body>\n'

        # -- Tabs (Library + Game Pass only) --
        '<div class="tabs">\n'
        '<div class="tab active" onclick="switchTab(\'library\',this)">My Library '
        '<span class="cnt">' + str(len(library)) + '</span></div>\n'
        '<div class="tab" onclick="switchTab(\'gamepass\',this)">Game Pass Catalog '
        '<span class="cnt">' + str(len(gp_items)) + '</span></div>\n'
        '</div>\n'
        '\n'

        # -- Game Pass section --
        '<div class="section" id="gamepass">\n'
        '<h2>Game Pass Catalog</h2>\n'
        '<p class="sub">' + str(gp_not_owned_count) + ' games available you don\'t own | '
        + str(gp_owned_count) + ' already in your library</p>\n'
        '<div class="filters">\n'
        '<input type="text" id="gp-search" placeholder="Search Game Pass..." oninput="filterGP()">\n'
        '<div class="pill active" onclick="setGPFilter(\'all\',this)">All</div>\n'
        '<div class="pill" onclick="setGPFilter(\'notOwned\',this)">Not Owned</div>\n'
        '<div class="pill" onclick="setGPFilter(\'owned\',this)">Owned</div>\n'
        '<div class="pill" onclick="setGPFilter(\'recent\',this)">Recently Added</div>\n'
        '<div class="pill" onclick="setGPFilter(\'popular\',this)">Most Popular</div>\n'
        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'gp\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'gp\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="cbar" id="gp-cbar"></div>\n'
        '<div class="grid" id="gp-grid" style="display:none"></div>\n'
        '<div class="list-view gp-list" id="gp-list"></div>\n'
        '</div>\n'
        '\n'

        # -- Library section (active by default) --
        '<div class="section active" id="library">\n'
        '<h2>My Xbox Library</h2>\n'
        '<p class="sub">Full entitlements from Microsoft Collections API</p>\n'
        '<div class="filters">\n'
        '<input type="text" id="lib-search" placeholder="Search library..." oninput="filterLib()">\n'
        '<select id="lib-status" onchange="filterLib()"><option value="all">All Status</option>'
        '<option value="Active" selected>Active</option><option value="Expired">Expired</option>'
        '<option value="Revoked">Revoked</option></select>\n'
        '<select id="lib-type" onchange="filterLib()"><option value="all">All Types</option>'
        '<option value="Game" selected>Game</option><option value="Durable">DLC</option>'
        '<option value="Application">App</option><option value="Consumable">Consumable</option>'
        '<option value="Pass">Pass</option></select>\n'
        '<select id="lib-cat" onchange="filterLib()"><option value="all">All Categories</option>'
        + cat_options + '</select>\n'
        '<select id="lib-plat" onchange="filterLib()"><option value="all">All Platforms</option>'
        + plat_options + '</select>\n'
        '<select id="lib-pub" onchange="filterLib()"><option value="all">All Publishers</option>'
        + pub_options + '</select>\n'
        '<select id="lib-ryear" onchange="filterLib()"><option value="all">Release Year</option>'
        + ry_options + '</select>\n'
        '<select id="lib-ayear" onchange="filterLib()"><option value="all">Purchased Year</option>'
        + ay_options + '</select>\n'
        '<select id="lib-sort" onchange="filterLib()"><option value="name">Sort: Name</option>'
        '<option value="priceDesc" selected>Sort: Price (High-Low)</option>'
        '<option value="priceAsc">Sort: Price (Low-High)</option>'
        '<option value="pubAsc">Sort: Publisher A-Z</option>'
        '<option value="pubDesc">Sort: Publisher Z-A</option>'
        '<option value="relDesc">Sort: Release (Newest)</option>'
        '<option value="relAsc">Sort: Release (Oldest)</option>'
        '<option value="acqDesc">Sort: Purchased (Newest)</option>'
        '<option value="acqAsc">Sort: Purchased (Oldest)</option>'
        '<option value="platAsc">Sort: Platform A-Z</option></select>\n'
        '<div class="pill" onclick="setLibSrcFilter(\'all\',this)">All</div>\n'
        '<div class="pill active" onclick="setLibSrcFilter(\'purchased\',this)">Purchased Only</div>\n'
        '<div class="pill" onclick="setLibSrcFilter(\'gamepass\',this)">Game Pass</div>\n'
        '<div class="pill" onclick="setLibSrcFilter(\'trials\',this)">Trials/Demos</div>\n'
        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'lib\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'lib\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="cbar" id="lib-cbar"></div>\n'
        '<div class="lib-grid" id="lib-grid" style="display:none"></div>\n'
        '<div class="list-view" id="lib-list"></div>\n'
        '</div>\n'
        '\n'

        # -- Context menu + Modal --
        '<div id="ctx-menu"></div>\n'
        '<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">\n'
        '<div class="modal"><button class="modal-close" onclick="closeModal()">&times;</button>\n'
        '<img class="modal-hero" id="modal-hero" src="" alt="">\n'
        '<div class="modal-body" id="modal-body"></div></div></div>\n'
        '\n'

        # -- JavaScript --
        '<script>\n'
        'const GP=' + gp_json + ';\n'
        'const LIB=' + lib_json + ';\n'
        "let gpF='all',libSF='purchased';\n"
        "let views={gp:'list',lib:'list'};\n"
        '\n'
        "function switchTab(id,el){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));"
        "document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));"
        "document.getElementById(id).classList.add('active');el.classList.add('active')}\n"

        "function setGPFilter(f,el){gpF=f;document.querySelectorAll('#gamepass .pill').forEach(p=>p.classList.remove('active'));"
        "el.classList.add('active');filterGP()}\n"

        "function setLibSrcFilter(f,el){libSF=f;document.querySelectorAll('#library .pill').forEach(p=>p.classList.remove('active'));"
        "el.classList.add('active');filterLib()}\n"

        "function setView(tab,mode,el){views[tab]=mode;el.parentElement.querySelectorAll('.view-btn').forEach(b=>b.classList.remove('active'));"
        "el.classList.add('active');"
        "if(tab==='gp'){document.getElementById('gp-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('gp-list').style.display=mode==='list'?'flex':'none';filterGP()}"
        "else{document.getElementById('lib-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('lib-list').style.display=mode==='list'?'flex':'none';filterLib()}}\n"
        '\n'

        "let manualFlags=JSON.parse(localStorage.getItem('xboxLibFlags')||'{}');\n"
        "function flagItem(pid,flag){if(flag){manualFlags[pid]=flag}else{delete manualFlags[pid]}"
        "localStorage.setItem('xboxLibFlags',JSON.stringify(manualFlags));filterLib()}\n"

        "function showFlagMenu(e,pid,title){e.preventDefault();e.stopPropagation();"
        "const existing=manualFlags[pid];"
        "const m=document.getElementById('ctx-menu');"
        "m.innerHTML=`<div style=\"padding:6px 10px;color:#888;font-size:11px;border-bottom:1px solid #333;"
        "max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">${title}</div>`+"
        "(existing?`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}',null)\">Remove flag</div>`:"
        "`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}','beta')\">Flag as Beta/Demo</div>`);"
        "m.style.left=e.clientX+'px';m.style.top=e.clientY+'px';m.style.display='block';"
        "setTimeout(()=>document.addEventListener('click',()=>{m.style.display='none'},{once:true}),10)}\n"
        '\n'

        # -- filterGP --
        'function filterGP(){\n'
        "const q=document.getElementById('gp-search').value.toLowerCase();\n"
        "const g=document.getElementById('gp-grid');const l=document.getElementById('gp-list');\n"
        "g.innerHTML='';let c=0;"
        "let gh='',lh='<div class=\"lv-head\"><div></div><div>Title</div><div>Publisher</div>"
        "<div>Release</div><div style=\"text-align:right\">GBP</div><div style=\"text-align:right\">USD</div>"
        "<div style=\"text-align:center\">Status</div></div>';\n"
        'GP.forEach((item,i)=>{\n'
        "const t=(item.title||'').toLowerCase(),p=(item.publisher||'').toLowerCase();\n"
        "if(q&&!t.includes(q)&&!p.includes(q)&&!(item.productId||'').toLowerCase().includes(q))return;\n"
        "if(gpF==='notOwned'&&item.owned)return;\n"
        "if(gpF==='owned'&&!item.owned)return;\n"
        "if(gpF==='recent'&&!(item.collections||[]).includes('Recently Added'))return;\n"
        "if(gpF==='popular'&&!(item.collections||[]).includes('Most Popular'))return;\n"
        'c++;if(c>500)return;\n'
        "const owned=item.owned?'<span class=\"badge owned\">OWNED</span>':'<span class=\"badge new\">NOT OWNED</span>';\n"
        "const colls=(item.collections||[]).map(c=>'<span class=\"badge gp\">'+c+'</span>').join('');\n"
        "const img=item.heroImage||item.boxArt||'';\n"
        "const imgTag=img?`<img class=\"card-img\" src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:"
        "'<div class=\"card-img\" style=\"display:flex;align-items:center;justify-content:center;color:#333;font-size:36px\">'+(item.title||'?')[0]+'</div>';\n"
        "const gbpP=item.priceGBP>0?`\\u00a3${item.priceGBP.toFixed(2)}`:'';\n"
        "const usdP=item.priceUSD>0?`$${item.priceUSD.toFixed(2)}`:'';\n"
        "const priceTag=gbpP?`<span style=\"color:#4caf50;font-weight:600;font-size:13px\">${gbpP}</span>"
        "${usdP?' <span style=\"color:#555;font-size:11px\">/ '+usdP+'</span>':''}`:usdP?"
        "`<span style=\"color:#42a5f5;font-weight:600\">${usdP}</span>`:"
        "'<span style=\"color:#555;font-size:11px\">Free / Included</span>';\n"
        'gh+=`<div class="card" onclick="showGPDetail(${i})">${imgTag}<div class="card-body">'
        '<div class="card-name" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="card-meta">${item.publisher||\'\'} | ${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div style="margin:4px 0">${priceTag}</div>'
        '<div class="card-desc">${item.description||\'\'}</div>'
        '<div class="card-badges">${owned}${colls}</div></div></div>`;\n'
        "const thumbImg=img?`<img src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'';\n"
        "const ownedBadge=item.owned?'<span class=\"badge owned\" style=\"font-size:9px\">OWNED</span>'"
        ":'<span class=\"badge new\" style=\"font-size:9px\">NEW</span>';\n"
        'lh+=`<div class="lv-row" onclick="showGPDetail(${i})">${thumbImg}'
        '<div class="lv-title" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-type">${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div class="lv-gbp">${gbpP}</div><div class="lv-usd">${usdP}</div>'
        '<div class="lv-status">${ownedBadge}</div></div>`;\n'
        '});\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "document.getElementById('gp-cbar').innerHTML=`<span>${c}</span> of ${GP.length} shown`}\n"
        '\n'

        # -- showGPDetail --
        'function showGPDetail(i){\n'
        'const item=GP[i];\n'
        "const img=item.heroImage||item.boxArt||'';\n"
        "document.getElementById('modal-hero').src=img;\n"
        "document.getElementById('modal-hero').style.display=img?'block':'none';\n"
        "const owned=item.owned?'<span class=\"badge owned\">IN YOUR LIBRARY</span>'"
        ":'<span class=\"badge new\">NOT OWNED</span>';\n"
        "const colls=(item.collections||[]).map(c=>'<span class=\"badge gp\">'+c+'</span>').join(' ');\n"
        "document.getElementById('modal-body').innerHTML=`\n"
        '<div class="modal-title">${item.title||\'Unknown\'}</div>\n'
        '<div class="modal-pub">${item.publisher||\'\'} ${item.developer&&item.developer!==item.publisher?\'/  \'+item.developer:\'\'}</div>\n'
        '<div style="margin-bottom:10px">${owned} ${colls}</div>\n'
        '<div class="modal-desc">${item.description||\'No description.\'}</div>\n'
        '<div class="modal-info">\n'
        '<div><span class="lbl">Product ID:</span></div><div class="val">${item.productId}</div>\n'
        '<div><span class="lbl">Release:</span></div><div class="val">${(item.releaseDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Type:</span></div><div class="val">${item.productType||\'\'}</div>\n'
        "${item.priceGBP>0?'<div><span class=\"lbl\">Price (GBP):</span></div><div class=\"val\" style=\"color:#4caf50;font-weight:600\">\\u00a3'+item.priceGBP.toFixed(2)+'</div>':''}\n"
        "${item.priceUSD>0?'<div><span class=\"lbl\">Price (USD):</span></div><div class=\"val\" style=\"color:#42a5f5;font-weight:600\">$'+item.priceUSD.toFixed(2)+'</div>':''}\n"
        '<div><span class="lbl">Store:</span></div><div class="val"><a href="https://www.xbox.com/en-GB/games/store/p/${item.productId}" target="_blank">${item.productId}</a></div>\n'
        "</div>`;\n"
        "document.getElementById('modal').classList.add('active')}\n"
        '\n'

        # -- filterLib --
        'function filterLib(){\n'
        "const q=document.getElementById('lib-search').value.toLowerCase();\n"
        "const s=document.getElementById('lib-status').value;\n"
        "const t=document.getElementById('lib-type').value;\n"
        "const so=document.getElementById('lib-sort').value;\n"
        "const cat=document.getElementById('lib-cat').value;\n"
        "const plat=document.getElementById('lib-plat').value;\n"
        "const pub=document.getElementById('lib-pub').value;\n"
        "const ry=document.getElementById('lib-ryear').value;\n"
        "const ay=document.getElementById('lib-ayear').value;\n"
        "const g=document.getElementById('lib-grid');const l=document.getElementById('lib-list');\n"
        'let filtered=LIB.filter(item=>{\n'
        "if(q&&!(item.title||'').toLowerCase().includes(q)&&!(item.publisher||'').toLowerCase().includes(q)"
        "&&!(item.productId||'').toLowerCase().includes(q))return false;\n"
        "if(s!=='all'&&item.status!==s)return false;\n"
        "if(t!=='all'&&item.productKind!==t)return false;\n"
        "if(cat!=='all'&&(item.category||'')!==cat)return false;\n"
        "if(plat!=='all'&&!(item.platforms||[]).includes(plat))return false;\n"
        "if(pub!=='all'&&(item.publisher||'')!==pub)return false;\n"
        "if(ry!=='all'&&!(item.releaseDate||'').startsWith(ry))return false;\n"
        "if(ay!=='all'&&!(item.acquiredDate||'').startsWith(ay))return false;\n"
        'const flagged=manualFlags[item.productId];\n'
        "const isTD=item.isTrial||item.isDemo||flagged==='beta';\n"
        "if(libSF==='purchased'&&(item.onGamePass||isTD))return false;\n"
        "if(libSF==='gamepass'&&!item.onGamePass)return false;\n"
        "if(libSF==='trials'&&!isTD)return false;\n"
        "if(libSF==='priced'&&!(item.priceGBP>0))return false;\n"
        "if(libSF==='free'&&(item.priceGBP>0))return false;\n"
        'return true});\n'
        "if(so==='priceDesc')filtered.sort((a,b)=>((b.priceGBP||0)-(a.priceGBP||0))||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='priceAsc')filtered.sort((a,b)=>{const ap=a.priceGBP||0,bp=b.priceGBP||0;"
        "if(!ap&&bp)return 1;if(ap&&!bp)return -1;return(ap-bp)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='pubAsc')filtered.sort((a,b)=>(a.publisher||'').localeCompare(b.publisher||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='pubDesc')filtered.sort((a,b)=>(b.publisher||'').localeCompare(a.publisher||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='relDesc')filtered.sort((a,b)=>(b.releaseDate||'').localeCompare(a.releaseDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='relAsc')filtered.sort((a,b)=>(a.releaseDate||'').localeCompare(b.releaseDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='acqDesc')filtered.sort((a,b)=>(b.acquiredDate||'').localeCompare(a.acquiredDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='acqAsc')filtered.sort((a,b)=>(a.acquiredDate||'').localeCompare(b.acquiredDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='platAsc')filtered.sort((a,b)=>((a.platforms||[])[0]||'zzz').localeCompare((b.platforms||[])[0]||'zzz')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        'let vGBP=0,vUSD=0;filtered.forEach(item=>{vGBP+=(item.priceGBP||0);vUSD+=(item.priceUSD||0)});\n'
        "const shown=Math.min(filtered.length,views.lib==='list'?2000:500);\n"
        "let gh='',lh='<div class=\"lv-head\"><div></div><div>Title</div><div>Publisher</div><div>Category</div>"
        "<div>Platform</div><div>Released</div><div>Purchased</div><div style=\"text-align:right\">GBP</div>"
        "<div style=\"text-align:right\">USD</div><div>CC</div><div>SKU</div>"
        "<div style=\"text-align:center\">Status</div></div>';\n"
        'for(let i=0;i<shown;i++){const item=filtered[i];\n'
        'const flagged=manualFlags[item.productId];\n'
        "const sc=item.status==='Active'?'s-active':item.status==='Expired'?'s-expired':'s-revoked';\n"
        "const img=item.image?`<img src=\"${item.image}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'';\n"
        "const gbp=item.priceGBP>0?`<span class=\"gbp\">\\u00a3${item.priceGBP.toFixed(2)}</span>`:'';\n"
        "const usd=item.priceUSD>0?`<span class=\"usd\">$${item.priceUSD.toFixed(2)}</span>`:'';\n"
        "const pr=gbp||usd?`<div class=\"lp\">${gbp}${gbp&&usd?' / ':''}${usd}</div>`:'';\n"
        "const gpBadge=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';\n"
        "const trBadge=item.isTrial?'<span class=\"badge trial\" style=\"font-size:9px;margin-left:4px\">TRIAL</span>'"
        ":item.isDemo?'<span class=\"badge demo\" style=\"font-size:9px;margin-left:4px\">DEMO</span>':'';\n"
        "const flBadge=flagged==='beta'?'<span class=\"badge flagged\" style=\"font-size:9px;margin-left:4px\">FLAGGED</span>':'';\n"
        "const safeTitle=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');\n"
        'gh+=`<div class="lib-card" oncontextmenu="showFlagMenu(event,\'${item.productId}\',\'${safeTitle}\')">'
        '${img}<div class="info"><div class="ln" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">'
        '${item.title||item.productId}${gpBadge}${trBadge}${flBadge}</div>'
        '<div class="lm">${item.publisher||\'\'} | ${item.productKind||\'\'} | ${item.category||\'\'} | '
        '<span class="${sc}">${item.status||\'\'}</span></div>${pr}</div></div>`;\n'
        "const gbpL=item.priceGBP>0?`\\u00a3${item.priceGBP.toFixed(2)}`:'';\n"
        "const usdL=item.priceUSD>0?`$${item.priceUSD.toFixed(2)}`:'';\n"
        "const statusBadge=`<span class=\"${sc}\">${item.status||''}</span>`;\n"
        "const gpTag=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';\n"
        "const trTag=item.isTrial?'<span class=\"badge trial\" style=\"font-size:9px;margin-left:3px\">TRIAL</span>'"
        ":item.isDemo?'<span class=\"badge demo\" style=\"font-size:9px;margin-left:3px\">DEMO</span>':'';\n"
        "const flTag=flagged==='beta'?'<span class=\"badge flagged\" style=\"font-size:9px;margin-left:3px\">FLAGGED</span>':'';\n"
        "const safeTitle2=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');\n"
        "const relD=(item.releaseDate||'').substring(0,10);\n"
        "const acqD=(item.acquiredDate||'').substring(0,10);\n"
        "const platStr=(item.platforms||[]).join(', ')||'';\n"
        'lh+=`<div class="lv-row" oncontextmenu="showFlagMenu(event,\'${item.productId}\',\'${safeTitle2}\')">'
        '${img}<div class="lv-title" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">'
        '${item.title||item.productId}${gpTag}${trTag}${flTag}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-type">${item.category||\'\'}</div>'
        '<div class="lv-type">${platStr}</div>'
        '<div class="lv-type">${relD}</div>'
        '<div class="lv-type">${acqD}</div>'
        '<div class="lv-gbp">${gbpL}</div>'
        '<div class="lv-usd">${usdL}</div>'
        '<div class="lv-type" title="${item.purchasedCountry||\'\'}">${item.purchasedCountry||\'\'}</div>'
        '<div class="lv-type">${item.skuId||\'\'}</div>'
        '<div class="lv-status">${statusBadge}</div></div>`}\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "document.getElementById('lib-cbar').innerHTML=`<span>${filtered.length}</span>"
        "${filtered.length>shown?' (showing '+shown+')':''} of ${LIB.length} "
        "<span class=\"val-summary\">Value: <span class=\"gbp\">\\u00a3${vGBP.toLocaleString('en',{minimumFractionDigits:2,maximumFractionDigits:2})}</span>"
        " / <span class=\"usd\">$${vUSD.toLocaleString('en',{minimumFractionDigits:2,maximumFractionDigits:2})}</span></span>`}\n"
        '\n'

        "function closeModal(){document.getElementById('modal').classList.remove('active')}\n"
        "document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});\n"
        'filterGP();filterLib();\n'
        '</script></body></html>'
    )

    return html


# ===========================================================================
# Main entry point
# ===========================================================================

def main():
    banner()
    start_time = time.time()

    # -- Step 1: Auth token --
    auth_token = read_auth_token()

    # -- Step 2: Entitlements --
    entitlements = fetch_entitlements(auth_token)
    product_ids = list(dict.fromkeys(e["productId"] for e in entitlements if e["productId"]))
    print(f"  Unique product IDs: {len(product_ids)}")

    # -- Step 3a: Display Catalog - GB market (full data) --
    catalog_gb = fetch_display_catalog(
        product_ids, "GB", "en-GB", CATALOG_GB_FILE, "Display Catalog (GB)"
    )

    # -- Step 3b: Display Catalog - US market (prices only) --
    catalog_us = fetch_display_catalog(
        product_ids, "US", "en-US", CATALOG_US_FILE, "Display Catalog (US)"
    )

    # -- Step 4: Merge into library --
    library = merge_library(entitlements, catalog_gb, catalog_us)

    # Count trials/demos
    trial_count = sum(1 for x in library if x.get("isTrial"))
    demo_count  = sum(1 for x in library if x.get("isDemo"))
    print(f"  Trial entitlements: {trial_count}")
    print(f"  Catalog demos: {demo_count}")

    # -- Step 5: Game Pass --
    gp_catalog = fetch_gamepass_catalog()
    gp_details = fetch_gamepass_details(gp_catalog, catalog_gb, catalog_us)

    # Tag library items on Game Pass
    gp_pids = set(gp_catalog.get("items", {}).keys())
    gp_in_lib = 0
    for item in library:
        if item["productId"] in gp_pids:
            item["onGamePass"] = True
            gp_in_lib += 1

    print(f"  Library items on Game Pass: {gp_in_lib}")

    # Build Game Pass items list, marking owned status
    lib_pids = set(e["productId"] for e in entitlements)
    gp_items = []
    for pid, detail in gp_details.items():
        detail["owned"] = pid in lib_pids
        gp_items.append(detail)

    # Sort: not owned first, then by title
    gp_items.sort(key=lambda x: (x.get("owned", True), (x.get("title") or "").lower()))

    gp_owned     = sum(1 for x in gp_items if x.get("owned"))
    gp_not_owned = len(gp_items) - gp_owned

    # -- Compute value summaries --
    total_gbp = sum((x.get("priceGBP") or 0) for x in library)
    total_usd = sum((x.get("priceUSD") or 0) for x in library)
    priced    = sum(1 for x in library if (x.get("priceGBP") or 0) > 0)
    purch_gbp = sum((x.get("priceGBP") or 0) for x in library if not x.get("onGamePass"))
    purch_usd = sum((x.get("priceUSD") or 0) for x in library if not x.get("onGamePass"))

    print()
    print(f"  Library value:        GBP {total_gbp:,.2f} / USD {total_usd:,.2f} ({priced} priced)")
    print(f"  Purchased-only value: GBP {purch_gbp:,.2f} / USD {purch_usd:,.2f}")
    print(f"  Game Pass catalog:    {len(gp_items)} items ({gp_owned} owned, {gp_not_owned} not owned)")
    gp_priced = sum(1 for x in gp_items if (x.get("priceGBP") or 0) > 0)
    print(f"  Game Pass with prices: {gp_priced}/{len(gp_items)}")

    # -- Step 6: Build HTML --
    print()
    print("[*] Building HTML page...")
    html = build_html(library, gp_items, gp_owned, gp_not_owned)

    with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    size_mb = len(html.encode("utf-8")) / 1024 / 1024
    elapsed = time.time() - start_time

    print(f"[+] Saved {OUTPUT_HTML_FILE} ({size_mb:.1f} MB)")
    print(f"  Library tab:    {len(library)} items")
    print(f"  Game Pass tab:  {len(gp_items)} items")
    print(f"  Completed in {elapsed:.1f}s")
    print()

    # Open in browser
    file_url = "file:///" + OUTPUT_HTML_FILE.replace("\\", "/").replace(" ", "%20")
    print(f"[*] Opening in browser: {file_url}")
    webbrowser.open(file_url)


if __name__ == "__main__":
    main()
