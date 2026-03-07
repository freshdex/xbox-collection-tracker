#!/usr/bin/env python3
"""Amazon Physical Disc Scraper — uses Playwright to bypass WAF.

Fetches all Game-type products from xct.live, searches Amazon UK & US
for physical Xbox copies, and uploads results via the admin API.

Usage:
    python amazon_scraper.py                # Full scan (all games)
    python amazon_scraper.py --resume       # Resume from last position
    python amazon_scraper.py --limit 50     # Only scan first 50 games
    python amazon_scraper.py --market uk    # Only scan Amazon UK
    python amazon_scraper.py --market us    # Only scan Amazon US
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse

import requests
from playwright.sync_api import sync_playwright

API_BASE = "https://xct.live"
STATE_FILE = "amazon_scraper_state.json"
PRODUCTS_CACHE_FILE = "amazon_scraper_products.json"
PRODUCTS_CACHE_TTL = 86400  # 24 hours

MARKETS = {
    "uk": {"domain": "amazon.co.uk", "currency": "£"},
    "us": {"domain": "amazon.com", "currency": "$"},
}

SKIP_WORDS = [
    "controller", "headset", "cable", "adapter", "stand", "charger",
    "skin", "case", "grip", "battery", "keyboard", "mouse", "mic",
    "chair", "desk", "monitor", "webcam", "capture card", "gift card",
    "t-shirt", "poster", "figure", "funko", "plush", "lego", "book",
    "soundtrack", "vinyl", "art of", "guide", "manga", "novel",
]


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"scanned": {}, "last_index": 0}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def fetch_all_products(api_key):
    """Fetch Xbox One/Series X|S games with achievements from xct.live."""
    products = []
    page = 0
    per_page = 200
    while True:
        params = {
            "type": "Game",
            "plat": "Xbox One,Xbox Series X|S",
            "ach": "1",
            "sort": "name",
            "page": page,
            "per_page": per_page,
        }
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        r = requests.get(f"{API_BASE}/api/v1/store/products", params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
        batch = data.get("products", [])
        products.extend(batch)
        total_pages = data.get("totalPages", 1)
        print(f"  Fetched page {page + 1}/{total_pages} ({len(products)} products)")
        page += 1
        if page >= total_pages:
            break
        time.sleep(0.3)
    return products


def search_amazon(page, title, market):
    """Search Amazon for a game title. Returns list of result dicts."""
    info = MARKETS[market]
    domain = info["domain"]
    query = f"{title} Xbox"
    # Use plus-separated format like the user wants
    url = f"https://www.{domain}/s?k={urllib.parse.quote_plus(query)}&i=videogames&dc&ref=a9_asc_1"

    try:
        page.goto(url, wait_until="domcontentloaded", timeout=20000)
        # Wait for search results to appear
        page.wait_for_selector("[data-component-type='s-search-result']", timeout=10000)
    except Exception as e:
        # Check for captcha
        if "captcha" in page.content().lower():
            print(f"    [!] CAPTCHA detected on {domain} — waiting 30s for manual solve...")
            time.sleep(30)
            try:
                page.wait_for_selector("[data-component-type='s-search-result']", timeout=30000)
            except Exception:
                print(f"    [!] Still no results after captcha wait, skipping")
                return []
        else:
            return []

    # Extract results using JS in the page context
    results = page.evaluate("""() => {
        const items = document.querySelectorAll("[data-component-type='s-search-result']");
        const results = [];
        items.forEach(item => {
            const asin = item.getAttribute('data-asin');
            if (!asin) return;

            // Title
            const titleEl = item.querySelector('h2 a span, h2 span');
            const title = titleEl ? titleEl.textContent.trim() : '';

            // URL
            const linkEl = item.querySelector('h2 a');
            const href = linkEl ? linkEl.getAttribute('href') : '';

            // Price
            const priceWhole = item.querySelector('.a-price-whole');
            const priceFrac = item.querySelector('.a-price-fraction');
            let price = '';
            if (priceWhole) {
                price = priceWhole.textContent.trim().replace('.', '');
                if (priceFrac) price += '.' + priceFrac.textContent.trim();
            }

            if (title) {
                results.push({ asin, title, href, price });
            }
        });
        return results;
    }""")

    filtered = []
    # Build keywords from the game title for relevance matching
    title_lower = title.lower()
    # Strip punctuation and split into significant words (3+ chars)
    title_words = set(re.sub(r'[^\w\s]', '', title_lower).split())
    title_words = {w for w in title_words if len(w) >= 3}

    for r in results:
        rt = r["title"].lower()
        # Must mention Xbox
        if "xbox" not in rt:
            continue
        # Skip accessories/merch
        if any(w in rt for w in SKIP_WORDS):
            continue
        # Relevance check: at least 50% of game title words must appear
        # in the Amazon result title
        if title_words:
            rt_clean = re.sub(r'[^\w\s]', '', rt)
            matches = sum(1 for w in title_words if w in rt_clean)
            ratio = matches / len(title_words)
            if ratio < 0.5:
                continue
        # Build full URL
        full_url = f"https://www.{domain}/dp/{r['asin']}"
        price = r["price"]
        if price:
            price = info["currency"] + price

        filtered.append({
            "title": r["title"],
            "price": price,
            "url": full_url,
            "asin": r["asin"],
        })

    return filtered


def upload_result(api_key, product_id, status, url_uk="", url_us=""):
    """Upload a result to the server."""
    r = requests.post(
        f"{API_BASE}/api/v1/store/amazon/set",
        json={
            "productId": product_id,
            "status": status,
            "urlUK": url_uk,
            "urlUS": url_us,
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return r.json()


def main():
    parser = argparse.ArgumentParser(description="Amazon Physical Disc Scraper")
    parser.add_argument("--api-key", help="XCT API key (or set XCT_API_KEY env var)")
    parser.add_argument("--resume", action="store_true", help="Resume from last position")
    parser.add_argument("--limit", type=int, default=0, help="Max games to scan")
    parser.add_argument("--market", choices=["uk", "us", "both"], default="both",
                        help="Which Amazon market(s) to scan")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between searches (seconds)")
    parser.add_argument("--headed", action="store_true", help="Show browser window")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("XCT_API_KEY", "")
    if not api_key:
        # Try cdn_sync_config.json
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdn_sync_config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                cfg = json.load(f)
                api_key = cfg.get("api_key", "")
            if api_key:
                print(f"[*] Using API key from cdn_sync_config.json")
    if not api_key:
        api_key = input("Enter your XCT API key: ").strip()
    if not api_key:
        print("[!] API key required")
        sys.exit(1)

    markets = ["uk", "us"] if args.market == "both" else [args.market]

    # Use cached product list if recent
    products = None
    if os.path.exists(PRODUCTS_CACHE_FILE):
        age = time.time() - os.path.getmtime(PRODUCTS_CACHE_FILE)
        if age < PRODUCTS_CACHE_TTL:
            with open(PRODUCTS_CACHE_FILE) as f:
                products = json.load(f)
            print(f"[*] Using cached product list ({len(products)} games, {int(age/60)}m old)")

    if not products:
        print("[*] Fetching products from xct.live...")
        products = fetch_all_products(api_key)
        with open(PRODUCTS_CACHE_FILE, "w") as f:
            json.dump(products, f)
    print(f"[+] Got {len(products)} games\n")

    state = load_state() if args.resume else {"scanned": {}, "last_index": 0}
    start_idx = state["last_index"] if args.resume else 0

    if args.limit:
        end_idx = min(start_idx + args.limit, len(products))
    else:
        end_idx = len(products)

    to_scan = products[start_idx:end_idx]
    print(f"[*] Scanning {len(to_scan)} games (index {start_idx}-{end_idx - 1})")
    print(f"[*] Markets: {', '.join(m.upper() for m in markets)}")
    print(f"[*] Delay: {args.delay}s between searches")
    print()

    found_count = 0
    digital_count = 0

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = context.new_page()

        for i, product in enumerate(to_scan):
            pid = product["productId"]
            title = product.get("title", "")
            idx = start_idx + i

            if pid in state["scanned"]:
                print(f"  [{idx}] {title} — already scanned, skipping")
                continue

            print(f"  [{idx}/{end_idx - 1}] {title} ({pid})")

            uk_results = []
            us_results = []

            for market in markets:
                results = search_amazon(page, title, market)
                if market == "uk":
                    uk_results = results
                else:
                    us_results = results

                if results:
                    print(f"    {market.upper()}: {len(results)} result(s) — {results[0]['price'] or 'no price'} — {results[0]['title'][:60]}")
                else:
                    print(f"    {market.upper()}: no physical disc found")

                time.sleep(args.delay)

            # Determine status and upload
            has_uk = len(uk_results) > 0
            has_us = len(us_results) > 0
            url_uk = uk_results[0]["url"] if has_uk else ""
            url_us = us_results[0]["url"] if has_us else ""

            if has_uk and has_us:
                status = "both"
                found_count += 1
            elif has_uk:
                status = "uk"
                found_count += 1
            elif has_us:
                status = "us"
                found_count += 1
            else:
                status = "digital"
                digital_count += 1

            try:
                resp = upload_result(api_key, pid, status, url_uk, url_us)
                if resp.get("ok"):
                    print(f"    -> Saved: {status.upper()}")
                else:
                    print(f"    -> Error: {resp.get('error', 'unknown')}")
            except Exception as e:
                print(f"    -> Upload error: {e}")

            state["scanned"][pid] = status
            state["last_index"] = idx + 1
            save_state(state)

        browser.close()

    print(f"\n[+] Done! Scanned {len(to_scan)} games")
    print(f"    Physical discs found: {found_count}")
    print(f"    Digital only: {digital_count}")


if __name__ == "__main__":
    main()
