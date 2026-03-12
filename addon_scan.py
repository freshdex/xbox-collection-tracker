"""Discover DLC/add-ons from user collections and enrich via catalog v3.

Usage:
    docker exec freshdex-xct-live python3 /app/addon_scan.py
    docker exec freshdex-xct-live python3 /app/addon_scan.py --force  (re-enrich existing)
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
import base64
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freshdex_cdn")
SSL_CTX = ssl.create_default_context()


def _cv():
    return base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"


def get_auth():
    """Get auth tokens from marketplace_scanner."""
    sys.path.insert(0, "/app")
    from marketplace_scanner import get_tokens
    return get_tokens()


def fetch_catalog_v3(product_ids, auth_xl, market="US", lang="en-US"):
    """Fetch product metadata via catalog.gamepass.com/v3/products."""
    if not product_ids:
        return {}
    url = (f"https://catalog.gamepass.com/v3/products"
           f"?market={market}&language={lang}&hydration=MobileLowAmber0")
    BATCH = 2000
    products = {}
    for i in range(0, len(product_ids), BATCH):
        chunk = product_ids[i:i + BATCH]
        body = json.dumps({"Products": chunk}).encode()
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": auth_xl,
            "Content-Type": "application/json",
            "calling-app-name": "XboxMobile",
            "calling-app-version": "2602.2.1",
            "MS-CV": _cv(),
            "Accept": "application/json",
            "User-Agent": "okhttp/4.12.0",
        })
        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=120) as resp:
                data = json.loads(resp.read())
            products.update(data.get("Products", {}))
            print(f"  catalog_v3 batch {i}-{i + len(chunk)}: "
                  f"{len(data.get('Products', {}))} products")
        except Exception as e:
            print(f"  catalog_v3 batch {i}-{i + len(chunk)} failed: {e}")
    return products


PLAT_MAP = {
    "Console": "Xbox One", "XboxOne": "Xbox One",
    "XboxSeriesX": "Xbox Series X|S", "PC": "PC",
    "Desktop": "PC", "Handheld": "PC", "XCloud": "xCloud",
    "Mobile": "Mobile",
}


def norm_kind(kind):
    if kind and kind.isupper():
        return kind.capitalize()
    return kind or ""


def parse_catalog_raw(info):
    """Parse raw catalog v3 product entry (before marketplace_scanner transform)."""
    v3_platforms = info.get("availablePlatforms", [])
    platforms = []
    for p in v3_platforms:
        mapped = PLAT_MAP.get(p, p)
        if mapped not in platforms:
            platforms.append(mapped)

    tile_img = info.get("tileImage", {})
    poster_img = info.get("posterImage", {})
    categories = info.get("categories", [])

    return {
        "title": info.get("name", ""),
        "publisher": info.get("publisherName", ""),
        "developer": info.get("developerName", ""),
        "category": categories[0] if categories else "",
        "release_date": (info.get("releaseDate", "") or "")[:10],
        "platforms": sorted(platforms),
        "product_kind": norm_kind(info.get("productKind", "")),
        "xbox_title_id": "",  # v3 doesn't return xboxTitleId for Durables
        "image": tile_img.get("uri", ""),
        "box_art": poster_img.get("uri", ""),
        "short_desc": info.get("shortDescription", ""),
        "is_bundle": info.get("isBundle", False),
        "alternate_ids": psycopg2.extras.Json(info.get("alternateIds") or []),
        "capabilities": [str(c) for c in (info.get("capabilities") or [])],
    }


def main():
    force = "--force" in sys.argv
    t0 = time.time()

    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Phase 1: Discover DLC product IDs from user collections
    print("[addon-scan] Extracting Durable product IDs from user collections...")
    cur.execute("""
        SELECT DISTINCT item->>'productId' as pid
        FROM user_collections, jsonb_array_elements(lib::jsonb) as item
        WHERE item->>'productKind' IN ('Durable', 'DURABLE', 'durable')
        AND item->>'productId' IS NOT NULL
        AND length(item->>'productId') = 12
    """)
    all_dlc_pids = [r["pid"] for r in cur.fetchall()]
    print(f"[addon-scan] Found {len(all_dlc_pids)} unique DLC products in collections")

    if not force:
        # Filter to only new (not yet in marketplace_products)
        cur.execute(
            "SELECT product_id FROM marketplace_products "
            "WHERE product_id = ANY(%s)", (all_dlc_pids,))
        existing = {r["product_id"] for r in cur.fetchall()}
        new_pids = [p for p in all_dlc_pids if p not in existing]
        print(f"[addon-scan] {len(existing)} already in DB, "
              f"{len(new_pids)} new to process")
    else:
        new_pids = all_dlc_pids
        print(f"[addon-scan] Force mode: processing all {len(new_pids)} DLC")

    if not new_pids:
        print("[addon-scan] Nothing to do")
        conn.close()
        return

    # Phase 2: Enrich via catalog v3
    print(f"[addon-scan] Enriching {len(new_pids)} DLC via catalog v3...")
    auth_xl, auth_mp = get_auth()
    catalog = fetch_catalog_v3(new_pids, auth_xl)
    print(f"[addon-scan] Catalog returned {len(catalog)} products")

    # Phase 3: Insert/update marketplace_products
    inserted = 0
    updated = 0
    for pid in new_pids:
        cat = catalog.get(pid)
        if not cat:
            continue
        info = parse_catalog_raw(cat)
        if not info["title"]:
            continue

        cur.execute(
            "SELECT product_id FROM marketplace_products "
            "WHERE product_id = %s", (pid,))
        exists = cur.fetchone()

        if exists and not force:
            continue

        if exists:
            cur.execute("""
                UPDATE marketplace_products SET
                    title = %s, publisher = %s, developer = %s, category = %s,
                    release_date = %s, platforms = %s, product_kind = %s,
                    xbox_title_id = %s, image_tile = %s, image_box_art = %s,
                    short_description = %s, is_bundle = %s,
                    alternate_ids = %s, capabilities = %s,
                    last_seen_at = NOW()
                WHERE product_id = %s
            """, (
                info["title"], info["publisher"], info["developer"],
                info["category"], info["release_date"] or None,
                info["platforms"], info["product_kind"],
                info["xbox_title_id"], info["image"], info["box_art"],
                info["short_desc"], info["is_bundle"],
                info["alternate_ids"],
                info["capabilities"], pid,
            ))
            updated += 1
        else:
            cur.execute("""
                INSERT INTO marketplace_products (
                    product_id, title, publisher, developer, category,
                    release_date, platforms, product_kind, xbox_title_id,
                    image_tile, image_box_art, short_description, is_bundle,
                    alternate_ids, capabilities
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                )
            """, (
                pid, info["title"], info["publisher"], info["developer"],
                info["category"], info["release_date"] or None,
                info["platforms"], info["product_kind"],
                info["xbox_title_id"], info["image"], info["box_art"],
                info["short_desc"], info["is_bundle"],
                info["alternate_ids"],
                info["capabilities"],
            ))
            inserted += 1

        if (inserted + updated) % 500 == 0:
            conn.commit()
            print(f"  ... {inserted} inserted, {updated} updated")

    conn.commit()
    dt = time.time() - t0
    print(f"[addon-scan] Done in {dt:.1f}s: {inserted} inserted, "
          f"{updated} updated, "
          f"{len(new_pids) - inserted - updated} skipped (no catalog data)")
    conn.close()


if __name__ == "__main__":
    main()
