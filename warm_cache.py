"""Build cached_response for all existing user_collections.

Run inside the Docker container:
    docker exec freshdex-xct-live python3 /app/warm_cache.py

Use --force to rebuild all caches (not just missing ones):
    docker exec freshdex-xct-live python3 /app/warm_cache.py --force
"""
import gzip
import json
import os
import sys
import time

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freshdex_cdn")

conn = psycopg2.connect(DATABASE_URL)
conn.autocommit = False
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

force = "--force" in sys.argv

if force:
    cur.execute("""
        SELECT uc.contributor_id, c.username, c.settings,
               uc.lib, uc.play_history, uc.scan_history, uc.accounts_meta, uc.purchases,
               uc.uploaded_at, uc.version
        FROM user_collections uc
        JOIN contributors c ON c.id = uc.contributor_id
    """)
else:
    cur.execute("""
        SELECT uc.contributor_id, c.username, c.settings,
               uc.lib, uc.play_history, uc.scan_history, uc.accounts_meta, uc.purchases,
               uc.uploaded_at, uc.version
        FROM user_collections uc
        JOIN contributors c ON c.id = uc.contributor_id
        WHERE uc.cached_response IS NULL
    """)
rows = cur.fetchall()
print(f"[+] Found {len(rows)} users to cache{' (force rebuild)' if force else ''}")


def _write_gz(path, obj):
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw, compresslevel=6)
    with open(path, "wb") as f:
        f.write(gz)
    return len(gz)


for row in rows:
    t0 = time.time()
    lib = row["lib"] or []
    ph = row["play_history"] or []
    history = row["scan_history"] or []
    accounts = row["accounts_meta"] or []
    purchases = row["purchases"] or []

    # Enrich invalid items from title_id_db
    invalid_tids = set()
    for item in lib:
        if item.get("catalogInvalid") and item.get("xboxTitleId"):
            invalid_tids.add(item["xboxTitleId"])
    if invalid_tids:
        cur.execute("""
            SELECT xbox_title_id, title, category, product_kind,
                   platforms, publisher, developer, image_url
            FROM title_id_db
            WHERE xbox_title_id = ANY(%s) AND title != ''
        """, (list(invalid_tids),))
        tid_info = {r["xbox_title_id"]: r for r in cur.fetchall()}
        for item in lib:
            tid = item.get("xboxTitleId", "")
            if tid in tid_info:
                info = tid_info[tid]
                if info["title"]:
                    item["title"] = info["title"]
                    item["catalogInvalid"] = False
                if info["category"] and not item.get("category"):
                    item["category"] = info["category"]
                if info["product_kind"] and not item.get("productKind"):
                    item["productKind"] = info["product_kind"]
                if info["platforms"] and not item.get("platforms"):
                    item["platforms"] = info["platforms"]
                if info["publisher"] and not item.get("publisher"):
                    item["publisher"] = info["publisher"]
                if info["developer"] and not item.get("developer"):
                    item["developer"] = info["developer"]
                if info["image_url"] and not item.get("boxArt"):
                    item["boxArt"] = info["image_url"]

    # Core response (library + metadata, no PH/purchases)
    result = {
        "library": lib,
        "history": history,
        "accounts": accounts,
        "username": row["username"],
        "settings": row["settings"] or {},
        "uploadedAt": row["uploaded_at"].isoformat() if row["uploaded_at"] else None,
        "version": row["version"] or 1,
        "uploaded": True,
        "phCount": len(ph),
        "purchasesCount": len(purchases),
    }

    cache_dir = "/app/static/collection"
    os.makedirs(cache_dir, exist_ok=True)
    cid = row["contributor_id"]

    core_sz = _write_gz(os.path.join(cache_dir, f"{cid}.json.gz"), result)
    ph_sz = _write_gz(os.path.join(cache_dir, f"{cid}_ph.json.gz"), {"playHistory": ph})
    purch_sz = _write_gz(os.path.join(cache_dir, f"{cid}_purch.json.gz"), {"purchases": purchases})

    # Mark cache as present in DB (lightweight flag)
    cur.execute(
        "UPDATE user_collections SET cached_response = 'Y' WHERE contributor_id = %s",
        (cid,))
    conn.commit()

    dt = time.time() - t0
    print(f"  {row['username']:20s} lib={len(lib):5d} core={core_sz:,} ph={ph_sz:,} purch={purch_sz:,} ({dt:.2f}s)")

print(f"[+] Done — {len(rows)} users cached")
conn.close()
