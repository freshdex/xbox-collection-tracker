#!/usr/bin/env python3
"""
XCT Live Server — Hosted Xbox Collection Tracker at xct.freshdex.app.
Flask app fronting PostgreSQL. Shares the same DB as cdn.freshdex.app
(reuses the contributors table for auth).

Usage:
    pip install -r xct_server_requirements.txt
    export DATABASE_URL="postgresql://user:pass@localhost/freshdex_cdn"
    python xct_server.py                          # Dev mode (port 5001)
    gunicorn xct_server:app -b 0.0.0.0:8001      # Production

    # Import shared data (operator only):
    flask --app xct_server import-shared mkt /path/to/marketplace.json
    flask --app xct_server import-shared gp  /path/to/gamepass_details.json
    flask --app xct_server import-shared rates /path/to/exchange_rates.json
    flask --app xct_server import-shared flags /path/to/tags.json
    flask --app xct_server import-shared gfwl /path/to/gfwl_links.json
"""

import gzip
import hashlib
import json
import os
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

import click
import psycopg2
import psycopg2.extras
from flask import Flask, Response, jsonify, request

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freshdex_cdn")

# Rate limiting (in-memory, resets on restart)
_rate_register = defaultdict(list)   # ip -> [timestamps]
_rate_upload = defaultdict(list)     # api_key -> [timestamps]
REGISTER_LIMIT = 5     # per hour
UPLOAD_LIMIT = 5        # per minute

# In-memory cache for shared data responses (key -> (etag, gzipped_bytes, timestamp))
_shared_cache = {}
SHARED_CACHE_TTL = 300  # 5 minutes


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def _check_rate(store, key, limit, window_sec):
    now = time.time()
    store[key] = [t for t in store[key] if now - t < window_sec]
    if len(store[key]) >= limit:
        return False
    store[key].append(now)
    return True


# ---------------------------------------------------------------------------
# DB schema initialization
# ---------------------------------------------------------------------------

def init_db():
    """Create tables if they don't exist (idempotent)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_data (
                key         TEXT PRIMARY KEY,
                data        JSONB NOT NULL,
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_collections (
                id              SERIAL PRIMARY KEY,
                contributor_id  INTEGER NOT NULL UNIQUE REFERENCES contributors(id),
                lib             JSONB,
                play_history    JSONB,
                scan_history    JSONB,
                accounts_meta   JSONB,
                uploaded_at     TIMESTAMPTZ DEFAULT NOW(),
                version         INTEGER DEFAULT 1
            )
        """)
        conn.commit()
    finally:
        conn.close()


with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"[!] DB init skipped ({e}) — will retry on first request")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_contributor(cur, api_key):
    """Validate Bearer token and return contributor row or None."""
    cur.execute(
        "SELECT id, username, total_points FROM contributors WHERE api_key = %s",
        (api_key,))
    return cur.fetchone()


def require_auth(f):
    """Decorator: require Bearer api_key, inject contributor dict."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="Authorization header required (Bearer api_key)"), 401
        api_key = auth[7:].strip()
        if not api_key:
            return jsonify(error="Empty api_key"), 401
        conn = get_db()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            contributor = _get_contributor(cur, api_key)
            if not contributor:
                return jsonify(error="Invalid api_key. Register first."), 401
            kwargs["conn"] = conn
            kwargs["cur"] = cur
            kwargs["contributor"] = contributor
            kwargs["api_key"] = api_key
            return f(*args, **kwargs)
        except Exception as e:
            conn.rollback()
            return jsonify(error=str(e)), 500
        finally:
            conn.close()
    return wrapper


# ---------------------------------------------------------------------------
# Gzip + ETag response helper
# ---------------------------------------------------------------------------

def _gzip_json_response(data, cache_key=None):
    """Return a gzipped JSON response with ETag and Cache-Control headers.

    Uses in-memory cache if cache_key is provided and TTL is fresh.
    """
    now = time.time()

    # Check client ETag
    client_etag = request.headers.get("If-None-Match", "")

    # Check in-memory cache
    if cache_key and cache_key in _shared_cache:
        etag, gz_bytes, ts = _shared_cache[cache_key]
        if now - ts < SHARED_CACHE_TTL:
            if client_etag == etag:
                return Response(status=304, headers={
                    "ETag": etag,
                    "Cache-Control": "public, max-age=300",
                })
            return Response(gz_bytes, status=200, headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "ETag": etag,
                "Cache-Control": "public, max-age=300",
            })

    # Build fresh response
    json_bytes = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz_bytes = gzip.compress(json_bytes, compresslevel=6)
    etag = '"' + hashlib.md5(gz_bytes).hexdigest() + '"'

    if cache_key:
        _shared_cache[cache_key] = (etag, gz_bytes, now)

    if client_etag == etag:
        return Response(status=304, headers={
            "ETag": etag,
            "Cache-Control": "public, max-age=300",
        })

    return Response(gz_bytes, status=200, headers={
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "ETag": etag,
        "Cache-Control": "public, max-age=300",
    })


# ---------------------------------------------------------------------------
# GET / — Serve hosted HTML
# ---------------------------------------------------------------------------

_cached_html = None
_cached_html_gz = None


@app.route("/")
def index():
    """Serve the hosted XCT HTML page."""
    global _cached_html, _cached_html_gz

    if _cached_html_gz is None:
        try:
            from XCT import build_html_template
            html = build_html_template(hosted=True)
        except Exception as e:
            return Response(f"Error generating HTML: {e}", status=500,
                            content_type="text/plain")
        _cached_html = html
        _cached_html_gz = gzip.compress(html.encode("utf-8"), compresslevel=6)

    # Check Accept-Encoding
    if "gzip" in request.headers.get("Accept-Encoding", ""):
        return Response(_cached_html_gz, status=200, headers={
            "Content-Type": "text/html; charset=utf-8",
            "Content-Encoding": "gzip",
            "Cache-Control": "public, max-age=3600",
        })
    return Response(_cached_html, status=200, headers={
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
    })


# ---------------------------------------------------------------------------
# POST /api/v1/register — Same auth system as CDN Sync
# ---------------------------------------------------------------------------

@app.route("/api/v1/register", methods=["POST"])
def register():
    ip = request.remote_addr or "unknown"
    if not _check_rate(_rate_register, ip, REGISTER_LIMIT, 3600):
        return jsonify(error="Rate limit exceeded. Try again later."), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("username"), str):
        return jsonify(error="username is required"), 400

    username = data["username"].strip()[:64]
    if not username or not re.match(r"^[A-Za-z0-9_ -]{1,64}$", username):
        return jsonify(error="Invalid username. Use letters, numbers, spaces, hyphens, underscores."), 400

    existing_key = data.get("api_key", "")
    if isinstance(existing_key, str):
        existing_key = existing_key.strip()[:64]
    else:
        existing_key = ""

    passphrase = data.get("passphrase", "")
    if isinstance(passphrase, str):
        passphrase = passphrase.strip()[:128]
    else:
        passphrase = ""

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # If api_key provided, try to reclaim/rename and optionally set passphrase
        if existing_key:
            cur.execute(
                "SELECT id, username, api_key, total_points FROM contributors WHERE api_key = %s",
                (existing_key,))
            row = cur.fetchone()
            if row:
                if row["username"] != username:
                    cur.execute("UPDATE contributors SET username = %s WHERE id = %s",
                                (username, row["id"]))
                if passphrase:
                    ph = hashlib.sha256(passphrase.encode()).hexdigest()
                    cur.execute("UPDATE contributors SET passphrase_hash = %s WHERE id = %s",
                                (ph, row["id"]))
                conn.commit()
                return jsonify(username=username, api_key=row["api_key"],
                               total_points=row["total_points"], created=False)

        # Check if username already taken
        cur.execute(
            "SELECT id, api_key, total_points, passphrase_hash FROM contributors WHERE username = %s",
            (username,))
        existing = cur.fetchone()
        if existing:
            if passphrase and existing["passphrase_hash"]:
                ph = hashlib.sha256(passphrase.encode()).hexdigest()
                if ph == existing["passphrase_hash"]:
                    return jsonify(username=username, api_key=existing["api_key"],
                                   total_points=existing["total_points"], created=False)
                else:
                    return jsonify(error="Incorrect passphrase."), 403
            return jsonify(
                error="Username already taken. Provide your api_key or passphrase to reclaim, "
                      "or choose a different name."), 409

        api_key = secrets.token_urlsafe(32)
        passphrase_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else None
        cur.execute(
            "INSERT INTO contributors (username, api_key, passphrase_hash) "
            "VALUES (%s, %s, %s) RETURNING id, total_points",
            (username, api_key, passphrase_hash))
        cur.fetchone()
        conn.commit()
        return jsonify(username=username, api_key=api_key, total_points=0, created=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Shared data endpoints — GET /api/v1/shared/<key>
# ---------------------------------------------------------------------------

@app.route("/api/v1/shared/mkt")
def shared_mkt():
    return _serve_shared_data("mkt")


@app.route("/api/v1/shared/gp")
def shared_gp():
    return _serve_shared_data("gp")


@app.route("/api/v1/shared/rates")
def shared_rates():
    return _serve_shared_data("rates")


@app.route("/api/v1/shared/flags")
def shared_flags():
    return _serve_shared_data("flags")


@app.route("/api/v1/shared/gfwl")
def shared_gfwl():
    return _serve_shared_data("gfwl")


def _serve_shared_data(key):
    """Fetch a shared_data row and return gzipped JSON with ETag caching."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT data FROM shared_data WHERE key = %s", (key,))
        row = cur.fetchone()
        if not row:
            return _gzip_json_response([], cache_key=f"shared_{key}")
        return _gzip_json_response(row["data"], cache_key=f"shared_{key}")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/shared/cdn")
def shared_cdn():
    """Build CDN_DB dict from cdn_entries table (same shape the frontend expects)."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT e.store_id, e.build_id, e.content_id, e.package_name,
                   e.build_version, e.platform, e.size_bytes, e.cdn_urls,
                   e.content_types, e.devices, e.language, e.plan_id,
                   e.source, e.scraped_at,
                   e.prior_build_version, e.prior_build_id,
                   c2.username AS contributor
            FROM cdn_entries e
            LEFT JOIN contributions c ON c.cdn_entry_id = e.id
            LEFT JOIN contributors c2 ON c2.id = c.contributor_id
            WHERE NOT e.deleted
            ORDER BY e.store_id, e.scraped_at DESC
        """)
        rows = cur.fetchall()

        # Group by store_id to produce CDN_DB dict
        cdn_db = {}
        for row in rows:
            sid = row["store_id"]
            entry = {
                "buildId": row["build_id"],
                "contentId": row["content_id"],
                "packageName": row["package_name"],
                "buildVersion": row["build_version"],
                "platform": row["platform"],
                "sizeBytes": row["size_bytes"],
                "cdnUrls": row["cdn_urls"] or [],
                "contentTypes": row["content_types"],
                "devices": row["devices"],
                "language": row["language"],
                "planId": row["plan_id"],
                "source": row["source"],
                "scrapedAt": row["scraped_at"].isoformat() if row["scraped_at"] else None,
                "priorBuildVersion": row["prior_build_version"],
                "priorBuildId": row["prior_build_id"],
                "contributor": row["contributor"],
            }
            if sid not in cdn_db:
                cdn_db[sid] = {"versions": [entry]}
            else:
                cdn_db[sid]["versions"].append(entry)

        return _gzip_json_response(cdn_db, cache_key="shared_cdn")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/shared/cdn_lb")
def shared_cdn_lb():
    """CDN leaderboard + stats (same shape as CDN Sync leaderboard endpoint)."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT username, total_points, last_sync_at
            FROM contributors
            WHERE total_points > 0
            ORDER BY total_points DESC
            LIMIT 50
        """)
        board = []
        for row in cur.fetchall():
            board.append({
                "username": row["username"],
                "points": row["total_points"],
                "lastSync": row["last_sync_at"].isoformat() if row["last_sync_at"] else None,
            })

        cur.execute("SELECT COUNT(*) as cnt FROM contributors WHERE total_points > 0")
        total_contributors = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_entries WHERE NOT deleted")
        total_entries = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(DISTINCT store_id) as cnt FROM cdn_entries WHERE NOT deleted")
        total_games = cur.fetchone()["cnt"]

        return _gzip_json_response({
            "leaderboard": board,
            "total_contributors": total_contributors,
            "total_entries": total_entries,
            "total_games": total_games,
        }, cache_key="shared_cdn_lb")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/shared/cdn_log")
def shared_cdn_log():
    """CDN sync log (recent syncs)."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT username, points_earned, total_points, new_entries,
                   duplicates_skipped, synced_at
            FROM sync_log
            ORDER BY synced_at DESC
            LIMIT 100
        """)
        log = []
        for row in cur.fetchall():
            log.append({
                "username": row["username"],
                "pointsEarned": row["points_earned"],
                "totalPoints": row["total_points"],
                "newEntries": row["new_entries"],
                "duplicatesSkipped": row["duplicates_skipped"],
                "syncedAt": row["synced_at"].isoformat() if row["synced_at"] else None,
            })
        return _gzip_json_response({"sync_log": log}, cache_key="shared_cdn_log")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/shared/meta")
def shared_meta():
    """Last-updated timestamps + item counts for all shared data."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT key, updated_at,
                   CASE WHEN jsonb_typeof(data) = 'array' THEN jsonb_array_length(data)
                        WHEN jsonb_typeof(data) = 'object' THEN (SELECT count(*) FROM jsonb_object_keys(data))::int
                        ELSE 0 END AS item_count
            FROM shared_data
        """)
        meta = {}
        for row in cur.fetchall():
            meta[row["key"]] = {
                "updatedAt": row["updated_at"].isoformat() if row["updated_at"] else None,
                "itemCount": row["item_count"],
            }

        # CDN entries count
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_entries WHERE NOT deleted")
        meta["cdn"] = {"itemCount": cur.fetchone()["cnt"]}

        return _gzip_json_response(meta, cache_key="shared_meta")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Collection endpoints — auth required
# ---------------------------------------------------------------------------

@app.route("/api/v1/collection/upload", methods=["POST"])
@require_auth
def collection_upload(conn=None, cur=None, contributor=None, api_key=None):
    """Upload user collection JSON (max 20MB)."""
    if not _check_rate(_rate_upload, api_key, UPLOAD_LIMIT, 60):
        return jsonify(error="Rate limit exceeded. Try again in a minute."), 429

    # Accept JSON body
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="Invalid JSON body"), 400

    # Validate expected structure
    if not isinstance(data.get("library"), list):
        return jsonify(error="'library' array is required"), 400

    lib = data["library"]
    ph = data.get("playHistory", [])
    history = data.get("history", [])
    accounts = data.get("accounts", [])

    if not isinstance(ph, list):
        ph = []
    if not isinstance(history, list):
        history = []
    if not isinstance(accounts, list):
        accounts = []

    # Size guard: ~20MB JSON limit
    raw_size = len(request.get_data(as_text=False))
    if raw_size > 20 * 1024 * 1024:
        return jsonify(error="Payload too large (max 20MB)"), 413

    # Cap history to 100 entries
    history = history[:100]

    # Strip accounts to gamertag only
    safe_accounts = []
    for a in accounts:
        if isinstance(a, dict) and a.get("gamertag"):
            safe_accounts.append({"gamertag": a["gamertag"]})

    try:
        cur.execute("""
            INSERT INTO user_collections (contributor_id, lib, play_history, scan_history, accounts_meta, uploaded_at, version)
            VALUES (%s, %s, %s, %s, %s, NOW(), 1)
            ON CONFLICT (contributor_id) DO UPDATE SET
                lib = EXCLUDED.lib,
                play_history = EXCLUDED.play_history,
                scan_history = EXCLUDED.scan_history,
                accounts_meta = EXCLUDED.accounts_meta,
                uploaded_at = NOW(),
                version = user_collections.version + 1
        """, (
            contributor["id"],
            psycopg2.extras.Json(lib),
            psycopg2.extras.Json(ph),
            psycopg2.extras.Json(history),
            psycopg2.extras.Json(safe_accounts),
        ))
        conn.commit()
        return jsonify(
            status="ok",
            items=len(lib),
            playHistory=len(ph),
            history=len(history),
            accounts=len(safe_accounts),
        )
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/collection", methods=["GET"])
@require_auth
def collection_get(conn=None, cur=None, contributor=None, api_key=None):
    """Retrieve stored collection for the authenticated user."""
    try:
        cur.execute("""
            SELECT lib, play_history, scan_history, accounts_meta, uploaded_at, version
            FROM user_collections
            WHERE contributor_id = %s
        """, (contributor["id"],))
        row = cur.fetchone()
        if not row:
            return jsonify(
                library=[], playHistory=[], history=[], accounts=[],
                username=contributor["username"], uploaded=False)
        return jsonify(
            library=row["lib"] or [],
            playHistory=row["play_history"] or [],
            history=row["scan_history"] or [],
            accounts=row["accounts_meta"] or [],
            username=contributor["username"],
            uploadedAt=row["uploaded_at"].isoformat() if row["uploaded_at"] else None,
            version=row["version"],
            uploaded=True,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/collection", methods=["DELETE"])
@require_auth
def collection_delete(conn=None, cur=None, contributor=None, api_key=None):
    """Delete stored collection for the authenticated user."""
    try:
        cur.execute("DELETE FROM user_collections WHERE contributor_id = %s",
                    (contributor["id"],))
        conn.commit()
        return jsonify(status="ok", deleted=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


# ---------------------------------------------------------------------------
# Flask CLI: import-shared
# ---------------------------------------------------------------------------

@app.cli.command("import-shared")
@click.argument("key", type=click.Choice(["mkt", "gp", "rates", "flags", "gfwl"]))
@click.argument("filepath", type=click.Path(exists=True))
def import_shared(key, filepath):
    """Import a JSON file into the shared_data table.

    Usage:
        flask --app xct_server import-shared mkt marketplace.json
        flask --app xct_server import-shared gp gamepass_details.json
        flask --app xct_server import-shared rates exchange_rates.json
        flask --app xct_server import-shared flags tags.json
        flask --app xct_server import-shared gfwl gfwl_links.json
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Normalize some formats
    if key == "rates" and isinstance(data, dict) and "rates" in data:
        # exchange_rates.json wraps rates in {"rates": {...}}
        data = data["rates"]
    elif key == "gp" and isinstance(data, dict):
        # gamepass_details.json is a dict keyed by productId — flatten to list
        data = list(data.values())
    elif key == "gfwl" and isinstance(data, dict):
        # gfwl_links.json is a dict keyed by titleId — keep the 71 achievement titles
        GFWL_71_TIDS = {
            "4E4D0FA2", "48450FA0", "4D530FA3", "534307FF", "5343080C", "57520FA0",
            "5A450FA0", "534307FA", "5454085C", "5454086F", "58410A6D", "415807D5",
            "45410935", "58410A1C", "44540FA0", "4E4D0FA1", "43430803", "4343080E",
            "43430FA2", "434D0820", "434D0FA0", "434D0831", "434D0FA1", "4D53090A",
            "425307D6", "454D07D4", "434D082F", "4D530901", "4D530842", "57520FA3",
            "5454083B", "4D53080F", "4D5707E4", "4D530FA7", "4D530FA8", "5451081F",
            "534307EB", "43430808", "434307DE", "584109F1", "4D5308D2", "57520FA2",
            "4D530FA5", "434D083E", "58410A10", "41560829", "54510837", "434307F7",
            "43430FA1", "48450FA1", "535007E3", "544707D4", "4D5307D6", "4C4107EB",
            "53450826", "434307F4", "43430FA5", "43430FA0", "49470FA1", "534507F6",
            "584109EB", "4D530FA2", "425607F3", "534507F0", "5345082C", "53450FA2",
            "4D530841", "5451082D", "58410A01", "584109F0",
            "424107DF",
        }
        gfwl_list = []
        for tid, v in data.items():
            if tid in GFWL_71_TIDS:
                gfwl_list.append({
                    "tid": tid,
                    "name": v["name"],
                    "short_id": v.get("short_id", ""),
                    "packages": v.get("packages", []),
                    "total_size": v.get("total_size", 0),
                })
        gfwl_list.sort(key=lambda x: x["name"].lower())
        data = gfwl_list

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO shared_data (key, data, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
        """, (key, psycopg2.extras.Json(data)))
        conn.commit()

        # Invalidate cache
        cache_key = f"shared_{key}"
        _shared_cache.pop(cache_key, None)
        _shared_cache.pop("shared_meta", None)

        count = len(data) if isinstance(data, (list, dict)) else 0
        click.echo(f"[+] Imported '{key}': {count} items")
    except Exception as e:
        conn.rollback()
        click.echo(f"[!] Error: {e}", err=True)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CORS (allow xct.freshdex.app frontend)
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    allowed = {"https://xct.freshdex.app", "http://localhost:5001", "http://127.0.0.1:5001"}
    if origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response


@app.route("/api/v1/collection/upload", methods=["OPTIONS"])
@app.route("/api/v1/collection", methods=["OPTIONS"])
@app.route("/api/v1/register", methods=["OPTIONS"])
def cors_preflight():
    return Response(status=204)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
