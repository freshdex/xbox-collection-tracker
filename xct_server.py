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
import logging
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
from cryptography.fernet import Fernet
from flask import Flask, Response, jsonify, redirect, request

import xbox_auth_server as xba

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
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

# Xbox OAuth2 settings
XBOX_CLIENT_ID = os.environ.get("XBOX_CLIENT_ID", "")
XBOX_CLIENT_SECRET = os.environ.get("XBOX_CLIENT_SECRET", "")
XBOX_REDIRECT_URI = os.environ.get("XBOX_REDIRECT_URI", "https://xct.freshdex.app/api/v1/xbox/callback")
XBOX_ENCRYPTION_KEY = os.environ.get("XBOX_ENCRYPTION_KEY", "")
_fernet = Fernet(XBOX_ENCRYPTION_KEY.encode()) if XBOX_ENCRYPTION_KEY else None

# Xbox auth rate limiters
_rate_xbox_refresh = defaultdict(list)   # api_key -> [timestamps]
XBOX_REFRESH_LIMIT = 1     # per 5 minutes

# OAuth2 state tokens (short-lived, in-memory)
_oauth_states = {}          # state -> {created_at, contributor_id (optional)}
OAUTH_STATE_TTL = 600       # 10 minutes

log = logging.getLogger(__name__)


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
        # Core tables (original)
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
    except Exception:
        conn.rollback()
    # Marketplace scanner tables — separate transaction so core tables
    # are committed even if these fail (e.g. on first deploy before migration)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_products (
                product_id        VARCHAR(16) PRIMARY KEY,
                title             TEXT NOT NULL DEFAULT '',
                publisher         TEXT NOT NULL DEFAULT '',
                developer         TEXT NOT NULL DEFAULT '',
                category          TEXT NOT NULL DEFAULT '',
                release_date      DATE,
                platforms         TEXT[] NOT NULL DEFAULT '{}',
                product_kind      VARCHAR(32) NOT NULL DEFAULT '',
                xbox_title_id     VARCHAR(32) NOT NULL DEFAULT '',
                is_bundle         BOOLEAN NOT NULL DEFAULT FALSE,
                is_ea_play        BOOLEAN NOT NULL DEFAULT FALSE,
                xcloud_streamable BOOLEAN NOT NULL DEFAULT FALSE,
                capabilities      TEXT[] NOT NULL DEFAULT '{}',
                alternate_ids     JSONB NOT NULL DEFAULT '[]',
                image_tile        TEXT NOT NULL DEFAULT '',
                image_box_art     TEXT NOT NULL DEFAULT '',
                image_hero        TEXT NOT NULL DEFAULT '',
                short_description TEXT NOT NULL DEFAULT '',
                average_rating    REAL NOT NULL DEFAULT 0,
                rating_count      INTEGER NOT NULL DEFAULT 0,
                first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                sources           TEXT[] NOT NULL DEFAULT '{}'
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_prices (
                product_id  VARCHAR(16) REFERENCES marketplace_products(product_id),
                market      VARCHAR(4) NOT NULL,
                currency    VARCHAR(4) NOT NULL,
                msrp        REAL NOT NULL DEFAULT 0,
                sale_price  REAL NOT NULL DEFAULT 0,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (product_id, market)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_channels (
                product_id  VARCHAR(16) REFERENCES marketplace_products(product_id),
                channel     VARCHAR(64) NOT NULL,
                regions     TEXT[] NOT NULL DEFAULT '{}',
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (product_id, channel)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_tags (
                product_id  VARCHAR(16) NOT NULL,
                tag_type    VARCHAR(32) NOT NULL,
                tag_value   TEXT NOT NULL DEFAULT '',
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (product_id, tag_type)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS marketplace_scans (
                id                SERIAL PRIMARY KEY,
                started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                completed_at      TIMESTAMPTZ,
                status            VARCHAR(16) NOT NULL DEFAULT 'running',
                scan_type         VARCHAR(32) NOT NULL DEFAULT 'full',
                channels_scanned  INTEGER DEFAULT 0,
                browse_products   INTEGER DEFAULT 0,
                catalog_enriched  INTEGER DEFAULT 0,
                prices_fetched    INTEGER DEFAULT 0,
                products_total    INTEGER DEFAULT 0,
                products_new      INTEGER DEFAULT 0,
                errors            JSONB DEFAULT '[]',
                duration_seconds  REAL
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_mp_xbox_title_id
            ON marketplace_products(xbox_title_id) WHERE xbox_title_id != ''
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Marketplace tables init failed ({e}) — run migration manually")
    # Xbox Live auth + achievements tables
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS xbox_auth (
                contributor_id    INTEGER PRIMARY KEY REFERENCES contributors(id) ON DELETE CASCADE,
                xuid              TEXT NOT NULL,
                gamertag          TEXT NOT NULL,
                refresh_token_enc BYTEA NOT NULL,
                xbl3_token        TEXT,
                token_acquired_at TIMESTAMPTZ,
                created_at        TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS xbox_achievement_summaries (
                contributor_id       INTEGER NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
                xbox_title_id        TEXT NOT NULL,
                product_id           TEXT NOT NULL DEFAULT '',
                title_name           TEXT NOT NULL DEFAULT '',
                current_gamerscore   INTEGER NOT NULL DEFAULT 0,
                total_gamerscore     INTEGER NOT NULL DEFAULT 0,
                current_achievements INTEGER NOT NULL DEFAULT 0,
                total_achievements   INTEGER NOT NULL DEFAULT 0,
                last_time_played     TIMESTAMPTZ,
                display_image        TEXT NOT NULL DEFAULT '',
                platforms            TEXT[] NOT NULL DEFAULT '{}',
                fetched_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (contributor_id, xbox_title_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS xbox_achievement_details (
                contributor_id  INTEGER NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
                xbox_title_id   TEXT NOT NULL,
                achievement_id  TEXT NOT NULL,
                name            TEXT NOT NULL DEFAULT '',
                description     TEXT NOT NULL DEFAULT '',
                gamerscore      INTEGER NOT NULL DEFAULT 0,
                is_secret       BOOLEAN NOT NULL DEFAULT FALSE,
                unlocked        BOOLEAN NOT NULL DEFAULT FALSE,
                unlock_time     TIMESTAMPTZ,
                rarity_category TEXT NOT NULL DEFAULT '',
                rarity_pct      REAL NOT NULL DEFAULT 0,
                media_url       TEXT NOT NULL DEFAULT '',
                fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (contributor_id, xbox_title_id, achievement_id)
            )
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Xbox auth tables init failed ({e}) — run migration manually")
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
# Tab slug routes — persistent URLs for tabs (e.g. /xvcdb, /gamepass)
# ---------------------------------------------------------------------------

_TAB_SLUGS = {
    "library", "marketplace", "gamepass", "playhistory", "scanlog",
    "gamertags", "gfwl", "xvcdb", "imports", "achievements",
}


@app.route("/<slug>")
def tab_route(slug):
    """Serve same HTML for tab URLs — client JS reads path to auto-select tab."""
    if slug not in _TAB_SLUGS:
        return index()  # fallback to index for unknown slugs
    return index()


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
    """Build CDN_DB live from cdn_entries table, enriched with titles from shared_data.
    Automatically includes new entries from CDN Sync without manual import.
    Cached for SHARED_CACHE_TTL (5 min) via _gzip_json_response."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Load enrichment data (title/developer/publisher) from shared_data import
        enrichment = {}
        cur.execute("SELECT data FROM shared_data WHERE key = 'cdn'")
        row = cur.fetchone()
        if row and isinstance(row["data"], dict):
            for sid, rec in row["data"].items():
                t = rec.get("title") or ""
                if t:
                    enrichment[sid] = {
                        "title": t,
                        "developer": rec.get("developer", ""),
                        "publisher": rec.get("publisher", ""),
                    }

        # Fetch all live entries from cdn_entries
        cur.execute("""
            SELECT store_id, build_id, content_id, package_name, build_version,
                   platform, size_bytes, cdn_urls, content_types, devices,
                   language, plan_id, source, scraped_at,
                   prior_build_version, prior_build_id
            FROM cdn_entries
            WHERE NOT deleted
            ORDER BY store_id, scraped_at DESC
        """)

        _VER_KEYS = ("buildVersion", "buildId", "platform", "sizeBytes", "cdnUrls",
                      "scrapedAt", "priorBuildVersion", "priorBuildId")
        cdn_db = {}
        for row in cur:
            sid = row["store_id"]
            entry = {
                "contentId": row["content_id"],
                "storeId": sid,
                "packageName": row["package_name"],
                "buildVersion": row["build_version"],
                "buildId": row["build_id"],
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
            }
            if sid not in cdn_db:
                cdn_db[sid] = entry
            else:
                existing = cdn_db[sid]
                if existing["buildId"] == entry["buildId"]:
                    continue
                versions = existing.get("versions", [])
                if not versions:
                    versions.append({k: existing[k] for k in _VER_KEYS if k in existing})
                if not any(v.get("buildId") == entry["buildId"] for v in versions):
                    versions.append({k: entry[k] for k in _VER_KEYS if k in entry})
                existing["versions"] = versions

        # Apply enrichment
        for sid, rec in cdn_db.items():
            if sid in enrichment:
                rec.update(enrichment[sid])

        return _gzip_json_response(cdn_db, cache_key="shared_cdn")
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/shared/cdn_meta")
def shared_cdn_meta():
    """Serve contributor map from cdn_entries for the hosted viewer.
    Returns {storeId:buildId: username, ...} so the frontend can show
    who contributed each CDN entry."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT e.store_id, e.build_id, c2.username
            FROM cdn_entries e
            JOIN contributions c ON c.cdn_entry_id = e.id
            JOIN contributors c2 ON c2.id = c.contributor_id
            WHERE NOT e.deleted
        """)
        contributor_map = {}
        for row in cur:
            contributor_map[f"{row['store_id']}:{row['build_id']}"] = row["username"]
        return _gzip_json_response(contributor_map, cache_key="shared_cdn_meta")
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
# Marketplace endpoints — scanner-populated data
# ---------------------------------------------------------------------------

@app.route("/api/v1/marketplace")
def marketplace():
    """Full marketplace dataset from scanner-populated tables.

    Returns products, prices, channels, tags, exchange rates, and last scan info.
    Gzipped with ETag caching (5-min in-memory cache).
    """
    _empty_result = {
        "products": [], "exchangeRates": {}, "gcFactor": 0.81,
        "tags": {}, "lastScan": None,
    }
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check if tables exist (graceful fallback before migration)
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'marketplace_products'
            )
        """)
        if not cur.fetchone()["exists"]:
            return _gzip_json_response(_empty_result, cache_key="marketplace_full")

        # 1. Products
        cur.execute("""
            SELECT product_id, title, publisher, developer, category, release_date,
                   platforms, product_kind, xbox_title_id, is_bundle, is_ea_play,
                   xcloud_streamable, capabilities, alternate_ids,
                   image_tile, image_box_art, image_hero, short_description,
                   average_rating, rating_count, sources
            FROM marketplace_products
            ORDER BY title
        """)
        products_raw = cur.fetchall()

        # 2. Prices — pivot into {product_id: {market: {msrp, salePrice, currency}}}
        cur.execute("SELECT product_id, market, currency, msrp, sale_price FROM marketplace_prices")
        price_map = {}
        for row in cur:
            pid = row["product_id"]
            if pid not in price_map:
                price_map[pid] = {}
            price_map[pid][row["market"]] = {
                "msrp": row["msrp"],
                "salePrice": row["sale_price"],
                "currency": row["currency"],
            }

        # 3. Channels — pivot into {product_id: [channel_names]}
        cur.execute("SELECT product_id, channel FROM marketplace_channels")
        channel_map = {}
        for row in cur:
            pid = row["product_id"]
            if pid not in channel_map:
                channel_map[pid] = []
            channel_map[pid].append(row["channel"])

        # 4. Tags
        cur.execute("SELECT product_id, tag_type, tag_value FROM marketplace_tags")
        tags = {}
        for row in cur:
            pid = row["product_id"]
            if pid not in tags:
                tags[pid] = {}
            tags[pid][row["tag_type"]] = row["tag_value"]

        # 5. Exchange rates from shared_data
        cur.execute("SELECT data FROM shared_data WHERE key = 'rates'")
        rates_row = cur.fetchone()
        exchange_rates = {}
        if rates_row and isinstance(rates_row["data"], dict):
            exchange_rates = rates_row["data"].get("rates", rates_row["data"])

        # 6. Last scan
        cur.execute("""
            SELECT id, completed_at, status, products_total, products_new,
                   duration_seconds, scan_type
            FROM marketplace_scans
            ORDER BY id DESC LIMIT 1
        """)
        scan_row = cur.fetchone()
        last_scan = None
        if scan_row:
            last_scan = {
                "completedAt": scan_row["completed_at"].isoformat() if scan_row["completed_at"] else None,
                "productsTotal": scan_row["products_total"],
                "productsNew": scan_row["products_new"],
                "status": scan_row["status"],
                "scanType": scan_row["scan_type"],
                "durationSeconds": scan_row["duration_seconds"],
            }

        # Assemble product list
        products = []
        for p in products_raw:
            pid = p["product_id"]
            products.append({
                "productId": pid,
                "title": p["title"],
                "publisher": p["publisher"],
                "developer": p["developer"],
                "category": p["category"],
                "releaseDate": p["release_date"].isoformat() if p["release_date"] else "",
                "platforms": p["platforms"] or [],
                "productKind": p["product_kind"],
                "xboxTitleId": p["xbox_title_id"],
                "isBundle": p["is_bundle"],
                "isEAPlay": p["is_ea_play"],
                "xCloudStreamable": p["xcloud_streamable"],
                "imageBoxArt": p["image_box_art"],
                "imageHero": p["image_hero"],
                "shortDescription": p["short_description"],
                "averageRating": p["average_rating"],
                "ratingCount": p["rating_count"],
                "channels": channel_map.get(pid, []),
                "sources": p["sources"] or [],
                "regionalPrices": price_map.get(pid, {}),
            })

        result = {
            "products": products,
            "exchangeRates": exchange_rates,
            "gcFactor": 0.81,
            "tags": tags,
            "lastScan": last_scan,
        }
        return _gzip_json_response(result, cache_key="marketplace_full")

    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/marketplace/tags", methods=["POST"])
def marketplace_tags_update():
    """Admin endpoint: set manual tags on marketplace products.

    Requires ADMIN_API_KEY env var. Body: {productId, tagType, tagValue}.
    """
    if not ADMIN_API_KEY:
        return jsonify(error="Admin endpoint not configured"), 501

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:].strip() != ADMIN_API_KEY:
        return jsonify(error="Invalid admin key"), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="JSON body required"), 400

    product_id = (data.get("productId") or "").strip()
    tag_type = (data.get("tagType") or "").strip()
    tag_value = (data.get("tagValue") or "").strip()

    if not product_id or not tag_type:
        return jsonify(error="productId and tagType are required"), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        if tag_value:
            cur.execute("""
                INSERT INTO marketplace_tags (product_id, tag_type, tag_value, created_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (product_id, tag_type) DO UPDATE SET
                    tag_value = EXCLUDED.tag_value, created_at = NOW()
            """, (product_id, tag_type, tag_value))
        else:
            # Empty value = delete the tag
            cur.execute("DELETE FROM marketplace_tags WHERE product_id = %s AND tag_type = %s",
                        (product_id, tag_type))
        conn.commit()
        # Invalidate marketplace cache
        _shared_cache.pop("marketplace_full", None)
        return jsonify(status="ok", productId=product_id, tagType=tag_type, tagValue=tag_value)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/marketplace/tags", methods=["OPTIONS"])
def marketplace_tags_preflight():
    return Response(status=204)


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
@click.argument("key", type=click.Choice(["mkt", "gp", "rates", "flags", "gfwl", "cdn"]))
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
# Xbox Live OAuth2 — helpers
# ---------------------------------------------------------------------------

def _cleanup_oauth_states():
    """Remove expired OAuth state tokens."""
    now = time.time()
    expired = [s for s, v in _oauth_states.items() if now - v["created_at"] > OAUTH_STATE_TTL]
    for s in expired:
        del _oauth_states[s]


def _ensure_xbl3_token(cur, conn, contributor_id):
    """Return a valid XBL3.0 token for the contributor, refreshing if needed.

    Returns (xbl3_token, xuid, gamertag) or raises.
    """
    cur.execute(
        "SELECT xuid, gamertag, refresh_token_enc, xbl3_token, token_acquired_at "
        "FROM xbox_auth WHERE contributor_id = %s",
        (contributor_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError("No Xbox account linked")

    # Check if token is still fresh (< 12 hours)
    token_age = 999999
    if row["token_acquired_at"]:
        token_age = (datetime.now(timezone.utc) - row["token_acquired_at"]).total_seconds()

    if row["xbl3_token"] and token_age < 43200:  # 12 hours
        return row["xbl3_token"], row["xuid"], row["gamertag"]

    # Token stale — refresh
    if not _fernet:
        raise ValueError("Encryption key not configured")
    refresh_token = _fernet.decrypt(row["refresh_token_enc"]).decode()

    try:
        msa = xba.refresh_msa_token(XBOX_CLIENT_ID, XBOX_CLIENT_SECRET, refresh_token)
    except Exception:
        # Refresh token revoked — clear Xbox auth
        cur.execute("DELETE FROM xbox_auth WHERE contributor_id = %s", (contributor_id,))
        cur.execute("DELETE FROM xbox_achievement_summaries WHERE contributor_id = %s",
                    (contributor_id,))
        cur.execute("DELETE FROM xbox_achievement_details WHERE contributor_id = %s",
                    (contributor_id,))
        conn.commit()
        raise ValueError("Xbox session expired — please sign in again")

    auth_result = xba.full_auth(msa["access_token"])
    new_refresh_enc = _fernet.encrypt(msa["refresh_token"].encode())

    cur.execute("""
        UPDATE xbox_auth SET
            xbl3_token = %s, token_acquired_at = NOW(),
            refresh_token_enc = %s, gamertag = %s, xuid = %s
        WHERE contributor_id = %s
    """, (auth_result["xbl3_token"], new_refresh_enc,
          auth_result["gamertag"], auth_result["xuid"], contributor_id))
    conn.commit()

    return auth_result["xbl3_token"], auth_result["xuid"], auth_result["gamertag"]


def _store_achievement_summaries(cur, contributor_id, summaries):
    """Upsert TitleHub achievement summaries into DB."""
    for s in summaries:
        last_played = None
        if s.get("lastTimePlayed"):
            try:
                last_played = datetime.fromisoformat(
                    s["lastTimePlayed"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        cur.execute("""
            INSERT INTO xbox_achievement_summaries
                (contributor_id, xbox_title_id, product_id, title_name,
                 current_gamerscore, total_gamerscore, current_achievements,
                 total_achievements, last_time_played, display_image,
                 platforms, fetched_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
            ON CONFLICT (contributor_id, xbox_title_id) DO UPDATE SET
                product_id = EXCLUDED.product_id,
                title_name = EXCLUDED.title_name,
                current_gamerscore = EXCLUDED.current_gamerscore,
                total_gamerscore = EXCLUDED.total_gamerscore,
                current_achievements = EXCLUDED.current_achievements,
                total_achievements = EXCLUDED.total_achievements,
                last_time_played = EXCLUDED.last_time_played,
                display_image = EXCLUDED.display_image,
                platforms = EXCLUDED.platforms,
                fetched_at = NOW()
        """, (contributor_id, s["titleId"], s.get("productId", ""),
              s.get("name", ""), s.get("currentGamerscore", 0),
              s.get("totalGamerscore", 0), s.get("currentAchievements", 0),
              s.get("totalAchievements", 0), last_played,
              s.get("displayImage", ""), s.get("platforms", [])))


def _store_achievement_details(cur, contributor_id, xbox_title_id, details):
    """Upsert individual achievements into DB."""
    for d in details:
        unlock_time = None
        if d.get("unlockTime"):
            try:
                unlock_time = datetime.fromisoformat(
                    d["unlockTime"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        gamerscore = d.get("gamerscore", 0)
        if isinstance(gamerscore, str):
            try:
                gamerscore = int(gamerscore)
            except ValueError:
                gamerscore = 0

        cur.execute("""
            INSERT INTO xbox_achievement_details
                (contributor_id, xbox_title_id, achievement_id, name,
                 description, gamerscore, is_secret, unlocked, unlock_time,
                 rarity_category, rarity_pct, media_url, fetched_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
            ON CONFLICT (contributor_id, xbox_title_id, achievement_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                gamerscore = EXCLUDED.gamerscore,
                is_secret = EXCLUDED.is_secret,
                unlocked = EXCLUDED.unlocked,
                unlock_time = EXCLUDED.unlock_time,
                rarity_category = EXCLUDED.rarity_category,
                rarity_pct = EXCLUDED.rarity_pct,
                media_url = EXCLUDED.media_url,
                fetched_at = NOW()
        """, (contributor_id, xbox_title_id, d["id"], d.get("name", ""),
              d.get("description", ""), gamerscore, d.get("isSecret", False),
              d.get("unlocked", False), unlock_time,
              d.get("rarityCategory", ""), d.get("rarityPct", 0),
              d.get("mediaUrl", "")))


# ---------------------------------------------------------------------------
# Xbox Live OAuth2 — endpoints
# ---------------------------------------------------------------------------

@app.route("/api/v1/xbox/auth/start")
def xbox_auth_start():
    """Start Xbox OAuth2 flow. Redirects to Microsoft login."""
    if not XBOX_CLIENT_ID or not XBOX_CLIENT_SECRET:
        return jsonify(error="Xbox OAuth not configured on server"), 501

    _cleanup_oauth_states()

    state = secrets.token_urlsafe(32)
    state_data = {"created_at": time.time()}

    # If user already has an api_key, link Xbox to that account
    link_key = request.args.get("link", "")
    if link_key:
        conn = get_db()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            contributor = _get_contributor(cur, link_key)
            if contributor:
                state_data["contributor_id"] = contributor["id"]
                state_data["api_key"] = link_key
        finally:
            conn.close()

    _oauth_states[state] = state_data

    url = xba.build_authorize_url(XBOX_CLIENT_ID, XBOX_REDIRECT_URI, state)
    return redirect(url)


@app.route("/api/v1/xbox/callback")
def xbox_auth_callback():
    """Handle OAuth2 callback from Microsoft."""
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", error)
        return redirect(f"/?xbox_auth=error&message={desc}")

    code = request.args.get("code", "")
    state = request.args.get("state", "")

    if not code or not state:
        return redirect("/?xbox_auth=error&message=Missing+code+or+state")

    # Validate state (CSRF)
    _cleanup_oauth_states()
    state_data = _oauth_states.pop(state, None)
    if not state_data:
        return redirect("/?xbox_auth=error&message=Invalid+or+expired+state")

    if not _fernet:
        return redirect("/?xbox_auth=error&message=Server+encryption+not+configured")

    # Exchange code for tokens
    try:
        msa = xba.exchange_code_for_tokens(
            XBOX_CLIENT_ID, XBOX_CLIENT_SECRET, code, XBOX_REDIRECT_URI)
    except Exception as e:
        log.warning("Xbox code exchange failed: %s", e)
        return redirect("/?xbox_auth=error&message=Token+exchange+failed")

    # Get Xbox identity
    try:
        auth_result = xba.full_auth(msa["access_token"])
    except Exception as e:
        log.warning("Xbox auth chain failed: %s", e)
        return redirect("/?xbox_auth=error&message=Xbox+auth+failed")

    xbl3_token = auth_result["xbl3_token"]
    xuid = auth_result["xuid"]
    gamertag = auth_result["gamertag"]
    refresh_token_enc = _fernet.encrypt(msa["refresh_token"].encode())

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Find or create contributor
        contributor_id = state_data.get("contributor_id")
        api_key = state_data.get("api_key", "")

        if not contributor_id:
            # Check if xuid already linked to a contributor
            cur.execute(
                "SELECT contributor_id FROM xbox_auth WHERE xuid = %s", (xuid,))
            existing = cur.fetchone()
            if existing:
                contributor_id = existing["contributor_id"]
                cur.execute(
                    "SELECT api_key FROM contributors WHERE id = %s",
                    (contributor_id,))
                api_key = cur.fetchone()["api_key"]
            else:
                # Create new contributor with gamertag as username
                # Check if gamertag username is taken
                cur.execute(
                    "SELECT id, api_key FROM contributors WHERE username = %s",
                    (gamertag,))
                existing_user = cur.fetchone()
                if existing_user:
                    # Username taken — check if it has Xbox auth already
                    cur.execute(
                        "SELECT xuid FROM xbox_auth WHERE contributor_id = %s",
                        (existing_user["id"],))
                    if cur.fetchone():
                        # Different xuid owns this username — append suffix
                        new_username = f"{gamertag}_{xuid[-4:]}"
                        api_key = secrets.token_urlsafe(32)
                        cur.execute(
                            "INSERT INTO contributors (username, api_key) "
                            "VALUES (%s, %s) RETURNING id",
                            (new_username, api_key))
                        contributor_id = cur.fetchone()["id"]
                    else:
                        # Same username, no Xbox — link to this account
                        contributor_id = existing_user["id"]
                        api_key = existing_user["api_key"]
                else:
                    api_key = secrets.token_urlsafe(32)
                    cur.execute(
                        "INSERT INTO contributors (username, api_key) "
                        "VALUES (%s, %s) RETURNING id",
                        (gamertag, api_key))
                    contributor_id = cur.fetchone()["id"]

        # Upsert xbox_auth
        cur.execute("""
            INSERT INTO xbox_auth
                (contributor_id, xuid, gamertag, refresh_token_enc, xbl3_token, token_acquired_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (contributor_id) DO UPDATE SET
                xuid = EXCLUDED.xuid,
                gamertag = EXCLUDED.gamertag,
                refresh_token_enc = EXCLUDED.refresh_token_enc,
                xbl3_token = EXCLUDED.xbl3_token,
                token_acquired_at = NOW()
        """, (contributor_id, xuid, gamertag, refresh_token_enc, xbl3_token))
        conn.commit()

        # Fetch initial achievement summaries (best effort)
        try:
            summaries = xba.fetch_titlehub_achievements(xbl3_token, xuid)
            _store_achievement_summaries(cur, contributor_id, summaries)
            conn.commit()
        except Exception as e:
            conn.rollback()
            log.warning("Initial achievement fetch failed for %s: %s", gamertag, e)

        import urllib.parse
        params = urllib.parse.urlencode({
            "xbox_auth": "success",
            "api_key": api_key,
            "gamertag": gamertag,
            "xuid": xuid,
        })
        return redirect(f"/?{params}")

    except Exception as e:
        conn.rollback()
        log.error("Xbox callback DB error: %s", e)
        return redirect("/?xbox_auth=error&message=Server+error")
    finally:
        conn.close()


@app.route("/api/v1/xbox/achievements")
@require_auth
def xbox_achievements_list(conn=None, cur=None, contributor=None, api_key=None):
    """Return cached achievement summaries for the authenticated user."""
    try:
        # Check if Xbox linked
        cur.execute(
            "SELECT xuid, gamertag FROM xbox_auth WHERE contributor_id = %s",
            (contributor["id"],))
        xbox = cur.fetchone()
        if not xbox:
            return jsonify(error="No Xbox account linked", linked=False), 404

        # Ensure token is valid (refresh if needed)
        try:
            _ensure_xbl3_token(cur, conn, contributor["id"])
        except ValueError as e:
            return jsonify(error=str(e), linked=False), 401

        # Return summaries from DB
        cur.execute("""
            SELECT xbox_title_id, product_id, title_name, current_gamerscore,
                   total_gamerscore, current_achievements, total_achievements,
                   last_time_played, display_image, platforms, fetched_at
            FROM xbox_achievement_summaries
            WHERE contributor_id = %s
            ORDER BY last_time_played DESC NULLS LAST
        """, (contributor["id"],))

        summaries = []
        total_gs = 0
        for row in cur.fetchall():
            total_gs += row["current_gamerscore"]
            summaries.append({
                "xboxTitleId": row["xbox_title_id"],
                "productId": row["product_id"],
                "titleName": row["title_name"],
                "currentGamerscore": row["current_gamerscore"],
                "totalGamerscore": row["total_gamerscore"],
                "currentAchievements": row["current_achievements"],
                "totalAchievements": row["total_achievements"],
                "lastTimePlayed": row["last_time_played"].isoformat()
                    if row["last_time_played"] else None,
                "displayImage": row["display_image"],
                "platforms": row["platforms"] or [],
                "fetchedAt": row["fetched_at"].isoformat()
                    if row["fetched_at"] else None,
            })

        return jsonify(
            gamertag=xbox["gamertag"],
            xuid=xbox["xuid"],
            totalGamerscore=total_gs,
            totalTitles=len(summaries),
            summaries=summaries,
            linked=True,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/xbox/achievements/<xbox_title_id>")
@require_auth
def xbox_achievements_detail(xbox_title_id, conn=None, cur=None, contributor=None, api_key=None):
    """Return individual achievements for a specific title."""
    try:
        # Check cache freshness (1 hour)
        cur.execute("""
            SELECT fetched_at FROM xbox_achievement_details
            WHERE contributor_id = %s AND xbox_title_id = %s
            LIMIT 1
        """, (contributor["id"], xbox_title_id))
        cached = cur.fetchone()

        need_fetch = True
        if cached and cached["fetched_at"]:
            age = (datetime.now(timezone.utc) - cached["fetched_at"]).total_seconds()
            if age < 3600:
                need_fetch = False

        if need_fetch:
            try:
                xbl3, xuid, gt = _ensure_xbl3_token(cur, conn, contributor["id"])
                details = xba.fetch_achievement_details(xbl3, xuid, xbox_title_id)
                _store_achievement_details(cur, contributor["id"], xbox_title_id, details)
                conn.commit()
            except ValueError as e:
                return jsonify(error=str(e), linked=False), 401
            except Exception as e:
                log.warning("Achievement detail fetch failed for %s/%s: %s",
                            contributor["id"], xbox_title_id, e)
                # Fall through to serve cached data if available

        # Return from DB
        cur.execute("""
            SELECT achievement_id, name, description, gamerscore, is_secret,
                   unlocked, unlock_time, rarity_category, rarity_pct, media_url
            FROM xbox_achievement_details
            WHERE contributor_id = %s AND xbox_title_id = %s
            ORDER BY unlocked DESC, unlock_time DESC NULLS LAST, name
        """, (contributor["id"], xbox_title_id))

        # Also get the title name
        cur.execute("""
            SELECT title_name FROM xbox_achievement_summaries
            WHERE contributor_id = %s AND xbox_title_id = %s
        """, (contributor["id"], xbox_title_id))
        title_row = cur.fetchone()
        title_name = title_row["title_name"] if title_row else ""

        # Re-run detail query (cursor was consumed by title_name query)
        cur.execute("""
            SELECT achievement_id, name, description, gamerscore, is_secret,
                   unlocked, unlock_time, rarity_category, rarity_pct, media_url
            FROM xbox_achievement_details
            WHERE contributor_id = %s AND xbox_title_id = %s
            ORDER BY unlocked DESC, unlock_time DESC NULLS LAST, name
        """, (contributor["id"], xbox_title_id))

        achievements = []
        for row in cur.fetchall():
            achievements.append({
                "id": row["achievement_id"],
                "name": row["name"],
                "description": row["description"],
                "gamerscore": row["gamerscore"],
                "isSecret": row["is_secret"],
                "unlocked": row["unlocked"],
                "unlockTime": row["unlock_time"].isoformat()
                    if row["unlock_time"] else None,
                "rarityCategory": row["rarity_category"],
                "rarityPct": row["rarity_pct"],
                "mediaUrl": row["media_url"],
            })

        return jsonify(
            xboxTitleId=xbox_title_id,
            title=title_name,
            achievements=achievements,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/xbox/achievements/refresh", methods=["POST"])
@require_auth
def xbox_achievements_refresh(conn=None, cur=None, contributor=None, api_key=None):
    """Re-fetch achievement summaries from Xbox Live. Rate limited: 1 per 5 min."""
    if not _check_rate(_rate_xbox_refresh, api_key, XBOX_REFRESH_LIMIT, 300):
        return jsonify(error="Rate limit — try again in 5 minutes"), 429

    try:
        xbl3, xuid, gamertag = _ensure_xbl3_token(cur, conn, contributor["id"])
    except ValueError as e:
        return jsonify(error=str(e), linked=False), 401

    try:
        summaries = xba.fetch_titlehub_achievements(xbl3, xuid)
        _store_achievement_summaries(cur, contributor["id"], summaries)
        conn.commit()

        total_gs = sum(s.get("currentGamerscore", 0) for s in summaries)
        return jsonify(
            status="ok",
            totalTitles=len(summaries),
            totalGamerscore=total_gs,
        )
    except Exception as e:
        conn.rollback()
        return jsonify(error=f"Failed to fetch achievements: {e}"), 500


@app.route("/api/v1/xbox/auth/disconnect", methods=["POST"])
@require_auth
def xbox_auth_disconnect(conn=None, cur=None, contributor=None, api_key=None):
    """Disconnect Xbox account — removes auth state and all achievement data."""
    try:
        cur.execute("DELETE FROM xbox_achievement_details WHERE contributor_id = %s",
                    (contributor["id"],))
        cur.execute("DELETE FROM xbox_achievement_summaries WHERE contributor_id = %s",
                    (contributor["id"],))
        cur.execute("DELETE FROM xbox_auth WHERE contributor_id = %s",
                    (contributor["id"],))
        conn.commit()
        return jsonify(status="ok")
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/xbox/auth/status")
@require_auth
def xbox_auth_status(conn=None, cur=None, contributor=None, api_key=None):
    """Check if the user has an Xbox account linked."""
    try:
        cur.execute(
            "SELECT xuid, gamertag, token_acquired_at FROM xbox_auth "
            "WHERE contributor_id = %s",
            (contributor["id"],))
        row = cur.fetchone()
        if not row:
            return jsonify(linked=False)
        return jsonify(
            linked=True,
            gamertag=row["gamertag"],
            xuid=row["xuid"],
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


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
@app.route("/api/v1/xbox/achievements", methods=["OPTIONS"])
@app.route("/api/v1/xbox/achievements/refresh", methods=["OPTIONS"])
@app.route("/api/v1/xbox/auth/disconnect", methods=["OPTIONS"])
@app.route("/api/v1/xbox/auth/status", methods=["OPTIONS"])
def cors_preflight():
    return Response(status=204)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
