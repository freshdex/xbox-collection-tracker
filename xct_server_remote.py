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
import subprocess
import threading
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


_AUTH_JS = open("/app/auth_hosted.js").read()

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
    # Add purchases column if missing (migration)
    try:
        cur = conn.cursor()
        cur.execute("""
            ALTER TABLE user_collections ADD COLUMN IF NOT EXISTS purchases JSONB
        """)
        conn.commit()
    except Exception:
        conn.rollback()
    # OAuth state table (needed for multi-worker gunicorn)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state       TEXT PRIMARY KEY,
                data        JSONB NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT NOW()
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
                sources           TEXT[] NOT NULL DEFAULT '{}',
                has_trial_sku     BOOLEAN NOT NULL DEFAULT FALSE,
                has_achievements  BOOLEAN NOT NULL DEFAULT FALSE
            )
        """)
        # Migration: add has_trial_sku if it doesn't exist yet
        cur.execute("""
            ALTER TABLE marketplace_products
            ADD COLUMN IF NOT EXISTS has_trial_sku BOOLEAN NOT NULL DEFAULT FALSE
        """)
        # Migration: add has_achievements if it doesn't exist yet
        cur.execute("""
            ALTER TABLE marketplace_products
            ADD COLUMN IF NOT EXISTS has_achievements BOOLEAN NOT NULL DEFAULT FALSE
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
            CREATE TABLE IF NOT EXISTS marketplace_subscriptions (
                product_id  VARCHAR(16) REFERENCES marketplace_products(product_id),
                tier        VARCHAR(64) NOT NULL,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (product_id, tier)
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
            CREATE TABLE IF NOT EXISTS marketplace_changelog (
                id            SERIAL PRIMARY KEY,
                scan_id       INTEGER REFERENCES marketplace_scans(id),
                change_type   VARCHAR(32) NOT NULL,
                product_id    VARCHAR(16) NOT NULL,
                title         TEXT NOT NULL DEFAULT '',
                field_name    VARCHAR(64) NOT NULL DEFAULT '',
                old_value     TEXT NOT NULL DEFAULT '',
                new_value     TEXT NOT NULL DEFAULT '',
                market        VARCHAR(4) NOT NULL DEFAULT '',
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_changelog_scan
            ON marketplace_changelog(scan_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_changelog_created
            ON marketplace_changelog(created_at DESC)
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
    # Leaderboard tables
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ta_leaderboard_entries (
                id SERIAL PRIMARY KEY,
                leaderboard_type TEXT NOT NULL,
                position INTEGER NOT NULL,
                gamertag TEXT NOT NULL,
                score TEXT NOT NULL DEFAULT '',
                avatar_url TEXT DEFAULT '',
                scraped_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(leaderboard_type, gamertag)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS xbox_gamer_profiles (
                xuid TEXT PRIMARY KEY,
                gamertag TEXT NOT NULL,
                gamerscore INTEGER DEFAULT 0,
                games_played_v2 INTEGER DEFAULT 0,
                games_played_v1 INTEGER DEFAULT 0,
                games_played_total INTEGER DEFAULT 0,
                avatar_url TEXT DEFAULT '',
                scan_status TEXT DEFAULT 'pending',
                scan_error TEXT DEFAULT '',
                scanned_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_log (
                id SERIAL PRIMARY KEY,
                message TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Leaderboard tables init failed ({e}) — run migration manually")
    # Profile columns on contributors
    try:
        cur = conn.cursor()
        cur.execute("ALTER TABLE contributors ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT ''")
        cur.execute("ALTER TABLE contributors ADD COLUMN IF NOT EXISTS status TEXT DEFAULT ''")
        cur.execute("ALTER TABLE contributors ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}'")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Profile columns migration failed ({e}) — run manually")
    # CDN Version Monitor tables
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cdn_version_scans (
                id                  SERIAL PRIMARY KEY,
                started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                completed_at        TIMESTAMPTZ,
                status              VARCHAR(16) NOT NULL DEFAULT 'running',
                scan_type           VARCHAR(32) NOT NULL DEFAULT 'full',
                content_ids_total   INTEGER DEFAULT 0,
                content_ids_checked INTEGER DEFAULT 0,
                versions_found      INTEGER DEFAULT 0,
                new_versions        INTEGER DEFAULT 0,
                purged_detected     INTEGER DEFAULT 0,
                errors              JSONB DEFAULT '[]',
                duration_seconds    REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cdn_version_snapshots (
                id              SERIAL PRIMARY KEY,
                content_id      VARCHAR(64) NOT NULL,
                store_id        VARCHAR(16) NOT NULL DEFAULT '',
                version         VARCHAR(64) NOT NULL,
                build_id        VARCHAR(64) NOT NULL DEFAULT '',
                version_id      VARCHAR(128) NOT NULL DEFAULT '',
                cdn_url         TEXT NOT NULL DEFAULT '',
                file_size       BIGINT DEFAULT 0,
                filename        VARCHAR(512) NOT NULL DEFAULT '',
                status          VARCHAR(16) NOT NULL DEFAULT 'live',
                first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                purged_at       TIMESTAMPTZ,
                scan_id         INTEGER REFERENCES cdn_version_scans(id),
                UNIQUE(content_id, version_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cdn_version_changes (
                id              SERIAL PRIMARY KEY,
                scan_id         INTEGER REFERENCES cdn_version_scans(id),
                change_type     VARCHAR(32) NOT NULL,
                content_id      VARCHAR(64) NOT NULL,
                store_id        VARCHAR(16) NOT NULL DEFAULT '',
                title           TEXT NOT NULL DEFAULT '',
                version         VARCHAR(64) NOT NULL DEFAULT '',
                build_id        VARCHAR(64) NOT NULL DEFAULT '',
                old_value       TEXT NOT NULL DEFAULT '',
                new_value       TEXT NOT NULL DEFAULT '',
                created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_cdn_ver_snap_content
            ON cdn_version_snapshots(content_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_cdn_ver_snap_status
            ON cdn_version_snapshots(status)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_cdn_ver_changes_scan
            ON cdn_version_changes(scan_id)
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] CDN version monitor tables init failed ({e}) — run migration manually")
    # Amazon physical disc cache
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS amazon_cache (
                product_id   VARCHAR(16) NOT NULL,
                market       VARCHAR(4) NOT NULL,
                title        TEXT NOT NULL DEFAULT '',
                price        TEXT NOT NULL DEFAULT '',
                url          TEXT NOT NULL DEFAULT '',
                edition      TEXT NOT NULL DEFAULT '',
                fetched_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (product_id, market, url)
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_amazon_cache_product
            ON amazon_cache(product_id)
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Amazon cache tables init failed ({e}) — run migration manually")
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
        "SELECT id, username, total_points, avatar_url, status, settings FROM contributors WHERE api_key = %s",
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
            html = build_html_template(
                header_html='<div id="xct-auth" style="margin-left:auto;display:flex;align-items:center;gap:8px;padding:0 12px"><span id="xct-auth-user" style="color:#888;font-size:12px"></span><img id="xct-avatar" src="" style="width:24px;height:24px;border-radius:50%;object-fit:cover;display:none;cursor:pointer" onclick="_openProfile()"><span id="xct-xbox-gt" style="color:#107c10;font-size:12px;display:none;cursor:pointer" onclick="_openProfile()"></span><button id="xct-upload-btn" onclick="document.getElementById(\'xct-upload-input\').click()" style="display:none;padding:4px 12px;background:#333;color:#ccc;border:1px solid #555;border-radius:4px;font-size:12px;cursor:pointer">Upload</button><input type="file" id="xct-upload-input" accept=".json" style="display:none" onchange="_xctUploadFile(this)"><button id="xct-xbox-btn" onclick="_xctXboxAuth()" style="padding:4px 12px;background:#107c10;color:#fff;border:none;border-radius:4px;font-size:12px;cursor:pointer;display:none">⬢ Sign in with Xbox</button><button id="xct-auth-btn" onclick="_xctShowAuth()" style="padding:4px 12px;background:#107c10;color:#fff;border:none;border-radius:4px;font-size:12px;cursor:pointer">Log In</button></div>\n',
                default_tab="marketplace",
                extra_js=_AUTH_JS,
            )
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


# ---------------------------------------------------------------------------
# GET /data.js — Serve shared data as JS constants for the HTML template
# ---------------------------------------------------------------------------

_cached_data_js_gz = None
_cached_data_js_time = 0
DATA_JS_CACHE_TTL = 300  # 5 minutes

@app.route("/data.js")
def data_js():
    """Serve shared data as JS constants, matching write_data_js() format."""
    global _cached_data_js_gz, _cached_data_js_time
    import time as _time

    now = _time.time()
    if _cached_data_js_gz and (now - _cached_data_js_time) < DATA_JS_CACHE_TTL:
        if "gzip" in request.headers.get("Accept-Encoding", ""):
            return Response(_cached_data_js_gz, status=200, headers={
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Encoding": "gzip",
                "Cache-Control": "public, max-age=300",
            })
        return Response(gzip.decompress(_cached_data_js_gz), status=200, headers={
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
        })

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        def _load_shared(key, default=None):
            cur.execute("SELECT data FROM shared_data WHERE key = %s", (key,))
            row = cur.fetchone()
            if default is None:
                default = []
            return row["data"] if row else default

        rates = _load_shared("rates", {})
        flags = _load_shared("flags", {})
        gfwl = _load_shared("gfwl", [])
        gp = _load_shared("gp", [])

        import json as _json
        js = (
            "var LIB=[];\n"
            "var GP=" + _json.dumps(gp, ensure_ascii=False) + ";\n"
            "var PH=[];\n"
            "var MKT=[];\n"
            "var HISTORY=[];\n"
            "var DEFAULT_FLAGS=" + _json.dumps(flags, ensure_ascii=False) + ";\n"
            "var ACCOUNTS=[];\n"
            "var RATES=" + _json.dumps(rates, ensure_ascii=False) + ";\n"
            "var GC_FACTOR=0.81;\n"
            "var CDN_DB={};\n"
            "var GFWL=" + _json.dumps(gfwl, ensure_ascii=False) + ";\n"
            "var CDN_LEADERBOARD=[];\n"
            "var CDN_LB_STATS={};\n"
            "var CDN_SYNC_META={};\n"
            "var _MKT_TAGS={};\n"
            "var _MKT_LAST_SCAN=null;\n"
            "var CDN_SYNC_USER=\"\";\n"
            "var CDN_SYNC_LOG=[];\n"
            "var PURCHASES=[];\n"
        )

        js_bytes = js.encode("utf-8")
        _cached_data_js_gz = gzip.compress(js_bytes, compresslevel=6)
        del js_bytes
        _cached_data_js_time = now

        if "gzip" in request.headers.get("Accept-Encoding", ""):
            return Response(_cached_data_js_gz, status=200, headers={
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Encoding": "gzip",
                "Cache-Control": "public, max-age=300",
            })
        return Response(js, status=200, headers={
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
        })
    except Exception as e:
        return Response(f"// Error: {e}", status=500, content_type="application/javascript")
    finally:
        conn.close()
_TAB_SLUGS = {
    "summary", "library", "store", "marketplace", "subscriptions", "gamepass", "playhistory", "scanlog",
    "gamertags", "gfwl", "xvcdb", "imports", "purchases", "achievements", "admin",
}

# GP PIDs set (loaded from shared_data, refreshed every 5 minutes)
_gp_pids = set()
_gp_pids_time = 0
_GP_PIDS_TTL = 300

# Exchange rates cache (refreshed every 5 minutes)
_exchange_rates = {}
_exchange_rates_time = 0

def _refresh_gp_pids(cur):
    """Load Game Pass product IDs from shared_data into memory."""
    global _gp_pids, _gp_pids_time
    now = time.time()
    if now - _gp_pids_time < _GP_PIDS_TTL:
        return
    cur.execute("SELECT data FROM shared_data WHERE key = 'gp'")
    row = cur.fetchone()
    if row and isinstance(row["data"], list):
        _gp_pids = {item["productId"] for item in row["data"] if isinstance(item, dict) and "productId" in item}
    _gp_pids_time = now

def _refresh_exchange_rates(cur):
    """Load exchange rates from shared_data into memory."""
    global _exchange_rates, _exchange_rates_time
    now = time.time()
    if now - _exchange_rates_time < _GP_PIDS_TTL:
        return
    cur.execute("SELECT data FROM shared_data WHERE key = 'rates'")
    row = cur.fetchone()
    if row and isinstance(row["data"], dict):
        _exchange_rates = row["data"].get("rates", row["data"])
    _exchange_rates_time = now


def _legal_page(title, other_slug, other_label, body):
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{title} — XCT Live</title>'
        '<style>'
        '*{margin:0;padding:0;box-sizing:border-box}'
        'body{background:#111;color:#ccc;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.7}'
        '.header{background:#1a1a1a;border-bottom:1px solid #222;padding:14px 24px;display:flex;align-items:center;gap:10px}'
        '.header a{color:#ccc;text-decoration:none;font-size:14px}'
        '.header a:hover{color:#107c10}'
        '.header .logo{font-weight:600;font-size:16px;color:#fff}'
        '.container{max-width:720px;margin:0 auto;padding:32px 24px 48px}'
        'h1{color:#fff;font-size:22px;margin-bottom:6px}'
        '.updated{color:#666;font-size:12px;margin-bottom:28px}'
        'h2{color:#ddd;font-size:16px;margin:24px 0 8px;padding-top:16px;border-top:1px solid #222}'
        'p{margin-bottom:12px;font-size:14px}'
        'ul{margin:0 0 12px 20px;font-size:14px}'
        'li{margin-bottom:4px}'
        'a{color:#107c10}'
        '.footer{text-align:center;padding:24px;font-size:11px;color:#555;border-top:1px solid #222}'
        '.footer a{color:#666;text-decoration:none;margin:0 10px}'
        '</style></head><body>'
        f'<div class="header"><a href="/" class="logo">XCT Live</a>'
        f'<span style="color:#333">|</span><a href="/{other_slug}">{other_label}</a></div>'
        f'<div class="container">{body}</div>'
        '<div class="footer"><a href="/terms">Terms of Service</a>'
        '<span style="color:#333">|</span><a href="/privacy">Privacy Policy</a></div>'
        '</body></html>'
    )


@app.route("/terms")
def terms():
    body = (
        '<h1>Terms of Service</h1>'
        '<p class="updated">Last updated: March 7, 2026</p>'
        '<h2>1. Acceptance</h2>'
        '<p>By using XCT Live ("the Service"), operated at xct.live, you agree to these terms. If you do not agree, do not use the Service.</p>'
        '<h2>2. Description</h2>'
        '<p>XCT Live is a free community tool that lets you browse Xbox marketplace data, view Game Pass catalogs, and optionally upload your personal Xbox collection data for online viewing. The Service also provides CDN package tracking and community leaderboard features.</p>'
        '<h2>3. Accounts</h2>'
        '<p>You may create an account using a username and passphrase, or sign in with your Xbox/Microsoft account. You are responsible for keeping your credentials secure. Do not share your API key.</p>'
        '<h2>4. User Data</h2>'
        '<p>You may upload Xbox collection exports (library, play history, order history) to the Service. This data is stored on our servers and accessible only through your authenticated account. You retain ownership of your data and may request its deletion at any time.</p>'
        '<h2>5. Xbox Account Linking</h2>'
        '<p>When you link your Xbox account via Microsoft OAuth, the Service receives a limited authorization token to access your Xbox profile information (gamertag, avatar, XUID) and achievement data. You can disconnect your Xbox account at any time, which revokes the stored tokens.</p>'
        '<h2>6. Acceptable Use</h2>'
        '<p>You agree not to:</p>'
        '<ul>'
        '<li>Abuse, disrupt, or overload the Service</li>'
        '<li>Attempt to access other users\' data or accounts</li>'
        '<li>Use automated tools to scrape or bulk-download data from the Service beyond normal usage</li>'
        '<li>Upload false, misleading, or malicious data</li>'
        '</ul>'
        '<h2>7. CDN Sync &amp; Leaderboard</h2>'
        '<p>CDN Sync is a voluntary community feature. Data you contribute to the shared CDN database is visible to other contributors. Points and leaderboard standings are for community recognition only and hold no monetary value.</p>'
        '<h2>8. No Warranty</h2>'
        '<p>The Service is provided "as is" without warranty of any kind. We do not guarantee uptime, data accuracy, or availability. Xbox marketplace data, prices, and Game Pass listings are sourced from Microsoft APIs and may be outdated or incorrect.</p>'
        '<h2>9. Limitation of Liability</h2>'
        '<p>XCT Live and its operators are not liable for any damages arising from your use of the Service, including but not limited to data loss, account issues, or reliance on displayed pricing or availability information.</p>'
        '<h2>10. Third-Party Services</h2>'
        '<p>The Service interacts with Microsoft/Xbox APIs. Your use of Xbox features is also subject to the '
        '<a href="https://www.xbox.com/legal/livetou" target="_blank" rel="noopener">Microsoft Services Agreement</a> and '
        '<a href="https://privacy.microsoft.com/privacystatement" target="_blank" rel="noopener">Microsoft Privacy Statement</a>.</p>'
        '<h2>11. Termination</h2>'
        '<p>We may suspend or terminate accounts that violate these terms or abuse the Service. You may stop using the Service and request account deletion at any time.</p>'
        '<h2>12. Changes</h2>'
        '<p>We may update these terms at any time. Continued use of the Service after changes constitutes acceptance of the updated terms.</p>'
        '<h2>13. Contact</h2>'
        '<p>For questions about these terms, reach out via the XCT community channels or GitHub repository.</p>'
    )
    return Response(_legal_page("Terms of Service", "privacy", "Privacy Policy", body),
                    content_type="text/html; charset=utf-8")


@app.route("/privacy")
def privacy():
    body = (
        '<h1>Privacy Policy</h1>'
        '<p class="updated">Last updated: March 7, 2026</p>'
        '<h2>1. Overview</h2>'
        '<p>XCT Live ("the Service") respects your privacy. This policy explains what data we collect, how we use it, and your rights regarding that data.</p>'
        '<h2>2. Data We Collect</h2>'
        '<p><strong>Account Information:</strong> When you register, we store your chosen username and a hashed version of your passphrase. We generate a unique API key for authentication. We do not collect your email address.</p>'
        '<p><strong>Xbox Account Data:</strong> If you link your Xbox account, we store your gamertag, Xbox User ID (XUID), avatar URL, and an encrypted Microsoft refresh token. This token is used to access your Xbox achievement data and profile information.</p>'
        '<p><strong>Collection Data:</strong> If you upload your Xbox collection export, we store your library, play history, scan history, account list, and order/purchase history. This data is only accessible through your authenticated API key.</p>'
        '<p><strong>CDN Sync Data:</strong> If you participate in CDN Sync, your contributed CDN package entries are stored in the shared database with your contributor username attached.</p>'
        '<p><strong>Server Logs:</strong> Standard web server logs may include IP addresses, request timestamps, and user agents. These are used for security monitoring and are not shared with third parties.</p>'
        '<h2>3. How We Use Your Data</h2>'
        '<ul>'
        '<li>Display your collection, achievements, and purchase history in the web interface</li>'
        '<li>Maintain CDN Sync leaderboard standings</li>'
        '<li>Authenticate your sessions via API key</li>'
        '<li>Monitor and prevent abuse of the Service</li>'
        '</ul>'
        '<h2>4. Data Sharing</h2>'
        '<p>We do not sell, rent, or share your personal data with third parties. Your collection data is private to your account. CDN Sync contributions are shared with other CDN Sync participants by design.</p>'
        '<h2>5. Data Storage &amp; Security</h2>'
        '<p>Data is stored on secured servers. Xbox refresh tokens are encrypted at rest using Fernet symmetric encryption. Passphrases are hashed before storage. While we take reasonable measures to protect your data, no system is completely secure.</p>'
        '<h2>6. Microsoft / Xbox Data</h2>'
        '<p>When you sign in with Xbox, the Service accesses your data through Microsoft\'s OAuth2 authorization flow. We only request the scopes necessary for the features you use. Your Microsoft password is never transmitted to or stored by the Service. You can revoke access at any time by disconnecting your Xbox account in the Service or removing the app from your '
        '<a href="https://account.live.com/consent/Manage" target="_blank" rel="noopener">Microsoft account permissions</a>.</p>'
        '<h2>7. Cookies &amp; Local Storage</h2>'
        '<p>The Service uses browser localStorage to store your API key, username, gamertag, and display preferences. No tracking cookies or third-party analytics are used.</p>'
        '<h2>8. Data Retention</h2>'
        '<p>Your data is retained as long as your account is active. If you request account deletion, all associated data (collection, tokens, profile) will be removed from our servers.</p>'
        '<h2>9. Your Rights</h2>'
        '<p>You have the right to:</p>'
        '<ul>'
        '<li>Access your stored data through the API</li>'
        '<li>Disconnect your Xbox account at any time</li>'
        '<li>Request deletion of your account and all associated data</li>'
        '<li>Export your collection data</li>'
        '</ul>'
        '<h2>10. Children\'s Privacy</h2>'
        '<p>The Service is not directed at children under 13. We do not knowingly collect data from children under 13.</p>'
        '<h2>11. Changes</h2>'
        '<p>We may update this policy at any time. Material changes will be noted by updating the "Last updated" date at the top of this page.</p>'
        '<h2>12. Contact</h2>'
        '<p>For privacy-related questions or data deletion requests, reach out via the XCT community channels or GitHub repository.</p>'
    )
    return Response(_legal_page("Privacy Policy", "terms", "Terms of Service", body),
                    content_type="text/html; charset=utf-8")


@app.route("/xctbanner.jpg")
def banner_image():
    """Serve the summary tab banner image."""
    img_path = os.path.join(os.path.dirname(__file__), "xctbanner.jpg")
    if not os.path.isfile(img_path):
        return Response("Not found", status=404)
    with open(img_path, "rb") as f:
        data = f.read()
    return Response(data, status=200, headers={
        "Content-Type": "image/jpeg",
        "Cache-Control": "public, max-age=86400",
    })


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
# Store API — paginated, server-filtered marketplace endpoints
# ---------------------------------------------------------------------------

# Sort mapping: URL param → (SQL ORDER BY, needs US price join)
_STORE_SORT_MAP = {
    "relDesc":      ("p.release_date DESC NULLS LAST, p.title ASC", False),
    "relAsc":       ("p.release_date ASC NULLS LAST, p.title ASC", False),
    "name":         ("p.title ASC", False),
    "priceAsc":     ("pr_us.msrp ASC NULLS LAST, p.title ASC", True),
    "priceDesc":    ("pr_us.msrp DESC NULLS LAST, p.title ASC", True),
    "bestAsc":      ("p.best_gc_usd ASC NULLS LAST, p.title ASC", False),
    "bestDesc":     ("p.best_gc_usd DESC NULLS LAST, p.title ASC", False),
    "ratingDesc":   ("p.average_rating DESC, p.title ASC", False),
    "ratingCntDesc":("p.rating_count DESC, p.title ASC", False),
    "platCntDesc":  ("array_length(p.platforms, 1) DESC NULLS LAST, p.title ASC", False),
    "pub":          ("p.publisher ASC, p.title ASC", False),
    "dev":          ("p.developer ASC, p.title ASC", False),
    "cat":          ("p.category ASC, p.title ASC", False),
}


@app.route("/api/v1/store/filters")
def store_filters():
    """Dropdown options with global counts. Cached 5 min server-side."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check in-memory cache
        now = time.time()
        cache_key = "store_filters"
        if cache_key in _shared_cache:
            etag, gz_bytes, ts = _shared_cache[cache_key]
            if now - ts < SHARED_CACHE_TTL:
                client_etag = request.headers.get("If-None-Match", "")
                if client_etag == etag:
                    return Response(status=304, headers={
                        "ETag": etag, "Cache-Control": "public, max-age=300"})
                return Response(gz_bytes, status=200, headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                    "ETag": etag,
                    "Cache-Control": "public, max-age=300"})

        # Channels
        cur.execute("""
            SELECT mc.channel AS value, COUNT(DISTINCT mc.product_id) AS count
            FROM marketplace_channels mc
            JOIN marketplace_products p ON p.product_id = mc.product_id AND p.title != p.product_id
            GROUP BY mc.channel ORDER BY count DESC
        """)
        channels = [dict(r) for r in cur.fetchall()]

        # Types (product_kind → display name)
        cur.execute("""
            SELECT CASE WHEN product_kind = 'Durable' THEN 'DLC' ELSE product_kind END AS value,
                   COUNT(*) AS count
            FROM marketplace_products WHERE title != product_id AND product_kind != ''
            GROUP BY value ORDER BY count DESC
        """)
        types = [dict(r) for r in cur.fetchall()]

        # Platforms (UNNEST array)
        cur.execute("""
            SELECT u AS value, COUNT(*) AS count
            FROM marketplace_products, UNNEST(platforms) AS u
            WHERE title != product_id
            GROUP BY u ORDER BY count DESC
        """)
        platforms = [dict(r) for r in cur.fetchall()]

        # Categories
        cur.execute("""
            SELECT category AS value, COUNT(*) AS count
            FROM marketplace_products WHERE title != product_id AND category != ''
            GROUP BY category ORDER BY count DESC
        """)
        categories = [dict(r) for r in cur.fetchall()]

        # Publishers
        cur.execute("""
            SELECT publisher AS value, COUNT(*) AS count
            FROM marketplace_products WHERE title != product_id AND publisher != ''
            GROUP BY publisher ORDER BY count DESC
        """)
        publishers = [dict(r) for r in cur.fetchall()]

        # Developers
        cur.execute("""
            SELECT developer AS value, COUNT(*) AS count
            FROM marketplace_products WHERE title != product_id AND developer != ''
            GROUP BY developer ORDER BY count DESC
        """)
        developers = [dict(r) for r in cur.fetchall()]

        # Subscriptions (with total value per tier from regional prices)
        try:
            cur.execute("""
                SELECT ms.tier AS value,
                       COUNT(DISTINCT ms.product_id) AS count,
                       COALESCE(SUM(rp.msrp), 0) AS total_value
                FROM marketplace_subscriptions ms
                JOIN marketplace_products p ON p.product_id = ms.product_id AND p.title != p.product_id
                LEFT JOIN marketplace_prices rp ON rp.product_id = ms.product_id AND rp.market = 'US'
                GROUP BY ms.tier ORDER BY count DESC
            """)
            subscriptions = [dict(r) for r in cur.fetchall()]
            for s in subscriptions:
                s["total_value"] = float(s.get("total_value", 0) or 0)
        except Exception:
            subscriptions = []
            conn.rollback()

        # Total
        cur.execute("SELECT COUNT(*) AS cnt FROM marketplace_products WHERE title != product_id")
        total = cur.fetchone()["cnt"]

        # Last scan
        last_scan = None
        cur.execute("""
            SELECT completed_at, scan_type, products_total, products_new
            FROM marketplace_scans WHERE status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        """)
        scan_row = cur.fetchone()
        if scan_row:
            last_scan = {
                "completedAt": scan_row["completed_at"].isoformat() if scan_row["completed_at"] else None,
                "scanType": scan_row["scan_type"],
                "productsTotal": scan_row["products_total"],
                "productsNew": scan_row["products_new"],
            }

        result = {
            "channels": channels, "types": types, "platforms": platforms,
            "categories": categories, "publishers": publishers,
            "developers": developers, "subscriptions": subscriptions,
            "totalProducts": total, "lastScan": last_scan,
        }
        return _gzip_json_response(result, cache_key=cache_key)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/store/products")
def store_products():
    """Core paginated, filtered, sorted product listing."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Refresh in-memory caches
        _refresh_gp_pids(cur)
        _refresh_exchange_rates(cur)

        # Parse pagination
        page = max(0, request.args.get("page", 0, type=int))
        per_page = min(max(1, request.args.get("per_page", 50, type=int)), 200)

        # Parse filters
        q = (request.args.get("q") or "").strip()
        sort_key = request.args.get("sort", "relDesc")
        ch_raw = request.args.get("ch", "")
        type_raw = request.args.get("type", "")
        plat_raw = request.args.get("plat", "")
        price_raw = request.args.get("price", "")
        cat_raw = request.args.get("cat", "")
        subs_raw = request.args.get("subs", "")
        mp_raw = request.args.get("mp", "")
        pub_raw = request.args.get("pub", "")
        dev_raw = request.args.get("dev", "")
        own_raw = request.args.get("own", "")
        rel_raw = request.args.get("rel", "")
        bundle_raw = request.args.get("bundle", "")
        xcloud = request.args.get("xcloud", "")
        trial = request.args.get("trial", "")
        ach = request.args.get("ach", "")
        do_group = request.args.get("group", "")
        hide_owned_ed = request.args.get("hoe", "")
        regions_raw = request.args.get("regions", "")
        nosub = request.args.get("nosub", "")
        nodemo = request.args.get("nodemo", "")
        noplayed = request.args.get("noplayed", "")
        noach = request.args.get("noach", "")

        # Sort
        sort_sql, needs_us_price = _STORE_SORT_MAP.get(sort_key, _STORE_SORT_MAP["relDesc"])

        # Build WHERE clauses
        wheres = ["p.title != p.product_id"]
        params = {}

        # Always join US prices for display
        join_us = True

        if q:
            wheres.append("p.title ILIKE %(q)s")
            params["q"] = f"%{q}%"

        # Channel filter
        if ch_raw:
            ch_list = [c.strip() for c in ch_raw.split(",") if c.strip()]
            if ch_list:
                wheres.append(
                    "EXISTS (SELECT 1 FROM marketplace_channels mc "
                    "WHERE mc.product_id = p.product_id AND mc.channel = ANY(%(channels)s))")
                params["channels"] = ch_list

        # Type filter (map DLC → Durable for DB)
        if type_raw:
            t_list = [t.strip() for t in type_raw.split(",") if t.strip()]
            db_types = ["Durable" if t == "DLC" else t for t in t_list]
            if db_types:
                wheres.append("p.product_kind = ANY(%(types)s)")
                params["types"] = db_types

        # Platform filter (GIN array overlap)
        if plat_raw:
            p_list = [p.strip() for p in plat_raw.split(",") if p.strip()]
            if p_list:
                wheres.append("p.platforms && %(platforms)s")
                params["platforms"] = p_list

        # Price filter
        if price_raw:
            price_vals = [v.strip() for v in price_raw.split(",") if v.strip()]
            price_conds = []
            for pv in price_vals:
                if pv == "free":
                    price_conds.append("(pr_us.msrp IS NOT NULL AND pr_us.msrp = 0)")
                elif pv == "under10":
                    price_conds.append("(pr_us.msrp > 0 AND pr_us.msrp < 10)")
                elif pv == "under20":
                    price_conds.append("(pr_us.msrp > 0 AND pr_us.msrp < 20)")
                elif pv == "under40":
                    price_conds.append("(pr_us.msrp > 0 AND pr_us.msrp < 40)")
                elif pv == "over40":
                    price_conds.append("(pr_us.msrp >= 40)")
                elif pv == "sale":
                    price_conds.append(
                        "EXISTS (SELECT 1 FROM marketplace_prices sp "
                        "WHERE sp.product_id = p.product_id "
                        "AND sp.sale_price > 0 AND sp.sale_price < sp.msrp)")
            if price_conds:
                wheres.append("(" + " OR ".join(price_conds) + ")")

        # Category filter
        if cat_raw:
            c_list = [c.strip() for c in cat_raw.split(",") if c.strip()]
            if c_list:
                wheres.append("p.category = ANY(%(categories)s)")
                params["categories"] = c_list

        # Subscriptions filter — accepts tier names (e.g. "Game Pass PC")
        # or legacy short codes ("gp", "ea", "none")
        if subs_raw:
            s_list = [s.strip() for s in subs_raw.split(",") if s.strip()]
            subs_conds = []
            # Collect actual tier names for DB query
            tier_names = [s for s in s_list if s not in ("gp", "ea", "none")]
            # Legacy short codes
            if "gp" in s_list:
                if _gp_pids:
                    subs_conds.append("p.product_id = ANY(%(gp_pids)s)")
                    params["gp_pids"] = list(_gp_pids)
            if "ea" in s_list:
                tier_names.append("EA Play")
            if tier_names:
                subs_conds.append(
                    "EXISTS (SELECT 1 FROM marketplace_subscriptions ms "
                    "WHERE ms.product_id = p.product_id AND ms.tier = ANY(%(sub_tiers)s))")
                params["sub_tiers"] = tier_names
            if "none" in s_list:
                none_cond = (
                    "NOT EXISTS (SELECT 1 FROM marketplace_subscriptions ms2 "
                    "WHERE ms2.product_id = p.product_id)")
                if _gp_pids:
                    none_cond = "(" + none_cond + " AND NOT (p.product_id = ANY(%(gp_pids_none)s)))"
                    params["gp_pids_none"] = list(_gp_pids)
                subs_conds.append("(" + none_cond + ")")
            if subs_conds:
                wheres.append("(" + " OR ".join(subs_conds) + ")")

        # Multiplayer filter
        if mp_raw:
            mp_list = [m.strip() for m in mp_raw.split(",") if m.strip()]
            cap_map = {
                "online": ["XblOnlineMultiplayer", "OnlineMultiplayer"],
                "local": ["XblLocalMultiplayer", "LocalMultiplayer"],
                "coop": ["XblOnlineCoop", "OnlineCoop"],
                "localcoop": ["XblLocalCoop", "LocalCoop"],
                "crossgen": ["XblCrossGenMultiplayer", "CrossGen"],
            }
            all_caps = []
            for m in mp_list:
                all_caps.extend(cap_map.get(m, []))
            if all_caps:
                wheres.append("p.capabilities && %(mp_caps)s")
                params["mp_caps"] = all_caps

        # Publisher / Developer
        if pub_raw:
            pub_list = [p.strip() for p in pub_raw.split(",") if p.strip()]
            if pub_list:
                wheres.append("p.publisher = ANY(%(publishers)s)")
                params["publishers"] = pub_list
        if dev_raw:
            dev_list = [d.strip() for d in dev_raw.split(",") if d.strip()]
            if dev_list:
                wheres.append("p.developer = ANY(%(developers)s)")
                params["developers"] = dev_list

        # Ownership filter (requires auth)
        owned_pids = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)
                if contributor:
                    cur.execute(
                        "SELECT lib FROM user_collections WHERE contributor_id = %s",
                        (contributor["id"],))
                    uc_row = cur.fetchone()
                    if uc_row and uc_row["lib"]:
                        owned_pids = {item["productId"] for item in uc_row["lib"]
                                      if isinstance(item, dict) and "productId" in item}

        if own_raw:
            o_list = [o.strip() for o in own_raw.split(",") if o.strip()]
            if owned_pids is not None:
                own_conds = []
                if "owned" in o_list:
                    own_conds.append("p.product_id = ANY(%(owned_pids)s)")
                    params["owned_pids"] = list(owned_pids)
                if "notowned" in o_list:
                    own_conds.append("NOT (p.product_id = ANY(%(notowned_pids)s))")
                    params["notowned_pids"] = list(owned_pids)
                if own_conds:
                    wheres.append("(" + " OR ".join(own_conds) + ")")

        # Hide owned editions — exclude unowned products sharing a title ID with any owned product
        if hide_owned_ed == "1" and owned_pids:
            # Get title IDs of owned products
            cur.execute(
                "SELECT DISTINCT xbox_title_id FROM marketplace_products "
                "WHERE product_id = ANY(%s) AND xbox_title_id != ''",
                (list(owned_pids),))
            owned_tids = [row["xbox_title_id"] for row in cur.fetchall()]
            if owned_tids:
                wheres.append(
                    "NOT (p.xbox_title_id = ANY(%(owned_tids)s) "
                    "AND NOT p.product_id = ANY(%(hoe_owned_pids)s))")
                params["owned_tids"] = owned_tids
                params["hoe_owned_pids"] = list(owned_pids)

        # Release status
        if rel_raw:
            r_list = [r.strip() for r in rel_raw.split(",") if r.strip()]
            rel_conds = []
            if "released" in r_list:
                rel_conds.append(
                    "(p.release_date IS NOT NULL AND p.release_date <= CURRENT_DATE "
                    "AND EXTRACT(YEAR FROM p.release_date) < 2100)")
            if "priced" in r_list:
                rel_conds.append(
                    "(p.release_date > CURRENT_DATE AND EXTRACT(YEAR FROM p.release_date) < 2100 "
                    "AND EXISTS (SELECT 1 FROM marketplace_prices rp "
                    "WHERE rp.product_id = p.product_id AND rp.msrp > 0))")
            if "noPrice" in r_list:
                rel_conds.append(
                    "(p.release_date > CURRENT_DATE AND EXTRACT(YEAR FROM p.release_date) < 2100 "
                    "AND NOT EXISTS (SELECT 1 FROM marketplace_prices rp "
                    "WHERE rp.product_id = p.product_id AND rp.msrp > 0))")
            if rel_conds:
                wheres.append("(" + " OR ".join(rel_conds) + ")")

        # Bundle filter
        if bundle_raw:
            b_list = [b.strip() for b in bundle_raw.split(",") if b.strip()]
            bundle_conds = []
            if "bundles" in b_list:
                bundle_conds.append(
                    "(p.is_bundle = TRUE OR EXISTS (SELECT 1 FROM marketplace_tags mt "
                    "WHERE mt.product_id = p.product_id AND mt.tag_type = 'is_bundle_override' "
                    "AND mt.tag_value = 'true'))")
            if "notbundle" in b_list:
                bundle_conds.append(
                    "(p.is_bundle = FALSE AND NOT EXISTS (SELECT 1 FROM marketplace_tags mt "
                    "WHERE mt.product_id = p.product_id AND mt.tag_type = 'is_bundle_override' "
                    "AND mt.tag_value = 'true'))")
            if bundle_conds:
                wheres.append("(" + " OR ".join(bundle_conds) + ")")

        # Boolean checkboxes
        if xcloud == "1":
            wheres.append("p.xcloud_streamable = TRUE")
        if trial == "1":
            wheres.append("p.has_trial_sku = TRUE")
        if ach == "1":
            wheres.append("p.has_achievements = TRUE")

        # Hide all subscription games
        if nosub == "1":
            wheres.append(
                "NOT EXISTS (SELECT 1 FROM marketplace_subscriptions ms "
                "WHERE ms.product_id = p.product_id)")

        # Hide demos (titles ending with "Demo" or containing "(Demo)")
        if nodemo == "1":
            wheres.append(
                "p.title !~* '\\mDemo$' AND p.title NOT ILIKE '%%(Demo)%%'")

        # Hide played games (cross-reference user's play history)
        if noplayed == "1" and auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)
                if contributor:
                    cur.execute(
                        "SELECT play_history FROM user_collections "
                        "WHERE contributor_id = %s", (contributor["id"],))
                    uc_row = cur.fetchone()
                    if uc_row and uc_row["play_history"]:
                        played_pids = [
                            item["productId"]
                            for item in uc_row["play_history"]
                            if isinstance(item, dict) and item.get("productId")
                            and item.get("lastTimePlayed")]
                        if played_pids:
                            wheres.append(
                                "p.product_id != ALL(%(played_pids)s)")
                            params["played_pids"] = played_pids

        # Hide games user has achievements in
        if noach == "1" and auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)
                if contributor:
                    cur.execute(
                        "SELECT xbox_title_id FROM xbox_achievement_summaries "
                        "WHERE contributor_id = %s AND current_achievements > 0",
                        (contributor["id"],))
                    ach_tids = [row["xbox_title_id"] for row in cur.fetchall()]
                    if ach_tids:
                        wheres.append(
                            "(p.xbox_title_id = '' OR p.xbox_title_id != ALL(%(ach_tids)s))")
                        params["ach_tids"] = ach_tids

        # Region availability filter
        if regions_raw and regions_raw in ("myregions", "notmy"):
            # Get user's myRegions from their settings
            user_regions = []
            if owned_pids is not None and auth_header.startswith("Bearer "):
                api_key = auth_header[7:].strip()
                contributor = _get_contributor(cur, api_key)
                if contributor and contributor.get("settings"):
                    user_regions = contributor["settings"].get("myRegions", [])
            if user_regions:
                if regions_raw == "myregions":
                    wheres.append(
                        "EXISTS (SELECT 1 FROM marketplace_prices rpr "
                        "WHERE rpr.product_id = p.product_id AND rpr.market = ANY(%(user_regions)s))")
                    params["user_regions"] = user_regions
                elif regions_raw == "notmy":
                    wheres.append(
                        "NOT EXISTS (SELECT 1 FROM marketplace_prices rpr "
                        "WHERE rpr.product_id = p.product_id AND rpr.market = ANY(%(notmy_regions)s))")
                    params["notmy_regions"] = user_regions

        where_sql = " AND ".join(wheres)

        # Build main query
        join_clause = ""
        if join_us:
            join_clause = (
                "LEFT JOIN marketplace_prices pr_us "
                "ON pr_us.product_id = p.product_id AND pr_us.market = 'US'")

        # Edition grouping
        if do_group == "1":
            # Use window function to pick primary per xbox_title_id group
            inner_sql = f"""
                SELECT p.product_id, p.title, p.publisher, p.developer, p.category,
                       p.release_date, p.platforms, p.product_kind, p.xbox_title_id,
                       p.is_bundle, p.is_ea_play, p.xcloud_streamable,
                       p.has_trial_sku, p.has_achievements,
                       p.image_box_art, p.image_tile, p.image_hero,
                       p.average_rating, p.rating_count, p.best_gc_usd,
                       p.short_description, p.capabilities,
                       pr_us.msrp AS price_usd,
                       CASE WHEN pr_us.sale_price > 0 AND pr_us.sale_price < pr_us.msrp
                            THEN pr_us.sale_price ELSE NULL END AS current_price_usd,
                       ROW_NUMBER() OVER (
                           PARTITION BY CASE WHEN p.xbox_title_id != '' THEN p.xbox_title_id
                                             ELSE p.product_id END
                           ORDER BY pr_us.msrp DESC NULLS LAST, p.title ASC
                       ) AS rn,
                       COUNT(*) OVER (
                           PARTITION BY CASE WHEN p.xbox_title_id != '' THEN p.xbox_title_id
                                             ELSE p.product_id END
                       ) - 1 AS alt_count,
                       COUNT(*) OVER () AS _total
                FROM marketplace_products p
                {join_clause}
                WHERE {where_sql}
            """
            sql = f"""
                SELECT * FROM ({inner_sql}) sub
                WHERE sub.rn = 1
                ORDER BY {sort_sql.replace('p.', 'sub.').replace('pr_us.msrp', 'sub.price_usd')}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            # Also need total of grouped results
            count_sql = f"""
                SELECT COUNT(*) AS cnt FROM (
                    SELECT DISTINCT ON (
                        CASE WHEN p.xbox_title_id != '' THEN p.xbox_title_id
                             ELSE p.product_id END
                    ) p.product_id
                    FROM marketplace_products p
                    {join_clause}
                    WHERE {where_sql}
                    ORDER BY CASE WHEN p.xbox_title_id != '' THEN p.xbox_title_id
                                  ELSE p.product_id END,
                             pr_us.msrp DESC NULLS LAST
                ) grouped
            """
        else:
            sql = f"""
                SELECT p.product_id, p.title, p.publisher, p.developer, p.category,
                       p.release_date, p.platforms, p.product_kind, p.xbox_title_id,
                       p.is_bundle, p.is_ea_play, p.xcloud_streamable,
                       p.has_trial_sku, p.has_achievements,
                       p.image_box_art, p.image_tile, p.image_hero,
                       p.average_rating, p.rating_count, p.best_gc_usd,
                       p.short_description, p.capabilities,
                       pr_us.msrp AS price_usd,
                       CASE WHEN pr_us.sale_price > 0 AND pr_us.sale_price < pr_us.msrp
                            THEN pr_us.sale_price ELSE NULL END AS current_price_usd,
                       COUNT(*) OVER () AS _total
                FROM marketplace_products p
                {join_clause}
                WHERE {where_sql}
                ORDER BY {sort_sql}
                LIMIT %(limit)s OFFSET %(offset)s
            """

        params["limit"] = per_page
        params["offset"] = page * per_page

        cur.execute(sql, params)
        rows = cur.fetchall()

        total = rows[0]["_total"] if rows else 0
        if do_group == "1" and rows:
            # For grouped, _total is pre-grouping; recalculate
            cur.execute(count_sql, params)
            total = cur.fetchone()["cnt"]

        product_ids = [r["product_id"] for r in rows]

        # Fetch prices for these products
        prices_map = {}
        if product_ids:
            cur.execute(
                "SELECT product_id, market, currency, msrp, sale_price "
                "FROM marketplace_prices WHERE product_id = ANY(%(pids)s)",
                {"pids": product_ids})
            for pr in cur.fetchall():
                pid = pr["product_id"]
                if pid not in prices_map:
                    prices_map[pid] = {}
                prices_map[pid][pr["market"]] = {
                    "msrp": pr["msrp"],
                    "salePrice": pr["sale_price"],
                    "currency": pr["currency"],
                }

        # Fetch channels for these products
        channels_map = {}
        if product_ids:
            cur.execute(
                "SELECT product_id, channel FROM marketplace_channels "
                "WHERE product_id = ANY(%(pids)s)",
                {"pids": product_ids})
            for ch in cur.fetchall():
                pid = ch["product_id"]
                if pid not in channels_map:
                    channels_map[pid] = []
                channels_map[pid].append(ch["channel"])

        # Fetch bundle override tags
        tags_map = {}
        if product_ids:
            cur.execute(
                "SELECT product_id, tag_type, tag_value FROM marketplace_tags "
                "WHERE product_id = ANY(%(pids)s)",
                {"pids": product_ids})
            for tg in cur.fetchall():
                pid = tg["product_id"]
                if pid not in tags_map:
                    tags_map[pid] = {}
                tags_map[pid][tg["tag_type"]] = tg["tag_value"]

        # Compute best region for each product
        def _compute_best_region(rp):
            if not rp or not _exchange_rates:
                return None
            best = None
            for mkt_code, pr_data in rp.items():
                base = pr_data.get("msrp", 0) or 0
                sp = pr_data.get("salePrice", 0) or 0
                p = sp if 0 < sp < base else base
                rate = _exchange_rates.get(pr_data.get("currency", ""), 1)
                if rate <= 0:
                    rate = 1
                usd = (p / rate) * 0.81
                if usd > 0 and (best is None or usd < best["usd"]):
                    best = {"mkt": mkt_code, "usd": round(usd, 2)}
            return best

        # Assemble response
        products = []
        for r in rows:
            pid = r["product_id"]
            regional = prices_map.get(pid, {})
            is_on_sale = False
            for _m, _pr in regional.items():
                if _pr["salePrice"] > 0 and _pr["salePrice"] < _pr["msrp"]:
                    is_on_sale = True
                    break
            if not is_on_sale and r["current_price_usd"]:
                is_on_sale = True

            tag = tags_map.get(pid, {})
            is_bundle = r["is_bundle"]
            if tag.get("is_bundle_override") == "true":
                is_bundle = True
            elif tag.get("is_bundle_override") == "false":
                is_bundle = False

            img_box = r["image_box_art"] or r["image_tile"] or ""
            img_hero = r["image_hero"] or ""

            best = _compute_best_region(regional)

            item = {
                "productId": pid,
                "title": r["title"],
                "publisher": r["publisher"],
                "developer": r["developer"],
                "category": r["category"],
                "releaseDate": r["release_date"].isoformat() if r["release_date"] else "",
                "platforms": r["platforms"] or [],
                "productKind": r["product_kind"],
                "xboxTitleId": r["xbox_title_id"],
                "isBundle": is_bundle,
                "isEAPlay": r["is_ea_play"],
                "xCloudStreamable": r["xcloud_streamable"],
                "hasTrialSku": r["has_trial_sku"],
                "hasAchievements": r["has_achievements"],
                "imageBoxArt": (img_box + "?w=330&h=186") if img_box else "",
                "imageHero": (img_hero + "?w=330&h=186") if img_hero else "",
                "averageRating": r["average_rating"],
                "ratingCount": r["rating_count"],
                "channels": channels_map.get(pid, []),
                "priceUSD": r["price_usd"] or 0,
                "currentPriceUSD": r["current_price_usd"] or 0,
                "bestRegion": best,
                "regionalPrices": regional,
                "owned": pid in owned_pids if owned_pids is not None else False,
                "onGP": pid in _gp_pids,
                "_onSale": is_on_sale,
                "capabilities": r["capabilities"] or [],
            }
            if do_group == "1":
                item["altCount"] = r.get("alt_count", 0)
            products.append(item)

        total_pages = max(1, -(-total // per_page))  # ceil division
        result = {
            "products": products,
            "total": total,
            "page": page,
            "perPage": per_page,
            "totalPages": total_pages,
        }
        return _gzip_json_response(result)
    except Exception as e:
        log.exception("store_products error")
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/store/product/<product_id>")
def store_product_detail(product_id):
    """Single product detail for modal — PK lookup + prices + channels."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        _refresh_gp_pids(cur)
        _refresh_exchange_rates(cur)

        cur.execute("""
            SELECT product_id, title, publisher, developer, category, release_date,
                   platforms, product_kind, xbox_title_id, is_bundle, is_ea_play,
                   xcloud_streamable, capabilities, image_box_art, image_tile,
                   image_hero, short_description, average_rating, rating_count,
                   has_trial_sku, has_achievements
            FROM marketplace_products WHERE product_id = %s
        """, (product_id,))
        p = cur.fetchone()
        if not p:
            return jsonify(error="Product not found"), 404

        # Prices
        cur.execute(
            "SELECT market, currency, msrp, sale_price FROM marketplace_prices "
            "WHERE product_id = %s", (product_id,))
        regional = {}
        for pr in cur.fetchall():
            regional[pr["market"]] = {
                "msrp": pr["msrp"],
                "salePrice": pr["sale_price"],
                "currency": pr["currency"],
            }

        # Channels
        cur.execute(
            "SELECT channel FROM marketplace_channels WHERE product_id = %s",
            (product_id,))
        channels = [r["channel"] for r in cur.fetchall()]

        # Subscriptions
        cur.execute(
            "SELECT tier FROM marketplace_subscriptions WHERE product_id = %s",
            (product_id,))
        subscriptions = [r["tier"] for r in cur.fetchall()]

        # Tags
        cur.execute(
            "SELECT tag_type, tag_value FROM marketplace_tags WHERE product_id = %s",
            (product_id,))
        tags = {r["tag_type"]: r["tag_value"] for r in cur.fetchall()}

        is_bundle = p["is_bundle"]
        if tags.get("is_bundle_override") == "true":
            is_bundle = True
        elif tags.get("is_bundle_override") == "false":
            is_bundle = False

        us_price = regional.get("US", {})
        price_usd = us_price.get("msrp", 0) or 0
        current_price = 0
        sp = us_price.get("salePrice", 0) or 0
        if sp > 0 and sp < price_usd:
            current_price = sp

        is_on_sale = False
        for _m, _pr in regional.items():
            if _pr["salePrice"] > 0 and _pr["salePrice"] < _pr["msrp"]:
                is_on_sale = True
                break

        # Ownership check (optional auth)
        owned = False
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)
                if contributor:
                    cur.execute(
                        "SELECT lib FROM user_collections WHERE contributor_id = %s",
                        (contributor["id"],))
                    uc_row = cur.fetchone()
                    if uc_row and uc_row["lib"]:
                        owned = any(
                            item.get("productId") == product_id
                            for item in uc_row["lib"]
                            if isinstance(item, dict))

        img_box = p["image_box_art"] or p["image_tile"] or ""
        img_hero = p["image_hero"] or ""

        result = {
            "productId": p["product_id"],
            "title": p["title"],
            "publisher": p["publisher"],
            "developer": p["developer"],
            "category": p["category"],
            "releaseDate": p["release_date"].isoformat() if p["release_date"] else "",
            "platforms": p["platforms"] or [],
            "productKind": p["product_kind"],
            "xboxTitleId": p["xbox_title_id"],
            "isBundle": is_bundle,
            "isEAPlay": p["is_ea_play"],
            "xCloudStreamable": p["xcloud_streamable"],
            "hasTrialSku": p["has_trial_sku"],
            "hasAchievements": p["has_achievements"],
            "imageBoxArt": img_box,
            "imageHero": img_hero,
            "shortDescription": p["short_description"],
            "averageRating": p["average_rating"],
            "ratingCount": p["rating_count"],
            "channels": channels,
            "priceUSD": price_usd,
            "currentPriceUSD": current_price,
            "regionalPrices": regional,
            "owned": owned,
            "onGP": p["product_id"] in _gp_pids,
            "_onSale": is_on_sale,
            "capabilities": p["capabilities"] or [],
            "subscriptions": subscriptions,
        }
        return _gzip_json_response(result)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/store/editions/<xbox_title_id>")
def store_editions(xbox_title_id):
    """Alternate editions sharing the same xbox_title_id."""
    exclude = request.args.get("exclude", "")
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        _refresh_gp_pids(cur)

        wheres = ["p.xbox_title_id = %(tid)s", "p.title != p.product_id"]
        params = {"tid": xbox_title_id}
        if exclude:
            wheres.append("p.product_id != %(exclude)s")
            params["exclude"] = exclude

        where_sql = " AND ".join(wheres)
        cur.execute(f"""
            SELECT p.product_id, p.title, p.publisher, p.release_date,
                   p.platforms, p.product_kind, p.is_bundle,
                   p.image_box_art, p.image_tile, p.image_hero,
                   p.average_rating, p.rating_count
            FROM marketplace_products p
            WHERE {where_sql}
            ORDER BY p.title
        """, params)
        rows = cur.fetchall()

        product_ids = [r["product_id"] for r in rows]

        # Prices
        prices_map = {}
        if product_ids:
            cur.execute(
                "SELECT product_id, market, currency, msrp, sale_price "
                "FROM marketplace_prices WHERE product_id = ANY(%(pids)s)",
                {"pids": product_ids})
            for pr in cur.fetchall():
                pid = pr["product_id"]
                if pid not in prices_map:
                    prices_map[pid] = {}
                prices_map[pid][pr["market"]] = {
                    "msrp": pr["msrp"],
                    "salePrice": pr["sale_price"],
                    "currency": pr["currency"],
                }

        # Tags
        tags_map = {}
        if product_ids:
            cur.execute(
                "SELECT product_id, tag_type, tag_value FROM marketplace_tags "
                "WHERE product_id = ANY(%(pids)s)",
                {"pids": product_ids})
            for tg in cur.fetchall():
                pid = tg["product_id"]
                if pid not in tags_map:
                    tags_map[pid] = {}
                tags_map[pid][tg["tag_type"]] = tg["tag_value"]

        # Ownership
        owned_pids = set()
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)
                if contributor:
                    cur.execute(
                        "SELECT lib FROM user_collections WHERE contributor_id = %s",
                        (contributor["id"],))
                    uc_row = cur.fetchone()
                    if uc_row and uc_row["lib"]:
                        owned_pids = {item["productId"] for item in uc_row["lib"]
                                      if isinstance(item, dict) and "productId" in item}

        editions = []
        for r in rows:
            pid = r["product_id"]
            us_price = prices_map.get(pid, {}).get("US", {})
            price_usd = us_price.get("msrp", 0) or 0
            sp = us_price.get("salePrice", 0) or 0
            current_price = sp if 0 < sp < price_usd else 0

            tag = tags_map.get(pid, {})
            is_bundle = r["is_bundle"]
            if tag.get("is_bundle_override") == "true":
                is_bundle = True
            elif tag.get("is_bundle_override") == "false":
                is_bundle = False

            img = r["image_box_art"] or r["image_tile"] or ""

            editions.append({
                "productId": pid,
                "title": r["title"],
                "publisher": r["publisher"],
                "releaseDate": r["release_date"].isoformat() if r["release_date"] else "",
                "platforms": r["platforms"] or [],
                "productKind": r["product_kind"],
                "isBundle": is_bundle,
                "imageBoxArt": (img + "?w=80&h=80") if img else "",
                "priceUSD": price_usd,
                "currentPriceUSD": current_price,
                "owned": pid in owned_pids,
                "onGP": pid in _gp_pids,
                "regionalPrices": prices_map.get(pid, {}),
            })

        return _gzip_json_response(editions)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Amazon Physical Disc Finder (search-link mode — generates Amazon search URLs)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Marketplace endpoints — scanner-populated data (legacy full dump)
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
                   average_rating, rating_count, sources, has_trial_sku,
                   has_achievements
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

        # 3. Channels — pivot into {product_id: [channel_names]} + region map
        cur.execute("SELECT product_id, channel, regions FROM marketplace_channels")
        channel_map = {}
        region_map = {}
        for row in cur:
            pid = row["product_id"]
            if pid not in channel_map:
                channel_map[pid] = []
            channel_map[pid].append(row["channel"])
            if row["regions"]:
                if pid not in region_map:
                    region_map[pid] = set()
                region_map[pid].update(row["regions"])

        # 3b. Subscriptions — pivot into {product_id: [tier_labels]}
        sub_map = {}
        try:
            cur.execute("SELECT product_id, tier FROM marketplace_subscriptions")
            for row in cur:
                pid = row["product_id"]
                if pid not in sub_map:
                    sub_map[pid] = []
                sub_map[pid].append(row["tier"])
        except Exception:
            conn.rollback()

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

        # Assemble product list (skip products with missing titles)
        products = []
        for p in products_raw:
            pid = p["product_id"]
            if p["title"] == pid:
                continue
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
                "imageBoxArt": p["image_box_art"] or p["image_tile"] or "",
                "imageHero": p["image_hero"],
                "shortDescription": p["short_description"],
                "averageRating": p["average_rating"],
                "ratingCount": p["rating_count"],
                "channels": channel_map.get(pid, []),
                "subscriptions": sub_map.get(pid, []),
                "sources": p["sources"] or [],
                "hasTrialSku": p["has_trial_sku"],
                "hasAchievements": p["has_achievements"],
                "capabilities": p["capabilities"] or [],
                "regionalPrices": price_map.get(pid, {}),
                "channelRegions": sorted(region_map.get(pid, set())),
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
# Admin endpoints — Freshdex only
# ---------------------------------------------------------------------------

@app.route("/api/v1/admin/changelog", methods=["GET"])
@require_auth
def admin_changelog(conn=None, cur=None, contributor=None, api_key=None):
    """Get marketplace changelog entries. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 200, type=int)
    per_page = min(per_page, 1000)
    offset = (page - 1) * per_page

    filters = []
    params = []

    change_type = request.args.get("type")
    if change_type:
        filters.append("c.change_type = %s")
        params.append(change_type)

    scan_id = request.args.get("scan_id", type=int)
    if scan_id:
        filters.append("c.scan_id = %s")
        params.append(scan_id)

    q = request.args.get("q")
    if q:
        filters.append("(c.title ILIKE %s OR c.product_id ILIKE %s)")
        params.extend([f"%{q}%", f"%{q}%"])

    where = ""
    if filters:
        where = "WHERE " + " AND ".join(filters)

    try:
        # Total count
        cur.execute(f"SELECT COUNT(*) FROM marketplace_changelog c {where}", params)
        total = cur.fetchone()["count"]

        # Entries with scan metadata
        cur.execute(f"""
            SELECT c.id, c.scan_id, c.change_type, c.product_id, c.title,
                   c.field_name, c.old_value, c.new_value, c.market,
                   c.created_at,
                   s.scan_type, s.started_at AS scan_started_at
            FROM marketplace_changelog c
            LEFT JOIN marketplace_scans s ON s.id = c.scan_id
            {where}
            ORDER BY c.created_at DESC
            LIMIT %s OFFSET %s
        """, params + [per_page, offset])
        entries = cur.fetchall()

        # Serialize datetimes
        for e in entries:
            for k in ("created_at", "scan_started_at"):
                if e[k] is not None:
                    e[k] = e[k].isoformat()

        # Last 50 scans that have changelog entries
        cur.execute("""
            SELECT s.id, s.scan_type AS type, s.started_at, s.completed_at,
                   s.duration_seconds, s.products_new,
                   (SELECT COUNT(*) FROM marketplace_changelog c WHERE c.scan_id = s.id) AS change_count
            FROM marketplace_scans s
            WHERE EXISTS (SELECT 1 FROM marketplace_changelog c WHERE c.scan_id = s.id)
            ORDER BY s.started_at DESC
            LIMIT 50
        """)
        scans = cur.fetchall()
        for sc in scans:
            for k in ("started_at", "completed_at"):
                if sc[k] is not None:
                    sc[k] = sc[k].isoformat()

        return jsonify(entries=entries, total=total, page=page, scans=scans)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/scans", methods=["GET"])
@require_auth
def admin_scans(conn=None, cur=None, contributor=None, api_key=None):
    """Get recent marketplace scans. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    try:
        cur.execute("""
            SELECT s.*,
                   (SELECT COUNT(*) FROM marketplace_changelog c
                    WHERE c.scan_id = s.id) AS change_count,
                   (SELECT COUNT(*) FROM marketplace_changelog c
                    WHERE c.scan_id = s.id AND c.change_type = 'new_product') AS new_products,
                   (SELECT COUNT(*) FROM marketplace_changelog c
                    WHERE c.scan_id = s.id AND c.change_type = 'removed') AS removed_products,
                   (SELECT COUNT(*) FROM marketplace_changelog c
                    WHERE c.scan_id = s.id AND c.change_type = 'field_changed') AS field_changes,
                   (SELECT COUNT(*) FROM marketplace_changelog c
                    WHERE c.scan_id = s.id AND c.change_type = 'price_changed') AS price_changes
            FROM marketplace_scans s
            ORDER BY s.started_at DESC
            LIMIT 50
        """)
        scans = cur.fetchall()
        for sc in scans:
            for k in ("started_at", "completed_at"):
                if sc.get(k) is not None:
                    sc[k] = sc[k].isoformat()

        return jsonify(scans=scans)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/scans/<int:scan_id>/changelog", methods=["GET"])
@require_auth
def admin_scan_changelog(scan_id, conn=None, cur=None, contributor=None, api_key=None):
    """Get changelog entries for a specific scan. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    try:
        cur.execute("""
            SELECT change_type, product_id, title, field_name,
                   old_value, new_value, market, created_at
            FROM marketplace_changelog
            WHERE scan_id = %s
            ORDER BY change_type, title
            LIMIT 500
        """, (scan_id,))
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return jsonify(changes=rows)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/scan", methods=["POST"])
@require_auth
def admin_scan_trigger(conn=None, cur=None, contributor=None, api_key=None):
    """Trigger a marketplace scan. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    data = request.get_json(silent=True) or {}

    cmd = ["python3", "marketplace_scanner.py"]

    scan_type = data.get("type", "full")
    if scan_type == "nz_new":
        cmd.append("scan-nz")
    elif scan_type == "prices_only":
        cmd.extend(["scan", "--prices-only"])
    elif scan_type == "force_browse":
        cmd.extend(["scan", "--force-browse"])
    elif scan_type == "channel":
        cmd.extend(["scan", f"--channel={data.get('channel', '')}"])
    elif scan_type == "region":
        cmd.extend(["scan", f"--region={data.get('region', '')}"])
    else:
        cmd.append("scan")

    threading.Thread(
        target=lambda: subprocess.run(cmd, timeout=3600, capture_output=True,
                                       cwd="/app"),
        daemon=True
    ).start()

    return jsonify(ok=True, message="Scan triggered", type=scan_type)


@app.route("/api/v1/admin/subs", methods=["POST"])
@require_auth
def admin_subs_update(conn=None, cur=None, contributor=None, api_key=None):
    """Force-update subscription data. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    data = request.get_json(silent=True) or {}
    tier = data.get("tier", "all")

    cmd = ["python3", "marketplace_scanner.py", "subs-only"]

    if tier != "all":
        cmd.append(f"--tier={tier}")

    threading.Thread(
        target=lambda: subprocess.run(cmd, timeout=300, capture_output=True,
                                       cwd="/app"),
        daemon=True
    ).start()

    label = f"tier={tier}" if tier != "all" else "all tiers"
    return jsonify(ok=True, message=f"Subscription update triggered ({label})")


# ---------------------------------------------------------------------------
# Collection endpoints — auth required
# ---------------------------------------------------------------------------

@app.route("/api/v1/collection/upload", methods=["POST"])
@require_auth
def collection_upload(conn=None, cur=None, contributor=None, api_key=None):
    """Upload user collection JSON (max 20MB)."""
    if not _check_rate(_rate_upload, api_key, UPLOAD_LIMIT, 60):
        return jsonify(error="Rate limit exceeded. Try again in a minute."), 429

    # Accept JSON body (with gzip support)
    raw = request.get_data(as_text=False)
    if request.headers.get("Content-Encoding") == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            return jsonify(error="Invalid gzip data"), 400

    # Size guard: 50MB decompressed limit
    if len(raw) > 50 * 1024 * 1024:
        return jsonify(error="Payload too large (max 50MB)"), 413

    try:
        data = json.loads(raw)
    except Exception:
        return jsonify(error="Invalid JSON body"), 400

    # Validate expected structure
    if not isinstance(data.get("library"), list):
        return jsonify(error="'library' array is required"), 400

    lib = data["library"]

    # Server-side allowlist: strip any fields not needed for display
    _LIB_ALLOWED = {
        "gamertag", "productId", "productKind", "status",
        "acquiredDate", "startDate", "endDate", "isTrial", "skuType", "quantity",
        "title", "developer", "publisher", "image", "boxArt", "category",
        "releaseDate", "platforms", "isDemo", "hasTrialSku", "hasAchievements",
        "priceUSD", "currentPriceUSD",
        "onGamePass", "owned", "lastTimePlayed", "catalogInvalid", "xboxTitleId",
    }
    lib = [{k: v for k, v in item.items() if k in _LIB_ALLOWED}
           for item in lib if isinstance(item, dict)]

    ph = data.get("playHistory", [])
    history = data.get("history", [])
    accounts = data.get("accounts", [])
    purchases = data.get("purchases", [])

    if not isinstance(ph, list):
        ph = []
    if not isinstance(history, list):
        history = []
    if not isinstance(accounts, list):
        accounts = []
    if not isinstance(purchases, list):
        purchases = []

    # Cap history to 100 entries
    history = history[:100]

    # Strip accounts to gamertag only
    safe_accounts = []
    for a in accounts:
        if isinstance(a, dict) and a.get("gamertag"):
            safe_accounts.append({"gamertag": a["gamertag"]})

    # Allowlist purchase fields
    _PURCH_ALLOWED = {
        "gamertag", "orderId", "vanityOrderId", "orderDate", "market", "currency",
        "orderTotal", "orderType", "productId", "title", "type", "status",
        "isPurchased", "isCanceled", "isGift", "isPreorder", "isSubscription",
        "quantity", "listPrice", "amountPaid", "developer", "publisher",
        "image", "boxArt", "category", "releaseDate", "platforms",
        "productKind", "priceUSD", "currentPriceUSD",
    }
    purchases = [{k: v for k, v in item.items() if k in _PURCH_ALLOWED}
                 for item in purchases if isinstance(item, dict)]

    try:
        cur.execute("""
            INSERT INTO user_collections (contributor_id, lib, play_history, scan_history, accounts_meta, purchases, uploaded_at, version)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), 1)
            ON CONFLICT (contributor_id) DO UPDATE SET
                lib = EXCLUDED.lib,
                play_history = EXCLUDED.play_history,
                scan_history = EXCLUDED.scan_history,
                accounts_meta = EXCLUDED.accounts_meta,
                purchases = EXCLUDED.purchases,
                uploaded_at = NOW(),
                version = user_collections.version + 1
        """, (
            contributor["id"],
            psycopg2.extras.Json(lib),
            psycopg2.extras.Json(ph),
            psycopg2.extras.Json(history),
            psycopg2.extras.Json(safe_accounts),
            psycopg2.extras.Json(purchases),
        ))
        conn.commit()
        return jsonify(
            status="ok",
            items=len(lib),
            playHistory=len(ph),
            history=len(history),
            accounts=len(safe_accounts),
            purchases=len(purchases),
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
            SELECT lib, play_history, scan_history, accounts_meta, purchases, uploaded_at, version
            FROM user_collections
            WHERE contributor_id = %s
        """, (contributor["id"],))
        row = cur.fetchone()
        if not row:
            return jsonify(
                library=[], playHistory=[], history=[], accounts=[], purchases=[],
                username=contributor["username"],
                settings=contributor.get("settings") or {},
                uploaded=False)
        return jsonify(
            library=row["lib"] or [],
            playHistory=row["play_history"] or [],
            history=row["scan_history"] or [],
            accounts=row["accounts_meta"] or [],
            purchases=row["purchases"] or [],
            username=contributor["username"],
            settings=contributor.get("settings") or {},
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
    """Remove expired OAuth state tokens from DB."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM oauth_states WHERE created_at < NOW() - INTERVAL '%s seconds'",
                    (OAUTH_STATE_TTL,))
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()


def _save_oauth_state(state, data):
    """Save OAuth state to DB."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO oauth_states (state, data) VALUES (%s, %s)",
                    (state, psycopg2.extras.Json(data)))
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()


def _pop_oauth_state(state):
    """Retrieve and delete OAuth state from DB. Returns data dict or None."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("DELETE FROM oauth_states WHERE state = %s RETURNING data", (state,))
        row = cur.fetchone()
        conn.commit()
        return row["data"] if row else None
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()


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
    refresh_token = _fernet.decrypt(bytes(row["refresh_token_enc"])).decode()

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

    _save_oauth_state(state, state_data)

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

    # Validate state (CSRF) — stored in DB for multi-worker support
    _cleanup_oauth_states()
    state_data = _pop_oauth_state(state)
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

    # Resolve avatar URL from Xbox profile
    avatar_url = ""
    try:
        profile = xba.resolve_gamertag(xbl3_token, gamertag)
        avatar_url = profile.get("avatar_url", "")
    except Exception as e:
        log.warning("Avatar resolve failed for %s: %s", gamertag, e)

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

        # Save avatar_url on contributor
        if avatar_url:
            cur.execute(
                "UPDATE contributors SET avatar_url = %s WHERE id = %s",
                (avatar_url, contributor_id))
        conn.commit()

        # Fetch initial achievement summaries in background (avoid blocking redirect)
        def _bg_ach_fetch(cid, token, xu, gt):
            try:
                summaries = xba.fetch_titlehub_achievements(token, xu)
                c = get_db()
                try:
                    cr = c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                    _store_achievement_summaries(cr, cid, summaries)
                    c.commit()
                except Exception:
                    c.rollback()
                    raise
                finally:
                    c.close()
            except Exception as e:
                import traceback
                log.warning("Background achievement fetch failed for %s: %s\n%s",
                            gt, e, traceback.format_exc())
        threading.Thread(
            target=_bg_ach_fetch,
            args=(contributor_id, xbl3_token, xuid, gamertag),
            daemon=True).start()

        import urllib.parse
        params = urllib.parse.urlencode({
            "xbox_auth": "success",
            "api_key": api_key,
            "gamertag": gamertag,
            "xuid": xuid,
            "avatar_url": avatar_url,
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
        avatar_url = contributor.get("avatar_url") or ""
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

        rows = cur.fetchall()

        # Auto-fetch from Xbox Live in background if DB has no cached summaries
        # (e.g. first page load after sign-in, before background thread finishes)
        fetching = False
        if not rows:
            try:
                xbl3, xuid_val, gt = _ensure_xbl3_token(cur, conn, contributor["id"])
                def _bg_auto_fetch(cid, token, xu):
                    try:
                        live = xba.fetch_titlehub_achievements(token, xu)
                        c = get_db()
                        try:
                            cr = c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                            _store_achievement_summaries(cr, cid, live)
                            c.commit()
                        except Exception:
                            c.rollback()
                            raise
                        finally:
                            c.close()
                    except Exception as e:
                        import traceback
                        log.warning("Background auto-fetch summaries failed: %s\n%s",
                                    e, traceback.format_exc())
                threading.Thread(
                    target=_bg_auto_fetch,
                    args=(contributor["id"], xbl3, xuid_val),
                    daemon=True).start()
                fetching = True
            except Exception as e:
                log.warning("Auto-fetch setup failed: %s", e)

        summaries = []
        total_gs = 0
        for row in rows:
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
                "displayImage": (row["display_image"] or "").replace("http://", "https://"),
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
            fetching=fetching,
            avatarUrl=avatar_url,
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
# Leaderboard endpoints
# ---------------------------------------------------------------------------

# Background scan state
_lb_scan_active = False
_lb_scan_status = {"state": "idle", "scanned": 0, "total": 0, "errors": 0}
_lb_scan_log = []        # ring buffer of recent scan events
_LB_LOG_MAX = 500        # keep last 500 entries
_lb_scan_current = ""    # gamertag currently being scanned


def _scan_log(msg):
    """Append a timestamped message to the scan log — persisted to DB."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    # In-memory buffer for quick access
    _lb_scan_log.append(entry)
    if len(_lb_scan_log) > _LB_LOG_MAX:
        del _lb_scan_log[:len(_lb_scan_log) - _LB_LOG_MAX]
    # Persist to DB
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO scan_log (message) VALUES (%s)", (entry,))
        # Trim to last 1000 rows
        cur.execute("""
            DELETE FROM scan_log WHERE id NOT IN (
                SELECT id FROM scan_log ORDER BY id DESC LIMIT 1000
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass  # don't let logging errors break the scan


def _bg_scan_gamertags(xbl3_token):
    """Background thread: resolve gamertags via Xbox API and fetch games played."""
    global _lb_scan_active, _lb_scan_current
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get gamertags needing scan: missing, pending, error, or incomplete (v2=0)
        cur.execute("""
            SELECT DISTINCT t.gamertag
            FROM ta_leaderboard_entries t
            LEFT JOIN xbox_gamer_profiles x ON LOWER(t.gamertag) = LOWER(x.gamertag)
            WHERE x.xuid IS NULL
               OR x.scan_status IN ('pending', 'error')
               OR (x.scan_status = 'complete' AND x.games_played_v2 = 0)
            ORDER BY t.gamertag
        """)
        pending = [row["gamertag"] for row in cur.fetchall()]

        _lb_scan_status["total"] = len(pending)
        _lb_scan_status["scanned"] = 0
        _lb_scan_status["errors"] = 0
        _lb_scan_status["state"] = "scanning"
        _scan_log(f"Scan started: {len(pending)} gamertags pending")

        for gt in pending:
            if not _lb_scan_active:
                _scan_log("Scan aborted by user")
                break
            _lb_scan_current = gt
            try:
                # Step 1: Resolve gamertag → XUID + gamerscore + avatar
                _scan_log(f"Resolving: {gt}")
                profile = xba.resolve_gamertag(xbl3_token, gt)
                xuid = profile["xuid"]
                if not xuid:
                    raise ValueError("No XUID returned")

                # Step 2: Fetch games played counts
                counts = xba.fetch_games_played_count(xbl3_token, xuid)

                _scan_log(f"OK: {gt} → XUID={xuid} GS={profile['gamerscore']:,} "
                          f"games={counts['total']} (v2={counts['v2_count']} v1={counts['v1_count']})")

                # Step 3: Upsert into xbox_gamer_profiles
                cur.execute("""
                    INSERT INTO xbox_gamer_profiles
                        (xuid, gamertag, gamerscore, games_played_v2, games_played_v1,
                         games_played_total, avatar_url, scan_status, scanned_at, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'complete', NOW(), NOW())
                    ON CONFLICT (xuid) DO UPDATE SET
                        gamertag = EXCLUDED.gamertag,
                        gamerscore = EXCLUDED.gamerscore,
                        games_played_v2 = EXCLUDED.games_played_v2,
                        games_played_v1 = EXCLUDED.games_played_v1,
                        games_played_total = EXCLUDED.games_played_total,
                        avatar_url = EXCLUDED.avatar_url,
                        scan_status = 'complete',
                        scan_error = '',
                        scanned_at = NOW()
                """, (xuid, profile["gamertag"], profile["gamerscore"],
                      counts["v2_count"], counts["v1_count"], counts["total"],
                      profile["avatar_url"]))
                conn.commit()
                _lb_scan_status["scanned"] += 1

            except Exception as e:
                _scan_log(f"ERR: {gt} — {e}")
                # Mark as error in DB if we know the XUID, otherwise just count
                try:
                    cur.execute("""
                        INSERT INTO xbox_gamer_profiles
                            (xuid, gamertag, scan_status, scan_error, created_at)
                        VALUES (%s, %s, 'error', %s, NOW())
                        ON CONFLICT (xuid) DO UPDATE SET
                            scan_status = 'error', scan_error = EXCLUDED.scan_error
                    """, (f"err_{gt}", gt, str(e)[:200]))
                    conn.commit()
                except Exception:
                    conn.rollback()
                _lb_scan_status["errors"] += 1
                _lb_scan_status["scanned"] += 1

            time.sleep(4)  # rate limit: 4s between gamertags (3 API calls each)

        _lb_scan_status["state"] = "complete"
        _lb_scan_current = ""
        _scan_log(f"Scan complete: {_lb_scan_status['scanned']} scanned, "
                  f"{_lb_scan_status['errors']} errors")
    except Exception as e:
        _lb_scan_status["state"] = f"error: {e}"
        _lb_scan_current = ""
        _scan_log(f"Scan FAILED: {e}")
        log.error("Background scan failed: %s", e)
    finally:
        _lb_scan_active = False
        conn.close()


@app.route("/api/v1/leaderboard/<lb_type>")
def leaderboard_get(lb_type):
    """Return leaderboard data (public, no auth)."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check if ta_leaderboard_entries table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'ta_leaderboard_entries'
            )
        """)
        if not cur.fetchone()["exists"]:
            return _gzip_json_response({
                "type": lb_type, "entries": [],
                "scannedCount": 0, "totalCount": 0,
                "scanStatus": _lb_scan_status,
            }, cache_key=f"lb_{lb_type}")

        # Join TA entries with Xbox gamer profiles + contributor status
        cur.execute("""
            SELECT t.position, t.gamertag, t.score, t.avatar_url AS ta_avatar,
                   x.xuid, x.gamerscore, x.games_played_v2, x.games_played_v1,
                   x.games_played_total, x.avatar_url AS xbox_avatar,
                   x.scan_status, c.status AS user_status
            FROM ta_leaderboard_entries t
            LEFT JOIN xbox_gamer_profiles x ON LOWER(t.gamertag) = LOWER(x.gamertag)
            LEFT JOIN xbox_auth xa ON LOWER(xa.gamertag) = LOWER(t.gamertag)
            LEFT JOIN contributors c ON c.id = xa.contributor_id
            WHERE t.leaderboard_type = %s
            ORDER BY t.position
        """, (lb_type,))

        entries = []
        scanned = 0
        for row in cur.fetchall():
            status = row["scan_status"] or "pending"
            if status == "complete":
                scanned += 1
            entries.append({
                "position": row["position"],
                "gamertag": row["gamertag"],
                "score": row["score"],
                "gamerscore": row["gamerscore"],
                "gamesPlayedV2": row["games_played_v2"],
                "gamesPlayedV1": row["games_played_v1"],
                "gamesPlayed": row["games_played_total"],
                "avatarUrl": row["xbox_avatar"] or row["ta_avatar"] or "",
                "scanStatus": status,
                "status": row["user_status"] or "",
            })

        total = len(entries)

        # Invalidate cache so fresh data is always served
        _shared_cache.pop(f"lb_{lb_type}", None)

        return _gzip_json_response({
            "type": lb_type,
            "entries": entries,
            "scannedCount": scanned,
            "totalCount": total,
            "scanStatus": _lb_scan_status,
        })
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/leaderboard/scrape", methods=["POST"])
@require_auth
def leaderboard_scrape(conn=None, cur=None, contributor=None, api_key=None):
    """Trigger TA scrape + optional Xbox scan in background."""
    global _lb_scan_active

    lb_type = "gamesplayed"
    pages = 10

    body = request.get_json(silent=True) or {}
    if body.get("type"):
        lb_type = body["type"]
    if body.get("pages"):
        pages = min(int(body["pages"]), 20)

    def _bg_scrape_and_scan(cid, token):
        global _lb_scan_active
        try:
            _lb_scan_status["state"] = "scraping"
            _scan_log(f"Scraping TA leaderboard '{lb_type}' ({pages} pages)...")
            entries = xba.scrape_ta_leaderboard(lb_type, pages=pages)
            _scan_log(f"Scraped {len(entries)} gamertags from TA")

            # Store in DB
            c = get_db()
            try:
                cr = c.cursor()
                for e in entries:
                    cr.execute("""
                        INSERT INTO ta_leaderboard_entries
                            (leaderboard_type, position, gamertag, score, avatar_url, scraped_at)
                        VALUES (%s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (leaderboard_type, gamertag) DO UPDATE SET
                            position = EXCLUDED.position,
                            score = EXCLUDED.score,
                            avatar_url = EXCLUDED.avatar_url,
                            scraped_at = NOW()
                    """, (lb_type, e["position"], e["gamertag"],
                          e["score"], e["avatar_url"]))
                c.commit()
            finally:
                c.close()

            # Now start Xbox API scan
            _lb_scan_active = True
            _bg_scan_gamertags(token)

        except Exception as e:
            _lb_scan_status["state"] = f"error: {e}"
            log.error("Scrape+scan failed: %s", e)
            _lb_scan_active = False

    # Get XBL3.0 token for the authenticated user
    try:
        xbl3, xuid, gt = _ensure_xbl3_token(cur, conn, contributor["id"])
    except ValueError as e:
        return jsonify(error=str(e)), 401

    _lb_scan_active = True
    threading.Thread(
        target=_bg_scrape_and_scan,
        args=(contributor["id"], xbl3),
        daemon=True).start()

    return jsonify(status="started", message=f"Scraping {pages} pages of {lb_type}...")


@app.route("/api/v1/leaderboard/scan", methods=["POST"])
@require_auth
def leaderboard_scan(conn=None, cur=None, contributor=None, api_key=None):
    """Resume/restart Xbox API scanning for pending gamertags."""
    global _lb_scan_active

    if _lb_scan_active:
        return jsonify(status="already_running", scanStatus=_lb_scan_status)

    try:
        xbl3, xuid, gt = _ensure_xbl3_token(cur, conn, contributor["id"])
    except ValueError as e:
        return jsonify(error=str(e)), 401

    _lb_scan_active = True
    threading.Thread(
        target=_bg_scan_gamertags,
        args=(xbl3,),
        daemon=True).start()

    return jsonify(status="started", message="Scanning pending gamertags...")


@app.route("/api/v1/leaderboard/status")
def leaderboard_scan_status():
    """Return current scan status (public, no auth)."""
    return jsonify(scanStatus=_lb_scan_status, active=_lb_scan_active)


@app.route("/api/v1/leaderboard/admin")
@require_auth
def leaderboard_admin(conn=None, cur=None, contributor=None, api_key=None):
    """Admin-only: detailed scan status + log + DB stats."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403

    try:
        # DB stats
        cur.execute("SELECT COUNT(*) as cnt FROM ta_leaderboard_entries")
        ta_count = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM xbox_gamer_profiles")
        profile_count = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM xbox_gamer_profiles WHERE scan_status = 'complete'")
        complete_count = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM xbox_gamer_profiles WHERE scan_status = 'error'")
        error_count = cur.fetchone()["cnt"]

        # Recent scans (last 20 completed profiles)
        cur.execute("""
            SELECT gamertag, xuid, gamerscore, games_played_total,
                   games_played_v2, games_played_v1, scan_status, scan_error, scanned_at
            FROM xbox_gamer_profiles
            ORDER BY scanned_at DESC NULLS LAST
            LIMIT 20
        """)
        recent = []
        for row in cur.fetchall():
            recent.append({
                "gamertag": row["gamertag"],
                "xuid": row["xuid"],
                "gamerscore": row["gamerscore"],
                "gamesPlayed": row["games_played_total"],
                "v2": row["games_played_v2"],
                "v1": row["games_played_v1"],
                "status": row["scan_status"],
                "error": row["scan_error"] or "",
                "scannedAt": row["scanned_at"].isoformat() if row["scanned_at"] else None,
            })

        # Error profiles
        cur.execute("""
            SELECT gamertag, scan_error, scanned_at
            FROM xbox_gamer_profiles
            WHERE scan_status = 'error'
            ORDER BY scanned_at DESC NULLS LAST
            LIMIT 50
        """)
        errors = []
        for row in cur.fetchall():
            errors.append({
                "gamertag": row["gamertag"],
                "error": row["scan_error"] or "",
                "scannedAt": row["scanned_at"].isoformat() if row["scanned_at"] else None,
            })

        # Read persisted log from DB (last 200 entries, oldest first)
        cur.execute("""
            SELECT message FROM scan_log ORDER BY id DESC LIMIT 200
        """)
        db_log = [row["message"] for row in cur.fetchall()]
        db_log.reverse()  # oldest first

        return jsonify(
            scanStatus=_lb_scan_status,
            active=_lb_scan_active,
            currentGamertag=_lb_scan_current,
            log=db_log,
            dbStats={
                "taEntries": ta_count,
                "profiles": profile_count,
                "complete": complete_count,
                "errors": error_count,
            },
            recentScans=recent,
            errorProfiles=errors,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/leaderboard/stop", methods=["POST"])
@require_auth
def leaderboard_stop(conn=None, cur=None, contributor=None, api_key=None):
    """Admin-only: stop an active scan."""
    global _lb_scan_active
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    _lb_scan_active = False
    _scan_log("Scan stop requested by admin")
    return jsonify(status="ok", message="Stop signal sent")


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route("/api/v1/profile")
@require_auth
def profile_get(conn=None, cur=None, contributor=None, api_key=None):
    """Return profile data for the authenticated user."""
    try:
        cid = contributor["id"]
        # Get Xbox link info
        cur.execute(
            "SELECT xuid, gamertag FROM xbox_auth WHERE contributor_id = %s",
            (cid,))
        xbox = cur.fetchone()
        # Aggregate achievement stats
        cur.execute("""
            SELECT COALESCE(SUM(current_gamerscore), 0) AS total_gs,
                   COUNT(*) AS titles_played
            FROM xbox_achievement_summaries
            WHERE contributor_id = %s
        """, (cid,))
        stats = cur.fetchone()
        # Total CDN points
        cur.execute(
            "SELECT COALESCE(total_points, 0) AS pts FROM contributors WHERE id = %s",
            (cid,))
        pts_row = cur.fetchone()
        return jsonify(
            username=contributor["username"],
            avatarUrl=contributor.get("avatar_url") or "",
            status=contributor.get("status") or "",
            settings=contributor.get("settings") or {},
            totalPoints=pts_row["pts"] if pts_row else 0,
            xuid=xbox["xuid"] if xbox else "",
            gamertag=xbox["gamertag"] if xbox else "",
            gamerscore=stats["total_gs"] if stats else 0,
            titlesPlayed=stats["titles_played"] if stats else 0,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/profile", methods=["PUT"])
@require_auth
def profile_put(conn=None, cur=None, contributor=None, api_key=None):
    """Update profile fields (status, settings)."""
    try:
        data = request.get_json(force=True)
        # Merge settings if provided
        valid_regions = {
            "AE", "AR", "AT", "AU", "BE", "BG", "BH", "BR", "CA", "CH",
            "CL", "CN", "CO", "CY", "CZ", "DE", "DK", "EE", "EG", "ES",
            "FI", "FR", "GB", "GR", "GT", "HK", "HR", "HU", "ID", "IE",
            "IL", "IN", "IS", "IT", "JP", "KR", "KW", "LT", "LV", "MT",
            "MX", "MY", "NG", "NL", "NO", "NZ", "OM", "PE", "PH", "PL",
            "PT", "QA", "RO", "RS", "RU", "SA", "SE", "SG", "SI", "SK",
            "TH", "TR", "TT", "TW", "UA", "US", "VN", "ZA",
        }
        settings_update = {}
        if "settings" in data and isinstance(data["settings"], dict):
            raw = data["settings"]
            if "myRegions" in raw and isinstance(raw["myRegions"], list):
                settings_update["myRegions"] = [r for r in raw["myRegions"] if r in valid_regions]
        has_status = "status" in data
        status = (data.get("status") or "")[:280] if has_status else None
        if settings_update and has_status:
            cur.execute(
                "UPDATE contributors SET status = %s, settings = COALESCE(settings, '{}') || %s::jsonb WHERE id = %s",
                (status, json.dumps(settings_update), contributor["id"]))
        elif settings_update:
            cur.execute(
                "UPDATE contributors SET settings = COALESCE(settings, '{}') || %s::jsonb WHERE id = %s",
                (json.dumps(settings_update), contributor["id"]))
        elif has_status:
            cur.execute(
                "UPDATE contributors SET status = %s WHERE id = %s",
                (status, contributor["id"]))
        conn.commit()
        return jsonify(ok=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


# ---------------------------------------------------------------------------
# CDN Version Monitor
# ---------------------------------------------------------------------------

_cdn_mon_active = False
_cdn_mon_status = {"state": "idle", "checked": 0, "total": 0, "new": 0, "purged": 0, "errors": 0}
_cdn_mon_log = []
_CDN_MON_LOG_MAX = 500
_cdn_mon_current = ""


def _cdn_mon_log_msg(msg):
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    _cdn_mon_log.append(entry)
    if len(_cdn_mon_log) > _CDN_MON_LOG_MAX:
        del _cdn_mon_log[:len(_cdn_mon_log) - _CDN_MON_LOG_MAX]


def _cdn_mon_get_update_token(cur, conn, contributor_id):
    """Get XBL3.0 token for http://update.xboxlive.com RP."""
    cur.execute(
        "SELECT refresh_token_enc FROM xbox_auth WHERE contributor_id = %s",
        (contributor_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError("No Xbox account linked — link Xbox on your profile first")
    if not _fernet:
        raise ValueError("XBOX_ENCRYPTION_KEY not configured on server")
    refresh_token = _fernet.decrypt(bytes(row["refresh_token_enc"])).decode()
    msa = xba.refresh_msa_token(XBOX_CLIENT_ID, XBOX_CLIENT_SECRET, refresh_token)
    new_refresh_enc = _fernet.encrypt(msa["refresh_token"].encode())
    cur.execute("UPDATE xbox_auth SET refresh_token_enc = %s WHERE contributor_id = %s",
                (new_refresh_enc, contributor_id))
    conn.commit()
    user_token = xba.get_xbox_user_token(msa["access_token"])
    xsts_token, uhs, _, _ = xba.get_xsts_token(
        user_token, relying_party="http://update.xboxlive.com")
    return xba.build_xbl3_token(xsts_token, uhs)


def _cdn_mon_api_get(url, xbl3_token, timeout=15):
    """GET packagespc.xboxlive.com. Returns parsed JSON."""
    import urllib.request as _ur
    req = _ur.Request(url)
    req.add_header("Authorization", xbl3_token)
    req.add_header("User-Agent", "Microsoft-Delivery-Optimization/10.0")
    req.add_header("Accept", "application/json")
    with _ur.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _cdn_mon_head_check(url, timeout=10):
    """HEAD-check a CDN URL. Returns True=live, False=purged, None=error."""
    import urllib.request as _ur
    import urllib.error as _ue
    try:
        req = _ur.Request(url, method="HEAD")
        req.add_header("User-Agent", "Microsoft-Delivery-Optimization/10.0")
        _ur.urlopen(req, timeout=timeout)
        return True
    except _ue.HTTPError as e:
        if e.code in (404, 403):
            return False
        return None
    except Exception:
        return None


def _cdn_mon_parse_version_id(vid):
    """Parse '1.0.0.8.guid-here' → (version='1.0.0.8', build_id='guid-here')."""
    if not vid:
        return "", ""
    dots = [i for i, c in enumerate(vid) if c == "."]
    if len(dots) >= 4:
        return vid[:dots[3]], vid[dots[3] + 1:]
    return vid, ""


def _cdn_mon_resolve_title(cur, store_id):
    """Resolve display title from marketplace_products."""
    if not store_id:
        return ""
    try:
        cur.execute("SELECT title FROM marketplace_products WHERE product_id = %s",
                    (store_id,))
        row = cur.fetchone()
        return row["title"] if row and row.get("title") else ""
    except Exception:
        return ""


def _cdn_mon_upsert_snapshot(cur, conn, scan_id, content_id, store_id,
                             version, build_id, version_id, cdn_url,
                             file_size, filename, title):
    """Insert or update a version snapshot. Returns True if new."""
    cur.execute("""
        SELECT id, cdn_url, file_size FROM cdn_version_snapshots
        WHERE content_id = %s AND version_id = %s
    """, (content_id, version_id))
    existing = cur.fetchone()
    if existing:
        updates = ["last_checked_at = NOW()"]
        params = []
        if cdn_url and not existing.get("cdn_url"):
            updates.append("cdn_url = %s")
            params.append(cdn_url)
        if file_size and not existing.get("file_size"):
            updates.append("file_size = %s")
            params.append(file_size)
        params.append(existing["id"])
        cur.execute(f"UPDATE cdn_version_snapshots SET {', '.join(updates)} WHERE id = %s",
                    params)
        conn.commit()
        return False
    cur.execute("""
        INSERT INTO cdn_version_snapshots
            (content_id, store_id, version, build_id, version_id,
             cdn_url, file_size, filename, status, scan_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (content_id, store_id, version, build_id, version_id,
          cdn_url, file_size, filename,
          'live' if cdn_url else 'unknown', scan_id))
    cur.execute("""
        INSERT INTO cdn_version_changes
            (scan_id, change_type, content_id, store_id, title, version, build_id, new_value)
        VALUES (%s, 'new_version', %s, %s, %s, %s, %s, %s)
    """, (scan_id, content_id, store_id, title, version, build_id, cdn_url or version_id))
    conn.commit()
    return True


def _bg_cdn_version_scan(xbl3_token, scan_type="full"):
    """Background thread: scan content IDs for version changes + purge detection."""
    global _cdn_mon_active, _cdn_mon_current
    conn = get_db()
    scan_id = None
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            INSERT INTO cdn_version_scans (scan_type, status)
            VALUES (%s, 'running') RETURNING id
        """, (scan_type,))
        scan_id = cur.fetchone()["id"]
        conn.commit()

        cur.execute("""
            SELECT DISTINCT ON (content_id) content_id, store_id
            FROM cdn_entries
            WHERE NOT deleted AND content_id IS NOT NULL AND content_id != ''
            ORDER BY content_id
        """)
        content_ids = [(r["content_id"], r["store_id"] or "") for r in cur.fetchall()]

        _cdn_mon_status.update(state="scanning", total=len(content_ids),
                               checked=0, new=0, purged=0, errors=0)
        cur.execute("UPDATE cdn_version_scans SET content_ids_total = %s WHERE id = %s",
                    (len(content_ids), scan_id))
        conn.commit()
        _cdn_mon_log_msg(f"Scan started ({scan_type}): {len(content_ids)} content IDs")

        errors_list = []
        versions_found = 0
        new_versions = 0

        # Phase 1: API calls
        if scan_type != "purge_check" and xbl3_token:
            xsp_pat = re.compile(r"update-(\d+\.\d+\.\d+\.\d+)\.([0-9a-fA-F-]{36})\.xsp")
            for content_id, store_id in content_ids:
                if not _cdn_mon_active:
                    _cdn_mon_log_msg("Scan aborted")
                    break
                _cdn_mon_current = content_id
                try:
                    title = _cdn_mon_resolve_title(cur, store_id)
                    url = f"https://packagespc.xboxlive.com/GetBasePackage/{content_id}"
                    data = _cdn_mon_api_get(url, xbl3_token)
                    if not data.get("PackageFound"):
                        _cdn_mon_status["checked"] += 1
                        continue

                    latest_vid = data.get("VersionId", "")
                    files = data.get("PackageFiles", [])
                    version, build_id = _cdn_mon_parse_version_id(latest_vid)

                    base_pkg = None
                    for f in files:
                        if not f.get("FileName", "").endswith(".xsp"):
                            base_pkg = f
                            break
                    if base_pkg:
                        cdn_roots = base_pkg.get("CdnRootPaths", [])
                        rel_url = base_pkg.get("RelativeUrl", "")
                        cdn_url = (cdn_roots[0] + rel_url) if cdn_roots and rel_url else ""
                        is_new = _cdn_mon_upsert_snapshot(
                            cur, conn, scan_id, content_id, store_id,
                            version, build_id, latest_vid, cdn_url,
                            base_pkg.get("FileSize", 0),
                            base_pkg.get("FileName", ""), title)
                        versions_found += 1
                        if is_new:
                            new_versions += 1
                            _cdn_mon_status["new"] += 1
                            _cdn_mon_log_msg(f"NEW: {title or store_id or content_id[:8]} v{version}")

                    for f in files:
                        m = xsp_pat.match(f.get("FileName", ""))
                        if m:
                            ver, bid = m.group(1), m.group(2)
                            vid = f"{ver}.{bid}"
                            is_new = _cdn_mon_upsert_snapshot(
                                cur, conn, scan_id, content_id, store_id,
                                ver, bid, vid, "", 0, "", title)
                            versions_found += 1
                            if is_new:
                                new_versions += 1
                                _cdn_mon_status["new"] += 1

                    _cdn_mon_status["checked"] += 1
                except Exception as e:
                    err_str = str(e)[:100]
                    if "401" in err_str or "Unauthorized" in err_str:
                        _cdn_mon_log_msg(f"AUTH EXPIRED at {_cdn_mon_status['checked']}/{len(content_ids)} — stopping API phase")
                        errors_list.append("Token expired")
                        _cdn_mon_status["errors"] += 1
                        break
                    errors_list.append(f"{content_id[:8]}: {err_str}")
                    _cdn_mon_status["errors"] += 1
                    _cdn_mon_status["checked"] += 1
                time.sleep(1)

        # Phase 2: HEAD-check purge detection
        purged_count = 0
        if scan_type != "api_only" and _cdn_mon_active:
            _cdn_mon_log_msg("Starting purge detection...")
            _cdn_mon_status["state"] = "purge_check"
            cur.execute("""
                SELECT id, content_id, store_id, version, cdn_url
                FROM cdn_version_snapshots
                WHERE status = 'live' AND cdn_url != ''
            """)
            live_urls = cur.fetchall()
            _cdn_mon_log_msg(f"HEAD-checking {len(live_urls)} live CDN URLs...")
            for i, row in enumerate(live_urls):
                if not _cdn_mon_active:
                    break
                _cdn_mon_current = f"{row['content_id'][:8]} v{row['version']}"
                result = _cdn_mon_head_check(row["cdn_url"])
                if result is False:
                    cur.execute("""
                        UPDATE cdn_version_snapshots
                        SET status = 'purged', purged_at = NOW(), last_checked_at = NOW()
                        WHERE id = %s
                    """, (row["id"],))
                    cur.execute("""
                        INSERT INTO cdn_version_changes
                            (scan_id, change_type, content_id, store_id, version, old_value, new_value)
                        VALUES (%s, 'purged', %s, %s, %s, 'live', 'purged')
                    """, (scan_id, row["content_id"], row["store_id"] or "", row["version"]))
                    conn.commit()
                    purged_count += 1
                    _cdn_mon_status["purged"] += 1
                    title = _cdn_mon_resolve_title(cur, row.get("store_id", ""))
                    _cdn_mon_log_msg(f"PURGED: {title or row['content_id'][:8]} v{row['version']}")
                elif result is True:
                    cur.execute("UPDATE cdn_version_snapshots SET last_checked_at = NOW() WHERE id = %s",
                                (row["id"],))
                    if (i + 1) % 50 == 0:
                        conn.commit()
                if (i + 1) % 200 == 0:
                    _cdn_mon_log_msg(f"  HEAD-checked {i + 1}/{len(live_urls)}...")
                time.sleep(0.2)
            conn.commit()

        status = "completed" if _cdn_mon_active else "aborted"
        cur.execute("""
            UPDATE cdn_version_scans SET
                completed_at = NOW(), status = %s,
                content_ids_checked = %s, versions_found = %s,
                new_versions = %s, purged_detected = %s,
                errors = %s,
                duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))
            WHERE id = %s
        """, (status, _cdn_mon_status["checked"], versions_found,
              new_versions, purged_count,
              psycopg2.extras.Json(errors_list[:50]), scan_id))
        conn.commit()
        _cdn_mon_status["state"] = status
        _cdn_mon_current = ""
        _cdn_mon_log_msg(f"Scan {status}: {_cdn_mon_status['checked']} checked, "
                         f"{new_versions} new versions, {purged_count} purged, "
                         f"{_cdn_mon_status['errors']} errors")
    except Exception as e:
        _cdn_mon_status["state"] = f"error: {e}"
        _cdn_mon_current = ""
        _cdn_mon_log_msg(f"Scan FAILED: {e}")
        if scan_id:
            try:
                cur.execute("""
                    UPDATE cdn_version_scans SET
                        completed_at = NOW(), status = 'error',
                        errors = %s,
                        duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))
                    WHERE id = %s
                """, (psycopg2.extras.Json([str(e)[:200]]), scan_id))
                conn.commit()
            except Exception:
                pass
    finally:
        _cdn_mon_active = False
        conn.close()


@app.route("/api/v1/admin/cdn-monitor/scan", methods=["POST"])
@require_auth
def admin_cdn_monitor_scan(conn=None, cur=None, contributor=None, api_key=None):
    """Trigger CDN version scan. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    global _cdn_mon_active
    if _cdn_mon_active:
        return jsonify(error="Scan already running", status=_cdn_mon_status), 409
    data = request.get_json(silent=True) or {}
    scan_type = data.get("type", "full")
    xbl3 = None
    if scan_type != "purge_check":
        try:
            xbl3 = _cdn_mon_get_update_token(cur, conn, contributor["id"])
            _cdn_mon_log_msg(f"Update token acquired ({len(xbl3)} chars)")
        except Exception as e:
            return jsonify(error=f"Auth failed: {e}"), 401
    _cdn_mon_active = True
    _cdn_mon_log.clear()
    threading.Thread(target=_bg_cdn_version_scan, args=(xbl3, scan_type), daemon=True).start()
    return jsonify(ok=True, message=f"CDN version scan triggered ({scan_type})")


@app.route("/api/v1/admin/cdn-monitor/scans", methods=["GET"])
@require_auth
def admin_cdn_monitor_scans(conn=None, cur=None, contributor=None, api_key=None):
    """Recent CDN version scans. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    cur.execute("""
        SELECT s.*,
               (SELECT COUNT(*) FROM cdn_version_changes c WHERE c.scan_id = s.id AND c.change_type = 'new_version') AS new_count,
               (SELECT COUNT(*) FROM cdn_version_changes c WHERE c.scan_id = s.id AND c.change_type = 'purged') AS purge_count
        FROM cdn_version_scans s
        ORDER BY s.started_at DESC LIMIT 50
    """)
    scans = [dict(r) for r in cur.fetchall()]
    for sc in scans:
        for k in ("started_at", "completed_at"):
            if sc.get(k):
                sc[k] = sc[k].isoformat()
    return jsonify(scans=scans)


@app.route("/api/v1/admin/cdn-monitor/status", methods=["GET"])
@require_auth
def admin_cdn_monitor_status(conn=None, cur=None, contributor=None, api_key=None):
    """Live CDN monitor status. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    try:
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_version_snapshots")
        total_v = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_version_snapshots WHERE status = 'live'")
        live_v = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_version_snapshots WHERE status = 'purged'")
        purged_v = cur.fetchone()["cnt"]
        cur.execute("SELECT COUNT(DISTINCT content_id) as cnt FROM cdn_version_snapshots")
        tracked = cur.fetchone()["cnt"]
    except Exception:
        total_v = live_v = purged_v = tracked = 0
    return jsonify(
        active=_cdn_mon_active,
        scanStatus=_cdn_mon_status,
        currentContentId=_cdn_mon_current,
        log=_cdn_mon_log[-200:],
        dbStats={"totalVersions": total_v, "liveVersions": live_v,
                 "purgedVersions": purged_v, "trackedContentIds": tracked})


@app.route("/api/v1/admin/cdn-monitor/purged", methods=["GET"])
@require_auth
def admin_cdn_monitor_purged(conn=None, cur=None, contributor=None, api_key=None):
    """All purged versions. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    cur.execute("""
        SELECT s.content_id, s.store_id, s.version, s.build_id,
               s.cdn_url, s.file_size, s.filename,
               s.first_seen_at, s.purged_at
        FROM cdn_version_snapshots s
        WHERE s.status = 'purged'
        ORDER BY s.purged_at DESC NULLS LAST
        LIMIT 500
    """)
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        for k in ("first_seen_at", "purged_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    return jsonify(purged=rows)


@app.route("/api/v1/admin/cdn-monitor/stop", methods=["POST"])
@require_auth
def admin_cdn_monitor_stop(conn=None, cur=None, contributor=None, api_key=None):
    """Stop CDN version scan. Freshdex admin only."""
    global _cdn_mon_active
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    _cdn_mon_active = False
    _cdn_mon_log_msg("Scan stop requested by admin")
    return jsonify(status="ok", message="Stop signal sent")


# ---------------------------------------------------------------------------
# CORS (allow xct.freshdex.app frontend)
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    allowed = {"https://xct.freshdex.app", "https://xct.live", "http://localhost:5001", "http://127.0.0.1:5001"}
    if origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.route("/api/v1/collection/upload", methods=["OPTIONS"])
@app.route("/api/v1/collection", methods=["OPTIONS"])
@app.route("/api/v1/register", methods=["OPTIONS"])
@app.route("/api/v1/xbox/achievements", methods=["OPTIONS"])
@app.route("/api/v1/xbox/achievements/refresh", methods=["OPTIONS"])
@app.route("/api/v1/xbox/auth/disconnect", methods=["OPTIONS"])
@app.route("/api/v1/xbox/auth/status", methods=["OPTIONS"])
@app.route("/api/v1/leaderboard/scrape", methods=["OPTIONS"])
@app.route("/api/v1/leaderboard/scan", methods=["OPTIONS"])
@app.route("/api/v1/leaderboard/admin", methods=["OPTIONS"])
@app.route("/api/v1/leaderboard/stop", methods=["OPTIONS"])
@app.route("/api/v1/profile", methods=["OPTIONS"])
@app.route("/api/v1/admin/changelog", methods=["OPTIONS"])
@app.route("/api/v1/admin/scans", methods=["OPTIONS"])
@app.route("/api/v1/admin/scan", methods=["OPTIONS"])
@app.route("/api/v1/admin/subs", methods=["OPTIONS"])
@app.route("/api/v1/admin/scans/<int:scan_id>/changelog", methods=["OPTIONS"])
@app.route("/api/v1/store/filters", methods=["OPTIONS"])
@app.route("/api/v1/store/products", methods=["OPTIONS"])
@app.route("/api/v1/store/product/<product_id>", methods=["OPTIONS"])
@app.route("/api/v1/store/editions/<xbox_title_id>", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/scan", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/scans", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/status", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/purged", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/stop", methods=["OPTIONS"])
def cors_preflight():
    return Response(status=204)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
