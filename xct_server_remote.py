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

import base64
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
import requests as _requests_lib
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
    # Add cached_response column for pre-built GET responses (migration)
    try:
        cur = conn.cursor()
        cur.execute("""
            ALTER TABLE user_collections ADD COLUMN IF NOT EXISTS cached_response BYTEA
        """)
        conn.commit()
    except Exception:
        conn.rollback()
    # X (Twitter) profile columns on developer/publisher profiles (migration)
    for _tbl in ("developer_profiles", "publisher_profiles"):
        try:
            cur = conn.cursor()
            cur.execute(f"""
                ALTER TABLE {_tbl}
                    ADD COLUMN IF NOT EXISTS x_id TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_handle TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_name TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_bio TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_followers INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS x_following INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS x_tweet_count INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS x_listed_count INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS x_profile_image TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_banner_image TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_location TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_url TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_verified BOOLEAN DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS x_created_at TEXT DEFAULT '',
                    ADD COLUMN IF NOT EXISTS x_updated_at TIMESTAMPTZ,
                    ADD COLUMN IF NOT EXISTS x_list_url TEXT DEFAULT ''
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
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_ms_product_id ON marketplace_subscriptions(product_id);
            CREATE INDEX IF NOT EXISTS idx_mt_product_id ON marketplace_tags(product_id);
            CREATE INDEX IF NOT EXISTS idx_mc_product_id ON marketplace_channels(product_id);
            CREATE INDEX IF NOT EXISTS idx_al_product_id ON amazon_links(product_id);
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
    # Amazon physical disc links (admin-curated)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS amazon_links (
                product_id   VARCHAR(16) PRIMARY KEY,
                status       VARCHAR(16) NOT NULL DEFAULT 'digital',
                url_uk       TEXT NOT NULL DEFAULT '',
                url_us       TEXT NOT NULL DEFAULT '',
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Amazon links table init failed ({e}) — run migration manually")
    # Physical disc links (multi-locale, multi-link per product)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS physical_links (
                id          SERIAL PRIMARY KEY,
                product_id  VARCHAR(16) NOT NULL,
                locale      VARCHAR(5) NOT NULL,
                url         TEXT NOT NULL,
                label       TEXT NOT NULL DEFAULT '',
                added_by    INTEGER,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_physical_links_pid
            ON physical_links(product_id)
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Physical links table init failed ({e}) — run migration manually")
    # Disc ownership (per-user "I own this disc" flags)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS disc_ownership (
                contributor_id INTEGER NOT NULL,
                product_id     VARCHAR(16) NOT NULL,
                created_at     TIMESTAMPTZ DEFAULT NOW(),
                PRIMARY KEY (contributor_id, product_id)
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_disc_ownership_pid
            ON disc_ownership(product_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_disc_ownership_cid
            ON disc_ownership(contributor_id)
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Disc ownership table init failed ({e}) — run migration manually")
    # Shared title ID database (community-contributed from collection uploads)
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS title_id_db (
                xbox_title_id  VARCHAR(20) PRIMARY KEY,
                title          TEXT NOT NULL DEFAULT '',
                category       TEXT NOT NULL DEFAULT '',
                product_kind   TEXT NOT NULL DEFAULT '',
                platforms      TEXT[] NOT NULL DEFAULT '{}',
                publisher      TEXT NOT NULL DEFAULT '',
                developer      TEXT NOT NULL DEFAULT '',
                image_url      TEXT NOT NULL DEFAULT '',
                is_invalid     BOOLEAN NOT NULL DEFAULT FALSE,
                notes          TEXT NOT NULL DEFAULT '',
                seen_count     INTEGER NOT NULL DEFAULT 1,
                first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[!] Title ID DB table init failed ({e}) — run migration manually")
    finally:
        conn.close()


with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"[!] DB init skipped ({e}) — will retry on first request")

# Static HTML is pre-generated by gen_static.py (runs before gunicorn in start.sh).
# Nginx serves /app/static/index.html directly — Flask index() is the fallback.


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
_cached_data_js_etag = None
_cached_data_js_time = 0
DATA_JS_CACHE_TTL = 300  # 5 minutes

@app.route("/data.js")
def data_js():
    """Serve shared data as JS constants, matching write_data_js() format."""
    global _cached_data_js_gz, _cached_data_js_etag, _cached_data_js_time
    import time as _time

    now = _time.time()
    if _cached_data_js_gz and (now - _cached_data_js_time) < DATA_JS_CACHE_TTL:
        # ETag 304 support
        client_etag = request.headers.get("If-None-Match", "")
        if client_etag and client_etag == _cached_data_js_etag:
            return Response(status=304, headers={
                "ETag": _cached_data_js_etag,
                "Cache-Control": "public, max-age=300",
            })
        if "gzip" in request.headers.get("Accept-Encoding", ""):
            return Response(_cached_data_js_gz, status=200, headers={
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Encoding": "gzip",
                "Cache-Control": "public, max-age=300",
                "ETag": _cached_data_js_etag,
            })
        return Response(gzip.decompress(_cached_data_js_gz), status=200, headers={
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
            "ETag": _cached_data_js_etag,
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

        _rates_raw = _load_shared("rates", {})
        rates = _rates_raw.get("rates", _rates_raw) if isinstance(_rates_raw, dict) else {}
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
        _cached_data_js_etag = '"' + hashlib.md5(_cached_data_js_gz).hexdigest() + '"'
        del js_bytes
        _cached_data_js_time = now

        if "gzip" in request.headers.get("Accept-Encoding", ""):
            return Response(_cached_data_js_gz, status=200, headers={
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Encoding": "gzip",
                "Cache-Control": "public, max-age=300",
                "ETag": _cached_data_js_etag,
            })
        return Response(js, status=200, headers={
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
            "ETag": _cached_data_js_etag,
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
    "nameDesc":     ("p.title DESC", False),
    "priceAsc":     ("pr_us.msrp ASC NULLS LAST, p.title ASC", True),
    "priceDesc":    ("pr_us.msrp DESC NULLS LAST, p.title ASC", True),
    "bestAsc":      ("p.best_gc_usd ASC NULLS LAST, p.title ASC", False),
    "bestDesc":     ("p.best_gc_usd DESC NULLS LAST, p.title ASC", False),
    "ratingDesc":   ("p.average_rating DESC, p.title ASC", False),
    "ratingCntDesc":("p.rating_count DESC, p.title ASC", False),
    "mcDesc":       ("p.metacritic_score DESC NULLS LAST, p.title ASC", False),
    "mcAsc":        ("p.metacritic_score ASC NULLS LAST, p.title ASC", False),
    "platCntDesc":  ("array_length(p.platforms, 1) DESC NULLS LAST, p.title ASC", False),
    "pub":          ("p.publisher ASC, p.title ASC", False),
    "pubDesc":      ("p.publisher DESC, p.title ASC", False),
    "dev":          ("p.developer ASC, p.title ASC", False),
    "devDesc":      ("p.developer DESC, p.title ASC", False),
    "cat":          ("p.category ASC, p.title ASC", False),
}


@app.route("/api/v1/store/filters")
def store_filters():
    """Dropdown options with global counts. Cached 5 min server-side.

    ?fields=publishers,developers  — lazy-load only the heavy dropdown data.
    Without ?fields, returns everything except publishers/developers.
    """
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        fields_raw = request.args.get("fields", "")

        # Check in-memory cache
        now = time.time()
        cache_key = "store_filters" + ("_" + fields_raw if fields_raw else "")
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

        # Lazy mode: ?fields=publishers,developers — fetch ONLY those, skip everything else
        if fields_raw:
            lazy_result = {}
            field_list = [f.strip() for f in fields_raw.split(",")]
            if "publishers" in field_list:
                cur.execute("""
                    SELECT publisher AS value, COUNT(*) AS count
                    FROM marketplace_products WHERE title != product_id AND publisher != ''
                    GROUP BY publisher ORDER BY count DESC
                """)
                lazy_result["publishers"] = [dict(r) for r in cur.fetchall()]
            if "developers" in field_list:
                cur.execute("""
                    SELECT developer AS value, COUNT(*) AS count
                    FROM marketplace_products WHERE title != product_id AND developer != ''
                    GROUP BY developer ORDER BY count DESC
                """)
                lazy_result["developers"] = [dict(r) for r in cur.fetchall()]
            return _gzip_json_response(lazy_result, cache_key=cache_key)

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
        # Add virtual "Windows Only" platform (PC without any Xbox console)
        cur.execute("""
            SELECT COUNT(*) AS count FROM marketplace_products
            WHERE title != product_id AND 'PC' = ANY(platforms)
            AND NOT ('Xbox One' = ANY(platforms))
            AND NOT ('Xbox Series X|S' = ANY(platforms))
            AND NOT ('Xbox 360' = ANY(platforms))
        """)
        winonly_cnt = cur.fetchone()["count"]
        if winonly_cnt:
            platforms.append({"value": "Windows Only", "count": winonly_cnt})

        # Categories
        cur.execute("""
            SELECT category AS value, COUNT(*) AS count
            FROM marketplace_products WHERE title != product_id AND category != ''
            GROUP BY category ORDER BY count DESC
        """)
        categories = [dict(r) for r in cur.fetchall()]

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

        # Price brackets
        cur.execute("""
            SELECT 'free' AS value, COUNT(*) AS count FROM marketplace_products p
                JOIN marketplace_prices pr ON pr.product_id = p.product_id AND pr.market = 'US'
                WHERE p.title != p.product_id AND pr.msrp = 0
            UNION ALL
            SELECT 'under10', COUNT(*) FROM marketplace_products p
                JOIN marketplace_prices pr ON pr.product_id = p.product_id AND pr.market = 'US'
                WHERE p.title != p.product_id AND pr.msrp > 0 AND pr.msrp < 10
            UNION ALL
            SELECT 'under20', COUNT(*) FROM marketplace_products p
                JOIN marketplace_prices pr ON pr.product_id = p.product_id AND pr.market = 'US'
                WHERE p.title != p.product_id AND pr.msrp > 0 AND pr.msrp < 20
            UNION ALL
            SELECT 'under40', COUNT(*) FROM marketplace_products p
                JOIN marketplace_prices pr ON pr.product_id = p.product_id AND pr.market = 'US'
                WHERE p.title != p.product_id AND pr.msrp > 0 AND pr.msrp < 40
            UNION ALL
            SELECT 'over40', COUNT(*) FROM marketplace_products p
                JOIN marketplace_prices pr ON pr.product_id = p.product_id AND pr.market = 'US'
                WHERE p.title != p.product_id AND pr.msrp >= 40
            UNION ALL
            SELECT 'sale', COUNT(DISTINCT sp.product_id) FROM marketplace_prices sp
                JOIN marketplace_products p ON p.product_id = sp.product_id AND p.title != p.product_id
                WHERE sp.sale_price > 0 AND sp.sale_price < sp.msrp
        """)
        price_counts = {r["value"]: r["count"] for r in cur.fetchall()}

        # Multiplayer capabilities
        cur.execute("""
            SELECT cap, COUNT(*) AS count FROM (
                SELECT UNNEST(capabilities) AS cap FROM marketplace_products WHERE title != product_id
            ) sub WHERE cap IN ('XblOnlineMultiplayer','OnlineMultiplayer',
                'XblLocalMultiplayer','LocalMultiplayer',
                'XblOnlineCoop','OnlineCoop',
                'XblLocalCoop','LocalCoop',
                'XblCrossGenMultiplayer','CrossGen')
            GROUP BY cap
        """)
        mp_raw_counts = {r["cap"]: r["count"] for r in cur.fetchall()}
        mp_counts = {
            "online": mp_raw_counts.get("XblOnlineMultiplayer", 0) + mp_raw_counts.get("OnlineMultiplayer", 0),
            "local": mp_raw_counts.get("XblLocalMultiplayer", 0) + mp_raw_counts.get("LocalMultiplayer", 0),
            "coop": mp_raw_counts.get("XblOnlineCoop", 0) + mp_raw_counts.get("OnlineCoop", 0),
            "localcoop": mp_raw_counts.get("XblLocalCoop", 0) + mp_raw_counts.get("LocalCoop", 0),
            "crossgen": mp_raw_counts.get("XblCrossGenMultiplayer", 0) + mp_raw_counts.get("CrossGen", 0),
        }

        # Single-pass counts: bundles, booleans, release, total
        # Replaces 4 separate queries with one scan of marketplace_products
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE is_bundle = TRUE) AS bundles,
                COUNT(*) FILTER (WHERE is_bundle = FALSE) AS notbundle,
                COUNT(*) FILTER (WHERE xcloud_streamable = TRUE) AS xcloud,
                COUNT(*) FILTER (WHERE has_trial_sku = TRUE) AS trial,
                COUNT(*) FILTER (WHERE has_achievements = TRUE) AS ach,
                COUNT(*) FILTER (WHERE has_price AND release_date IS NOT NULL
                    AND release_date <= CURRENT_DATE
                    AND EXTRACT(YEAR FROM release_date) < 2100) AS released,
                COUNT(*) FILTER (WHERE has_price AND release_date > CURRENT_DATE
                    AND EXTRACT(YEAR FROM release_date) < 2100) AS preorder,
                COUNT(*) FILTER (WHERE NOT has_price) AS no_price
            FROM (
                SELECT p.*,
                    EXISTS (SELECT 1 FROM marketplace_prices rp
                        WHERE rp.product_id = p.product_id AND rp.msrp > 0) AS has_price
                FROM marketplace_products p WHERE p.title != p.product_id
            ) sub
        """)
        counts = dict(cur.fetchone())
        total = counts["total"]
        bundle_counts = {"bundles": counts["bundles"], "notbundle": counts["notbundle"]}
        bool_counts = {"xcloud": counts["xcloud"], "trial": counts["trial"], "ach": counts["ach"]}
        release_counts = {"released": counts["released"], "preorder": counts["preorder"],
                          "noPrice": counts["no_price"]}

        # Physical disc counts (separate table, tiny and fast)
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE status IN ('uk','us','both','ta_physical')) AS physical,
                COUNT(*) FILTER (WHERE status IN ('uk','both')) AS uk,
                COUNT(*) FILTER (WHERE status IN ('us','both')) AS us,
                COUNT(*) FILTER (WHERE status = 'digital') AS digital
            FROM amazon_links
        """)
        pc = dict(cur.fetchone())
        pc["notscanned"] = total - (pc["physical"] + pc["digital"])
        phys_counts = pc

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
            "categories": categories, "subscriptions": subscriptions,
            "priceCounts": price_counts, "mpCounts": mp_counts,
            "bundleCounts": bundle_counts, "physCounts": phys_counts,
            "releaseCounts": release_counts, "boolCounts": bool_counts,
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

        # Optional auth for user-specific filters (disc ownership)
        contributor = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            api_key = auth[7:].strip()
            if api_key:
                contributor = _get_contributor(cur, api_key)

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
        phys_raw = request.args.get("phys", "")
        mc_raw = request.args.get("mc", "")

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

        # Check for _none_ sentinel in any filter (means "nothing selected" → zero results)
        # Exclude subs: clearing all subscriptions = no filter (show everything)
        _all_filter_raws = [type_raw, plat_raw, price_raw, cat_raw, mp_raw,
                            pub_raw, dev_raw, own_raw, rel_raw, bundle_raw, phys_raw, regions_raw]
        if any(v == "_none_" for v in _all_filter_raws):
            wheres.append("FALSE")

        # Type filter (map DLC → Durable for DB)
        if type_raw and type_raw != "_none_":
            t_list = [t.strip() for t in type_raw.split(",") if t.strip()]
            db_types = ["Durable" if t == "DLC" else t for t in t_list]
            if db_types:
                wheres.append("p.product_kind = ANY(%(types)s)")
                params["types"] = db_types

        # Platform filter (GIN array overlap — game must have at least one selected platform)
        if plat_raw:
            p_list = [p.strip() for p in plat_raw.split(",") if p.strip()]
            if p_list:
                # "Windows Only" is a virtual platform: PC present, no Xbox consoles
                has_winonly = "Windows Only" in p_list
                real_plats = [p for p in p_list if p != "Windows Only"]
                plat_conds = []
                if real_plats:
                    plat_conds.append("p.platforms && %(platforms)s")
                    params["platforms"] = real_plats
                if has_winonly:
                    plat_conds.append(
                        "('PC' = ANY(p.platforms) "
                        "AND NOT ('Xbox One' = ANY(p.platforms)) "
                        "AND NOT ('Xbox Series X|S' = ANY(p.platforms)) "
                        "AND NOT ('Xbox 360' = ANY(p.platforms)))")
                if plat_conds:
                    wheres.append("(" + " OR ".join(plat_conds) + ")")
                # Xbox 360 BC games are tagged with Xbox One/Series by Microsoft.
                # If Xbox 360 is NOT selected, explicitly exclude them.
                if "Xbox 360" not in p_list and not has_winonly:
                    wheres.append("NOT ('Xbox 360' = ANY(p.platforms))")

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
        # _none_ means all unchecked → exclude subscription games (show only non-sub)
        if subs_raw == "_none_":
            none_cond = (
                "NOT EXISTS (SELECT 1 FROM marketplace_subscriptions ms2 "
                "WHERE ms2.product_id = p.product_id)")
            if _gp_pids:
                none_cond = "(" + none_cond + " AND NOT (p.product_id = ANY(%(gp_pids_nosub)s)))"
                params["gp_pids_nosub"] = list(_gp_pids)
            wheres.append(none_cond)
        elif subs_raw:
            s_list = [s.strip() for s in subs_raw.split(",") if s.strip()]
            subs_conds = []
            # Collect actual tier names for DB query
            tier_names = [s for s in s_list if s not in ("gp", "ea")]
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
            # Backward compat: old "notowned" → "notowned_digital"
            o_list = ["notowned_digital" if o == "notowned" else o for o in o_list]
            own_conds = []
            # Owned on Digital
            if "owned" in o_list and owned_pids is not None:
                own_conds.append("p.product_id = ANY(%(owned_pids)s)")
                params["owned_pids"] = list(owned_pids)
            # Not Owned on Digital
            if "notowned_digital" in o_list and owned_pids is not None:
                own_conds.append("NOT (p.product_id = ANY(%(notowned_pids)s))")
                params["notowned_pids"] = list(owned_pids)
            # Owned on Disc
            if "discowned" in o_list and contributor:
                own_conds.append(
                    "EXISTS (SELECT 1 FROM disc_ownership dsc "
                    "WHERE dsc.product_id = p.product_id "
                    "AND dsc.contributor_id = %(disc_cid)s)")
                params["disc_cid"] = contributor["id"]
            # Not Owned on Disc
            if "notowned_disc" in o_list and contributor:
                own_conds.append(
                    "NOT EXISTS (SELECT 1 FROM disc_ownership dsc "
                    "WHERE dsc.product_id = p.product_id "
                    "AND dsc.contributor_id = %(notowned_disc_cid)s)")
                params["notowned_disc_cid"] = contributor["id"]
            if own_conds:
                wheres.append("(" + " OR ".join(own_conds) + ")")

        # Hide owned editions — exclude unowned products sharing a title ID
        # with any digitally-owned or disc-owned product
        if hide_owned_ed == "1" and owned_pids:
            # Get title IDs of digitally owned products
            cur.execute(
                "SELECT DISTINCT xbox_title_id FROM marketplace_products "
                "WHERE product_id = ANY(%s) AND xbox_title_id != ''",
                (list(owned_pids),))
            owned_tids = set(row["xbox_title_id"] for row in cur.fetchall())
            # Also include title IDs from disc-owned products
            if contributor:
                cur.execute(
                    "SELECT DISTINCT mp.xbox_title_id "
                    "FROM disc_ownership dsc "
                    "JOIN marketplace_products mp ON mp.product_id = dsc.product_id "
                    "WHERE dsc.contributor_id = %s AND mp.xbox_title_id != ''",
                    (contributor["id"],))
                owned_tids.update(row["xbox_title_id"] for row in cur.fetchall())
            # Combine digital + disc owned product IDs for the exclusion check
            hoe_pids = set(owned_pids)
            if contributor:
                cur.execute(
                    "SELECT product_id FROM disc_ownership "
                    "WHERE contributor_id = %s",
                    (contributor["id"],))
                hoe_pids.update(row["product_id"] for row in cur.fetchall())
            if owned_tids:
                wheres.append(
                    "NOT (p.xbox_title_id = ANY(%(owned_tids)s) "
                    "AND NOT p.product_id = ANY(%(hoe_owned_pids)s))")
                params["owned_tids"] = list(owned_tids)
                params["hoe_owned_pids"] = list(hoe_pids)

        # Release status
        if rel_raw:
            r_list = [r.strip() for r in rel_raw.split(",") if r.strip()]
            rel_conds = []
            if "released" in r_list:
                rel_conds.append(
                    "((p.release_date IS NOT NULL AND p.release_date <= CURRENT_DATE "
                    "AND EXTRACT(YEAR FROM p.release_date) < 2100 "
                    "AND EXISTS (SELECT 1 FROM marketplace_prices rp "
                    "WHERE rp.product_id = p.product_id AND rp.msrp > 0)) "
                    "OR (EXTRACT(YEAR FROM p.release_date) >= 2100 "
                    "AND EXISTS (SELECT 1 FROM marketplace_prices rp "
                    "WHERE rp.product_id = p.product_id AND rp.msrp > 0)))")
            if "preorder" in r_list:
                rel_conds.append(
                    "(p.release_date > CURRENT_DATE AND EXTRACT(YEAR FROM p.release_date) < 2100 "
                    "AND EXISTS (SELECT 1 FROM marketplace_prices rp "
                    "WHERE rp.product_id = p.product_id AND rp.msrp > 0))")
            if "noPrice" in r_list:
                rel_conds.append(
                    "(NOT EXISTS (SELECT 1 FROM marketplace_prices rp "
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

        # Physical disc filter (amazon_links table)
        if phys_raw:
            ph_list = [v.strip() for v in phys_raw.split(",") if v.strip()]
            phys_conds = []
            if "physical" in ph_list:
                phys_conds.append(
                    "EXISTS (SELECT 1 FROM amazon_links al "
                    "WHERE al.product_id = p.product_id "
                    "AND al.status IN ('uk','us','both','ta_physical'))")
            if "uk" in ph_list:
                phys_conds.append(
                    "EXISTS (SELECT 1 FROM amazon_links al "
                    "WHERE al.product_id = p.product_id "
                    "AND al.status IN ('uk','both'))")
            if "us" in ph_list:
                phys_conds.append(
                    "EXISTS (SELECT 1 FROM amazon_links al "
                    "WHERE al.product_id = p.product_id "
                    "AND al.status IN ('us','both'))")
            if "digital" in ph_list:
                phys_conds.append(
                    "EXISTS (SELECT 1 FROM amazon_links al "
                    "WHERE al.product_id = p.product_id "
                    "AND al.status = 'digital')")
            if "notscanned" in ph_list:
                phys_conds.append(
                    "NOT EXISTS (SELECT 1 FROM amazon_links al "
                    "WHERE al.product_id = p.product_id)")
            if phys_conds:
                wheres.append("(" + " OR ".join(phys_conds) + ")")


        # Boolean checkboxes
        if xcloud == "1":
            wheres.append("p.xcloud_streamable = TRUE")
        if trial == "1":
            wheres.append("p.has_trial_sku = TRUE")
        if ach == "1":
            wheres.append("(p.has_achievements = TRUE OR 'Xbox 360' = ANY(p.platforms))")

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
                        "SELECT xbox_title_id, product_id "
                        "FROM xbox_achievement_summaries "
                        "WHERE contributor_id = %s AND current_achievements > 0",
                        (contributor["id"],))
                    ach_rows = cur.fetchall()
                    ach_tids = [r["xbox_title_id"] for r in ach_rows if r["xbox_title_id"]]
                    ach_pids = [r["product_id"] for r in ach_rows if r["product_id"]]
                    if ach_tids or ach_pids:
                        parts = []
                        if ach_tids:
                            parts.append("(p.xbox_title_id = '' OR p.xbox_title_id != ALL(%(ach_tids)s))")
                            params["ach_tids"] = ach_tids
                        if ach_pids:
                            parts.append("p.product_id != ALL(%(ach_pids)s)")
                            params["ach_pids"] = ach_pids
                        wheres.append("(" + " AND ".join(parts) + ")")

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

        # Metacritic score filter
        if mc_raw:
            mc_parts = [x.strip() for x in mc_raw.split(",") if x.strip()]
            mc_conds = []
            for mc_val in mc_parts:
                if mc_val == "mc90":
                    mc_conds.append("p.metacritic_score >= 90")
                elif mc_val == "mc75":
                    mc_conds.append("(p.metacritic_score >= 75 AND p.metacritic_score < 90)")
                elif mc_val == "mc50":
                    mc_conds.append("(p.metacritic_score >= 50 AND p.metacritic_score < 75)")
                elif mc_val == "mcLow":
                    mc_conds.append("p.metacritic_score < 50")
                elif mc_val == "mcAny":
                    mc_conds.append("p.metacritic_score IS NOT NULL")
                elif mc_val == "mcNone":
                    mc_conds.append("p.metacritic_score IS NULL")
            if mc_conds:
                wheres.append("(" + " OR ".join(mc_conds) + ")")

        where_sql = " AND ".join(wheres)

        # Build main query
        join_clause = (
            "LEFT JOIN marketplace_prices pr_us "
            "ON pr_us.product_id = p.product_id AND pr_us.market = 'US'")
        # Count query only needs the price join if WHERE references pr_us
        count_join = join_clause if "pr_us" in where_sql else ""

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
                       p.metacritic_score,
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
                       ) - 1 AS alt_count
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
                       p.metacritic_score,
                       pr_us.msrp AS price_usd,
                       CASE WHEN pr_us.sale_price > 0 AND pr_us.sale_price < pr_us.msrp
                            THEN pr_us.sale_price ELSE NULL END AS current_price_usd
                FROM marketplace_products p
                {join_clause}
                WHERE {where_sql}
                ORDER BY {sort_sql}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            count_sql = f"""
                SELECT COUNT(*) AS cnt
                FROM marketplace_products p
                {count_join}
                WHERE {where_sql}
            """

        params["limit"] = per_page
        params["offset"] = page * per_page

        cur.execute(sql, params)
        rows = cur.fetchall()

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
                "metacriticScore": r["metacritic_score"],
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
            "availableRegions": list(regional.keys()) if regional else [],
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
# Amazon Physical Disc Links (admin-curated)
# ---------------------------------------------------------------------------

@app.route("/api/v1/store/amazon/bulk")
def store_amazon_bulk():
    """Return all amazon_links rows for the current page of products."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        pids_raw = request.args.get("pids", "")
        if not pids_raw:
            return _gzip_json_response({})
        pids = [p.strip() for p in pids_raw.split(",") if p.strip()][:200]
        cur.execute(
            "SELECT product_id, status, url_uk, url_us FROM amazon_links "
            "WHERE product_id = ANY(%s)", (pids,))
        result = {}
        for r in cur.fetchall():
            result[r["product_id"]] = {
                "status": r["status"],
                "urlUK": r["url_uk"],
                "urlUS": r["url_us"],
            }
        return _gzip_json_response(result)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/store/amazon/hits")
@require_auth
def store_amazon_hits(contributor, conn, cur, api_key):
    """Return all non-digital amazon_links (positive hits) with game titles."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    cur.execute("""
        SELECT al.product_id, al.status, al.url_uk, al.url_us,
               COALESCE(mp.title, '') as title
        FROM amazon_links al
        LEFT JOIN marketplace_products mp ON mp.product_id = al.product_id
        WHERE al.status != 'digital'
        ORDER BY mp.title
    """)
    hits = []
    for r in cur.fetchall():
        hits.append({
            "productId": r["product_id"],
            "status": r["status"],
            "urlUK": r["url_uk"],
            "urlUS": r["url_us"],
            "title": r["title"],
        })
    return _gzip_json_response(hits)


@app.route("/api/v1/store/amazon/set", methods=["POST"])
@require_auth
def store_amazon_set(contributor, conn, cur, api_key):
    """Admin-only: set physical disc status for a product."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    body = request.get_json(force=True) or {}
    pid = body.get("productId", "").strip()
    status = body.get("status", "").strip()
    url_uk = body.get("urlUK", "").strip()
    url_us = body.get("urlUS", "").strip()
    if not pid or status not in ("digital", "uk", "us", "both"):
        return jsonify(error="productId and valid status required"), 400
    cur.execute(
        "INSERT INTO amazon_links (product_id, status, url_uk, url_us, updated_at) "
        "VALUES (%s, %s, %s, %s, NOW()) "
        "ON CONFLICT (product_id) DO UPDATE SET status=%s, url_uk=%s, url_us=%s, updated_at=NOW()",
        (pid, status, url_uk, url_us, status, url_uk, url_us))
    conn.commit()
    return jsonify(ok=True)


@app.route("/api/v1/store/amazon/remove", methods=["POST"])
@require_auth
def store_amazon_remove(contributor, conn, cur, api_key):
    """Admin-only: remove physical disc status for a product."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    body = request.get_json(force=True) or {}
    pid = body.get("productId", "").strip()
    if not pid:
        return jsonify(error="productId required"), 400
    cur.execute("DELETE FROM amazon_links WHERE product_id = %s", (pid,))
    conn.commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Developers & Publishers — aggregated directory listing
# ---------------------------------------------------------------------------

_ENTITY_SORT_MAP = {
    "games": "game_count DESC",
    "gamesAsc": "game_count ASC",
    "name": "entity_name ASC",
    "nameDesc": "entity_name DESC",
    "products": "product_count DESC",
    "productsAsc": "product_count ASC",
    "rating": "avg_rating DESC NULLS LAST",
    "ratingAsc": "avg_rating ASC NULLS LAST",
    "metacritic": "avg_metacritic DESC NULLS LAST",
    "metacriticAsc": "avg_metacritic ASC NULLS LAST",
    "newest": "newest_release DESC NULLS LAST",
    "oldest": "oldest_release ASC NULLS LAST",
    "xFollowers": "x_followers DESC NULLS LAST",
    "xFollowersAsc": "x_followers ASC NULLS LAST",
}


def _entity_listing(entity_type):
    """Shared logic for /developers and /publishers listing."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        col = "developer" if entity_type == "developer" else "publisher"
        profile_table = "developer_profiles" if entity_type == "developer" else "publisher_profiles"

        page = max(0, request.args.get("page", 0, type=int))
        per_page = min(max(1, request.args.get("per_page", 50, type=int)), 200)
        q = (request.args.get("q") or "").strip()
        sort_key = request.args.get("sort", "games")
        sort_sql = _ENTITY_SORT_MAP.get(sort_key, "game_count DESC")

        wheres = [f"p.{col} != ''", "p.title != p.product_id"]
        params = {}

        if q:
            wheres.append(f"p.{col} ILIKE %(q)s")
            params["q"] = f"%{q}%"

        where_sql = " AND ".join(wheres)

        # Main aggregation query
        sql = f"""
            SELECT p.{col} AS entity_name,
                   COUNT(*) AS product_count,
                   COUNT(*) FILTER (WHERE p.product_kind = 'Game') AS game_count,
                   COUNT(*) FILTER (WHERE p.product_kind = 'Durable') AS dlc_count,
                   AVG(p.average_rating) FILTER (WHERE p.average_rating > 0) AS avg_rating,
                   MAX(p.average_rating) FILTER (WHERE p.average_rating > 0) AS max_rating,
                   SUM(p.rating_count) FILTER (WHERE p.rating_count > 0) AS total_ratings,
                   AVG(p.metacritic_score) FILTER (WHERE p.metacritic_score IS NOT NULL) AS avg_metacritic,
                   MAX(p.metacritic_score) AS max_metacritic,
                   COUNT(*) FILTER (WHERE p.metacritic_score IS NOT NULL) AS metacritic_count,
                   MIN(p.release_date) FILTER (WHERE p.release_date IS NOT NULL
                       AND EXTRACT(YEAR FROM p.release_date) < 2100) AS oldest_release,
                   MAX(p.release_date) FILTER (WHERE p.release_date IS NOT NULL
                       AND EXTRACT(YEAR FROM p.release_date) < 2100) AS newest_release,
                   COUNT(*) FILTER (WHERE p.xcloud_streamable) AS xcloud_count,
                   COUNT(*) FILTER (WHERE p.has_achievements) AS ach_count,
                   ARRAY_AGG(DISTINCT unnest_plat) FILTER (WHERE unnest_plat IS NOT NULL) AS all_platforms,
                   MAX(ep.x_followers) AS x_followers
            FROM marketplace_products p
            LEFT JOIN LATERAL UNNEST(p.platforms) AS unnest_plat ON TRUE
            LEFT JOIN {profile_table} ep ON ep.name = p.{col}
            WHERE {where_sql}
            GROUP BY p.{col}
            ORDER BY {sort_sql}
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = per_page
        params["offset"] = page * per_page

        cur.execute(sql, params)
        rows = cur.fetchall()

        # Get total count
        count_sql = f"""
            SELECT COUNT(DISTINCT p.{col}) AS cnt
            FROM marketplace_products p
            WHERE {where_sql}
        """
        cur.execute(count_sql, params)
        total = cur.fetchone()["cnt"]

        # Fetch profile data for these entities
        entity_names = [r["entity_name"] for r in rows]
        profiles = {}
        if entity_names:
            cur.execute(
                f"SELECT * FROM {profile_table} WHERE name = ANY(%(names)s)",
                {"names": entity_names})
            for pr in cur.fetchall():
                profiles[pr["name"]] = pr

        # Fetch a representative image (box art of highest-rated game)
        rep_images = {}
        if entity_names:
            cur.execute(f"""
                SELECT DISTINCT ON (p.{col}) p.{col} AS entity_name,
                       p.image_box_art, p.image_tile
                FROM marketplace_products p
                WHERE p.{col} = ANY(%(names)s) AND p.title != p.product_id
                      AND p.product_kind = 'Game'
                      AND (p.image_box_art != '' OR p.image_tile != '')
                ORDER BY p.{col}, p.average_rating DESC NULLS LAST, p.rating_count DESC NULLS LAST
            """, {"names": entity_names})
            for img_row in cur.fetchall():
                rep_images[img_row["entity_name"]] = img_row["image_box_art"] or img_row["image_tile"] or ""

        # Assemble response
        entities = []
        for r in rows:
            name = r["entity_name"]
            prof = profiles.get(name, {})
            entities.append({
                "name": name,
                "productCount": r["product_count"],
                "gameCount": r["game_count"],
                "dlcCount": r["dlc_count"],
                "avgRating": round(float(r["avg_rating"]), 2) if r["avg_rating"] else None,
                "maxRating": round(float(r["max_rating"]), 2) if r["max_rating"] else None,
                "totalRatings": r["total_ratings"] or 0,
                "avgMetacritic": round(float(r["avg_metacritic"])) if r["avg_metacritic"] else None,
                "maxMetacritic": r["max_metacritic"],
                "metacriticCount": r["metacritic_count"] or 0,
                "oldestRelease": r["oldest_release"].isoformat() if r["oldest_release"] else None,
                "newestRelease": r["newest_release"].isoformat() if r["newest_release"] else None,
                "xcloudCount": r["xcloud_count"] or 0,
                "achievementCount": r["ach_count"] or 0,
                "platforms": sorted(r["all_platforms"]) if r["all_platforms"] else [],
                "logoUrl": prof.get("logo_url", "") or "",
                "bannerUrl": prof.get("banner_url", "") or "",
                "website": prof.get("website", "") or "",
                "twitter": prof.get("twitter", "") or "",
                "youtube": prof.get("youtube", "") or "",
                "discord": prof.get("discord", "") or "",
                "xHandle": prof.get("x_handle", "") or "",
                "xFollowers": prof.get("x_followers") or 0,
                "xProfileImage": prof.get("x_profile_image", "") or "",
                "xVerified": bool(prof.get("x_verified")),
                "xBio": prof.get("x_bio", "") or "",
                "xListUrl": prof.get("x_list_url", "") or "",
                "repImage": rep_images.get(name, ""),
            })

        result = {
            "entities": entities,
            "total": total,
            "page": page,
            "perPage": per_page,
            "totalPages": max(1, -(-total // per_page)),
        }
        return _gzip_json_response(result)
    except Exception as e:
        log.exception(f"{entity_type}_listing error")
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


def _entity_detail(entity_type, name):
    """Shared logic for developer/publisher detail — profile + games list."""
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        col = "developer" if entity_type == "developer" else "publisher"
        profile_table = "developer_profiles" if entity_type == "developer" else "publisher_profiles"

        _refresh_exchange_rates(cur)

        # Profile
        cur.execute(f"SELECT * FROM {profile_table} WHERE name = %s", (name,))
        prof = cur.fetchone() or {}

        # All products by this entity
        cur.execute(f"""
            SELECT p.product_id, p.title, p.publisher, p.developer, p.category,
                   p.release_date, p.platforms, p.product_kind, p.xbox_title_id,
                   p.is_bundle, p.is_ea_play, p.xcloud_streamable,
                   p.has_trial_sku, p.has_achievements,
                   p.image_box_art, p.image_tile, p.image_hero,
                   p.average_rating, p.rating_count,
                   p.metacritic_score, p.metacritic_url,
                   p.best_gc_usd, p.short_description,
                   pr_us.msrp AS price_usd,
                   CASE WHEN pr_us.sale_price > 0 AND pr_us.sale_price < pr_us.msrp
                        THEN pr_us.sale_price ELSE NULL END AS current_price_usd
            FROM marketplace_products p
            LEFT JOIN marketplace_prices pr_us ON pr_us.product_id = p.product_id AND pr_us.market = 'US'
            WHERE p.{col} = %s AND p.title != p.product_id
            ORDER BY p.product_kind ASC, p.release_date DESC NULLS LAST
        """, (name,))
        rows = cur.fetchall()

        # Fetch subscription info
        pids = [r["product_id"] for r in rows]
        subs_map = {}
        if pids:
            cur.execute(
                "SELECT product_id, tier FROM marketplace_subscriptions "
                "WHERE product_id = ANY(%(pids)s)",
                {"pids": pids})
            for s in cur.fetchall():
                subs_map.setdefault(s["product_id"], []).append(s["tier"])

        products = []
        for r in rows:
            pid = r["product_id"]
            products.append({
                "productId": pid,
                "title": r["title"],
                "publisher": r["publisher"],
                "developer": r["developer"],
                "category": r["category"],
                "releaseDate": r["release_date"].isoformat() if r["release_date"] else "",
                "platforms": r["platforms"] or [],
                "productKind": r["product_kind"],
                "isBundle": r["is_bundle"],
                "isEAPlay": r["is_ea_play"],
                "xCloudStreamable": r["xcloud_streamable"],
                "hasAchievements": r["has_achievements"],
                "imageBoxArt": r["image_box_art"] or r["image_tile"] or "",
                "imageHero": r["image_hero"] or "",
                "averageRating": r["average_rating"],
                "ratingCount": r["rating_count"],
                "metacriticScore": r["metacritic_score"],
                "metacriticUrl": r["metacritic_url"] or "",
                "priceUSD": r["price_usd"] or 0,
                "currentPriceUSD": r["current_price_usd"] or 0,
                "subscriptions": subs_map.get(pid, []),
            })

        result = {
            "name": name,
            "profile": {
                "logoUrl": prof.get("logo_url", "") or "",
                "bannerUrl": prof.get("banner_url", "") or "",
                "website": prof.get("website", "") or "",
                "twitter": prof.get("twitter", "") or "",
                "youtube": prof.get("youtube", "") or "",
                "facebook": prof.get("facebook", "") or "",
                "instagram": prof.get("instagram", "") or "",
                "discord": prof.get("discord", "") or "",
                "linkedin": prof.get("linkedin", "") or "",
                "description": prof.get("description", "") or "",
                "country": prof.get("country", "") or "",
                "foundedYear": prof.get("founded_year"),
                "xHandle": prof.get("x_handle", "") or "",
                "xName": prof.get("x_name", "") or "",
                "xBio": prof.get("x_bio", "") or "",
                "xFollowers": prof.get("x_followers") or 0,
                "xFollowing": prof.get("x_following") or 0,
                "xTweetCount": prof.get("x_tweet_count") or 0,
                "xListedCount": prof.get("x_listed_count") or 0,
                "xProfileImage": prof.get("x_profile_image", "") or "",
                "xBannerImage": prof.get("x_banner_image", "") or "",
                "xLocation": prof.get("x_location", "") or "",
                "xUrl": prof.get("x_url", "") or "",
                "xVerified": bool(prof.get("x_verified")),
                "xCreatedAt": prof.get("x_created_at", "") or "",
            },
            "products": products,
            "gameCount": sum(1 for p in products if p["productKind"] == "Game"),
            "dlcCount": sum(1 for p in products if p["productKind"] == "Durable"),
            "totalProducts": len(products),
        }
        return _gzip_json_response(result)
    except Exception as e:
        log.exception(f"{entity_type}_detail error")
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route("/api/v1/store/developers")
def store_developers():
    """Paginated, sorted developer directory."""
    return _entity_listing("developer")


@app.route("/api/v1/store/developer/<path:name>")
def store_developer_detail(name):
    """Developer detail: profile + all products."""
    return _entity_detail("developer", name)


@app.route("/api/v1/store/publishers")
def store_publishers():
    """Paginated, sorted publisher directory."""
    return _entity_listing("publisher")


@app.route("/api/v1/store/publisher/<path:name>")
def store_publisher_detail(name):
    """Publisher detail: profile + all products."""
    return _entity_detail("publisher", name)


# ---------------------------------------------------------------------------
# Physical Disc Links (multi-locale, community-contributed)
# ---------------------------------------------------------------------------

@app.route("/api/v1/store/physical/<product_id>")
@require_auth
def store_physical_get(product_id, contributor, conn, cur, api_key):
    """Get all physical disc links for a product."""
    cur.execute("""
        SELECT id, locale, url, label, created_at
        FROM physical_links WHERE product_id = %s
        ORDER BY locale, created_at
    """, (product_id,))
    links = []
    for r in cur.fetchall():
        links.append({
            "id": r["id"],
            "locale": r["locale"],
            "url": r["url"],
            "label": r["label"],
            "createdAt": r["created_at"].isoformat() if r["created_at"] else None,
        })
    return jsonify(links=links)


@app.route("/api/v1/store/physical/<product_id>", methods=["POST"])
@require_auth
def store_physical_add(product_id, contributor, conn, cur, api_key):
    """Add a physical disc link for a product."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    body = request.get_json(force=True) or {}
    locale = body.get("locale", "").strip().upper()
    url = body.get("url", "").strip()
    label = body.get("label", "").strip()
    if not locale or not url:
        return jsonify(error="locale and url required"), 400
    if len(locale) > 5 or len(url) > 2000:
        return jsonify(error="Invalid input"), 400
    cur.execute("""
        INSERT INTO physical_links (product_id, locale, url, label, added_by)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
    """, (product_id, locale, url, label, contributor["id"]))
    link_id = cur.fetchone()["id"]
    # Auto-sync amazon_links status for filter compatibility
    _sync_amazon_links_from_physical(cur, conn, product_id)
    conn.commit()
    return jsonify(ok=True, id=link_id)


@app.route("/api/v1/store/physical/<int:link_id>", methods=["DELETE"])
@require_auth
def store_physical_delete(link_id, contributor, conn, cur, api_key):
    """Remove a physical disc link."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin only"), 403
    # Get product_id before deleting
    cur.execute("SELECT product_id FROM physical_links WHERE id = %s", (link_id,))
    row = cur.fetchone()
    if not row:
        return jsonify(error="Link not found"), 404
    product_id = row["product_id"]
    cur.execute("DELETE FROM physical_links WHERE id = %s", (link_id,))
    # Re-sync amazon_links
    _sync_amazon_links_from_physical(cur, conn, product_id)
    conn.commit()
    return jsonify(ok=True)


def _sync_amazon_links_from_physical(cur, conn, product_id):
    """Update amazon_links status based on physical_links entries."""
    cur.execute(
        "SELECT DISTINCT locale FROM physical_links WHERE product_id = %s",
        (product_id,))
    locales = {r["locale"] for r in cur.fetchall()}
    if not locales:
        # No physical links — remove amazon_links entry if it was auto-created
        cur.execute(
            "DELETE FROM amazon_links WHERE product_id = %s "
            "AND status NOT IN ('digital', 'ta_physical')", (product_id,))
        return
    has_uk = "GB" in locales
    has_us = "US" in locales
    if has_uk and has_us:
        status = "both"
    elif has_uk:
        status = "uk"
    elif has_us:
        status = "us"
    else:
        # Has links but not UK/US — still physical
        status = "ta_physical"
    # Get first UK/US URLs for backward compat
    url_uk = ""
    url_us = ""
    if has_uk:
        cur.execute(
            "SELECT url FROM physical_links "
            "WHERE product_id = %s AND locale = 'GB' ORDER BY created_at LIMIT 1",
            (product_id,))
        r = cur.fetchone()
        if r:
            url_uk = r["url"]
    if has_us:
        cur.execute(
            "SELECT url FROM physical_links "
            "WHERE product_id = %s AND locale = 'US' ORDER BY created_at LIMIT 1",
            (product_id,))
        r = cur.fetchone()
        if r:
            url_us = r["url"]
    cur.execute("""
        INSERT INTO amazon_links (product_id, status, url_uk, url_us, updated_at)
        VALUES (%s, %s, %s, %s, NOW())
        ON CONFLICT (product_id) DO UPDATE
        SET status = %s, url_uk = %s, url_us = %s, updated_at = NOW()
    """, (product_id, status, url_uk, url_us, status, url_uk, url_us))


# ---------------------------------------------------------------------------
# Disc Ownership (per-user "I own this disc" tracking)
# ---------------------------------------------------------------------------

@app.route("/api/v1/store/disc-owned/bulk")
@require_auth
def disc_owned_bulk(contributor, conn, cur, api_key):
    """Return owned disc product IDs for the current user (for a page of products)."""
    pids_raw = request.args.get("pids", "")
    pids = [p.strip() for p in pids_raw.split(",") if p.strip()][:500]
    if not pids:
        return jsonify(owned=[])
    cur.execute(
        "SELECT product_id FROM disc_ownership "
        "WHERE contributor_id = %s AND product_id = ANY(%s)",
        (contributor["id"], pids))
    owned = [r["product_id"] for r in cur.fetchall()]
    return jsonify(owned=owned)


@app.route("/api/v1/store/disc-owned/all")
@require_auth
def disc_owned_all(contributor, conn, cur, api_key):
    """Return all product IDs the user has marked as disc-owned."""
    cur.execute(
        "SELECT product_id FROM disc_ownership WHERE contributor_id = %s",
        (contributor["id"],))
    return jsonify(owned=[r["product_id"] for r in cur.fetchall()])


@app.route("/api/v1/store/disc-owned/<product_id>", methods=["POST"])
@require_auth
def disc_owned_set(product_id, contributor, conn, cur, api_key):
    """Mark a product as disc-owned for the current user."""
    if len(product_id) > 16:
        return jsonify(error="Invalid product ID"), 400
    cur.execute("""
        INSERT INTO disc_ownership (contributor_id, product_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
    """, (contributor["id"], product_id))
    conn.commit()
    return jsonify(ok=True)


@app.route("/api/v1/store/disc-owned/<product_id>", methods=["DELETE"])
@require_auth
def disc_owned_unset(product_id, contributor, conn, cur, api_key):
    """Remove disc-owned mark for the current user."""
    cur.execute(
        "DELETE FROM disc_ownership WHERE contributor_id = %s AND product_id = %s",
        (contributor["id"], product_id))
    conn.commit()
    return jsonify(ok=True)


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
# Title ID DB — admin endpoints
# ---------------------------------------------------------------------------

@app.route("/api/v1/admin/title-ids", methods=["GET"])
@require_auth
def admin_title_ids(conn=None, cur=None, contributor=None, api_key=None):
    """List title IDs. Admin only. Supports ?filter=invalid|identified|all"""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    filt = request.args.get("filter", "invalid")
    page = max(0, request.args.get("page", 0, type=int))
    per_page = min(max(1, request.args.get("per_page", 100, type=int)), 500)
    q = (request.args.get("q") or "").strip()

    wheres = []
    params = {}
    if filt == "invalid":
        wheres.append("(t.is_invalid = TRUE AND t.title = '')")
    elif filt == "identified":
        wheres.append("t.title != ''")
    # 'all' = no filter

    if q:
        wheres.append("(t.xbox_title_id ILIKE %(q)s OR t.title ILIKE %(q)s OR t.notes ILIKE %(q)s)")
        params["q"] = f"%{q}%"

    where_sql = (" WHERE " + " AND ".join(wheres)) if wheres else ""

    try:
        cur.execute(f"SELECT COUNT(*) AS cnt FROM title_id_db t{where_sql}", params)
        total = cur.fetchone()["cnt"]

        cur.execute(f"""
            SELECT t.xbox_title_id, t.title, t.category, t.product_kind,
                   t.platforms, t.publisher, t.developer, t.image_url,
                   t.is_invalid, t.notes, t.seen_count, t.first_seen_at, t.updated_at
            FROM title_id_db t{where_sql}
            ORDER BY t.seen_count DESC, t.first_seen_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """, {**params, "limit": per_page, "offset": page * per_page})
        rows = []
        for r in cur.fetchall():
            rows.append({
                "xboxTitleId": r["xbox_title_id"],
                "title": r["title"],
                "category": r["category"],
                "productKind": r["product_kind"],
                "platforms": r["platforms"] or [],
                "publisher": r["publisher"],
                "developer": r["developer"],
                "imageUrl": r["image_url"],
                "isInvalid": r["is_invalid"],
                "notes": r["notes"],
                "seenCount": r["seen_count"],
                "firstSeen": r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
                "updatedAt": r["updated_at"].isoformat() if r["updated_at"] else None,
            })
        return jsonify(items=rows, total=total,
                       page=page, totalPages=max(1, -(-total // per_page)))
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/title-ids", methods=["POST"])
@require_auth
def admin_title_id_update(conn=None, cur=None, contributor=None, api_key=None):
    """Update a title ID entry. Admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    data = request.get_json(force=True)
    tid = (data.get("xboxTitleId") or "").strip()
    if not tid:
        return jsonify(error="xboxTitleId required"), 400
    try:
        cur.execute("""
            UPDATE title_id_db SET
                title = COALESCE(NULLIF(%(title)s, ''), title),
                category = COALESCE(NULLIF(%(cat)s, ''), category),
                product_kind = COALESCE(NULLIF(%(kind)s, ''), product_kind),
                publisher = COALESCE(NULLIF(%(pub)s, ''), publisher),
                developer = COALESCE(NULLIF(%(dev)s, ''), developer),
                notes = %(notes)s,
                is_invalid = %(inv)s,
                updated_at = NOW()
            WHERE xbox_title_id = %(tid)s
        """, {
            "tid": tid,
            "title": data.get("title", ""),
            "cat": data.get("category", ""),
            "kind": data.get("productKind", ""),
            "pub": data.get("publisher", ""),
            "dev": data.get("developer", ""),
            "notes": data.get("notes", ""),
            "inv": data.get("isInvalid", True),
        })
        conn.commit()
        # Invalidate all collection caches (title ID edit may affect any user)
        _invalidate_collection_cache(cur, conn)
        return jsonify(ok=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/title-ids", methods=["OPTIONS"])
def admin_title_ids_options():
    return "", 204


# ---------------------------------------------------------------------------
# Collection endpoints — auth required
# ---------------------------------------------------------------------------

def _invalidate_collection_cache(cur, conn, contributor_id=None):
    """Invalidate cached collection response(s). If contributor_id is None, invalidate all."""
    cache_dir = "/app/static/collection"
    suffixes = [".json.gz", "_ph.json.gz", "_purch.json.gz"]
    if contributor_id:
        cur.execute("UPDATE user_collections SET cached_response = NULL WHERE contributor_id = %s",
                    (contributor_id,))
        for sfx in suffixes:
            try:
                os.remove(os.path.join(cache_dir, f"{contributor_id}{sfx}"))
            except FileNotFoundError:
                pass
    else:
        # Get all contributor IDs to delete their cache files
        cur.execute("SELECT contributor_id FROM user_collections WHERE cached_response IS NOT NULL")
        for row in cur.fetchall():
            for sfx in suffixes:
                try:
                    os.remove(os.path.join(cache_dir, f"{row['contributor_id']}{sfx}"))
                except FileNotFoundError:
                    pass
        cur.execute("UPDATE user_collections SET cached_response = NULL")
    conn.commit()


def _build_collection_cache(cur, conn, contributor_id, lib, ph, history, accounts, purchases,
                            username="", settings=None, uploaded_at=None, version=1):
    """Build and store gzipped collection GET response for fast serving.

    Performs title_id_db enrichment on catalogInvalid items, serialises the
    COMPLETE result (including username/settings/uploadedAt/version),
    gzip-compresses, and stores in user_collections.cached_response.
    The blob is served directly on GET with zero processing.
    """
    # Enrich invalid items from title_id_db (same logic as collection_get)
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

    # Core response: library + lightweight metadata (no PH/purchases — loaded lazily)
    result = {
        "library": lib,
        "history": history,
        "accounts": accounts,
        "username": username,
        "settings": settings or {},
        "uploadedAt": uploaded_at.isoformat() if uploaded_at else None,
        "version": version,
        "uploaded": True,
        "phCount": len(ph),
        "purchasesCount": len(purchases),
    }

    cache_dir = "/app/static/collection"
    os.makedirs(cache_dir, exist_ok=True)

    def _write_gz(path, obj):
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        gz = gzip.compress(raw, compresslevel=6)
        with open(path, "wb") as f:
            f.write(gz)
        return len(gz)

    # Write core collection (library + meta)
    core_path = os.path.join(cache_dir, f"{contributor_id}.json.gz")
    core_sz = _write_gz(core_path, result)

    # Write play history (lazy)
    ph_path = os.path.join(cache_dir, f"{contributor_id}_ph.json.gz")
    ph_sz = _write_gz(ph_path, {"playHistory": ph})

    # Write purchases (lazy)
    purch_path = os.path.join(cache_dir, f"{contributor_id}_purch.json.gz")
    purch_sz = _write_gz(purch_path, {"purchases": purchases})

    # Mark cache as present in DB (lightweight flag, not the blob)
    cur.execute(
        "UPDATE user_collections SET cached_response = 'Y' WHERE contributor_id = %s",
        (contributor_id,))
    conn.commit()
    print(f"[+] Collection cache: core={core_sz:,} ph={ph_sz:,} purch={purch_sz:,} bytes gz")


def _upsert_title_ids(cur, conn, lib):
    """Extract title IDs from a collection upload and upsert into shared DB."""
    # Dedupe: pick the best info per title ID (prefer non-invalid items)
    tid_map = {}
    for item in lib:
        tid = item.get("xboxTitleId", "")
        if not tid:
            continue
        invalid = item.get("catalogInvalid", False)
        # Keep the best item per title ID (prefer non-invalid)
        if tid not in tid_map or (tid_map[tid]["catalogInvalid"] and not invalid):
            tid_map[tid] = item

    if not tid_map:
        return

    for tid, item in tid_map.items():
        invalid = item.get("catalogInvalid", False)
        title = item.get("title", "") if not invalid else ""
        # Don't store title if it looks like a product ID (invalid placeholder)
        if title and (title == item.get("productId", "") or len(title) == 12):
            title = ""
        cur.execute("""
            INSERT INTO title_id_db (xbox_title_id, title, category, product_kind,
                platforms, publisher, developer, image_url, is_invalid, seen_count)
            VALUES (%(tid)s, %(title)s, %(cat)s, %(kind)s,
                %(plats)s, %(pub)s, %(dev)s, %(img)s, %(inv)s, 1)
            ON CONFLICT (xbox_title_id) DO UPDATE SET
                title = CASE WHEN title_id_db.title = '' AND %(title)s != ''
                    THEN %(title)s ELSE title_id_db.title END,
                category = CASE WHEN title_id_db.category = '' AND %(cat)s != ''
                    THEN %(cat)s ELSE title_id_db.category END,
                product_kind = CASE WHEN title_id_db.product_kind = '' AND %(kind)s != ''
                    THEN %(kind)s ELSE title_id_db.product_kind END,
                platforms = CASE WHEN title_id_db.platforms = '{}' AND %(plats)s != '{}'
                    THEN %(plats)s ELSE title_id_db.platforms END,
                publisher = CASE WHEN title_id_db.publisher = '' AND %(pub)s != ''
                    THEN %(pub)s ELSE title_id_db.publisher END,
                developer = CASE WHEN title_id_db.developer = '' AND %(dev)s != ''
                    THEN %(dev)s ELSE title_id_db.developer END,
                image_url = CASE WHEN title_id_db.image_url = '' AND %(img)s != ''
                    THEN %(img)s ELSE title_id_db.image_url END,
                is_invalid = CASE WHEN NOT %(inv)s THEN FALSE ELSE title_id_db.is_invalid END,
                seen_count = title_id_db.seen_count + 1,
                updated_at = NOW()
        """, {
            "tid": tid,
            "title": title,
            "cat": item.get("category", "") if not invalid else "",
            "kind": item.get("productKind", "") if not invalid else "",
            "plats": item.get("platforms", []) if not invalid else [],
            "pub": item.get("publisher", "") if not invalid else "",
            "dev": item.get("developer", "") if not invalid else "",
            "img": item.get("boxArt", "") or item.get("image", "") if not invalid else "",
            "inv": invalid,
        })
    conn.commit()


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

        # Extract title IDs and upsert into shared title_id_db
        try:
            _upsert_title_ids(cur, conn, lib)
        except Exception as e:
            print(f"[!] Title ID DB upsert failed: {e}")
            try:
                conn.rollback()
            except Exception:
                pass

        # Tag Xbox 360 BC games in marketplace_products from collection data
        try:
            x360_pids = [
                g["productId"] for g in lib
                if "Xbox 360" in (g.get("platforms") or [])
                and g.get("productId")
            ]
            if x360_pids:
                cur.execute("""
                    UPDATE marketplace_products
                    SET platforms = array_append(platforms, 'Xbox 360')
                    WHERE product_id = ANY(%s)
                    AND NOT ('Xbox 360' = ANY(platforms))
                """, (x360_pids,))
                if cur.rowcount:
                    conn.commit()
        except Exception as e:
            print(f"[!] Xbox 360 platform tagging failed: {e}")
            try:
                conn.rollback()
            except Exception:
                pass

        # Pre-build and cache the GET response (complete blob, zero processing on GET)
        try:
            cur.execute("SELECT uploaded_at, version FROM user_collections WHERE contributor_id = %s",
                        (contributor["id"],))
            uc_row = cur.fetchone()
            _build_collection_cache(
                cur, conn, contributor["id"],
                lib, ph, history, safe_accounts, purchases,
                username=contributor["username"],
                settings=contributor.get("settings") or {},
                uploaded_at=uc_row["uploaded_at"] if uc_row else None,
                version=uc_row["version"] if uc_row else 1,
            )
        except Exception as e:
            print(f"[!] Collection cache build failed: {e}")
            try:
                conn.rollback()
            except Exception:
                pass

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
        # Fast path: try pre-built cached response
        cur.execute("""
            SELECT cached_response, uploaded_at, version
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

        if row["cached_response"]:
            # Fast path: tell Nginx to serve the pre-built file directly (X-Accel-Redirect)
            cache_file = f"/app/static/collection/{contributor['id']}.json.gz"
            if os.path.exists(cache_file):
                return Response("", status=200, headers={
                    "X-Accel-Redirect": f"/internal/collection/{contributor['id']}.json.gz",
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                })
            # Cache file missing — clear flag and fall through to slow path
            _invalidate_collection_cache(cur, conn, contributor["id"])

        # Slow path fallback: build from JSONB columns (uncached users)
        cur.execute("""
            SELECT lib, play_history, scan_history, accounts_meta, purchases
            FROM user_collections
            WHERE contributor_id = %s
        """, (contributor["id"],))
        full_row = cur.fetchone()
        lib = full_row["lib"] or []

        # Enrich invalid items from shared title_id_db
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

        ph = full_row["play_history"] or []
        purchases = full_row["purchases"] or []
        result = {
            "library": lib,
            "history": full_row["scan_history"] or [],
            "accounts": full_row["accounts_meta"] or [],
            "username": contributor["username"],
            "settings": contributor.get("settings") or {},
            "uploadedAt": row["uploaded_at"].isoformat() if row["uploaded_at"] else None,
            "version": row["version"],
            "uploaded": True,
            "phCount": len(ph),
            "purchasesCount": len(purchases),
        }
        json_bytes = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        gz_bytes = gzip.compress(json_bytes, compresslevel=6)
        return Response(gz_bytes, status=200, headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        })
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/collection", methods=["DELETE"])
@require_auth
def collection_delete(conn=None, cur=None, contributor=None, api_key=None):
    """Delete stored collection for the authenticated user."""
    try:
        cur.execute("DELETE FROM user_collections WHERE contributor_id = %s",
                    (contributor["id"],))
        _invalidate_collection_cache(cur, conn, contributor["id"])
        conn.commit()
        return jsonify(status="ok", deleted=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/collection/playhistory", methods=["GET"])
@require_auth
def collection_playhistory(conn=None, cur=None, contributor=None, api_key=None):
    """Lazy-load play history for the authenticated user."""
    try:
        cache_file = f"/app/static/collection/{contributor['id']}_ph.json.gz"
        if os.path.exists(cache_file):
            return Response("", status=200, headers={
                "X-Accel-Redirect": f"/internal/collection/{contributor['id']}_ph.json.gz",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            })
        # Slow path: read from DB
        cur.execute("SELECT play_history FROM user_collections WHERE contributor_id = %s",
                    (contributor["id"],))
        row = cur.fetchone()
        if not row:
            return jsonify(playHistory=[])
        result = {"playHistory": row["play_history"] or []}
        gz = gzip.compress(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode(), 6)
        return Response(gz, status=200, headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        })
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/v1/collection/purchases", methods=["GET"])
@require_auth
def collection_purchases(conn=None, cur=None, contributor=None, api_key=None):
    """Lazy-load purchases for the authenticated user."""
    try:
        cache_file = f"/app/static/collection/{contributor['id']}_purch.json.gz"
        if os.path.exists(cache_file):
            return Response("", status=200, headers={
                "X-Accel-Redirect": f"/internal/collection/{contributor['id']}_purch.json.gz",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            })
        # Slow path: read from DB
        cur.execute("SELECT purchases FROM user_collections WHERE contributor_id = %s",
                    (contributor["id"],))
        row = cur.fetchone()
        if not row:
            return jsonify(purchases=[])
        result = {"purchases": row["purchases"] or []}
        gz = gzip.compress(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode(), 6)
        return Response(gz, status=200, headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        })
    except Exception as e:
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


@app.route("/api/v1/xbox/achievements/leaderboard/<board_id>")
def xbox_achievement_leaderboard(board_id):
    """Public leaderboard endpoint — no auth required."""
    BOARDS = {
        "baby-games": {
            "title": "Baby Games",
            "developers": [
                "Afil Games", "Synnergy Circle Games",
                "EpiXR Games", "Jolly Lobster Interactive",
            ],
        },
    }
    board = BOARDS.get(board_id)
    if not board:
        return jsonify(error="Unknown leaderboard"), 404

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # Find product IDs from the target developers
        cur.execute("""
            SELECT product_id FROM marketplace_products
            WHERE developer = ANY(%s)
        """, (board["developers"],))
        dev_pids = {r["product_id"] for r in cur.fetchall()}
        if not dev_pids:
            return jsonify(title=board["title"], entries=[])

        # Get all achievement summaries for those product IDs, grouped by user
        cur.execute("""
            SELECT xa.contributor_id,
                   COALESCE(xauth.gamertag, c.username) AS gamertag,
                   c.avatar_url,
                   xa.product_id,
                   xa.current_gamerscore,
                   xa.total_gamerscore,
                   xa.current_achievements,
                   xa.total_achievements,
                   xa.title_name
            FROM xbox_achievement_summaries xa
            JOIN contributors c ON c.id = xa.contributor_id
            LEFT JOIN xbox_auth xauth ON xauth.contributor_id = xa.contributor_id
            WHERE xa.product_id = ANY(%s)
            ORDER BY xa.contributor_id, xa.current_gamerscore DESC
        """, (list(dev_pids),))
        rows = cur.fetchall()

        # Aggregate per user
        users = {}
        for r in rows:
            uid = r["contributor_id"]
            if uid not in users:
                users[uid] = {
                    "gamertag": r["gamertag"],
                    "avatarUrl": r["avatar_url"] or "",
                    "totalGS": 0,
                    "maxGS": 0,
                    "games": 0,
                    "completed": 0,
                }
            u = users[uid]
            u["totalGS"] += r["current_gamerscore"]
            u["maxGS"] += r["total_gamerscore"]
            u["games"] += 1
            if r["current_achievements"] and r["total_achievements"] and \
               r["current_achievements"] >= r["total_achievements"]:
                u["completed"] += 1

        entries = sorted(users.values(), key=lambda x: x["totalGS"], reverse=True)
        return jsonify(title=board["title"], entries=entries)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


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
            if "gamertagInfo" in raw and isinstance(raw["gamertagInfo"], dict):
                clean = {}
                for gt, info in raw["gamertagInfo"].items():
                    if not isinstance(info, dict):
                        continue
                    entry = {}
                    if "region" in info and (info["region"] == "" or info["region"] in valid_regions):
                        entry["region"] = info["region"]
                    if "email" in info and isinstance(info["email"], str):
                        entry["email"] = info["email"][:320]
                    if "col1" in info:
                        if isinstance(info["col1"], bool):
                            entry["col1"] = info["col1"]
                        elif isinstance(info["col1"], str):
                            entry["col1"] = info["col1"][:128]
                    if "col2" in info:
                        if isinstance(info["col2"], bool):
                            entry["col2"] = info["col2"]
                        elif isinstance(info["col2"], str):
                            entry["col2"] = info["col2"][:128]
                    if "regionLock" in info and isinstance(info["regionLock"], bool):
                        entry["regionLock"] = info["regionLock"]
                    if "changesLeft" in info and isinstance(info["changesLeft"], str):
                        entry["changesLeft"] = info["changesLeft"][:1]
                    if "notes" in info and isinstance(info["notes"], str):
                        entry["notes"] = info["notes"][:500]
                    if entry:
                        clean[gt[:64]] = entry
                if clean:
                    settings_update["gamertagInfo"] = clean
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
        # Invalidate collection cache (it embeds username/settings)
        if settings_update:
            _invalidate_collection_cache(cur, conn, contributor["id"])
        return jsonify(ok=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500


@app.route("/api/v1/profile/passphrase", methods=["PUT"])
@require_auth
def profile_change_passphrase(conn=None, cur=None, contributor=None, api_key=None):
    """Change passphrase for the authenticated user."""
    try:
        data = request.get_json(force=True)
        current = (data.get("current") or "").strip()[:128]
        new_pass = (data.get("new_passphrase") or "").strip()[:128]
        if not current:
            return jsonify(error="Current passphrase required"), 400
        if not new_pass or len(new_pass) < 4:
            return jsonify(error="New passphrase must be at least 4 characters"), 400
        # Verify current passphrase
        cur.execute("SELECT passphrase_hash FROM contributors WHERE id = %s", (contributor["id"],))
        row = cur.fetchone()
        if not row or not row["passphrase_hash"]:
            return jsonify(error="No passphrase set on this account"), 400
        current_hash = hashlib.sha256(current.encode()).hexdigest()
        if current_hash != row["passphrase_hash"]:
            return jsonify(error="Current passphrase is incorrect"), 403
        # Update
        new_hash = hashlib.sha256(new_pass.encode()).hexdigest()
        cur.execute("UPDATE contributors SET passphrase_hash = %s WHERE id = %s",
                    (new_hash, contributor["id"]))
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
# Xbox 360 BC TitleHub Scanner
# ---------------------------------------------------------------------------
# TitleHub is the authoritative source for Xbox 360 platform data.
# Microsoft catalog API tags BC games as "Xbox One"/"Xbox Series X|S" only,
# but TitleHub correctly reports "Xbox360" in the devices array.
# This scanner checks ALL marketplace_products against TitleHub and tags
# any Xbox 360 BC games that were missed by collection-based tagging.
# ---------------------------------------------------------------------------

_x360_scan_lock = threading.Lock()
_x360_scan_active = False


def _titlehub_batch_scan_x360(xbl3_token):
    """Scan marketplace_products via TitleHub and tag Xbox 360 BC games.

    Queries TitleHub batch endpoint for all products with a non-empty
    xbox_title_id that don't already have 'Xbox 360' in platforms.
    Tags any that TitleHub reports as Xbox360 devices.

    Returns (tagged_count, checked_count, error_msg_or_None).
    """
    import urllib.request as _ur
    import urllib.error as _ue
    import ssl

    global _x360_scan_active
    with _x360_scan_lock:
        if _x360_scan_active:
            return 0, 0, "Scan already running"
        _x360_scan_active = True

    conn = None
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"],
                                cursor_factory=psycopg2.extras.RealDictCursor)
        cur = conn.cursor()

        # Get all products with a title ID that aren't already tagged Xbox 360
        # Also extract XBOXTITLEID from alternate_ids for products missing
        # xbox_title_id (belt-and-suspenders coverage)
        cur.execute("""
            SELECT product_id, xbox_title_id, alternate_ids
            FROM marketplace_products
            WHERE NOT ('Xbox 360' = ANY(platforms))
            AND (xbox_title_id != ''
                 OR alternate_ids @> '[{"idType": "XboxTitleId"}]'::jsonb
                 OR alternate_ids @> '[{"idType": "XBOXTITLEID"}]'::jsonb)
        """)
        rows = cur.fetchall()
        if not rows:
            return 0, 0, None

        # Build mapping: title_id -> list of product_ids
        tid_to_pids = {}
        for r in rows:
            tid = r["xbox_title_id"].strip() if r["xbox_title_id"] else ""
            if not tid:
                # Fallback: extract from alternate_ids JSONB
                alt_ids = r.get("alternate_ids") or []
                if isinstance(alt_ids, list):
                    for alt in alt_ids:
                        if isinstance(alt, dict) and alt.get("idType", "").upper() == "XBOXTITLEID":
                            tid = alt.get("id", "").strip()
                            break
            if tid:
                tid_to_pids.setdefault(tid, []).append(r["product_id"])

        all_tids = list(tid_to_pids.keys())
        print(f"[x360-scan] Checking {len(all_tids)} title IDs via TitleHub...",
              flush=True)

        tagged_count = 0
        checked = 0
        batch_size = 500
        ssl_ctx = ssl.create_default_context()

        for i in range(0, len(all_tids), batch_size):
            batch = all_tids[i:i + batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(all_tids) + batch_size - 1) // batch_size

            cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
            body = json.dumps({
                "pfns": None,
                "titleIds": batch,
            }).encode("utf-8")

            url = "https://titlehub.xboxlive.com/titles/batch/decoration/Image,ProductId"
            req = _ur.Request(url, data=body, headers={
                "Authorization": xbl3_token,
                "Content-Type": "application/json",
                "x-xbl-contract-version": "2",
                "Accept-Language": "en-US",
                "MS-CV": cv,
                "Accept": "application/json",
            })

            try:
                with _ur.urlopen(req, context=ssl_ctx, timeout=60) as resp:
                    data = json.loads(resp.read())
            except _ue.HTTPError as e:
                err_body = ""
                try:
                    err_body = e.read().decode("utf-8", errors="replace")[:300]
                except Exception:
                    pass
                print(f"[x360-scan] Batch {batch_num}/{total_batches} "
                      f"HTTP {e.code}: {err_body[:100]}")
                continue
            except Exception as e:
                print(f"[x360-scan] Batch {batch_num}/{total_batches} FAILED: {e}")
                continue

            # Check each title for Xbox360 device
            x360_pids = set()
            titles = data.get("titles", [])
            for title in titles:
                devices = title.get("devices", [])
                if "Xbox360" in devices:
                    pid = title.get("productId", "")
                    t_id = str(title.get("titleId", ""))
                    # Add the productId from TitleHub response
                    if pid:
                        x360_pids.add(pid)
                    # Also tag all products sharing this titleId
                    for p in tid_to_pids.get(t_id, []):
                        x360_pids.add(p)

            if x360_pids:
                pid_list = list(x360_pids)
                cur.execute("""
                    UPDATE marketplace_products
                    SET platforms = array_append(platforms, 'Xbox 360')
                    WHERE product_id = ANY(%s)
                    AND NOT ('Xbox 360' = ANY(platforms))
                """, (pid_list,))
                batch_tagged = cur.rowcount
                conn.commit()
                tagged_count += batch_tagged
                print(f"[x360-scan] Batch {batch_num}/{total_batches}: "
                      f"tagged {batch_tagged} Xbox 360 games")
            else:
                print(f"[x360-scan] Batch {batch_num}/{total_batches}: "
                      f"no new Xbox 360 games found")

            checked += len(batch)

        if tagged_count:
            _shared_cache.pop("marketplace_full", None)

        print(f"[x360-scan] Done: tagged {tagged_count} games, "
              f"checked {checked} title IDs")
        return tagged_count, checked, None

    except Exception as e:
        print(f"[x360-scan] Error: {e}")
        return 0, 0, str(e)
    finally:
        _x360_scan_active = False
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _x360_tag_from_all_collections():
    """One-time migration: scan ALL user collections for Xbox 360 games.

    This catches games uploaded before the per-upload Xbox 360 tagging
    code was added.
    """
    conn = None
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"],
                                cursor_factory=psycopg2.extras.RealDictCursor)
        cur = conn.cursor()

        cur.execute("SELECT lib FROM user_collections WHERE lib IS NOT NULL")
        all_x360_pids = set()
        for row in cur:
            lib = row["lib"]
            if not isinstance(lib, list):
                continue
            for g in lib:
                if ("Xbox 360" in (g.get("platforms") or [])
                        and g.get("productId")):
                    all_x360_pids.add(g["productId"])

        if all_x360_pids:
            pid_list = list(all_x360_pids)
            cur.execute("""
                UPDATE marketplace_products
                SET platforms = array_append(platforms, 'Xbox 360')
                WHERE product_id = ANY(%s)
                AND NOT ('Xbox 360' = ANY(platforms))
            """, (pid_list,))
            tagged = cur.rowcount
            conn.commit()
            if tagged:
                _shared_cache.pop("marketplace_full", None)
                print(f"[x360-scan] Collection migration: tagged {tagged} "
                      f"games from {len(all_x360_pids)} Xbox 360 PIDs "
                      f"across all user collections")
        else:
            print("[x360-scan] Collection migration: no Xbox 360 games "
                  "found in user collections")
    except Exception as e:
        print(f"[x360-scan] Collection migration failed: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _x360_scan_startup():
    """Run Xbox 360 scans on server startup (background thread).

    Phase 1: Tag from all user collections (no auth needed)
    Phase 2: TitleHub batch scan (needs Xbox auth)
    """
    # Phase 1: Collection-based tagging (catches all games in user libraries)
    _x360_tag_from_all_collections()

    # Phase 2: TitleHub scan (catches games NOT in any user's collection)
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"],
                                cursor_factory=psycopg2.extras.RealDictCursor)
        cur = conn.cursor()

        # Find any linked Xbox user to use as auth source
        cur.execute("""
            SELECT contributor_id FROM xbox_auth
            WHERE refresh_token_enc IS NOT NULL
            LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            print("[x360-scan] No linked Xbox users — skipping TitleHub scan")
            conn.close()
            return

        contributor_id = row["contributor_id"]
        try:
            xbl3, _, _ = _ensure_xbl3_token(cur, conn, contributor_id)
        except Exception as e:
            print(f"[x360-scan] Could not get XBL3 token: {e}")
            conn.close()
            return
        conn.close()

        tagged, checked, err = _titlehub_batch_scan_x360(xbl3)
        if err:
            print(f"[x360-scan] TitleHub scan error: {err}")
        elif tagged:
            print(f"[x360-scan] TitleHub scan tagged {tagged}/{checked} "
                  f"Xbox 360 BC games")
        else:
            print(f"[x360-scan] TitleHub scan complete: "
                  f"all {checked} title IDs already correctly tagged")

    except Exception as e:
        print(f"[x360-scan] TitleHub scan failed: {e}")


# Launch startup scan after 10 seconds (let Flask start first)
threading.Timer(10.0, _x360_scan_startup).start()


@app.route("/api/v1/admin/achievements-refresh", methods=["POST"])
@require_auth
def admin_achievements_refresh(conn=None, cur=None, contributor=None, api_key=None):
    """Force refresh achievement summaries for all Xbox-linked users. Admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    # Gather all Xbox-linked users
    cur.execute("SELECT contributor_id, xuid FROM xbox_auth")
    users = cur.fetchall()
    if not users:
        return jsonify(ok=True, message="No Xbox-linked users found", count=0)

    def _bg_refresh_all(user_list):
        ok_count = 0
        fail_count = 0
        for u in user_list:
            try:
                c = get_db()
                cr = c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                xbl3, xuid, gt = _ensure_xbl3_token(cr, c, u["contributor_id"])
                summaries = xba.fetch_titlehub_achievements(xbl3, xuid)
                _store_achievement_summaries(cr, u["contributor_id"], summaries)
                c.commit()
                ok_count += 1
                log.info("[admin-ach-refresh] %s (%s): %d summaries", gt, xuid, len(summaries))
            except Exception as e:
                log.warning("[admin-ach-refresh] user %s failed: %s", u["contributor_id"], e)
                fail_count += 1
                try:
                    c.rollback()
                except Exception:
                    pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass
        log.info("[admin-ach-refresh] Done: %d ok, %d failed", ok_count, fail_count)

    threading.Thread(target=_bg_refresh_all, args=(users,), daemon=True).start()
    return jsonify(ok=True, message=f"Refreshing achievements for {len(users)} users in background", count=len(users))


def _x_lookup_user(username):
    """Look up a single X/Twitter user by username. Returns profile dict or None."""
    if not X_BEARER_TOKEN:
        return None
    import urllib.parse
    token = urllib.parse.unquote(X_BEARER_TOKEN)
    resp = _requests_lib.get(
        f"https://api.x.com/2/users/by/username/{username}",
        headers={"Authorization": f"Bearer {token}"},
        params={
            "user.fields": "id,name,username,description,public_metrics,profile_image_url,"
                           "verified,verified_type,created_at,location,url,entities,"
                           "protected,profile_banner_url"
        },
        timeout=15,
    )
    if resp.status_code == 429:
        log.warning("[x-api] Rate limited (429)")
        return {"error": "rate_limited", "reset": resp.headers.get("x-rate-limit-reset", "")}
    if resp.status_code != 200:
        log.warning("[x-api] HTTP %s for @%s: %s", resp.status_code, username, resp.text[:200])
        return None
    data = resp.json().get("data")
    if not data:
        return None
    pm = data.get("public_metrics", {})
    # Resolve t.co URL to real URL
    expanded_url = ""
    if data.get("entities") and data["entities"].get("url"):
        urls = data["entities"]["url"].get("urls", [])
        if urls:
            expanded_url = urls[0].get("expanded_url", "") or urls[0].get("display_url", "")
    return {
        "x_id": data.get("id", ""),
        "x_handle": data.get("username", ""),
        "x_name": data.get("name", ""),
        "x_bio": data.get("description", ""),
        "x_followers": pm.get("followers_count", 0),
        "x_following": pm.get("following_count", 0),
        "x_tweet_count": pm.get("tweet_count", 0),
        "x_listed_count": pm.get("listed_count", 0),
        "x_profile_image": (data.get("profile_image_url") or "").replace("_normal.", "_400x400."),
        "x_banner_image": data.get("profile_banner_url", ""),
        "x_location": data.get("location", ""),
        "x_url": expanded_url or data.get("url", ""),
        "x_verified": bool(data.get("verified")),
        "x_created_at": data.get("created_at", ""),
    }


@app.route("/api/v1/admin/entity-x-profile", methods=["PUT"])
@require_auth
def admin_entity_x_profile(conn=None, cur=None, contributor=None, api_key=None):
    """Save X handle for a developer/publisher, fetch profile from X API. Admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    data = request.get_json(force=True)
    entity_type = data.get("entityType", "")  # "developer" or "publisher"
    entity_name = data.get("name", "").strip()
    x_url = data.get("xUrl", "").strip()

    if entity_type not in ("developer", "publisher"):
        return jsonify(error="Invalid entityType"), 400
    if not entity_name:
        return jsonify(error="name required"), 400
    if not x_url:
        return jsonify(error="xUrl required"), 400

    # Extract handle from URL: https://x.com/handle or https://twitter.com/handle or just @handle
    import re
    m = re.search(r'(?:x\.com|twitter\.com)/([A-Za-z0-9_]+)', x_url)
    if m:
        handle = m.group(1)
    elif x_url.startswith("@"):
        handle = x_url[1:]
    else:
        handle = x_url.strip().split("/")[-1].lstrip("@")

    if not handle or len(handle) > 50:
        return jsonify(error=f"Could not parse handle from: {x_url}"), 400

    profile_table = "developer_profiles" if entity_type == "developer" else "publisher_profiles"

    # Look up from X API
    x_data = _x_lookup_user(handle)
    if not x_data:
        return jsonify(error=f"X user @{handle} not found"), 404
    if x_data.get("error") == "rate_limited":
        return jsonify(error="X API rate limited. Try again later.",
                       reset=x_data.get("reset")), 429

    try:
        cur.execute(f"""
            UPDATE {profile_table} SET
                twitter = %(handle)s,
                x_id = %(x_id)s, x_handle = %(x_handle)s, x_name = %(x_name)s,
                x_bio = %(x_bio)s, x_followers = %(x_followers)s,
                x_following = %(x_following)s, x_tweet_count = %(x_tweet_count)s,
                x_listed_count = %(x_listed_count)s,
                x_profile_image = %(x_profile_image)s,
                x_banner_image = %(x_banner_image)s,
                x_location = %(x_location)s, x_url = %(x_url)s,
                x_verified = %(x_verified)s, x_created_at = %(x_created_at)s,
                x_updated_at = NOW(),
                updated_at = NOW()
            WHERE name = %(name)s
        """, {**x_data, "handle": handle, "name": entity_name})
        if cur.rowcount == 0:
            # Profile row doesn't exist yet — insert it
            cur.execute(f"""
                INSERT INTO {profile_table} (name, twitter, x_id, x_handle, x_name, x_bio,
                    x_followers, x_following, x_tweet_count, x_listed_count,
                    x_profile_image, x_banner_image, x_location, x_url,
                    x_verified, x_created_at, x_updated_at, updated_at)
                VALUES (%(name)s, %(handle)s, %(x_id)s, %(x_handle)s, %(x_name)s, %(x_bio)s,
                    %(x_followers)s, %(x_following)s, %(x_tweet_count)s, %(x_listed_count)s,
                    %(x_profile_image)s, %(x_banner_image)s, %(x_location)s, %(x_url)s,
                    %(x_verified)s, %(x_created_at)s, NOW(), NOW())
            """, {**x_data, "handle": handle, "name": entity_name})
        conn.commit()
        log.info("[x-profile] Saved @%s for %s '%s' (%d followers)",
                 handle, entity_type, entity_name, x_data.get("x_followers", 0))
        return jsonify(ok=True, profile=x_data)
    except Exception as e:
        conn.rollback()
        log.exception("[x-profile] DB error")
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/entity-x-list", methods=["PUT"])
@require_auth
def admin_entity_x_list(conn=None, cur=None, contributor=None, api_key=None):
    """Save X list URL for a developer/publisher. Admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    data = request.get_json(force=True)
    entity_type = data.get("entityType", "")
    entity_name = data.get("name", "").strip()
    list_url = data.get("listUrl", "").strip()
    if entity_type not in ("developer", "publisher"):
        return jsonify(error="Invalid entityType"), 400
    if not entity_name:
        return jsonify(error="Missing name"), 400
    if not list_url:
        return jsonify(error="Missing listUrl"), 400
    profile_table = "developer_profiles" if entity_type == "developer" else "publisher_profiles"
    try:
        cur.execute(f"""
            UPDATE {profile_table} SET x_list_url = %(url)s, updated_at = NOW()
            WHERE name = %(name)s
        """, {"url": list_url, "name": entity_name})
        if cur.rowcount == 0:
            cur.execute(f"""
                INSERT INTO {profile_table} (name, x_list_url, updated_at)
                VALUES (%(name)s, %(url)s, NOW())
            """, {"url": list_url, "name": entity_name})
        conn.commit()
        return jsonify(ok=True, listUrl=list_url)
    except Exception as e:
        conn.rollback()
        log.exception("[x-list] DB error")
        return jsonify(error=str(e)), 500


@app.route("/api/v1/admin/tag-xbox360", methods=["POST"])
@require_auth
def admin_tag_xbox360(conn=None, cur=None, contributor=None, api_key=None):
    """Scan marketplace via TitleHub and tag Xbox 360 BC games. Admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403

    if _x360_scan_active:
        return jsonify(error="Scan already running"), 409

    # Get auth token from the admin's linked Xbox account
    try:
        xbl3, _, _ = _ensure_xbl3_token(cur, conn, contributor["id"])
    except ValueError as e:
        return jsonify(error=str(e)), 401

    # Run scan in background thread
    def _run():
        tagged, checked, err = _titlehub_batch_scan_x360(xbl3)
        if err:
            print(f"[x360-scan] Admin scan error: {err}")
        else:
            print(f"[x360-scan] Admin scan complete: tagged {tagged}/{checked}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify(status="ok", message="Xbox 360 TitleHub scan started")


# ---------------------------------------------------------------------------
# RAWG.io Metacritic Score Scraper (background job)
# ---------------------------------------------------------------------------

_rawg_active = False
_rawg_progress = {"status": "idle", "matched": 0, "total": 0, "page": 0}
RAWG_API_KEY = os.environ.get("RAWG_API_KEY", "")
X_BEARER_TOKEN = os.environ.get("X_BEARER_TOKEN", "")


def _rawg_normalize(name):
    """Normalize a game title for fuzzy matching."""
    import unicodedata
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    name = name.lower()
    name = re.sub(r'[®™©]', '', name)
    name = re.sub(r'\s*[\(\[].*?[\)\]]', '', name)
    name = re.sub(r"[^a-z0-9 ]", "", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name


def _bg_rawg_scrape():
    """Background job: fetch Metacritic scores from RAWG.io and update DB."""
    global _rawg_active, _rawg_progress
    _rawg_active = True
    _rawg_progress = {"status": "running", "matched": 0, "total": 0, "page": 0,
                      "phase": "fetching"}

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Get all titles from our DB that don't have metacritic scores
        cur.execute("""
            SELECT product_id, title FROM marketplace_products
            WHERE title != product_id AND product_kind = 'Game'
        """)
        all_games = {r["product_id"]: r["title"] for r in cur.fetchall()}
        _rawg_progress["total"] = len(all_games)

        # Build normalized title -> product_id lookup
        title_lookup = {}
        for pid, title in all_games.items():
            norm = _rawg_normalize(title)
            if norm and norm not in title_lookup:
                title_lookup[norm] = pid

        # Phase 1: Paginate all Xbox/PC games from RAWG
        rawg_matches = {}  # product_id -> metacritic_score
        platform_ids = "1,14,186,4,80"  # Xbox One, 360, Series X|S, PC, OG Xbox
        url = f"https://api.rawg.io/api/games"
        params = {
            "key": RAWG_API_KEY,
            "platforms": platform_ids,
            "page_size": 40,
            "ordering": "-metacritic",
        }
        page = 0

        while url and page < 500:  # Safety cap at 500 pages
            page += 1
            _rawg_progress["page"] = page
            _rawg_progress["phase"] = f"fetching page {page}"

            try:
                resp = _requests_lib.get(url, params=params if page == 1 else None,
                                        timeout=30)
                if resp.status_code == 429:
                    time.sleep(5)
                    continue
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                log.warning(f"[rawg] Page {page} failed: {e}")
                time.sleep(2)
                continue

            for g in data.get("results", []):
                mc = g.get("metacritic")
                if not mc:
                    continue
                norm = _rawg_normalize(g.get("name", ""))
                if norm in title_lookup:
                    pid = title_lookup[norm]
                    rawg_matches[pid] = mc
                    _rawg_progress["matched"] = len(rawg_matches)

            url = data.get("next")
            if not url:
                break
            # next URL already has params
            params = None
            time.sleep(0.25)

        # Phase 2: Update DB
        _rawg_progress["phase"] = "updating database"
        updated = 0
        for pid, score in rawg_matches.items():
            cur.execute(
                "UPDATE marketplace_products SET metacritic_score = %s "
                "WHERE product_id = %s AND (metacritic_score IS NULL OR metacritic_score != %s)",
                (score, pid, score))
            updated += cur.rowcount

        conn.commit()
        _rawg_progress = {
            "status": "done", "matched": len(rawg_matches),
            "updated": updated, "total": len(all_games), "page": page}
        log.info(f"[rawg] Done: {len(rawg_matches)} matched, {updated} updated, {page} pages")

    except Exception as e:
        log.exception("[rawg] Scrape failed")
        _rawg_progress = {"status": f"error: {e}", "matched": 0, "total": 0, "page": 0}
    finally:
        _rawg_active = False
        try:
            conn.close()
        except Exception:
            pass


@app.route("/api/v1/admin/rawg-scrape", methods=["POST"])
@require_auth
def admin_rawg_scrape(conn=None, cur=None, contributor=None, api_key=None):
    """Trigger RAWG Metacritic score scrape. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    if _rawg_active:
        return jsonify(error="Scrape already running", progress=_rawg_progress), 409
    if not RAWG_API_KEY:
        return jsonify(error="RAWG_API_KEY not set in environment"), 400
    threading.Thread(target=_bg_rawg_scrape, daemon=True).start()
    return jsonify(ok=True, message="RAWG scrape started")


@app.route("/api/v1/admin/rawg-status", methods=["GET"])
@require_auth
def admin_rawg_status(conn=None, cur=None, contributor=None, api_key=None):
    """Check RAWG scrape progress. Freshdex admin only."""
    if contributor["username"].lower() != "freshdex":
        return jsonify(error="Admin access required"), 403
    return jsonify(active=_rawg_active, progress=_rawg_progress)


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
@app.route("/api/v1/profile/passphrase", methods=["OPTIONS"])
@app.route("/api/v1/admin/changelog", methods=["OPTIONS"])
@app.route("/api/v1/admin/scans", methods=["OPTIONS"])
@app.route("/api/v1/admin/scan", methods=["OPTIONS"])
@app.route("/api/v1/admin/subs", methods=["OPTIONS"])
@app.route("/api/v1/admin/scans/<int:scan_id>/changelog", methods=["OPTIONS"])
@app.route("/api/v1/store/filters", methods=["OPTIONS"])
@app.route("/api/v1/store/products", methods=["OPTIONS"])
@app.route("/api/v1/store/product/<product_id>", methods=["OPTIONS"])
@app.route("/api/v1/store/editions/<xbox_title_id>", methods=["OPTIONS"])
@app.route("/api/v1/store/amazon/bulk", methods=["OPTIONS"])
@app.route("/api/v1/store/amazon/hits", methods=["OPTIONS"])
@app.route("/api/v1/store/amazon/set", methods=["OPTIONS"])
@app.route("/api/v1/store/amazon/remove", methods=["OPTIONS"])
@app.route("/api/v1/store/physical/<product_id>", methods=["OPTIONS"])
@app.route("/api/v1/store/physical/<int:link_id>", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/scan", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/scans", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/status", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/purged", methods=["OPTIONS"])
@app.route("/api/v1/admin/cdn-monitor/stop", methods=["OPTIONS"])
@app.route("/api/v1/admin/achievements-refresh", methods=["OPTIONS"])
@app.route("/api/v1/admin/tag-xbox360", methods=["OPTIONS"])
@app.route("/api/v1/admin/entity-x-profile", methods=["OPTIONS"])
@app.route("/api/v1/admin/entity-x-list", methods=["OPTIONS"])
def cors_preflight():
    return Response(status=204)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5001)
