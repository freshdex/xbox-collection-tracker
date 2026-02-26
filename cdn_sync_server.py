#!/usr/bin/env python3
"""
Freshdex CDN Sync Server — REST API for shared Xbox CDN link database.
Flask app fronting PostgreSQL. Deploy with Gunicorn + Nginx + Let's Encrypt.

Usage:
    pip install flask psycopg2-binary gunicorn
    export DATABASE_URL="postgresql://user:pass@localhost/freshdex_cdn"
    python cdn_sync_server.py          # Dev mode (port 5000)
    gunicorn cdn_sync_server:app -b 0.0.0.0:8000  # Production
"""

import hashlib
import os
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, request

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freshdex_cdn")

# Rate limiting (in-memory, resets on restart)
_rate_sync = defaultdict(list)    # api_key -> [timestamps]
_rate_register = defaultdict(list)  # ip -> [timestamps]
SYNC_LIMIT = 10       # per minute
REGISTER_LIMIT = 5    # per hour


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


def _validate_store_id(s):
    return isinstance(s, str) and 1 <= len(s) <= 16 and re.match(r'^[A-Za-z0-9]+$', s)


def _validate_build_id(s):
    return isinstance(s, str) and 1 <= len(s) <= 64


def _validate_cdn_url(u):
    if not isinstance(u, str) or len(u) > 512:
        return False
    return 'xboxlive.com' in u or 'xboxlive.cn' in u


def _sanitize_str(s, max_len=512):
    if s is None:
        return None
    if not isinstance(s, str):
        return None
    return s[:max_len]


@app.route('/api/v1/register', methods=['POST'])
def register():
    ip = request.remote_addr or 'unknown'
    if not _check_rate(_rate_register, ip, REGISTER_LIMIT, 3600):
        return jsonify(error="Rate limit exceeded. Try again later."), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('username'), str):
        return jsonify(error="username is required"), 400

    username = data['username'].strip()[:64]
    if not username or not re.match(r'^[A-Za-z0-9_ -]{1,64}$', username):
        return jsonify(error="Invalid username. Use letters, numbers, spaces, hyphens, underscores."), 400

    existing_key = _sanitize_str(data.get('api_key'), 64)
    passphrase = _sanitize_str(data.get('passphrase'), 128)

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # If api_key provided, try to reclaim/rename and optionally set passphrase
        if existing_key:
            cur.execute("SELECT id, username, api_key, total_points FROM contributors WHERE api_key = %s",
                        (existing_key,))
            row = cur.fetchone()
            if row:
                if row['username'] != username:
                    cur.execute("UPDATE contributors SET username = %s WHERE id = %s",
                                (username, row['id']))
                if passphrase:
                    ph = hashlib.sha256(passphrase.encode()).hexdigest()
                    cur.execute("UPDATE contributors SET passphrase_hash = %s WHERE id = %s",
                                (ph, row['id']))
                conn.commit()
                return jsonify(username=username, api_key=row['api_key'],
                               total_points=row['total_points'], created=False)

        # Check if username already taken
        cur.execute("SELECT id, api_key, total_points, passphrase_hash FROM contributors WHERE username = %s",
                    (username,))
        existing = cur.fetchone()
        if existing:
            # If passphrase provided, try to reclaim via passphrase
            if passphrase and existing['passphrase_hash']:
                ph = hashlib.sha256(passphrase.encode()).hexdigest()
                if ph == existing['passphrase_hash']:
                    return jsonify(username=username, api_key=existing['api_key'],
                                   total_points=existing['total_points'], created=False)
                else:
                    return jsonify(error="Incorrect passphrase."), 403
            return jsonify(error="Username already taken. Provide your api_key or passphrase to reclaim, or choose a different name."), 409

        api_key = secrets.token_urlsafe(32)
        passphrase_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else None
        cur.execute(
            "INSERT INTO contributors (username, api_key, passphrase_hash) VALUES (%s, %s, %s) RETURNING id, total_points",
            (username, api_key, passphrase_hash))
        row = cur.fetchone()
        conn.commit()
        return jsonify(username=username, api_key=api_key, total_points=0, created=True)
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route('/api/v1/sync', methods=['POST'])
def sync():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('api_key'), str):
        return jsonify(error="api_key is required"), 400

    api_key = data['api_key']
    if not _check_rate(_rate_sync, api_key, SYNC_LIMIT, 60):
        return jsonify(error="Rate limit exceeded. Try again in a minute."), 429

    entries = data.get('entries', [])
    known_keys = set(data.get('known_keys', []))

    if not isinstance(entries, list) or not isinstance(known_keys, set):
        return jsonify(error="Invalid request format"), 400

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Validate api_key
        cur.execute("SELECT id, username, total_points FROM contributors WHERE api_key = %s", (api_key,))
        contributor = cur.fetchone()
        if not contributor:
            return jsonify(error="Invalid api_key. Register first."), 401

        contributor_id = contributor['id']
        contributor_username = contributor['username']
        points_earned = 0
        new_accepted = 0
        duplicates_skipped = 0

        # Process uploaded entries
        for entry in entries[:5000]:  # cap at 5000 per sync
            store_id = entry.get('storeId') or entry.get('store_id')
            build_id = entry.get('buildId') or entry.get('build_id')

            if not store_id or not build_id:
                continue
            if not _validate_store_id(store_id) or not _validate_build_id(build_id):
                continue

            # Validate CDN URLs if present
            cdn_urls = entry.get('cdnUrls') or entry.get('cdn_urls')
            if isinstance(cdn_urls, list):
                cdn_urls = [u for u in cdn_urls if _validate_cdn_url(u)]
            elif isinstance(cdn_urls, str) and _validate_cdn_url(cdn_urls):
                cdn_urls = [cdn_urls]
            else:
                cdn_urls = []

            # Parse scraped_at
            scraped_at = None
            raw_scraped = entry.get('scrapedAt') or entry.get('scraped_at')
            if isinstance(raw_scraped, str):
                try:
                    scraped_at = datetime.fromisoformat(raw_scraped.replace('Z', '+00:00'))
                except Exception:
                    pass

            try:
                cur.execute("""
                    INSERT INTO cdn_entries (store_id, build_id, content_id, package_name,
                        build_version, platform, size_bytes, cdn_urls, content_types,
                        devices, language, plan_id, source, scraped_at,
                        prior_build_version, prior_build_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (store_id, build_id) DO NOTHING
                    RETURNING id
                """, (
                    store_id,
                    build_id,
                    _sanitize_str(entry.get('contentId') or entry.get('content_id'), 64),
                    _sanitize_str(entry.get('packageName') or entry.get('package_name')),
                    _sanitize_str(entry.get('buildVersion') or entry.get('build_version'), 32),
                    _sanitize_str(entry.get('platform'), 32),
                    entry.get('sizeBytes') or entry.get('size_bytes'),
                    psycopg2.extras.Json(cdn_urls) if cdn_urls else None,
                    _sanitize_str(entry.get('contentTypes') or entry.get('content_types')),
                    _sanitize_str(entry.get('devices')),
                    _sanitize_str(entry.get('language')),
                    _sanitize_str(entry.get('planId') or entry.get('plan_id')),
                    _sanitize_str(entry.get('source'), 32),
                    scraped_at,
                    _sanitize_str(entry.get('priorBuildVersion') or entry.get('prior_build_version'), 32),
                    _sanitize_str(entry.get('priorBuildId') or entry.get('prior_build_id'), 64),
                ))
                row = cur.fetchone()
                if row:
                    # New entry inserted — record contribution
                    cur.execute(
                        "INSERT INTO contributions (contributor_id, cdn_entry_id) VALUES (%s, %s)",
                        (contributor_id, row['id']))
                    points_earned += 1
                    new_accepted += 1
                else:
                    duplicates_skipped += 1
            except Exception:
                conn.rollback()
                conn = get_db()
                cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute("SELECT id, total_points FROM contributors WHERE api_key = %s", (api_key,))
                contributor = cur.fetchone()
                contributor_id = contributor['id']
                duplicates_skipped += 1
                continue

        # Update contributor points
        if points_earned > 0:
            cur.execute(
                "UPDATE contributors SET total_points = total_points + %s, last_sync_at = NOW() WHERE id = %s",
                (points_earned, contributor_id))
        else:
            cur.execute("UPDATE contributors SET last_sync_at = NOW() WHERE id = %s",
                        (contributor_id,))

        # Fetch entries the client doesn't have
        remote_entries = []
        cur.execute("SELECT store_id, build_id FROM cdn_entries WHERE NOT deleted")
        all_db_keys = set()
        for row in cur:
            all_db_keys.add(f"{row['store_id']}:{row['build_id']}")

        missing_keys = all_db_keys - known_keys
        if missing_keys:
            # Fetch full records for missing entries (cap at 5000)
            missing_list = list(missing_keys)[:5000]
            pairs = [(k.split(':', 1)[0], k.split(':', 1)[1]) for k in missing_list if ':' in k]
            if pairs:
                # Build query for missing entries
                values_clause = ','.join(
                    cur.mogrify("(%s, %s)", (s, b)).decode() for s, b in pairs)
                cur.execute(f"""
                    SELECT e.store_id, e.build_id, e.content_id, e.package_name, e.build_version,
                           e.platform, e.size_bytes, e.cdn_urls, e.content_types, e.devices,
                           e.language, e.plan_id, e.source, e.scraped_at,
                           e.prior_build_version, e.prior_build_id,
                           c2.username AS contributor
                    FROM cdn_entries e
                    LEFT JOIN contributions c ON c.cdn_entry_id = e.id
                    LEFT JOIN contributors c2 ON c2.id = c.contributor_id
                    WHERE (e.store_id, e.build_id) IN ({values_clause})
                      AND NOT e.deleted
                """)
                for row in cur:
                    remote_entries.append({
                        'storeId': row['store_id'],
                        'buildId': row['build_id'],
                        'contentId': row['content_id'],
                        'packageName': row['package_name'],
                        'buildVersion': row['build_version'],
                        'platform': row['platform'],
                        'sizeBytes': row['size_bytes'],
                        'cdnUrls': row['cdn_urls'] or [],
                        'contentTypes': row['content_types'],
                        'devices': row['devices'],
                        'language': row['language'],
                        'planId': row['plan_id'],
                        'source': row['source'],
                        'scrapedAt': row['scraped_at'].isoformat() if row['scraped_at'] else None,
                        'priorBuildVersion': row['prior_build_version'],
                        'priorBuildId': row['prior_build_id'],
                        'contributor': row['contributor'],
                    })

        # Build contributor map for all entries (storeId:buildId -> username)
        contributor_map = {}
        cur.execute("""
            SELECT e.store_id, e.build_id, c2.username
            FROM cdn_entries e
            JOIN contributions c ON c.cdn_entry_id = e.id
            JOIN contributors c2 ON c2.id = c.contributor_id
            WHERE NOT e.deleted
        """)
        for row in cur:
            contributor_map[f"{row['store_id']}:{row['build_id']}"] = row['username']

        # Get totals
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_entries WHERE NOT deleted")
        total_entries = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT store_id) as cnt FROM cdn_entries WHERE NOT deleted")
        total_games = cur.fetchone()['cnt']

        # Get updated points
        cur.execute("SELECT total_points FROM contributors WHERE id = %s", (contributor_id,))
        total_points = cur.fetchone()['total_points']

        # Log sync (only if points earned)
        if points_earned > 0:
            cur.execute("""
                INSERT INTO sync_log (contributor_id, username, points_earned, total_points,
                                      new_entries, duplicates_skipped)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (contributor_id, contributor_username, points_earned, total_points,
                  new_accepted, duplicates_skipped))

        conn.commit()
        return jsonify(
            points_earned=points_earned,
            total_points=total_points,
            new_entries_accepted=new_accepted,
            duplicates_skipped=duplicates_skipped,
            remote_entries=remote_entries,
            contributor_map=contributor_map,
            total_db_entries=total_entries,
            total_db_games=total_games,
        )
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route('/api/v1/leaderboard', methods=['GET'])
def leaderboard():
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
        rows = cur.fetchall()
        board = []
        for row in rows:
            board.append({
                'username': row['username'],
                'points': row['total_points'],
                'lastSync': row['last_sync_at'].isoformat() if row['last_sync_at'] else None,
            })

        cur.execute("SELECT COUNT(*) as cnt FROM contributors WHERE total_points > 0")
        total_contributors = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_entries WHERE NOT deleted")
        total_entries = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT store_id) as cnt FROM cdn_entries WHERE NOT deleted")
        total_games = cur.fetchone()['cnt']

        return jsonify(
            leaderboard=board,
            total_contributors=total_contributors,
            total_entries=total_entries,
            total_games=total_games,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route('/api/v1/sync_log', methods=['GET'])
def sync_log():
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
        rows = cur.fetchall()
        log = []
        for row in rows:
            log.append({
                'username': row['username'],
                'pointsEarned': row['points_earned'],
                'totalPoints': row['total_points'],
                'newEntries': row['new_entries'],
                'duplicatesSkipped': row['duplicates_skipped'],
                'syncedAt': row['synced_at'].isoformat() if row['synced_at'] else None,
            })
        return jsonify(sync_log=log)
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route('/api/v1/stats', methods=['GET'])
def stats():
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT COUNT(*) as cnt FROM cdn_entries WHERE NOT deleted")
        total_entries = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT store_id) as cnt FROM cdn_entries WHERE NOT deleted")
        total_games = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM contributors")
        total_contributors = cur.fetchone()['cnt']
        return jsonify(
            status="ok",
            total_entries=total_entries,
            total_games=total_games,
            total_contributors=total_contributors,
        )
    except Exception as e:
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


@app.route('/api/v1/admin/reset', methods=['POST'])
def admin_reset():
    """Wipe all CDN entries, contributions, and reset contributor points."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get('api_key'), str):
        return jsonify(error="api_key is required"), 400

    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Validate api_key
        cur.execute("SELECT id, username FROM contributors WHERE api_key = %s", (data['api_key'],))
        contributor = cur.fetchone()
        if not contributor:
            return jsonify(error="Invalid api_key"), 401

        # Wipe everything
        cur.execute("DELETE FROM contributions")
        cur.execute("DELETE FROM cdn_entries")
        cur.execute("UPDATE contributors SET total_points = 0, last_sync_at = NULL")
        conn.commit()

        return jsonify(
            status="ok",
            message=f"Database wiped by {contributor['username']}",
        )
    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(debug=True, port=5000)
