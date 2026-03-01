"""
Xbox Live OAuth2 auth helpers for XCT Live server.

Handles the standard browser OAuth2 authorization code flow:
  1. Build authorize URL → user logs in at login.live.com
  2. Exchange authorization code → MSA access_token + refresh_token
  3. MSA access_token → Xbox User Token → XSTS Token → XBL3.0 token
  4. XBL3.0 token → TitleHub achievements + per-title achievement details

No EC P-256 signing or device tokens — uses the simple non-device-bound flow
which gives full TitleHub + achievements access via the xboxlive.com RP.
"""

import re
import time
import urllib.parse

import requests

# ---------------------------------------------------------------------------
# Microsoft OAuth2 endpoints
# ---------------------------------------------------------------------------

OAUTH_AUTHORIZE = "https://login.live.com/oauth20_authorize.srf"
OAUTH_TOKEN = "https://login.live.com/oauth20_token.srf"
USER_AUTH = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH = "https://xsts.auth.xboxlive.com/xsts/authorize"
XBOX_SCOPES = "Xboxlive.signin Xboxlive.offline_access"

# Xbox API endpoints
TITLEHUB_URL = "https://titlehub.xboxlive.com"
ACHIEVEMENTS_URL = "https://achievements.xboxlive.com"


# ---------------------------------------------------------------------------
# OAuth2 helpers
# ---------------------------------------------------------------------------

def build_authorize_url(client_id, redirect_uri, state):
    """Build the Microsoft OAuth2 authorization URL for browser redirect."""
    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": XBOX_SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    return OAUTH_AUTHORIZE + "?" + urllib.parse.urlencode(params)


def exchange_code_for_tokens(client_id, client_secret, code, redirect_uri):
    """Exchange authorization code for MSA access_token + refresh_token.

    Returns dict with keys: access_token, refresh_token, expires_in.
    Raises on HTTP error.
    """
    resp = requests.post(OAUTH_TOKEN, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "expires_in": data.get("expires_in", 3600),
    }


def refresh_msa_token(client_id, client_secret, refresh_token):
    """Refresh an MSA token. Returns new access_token + refresh_token.

    Microsoft rotates refresh tokens — always store the new one.
    Raises on HTTP error (e.g. revoked token).
    """
    resp = requests.post(OAUTH_TOKEN, data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": XBOX_SCOPES,
        "client_id": client_id,
        "client_secret": client_secret,
    }, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "expires_in": data.get("expires_in", 3600),
    }


# ---------------------------------------------------------------------------
# Xbox Live token chain
# ---------------------------------------------------------------------------

def get_xbox_user_token(access_token):
    """Exchange MSA access_token for an Xbox User Token.

    Returns the user token string.
    """
    resp = requests.post(USER_AUTH, json={
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={access_token}",
        },
    }, headers={"x-xbl-contract-version": "1"}, timeout=30)
    resp.raise_for_status()
    return resp.json()["Token"]


def get_xsts_token(user_token, relying_party="http://xboxlive.com"):
    """Exchange Xbox User Token for an XSTS token.

    Returns (xsts_token, uhs, xuid, gamertag).
    """
    resp = requests.post(XSTS_AUTH, json={
        "RelyingParty": relying_party,
        "TokenType": "JWT",
        "Properties": {
            "UserTokens": [user_token],
            "SandboxId": "RETAIL",
        },
    }, headers={"x-xbl-contract-version": "1"}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    xsts_token = data["Token"]
    display_claims = data["DisplayClaims"]["xui"][0]
    uhs = display_claims["uhs"]
    xuid = display_claims.get("xid", "")
    gamertag = display_claims.get("gtg", "")
    return xsts_token, uhs, xuid, gamertag


def build_xbl3_token(xsts_token, uhs):
    """Build an XBL3.0 authorization header value."""
    return f"XBL3.0 x={uhs};{xsts_token}"


def full_auth(access_token):
    """Full auth chain: MSA access_token → XBL3.0 token.

    Returns dict with keys: xbl3_token, xuid, gamertag, uhs.
    """
    user_token = get_xbox_user_token(access_token)
    xsts_token, uhs, xuid, gamertag = get_xsts_token(user_token)
    xbl3_token = build_xbl3_token(xsts_token, uhs)
    return {
        "xbl3_token": xbl3_token,
        "xuid": xuid,
        "gamertag": gamertag,
        "uhs": uhs,
    }


# ---------------------------------------------------------------------------
# Xbox API calls
# ---------------------------------------------------------------------------

def _parse_titlehub_titles(data):
    """Parse titles from a TitleHub response into achievement summary dicts."""
    results = []
    for title in data.get("titles", []):
        ach = title.get("achievement", {})
        results.append({
            "titleId": str(title.get("titleId", "")),
            "name": title.get("name", ""),
            "productId": title.get("productId", ""),
            "displayImage": (title.get("displayImage", "") or "").replace("http://", "https://"),
            "platforms": [d.get("platform", "") if isinstance(d, dict) else str(d)
                          for d in title.get("devices", []) if d],
            "currentGamerscore": ach.get("currentGamerscore", 0),
            "totalGamerscore": ach.get("totalGamerscore", 0),
            "currentAchievements": ach.get("currentAchievements", 0),
            "totalAchievements": ach.get("totalAchievements", 0),
            "lastTimePlayed": title.get("titleHistory", {}).get("lastTimePlayed", ""),
        })
    return results


def _fetch_history_paginated(xbl3_token, xuid, contract_version):
    """Fetch all titles from achievements.xboxlive.com/history/titles.

    Uses skipItems pagination to fetch all pages.
    contract_version=2: modern titles (Xbox One/Series/PC), ~8000+ titles
    contract_version=1: Xbox 360 titles, ~2000+ titles
    These two sets have zero overlap and must both be fetched.
    """
    url = f"{ACHIEVEMENTS_URL}/users/xuid({xuid})/history/titles"
    headers = {
        "Authorization": xbl3_token,
        "x-xbl-contract-version": str(contract_version),
        "Accept-Language": "en-US",
    }
    all_titles = []
    skip = 0

    for _ in range(50):  # safety limit
        params = {"maxItems": "1000", "skipItems": str(skip)}
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        titles = data.get("titles", [])
        if not titles:
            break
        all_titles.extend(titles)
        skip += len(titles)

        total = data.get("pagingInfo", {}).get("totalRecords", 0)
        if total and len(all_titles) >= total:
            break

    return all_titles


# v1 platform int → display name mapping
_V1_PLATFORM_MAP = {
    1: "XboxOne", 2: "Xbox360", 3: "WindowsOneCore",
    4: "Win32", 5: "iOS", 6: "Android",
}


def fetch_titlehub_achievements(xbl3_token, xuid):
    """Fetch achievement summaries by merging three Xbox Live sources.

    1. achievements.xboxlive.com/history/titles (v2) — modern titles (~8000+)
    2. achievements.xboxlive.com/history/titles (v1) — Xbox 360 titles (~2000+)
       v1 and v2 return completely separate title sets with zero overlap.
    3. titlehub.xboxlive.com/titlehistory — enrichment (images, productId)

    Returns list of dicts with keys:
        titleId, name, productId, displayImage, platforms,
        currentGamerscore, totalGamerscore, currentAchievements,
        totalAchievements, lastTimePlayed
    """
    # Step 1: Fetch v2 modern titles (Xbox One/Series/PC, ~8000+)
    v2_titles = _fetch_history_paginated(xbl3_token, xuid, contract_version=2)

    # Step 2: Fetch v1 Xbox 360 titles (~2000+, zero overlap with v2)
    v1_titles = _fetch_history_paginated(xbl3_token, xuid, contract_version=1)

    # Step 3: Fetch TitleHub for enrichment (images, productId)
    th_by_id = {}
    try:
        th_url = (
            f"{TITLEHUB_URL}/users/xuid({xuid})/titles/titlehistory/decoration/"
            "Achievement,Image,ProductId"
        )
        resp = requests.get(th_url, headers={
            "Authorization": xbl3_token,
            "x-xbl-contract-version": "2",
            "Accept-Language": "en-US",
        }, params={"maxItems": "15000"}, timeout=120)
        resp.raise_for_status()
        th_data = resp.json()
        if isinstance(th_data, dict):
            for t in th_data.get("titles", []):
                th_by_id[str(t.get("titleId", ""))] = t
    except Exception:
        pass  # TitleHub enrichment is optional

    # Step 4: Merge all sources
    results = []
    seen_ids = set()

    # Process v2 modern titles
    for title in v2_titles:
        tid = str(title.get("titleId", ""))
        if not tid or tid in seen_ids:
            continue
        seen_ids.add(tid)

        th = th_by_id.pop(tid, None)
        if th:
            ach = th.get("achievement", {})
            results.append({
                "titleId": tid,
                "name": th.get("name", "") or title.get("name", ""),
                "productId": th.get("productId", ""),
                "displayImage": (th.get("displayImage", "") or "").replace("http://", "https://"),
                "platforms": [d.get("platform", "") if isinstance(d, dict) else str(d)
                              for d in th.get("devices", []) if d],
                "currentGamerscore": title.get("currentGamerscore", 0),
                "totalGamerscore": title.get("maxGamerscore", 0) or ach.get("totalGamerscore", 0),
                "currentAchievements": title.get("earnedAchievements", 0),
                "totalAchievements": ach.get("totalAchievements", 0),
                "lastTimePlayed": title.get("lastUnlock", ""),
            })
        else:
            platform = title.get("platform", "")
            results.append({
                "titleId": tid,
                "name": title.get("name", ""),
                "productId": "",
                "displayImage": "",
                "platforms": [platform] if platform else [],
                "currentGamerscore": title.get("currentGamerscore", 0),
                "totalGamerscore": title.get("maxGamerscore", 0),
                "currentAchievements": title.get("earnedAchievements", 0),
                "totalAchievements": 0,
                "lastTimePlayed": title.get("lastUnlock", ""),
            })

    # Process v1 Xbox 360 titles (zero overlap with v2)
    for title in v1_titles:
        tid = str(title.get("titleId", ""))
        if not tid or tid in seen_ids:
            continue
        seen_ids.add(tid)

        th = th_by_id.pop(tid, None)
        platforms_raw = title.get("platforms", [])
        platforms = [_V1_PLATFORM_MAP.get(p, str(p)) for p in platforms_raw
                     ] if platforms_raw else []

        if th:
            ach = th.get("achievement", {})
            results.append({
                "titleId": tid,
                "name": th.get("name", "") or title.get("name", ""),
                "productId": th.get("productId", ""),
                "displayImage": (th.get("displayImage", "") or "").replace("http://", "https://"),
                "platforms": [d.get("platform", "") if isinstance(d, dict) else str(d)
                              for d in th.get("devices", []) if d] or platforms,
                "currentGamerscore": title.get("currentGamerscore", 0),
                "totalGamerscore": title.get("totalGamerscore", 0),
                "currentAchievements": title.get("currentAchievements", 0),
                "totalAchievements": title.get("totalAchievements", 0),
                "lastTimePlayed": title.get("lastPlayed", ""),
            })
        else:
            results.append({
                "titleId": tid,
                "name": title.get("name", ""),
                "productId": "",
                "displayImage": "",
                "platforms": platforms,
                "currentGamerscore": title.get("currentGamerscore", 0),
                "totalGamerscore": title.get("totalGamerscore", 0),
                "currentAchievements": title.get("currentAchievements", 0),
                "totalAchievements": title.get("totalAchievements", 0),
                "lastTimePlayed": title.get("lastPlayed", ""),
            })

    # Add any TitleHub-only titles
    for tid, th in th_by_id.items():
        if tid in seen_ids:
            continue
        seen_ids.add(tid)
        ach = th.get("achievement", {})
        results.append({
            "titleId": tid,
            "name": th.get("name", ""),
            "productId": th.get("productId", ""),
            "displayImage": (th.get("displayImage", "") or "").replace("http://", "https://"),
            "platforms": [d.get("platform", "") if isinstance(d, dict) else str(d)
                          for d in th.get("devices", []) if d],
            "currentGamerscore": ach.get("currentGamerscore", 0),
            "totalGamerscore": ach.get("totalGamerscore", 0),
            "currentAchievements": ach.get("currentAchievements", 0),
            "totalAchievements": ach.get("totalAchievements", 0),
            "lastTimePlayed": th.get("titleHistory", {}).get("lastTimePlayed", ""),
        })

    return results


def fetch_achievement_details(xbl3_token, xuid, title_id):
    """Fetch individual achievements for a specific title.

    Returns list of dicts with keys:
        id, name, description, gamerscore, isSecret, unlocked,
        unlockTime, rarityCategory, rarityPct, mediaUrl
    """
    url = (
        f"{ACHIEVEMENTS_URL}/users/xuid({xuid})/achievements"
        f"?titleId={title_id}&maxItems=1000"
    )
    headers = {
        "Authorization": xbl3_token,
        "x-xbl-contract-version": "2",
        "Accept-Language": "en-US",
    }
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for ach in data.get("achievements", []):
        rarity = ach.get("rarity", {})
        media_url = ""
        for asset in ach.get("mediaAssets", []):
            if asset.get("type") == "Icon":
                media_url = asset.get("url", "")
                break

        progress = ach.get("progressState", "NotStarted")
        unlock_time = ""
        if progress == "Achieved":
            progression = ach.get("progression", {})
            unlock_time = progression.get("timeUnlocked", "")

        results.append({
            "id": str(ach.get("id", "")),
            "name": ach.get("name", ""),
            "description": (ach.get("lockedDescription", "") or
                            ach.get("description", "")),
            "gamerscore": ach.get("rewards", [{}])[0].get("value", 0)
                          if ach.get("rewards") else 0,
            "isSecret": ach.get("isSecret", False),
            "unlocked": progress == "Achieved",
            "unlockTime": unlock_time,
            "rarityCategory": rarity.get("currentCategory", ""),
            "rarityPct": rarity.get("currentPercentage", 0),
            "mediaUrl": media_url,
        })
    return results


# ---------------------------------------------------------------------------
# TrueAchievements leaderboard scraper
# ---------------------------------------------------------------------------

PROFILE_URL = "https://profile.xboxlive.com"


def scrape_ta_leaderboard(leaderboard_type="gamesplayed", pages=10):
    """Scrape TrueAchievements leaderboard pages.

    Returns list of dicts: {position, gamertag, score, avatar_url}.
    ~50 entries per page × pages = ~500 gamertags.
    """
    base_url = f"https://www.trueachievements.com/leaderboard/gamer/{leaderboard_type}"
    results = []
    seen = set()

    for page in range(1, pages + 1):
        url = base_url if page == 1 else f"{base_url}?page={page}"
        try:
            resp = requests.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/131.0.0.0 Safari/537.36",
            }, timeout=30)
            resp.raise_for_status()
            html = resp.text

            # Extract rows: each row has position, gamertag link, score, optional avatar
            # Pattern: <a href="/gamer/GAMERTAG" ... >
            # Score cells and position cells vary by leaderboard
            for m in re.finditer(
                r'<tr[^>]*>.*?'
                r'(?:<td[^>]*>\s*(\d+)\s*</td>)?'  # position (group 1)
                r'.*?'
                r'<a\s+href="/gamer/([^"]+)"'        # gamertag (group 2)
                r'.*?'
                r'(?:<img[^>]+src="([^"]*)")?'        # avatar (group 3, optional)
                r'.*?</tr>',
                html, re.DOTALL
            ):
                gt = urllib.parse.unquote_plus(m.group(2)).strip()
                if not gt or gt in seen:
                    continue
                seen.add(gt)
                pos = int(m.group(1)) if m.group(1) else len(results) + 1
                avatar = m.group(3) or ""
                results.append({
                    "position": pos,
                    "gamertag": gt,
                    "score": "",
                    "avatar_url": avatar,
                })

            # Fallback: simpler per-row pattern if the above didn't match well
            if not results and page == 1:
                # Try line-by-line extraction
                for line_m in re.finditer(r'/gamer/([^"\'<>\s]+)', html):
                    gt = urllib.parse.unquote_plus(line_m.group(1)).strip()
                    if not gt or gt in seen or gt.lower() in ("leaderboard",):
                        continue
                    seen.add(gt)
                    results.append({
                        "position": len(results) + 1,
                        "gamertag": gt,
                        "score": "",
                        "avatar_url": "",
                    })

        except Exception as e:
            print(f"[TA] Page {page} failed: {e}")

        if page < pages:
            time.sleep(1)  # respectful delay

    # Extract scores from TA page — second pass with score-aware pattern
    # TA leaderboard tables have score in a specific cell
    return results


def resolve_gamertag(xbl3_token, gamertag):
    """Look up a gamertag via Xbox profile API.

    Returns {xuid, gamertag, gamerscore, avatar_url}.
    Raises on 404 (not found / private).
    """
    encoded_gt = urllib.parse.quote(gamertag)
    url = (f"{PROFILE_URL}/users/gt({encoded_gt})/profile/settings"
           f"?settings=GameDisplayName,Gamerscore,GameDisplayPicRaw")
    resp = requests.get(url, headers={
        "Authorization": xbl3_token,
        "x-xbl-contract-version": "3",
        "Accept-Language": "en-US",
    }, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    xuid = str(data.get("profileUsers", [{}])[0].get("id", ""))
    settings = {}
    for s in data.get("profileUsers", [{}])[0].get("settings", []):
        settings[s["id"]] = s["value"]

    return {
        "xuid": xuid,
        "gamertag": settings.get("GameDisplayName", gamertag),
        "gamerscore": int(settings.get("Gamerscore", 0)),
        "avatar_url": settings.get("GameDisplayPicRaw", ""),
    }


def _fetch_count_with_retry(url, xbl3_token, contract_version, retries=3):
    """Fetch pagingInfo.totalRecords with retry on timeout."""
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers={
                "Authorization": xbl3_token,
                "x-xbl-contract-version": str(contract_version),
            }, params={"maxItems": "1"}, timeout=30)
            resp.raise_for_status()
            return resp.json().get("pagingInfo", {}).get("totalRecords", 0)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if attempt < retries - 1:
                time.sleep(3)
                continue
            raise
    return 0


def fetch_games_played_count(xbl3_token, xuid):
    """Fetch games-played counts (v2 modern + v1 Xbox 360) for a XUID.

    Only requests maxItems=1 to read pagingInfo.totalRecords.
    v1 and v2 return completely separate title sets (zero overlap).
    Raises on failure so caller can mark profile as error for retry.
    Returns {v2_count, v1_count, total}.
    """
    url = f"{ACHIEVEMENTS_URL}/users/xuid({xuid})/history/titles"

    # v2: modern titles (Xbox One/Series/PC)
    v2_count = _fetch_count_with_retry(url, xbl3_token, 2)

    time.sleep(1)  # small gap between calls

    # v1: Xbox 360 titles
    v1_count = _fetch_count_with_retry(url, xbl3_token, 1)

    return {
        "v2_count": v2_count,
        "v1_count": v1_count,
        "total": v2_count + v1_count,
    }
