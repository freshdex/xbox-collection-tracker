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

def fetch_titlehub_achievements(xbl3_token, xuid):
    """Fetch achievement summaries from TitleHub for all titles.

    Returns list of dicts with keys:
        titleId, name, productId, displayImage, platforms,
        currentGamerscore, totalGamerscore, currentAchievements,
        totalAchievements, lastTimePlayed
    """
    url = (
        f"{TITLEHUB_URL}/users/xuid({xuid})/titles/titlehistory/decoration/"
        "Achievement,Image,ProductId"
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
    for title in data.get("titles", []):
        ach = title.get("achievement", {})
        results.append({
            "titleId": str(title.get("titleId", "")),
            "name": title.get("name", ""),
            "productId": title.get("productId", ""),
            "displayImage": title.get("displayImage", ""),
            "platforms": [d.get("platform", "") for d in title.get("devices", [])
                          if d.get("platform")],
            "currentGamerscore": ach.get("currentGamerscore", 0),
            "totalGamerscore": ach.get("totalGamerscore", 0),
            "currentAchievements": ach.get("currentAchievements", 0),
            "totalAchievements": ach.get("totalAchievements", 0),
            "lastTimePlayed": title.get("titleHistory", {}).get("lastTimePlayed", ""),
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
