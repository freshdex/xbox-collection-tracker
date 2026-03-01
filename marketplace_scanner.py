#!/usr/bin/env python3
"""
XCT Marketplace Scanner — standalone hourly scanner for xct.freshdex.app

Authenticates with Xbox Live via device-bound EC P-256 flow, scans marketplace
channels across multiple regions, enriches with catalog metadata and regional
prices, and writes results directly to PostgreSQL.

Usage:
    python marketplace_scanner.py setup                 # One-time device-code auth
    python marketplace_scanner.py scan                  # Full hourly scan
    python marketplace_scanner.py scan --prices-only    # Prices-only refresh
"""

import base64
import concurrent.futures
import hashlib
import json
import logging
import os
import ssl
import struct
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request

import ecdsa
import psycopg2
import psycopg2.extras

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freshdex_cdn")
ACCOUNT_DIR = os.environ.get("SCANNER_ACCOUNT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_account"))

CLIENT_ID = "000000004c12ae6f"
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"
GC_FACTOR = 0.81

SSL_CTX = ssl.create_default_context()

MARKETPLACE_CHANNELS = {
    "MobileNewGames":     "New Games",
    "GameDeals":          "Game Deals",
    "GamesComingSoon":    "Coming Soon",
    "TopPaidGames":       "Top Paid",
    "TopFreeGames":       "Top Free",
    "XboxPlayAnywhere":   "Play Anywhere",
    "GameDemos":          "Game Demos",
    "DealsWithGamePass":  "Deals with GP",
}

PRICE_REGIONS = {
    "AR": {"locale": "es-AR", "name": "Argentina", "currency": "ARS", "symbol": "AR$"},
    "BR": {"locale": "pt-BR", "name": "Brazil", "currency": "BRL", "symbol": "R$"},
    "TR": {"locale": "tr-TR", "name": "Turkey", "currency": "TRY", "symbol": "₺"},
    "IS": {"locale": "is-IS", "name": "Iceland", "currency": "ISK", "symbol": "kr"},
    "NG": {"locale": "en-NG", "name": "Nigeria", "currency": "NGN", "symbol": "₦"},
    "TW": {"locale": "zh-TW", "name": "Taiwan", "currency": "TWD", "symbol": "NT$"},
    "NZ": {"locale": "en-NZ", "name": "New Zealand", "currency": "NZD", "symbol": "NZ$"},
    "CO": {"locale": "es-CO", "name": "Colombia", "currency": "COP", "symbol": "CO$"},
    "HK": {"locale": "zh-HK", "name": "Hong Kong", "currency": "HKD", "symbol": "HK$"},
    "US": {"locale": "en-US", "name": "USA", "currency": "USD", "symbol": "$"},
}

BROWSE_PLATFORM_MAP = {
    "XboxSeriesX":    "Xbox Series X|S",
    "XboxOne":        "Xbox One",
    "PC":             "PC",
    "XCloud":         "Cloud",
    "Handheld":       "Handheld",
    "Mobile":         "Mobile",
}

ALL_MARKETS = {
    "AE": {"locale": "ar-AE", "name": "UAE",          "currency": "AED", "symbol": "AED"},
    "AR": {"locale": "es-AR", "name": "Argentina",    "currency": "ARS", "symbol": "AR$"},
    "AT": {"locale": "de-AT", "name": "Austria",      "currency": "EUR", "symbol": "€"},
    "AU": {"locale": "en-AU", "name": "Australia",    "currency": "AUD", "symbol": "A$"},
    "BE": {"locale": "fr-BE", "name": "Belgium",      "currency": "EUR", "symbol": "€"},
    "BG": {"locale": "bg-BG", "name": "Bulgaria",     "currency": "BGN", "symbol": "лв"},
    "BH": {"locale": "ar-BH", "name": "Bahrain",      "currency": "BHD", "symbol": "BD"},
    "BR": {"locale": "pt-BR", "name": "Brazil",       "currency": "BRL", "symbol": "R$"},
    "CA": {"locale": "en-CA", "name": "Canada",       "currency": "CAD", "symbol": "CA$"},
    "CH": {"locale": "de-CH", "name": "Switzerland",  "currency": "CHF", "symbol": "CHF"},
    "CL": {"locale": "es-CL", "name": "Chile",        "currency": "CLP", "symbol": "CL$"},
    "CN": {"locale": "zh-CN", "name": "China",        "currency": "CNY", "symbol": "¥"},
    "CO": {"locale": "es-CO", "name": "Colombia",     "currency": "COP", "symbol": "CO$"},
    "CY": {"locale": "el-CY", "name": "Cyprus",       "currency": "EUR", "symbol": "€"},
    "CZ": {"locale": "cs-CZ", "name": "Czechia",      "currency": "CZK", "symbol": "Kč"},
    "DE": {"locale": "de-DE", "name": "Germany",      "currency": "EUR", "symbol": "€"},
    "DK": {"locale": "da-DK", "name": "Denmark",      "currency": "DKK", "symbol": "kr"},
    "EE": {"locale": "et-EE", "name": "Estonia",      "currency": "EUR", "symbol": "€"},
    "EG": {"locale": "ar-EG", "name": "Egypt",        "currency": "EGP", "symbol": "E£"},
    "ES": {"locale": "es-ES", "name": "Spain",        "currency": "EUR", "symbol": "€"},
    "FI": {"locale": "fi-FI", "name": "Finland",      "currency": "EUR", "symbol": "€"},
    "FR": {"locale": "fr-FR", "name": "France",       "currency": "EUR", "symbol": "€"},
    "GB": {"locale": "en-GB", "name": "UK",           "currency": "GBP", "symbol": "£"},
    "GR": {"locale": "el-GR", "name": "Greece",       "currency": "EUR", "symbol": "€"},
    "GT": {"locale": "es-GT", "name": "Guatemala",    "currency": "GTQ", "symbol": "Q"},
    "HK": {"locale": "zh-HK", "name": "Hong Kong",    "currency": "HKD", "symbol": "HK$"},
    "HR": {"locale": "hr-HR", "name": "Croatia",      "currency": "EUR", "symbol": "€"},
    "HU": {"locale": "hu-HU", "name": "Hungary",      "currency": "HUF", "symbol": "Ft"},
    "ID": {"locale": "id-ID", "name": "Indonesia",    "currency": "IDR", "symbol": "Rp"},
    "IE": {"locale": "en-IE", "name": "Ireland",      "currency": "EUR", "symbol": "€"},
    "IL": {"locale": "he-IL", "name": "Israel",       "currency": "ILS", "symbol": "₪"},
    "IN": {"locale": "en-IN", "name": "India",        "currency": "INR", "symbol": "₹"},
    "IS": {"locale": "is-IS", "name": "Iceland",      "currency": "ISK", "symbol": "kr"},
    "IT": {"locale": "it-IT", "name": "Italy",        "currency": "EUR", "symbol": "€"},
    "JP": {"locale": "ja-JP", "name": "Japan",        "currency": "JPY", "symbol": "¥"},
    "KR": {"locale": "ko-KR", "name": "South Korea",  "currency": "KRW", "symbol": "₩"},
    "KW": {"locale": "ar-KW", "name": "Kuwait",       "currency": "KWD", "symbol": "KD"},
    "LT": {"locale": "lt-LT", "name": "Lithuania",    "currency": "EUR", "symbol": "€"},
    "LV": {"locale": "lv-LV", "name": "Latvia",       "currency": "EUR", "symbol": "€"},
    "MT": {"locale": "en-MT", "name": "Malta",        "currency": "EUR", "symbol": "€"},
    "MX": {"locale": "es-MX", "name": "Mexico",       "currency": "MXN", "symbol": "MX$"},
    "MY": {"locale": "ms-MY", "name": "Malaysia",     "currency": "MYR", "symbol": "RM"},
    "NG": {"locale": "en-NG", "name": "Nigeria",      "currency": "NGN", "symbol": "₦"},
    "NL": {"locale": "nl-NL", "name": "Netherlands",  "currency": "EUR", "symbol": "€"},
    "NO": {"locale": "nb-NO", "name": "Norway",       "currency": "NOK", "symbol": "kr"},
    "NZ": {"locale": "en-NZ", "name": "New Zealand",  "currency": "NZD", "symbol": "NZ$"},
    "OM": {"locale": "ar-OM", "name": "Oman",         "currency": "OMR", "symbol": "OMR"},
    "PE": {"locale": "es-PE", "name": "Peru",         "currency": "PEN", "symbol": "S/"},
    "PH": {"locale": "en-PH", "name": "Philippines",  "currency": "PHP", "symbol": "₱"},
    "PL": {"locale": "pl-PL", "name": "Poland",       "currency": "PLN", "symbol": "zł"},
    "PT": {"locale": "pt-PT", "name": "Portugal",     "currency": "EUR", "symbol": "€"},
    "QA": {"locale": "ar-QA", "name": "Qatar",        "currency": "QAR", "symbol": "QR"},
    "RO": {"locale": "ro-RO", "name": "Romania",      "currency": "RON", "symbol": "lei"},
    "RS": {"locale": "sr-RS", "name": "Serbia",       "currency": "RSD", "symbol": "din"},
    "RU": {"locale": "ru-RU", "name": "Russia",       "currency": "RUB", "symbol": "₽"},
    "SA": {"locale": "ar-SA", "name": "Saudi Arabia",  "currency": "SAR", "symbol": "SAR"},
    "SE": {"locale": "sv-SE", "name": "Sweden",       "currency": "SEK", "symbol": "kr"},
    "SG": {"locale": "en-SG", "name": "Singapore",    "currency": "SGD", "symbol": "S$"},
    "SI": {"locale": "sl-SI", "name": "Slovenia",     "currency": "EUR", "symbol": "€"},
    "SK": {"locale": "sk-SK", "name": "Slovakia",     "currency": "EUR", "symbol": "€"},
    "TH": {"locale": "th-TH", "name": "Thailand",     "currency": "THB", "symbol": "฿"},
    "TR": {"locale": "tr-TR", "name": "Turkey",       "currency": "TRY", "symbol": "₺"},
    "TT": {"locale": "en-TT", "name": "Trinidad",     "currency": "TTD", "symbol": "TT$"},
    "TW": {"locale": "zh-TW", "name": "Taiwan",       "currency": "TWD", "symbol": "NT$"},
    "UA": {"locale": "uk-UA", "name": "Ukraine",      "currency": "UAH", "symbol": "₴"},
    "US": {"locale": "en-US", "name": "USA",          "currency": "USD", "symbol": "$"},
    "VN": {"locale": "vi-VN", "name": "Vietnam",      "currency": "VND", "symbol": "₫"},
    "ZA": {"locale": "en-ZA", "name": "South Africa",  "currency": "ZAR", "symbol": "R"},
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("scanner")

# ---------------------------------------------------------------------------
# EC P-256 request signing (extracted from XCT.py RequestSigner)
# ---------------------------------------------------------------------------

_FILETIME_EPOCH_OFFSET = 116444736000000000


def _base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s):
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


class RequestSigner:
    """Signs Xbox Live requests with EC P-256 proof-of-possession."""

    SIGNATURE_VERSION = 1
    MAX_BODY_BYTES = 8192

    def __init__(self, ec_key=None):
        if ec_key is None:
            self.signing_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        else:
            self.signing_key = ec_key
        self.verifying_key = self.signing_key.get_verifying_key()

    @classmethod
    def from_state(cls, state_dict):
        if not state_dict or "d" not in state_dict:
            return None
        try:
            d_bytes = _base64url_decode(state_dict["d"])
            sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.NIST256p)
            return cls(ec_key=sk)
        except Exception as e:
            log.warning("RequestSigner.from_state failed: %s", e)
            return None

    def export_state(self):
        d_bytes = self.signing_key.to_string()
        x_bytes, y_bytes = self._get_xy_bytes()
        return {
            "kty": "EC", "crv": "P-256",
            "d": _base64url_encode(d_bytes),
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }

    def get_proof_key(self):
        x_bytes, y_bytes = self._get_xy_bytes()
        return {
            "use": "sig", "alg": "ES256", "kty": "EC", "crv": "P-256",
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }

    def sign_request(self, method, url, authorization="", body=b"", timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        filetime = _FILETIME_EPOCH_OFFSET + int(timestamp * 10_000_000)
        parsed = urllib.parse.urlparse(url)
        path_and_query = parsed.path
        if parsed.query:
            path_and_query += "?" + parsed.query
        version_bytes = struct.pack(">I", self.SIGNATURE_VERSION)
        filetime_bytes = struct.pack(">Q", filetime)
        signing_data = b""
        signing_data += version_bytes + b"\x00"
        signing_data += filetime_bytes + b"\x00"
        signing_data += method.upper().encode("ascii") + b"\x00"
        signing_data += path_and_query.encode("ascii") + b"\x00"
        signing_data += authorization.encode("ascii") + b"\x00"
        signing_data += body[:self.MAX_BODY_BYTES] + b"\x00"
        digest = hashlib.sha256(signing_data).digest()
        signature = self.signing_key.sign_digest_deterministic(
            digest, sigencode=ecdsa.util.sigencode_string)
        sig_header = version_bytes + filetime_bytes + signature
        return base64.b64encode(sig_header).decode("ascii")

    def _get_xy_bytes(self):
        pub_bytes = self.verifying_key.to_string()
        return pub_bytes[:32], pub_bytes[32:]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _cv():
    """Generate a correlation vector."""
    return base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"


def _signed_request(signer, method, url, body_dict=None, headers=None, timeout=30):
    if headers is None:
        headers = {}
    body = b""
    if body_dict is not None:
        body = json.dumps(body_dict).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    auth_header = headers.get("Authorization", "")
    signature = signer.sign_request(method, url, authorization=auth_header, body=body)
    headers["Signature"] = signature
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=headers)
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def msa_request(url, params):
    body = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_request(url, method="GET", headers=None, body=None, retries=3):
    hdrs = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                wait = 2 ** attempt
                log.warning("HTTP %d on %s, retry in %ds", e.code, url[:80], wait)
                time.sleep(wait)
                continue
            log.error("HTTP %d on %s: %s", e.code, url[:80], err_body[:200])
            return None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            log.error("Error on %s: %s", url[:80], e)
            return None
    return None


# ---------------------------------------------------------------------------
# Xbox Live auth chain
# ---------------------------------------------------------------------------

def device_code_auth():
    """Device code flow for initial setup. Returns (access_token, refresh_token)."""
    log.info("Starting device code flow...")
    resp = msa_request("https://login.live.com/oauth20_connect.srf", {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "response_type": "device_code",
    })
    user_code = resp["user_code"]
    verification_uri = resp["verification_uri"]
    device_code = resp["device_code"]
    interval = resp.get("interval", 5)

    print()
    print("=" * 56)
    print(f"  Go to:   {verification_uri}")
    print(f"  Enter:   {user_code}")
    print("=" * 56)
    print()
    print("Waiting for sign-in...")

    poll_params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }).encode("utf-8")

    while True:
        time.sleep(interval)
        try:
            req = urllib.request.Request(
                "https://login.live.com/oauth20_token.srf",
                data=poll_params, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=30) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))
            log.info("Sign-in complete!")
            return token_resp["access_token"], token_resp.get("refresh_token")
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            if "authorization_pending" not in error_body and "slow_down" not in error_body:
                log.warning("Unexpected polling error (HTTP %d): %s", e.code, error_body[:200])
        except Exception:
            pass


def get_device_token(signer, device_id=None):
    if device_id is None:
        device_id = str(uuid.uuid4())
    url = "https://device.auth.xboxlive.com/device/authenticate"
    data = {
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "ProofOfPossession",
            "Id": "{%s}" % device_id,
            "DeviceType": "Android",
            "Version": "8.0.0",
            "ProofKey": signer.get_proof_key(),
        },
    }
    headers = {"x-xbl-contract-version": "1", "Content-Type": "application/json", "MS-CV": _cv()}
    resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    return resp["Token"], device_id


def sisu_authorize(signer, msa_token, device_token):
    url = "https://sisu.xboxlive.com/authorize"
    data = {
        "AccessToken": f"t={msa_token}",
        "AppId": CLIENT_ID,
        "DeviceToken": device_token,
        "Sandbox": "RETAIL",
        "SiteName": "user.auth.xboxlive.com",
        "ProofKey": signer.get_proof_key(),
    }
    headers = {"x-xbl-contract-version": "1", "Content-Type": "application/json"}
    resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    display = resp.get("AuthorizationToken", {}).get("DisplayClaims", {})
    xui = display.get("xui", [{}])[0] if display.get("xui") else {}
    return {
        "user_token": resp.get("UserToken", {}).get("Token", ""),
        "title_token": resp.get("TitleToken", {}).get("Token", ""),
        "authorization_token": resp.get("AuthorizationToken", {}).get("Token", ""),
        "userhash": xui.get("uhs", ""),
        "xuid": xui.get("xid", ""),
        "gamertag": xui.get("gtg", ""),
    }


def get_xsts_token(signer, user_token, device_token, title_token, relying_party):
    url = "https://xsts.auth.xboxlive.com/xsts/authorize"
    data = {
        "RelyingParty": relying_party,
        "TokenType": "JWT",
        "Properties": {
            "SandboxId": "RETAIL",
            "DeviceToken": device_token,
            "TitleToken": title_token,
            "UserTokens": [user_token],
        },
    }
    headers = {"x-xbl-contract-version": "1", "Content-Type": "application/json"}
    resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    token = resp["Token"]
    uhs = resp["DisplayClaims"]["xui"][0]["uhs"]
    return token, uhs


def build_xbl3_token(xsts_token, user_hash):
    return f"XBL3.0 x={user_hash};{xsts_token}"


def authenticate(state):
    """Full device-bound auth from saved state. Returns (auth_xl, auth_mp, signer, state_dict)."""
    refresh_token = state["refresh_token"]
    device_id = state.get("device_id")
    signer = RequestSigner.from_state(state.get("ec_key"))
    if signer is None:
        signer = RequestSigner()
        log.info("Generated new EC P-256 device key")

    log.info("Refreshing MSA token...")
    msa_resp = msa_request("https://login.live.com/oauth20_token.srf", {
        "client_id": CLIENT_ID, "scope": SCOPE,
        "grant_type": "refresh_token", "refresh_token": refresh_token,
    })
    msa_token = msa_resp["access_token"]
    new_refresh = msa_resp.get("refresh_token", refresh_token)

    log.info("Registering device...")
    if device_id is None:
        device_id = str(uuid.uuid4())
    device_token, device_id = get_device_token(signer, device_id)

    log.info("SISU authorization...")
    sisu_result = sisu_authorize(signer, msa_token, device_token)
    user_token = sisu_result["user_token"]
    title_token = sisu_result["title_token"]
    gamertag = sisu_result["gamertag"]
    log.info("Authenticated as %s", gamertag)

    log.info("Getting XSTS tokens...")
    xl_token, xl_uhs = get_xsts_token(signer, user_token, device_token, title_token, "http://xboxlive.com")
    mp_token, mp_uhs = get_xsts_token(signer, user_token, device_token, title_token, "http://mp.microsoft.com/")

    auth_xl = build_xbl3_token(xl_token, xl_uhs)
    auth_mp = build_xbl3_token(mp_token, mp_uhs)

    new_state = {
        "refresh_token": new_refresh,
        "ec_key": signer.export_state(),
        "device_id": device_id,
    }
    return auth_xl, auth_mp, signer, new_state


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _state_file():
    return os.path.join(ACCOUNT_DIR, "xbox_auth_state.json")


def _token_age_hours():
    tf = os.path.join(ACCOUNT_DIR, "token_timestamp")
    if not os.path.isfile(tf):
        return 999
    return (time.time() - os.path.getmtime(tf)) / 3600


def load_state():
    path = _state_file()
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def save_state(state):
    os.makedirs(ACCOUNT_DIR, exist_ok=True)
    with open(_state_file(), "w") as f:
        json.dump(state, f, indent=2)
    # Touch timestamp file for token age tracking
    ts_file = os.path.join(ACCOUNT_DIR, "token_timestamp")
    with open(ts_file, "w") as f:
        f.write(str(time.time()))


def get_tokens():
    """Load state, authenticate if needed, return (auth_xl, auth_mp)."""
    state = load_state()
    if state is None:
        raise RuntimeError("No auth state found. Run 'marketplace_scanner.py setup' first.")

    if _token_age_hours() > 10:
        log.info("Token is >10h old, refreshing...")
        auth_xl, auth_mp, signer, new_state = authenticate(state)
        save_state(new_state)
        return auth_xl, auth_mp

    # Try to reuse cached tokens
    cached_xl = os.path.join(ACCOUNT_DIR, "auth_token_xl.txt")
    cached_mp = os.path.join(ACCOUNT_DIR, "auth_token_mp.txt")
    if os.path.isfile(cached_xl) and os.path.isfile(cached_mp):
        with open(cached_xl) as f:
            auth_xl = f.read().strip()
        with open(cached_mp) as f:
            auth_mp = f.read().strip()
        if auth_xl and auth_mp:
            return auth_xl, auth_mp

    # Cached tokens missing, re-auth
    auth_xl, auth_mp, signer, new_state = authenticate(state)
    save_state(new_state)
    # Cache the tokens
    with open(cached_xl, "w") as f:
        f.write(auth_xl)
    with open(cached_mp, "w") as f:
        f.write(auth_mp)
    return auth_xl, auth_mp


def refresh_tokens():
    """Force token refresh. Returns (auth_xl, auth_mp)."""
    state = load_state()
    if state is None:
        raise RuntimeError("No auth state found.")
    auth_xl, auth_mp, signer, new_state = authenticate(state)
    save_state(new_state)
    cached_xl = os.path.join(ACCOUNT_DIR, "auth_token_xl.txt")
    cached_mp = os.path.join(ACCOUNT_DIR, "auth_token_mp.txt")
    with open(cached_xl, "w") as f:
        f.write(auth_xl)
    with open(cached_mp, "w") as f:
        f.write(auth_mp)
    return auth_xl, auth_mp


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


# ---------------------------------------------------------------------------
# API functions (adapted from XCT.py)
# ---------------------------------------------------------------------------

def fetch_dynamic_channel(channel_name, auth_token, market="GB", lang="en-GB"):
    """Fetch product IDs from a marketplace DynamicChannel."""
    url = (f"https://bronze.xboxservices.com/Channel/"
           f"DynamicChannel.{channel_name}?market={market}&language={lang}")
    req = urllib.request.Request(url, headers={
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MS-CV": _cv(),
        "Accept-Language": lang,
    })
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        log.warning("DynamicChannel.%s %s HTTP %d: %s", channel_name, market, e.code, err_body[:100])
        return []
    except urllib.error.URLError as e:
        log.warning("DynamicChannel.%s %s failed: %s", channel_name, market, e)
        return []
    return data.get("productIds", [])


def fetch_catalog_v3(product_ids, auth_token_xl, market="US", lang="en-US"):
    """Fetch rich product metadata via catalog.gamepass.com/v3/products."""
    if not product_ids:
        return {}
    unique_ids = list(dict.fromkeys(product_ids))
    url = (f"https://catalog.gamepass.com/v3/products"
           f"?market={market}&language={lang}&hydration=MobileLowAmber0")

    # Batch into chunks to avoid gateway timeouts
    BATCH = 2000
    products = {}
    for i in range(0, len(unique_ids), BATCH):
        chunk = unique_ids[i:i + BATCH]
        body = json.dumps({"Products": chunk}).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={
            "Authorization": auth_token_xl,
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
            log.info("  catalog_v3 batch %d-%d: %d products", i, i + len(chunk), len(data.get("Products", {})))
        except Exception as e:
            log.error("catalog_v3 batch %d-%d failed: %s", i, i + len(chunk), e)
    if not products:
        return None

    plat_map = {
        "Console": "Xbox One", "XboxOne": "Xbox One",
        "XboxSeriesX": "Xbox Series X|S", "PC": "PC",
        "Desktop": "PC", "Handheld": "PC", "XCloud": "xCloud",
        "Mobile": "Mobile",
    }

    catalog = {}
    for pid, info in products.items():
        prices = info.get("approximatePrices", {})
        msrp_obj = prices.get("msrp", {})
        msrp_val = msrp_obj.get("value", 0) or 0
        sale_obj = prices.get("anonymousDiscountPrice", {})
        current_val = sale_obj.get("value", msrp_val) if sale_obj else msrp_val

        v3_platforms = info.get("availablePlatforms", [])
        platforms = []
        for p in v3_platforms:
            mapped = plat_map.get(p, p)
            if mapped not in platforms:
                platforms.append(mapped)

        tile_img = info.get("tileImage", {})
        poster_img = info.get("posterImage", {})
        hero_img = info.get("heroImage", {}) or info.get("titledHeroArt", {})
        categories = info.get("categories", [])

        catalog[pid] = {
            "title": info.get("name", ""),
            "developer": info.get("developerName", ""),
            "publisher": info.get("publisherName", ""),
            "image": tile_img.get("uri", ""),
            "boxArt": poster_img.get("uri", ""),
            "heroImage": hero_img.get("uri", ""),
            "category": categories[0] if categories else "",
            "releaseDate": (info.get("releaseDate", "") or "")[:10],
            "platforms": sorted(platforms),
            "productKind": info.get("productKind", ""),
            "alternateIds": info.get("alternateIds", []),
            "isBundle": info.get("isBundle", False),
            "isEAPlay": info.get("isEAPlay", False),
            "xCloudIsStreamable": info.get("xCloudIsStreamable", False),
            "capabilities": info.get("capabilities", []),
            "priceUSD": msrp_val,
            "currentPriceUSD": current_val,
            "shortDescription": info.get("shortDescription", ""),
            "averageRating": info.get("averageRating", 0) or 0,
            "ratingCount": info.get("ratingCount", 0) or 0,
        }
    return catalog


def _fetch_region_prices(market, info, product_ids, auth_token_xl):
    """Fetch prices from catalog v3 for a single market region, batched."""
    locale = info["locale"]
    currency = info["currency"]
    base_url = (f"https://catalog.gamepass.com/v3/products"
                f"?market={market}&language={locale}&hydration=MobileLowAmber0")

    BATCH = 2000
    region_prices = {}
    for i in range(0, len(product_ids), BATCH):
        chunk = product_ids[i:i + BATCH]
        body = json.dumps({"Products": chunk}).encode("utf-8")
        req = urllib.request.Request(base_url, data=body, headers={
            "Authorization": auth_token_xl,
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
        except Exception as e:
            log.warning("Regional prices %s batch %d failed: %s", market, i // BATCH, e)
            time.sleep(2)
            continue

        products = data.get("Products", {})
        for pid, pdata in products.items():
            prices = pdata.get("approximatePrices", {})
            msrp_obj = prices.get("msrp", {})
            msrp = msrp_obj.get("value", 0) or 0
            sale_obj = prices.get("anonymousDiscountPrice", {})
            sale = sale_obj.get("value", 0) if sale_obj else 0
            if msrp > 0:
                region_prices[pid] = {
                    "price": msrp,
                    "salePrice": sale if sale > 0 and sale < msrp else 0,
                    "currency": currency,
                }
    return market, region_prices


def fetch_regional_prices(product_ids, auth_token_xl):
    """Fetch prices across all PRICE_REGIONS sequentially to avoid API rate limits."""
    unique_ids = list(dict.fromkeys(product_ids))
    results = {}
    for market, info in PRICE_REGIONS.items():
        try:
            market, prices = _fetch_region_prices(market, info, unique_ids, auth_token_xl)
            results[market] = prices
            log.info("  %s: %d products with prices", market, len(prices))
        except Exception as e:
            log.error("  %s: failed (%s)", market, e)
            results[market] = {}
    return results


def fetch_browse_all(auth_token, locale="en-US"):
    """Scrape Xbox Marketplace catalog via emerald browse endpoint."""
    url = f"https://emerald.xboxservices.com/xboxcomfd/browse?locale={locale}"
    sort_key = "Title Asc"
    channel_key = "BROWSE_CHANNELID=_FILTERS=ORDERBY=TITLE ASC"
    filters_obj = {"orderby": {"id": "orderby", "choices": [{"id": sort_key}]}}
    filters_b64 = base64.b64encode(json.dumps(filters_obj).encode()).decode()

    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "x-ms-api-version": "1.1",
        "Accept": "*/*",
        "Origin": "https://www.xbox.com",
        "Referer": "https://www.xbox.com/",
    }

    products = []
    encoded_ct = ""
    has_more = True
    seen_ids = set()
    page = 1
    errors = 0
    total_items = 0

    log.info("Starting browse catalog scrape (Title A-Z)")

    while has_more:
        body = {
            "Filters": filters_b64,
            "ReturnFilters": page == 1,
            "ChannelKeyToBeUsedInResponse": channel_key,
            "ChannelId": "",
        }
        if encoded_ct:
            body["EncodedCT"] = encoded_ct

        headers["MS-CV"] = _cv()
        data_bytes = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers)

        success = False
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as resp:
                    resp_data = json.loads(resp.read())
                success = True
                break
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    raise
                if e.code in (403, 429) and attempt < 5:
                    wait = min(2 ** attempt, 60)
                    log.warning("Browse page %d: HTTP %d, retry in %ds", page, e.code, wait)
                    time.sleep(wait)
                    continue
                log.error("Browse page %d: HTTP %d", page, e.code)
                errors += 1
                break
            except Exception as e:
                if attempt < 5:
                    time.sleep(2)
                    continue
                log.error("Browse page %d error: %s", page, e)
                errors += 1
                break

        if not success:
            if errors >= 20:
                log.warning("Too many browse errors, stopping at %d products", len(products))
                break
            continue

        channels = resp_data.get("channels", {})
        channel = channels.get(channel_key, {})
        if not channel and channels:
            channel = next(iter(channels.values()))

        if channel:
            total_items = channel.get("totalItems", total_items)
            encoded_ct = channel.get("encodedCT", "")
        else:
            encoded_ct = ""

        page_products = resp_data.get("productSummaries", [])
        new_count = 0
        for item in page_products:
            pid = item.get("productId", "")
            if pid and pid not in seen_ids:
                seen_ids.add(pid)
                products.append(item)
                new_count += 1

        has_more = bool(encoded_ct)

        if page % 50 == 0 or not has_more:
            log.info("  Browse: %d/%d products (page %d)", len(products), total_items, page)

        page += 1
        time.sleep(0.5)

    log.info("Browse catalog complete: %d products", len(products))
    return products


def browse_to_catalog_entries(products):
    """Convert browse productSummaries to a dict keyed by product ID with basic info."""
    entries = {}
    for p in products:
        pid = p.get("productId", "")
        if not pid:
            continue
        title = p.get("title", "")
        if not title:
            continue

        platforms = []
        for plat in p.get("availableOn", []):
            mapped = BROWSE_PLATFORM_MAP.get(plat, plat)
            if mapped and mapped not in platforms:
                platforms.append(mapped)

        images = p.get("images", {})
        entries[pid] = {
            "title": title,
            "publisher": p.get("publisherName", ""),
            "developer": p.get("developerName", ""),
            "category": (p.get("categories", []) or [""])[0],
            "releaseDate": p.get("releaseDate", ""),
            "platforms": platforms,
            "productKind": p.get("productKind", ""),
            "shortDescription": p.get("shortDescription", ""),
            "averageRating": p.get("averageRating", 0) or 0,
            "ratingCount": p.get("ratingCount", 0) or 0,
            "boxArt": images.get("boxArt", {}).get("url", ""),
            "heroImage": images.get("superHeroArt", {}).get("url", ""),
            "image": images.get("poster", {}).get("url", "") or images.get("boxArt", {}).get("url", ""),
        }
    return entries


def fetch_exchange_rates():
    """Fetch USD exchange rates from open.er-api.com."""
    url = "https://open.er-api.com/v6/latest/USD"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "XCT-Scanner/1.0"})
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            data = json.loads(resp.read())
        rates = data.get("rates", {})
        log.info("Exchange rates: %d currencies", len(rates))
        return rates
    except Exception as e:
        log.error("Exchange rates failed: %s", e)
        return {
            "ARS": 1200, "BRL": 5.8, "TRY": 36, "ISK": 140,
            "NGN": 1600, "TWD": 32, "NZD": 1.72, "COP": 4400,
            "HKD": 7.82, "USD": 1.0,
        }


def _norm_kind(kind):
    if kind and kind.isupper():
        return kind.capitalize()
    return kind


# ---------------------------------------------------------------------------
# Scan phases
# ---------------------------------------------------------------------------

def phase_channels(auth_mp, channel_filter=None, region_filter=None):
    """Phase 2: Fetch DynamicChannels across all markets.

    Returns {pid: {"channels": set, "regions": set}}.
    """
    channels_dict = MARKETPLACE_CHANNELS
    if channel_filter:
        channels_dict = {k: v for k, v in MARKETPLACE_CHANNELS.items() if k == channel_filter}
    channels = list(channels_dict.keys())
    markets = ALL_MARKETS
    if region_filter:
        markets = {k: v for k, v in ALL_MARKETS.items() if k == region_filter}
    pid_meta = {}

    for cc, info in markets.items():
        locale = info["locale"]
        name = info["name"]
        log.info("Scanning channels for %s (%s)...", name, cc)
        for ch in channels:
            pids = fetch_dynamic_channel(ch, auth_mp, market=cc, lang=locale)
            ch_label = MARKETPLACE_CHANNELS.get(ch, ch)
            for pid in pids:
                if pid not in pid_meta:
                    pid_meta[pid] = {"channels": set(), "regions": set()}
                pid_meta[pid]["channels"].add(ch_label)
                pid_meta[pid]["regions"].add(cc)

    log.info("Channels phase: %d unique products across %d markets", len(pid_meta), len(markets))
    return pid_meta


def phase_browse(auth_mp, scan_hour, force=False):
    """Phase 3: Browse catalog scrape (every 6th hour only).

    Returns {pid: browse_entry} or empty dict if skipped.
    """
    if not force and scan_hour % 6 != 0:
        log.info("Browse phase skipped (hour %d, runs every 6th hour)", scan_hour)
        return {}

    try:
        products = fetch_browse_all(auth_mp, locale="en-US")
        entries = browse_to_catalog_entries(products)
        log.info("Browse phase: %d products", len(entries))
        return entries
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise
        log.error("Browse phase failed: HTTP %d", e.code)
        return {}
    except Exception as e:
        log.error("Browse phase failed: %s", e)
        return {}


def phase_catalog(all_pids, auth_xl):
    """Phase 4: Catalog v3 enrichment."""
    log.info("Enriching %d products via catalog v3...", len(all_pids))
    catalog = fetch_catalog_v3(list(all_pids), auth_xl, market="US", lang="en-US")
    if catalog is None:
        log.error("Catalog v3 returned None")
        return {}
    log.info("Catalog v3: %d products enriched", len(catalog))
    return catalog


def _fetch_trial_batch(product_ids):
    """Fetch a batch of up to 20 product IDs from Display Catalog v7 for trial detection."""
    ids_str = ",".join(product_ids)
    url = (f"https://displaycatalog.md.mp.microsoft.com/v7.0/products"
           f"?bigIds={ids_str}&market=US&languages=en-US")
    req = urllib.request.Request(url, headers={
        "User-Agent": "okhttp/4.12.0", "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception:
        return {}
    results = {}
    for product in data.get("Products", []):
        pid = product.get("ProductId")
        if not pid:
            continue
        has_trial = False
        for da in (product.get("DisplaySkuAvailabilities") or []):
            sku_props = da.get("Sku", {}).get("Properties", {})
            if sku_props.get("IsTrial", False):
                for avail in (da.get("Availabilities") or []):
                    if "Purchase" in (avail.get("Actions") or []):
                        has_trial = True
                        break
                if has_trial:
                    break
        results[pid] = has_trial
    return results


def phase_trials(all_pids):
    """Detect free trial SKUs via Display Catalog v7 (no auth required)."""
    pids = list(all_pids)
    if not pids:
        return {}
    log.info("Checking %d products for free trials via Display Catalog v7...", len(pids))
    batches = [pids[i:i + 20] for i in range(0, len(pids), 20)]
    trial_map = {}
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_fetch_trial_batch, batch): batch for batch in batches}
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                trial_map.update(future.result())
            except Exception as e:
                log.warning("Trial batch error: %s", e)
            if completed % 50 == 0 or completed == len(batches):
                log.info("  Trial detection: %d/%d batches", completed, len(batches))
    trial_count = sum(1 for v in trial_map.values() if v)
    log.info("Found %d products with free trials", trial_count)
    return trial_map


def phase_prices(all_pids, auth_xl):
    """Phase 5: Regional prices."""
    log.info("Fetching regional prices for %d products...", len(all_pids))
    return fetch_regional_prices(list(all_pids), auth_xl)


# ---------------------------------------------------------------------------
# Database writes
# ---------------------------------------------------------------------------

def db_mark_stale_scans(conn):
    """Mark any running scans >30 min old as failed."""
    cur = conn.cursor()
    cur.execute("""
        UPDATE marketplace_scans
        SET status = 'failed', completed_at = NOW(),
            errors = COALESCE(errors, '[]'::jsonb) || '"stale guard: marked failed"'::jsonb
        WHERE status = 'running'
          AND started_at < NOW() - INTERVAL '30 minutes'
    """)
    if cur.rowcount > 0:
        log.warning("Marked %d stale scan(s) as failed", cur.rowcount)
    conn.commit()
    cur.close()


def db_start_scan(conn, scan_type="full"):
    """Insert a new scan record, return its ID."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO marketplace_scans (status, scan_type)
        VALUES ('running', %s)
        RETURNING id
    """, (scan_type,))
    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    return scan_id


def db_update_scan(conn, scan_id, **kwargs):
    """Update scan record fields."""
    if not kwargs:
        return
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k == "errors" and isinstance(v, list):
            sets.append(f"{k} = %s::jsonb")
            vals.append(json.dumps(v))
        elif isinstance(v, str) and v.upper() == "NOW()":
            sets.append(f"{k} = NOW()")
        else:
            sets.append(f"{k} = %s")
            vals.append(v)
    vals.append(scan_id)
    cur = conn.cursor()
    cur.execute(f"UPDATE marketplace_scans SET {', '.join(sets)} WHERE id = %s", vals)
    conn.commit()
    cur.close()


def db_write_changelog(conn, entries):
    """Batch-insert changelog entries.

    Each entry: (scan_id, change_type, product_id, title, field_name, old_value, new_value, market)
    """
    if not entries:
        return
    cur = conn.cursor()
    psycopg2.extras.execute_values(cur, """
        INSERT INTO marketplace_changelog
            (scan_id, change_type, product_id, title, field_name, old_value, new_value, market)
        VALUES %s
    """, entries)
    conn.commit()
    log.info("Changelog: %d entries written", len(entries))


def db_write_products(conn, catalog, pid_meta, browse_entries, scan_id, trial_map=None):
    """Upsert products into marketplace_products."""
    all_pids = set(catalog.keys()) | set(pid_meta.keys()) | set(browse_entries.keys())
    if not all_pids:
        return 0, 0

    cur = conn.cursor()

    # Load existing products for changelog comparison
    cur.execute("""SELECT product_id, title, publisher, developer, category,
        platforms, product_kind, has_trial_sku, has_achievements,
        is_bundle, is_ea_play, xcloud_streamable FROM marketplace_products""")
    existing_data = {}
    for row in cur.fetchall():
        existing_data[row[0]] = {
            "title": row[1] or "", "publisher": row[2] or "", "developer": row[3] or "",
            "category": row[4] or "", "platforms": sorted(row[5] or []),
            "product_kind": row[6] or "", "has_trial_sku": row[7],
            "has_achievements": row[8], "is_bundle": row[9],
            "is_ea_play": row[10], "xcloud_streamable": row[11]
        }
    existing = set(existing_data.keys())

    _TRACKED = ["title", "publisher", "developer", "category", "product_kind",
                 "has_trial_sku", "has_achievements", "is_bundle", "is_ea_play", "xcloud_streamable"]

    changelog_entries = []
    new_count = 0
    total = 0

    for pid in all_pids:
        cat = catalog.get(pid, {})
        browse = browse_entries.get(pid, {})
        meta = pid_meta.get(pid, {})

        # Merge data: catalog takes priority, browse fills gaps
        title = cat.get("title") or browse.get("title", "") or pid

        publisher = cat.get("publisher") or browse.get("publisher", "")
        developer = cat.get("developer") or browse.get("developer", "")
        category = cat.get("category") or browse.get("category", "")
        release_date = cat.get("releaseDate") or browse.get("releaseDate", "")
        platforms = [str(p) if not isinstance(p, str) else p for p in (cat.get("platforms") or browse.get("platforms", []))]
        product_kind = _norm_kind(cat.get("productKind") or browse.get("productKind", ""))
        is_bundle = cat.get("isBundle", False)
        is_ea_play = cat.get("isEAPlay", False)
        xcloud = cat.get("xCloudIsStreamable", False)
        raw_caps = cat.get("capabilities", [])
        has_ach = any(
            (isinstance(c, dict) and c.get("id") == "XblAchievements") or c == "XblAchievements"
            for c in raw_caps
        )
        # Normalize capabilities to flat strings for DB storage
        capabilities = []
        for c in raw_caps:
            if isinstance(c, dict):
                capabilities.append(c.get("id", str(c)))
            else:
                capabilities.append(str(c))
        alternate_ids = cat.get("alternateIds", [])
        image_tile = cat.get("image") or browse.get("image", "")
        image_box_art = cat.get("boxArt") or browse.get("boxArt", "")
        image_hero = cat.get("heroImage") or browse.get("heroImage", "")
        short_desc = cat.get("shortDescription") or browse.get("shortDescription", "")
        avg_rating = cat.get("averageRating", 0) or browse.get("averageRating", 0)
        rating_count = cat.get("ratingCount", 0) or browse.get("ratingCount", 0)

        # Extract xbox title ID from alternateIds
        xbox_title_id = ""
        for aid in alternate_ids:
            if aid.get("idType") == "XBOXTITLEID":
                xbox_title_id = aid.get("id", "")
                break

        # Determine sources
        sources = []
        if pid in pid_meta:
            sources.append("dynamic_channels")
        if pid in browse_entries:
            sources.append("browse_catalog")
        if pid in catalog:
            sources.append("catalog_v3")

        has_trial = (trial_map or {}).get(pid, False)

        # Parse release date
        rd = None
        if release_date and len(release_date) >= 10:
            try:
                rd = release_date[:10]
            except Exception:
                rd = None

        is_new = pid not in existing
        if is_new:
            new_count += 1
            changelog_entries.append((scan_id, 'product_added', pid, title, '', '', '', ''))
        else:
            # Compare tracked fields for changes
            old = existing_data[pid]
            new_vals = {
                "title": title or "", "publisher": publisher or "",
                "developer": developer or "", "category": category or "",
                "product_kind": product_kind or "",
                "has_trial_sku": has_trial, "has_achievements": has_ach,
                "is_bundle": is_bundle, "is_ea_play": is_ea_play,
                "xcloud_streamable": xcloud,
            }
            for field in _TRACKED:
                old_val = old.get(field)
                new_val = new_vals.get(field)
                # Skip if new value is empty/falsy (COALESCE keeps old)
                if isinstance(new_val, str) and not new_val:
                    continue
                if old_val != new_val:
                    changelog_entries.append((scan_id, 'field_changed', pid, title, field,
                                             str(old_val), str(new_val), ''))
            # Compare platforms as comma-joined sorted strings
            old_plats = ",".join(sorted(old.get("platforms", [])))
            new_plats = ",".join(sorted(platforms))
            if new_plats and old_plats != new_plats:
                changelog_entries.append((scan_id, 'field_changed', pid, title, 'platforms',
                                         old_plats, new_plats, ''))

        cur.execute("""
            INSERT INTO marketplace_products (
                product_id, title, publisher, developer, category, release_date,
                platforms, product_kind, xbox_title_id, is_bundle, is_ea_play,
                xcloud_streamable, capabilities, alternate_ids,
                image_tile, image_box_art, image_hero, short_description,
                average_rating, rating_count, sources, has_trial_sku, has_achievements, last_seen_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s, %s, NOW()
            )
            ON CONFLICT (product_id) DO UPDATE SET
                title = COALESCE(NULLIF(EXCLUDED.title, ''), marketplace_products.title),
                publisher = COALESCE(NULLIF(EXCLUDED.publisher, ''), marketplace_products.publisher),
                developer = COALESCE(NULLIF(EXCLUDED.developer, ''), marketplace_products.developer),
                category = COALESCE(NULLIF(EXCLUDED.category, ''), marketplace_products.category),
                release_date = COALESCE(EXCLUDED.release_date, marketplace_products.release_date),
                platforms = CASE WHEN array_length(EXCLUDED.platforms, 1) > 0 THEN EXCLUDED.platforms ELSE marketplace_products.platforms END,
                product_kind = COALESCE(NULLIF(EXCLUDED.product_kind, ''), marketplace_products.product_kind),
                xbox_title_id = COALESCE(NULLIF(EXCLUDED.xbox_title_id, ''), marketplace_products.xbox_title_id),
                is_bundle = EXCLUDED.is_bundle OR marketplace_products.is_bundle,
                is_ea_play = EXCLUDED.is_ea_play OR marketplace_products.is_ea_play,
                xcloud_streamable = EXCLUDED.xcloud_streamable OR marketplace_products.xcloud_streamable,
                capabilities = CASE WHEN array_length(EXCLUDED.capabilities, 1) > 0 THEN EXCLUDED.capabilities ELSE marketplace_products.capabilities END,
                alternate_ids = CASE WHEN EXCLUDED.alternate_ids != '[]'::jsonb THEN EXCLUDED.alternate_ids ELSE marketplace_products.alternate_ids END,
                image_tile = COALESCE(NULLIF(EXCLUDED.image_tile, ''), marketplace_products.image_tile),
                image_box_art = COALESCE(NULLIF(EXCLUDED.image_box_art, ''), marketplace_products.image_box_art),
                image_hero = COALESCE(NULLIF(EXCLUDED.image_hero, ''), marketplace_products.image_hero),
                short_description = COALESCE(NULLIF(EXCLUDED.short_description, ''), marketplace_products.short_description),
                average_rating = GREATEST(EXCLUDED.average_rating, marketplace_products.average_rating),
                rating_count = GREATEST(EXCLUDED.rating_count, marketplace_products.rating_count),
                sources = EXCLUDED.sources,
                has_trial_sku = EXCLUDED.has_trial_sku,
                has_achievements = EXCLUDED.has_achievements OR marketplace_products.has_achievements,
                last_seen_at = NOW()
        """, (
            pid, title, publisher, developer, category, rd,
            platforms, product_kind, xbox_title_id, is_bundle, is_ea_play,
            xcloud, capabilities, psycopg2.extras.Json(alternate_ids),
            image_tile, image_box_art, image_hero, short_desc,
            avg_rating, rating_count, sources, has_trial, has_ach,
        ))
        total += 1

        # Commit in batches to reduce memory pressure
        if total % 1000 == 0:
            conn.commit()

    conn.commit()
    cur.close()

    db_write_changelog(conn, changelog_entries)

    log.info("Products: %d written (%d new)", total, new_count)
    return total, new_count


def db_write_channels(conn, pid_meta):
    """Upsert channel membership."""
    if not pid_meta:
        return

    cur = conn.cursor()
    i = 0
    for pid, meta in pid_meta.items():
        for channel in meta.get("channels", set()):
            regions = sorted(meta.get("regions", set()))
            cur.execute("""
                INSERT INTO marketplace_channels (product_id, channel, regions, updated_at)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (product_id, channel) DO UPDATE SET
                    regions = EXCLUDED.regions,
                    updated_at = NOW()
            """, (pid, channel, regions))
            i += 1
            if i % 1000 == 0:
                conn.commit()
    conn.commit()
    cur.close()
    log.info("Channels: %d product-channel pairs written", sum(len(m.get("channels", set())) for m in pid_meta.values()))


def db_write_prices(conn, regional_prices, scan_id=None, title_map=None):
    """Upsert regional prices."""
    if not regional_prices:
        return 0

    cur = conn.cursor()

    # Load existing prices for changelog comparison
    changelog_entries = []
    if scan_id:
        cur2 = conn.cursor()
        cur2.execute("SELECT product_id, market, msrp, sale_price FROM marketplace_prices")
        existing_prices = {(r[0], r[1]): (r[2], r[3]) for r in cur2.fetchall()}
        cur2.close()
    else:
        existing_prices = {}

    count = 0
    for market, prices in regional_prices.items():
        for pid, p in prices.items():
            msrp = p["price"]
            sale_price = p.get("salePrice", 0)

            # Detect price changes
            if scan_id and (pid, market) in existing_prices:
                old_msrp, old_sale = existing_prices[(pid, market)]
                old_m = float(old_msrp) if old_msrp else 0
                old_s = float(old_sale) if old_sale else 0
                new_m = float(msrp) if msrp else 0
                new_s = float(sale_price) if sale_price else 0
                t = (title_map or {}).get(pid, "")
                if abs(old_m - new_m) > 0.001:
                    changelog_entries.append((scan_id, 'price_changed', pid, t, 'msrp', str(old_m), str(new_m), market))
                if abs(old_s - new_s) > 0.001:
                    changelog_entries.append((scan_id, 'price_changed', pid, t, 'sale_price', str(old_s), str(new_s), market))

            cur.execute("""
                INSERT INTO marketplace_prices (product_id, market, currency, msrp, sale_price, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (product_id, market) DO UPDATE SET
                    currency = EXCLUDED.currency,
                    msrp = EXCLUDED.msrp,
                    sale_price = EXCLUDED.sale_price,
                    updated_at = NOW()
            """, (pid, market, p["currency"], msrp, sale_price))
            count += 1
            if count % 2000 == 0:
                conn.commit()
    conn.commit()
    cur.close()

    db_write_changelog(conn, changelog_entries)

    log.info("Prices: %d market-product pairs written", count)
    return count


def db_write_rates(conn, rates):
    """Update exchange rates in shared_data table."""
    if not rates:
        return
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO shared_data (key, data, updated_at)
        VALUES ('rates', %s, NOW())
        ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
    """, (psycopg2.extras.Json({"rates": rates}),))
    conn.commit()
    cur.close()
    log.info("Exchange rates written to shared_data")


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(prices_only=False, force_browse=False, channel_filter=None, region_filter=None):
    """Execute a full marketplace scan."""
    t0 = time.time()
    scan_errors = []
    scan_hour = int(time.strftime("%H"))

    conn = get_db()

    # Mark stale scans
    db_mark_stale_scans(conn)

    scan_type = "prices_only" if prices_only else "full"
    if channel_filter:
        scan_type += f"_ch:{channel_filter}"
    if region_filter:
        scan_type += f"_rg:{region_filter}"
    scan_id = db_start_scan(conn, scan_type)
    log.info("Scan #%d started (type=%s)", scan_id, scan_type)

    # Phase 1: Auth
    try:
        auth_xl, auth_mp = get_tokens()
        log.info("Auth OK")
    except Exception as e:
        log.error("Auth failed: %s", e)
        db_update_scan(conn, scan_id, status="failed", completed_at="NOW()",
                       errors=[f"auth: {e}"], duration_seconds=time.time() - t0)
        conn.close()
        return

    def _with_retry(phase_name, fn, *args):
        """Run a phase, retry once with fresh tokens on 401."""
        nonlocal auth_xl, auth_mp
        try:
            return fn(*args)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log.warning("%s got 401, refreshing tokens...", phase_name)
                try:
                    auth_xl, auth_mp = refresh_tokens()
                    # Re-call with refreshed tokens — caller must re-bind args
                    return None  # Signal caller to retry
                except Exception as re:
                    log.error("Token refresh failed: %s", re)
                    scan_errors.append(f"{phase_name}: token refresh failed: {re}")
                    return None
            log.error("%s failed: HTTP %d", phase_name, e.code)
            scan_errors.append(f"{phase_name}: HTTP {e.code}")
            return None
        except Exception as e:
            log.error("%s failed: %s", phase_name, e)
            scan_errors.append(f"{phase_name}: {e}")
            return None

    channels_scanned = 0
    browse_count = 0
    catalog_count = 0
    prices_count = 0
    products_total = 0
    products_new = 0

    if prices_only:
        # Prices-only: just refresh prices for existing products
        try:
            cur = conn.cursor()
            cur.execute("SELECT product_id FROM marketplace_products")
            all_pids = [row[0] for row in cur.fetchall()]
            cur.close()
            log.info("Prices-only mode: %d existing products", len(all_pids))

            if all_pids:
                regional = phase_prices(all_pids, auth_xl)
                if regional is None:
                    # Retry with fresh tokens
                    auth_xl, auth_mp = refresh_tokens()
                    regional = phase_prices(all_pids, auth_xl)
                if regional:
                    prices_count = db_write_prices(conn, regional, scan_id=scan_id)

            # Also refresh exchange rates
            rates = fetch_exchange_rates()
            db_write_rates(conn, rates)

        except Exception as e:
            log.error("Prices-only scan failed: %s", e)
            scan_errors.append(f"prices_only: {e}")
    else:
        # Full scan

        # Phase 2: Dynamic channels
        pid_meta = _with_retry("channels", phase_channels, auth_mp, channel_filter, region_filter)
        if pid_meta is None:
            # Retry after token refresh
            try:
                pid_meta = phase_channels(auth_mp, channel_filter=channel_filter, region_filter=region_filter)
            except Exception as e:
                log.error("Channels retry failed: %s", e)
                pid_meta = {}
                scan_errors.append(f"channels retry: {e}")

        channels_scanned = len(ALL_MARKETS) * len(MARKETPLACE_CHANNELS)

        # Phase 3: Browse catalog (every 6th hour)
        browse_entries = {}
        try:
            browse_entries = phase_browse(auth_mp, scan_hour, force=force_browse)
            browse_count = len(browse_entries)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log.warning("Browse got 401, refreshing tokens...")
                try:
                    auth_xl, auth_mp = refresh_tokens()
                    browse_entries = phase_browse(auth_mp, scan_hour, force=force_browse)
                    browse_count = len(browse_entries)
                except Exception as re:
                    log.error("Browse retry failed: %s", re)
                    scan_errors.append(f"browse: {re}")
        except Exception as e:
            log.error("Browse failed: %s", e)
            scan_errors.append(f"browse: {e}")

        # Merge all product IDs
        all_pids = set(pid_meta.keys()) | set(browse_entries.keys())
        log.info("Total unique products: %d", len(all_pids))

        # Phase 4: Catalog v3 enrichment
        catalog = {}
        if all_pids:
            try:
                catalog = phase_catalog(all_pids, auth_xl)
                if catalog is None:
                    auth_xl, auth_mp = refresh_tokens()
                    catalog = phase_catalog(all_pids, auth_xl)
                if catalog is None:
                    catalog = {}
                catalog_count = len(catalog)
            except Exception as e:
                log.error("Catalog failed: %s", e)
                scan_errors.append(f"catalog: {e}")

        # Phase 5: Regional prices
        regional = {}
        if all_pids:
            try:
                regional = phase_prices(list(all_pids), auth_xl)
                if regional:
                    prices_count = sum(len(v) for v in regional.values())
            except Exception as e:
                log.error("Prices failed: %s", e)
                scan_errors.append(f"prices: {e}")

        # Phase 5b: Trial detection (Display Catalog v7, no auth needed)
        trial_map = {}
        if all_pids:
            try:
                trial_map = phase_trials(all_pids)
            except Exception as e:
                log.error("Trial detection failed: %s", e)
                scan_errors.append(f"trials: {e}")

        # Phase 6: Exchange rates
        rates = fetch_exchange_rates()

        # Phase 7: DB writes
        try:
            products_total, products_new = db_write_products(conn, catalog, pid_meta, browse_entries, scan_id, trial_map)
        except Exception as e:
            log.error("DB write products failed: %s", e)
            scan_errors.append(f"db_products: {e}")
            conn.rollback()

        try:
            # Only write channels for products that exist in DB
            # Filter pid_meta to only include PIDs we successfully wrote
            db_write_channels(conn, pid_meta)
        except Exception as e:
            log.error("DB write channels failed: %s", e)
            scan_errors.append(f"db_channels: {e}")
            conn.rollback()

        try:
            if regional:
                title_map = {pid: info.get("title", "") for pid, info in catalog.items()} if catalog else {}
                db_write_prices(conn, regional, scan_id=scan_id, title_map=title_map)
        except Exception as e:
            log.error("DB write prices failed: %s", e)
            scan_errors.append(f"db_prices: {e}")
            conn.rollback()

        try:
            db_write_rates(conn, rates)
        except Exception as e:
            log.error("DB write rates failed: %s", e)
            scan_errors.append(f"db_rates: {e}")
            conn.rollback()

    # Finalize scan record
    duration = time.time() - t0
    status = "completed" if not scan_errors else "partial"
    db_update_scan(conn, scan_id,
                   status=status,
                   completed_at="NOW()",
                   channels_scanned=channels_scanned,
                   browse_products=browse_count,
                   catalog_enriched=catalog_count,
                   prices_fetched=prices_count,
                   products_total=products_total,
                   products_new=products_new,
                   errors=scan_errors,
                   duration_seconds=round(duration, 1))

    conn.close()
    log.info("Scan #%d %s in %.1fs — %d products (%d new), %d prices",
             scan_id, status, duration, products_total, products_new, prices_count)


def run_scan_nz_new():
    """Quick scan: NZ new releases channel + NZ prices only."""
    conn = get_db()
    cur = conn.cursor()
    # Mark stale scans
    cur.execute("""UPDATE marketplace_scans SET status='failed',
        completed_at=NOW(), errors='["Timed out (stale)"]'::jsonb
        WHERE status='running' AND started_at < NOW() - INTERVAL '30 minutes'""")
    conn.commit()
    # Create scan record
    cur.execute("""INSERT INTO marketplace_scans (scan_type, status, started_at)
        VALUES ('nz_new_releases', 'running', NOW()) RETURNING id""")
    scan_id = cur.fetchone()[0]
    conn.commit()
    t0 = time.time()
    errors = []
    try:
        auth_xl, auth_mp = get_tokens()
        # Fetch NZ new games channel
        pids = fetch_dynamic_channel("MobileNewGames", auth_mp, market="NZ", lang="en-NZ")
        if not pids:
            pids = fetch_dynamic_channel("newgames", auth_mp, market="NZ", lang="en-NZ")
        log.info("NZ new releases: %d products", len(pids))
        if not pids:
            errors.append("No products found in NZ new releases channel")
        all_pids = set(pids)
        # Catalog enrichment
        catalog = phase_catalog(all_pids, auth_xl) if all_pids else {}
        # NZ prices only
        nz_info = PRICE_REGIONS["NZ"]
        _, nz_prices = _fetch_region_prices("NZ", nz_info, list(all_pids), auth_xl)
        regional_prices = {"NZ": nz_prices} if nz_prices else {}
        # Build pid_meta for db_write_products
        pid_meta = {}
        for pid in pids:
            pid_meta.setdefault(pid, {"channels": set(), "regions": set()})
            pid_meta[pid]["channels"].add("MobileNewGames")
            pid_meta[pid]["regions"].add("NZ")
        # DB writes
        total, new_count = db_write_products(conn, catalog, pid_meta, {}, scan_id)
        db_write_channels(conn, pid_meta)
        title_map = {pid: info.get("title", "") for pid, info in catalog.items()} if catalog else {}
        price_count = db_write_prices(conn, regional_prices, scan_id=scan_id, title_map=title_map)
        # Finalize
        dur = time.time() - t0
        cur.execute("""UPDATE marketplace_scans SET status='completed', completed_at=NOW(),
            duration_seconds=%s, products_total=%s, products_new=%s, prices_fetched=%s,
            channels_scanned=1, errors=%s WHERE id=%s""",
            (dur, total, new_count, price_count, json.dumps(errors) if errors else None, scan_id))
        conn.commit()
        log.info("NZ new releases scan complete: %d products (%d new), %d prices, %.1fs",
                 total, new_count, price_count, dur)
    except Exception as e:
        log.exception("NZ scan failed: %s", e)
        errors.append(str(e))
        cur.execute("""UPDATE marketplace_scans SET status='failed', completed_at=NOW(),
            duration_seconds=%s, errors=%s WHERE id=%s""",
            (time.time() - t0, json.dumps(errors), scan_id))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Setup command
# ---------------------------------------------------------------------------

def cmd_setup():
    """Interactive one-time setup: device code auth."""
    os.makedirs(ACCOUNT_DIR, exist_ok=True)

    existing = load_state()
    if existing and existing.get("refresh_token"):
        print("Existing auth state found.")
        answer = input("Re-authenticate? [y/N]: ").strip().lower()
        if answer != "y":
            print("Setup cancelled.")
            return

    msa_token, refresh_token = device_code_auth()
    signer = RequestSigner()
    device_id = str(uuid.uuid4())

    log.info("Registering device...")
    device_token, device_id = get_device_token(signer, device_id)

    log.info("SISU authorization...")
    sisu_result = sisu_authorize(signer, msa_token, device_token)
    gamertag = sisu_result["gamertag"]
    log.info("Authenticated as %s", gamertag)

    # Get XSTS tokens to verify everything works
    user_token = sisu_result["user_token"]
    title_token = sisu_result["title_token"]
    xl_token, xl_uhs = get_xsts_token(signer, user_token, device_token, title_token, "http://xboxlive.com")
    mp_token, mp_uhs = get_xsts_token(signer, user_token, device_token, title_token, "http://mp.microsoft.com/")

    state = {
        "refresh_token": refresh_token,
        "ec_key": signer.export_state(),
        "device_id": device_id,
    }
    save_state(state)

    # Cache tokens
    with open(os.path.join(ACCOUNT_DIR, "auth_token_xl.txt"), "w") as f:
        f.write(build_xbl3_token(xl_token, xl_uhs))
    with open(os.path.join(ACCOUNT_DIR, "auth_token_mp.txt"), "w") as f:
        f.write(build_xbl3_token(mp_token, mp_uhs))

    print()
    print(f"Setup complete! Authenticated as {gamertag}")
    print(f"State saved to {ACCOUNT_DIR}")
    print(f"Run 'marketplace_scanner.py scan' to start scanning.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "setup":
        cmd_setup()
    elif cmd == "scan":
        prices_only = "--prices-only" in sys.argv
        force_browse = "--force-browse" in sys.argv
        channel_filter = None
        region_filter = None
        for arg in sys.argv[2:]:
            if arg.startswith("--channel="):
                channel_filter = arg.split("=", 1)[1]
            elif arg.startswith("--region="):
                region_filter = arg.split("=", 1)[1]
        run_scan(prices_only=prices_only, force_browse=force_browse,
                 channel_filter=channel_filter, region_filter=region_filter)
    elif cmd == "scan-nz":
        run_scan_nz_new()
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: marketplace_scanner.py [setup|scan|scan-nz]")
        sys.exit(1)


if __name__ == "__main__":
    main()
