#!/usr/bin/env python3
"""
XCT — Xbox Collection Tracker by Freshdex
==========================================
Authenticates with Xbox Live, fetches your Xbox/Microsoft Store entitlements,
resolves catalog details (titles, prices, images, platforms) for both GBP and
USD markets, pulls the Game Pass catalog, and builds a self-contained HTML
explorer page.

Supports multiple accounts stored under accounts/{gamertag}/.

Requirements:
  - Python 3.7+
  - pip install ecdsa  (for device-bound auth / Collections API)

Usage:
  python XCT.py                    # Interactive menu
  python XCT.py <gamertag>         # Refresh + process specific account
  python XCT.py --all              # Refresh all + process all
  python XCT.py add               # Add new account (device code flow)
  python XCT.py extract [file]    # Extract token from HAR file
"""

import base64
import concurrent.futures
import glob
import hashlib
import io
import json
import os
import re
import ssl
import struct
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

# EC P-256 device-bound signing (pip install ecdsa)
try:
    import ecdsa
    HAS_ECDSA = True
except ImportError:
    HAS_ECDSA = False

# ---------------------------------------------------------------------------
# Fix stdout encoding on Windows so Unicode doesn't explode
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

# ---------------------------------------------------------------------------
# Debug logging — writes all output + extra diagnostics to debug.log
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.1"
DEBUG_LOG_FILE = os.path.join(SCRIPT_DIR, "debug.log")

import datetime as _dt

def _init_debug_log():
    """Initialize the debug log file (truncate) and install stdout tee."""
    with open(DEBUG_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== XCT Debug Log — {_dt.datetime.now().isoformat()} ===\n")
        f.write(f"Python: {sys.version}\n")
        f.write(f"Platform: {sys.platform}\n")
        f.write(f"CWD: {os.getcwd()}\n")
        f.write(f"Script dir: {SCRIPT_DIR}\n")
        f.write(f"Args: {sys.argv}\n\n")

    class _TeeWriter:
        """Duplicates writes to both the original stdout and the log file."""
        def __init__(self, original):
            self._original = original
            self._log = open(DEBUG_LOG_FILE, "a", encoding="utf-8", errors="replace")
        def write(self, text):
            self._original.write(text)
            try:
                self._log.write(text)
                self._log.flush()
            except Exception:
                pass
        def flush(self):
            self._original.flush()
            try:
                self._log.flush()
            except Exception:
                pass
        @property
        def buffer(self):
            return self._original.buffer
        @property
        def encoding(self):
            return self._original.encoding

    sys.stdout = _TeeWriter(sys.stdout)

_init_debug_log()

def debug(msg):
    """Write a debug-only message to the log file (not printed to console)."""
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            ts = _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            f.write(f"[DEBUG {ts}] {msg}\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ACCOUNTS_DIR = os.path.join(SCRIPT_DIR, "accounts")
ACCOUNTS_FILE = os.path.join(SCRIPT_DIR, "accounts.json")

# MSA / Xbox Live auth constants
CLIENT_ID = "000000004c12ae6f"
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"

# Cache file names (cleared after token refresh)
CACHE_FILES = [
    "entitlements.json",
    "entitlements_collection.json",
    "entitlements_titlehub.json",
    "catalog_gb.json",
    "catalog_us.json",
    "catalog_v3_gb.json",
    "catalog_v3_us.json",
    "gamepass.json",
    "gamepass_details.json",
    "_gp_catalog_gb_tmp.json",
    "_gp_catalog_us_tmp.json",
    "library.json",
    "library_collection.json",
    "library_titlehub.json",
    "contentaccess.json",
    "prices_ar.json",
    "prices_br.json",
    "prices_tr.json",
    "prices_is.json",
    "prices_ng.json",
    "prices_tw.json",
    "prices_nz.json",
    "prices_co.json",
    "prices_hk.json",
    "prices_us.json",
]

# Per-account path globals (set by set_account_paths)
AUTH_TOKEN_FILE      = ""
ENTITLEMENTS_FILE    = ""
ENTITLEMENTS_COLLECTION_FILE = ""
ENTITLEMENTS_TITLEHUB_FILE   = ""
CATALOG_GB_FILE      = ""
CATALOG_US_FILE      = ""
CATALOG_V3_GB_FILE   = ""
CATALOG_V3_US_FILE   = ""
GAMEPASS_FILE        = ""
GAMEPASS_DETAIL_FILE = ""
OUTPUT_HTML_FILE     = ""
GP_CATALOG_GB_TMP    = ""
GP_CATALOG_US_TMP    = ""
LIBRARY_FILE         = ""
LIBRARY_COLLECTION_FILE = ""
LIBRARY_TITLEHUB_FILE   = ""
PLAY_HISTORY_FILE       = ""
CONTENTACCESS_FILE      = ""
MARKETPLACE_FILE        = ""

# How old (in seconds) a cached file can be before we re-fetch
CACHE_MAX_AGE = 3600  # 1 hour

# Default item flags — loaded from community-editable tags.json
TAGS_FILE = os.path.join(SCRIPT_DIR, "tags.json")
EXCHANGE_RATES_FILE = os.path.join(SCRIPT_DIR, "exchange_rates.json")

def load_default_flags():
    if os.path.isfile(TAGS_FILE):
        with open(TAGS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return {pid: entry["tag"] for pid, entry in raw.items()}
    return {}

DEFAULT_FLAGS = load_default_flags()

# On Windows, pip_system_certs patches ssl to use the OS certificate store
# instead of Python's bundled (often outdated) certs. Must import before
# creating any SSL contexts.  Install: pip install pip_system_certs
try:
    import pip_system_certs  # noqa: F401
except ImportError:
    pass

# SSL context for all HTTPS calls
SSL_CTX = ssl.create_default_context()

# Platform name mapping from SKU PlatformDependencies
PLATFORM_MAP = {
    "Windows.Xbox":             "Xbox One",
    "Windows.Desktop":          "PC",
    "Windows.Universal":        "PC/Xbox",
    "Windows.Mobile":           "Windows Phone",
    "Windows.WindowsPhone8x":   "Windows Phone",
    "Windows.WindowsPhone7x":   "Windows Phone",
    "Windows.Team":             "Surface Hub",
    "Windows.Holographic":      "HoloLens",
}

# Game Pass collection IDs
GP_COLLECTIONS = {
    "fdd9e2a7-0fee-49f6-ad69-4354098401ff": "All Game Pass Games",
    "f6f1f99f-9b49-4ccd-b3bf-4d9767a77f5e": "Recently Added",
    "29a81209-df6f-41fd-a528-2ae6b91f719c": "Most Popular",
}

# Marketplace DynamicChannel names → display labels
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

# Regional pricing markets (for marketplace price comparison)
PRICE_REGIONS = {
    "AR": {"locale": "es-AR", "name": "Argentina", "currency": "ARS", "symbol": "AR$"},
    "BR": {"locale": "pt-BR", "name": "Brazil", "currency": "BRL", "symbol": "R$"},
    "TR": {"locale": "tr-TR", "name": "Turkey", "currency": "TRY", "symbol": "\u20ba"},
    "IS": {"locale": "is-IS", "name": "Iceland", "currency": "ISK", "symbol": "kr"},
    "NG": {"locale": "en-NG", "name": "Nigeria", "currency": "NGN", "symbol": "\u20a6"},
    "TW": {"locale": "zh-TW", "name": "Taiwan", "currency": "TWD", "symbol": "NT$"},
    "NZ": {"locale": "en-NZ", "name": "New Zealand", "currency": "NZD", "symbol": "NZ$"},
    "CO": {"locale": "es-CO", "name": "Colombia", "currency": "COP", "symbol": "CO$"},
    "HK": {"locale": "zh-HK", "name": "Hong Kong", "currency": "HKD", "symbol": "HK$"},
    "US": {"locale": "en-US", "name": "USA", "currency": "USD", "symbol": "$"},
}

# Gift card discount factor (0.81c to $1)
GC_FACTOR = 0.81


# ===========================================================================
# EC P-256 Request Signing (Xbox Device Auth)
# ===========================================================================

# Windows FILETIME epoch offset (100-nanosecond intervals from 1601-01-01 to 1970-01-01)
_FILETIME_EPOCH_OFFSET = 116444736000000000

def _base64url_encode(data):
    """Base64url encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _base64url_decode(s):
    """Base64url decode string to bytes."""
    s = s + "=" * (4 - len(s) % 4)  # add padding
    return base64.urlsafe_b64decode(s)


class RequestSigner:
    """Signs Xbox Live requests with EC P-256 (ECDSA) proof-of-possession.

    The Xbox device auth flow requires all requests to be signed with a
    device-specific EC P-256 key pair. The signature proves the caller
    possesses the private key that matches the ProofKey sent during
    device registration.

    Signature format (76 bytes, base64-encoded):
      - 4 bytes: signature policy version (big-endian int, currently 1)
      - 8 bytes: Windows FILETIME timestamp (big-endian uint64)
      - 64 bytes: ECDSA signature (r || s, each 32 bytes, big-endian)

    Signed data (null-byte separated):
      version + \\x00 + timestamp + \\x00 + METHOD + \\x00 + path_and_query + \\x00
      + authorization + \\x00 + body[:8192] + \\x00
    """

    SIGNATURE_VERSION = 1
    MAX_BODY_BYTES = 8192

    def __init__(self, ec_key=None):
        """Initialize with an existing key or generate a new one.

        Args:
            ec_key: An ecdsa.SigningKey (NIST256p) or None to generate.
        """
        if not HAS_ECDSA:
            raise RuntimeError(
                "ecdsa package required for device-bound auth. "
                "Install with: pip install ecdsa"
            )
        if ec_key is None:
            self.signing_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
        else:
            self.signing_key = ec_key
        self.verifying_key = self.signing_key.get_verifying_key()

    @classmethod
    def from_pem(cls, pem_data):
        """Load a signer from PEM-encoded private key bytes."""
        sk = ecdsa.SigningKey.from_pem(pem_data)
        return cls(ec_key=sk)

    @classmethod
    def from_state(cls, state_dict):
        """Load a signer from saved state (base64url-encoded d value)."""
        if not state_dict or "d" not in state_dict:
            return None
        if not HAS_ECDSA:
            return None
        try:
            d_bytes = _base64url_decode(state_dict["d"])
            sk = ecdsa.SigningKey.from_string(d_bytes, curve=ecdsa.NIST256p)
            return cls(ec_key=sk)
        except Exception as e:
            debug(f"RequestSigner.from_state failed: {e}")
            return None

    def export_state(self):
        """Export the private key as a dict for JSON serialization."""
        d_bytes = self.signing_key.to_string()  # 32 bytes (private scalar)
        x_bytes, y_bytes = self._get_xy_bytes()
        return {
            "kty": "EC",
            "crv": "P-256",
            "d": _base64url_encode(d_bytes),
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }

    def get_proof_key(self):
        """Get the ProofKey JWK dict for device/SISU registration.

        Returns a JWK-format dict with the public key coordinates.
        Matches the format expected by Xbox Live auth endpoints.
        """
        x_bytes, y_bytes = self._get_xy_bytes()
        return {
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(x_bytes),
            "y": _base64url_encode(y_bytes),
        }

    def sign_request(self, method, url, authorization="", body=b"", timestamp=None):
        """Sign an HTTP request per Xbox signature spec.

        Args:
            method: HTTP method (e.g. "POST")
            url: Full URL string
            authorization: Authorization header value (empty string if none)
            body: Request body bytes (max 8192 bytes used for signing)
            timestamp: Unix timestamp (defaults to time.time())

        Returns:
            (signature_header, filetime_ts) where signature_header is the
            base64-encoded Signature header value.
        """
        if timestamp is None:
            timestamp = time.time()

        # Convert to Windows FILETIME (100ns intervals since 1601-01-01)
        filetime = _FILETIME_EPOCH_OFFSET + int(timestamp * 10_000_000)

        # Extract path + query from URL
        parsed = urllib.parse.urlparse(url)
        path_and_query = parsed.path
        if parsed.query:
            path_and_query += "?" + parsed.query

        # Build the signing payload (null-byte separated)
        version_bytes = struct.pack(">I", self.SIGNATURE_VERSION)
        filetime_bytes = struct.pack(">Q", filetime)

        # Construct data to sign
        signing_data = b""
        signing_data += version_bytes + b"\x00"
        signing_data += filetime_bytes + b"\x00"
        signing_data += method.upper().encode("ascii") + b"\x00"
        signing_data += path_and_query.encode("ascii") + b"\x00"
        signing_data += authorization.encode("ascii") + b"\x00"
        signing_data += body[:self.MAX_BODY_BYTES] + b"\x00"

        # Hash and sign (deterministic ECDSA per RFC 6979)
        digest = hashlib.sha256(signing_data).digest()
        signature = self.signing_key.sign_digest_deterministic(
            digest, sigencode=ecdsa.util.sigencode_string
        )
        # signature is 64 bytes (r || s)

        # Build the Signature header: version(4) + filetime(8) + sig(64) = 76 bytes
        sig_header = version_bytes + filetime_bytes + signature
        return base64.b64encode(sig_header).decode("ascii")

    def _get_xy_bytes(self):
        """Get the (x, y) public key coordinates as 32-byte big-endian each."""
        # verifying_key.to_string() returns x || y (64 bytes)
        pub_bytes = self.verifying_key.to_string()
        return pub_bytes[:32], pub_bytes[32:]


# ===========================================================================
# Account Registry
# ===========================================================================

def load_accounts():
    """Load the accounts registry. Returns dict of gamertag -> metadata."""
    if not os.path.isfile(ACCOUNTS_FILE):
        return {}
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_accounts(accounts):
    """Save the accounts registry."""
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2, ensure_ascii=False)


def register_account(gamertag, uhs):
    """Add or update an account in the registry."""
    accounts = load_accounts()
    accounts[gamertag] = {
        "gamertag": gamertag,
        "uhs": uhs,
    }
    save_accounts(accounts)


def account_dir(gamertag):
    """Return the directory path for a given account."""
    return os.path.join(ACCOUNTS_DIR, gamertag)


def account_path(gamertag, filename):
    """Return the full path for a file within an account's directory."""
    return os.path.join(ACCOUNTS_DIR, gamertag, filename)


def ensure_account_dir(gamertag):
    """Create the account directory if it doesn't exist."""
    d = account_dir(gamertag)
    os.makedirs(d, exist_ok=True)
    return d


def collect_account_metadata():
    """Collect metadata for all accounts from their stored files.

    Returns a list of dicts with: gamertag, uhs, xuid, deviceId, authMode,
    tokenAge (seconds since auth_token.txt was last modified).
    """
    accounts = load_accounts()
    result = []
    now = time.time()
    for gt, info in accounts.items():
        meta = {
            "gamertag": gt,
            "uhs": info.get("uhs", ""),
            "xuid": "",
            "deviceId": "",
            "authMode": "simple",
            "tokenAge": -1,
        }
        acct = account_dir(gt)
        # XUID
        xuid_file = os.path.join(acct, "xuid.txt")
        if os.path.isfile(xuid_file):
            try:
                with open(xuid_file, "r") as f:
                    meta["xuid"] = f.read().strip()
            except Exception:
                pass
        # Auth state (device_id, auth mode)
        state_file = os.path.join(acct, "xbox_auth_state.json")
        if os.path.isfile(state_file):
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)
                meta["deviceId"] = state.get("device_id", "")
                if state.get("ec_key"):
                    meta["authMode"] = "device-bound"
            except Exception:
                pass
        # Token age
        token_file = os.path.join(acct, "auth_token.txt")
        if os.path.isfile(token_file):
            try:
                meta["tokenAge"] = int(now - os.path.getmtime(token_file))
            except Exception:
                pass
        result.append(meta)
    return result


def set_account_paths(gamertag):
    """Set all global file path constants for the given account."""
    global AUTH_TOKEN_FILE, ENTITLEMENTS_FILE, CATALOG_GB_FILE, CATALOG_US_FILE
    global CATALOG_V3_GB_FILE, CATALOG_V3_US_FILE
    global GAMEPASS_FILE, GAMEPASS_DETAIL_FILE, OUTPUT_HTML_FILE
    global GP_CATALOG_GB_TMP, GP_CATALOG_US_TMP
    global ENTITLEMENTS_COLLECTION_FILE, ENTITLEMENTS_TITLEHUB_FILE
    global LIBRARY_FILE, LIBRARY_COLLECTION_FILE, LIBRARY_TITLEHUB_FILE, PLAY_HISTORY_FILE
    global CONTENTACCESS_FILE, MARKETPLACE_FILE

    acct_dir = os.path.join(ACCOUNTS_DIR, gamertag)
    AUTH_TOKEN_FILE      = os.path.join(acct_dir, "auth_token.txt")
    ENTITLEMENTS_FILE    = os.path.join(acct_dir, "entitlements.json")
    ENTITLEMENTS_COLLECTION_FILE = os.path.join(acct_dir, "entitlements_collection.json")
    ENTITLEMENTS_TITLEHUB_FILE   = os.path.join(acct_dir, "entitlements_titlehub.json")
    CATALOG_GB_FILE      = os.path.join(acct_dir, "catalog_gb.json")
    CATALOG_US_FILE      = os.path.join(acct_dir, "catalog_us.json")
    CATALOG_V3_GB_FILE   = os.path.join(acct_dir, "catalog_v3_gb.json")
    CATALOG_V3_US_FILE   = os.path.join(acct_dir, "catalog_v3_us.json")
    GAMEPASS_FILE        = os.path.join(acct_dir, "gamepass.json")
    GAMEPASS_DETAIL_FILE = os.path.join(acct_dir, "gamepass_details.json")
    OUTPUT_HTML_FILE     = os.path.join(acct_dir, "XCT.html")
    GP_CATALOG_GB_TMP    = os.path.join(acct_dir, "_gp_catalog_gb_tmp.json")
    GP_CATALOG_US_TMP    = os.path.join(acct_dir, "_gp_catalog_us_tmp.json")
    LIBRARY_FILE         = os.path.join(acct_dir, "library.json")
    LIBRARY_COLLECTION_FILE = os.path.join(acct_dir, "library_collection.json")
    LIBRARY_TITLEHUB_FILE   = os.path.join(acct_dir, "library_titlehub.json")
    PLAY_HISTORY_FILE       = os.path.join(acct_dir, "play_history.json")
    CONTENTACCESS_FILE      = os.path.join(acct_dir, "contentaccess.json")
    MARKETPLACE_FILE        = os.path.join(acct_dir, "marketplace.json")


def token_age_str(gamertag):
    """Return a human-readable age string for an account's token."""
    token_file = account_path(gamertag, "auth_token.txt")
    if not os.path.isfile(token_file):
        return "no token"
    age_s = time.time() - os.path.getmtime(token_file)
    age_h = age_s / 3600
    if age_h < 1:
        return f"{int(age_s / 60)}m old"
    return f"{age_h:.1f}h old"




def msa_request(url, params):
    """Make a form-encoded POST to login.live.com. Returns parsed JSON."""
    safe_params = {k: (v[:20] + "..." if k == "refresh_token" and len(str(v)) > 20 else v)
                   for k, v in params.items()}
    debug(f"msa_request: POST {url} params={safe_params}")
    body = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            debug(f"msa_request: OK, keys={list(data.keys())}")
            return data
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        debug(f"msa_request: HTTP {e.code} body={error_body[:1000]}")
        print(f"[!] HTTP {e.code} from {url}")
        print(f"    {error_body[:500]}")
        raise


# ===========================================================================
# Auth Flow Steps
# ===========================================================================

def device_code_auth():
    """
    Step A: Device Code Flow — get MSA access_token + refresh_token.
    User visits a URL and enters a code.
    """
    print("[*] Starting device code flow...")

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
    print("[*] Waiting for you to sign in...")

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
                data=poll_params, method="POST",
            )
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=30) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))
            print("[+] Sign-in complete!")
            return token_resp["access_token"], token_resp.get("refresh_token")
        except urllib.error.HTTPError as e:
            # authorization_pending is expected while waiting — silently retry
            error_body = e.read().decode("utf-8", errors="replace")
            if "authorization_pending" not in error_body and "slow_down" not in error_body:
                print(f"[!] Unexpected polling error (HTTP {e.code}): {error_body[:200]}")
        except Exception:
            pass


def refresh_msa_token(refresh_token):
    """Refresh the MSA access token using a stored refresh token."""
    print("[*] Refreshing MSA token...")
    resp = msa_request("https://login.live.com/oauth20_token.srf", {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })
    print("[+] Token refreshed!")
    return resp["access_token"], resp.get("refresh_token", refresh_token)




def build_xbl3_token(xsts_token, user_hash):
    """Step E: Build the XBL3.0 token string."""
    return f"XBL3.0 x={user_hash};{xsts_token}"


def get_xbl_tokens_simple(refresh_token):
    """Get XBL3.0 tokens using simple non-device-bound auth.

    This flow does NOT require ecdsa or device token registration.
    Returns (xbl3_xboxlive, xbl3_mp, xuid, gamertag, new_refresh_token)
    where xbl3_xboxlive is for TitleHub and xbl3_mp is for Collections API.
    """
    # Refresh MSA token
    print("[*] Refreshing MSA token...")
    msa_resp = msa_request("https://login.live.com/oauth20_token.srf", {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })
    msa_token = msa_resp["access_token"]
    new_refresh = msa_resp.get("refresh_token", refresh_token)
    print("[+] MSA token refreshed")

    return get_xbl_tokens_simple_from_msa(msa_token, new_refresh)


def fetch_titlehub_library(xbl3_token, xuid):
    """Fetch user's title history from TitleHub API.

    Returns a list of entitlement-like dicts with productId and metadata,
    compatible with the existing merge/catalog pipeline.
    """
    url = (
        f"https://titlehub.xboxlive.com/users/xuid({xuid})/titles/titlehistory"
        f"/decoration/GamePass,Achievement,Image,ProductId,TitleHistory"
    )
    debug(f"fetch_titlehub_library: xuid={xuid} token={len(xbl3_token)}ch")
    debug(f"  url={url}")
    headers = {
        "Authorization": xbl3_token,
        "Accept-Language": "en-GB",
        "x-xbl-contract-version": "2",
        "Accept": "application/json",
    }

    # Retry with increasing timeouts (large libraries can take a while)
    data = None
    for attempt, timeout in enumerate([120, 180, 240], 1):
        debug(f"  attempt {attempt} timeout={timeout}s")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
            debug(f"  response: {len(raw)} bytes, keys={list(data.keys())}")
            debug(f"  titles count: {len(data.get('titles', []))}")
            break
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")[:1000]
            debug(f"  TitleHub HTTP {e.code}: {err}")
            raise
        except (TimeoutError, OSError) as e:
            debug(f"  TitleHub timeout/error attempt {attempt}: {e}")
            if attempt == 3:
                raise
            print(f"  TitleHub timeout (attempt {attempt}/3), retrying...")
            time.sleep(2)

    titles = data.get("titles", [])
    items = []
    for t in titles:
        product_id = t.get("productId", "")
        if not product_id:
            continue
        items.append({
            "productId":   product_id,
            "productKind": "Game",
            "status":      "Active",
            "acquiredDate": "",
            "startDate":   "",
            "endDate":     "",
            "isTrial":     False,
            "skuType":     "",
            "skuId":       "",
            "purchasedCountry": "",
            "quantity":    1,
            # TitleHub-specific extras (used by merge_library if available)
            "_titlehub": {
                "name":        t.get("name", ""),
                "titleId":     t.get("titleId", ""),
                "devices":     t.get("devices", []),
                "displayImage": t.get("displayImage", ""),
                "gamePass":    t.get("gamePass", {}),
                "achievement": t.get("achievement", {}),
                "type":        t.get("type", ""),
                "lastTimePlayed": t.get("titleHistory", {}).get("lastTimePlayed", ""),
            },
        })

    return items


# ===========================================================================
# Cache Management
# ===========================================================================

def clear_api_cache(gamertag=None):
    """Delete cached API responses so fresh data is fetched."""
    cleared = []
    for name in CACHE_FILES:
        if gamertag:
            path = account_path(gamertag, name)
        else:
            path = os.path.join(SCRIPT_DIR, name)
        if os.path.isfile(path):
            os.remove(path)
            cleared.append(name)
    if cleared:
        print(f"[*] Cleared {len(cleared)} cached file(s): {', '.join(cleared)}")


# ===========================================================================
# Auth Flows
# ===========================================================================

def sisu_auth_for_account(existing_gamertag=None):
    """Full authentication flow for adding or refreshing an account.

    When ecdsa is available, uses device-bound EC P-256 auth which produces
    XSTS tokens with device claims — required for Collections API.
    Falls back to simple (non-device-bound) auth if ecdsa is not installed.

    For new accounts: device code flow -> save state.
    For existing accounts: refresh MSA token -> save tokens.
    Returns the gamertag.
    """
    debug(f"sisu_auth_for_account: existing_gamertag={existing_gamertag}")

    # Load existing state for refresh, or start fresh for new accounts
    refresh_token = None
    signer = None
    device_id = None
    if existing_gamertag:
        state_file = account_path(existing_gamertag, "xbox_auth_state.json")
        debug(f"  state_file={state_file} exists={os.path.isfile(state_file)}")
        if os.path.isfile(state_file):
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)
                refresh_token = state.get("refresh_token")
                device_id = state.get("device_id")
                # Restore EC key if saved
                ec_key_data = state.get("ec_key")
                if ec_key_data and HAS_ECDSA:
                    signer = RequestSigner.from_state(ec_key_data)
                    if signer:
                        debug(f"  EC key restored from state")
                debug(f"  refresh_token loaded: {len(refresh_token) if refresh_token else 0} chars")
            except (json.JSONDecodeError, KeyError) as e:
                debug(f"  state file parse error: {e}")

    # Try device-bound flow if ecdsa is available
    use_device_bound = HAS_ECDSA
    debug(f"  use_device_bound={use_device_bound} HAS_ECDSA={HAS_ECDSA}")

    if use_device_bound:
        # Get refresh token if we don't have one
        if not refresh_token:
            _, refresh_token = device_code_auth()
            print()

        try:
            xbl3_xl, xbl3_mp, xuid, gamertag_resolved, refresh_token, signer, device_id = \
                get_xbl_tokens_device_bound(refresh_token, signer=signer, device_id=device_id)
            print(f"[+] Device-bound auth complete (Collections API enabled)")
        except Exception as e:
            debug(f"  device-bound auth failed: {e}")
            print(f"[!] Device-bound auth failed: {e}")
            print("[*] Falling back to simple (non-device-bound) auth...")
            print("    (Collections API will return 0 items without device claims)")
            use_device_bound = False

    if not use_device_bound:
        # Fallback: simple non-device-bound flow
        msa_token = None
        if refresh_token:
            try:
                msa_resp = msa_request("https://login.live.com/oauth20_token.srf", {
                    "client_id": CLIENT_ID,
                    "scope": SCOPE,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                })
                msa_token = msa_resp["access_token"]
                refresh_token = msa_resp.get("refresh_token", refresh_token)
                print("[+] MSA token refreshed")
            except Exception as e:
                print(f"[!] Refresh failed: {e}")
                print("[*] Falling back to device code flow...")
                refresh_token = None

        if msa_token is None:
            msa_token, refresh_token = device_code_auth()

        print()
        xbl3_xl, xbl3_mp, xuid, gamertag_resolved, refresh_token = \
            get_xbl_tokens_simple_from_msa(msa_token, refresh_token)

    gamertag = existing_gamertag or gamertag_resolved

    if not gamertag:
        gamertag = input("  Enter gamertag label for this account: ").strip()
        if not gamertag:
            gamertag = f"Account_{xuid[:8] if xuid else 'unknown'}"

    # Save state (refresh token + EC key for device-bound reuse)
    ensure_account_dir(gamertag)
    state_file = account_path(gamertag, "xbox_auth_state.json")
    state_data = {"refresh_token": refresh_token}
    if signer:
        state_data["ec_key"] = signer.export_state()
    if device_id:
        state_data["device_id"] = device_id
    with open(state_file, "w") as f:
        json.dump(state_data, f, indent=2)

    # Save auth tokens
    token_file = account_path(gamertag, "auth_token.txt")
    with open(token_file, "w") as f:
        f.write(xbl3_mp)

    # Save xboxlive.com token (for TitleHub)
    xl_token_file = account_path(gamertag, "auth_token_xl.txt")
    with open(xl_token_file, "w") as f:
        f.write(xbl3_xl)

    # Save XUID
    xuid_file = account_path(gamertag, "xuid.txt")
    with open(xuid_file, "w") as f:
        f.write(xuid)

    # Register in accounts.json
    uhs = xbl3_mp.split("x=")[1].split(";")[0] if "x=" in xbl3_mp else ""
    register_account(gamertag, uhs)

    # Clear cache for this account
    clear_api_cache(gamertag=gamertag)

    print()
    print(f"[+] Account: {gamertag}")
    print(f"[+] Tokens saved to {account_dir(gamertag)}")
    print(f"    Collections token: {len(xbl3_mp)} chars")
    print(f"    TitleHub token:    {len(xbl3_xl)} chars")
    print(f"    XUID: {xuid}")
    if use_device_bound:
        print(f"    Auth mode: Device-bound (Collections API enabled)")
    else:
        print(f"    Auth mode: Simple (TitleHub only, no Collections)")

    return gamertag


def get_xbl_tokens_simple_from_msa(msa_token, refresh_token):
    """Get XBL3.0 tokens from an already-acquired MSA token.
    Returns (xbl3_xboxlive, xbl3_mp, xuid, gamertag, refresh_token)."""
    debug(f"get_xbl_tokens_simple_from_msa: msa_token={len(msa_token)} chars")

    # Simple user token (no device binding needed)
    print("[*] Getting user token...")
    user_body = json.dumps({
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"t={msa_token}",
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://user.auth.xboxlive.com/user/authenticate",
        data=user_body, method="POST",
        headers={"Content-Type": "application/json", "x-xbl-contract-version": "1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            user_resp_raw = resp.read().decode("utf-8")
            user_resp = json.loads(user_resp_raw)
            user_token = user_resp["Token"]
        debug(f"  user token: {len(user_token)} chars")
        debug(f"  user resp claims: {json.dumps(user_resp.get('DisplayClaims', {}))[:500]}")
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  user.auth FAILED: HTTP {e.code} body={err}")
        raise
    print("[+] User token acquired")

    # XSTS for xboxlive.com (gives xuid, gamertag, TitleHub access)
    print("[*] Getting XSTS token (xboxlive.com)...")
    xsts_body = json.dumps({
        "RelyingParty": "http://xboxlive.com",
        "TokenType": "JWT",
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        data=xsts_body, method="POST",
        headers={"Content-Type": "application/json", "x-xbl-contract-version": "1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            xl_resp = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  xsts xboxlive.com FAILED: HTTP {e.code} body={err}")
        raise
    xl_token = xl_resp["Token"]
    xl_uhs = xl_resp["DisplayClaims"]["xui"][0]["uhs"]
    xuid = xl_resp["DisplayClaims"]["xui"][0].get("xid", "")
    gamertag = xl_resp["DisplayClaims"]["xui"][0].get("gtg", "")
    xbl3_xl = build_xbl3_token(xl_token, xl_uhs)
    debug(f"  xboxlive.com XSTS: uhs={xl_uhs} xuid={xuid} gtg={gamertag} token={len(xbl3_xl)}ch")
    debug(f"  xboxlive.com claims: {json.dumps(xl_resp.get('DisplayClaims', {}))[:500]}")
    print(f"[+] Gamertag: {gamertag}, XUID: {xuid}")

    # XSTS for mp.microsoft.com (Collections API)
    print("[*] Getting XSTS token (mp.microsoft.com)...")
    mp_body = json.dumps({
        "RelyingParty": "http://mp.microsoft.com/",
        "TokenType": "JWT",
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        data=mp_body, method="POST",
        headers={"Content-Type": "application/json", "x-xbl-contract-version": "1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            mp_resp = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  xsts mp.microsoft.com FAILED: HTTP {e.code} body={err}")
        raise
    mp_token = mp_resp["Token"]
    mp_uhs = mp_resp["DisplayClaims"]["xui"][0]["uhs"]
    xbl3_mp = build_xbl3_token(mp_token, mp_uhs)
    debug(f"  mp.microsoft.com XSTS: uhs={mp_uhs} token={len(xbl3_mp)}ch")
    debug(f"  mp.microsoft.com claims: {json.dumps(mp_resp.get('DisplayClaims', {}))[:500]}")
    print(f"[+] Tokens ready (TitleHub: {len(xbl3_xl)} chars, Collections: {len(xbl3_mp)} chars)")

    return xbl3_xl, xbl3_mp, xuid, gamertag, refresh_token


# ===========================================================================
# Device-Bound Auth (EC P-256 signed requests for Collections API)
# ===========================================================================

def _signed_request(signer, method, url, body_dict=None, headers=None, timeout=30):
    """Make a signed HTTP request using the EC P-256 RequestSigner.

    The Signature header is computed over the request method, URL path+query,
    Authorization header, and body — proving possession of the EC private key.
    """
    if headers is None:
        headers = {}

    body = b""
    if body_dict is not None:
        body = json.dumps(body_dict).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    auth_header = headers.get("Authorization", "")
    signature = signer.sign_request(method, url, authorization=auth_header, body=body)
    headers["Signature"] = signature

    req = urllib.request.Request(url, data=body if body else None, method=method,
                                 headers=headers)
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_device_token(signer, device_id=None):
    """Register a device and get a DeviceToken using EC P-256 proof-of-possession.

    Args:
        signer: RequestSigner instance with the EC key pair
        device_id: UUID string for this device (generated if None)

    Returns:
        (device_token_jwt, device_id) tuple
    """
    if device_id is None:
        device_id = str(uuid.uuid4())

    # Android format: {uuid}
    formatted_id = "{%s}" % device_id

    url = "https://device.auth.xboxlive.com/device/authenticate"
    data = {
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "AuthMethod": "ProofOfPossession",
            "Id": formatted_id,
            "DeviceType": "Android",
            "Version": "8.0.0",
            "ProofKey": signer.get_proof_key(),
        },
    }
    cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
    headers = {
        "x-xbl-contract-version": "1",
        "Content-Type": "application/json",
        "MS-CV": cv,
    }

    debug(f"get_device_token: device_id={device_id}")
    debug(f"  ProofKey={json.dumps(signer.get_proof_key())}")

    try:
        resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  device.auth FAILED: HTTP {e.code} body={err}")
        print(f"[!] Device auth failed: HTTP {e.code}")
        print(f"    {err[:300]}")
        raise

    device_token = resp["Token"]
    debug(f"  DeviceToken: {len(device_token)} chars")
    debug(f"  Claims: {json.dumps(resp.get('DisplayClaims', {}))[:500]}")
    return device_token, device_id


def sisu_authorize(signer, msa_token, device_token, sisu_session_id=None):
    """Get User + Title + XSTS tokens via SISU authorization.

    This is the key step that produces device-bound tokens with full claims,
    enabling Collections API access.

    Args:
        signer: RequestSigner instance
        msa_token: MSA access token (from device code or refresh)
        device_token: DeviceToken JWT from get_device_token()
        sisu_session_id: Optional session ID from prior SISU authenticate

    Returns:
        dict with keys: user_token, title_token, authorization_token,
        xuid, gamertag, userhash
    """
    url = "https://sisu.xboxlive.com/authorize"
    data = {
        "AccessToken": f"t={msa_token}",
        "AppId": CLIENT_ID,
        "DeviceToken": device_token,
        "Sandbox": "RETAIL",
        "SiteName": "user.auth.xboxlive.com",
        "ProofKey": signer.get_proof_key(),
    }
    if sisu_session_id:
        data["SessionId"] = sisu_session_id

    headers = {
        "x-xbl-contract-version": "1",
        "Content-Type": "application/json",
    }

    debug(f"sisu_authorize: msa_token={len(msa_token)}ch device_token={len(device_token)}ch")

    try:
        resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  sisu.authorize FAILED: HTTP {e.code} body={err}")
        print(f"[!] SISU authorize failed: HTTP {e.code}")
        print(f"    {err[:300]}")
        raise

    debug(f"  SISU response keys: {list(resp.keys())}")

    # Extract tokens from response
    user_token = resp.get("UserToken", {}).get("Token", "")
    title_token = resp.get("TitleToken", {}).get("Token", "")
    auth_token = resp.get("AuthorizationToken", {}).get("Token", "")
    display = resp.get("AuthorizationToken", {}).get("DisplayClaims", {})
    xui = display.get("xui", [{}])[0] if display.get("xui") else {}
    userhash = xui.get("uhs", "")
    xuid = xui.get("xid", "")
    gamertag = xui.get("gtg", "")

    debug(f"  UserToken: {len(user_token)}ch, TitleToken: {len(title_token)}ch")
    debug(f"  AuthToken: {len(auth_token)}ch, xuid={xuid}, gtg={gamertag}")

    return {
        "user_token": user_token,
        "title_token": title_token,
        "authorization_token": auth_token,
        "userhash": userhash,
        "xuid": xuid,
        "gamertag": gamertag,
    }


def get_xsts_token_device_bound(signer, user_token, device_token, title_token,
                                 relying_party):
    """Get an XSTS token with device claims for a specific relying party.

    Unlike the simple flow, this includes DeviceToken and TitleToken in the
    XSTS Properties, which produces tokens with device claims — required
    for Collections API access.
    """
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
    headers = {
        "x-xbl-contract-version": "1",
        "Content-Type": "application/json",
    }

    debug(f"get_xsts_token_device_bound: rp={relying_party}")

    try:
        resp = _signed_request(signer, "POST", url, body_dict=data, headers=headers)
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")[:1000]
        debug(f"  xsts device-bound FAILED: HTTP {e.code} body={err}")
        print(f"[!] XSTS ({relying_party}) failed: HTTP {e.code}")
        print(f"    {err[:300]}")
        raise

    token = resp["Token"]
    uhs = resp["DisplayClaims"]["xui"][0]["uhs"]
    debug(f"  XSTS {relying_party}: token={len(token)}ch uhs={uhs}")
    return token, uhs


def get_xbl_tokens_device_bound(refresh_token, signer=None, device_id=None):
    """Get XBL3.0 tokens using device-bound auth with EC P-256 signing.

    This flow produces XSTS tokens WITH device claims, which are required
    for Collections API (mp.microsoft.com) to return actual data.

    Returns (xbl3_xboxlive, xbl3_mp, xuid, gamertag, new_refresh_token,
             signer, device_id)
    """
    if not HAS_ECDSA:
        raise RuntimeError(
            "ecdsa package required for device-bound auth. "
            "Install with: pip install ecdsa"
        )

    # Create or reuse signer
    if signer is None:
        signer = RequestSigner()
        print("[*] Generated new EC P-256 device key")
    else:
        print("[*] Using existing EC P-256 device key")

    # Refresh MSA token
    print("[*] Refreshing MSA token...")
    msa_resp = msa_request("https://login.live.com/oauth20_token.srf", {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })
    msa_token = msa_resp["access_token"]
    new_refresh = msa_resp.get("refresh_token", refresh_token)
    print("[+] MSA token refreshed")

    # Step 1: Get device token
    print("[*] Registering device (EC P-256 proof-of-possession)...")
    if device_id is None:
        device_id = str(uuid.uuid4())
    device_token, device_id = get_device_token(signer, device_id)
    print(f"[+] Device token acquired")

    # Step 2: SISU authorize — gets User + Title + Auth tokens in one call
    print("[*] SISU authorization (device-bound)...")
    sisu_result = sisu_authorize(signer, msa_token, device_token)
    user_token = sisu_result["user_token"]
    title_token = sisu_result["title_token"]
    xuid = sisu_result["xuid"]
    gamertag = sisu_result["gamertag"]
    print(f"[+] Gamertag: {gamertag}, XUID: {xuid}")

    # Step 3: Get XSTS for xboxlive.com (TitleHub)
    print("[*] Getting XSTS token (xboxlive.com, device-bound)...")
    xl_token, xl_uhs = get_xsts_token_device_bound(
        signer, user_token, device_token, title_token,
        "http://xboxlive.com"
    )
    xbl3_xl = build_xbl3_token(xl_token, xl_uhs)
    print(f"[+] TitleHub token: {len(xbl3_xl)} chars")

    # Step 4: Get XSTS for mp.microsoft.com (Collections API)
    print("[*] Getting XSTS token (mp.microsoft.com, device-bound)...")
    mp_token, mp_uhs = get_xsts_token_device_bound(
        signer, user_token, device_token, title_token,
        "http://mp.microsoft.com/"
    )
    xbl3_mp = build_xbl3_token(mp_token, mp_uhs)
    print(f"[+] Collections token: {len(xbl3_mp)} chars")

    print(f"[+] Device-bound tokens ready!")
    return xbl3_xl, xbl3_mp, xuid, gamertag, new_refresh, signer, device_id


def fetch_account_profile(auth_token_xl):
    """Fetch the current user's account profile using xboxlive.com RP token.

    Returns dict with gamertag, xuid, country, etc. or None on failure.
    Uses accounts.xboxlive.com/users/current/profile endpoint.
    """
    url = "https://accounts.xboxlive.com/users/current/profile"
    req = urllib.request.Request(url, headers={
        "Authorization": auth_token_xl,
        "x-xbl-contract-version": "5",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        debug(f"fetch_account_profile failed: {e}")
        return None

    gt_info = data.get("gamertag", {})
    return {
        "gamertag": gt_info.get("gamertag", ""),
        "gamertagSuffix": gt_info.get("gamertagSuffix", ""),
        "classicGamertag": gt_info.get("classicGamertag", ""),
        "xuid": str(data.get("ownerXuid", "")),
        "country": data.get("legalCountry", ""),
        "locale": data.get("locale", ""),
        "dateCreated": data.get("dateCreated", ""),
        "isAdult": data.get("isAdult", True),
    }


def cmd_add():
    """Add a new account via device code flow. Loops until user declines."""
    while True:
        print("=" * 56)
        print("  XCT — Add New Account")
        print("=" * 56)
        print()
        gamertag = sisu_auth_for_account()
        if gamertag:
            print()
            scan_now = input("  Process full library scan now? [Y/n]: ").strip().lower()
            if scan_now not in ("n", "no"):
                html_file, _lib = process_account(gamertag, method="both")
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
        print()
        again = input("Add another account? [y/N]: ").strip().lower()
        if again not in ("y", "yes"):
            break
        print()


def delete_account(gamertag):
    """Delete an account and all its data."""
    import shutil
    accounts = load_accounts()
    if gamertag not in accounts:
        print(f"[!] Account '{gamertag}' not found.")
        return
    confirm = input(f"  Delete account '{gamertag}' and all its data? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("  Cancelled.")
        return
    # Remove account directory
    acct = account_dir(gamertag)
    if os.path.isdir(acct):
        shutil.rmtree(acct)
    # Remove from registry
    del accounts[gamertag]
    save_accounts(accounts)
    print(f"[+] Account '{gamertag}' deleted.")


def refresh_account_token(gamertag):
    """Refresh an account's XBL3.0 token. Returns True on success.
    For HAR-only accounts (no refresh token), triggers device code auth."""
    debug(f"refresh_account_token: gamertag={gamertag}")
    state_file = account_path(gamertag, "xbox_auth_state.json")
    debug(f"  state_file={state_file} exists={os.path.isfile(state_file)}")
    # Log what files exist for this account
    acct_dir = account_dir(gamertag)
    if os.path.isdir(acct_dir):
        files = os.listdir(acct_dir)
        debug(f"  account dir files: {files}")
    else:
        debug(f"  account dir does NOT exist: {acct_dir}")
    if not os.path.isfile(state_file):
        print(f"[*] No auth state for {gamertag} (HAR-only account)")
        print(f"    Device code login needed to enable TitleHub access.")
        answer = input(f"    Authenticate {gamertag} now? [Y/n]: ").strip().lower()
        debug(f"  user answer: '{answer}'")
        if answer in ("n", "no"):
            print(f"    Skipping {gamertag}")
            return True
    try:
        sisu_auth_for_account(existing_gamertag=gamertag)
        debug(f"  refresh succeeded for {gamertag}")
        return True
    except Exception as e:
        debug(f"  refresh FAILED for {gamertag}: {e}")
        print(f"[!] Token refresh failed for {gamertag}: {e}")
        return False


# ===========================================================================
# HAR Extraction
# ===========================================================================

def find_har_file(arg=None):
    """Find a HAR file to parse."""
    if arg:
        path = os.path.join(SCRIPT_DIR, arg) if not os.path.isabs(arg) else arg
        if os.path.isfile(path):
            return path
        print(f"ERROR: File not found: {path}")
        sys.exit(1)

    har_files = sorted(glob.glob(os.path.join(SCRIPT_DIR, "*.har")),
                       key=os.path.getmtime, reverse=True)
    if not har_files:
        print("ERROR: No .har files found in the script directory.")
        print(f"  Directory: {SCRIPT_DIR}")
        print()
        print("  Capture Xbox app traffic with mitmproxy and export as HAR.")
        sys.exit(1)

    return har_files[0]


def extract_token(har_path):
    """Extract XBL3.0 tokens from a HAR file, return the best one."""
    with open(har_path, "r", encoding="utf-8") as f:
        har = json.load(f)

    tokens = {}

    for entry in har.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        headers = entry.get("request", {}).get("headers", [])

        for header in headers:
            name = header.get("name", "").lower()
            value = header.get("value", "")

            if name in ("authorization", "x-ms-authorization-xbl") and value.startswith("XBL3.0"):
                if value not in tokens:
                    tokens[value] = {"len": len(value), "urls": [], "header": name}
                tokens[value]["urls"].append(url)

    if not tokens:
        print("ERROR: No XBL3.0 tokens found in the HAR file.")
        print(f"  File: {har_path}")
        print(f"  Entries: {len(har.get('log', {}).get('entries', []))}")
        sys.exit(1)

    return tokens


def detect_gamertag_from_har(har_path, uhs):
    """Try to auto-detect the gamertag from a HAR file.

    Strategy 1: Match UHS against existing accounts in accounts.json.
    Strategy 2: Scan HAR response bodies for XSTS/profile DisplayClaims
                containing the gamertag ("gtg" field).
    Returns gamertag string or None.
    """
    # Strategy 1: match UHS against known accounts
    accounts = load_accounts()
    for gt, meta in accounts.items():
        if meta.get("uhs") == uhs:
            return gt

    # Strategy 2: scan HAR responses for gamertag in DisplayClaims
    try:
        with open(har_path, "r", encoding="utf-8") as f:
            har = json.load(f)
    except (json.JSONDecodeError, IOError):
        return None

    for entry in har.get("log", {}).get("entries", []):
        resp = entry.get("response", {})
        content = resp.get("content", {})
        text = content.get("text", "")
        if not text or '"DisplayClaims"' not in text:
            continue
        try:
            body = json.loads(text)
            claims = body.get("DisplayClaims", {})
            xui_list = claims.get("xui", [])
            for xui in xui_list:
                if xui.get("uhs") == uhs and xui.get("gtg"):
                    return xui["gtg"]
        except (json.JSONDecodeError, AttributeError):
            continue

    return None


def har_extract(arg=None):
    """HAR extraction flow."""
    print("=" * 56)
    print("  XCT — HAR Token Extractor")
    print("=" * 56)
    print()

    har_path = find_har_file(arg)
    print(f"[*] Reading: {os.path.basename(har_path)}")

    tokens = extract_token(har_path)

    by_len = {}
    for token, info in tokens.items():
        by_len.setdefault(info["len"], []).append((token, info))

    print(f"[+] Found {len(tokens)} unique tokens ({len(by_len)} different types)\n")

    sorted_lens = sorted(by_len.keys(), reverse=True)
    choices = []
    for i, length in enumerate(sorted_lens):
        group = by_len[length]
        token, info = group[0]
        uhs = token.split(";")[0].replace("XBL3.0 x=", "")
        sample_urls = [u.split("/")[2] for u in info["urls"][:3]]
        domains = ", ".join(sorted(set(sample_urls)))
        print(f"  [{i+1}] {length} chars (uhs={uhs})")
        print(f"      Used by: {domains}")
        print(f"      Requests: {len(info['urls'])}")
        print()
        choices.append(token)

    if len(choices) == 1:
        selected = choices[0]
        print("[+] Using the only token found.")
    else:
        best = None
        for token, info in tokens.items():
            for url in info["urls"]:
                if "collections.mp.microsoft.com" in url:
                    best = token
                    break
            if best:
                break

        if best:
            selected = best
            print("[+] Auto-selected: token used for collections.mp.microsoft.com")
        else:
            try:
                pick = input(f"Pick token [1-{len(choices)}, default=1]: ").strip()
                idx = int(pick) - 1 if pick else 0
                selected = choices[idx]
            except (ValueError, IndexError):
                selected = choices[0]

    # Auto-detect gamertag
    uhs = selected.split(";")[0].replace("XBL3.0 x=", "")
    detected = detect_gamertag_from_har(har_path, uhs)
    print()
    if detected:
        print(f"  Detected gamertag: {detected}")
        confirm = input(f"  Use '{detected}'? [Y/n]: ").strip().lower()
        if confirm in ("n", "no"):
            label = input(f"  Enter gamertag label (uhs={uhs}): ").strip()
            if not label:
                label = f"Account_{uhs[:8]}"
        else:
            label = detected
    else:
        label = input(f"  Enter gamertag label for this account (uhs={uhs}): ").strip()
        if not label:
            label = f"Account_{uhs[:8]}"

    # Save to account directory
    ensure_account_dir(label)
    token_file = account_path(label, "auth_token.txt")
    with open(token_file, "w") as f:
        f.write(selected)

    # Register in accounts.json
    register_account(label, uhs)

    # Clear cache for this account
    clear_api_cache(gamertag=label)

    print()
    print(f"[+] Account: {label}")
    print(f"[+] Token saved to {token_file}")
    print(f"    Length: {len(selected)} chars")


# ===========================================================================
# Library HTTP helper
# ===========================================================================

def api_request(url, method="GET", headers=None, body=None, retries=3):
    """
    Make an HTTPS request, returning parsed JSON.
    Retries on transient errors.
    """
    debug(f"api_request: {method} {url}")
    if body:
        debug(f"  body keys: {list(body.keys()) if isinstance(body, dict) else type(body).__name__}")
    hdrs = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
                raw = resp.read()
                result = json.loads(raw)
                debug(f"  OK: {len(raw)} bytes, "
                      f"type={type(result).__name__}, "
                      f"keys={list(result.keys()) if isinstance(result, dict) else f'len={len(result)}'}")
                return result
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            debug(f"  HTTP {e.code} attempt={attempt+1}/{retries} body={err_body[:500]}")
            if e.code in (429, 500, 502, 503) and attempt < retries - 1:
                wait = 2 ** attempt
                print(f"    HTTP {e.code} on {url[:80]}... retry in {wait}s")
                time.sleep(wait)
                continue
            print(f"    HTTP {e.code} on {url[:80]}... {err_body[:200]}")
            return None
        except Exception as e:
            debug(f"  Exception attempt={attempt+1}/{retries}: {e}")
            if attempt < retries - 1:
                time.sleep(1)
                continue
            print(f"    Error on {url[:80]}...: {e}")
            return None
    return None


# ===========================================================================
# Library utilities
# ===========================================================================

def print_header():
    """Print the XCT ASCII art header."""
    print()
    print("  ██╗  ██╗ ██████╗████████╗")
    print("  ╚██╗██╔╝██╔════╝╚══██╔══╝")
    print("   ╚███╔╝ ██║        ██║")
    print("   ██╔██╗ ██║        ██║")
    print("  ██╔╝ ██╗╚██████╗   ██║")
    print("  ╚═╝  ╚═╝ ╚═════╝   ╚═╝")
    print()
    print(f"  Xbox Collection Tracker by Freshdex v{VERSION}")
    print()


def banner(gamertag=None):
    """Print a short startup banner."""
    print()
    print(f"[*] Processing: {gamertag or 'unknown'}")
    print()


def is_cache_fresh(filepath):
    """Return True if filepath exists and is younger than CACHE_MAX_AGE."""
    if not os.path.isfile(filepath):
        return False
    age = time.time() - os.path.getmtime(filepath)
    return age < CACHE_MAX_AGE


def save_json(filepath, data):
    """Write data to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def load_json(filepath):
    """Load data from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


# ===========================================================================
# Step 1: Read auth token
# ===========================================================================

def read_auth_token(optional=False):
    """Read the XBL3.0 auth token from file.

    If optional=True, returns None instead of exiting when token is missing.
    """
    if not os.path.isfile(AUTH_TOKEN_FILE):
        if optional:
            return None
        print(f"ERROR: {AUTH_TOKEN_FILE} not found.")
        print("  Run `python XCT.py add` to set up your account.")
        sys.exit(1)
    with open(AUTH_TOKEN_FILE, "r") as f:
        token = f.read().strip()
    if not token:
        if optional:
            return None
        print("ERROR: auth_token.txt is empty.")
        sys.exit(1)
    print(f"[+] Auth token loaded ({len(token)} chars)")
    return token


# ===========================================================================
# Step 2: Fetch entitlements
# ===========================================================================

def fetch_entitlements_collection(auth_token):
    """Fetch entitlements from Collections API only.

    Uses the mp.microsoft.com RP token (auth_token.txt).
    Returns list of entitlement dicts with productId, status, acquiredDate, etc.
    """
    debug(f"fetch_entitlements_collection: auth_token={len(auth_token)}ch")

    if is_cache_fresh(ENTITLEMENTS_COLLECTION_FILE):
        items = load_json(ENTITLEMENTS_COLLECTION_FILE)
        debug(f"  cache hit: {len(items)} items")
        print(f"[+] Collections entitlements loaded from cache ({len(items)} items)")
        return items

    print("[*] Fetching entitlements from Collections API...")
    url = "https://collections.mp.microsoft.com/v7.0/collections/query"
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
    }
    base_body = {
        "beneficiaries": [],
        "market": "GB",
        "entitlementFilters": [],
        "excludeDuplicates": True,
        "expandSatisfiedBy": False,
        "maxPageSize": 1000,
        "validityType": "All",
        "productSkuIds": [],
    }

    all_items = []
    page = 0
    continuation = None

    while True:
        page += 1
        body = dict(base_body)
        if continuation:
            body["continuationToken"] = continuation

        data = api_request(url, method="POST", headers=headers, body=body)
        if data is None:
            print("  ERROR: Failed to fetch entitlements page. Aborting.")
            break

        items = data.get("items", [])
        for item in items:
            all_items.append({
                "productId":       item.get("productId", ""),
                "productKind":     item.get("productKind", ""),
                "status":          item.get("status", ""),
                "acquiredDate":    (item.get("acquiredDate") or "")[:10],
                "startDate":       (item.get("startDate") or "")[:10],
                "endDate":         (item.get("endDate") or "")[:10],
                "isTrial":         item.get("isTrial", False),
                "skuType":         item.get("skuType", ""),
                "skuId":           item.get("skuId", ""),
                "purchasedCountry": item.get("purchasedCountry", ""),
                "quantity":        item.get("quantity", 1),
            })

        continuation = data.get("continuationToken")
        print(f"  Page {page}: {len(items)} items (total: {len(all_items)})")
        if not continuation:
            break

    print(f"[+] Collections API: {len(all_items)} entitlements")
    if all_items:
        save_json(ENTITLEMENTS_COLLECTION_FILE, all_items)
    else:
        print("  WARNING: 0 entitlements returned — not caching empty result")
    return all_items


def fetch_entitlements_titlehub(gamertag):
    """Fetch entitlements from TitleHub API only.

    Reads auth_token_xl.txt and xuid.txt from the account directory.
    Returns list of entitlement dicts, or None if tokens are missing.
    """
    debug(f"fetch_entitlements_titlehub: gamertag={gamertag}")

    if is_cache_fresh(ENTITLEMENTS_TITLEHUB_FILE):
        items = load_json(ENTITLEMENTS_TITLEHUB_FILE)
        debug(f"  cache hit: {len(items)} items")
        print(f"[+] TitleHub entitlements loaded from cache ({len(items)} items)")
        return items

    xl_token_file = account_path(gamertag, "auth_token_xl.txt") if gamertag else ""
    xuid_file = account_path(gamertag, "xuid.txt") if gamertag else ""

    debug(f"  xl_token_file={xl_token_file} exists={os.path.isfile(xl_token_file) if xl_token_file else 'N/A'}")
    debug(f"  xuid_file={xuid_file} exists={os.path.isfile(xuid_file) if xuid_file else 'N/A'}")

    if not (xl_token_file and os.path.isfile(xl_token_file) and os.path.isfile(xuid_file)):
        debug("  TitleHub skipped: missing xl_token or xuid files")
        print("[!] TitleHub tokens not available (missing auth_token_xl.txt or xuid.txt)")
        return None

    with open(xl_token_file, "r") as f:
        xl_token = f.read().strip()
    with open(xuid_file, "r") as f:
        xuid = f.read().strip()

    debug(f"  xl_token={len(xl_token)}ch xuid={xuid}")

    if not (xl_token and xuid):
        print("[!] TitleHub tokens empty")
        return None

    print("[*] Fetching library from TitleHub...")
    try:
        items = fetch_titlehub_library(xl_token, xuid)
        debug(f"  TitleHub returned {len(items)} items")
        if items:
            for it in items[:5]:
                th = it.get("_titlehub", {})
                debug(f"    - {th.get('name', '?')} (pid={it['productId']})")
            print(f"[+] TitleHub: {len(items)} titles")
            try:
                save_json(ENTITLEMENTS_TITLEHUB_FILE, items)
                debug(f"  Save OK: {os.path.getsize(ENTITLEMENTS_TITLEHUB_FILE)} bytes")
            except OSError as save_err:
                debug(f"  save_json OSError: {save_err}")
                with open(ENTITLEMENTS_TITLEHUB_FILE, "w", encoding="utf-8") as ef:
                    json.dump(items, ef, ensure_ascii=False)
            return items
        else:
            print("  TitleHub returned 0 titles")
            return []
    except Exception as e:
        import traceback
        debug(f"  TitleHub exception: {type(e).__name__}: {e}")
        debug(f"  Traceback:\n{traceback.format_exc()}")
        print(f"[!] TitleHub failed: {e}")
        return None


def _merge_collection_titlehub(collection_items, titlehub_items):
    """Merge Collections API entitlements with TitleHub metadata.

    Collections provides the full entitlement list (~5000 items) with purchase
    metadata (acquiredDate, status, purchasedCountry, skuType, etc.).
    TitleHub provides game metadata (~987 items) with names, images, platforms,
    gamePass status, achievements, and lastTimePlayed.

    The merged result uses Collections as the base list, enriched with TitleHub
    _titlehub metadata where available.
    """
    # Build TitleHub lookup by productId
    th_by_pid = {}
    for item in titlehub_items:
        pid = item.get("productId", "")
        if pid:
            th_by_pid[pid] = item

    merged = []
    for item in collection_items:
        pid = item.get("productId", "")
        th = th_by_pid.get(pid)
        if th:
            # Enrich Collections item with TitleHub metadata
            item["_titlehub"] = th.get("_titlehub", {})
        merged.append(item)

    # Add any TitleHub-only items not in Collections (flagged for separation)
    col_pids = set(item.get("productId", "") for item in collection_items)
    for item in titlehub_items:
        if item.get("productId", "") not in col_pids:
            item["_titlehub_only"] = True
            merged.append(item)

    th_enriched = sum(1 for m in merged if "_titlehub" in m)
    debug(f"  _merge_collection_titlehub: {len(collection_items)} collection + "
          f"{len(titlehub_items)} titlehub = {len(merged)} merged "
          f"({th_enriched} enriched)")

    return merged


def fetch_entitlements(auth_token, gamertag=None, method=None):
    """Fetch entitlements using the specified method.

    method="collection" — Collections API only
    method="titlehub"   — TitleHub only
    method="both"       — Collections + TitleHub merged (Android app style)
    method=None          — same as "both" if both tokens available

    Always copies result to ENTITLEMENTS_FILE for backward compatibility.
    """
    debug(f"fetch_entitlements: gamertag={gamertag} method={method} auth_token={len(auth_token) if auth_token else 0}ch")

    if is_cache_fresh(ENTITLEMENTS_FILE) and method in (None, "both"):
        items = load_json(ENTITLEMENTS_FILE)
        debug(f"  cache hit: {len(items)} items")
        print(f"[+] Library loaded from cache ({len(items)} items)")
        return items

    items = None

    if method == "collection":
        if not auth_token:
            print("[!] Collections API requires auth_token.txt")
            return []
        items = fetch_entitlements_collection(auth_token)

    elif method == "titlehub":
        items = fetch_entitlements_titlehub(gamertag)
        if items is None:
            print("[!] TitleHub unavailable — no entitlements fetched")
            return []

    else:
        # "both" or None: Collections for full list + TitleHub for metadata
        col_items = None
        th_items = None

        if auth_token:
            col_items = fetch_entitlements_collection(auth_token)

        th_items = fetch_entitlements_titlehub(gamertag)

        if col_items and th_items:
            # Merge: Collections base + TitleHub enrichment
            print(f"[*] Merging: {len(col_items)} Collections + {len(th_items)} TitleHub...")
            items = _merge_collection_titlehub(col_items, th_items)
            th_enriched = sum(1 for m in items if "_titlehub" in m)
            print(f"[+] Merged: {len(items)} items ({th_enriched} with TitleHub metadata)")
        elif col_items:
            items = col_items
        elif th_items:
            items = th_items
        else:
            print("[!] No entitlements fetched from either source")
            items = []

    if items is None:
        items = []

    # Copy to ENTITLEMENTS_FILE for backward compat
    if items:
        save_json(ENTITLEMENTS_FILE, items)
    return items


# ===========================================================================
# Step 2b: Content Access (Xbox 360 / backward-compat discovery)
# ===========================================================================

def fetch_contentaccess(auth_token, cache_file=None):
    """Fetch all owned product IDs from Content Access API.

    This endpoint returns ALL owned content including Xbox 360 backward-compatible
    games that the Collections API misses. Response is protobuf binary; product IDs
    are extracted via regex.

    Uses mp.microsoft.com RP token (auth_token.txt).
    Returns list of product IDs, or None on failure.
    """
    if cache_file and is_cache_fresh(cache_file):
        data = load_json(cache_file)
        print(f"[+] Content Access loaded from cache ({len(data)} product IDs)")
        return data

    print("[*] Fetching Content Access (all owned products)...")
    cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
    url = "https://contentaccess.exp.xboxservices.com/all/v1?market=US&offering=XGPUWEB"

    req = urllib.request.Request(url, headers={
        "Authorization": auth_token,
        "MS-CV": cv,
        "Accept": "application/octet-stream",
        "User-Agent": "okhttp/4.12.0",
    })

    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        debug(f"  contentaccess HTTP {e.code}: {err_body}")
        print(f"  Content Access failed: HTTP {e.code}")
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        debug(f"  contentaccess failed: {e}")
        print(f"  Content Access failed: {e}")
        return None

    # Extract 12-character product IDs from protobuf response
    product_ids = list(dict.fromkeys(
        m.group(1).decode() for m in re.finditer(rb'[\x0c]([A-Z0-9]{12})', raw)
    ))

    print(f"[+] Content Access: {len(product_ids)} product IDs from {len(raw):,} bytes")

    if cache_file and product_ids:
        save_json(cache_file, product_ids)

    return product_ids


def fetch_titlehub_batch(title_ids, auth_token_xl):
    """Fetch title metadata via TitleHub batch endpoint.

    Accepts numeric TitleHub title IDs (XBOXTITLEID from catalog v3).
    Requests ProductId decoration so we can map responses back to
    Store product IDs (the input titleId != response titleId).

    Returns dict of {productId: title_data} keyed by Store product ID.
    """
    if not title_ids or not auth_token_xl:
        return {}

    print(f"    TitleHub batch: {len(title_ids)} title IDs to check")
    results = {}
    xbox360_running = 0
    batch_size = 500
    total_batches = (len(title_ids) + batch_size - 1) // batch_size
    t0 = time.time()

    for i in range(0, len(title_ids), batch_size):
        batch = title_ids[i:i + batch_size]
        batch_num = i // batch_size + 1
        print(f"    Batch {batch_num}/{total_batches} ({len(batch)} IDs)...", end="", flush=True)
        url = "https://titlehub.xboxlive.com/titles/batch/decoration/Image,ProductId"
        cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
        body = json.dumps({"pfns": None, "titleIds": batch}).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers={
            "Authorization": auth_token_xl,
            "Content-Type": "application/json",
            "x-xbl-contract-version": "2",
            "Accept-Language": "en-GB",
            "MS-CV": cv,
            "Accept": "application/json",
        })

        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as resp:
                raw = resp.read()
                data = json.loads(raw)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            debug(f"  titlehub_batch HTTP {e.code} batch {batch_num}: {err_body}")
            print(f" HTTP {e.code}: {err_body[:100]}")
            continue
        except Exception as e:
            debug(f"  titlehub_batch failed for batch {batch_num}: {e}")
            print(f" FAILED: {e}")
            continue

        titles = data.get("titles", [])
        batch_360 = 0
        for title in titles:
            pid = title.get("productId", "")
            if pid:
                results[pid] = title
                if "Xbox360" in title.get("devices", []):
                    batch_360 += 1
        xbox360_running += batch_360
        elapsed = time.time() - t0
        print(f" {len(titles)} titles returned, {batch_360} Xbox 360 ({elapsed:.1f}s)")

    print(f"    TitleHub batch complete: {len(results)} titles, "
          f"{xbox360_running} Xbox 360 found in {time.time() - t0:.1f}s")
    return results


def fetch_dynamic_channel(channel_name, auth_token_xl, market="GB", lang="en-GB"):
    """Fetch product IDs from a marketplace DynamicChannel.

    Calls bronze.xboxservices.com/Channel/DynamicChannel.{name}
    Returns list of product IDs, or empty list on error.
    """
    label = MARKETPLACE_CHANNELS.get(channel_name, channel_name)
    url = (f"https://bronze.xboxservices.com/Channel/"
           f"DynamicChannel.{channel_name}?market={market}&language={lang}")
    cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"

    req = urllib.request.Request(url, headers={
        "Authorization": auth_token_xl,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "MS-CV": cv,
        "Accept-Language": lang,
    })

    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
            raw = resp.read()
            data = json.loads(raw)
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        debug(f"  DynamicChannel.{channel_name} HTTP {e.code}: {err_body}")
        if e.code == 401:
            print(f"    {label}: HTTP 401 — token expired")
            raise  # propagate so caller can auto-refresh
        print(f"    {label}: HTTP {e.code} — {err_body[:100]}")
        return []
    except urllib.error.URLError as e:
        print(f"    {label}: {e}")
        debug(f"  DynamicChannel.{channel_name} failed: {e}")
        return []

    pids = data.get("productIds", [])
    print(f"    {label}: {len(pids)} products")
    return pids


# ===========================================================================
# Step 3: Fetch Display Catalog (combined pass per market)
# ===========================================================================

def extract_catalog_data(product, market="GB"):
    """
    Extract catalog fields from a single Display Catalog product.
    For GB market: extracts everything (title, description, images, prices, etc.)
    For US market: extracts only USD prices.
    """
    result = {}
    pid = product.get("ProductId", "")

    lp = product.get("LocalizedProperties", [])
    lp0 = lp[0] if lp else {}

    # -- Title, description, developer, publisher (always extract) --
    result["title"] = lp0.get("ProductTitle", "")
    result["description"] = lp0.get("ShortDescription", "")
    result["developer"] = lp0.get("DeveloperName", "")
    result["publisher"] = lp0.get("PublisherName", "")

    # -- Images: find BoxArt and Hero/SuperHeroArt --
    images = lp0.get("Images", [])
    box_art = ""
    hero_art = ""
    for img in images:
        purpose = img.get("ImagePurpose", "")
        uri = img.get("Uri", "")
        if uri and not uri.startswith("http"):
            uri = "https:" + uri
        if purpose == "BoxArt" and not box_art:
            box_art = uri
        elif purpose in ("SuperHeroArt", "Hero") and not hero_art:
            hero_art = uri
    result["boxArt"] = box_art
    result["heroImage"] = hero_art
    result["image"] = box_art or hero_art

    # -- Properties: Category, IsDemo --
    props = product.get("Properties", {})
    result["category"] = props.get("Category", "")
    result["isDemo"] = props.get("IsDemo", False)

    # -- DisplaySkuAvailabilities: prices, trial, platforms, releaseDate --
    skus = product.get("DisplaySkuAvailabilities", [])

    best_msrp = 0
    best_list = 0
    currency = "GBP" if market == "GB" else "USD"
    has_trial_sku = False
    has_purchase_sku = False
    platforms = set()
    release_date = ""

    for sku_entry in skus:
        sku_obj = sku_entry.get("Sku", {})
        sku_props = sku_obj.get("Properties", {})
        is_trial_sku = sku_props.get("IsTrial", False)
        if is_trial_sku:
            has_trial_sku = True

        # Packages -> PlatformDependencies
        for pkg in sku_props.get("Packages", []):
            for pdep in pkg.get("PlatformDependencies", []):
                pname = pdep.get("PlatformName", "")
                mapped = PLATFORM_MAP.get(pname, pname)
                if mapped:
                    platforms.add(mapped)

        avails = sku_entry.get("Availabilities", [])
        for avail in avails:
            # Price
            omd = avail.get("OrderManagementData", {})
            price_info = omd.get("Price", {})
            msrp = price_info.get("MSRP", 0) or 0
            list_price = price_info.get("ListPrice", 0) or 0
            cc = price_info.get("CurrencyCode", "")

            expected_cc = "GBP" if market == "GB" else "USD"
            if cc == expected_cc:
                if msrp > 0 and (best_msrp == 0 or msrp < best_msrp):
                    best_msrp = msrp
                if list_price > 0 and (best_list == 0 or list_price < best_list):
                    best_list = list_price
                if not is_trial_sku and msrp > 0:
                    has_purchase_sku = True

            # Release date
            avail_props = avail.get("Properties", {})
            ord_str = avail_props.get("OriginalReleaseDate", "")
            if ord_str and not release_date:
                release_date = ord_str[:10]

    result["hasTrialSku"] = has_trial_sku
    result["hasPurchaseSku"] = has_purchase_sku
    result["platforms"] = sorted(platforms)
    result["releaseDate"] = release_date
    if market == "GB":
        result["priceGBP"] = best_msrp
        result["currentPriceGBP"] = best_list
    else:
        result["priceUSD"] = best_msrp
        result["currentPriceUSD"] = best_list

    return pid, result


def fetch_catalog_batch(product_ids, market, lang):
    """Fetch a single batch of up to 20 product IDs from Display Catalog."""
    ids_str = ",".join(product_ids)
    url = (
        f"https://displaycatalog.md.mp.microsoft.com/v7.0/products"
        f"?bigIds={ids_str}&market={market}&languages={lang}"
    )
    headers = {
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
    }
    data = api_request(url, method="GET", headers=headers)
    if data is None:
        return {}

    results = {}
    for product in data.get("Products", []):
        pid, info = extract_catalog_data(product, market)
        if pid:
            results[pid] = info
    return results


def fetch_display_catalog(product_ids, market, lang, cache_file, label):
    """
    Fetch Display Catalog data for all product_ids in batches of 20,
    using ThreadPoolExecutor for parallelism.
    """
    if is_cache_fresh(cache_file):
        catalog = load_json(cache_file)
        print(f"[+] {label} loaded from cache ({len(catalog)} products)")
        return catalog

    print(f"[*] Fetching {label} for {len(product_ids)} products...")

    # Deduplicate
    unique_ids = list(dict.fromkeys(product_ids))

    # Batch into groups of 20
    batches = []
    for i in range(0, len(unique_ids), 20):
        batches.append(unique_ids[i:i + 20])

    catalog = {}
    completed = 0
    total = len(batches)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(fetch_catalog_batch, batch, market, lang): batch
            for batch in batches
        }
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            try:
                batch_result = future.result()
                catalog.update(batch_result)
            except Exception as e:
                print(f"    Batch error: {e}")
            if completed % 20 == 0 or completed == total:
                print(f"  {label}: {completed}/{total} batches done ({len(catalog)} products)")

    print(f"[+] {label}: {len(catalog)} products resolved")
    save_json(cache_file, catalog)
    return catalog


# ===========================================================================
# Step 4: Merge entitlements + catalog into library data
# ===========================================================================

def _norm_kind(kind):
    """Normalize productKind: GAME→Game, DURABLE→Durable, etc."""
    if kind and kind.isupper():
        return kind.capitalize()
    return kind


def merge_library(entitlements, catalog, gamertag=""):
    """Combine entitlement data with catalog data.

    If an entitlement has TitleHub metadata (from _titlehub key), uses it
    as fallback when catalog data is missing.

    Returns (library, play_history) where play_history contains TitleHub-only
    items (play history games not in Collections — trials, disc rentals, etc.).
    lastTimePlayed from TitleHub is still applied to owned library items.
    """
    debug(f"merge_library: {len(entitlements)} entitlements, "
          f"{len(catalog)} catalog entries")
    library = []
    play_history = []
    for ent in entitlements:
        pid = ent["productId"]
        cat = catalog.get(pid, {})
        th = ent.get("_titlehub", {})

        # Check if product was flagged invalid by catalog v3
        is_invalid = cat.get("_invalid", False)
        if is_invalid:
            cat = {}

        # Map TitleHub devices to platform names for fallback
        th_platforms = []
        for d in th.get("devices", []):
            mapped = {"XboxOne": "Xbox One", "XboxSeries": "Xbox Series X|S",
                      "PC": "PC", "Mobile": "Mobile"}.get(d, d)
            if mapped not in th_platforms:
                th_platforms.append(mapped)

        # Resolve title: catalog → TitleHub → product ID for invalid/unknown
        resolved_title = cat.get("title", "") or th.get("name", "") or pid

        item = {
            # Account identifier
            "gamertag":        gamertag,
            # Entitlement fields
            "productId":       pid,
            "productKind":     _norm_kind(ent.get("productKind", "") or cat.get("productKind", "")),
            "status":          ent.get("status", ""),
            "acquiredDate":    ent.get("acquiredDate", ""),
            "startDate":       ent.get("startDate", ""),
            "endDate":         ent.get("endDate", ""),
            "isTrial":         ent.get("isTrial", False) or ent.get("skuType", "") == "Trial",
            "skuType":         ent.get("skuType", ""),
            "skuId":           ent.get("skuId", ""),
            "purchasedCountry": ent.get("purchasedCountry", ""),
            "quantity":        ent.get("quantity", 1),
            # Catalog fields with TitleHub fallback
            "title":           resolved_title,
            "description":     cat.get("description", ""),
            "developer":       cat.get("developer", ""),
            "publisher":       cat.get("publisher", ""),
            "image":           cat.get("image", "") or th.get("displayImage", ""),
            "boxArt":          cat.get("boxArt", ""),
            "heroImage":       cat.get("heroImage", ""),
            "category":        cat.get("category", ""),
            "releaseDate":     cat.get("releaseDate", ""),
            "platforms":       cat.get("platforms", []) or th_platforms,
            "isDemo":          cat.get("isDemo", False),
            # Prices (USD)
            "priceUSD":        cat.get("priceUSD", 0),
            "currentPriceUSD": cat.get("currentPriceUSD", 0),
            # Ownership classification
            # _contentaccess_only items come from ContentAccess API (Game Pass/subscription)
            # not from Collections API — they are NOT purchased
            "onGamePass":      False,  # set by JS cross-ref with fresh GP data
            "owned":           not ent.get("_contentaccess_only", False),
            # Last played (from TitleHub TitleHistory decoration)
            "lastTimePlayed":  th.get("lastTimePlayed", ""),
            # Catalog validity
            "catalogInvalid":  is_invalid,
            # Xbox Title ID (same value = same game, different editions)
            "xboxTitleId":     next((a["id"] for a in cat.get("alternateIds", [])
                                     if a.get("idType") == "XBOXTITLEID"), ""),
        }

        # Title-based demo detection (catalog isDemo is unreliable)
        if not item["isDemo"] and item["productKind"] == "Game":
            t = item["title"].lower()
            if (t.endswith(" demo") or " demo " in t or t.endswith(" - demo")
                    or "pre-alpha" in t or "tech demo" in t):
                item["isDemo"] = True

        # Legacy platform tagging: items not in TitleHub with no platform data
        # that have Windows Phone era product IDs → tag as Windows Phone
        if not th and item["productKind"] in ("Game", ""):
            plats = item["platforms"]
            if pid.startswith("9WZDNCR") and not plats:
                item["platforms"] = ["Windows Phone"]

        # TitleHub-only items go to play_history (disc rentals, trials, etc.)
        # Detect by: has _titlehub metadata but no Collections purchase data
        is_th_only = (ent.get("_titlehub_only")
                      or ("_titlehub" in ent and not ent.get("acquiredDate")
                          and not ent.get("skuId")))
        if is_th_only:
            play_history.append(item)
        else:
            library.append(item)

    debug(f"  merge_library: {len(library)} library + {len(play_history)} play history")
    return library, play_history


# ===========================================================================
# Step 4b: Catalog v3 (replaces Display Catalog batching)
# ===========================================================================

def fetch_catalog_v3(product_ids, auth_token_xl, market="GB", lang="en-GB",
                     cache_file=None, label="Catalog v3"):
    """Fetch rich product metadata via catalog.gamepass.com/v3/products.

    Despite the name, this endpoint works for ALL product IDs, not just
    Game Pass items. Accepts thousands of IDs in a single POST call.
    Requires xboxlive.com RP token (auth_token_xl.txt).

    Returns dict of {productId: info_dict} in the same shape as
    fetch_display_catalog for downstream compatibility.
    """
    if cache_file and is_cache_fresh(cache_file):
        catalog = load_json(cache_file)
        print(f"[+] {label} loaded from cache ({len(catalog)} products)")
        return catalog

    print(f"[*] Fetching {label} for {len(product_ids)} products...")

    unique_ids = list(dict.fromkeys(product_ids))
    cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
    url = (f"https://catalog.gamepass.com/v3/products"
           f"?market={market}&language={lang}&hydration=MobileLowAmber0")
    body = json.dumps({"Products": unique_ids}).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers={
        "Authorization": auth_token_xl,
        "Content-Type": "application/json",
        "calling-app-name": "XboxMobile",
        "calling-app-version": "2602.2.1",
        "MS-CV": cv,
        "Accept": "application/json",
        "User-Agent": "okhttp/4.12.0",
    })

    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=120) as resp:
            raw = resp.read()
            data = json.loads(raw)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        debug(f"  catalog_v3 failed: {e}")
        print(f"  Catalog v3 failed: {e}")
        return None

    products = data.get("Products", {})
    invalid = data.get("InvalidIds", [])
    debug(f"  catalog_v3: {len(products)} products, {len(invalid)} invalid")

    # Map v3 response to our standard catalog shape
    currency_key = "GBP" if market == "GB" else "USD"
    catalog = {}
    for pid, info in products.items():
        prices = info.get("approximatePrices", {})
        msrp_obj = prices.get("msrp", {})
        msrp_val = msrp_obj.get("value", 0) or 0

        # Current price: sale price or GP discount or MSRP
        sale_obj = prices.get("anonymousDiscountPrice", {})
        current_val = sale_obj.get("value", msrp_val) if sale_obj else msrp_val

        # Map v3 platforms to our names
        v3_platforms = info.get("availablePlatforms", [])
        plat_map = {
            "Console": "Xbox One", "XboxOne": "Xbox One",
            "XboxSeriesX": "Xbox Series X|S", "PC": "PC",
            "Desktop": "PC", "Handheld": "PC", "XCloud": "xCloud",
            "Mobile": "Mobile",
        }
        platforms = []
        for p in v3_platforms:
            mapped = plat_map.get(p, p)
            if mapped not in platforms:
                platforms.append(mapped)

        # Images
        tile_img = info.get("tileImage", {})
        poster_img = info.get("posterImage", {})
        hero_img = info.get("heroImage", {}) or info.get("titledHeroArt", {})

        categories = info.get("categories", [])

        entry = {
            "title": info.get("name", ""),
            "description": "",  # v3 doesn't include descriptions
            "developer": info.get("developerName", ""),
            "publisher": info.get("publisherName", ""),
            "image": tile_img.get("uri", ""),
            "boxArt": poster_img.get("uri", ""),
            "heroImage": hero_img.get("uri", ""),
            "category": categories[0] if categories else "",
            "releaseDate": (info.get("releaseDate", "") or "")[:10],
            "platforms": sorted(platforms),
            "isDemo": False,
            "hasTrialSku": False,
            "hasPurchaseSku": msrp_val > 0,
            # v3-exclusive fields
            "productKind": info.get("productKind", ""),
            "alternateIds": info.get("alternateIds", []),
            "isEAPlay": info.get("isEAPlay", False),
            "xCloudIsStreamable": info.get("xCloudIsStreamable", False),
            "capabilities": info.get("capabilities", []),
            "isBundle": info.get("isBundle", False),
        }

        if market == "GB":
            entry["priceGBP"] = msrp_val
            entry["currentPriceGBP"] = current_val
        else:
            entry["priceUSD"] = msrp_val
            entry["currentPriceUSD"] = current_val

        catalog[pid] = entry

    # Mark invalid IDs in catalog with a sentinel entry so merge can flag them
    for inv_id in invalid:
        catalog[inv_id] = {"_invalid": True}

    print(f"[+] {label}: {len(catalog) - len(invalid)} products resolved"
          f"{f', {len(invalid)} invalid' if invalid else ''}")

    if cache_file:
        save_json(cache_file, catalog)
    return catalog


def _read_xl_token():
    """Read the xboxlive.com RP token (auth_token_xl.txt) for current account."""
    acct = os.path.dirname(AUTH_TOKEN_FILE)  # same dir as auth_token.txt
    xl_file = os.path.join(acct, "auth_token_xl.txt")
    if not os.path.isfile(xl_file):
        return None
    with open(xl_file, "r") as f:
        token = f.read().strip()
    return token if token else None


# ===========================================================================
# Regional Pricing (multi-market price comparison)
# ===========================================================================

def fetch_exchange_rates():
    """Fetch USD exchange rates from open.er-api.com (free, no key).

    Returns dict of {currency_code: rate_vs_USD}.
    Rates are cached globally for 1 hour.
    """
    if is_cache_fresh(EXCHANGE_RATES_FILE):
        try:
            data = load_json(EXCHANGE_RATES_FILE)
            rates = data.get("rates", {})
            debug(f"Exchange rates loaded from cache ({len(rates)} currencies)")
            return rates
        except Exception:
            pass

    print("[*] Fetching exchange rates...")
    url = "https://open.er-api.com/v6/latest/USD"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"XCT/{VERSION}"})
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            data = json.loads(resp.read())
        rates = data.get("rates", {})
        save_json(EXCHANGE_RATES_FILE, {"rates": rates, "fetchedAt": time.time()})
        print(f"[+] Exchange rates: {len(rates)} currencies")
        return rates
    except Exception as e:
        print(f"[!] Exchange rates failed: {e}")
        # Hardcoded fallback rates (approximate)
        return {
            "ARS": 1200, "BRL": 5.8, "TRY": 36, "ISK": 140,
            "NGN": 1600, "TWD": 32, "NZD": 1.72, "COP": 4400,
            "HKD": 7.82, "USD": 1.0,
        }


def _fetch_region_prices(market, info, product_ids, auth_token_xl, cache_dir):
    """Fetch prices from catalog v3 for a single market region.

    Returns (market_code, {pid: {"price": float, "salePrice": float, "currency": str}}).
    """
    locale = info["locale"]
    currency = info["currency"]
    cache_file = os.path.join(cache_dir, f"prices_{market.lower()}.json")

    if is_cache_fresh(cache_file):
        try:
            cached = load_json(cache_file)
            return market, cached
        except Exception:
            pass

    cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
    url = (f"https://catalog.gamepass.com/v3/products"
           f"?market={market}&language={locale}&hydration=MobileLowAmber0")
    body = json.dumps({"Products": product_ids}).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers={
        "Authorization": auth_token_xl,
        "Content-Type": "application/json",
        "calling-app-name": "XboxMobile",
        "calling-app-version": "2602.2.1",
        "MS-CV": cv,
        "Accept": "application/json",
        "User-Agent": "okhttp/4.12.0",
    })

    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=120) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        debug(f"  regional prices {market} failed: {e}")
        return market, {}

    products = data.get("Products", {})
    region_prices = {}
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

    save_json(cache_file, region_prices)
    return market, region_prices


def fetch_regional_prices(product_ids, auth_token_xl, cache_dir):
    """Fetch prices from catalog v3 for all PRICE_REGIONS in parallel.

    Returns dict of {market_code: {pid: {"price", "salePrice", "currency"}}}.
    """
    if not auth_token_xl:
        print("[!] auth_token_xl required for regional pricing")
        return {}

    unique_ids = list(dict.fromkeys(product_ids))
    print(f"[*] Fetching regional prices for {len(unique_ids)} products "
          f"across {len(PRICE_REGIONS)} regions...")

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(
                _fetch_region_prices, market, info, unique_ids,
                auth_token_xl, cache_dir
            ): market
            for market, info in PRICE_REGIONS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                market, prices = future.result()
                results[market] = prices
                print(f"    {market}: {len(prices)} products with prices")
            except Exception as e:
                market = futures[future]
                debug(f"  regional prices {market} exception: {e}")
                print(f"    {market}: failed ({e})")
                results[market] = {}

    return results


def enrich_regional_prices(mkt_items, auth_token_xl):
    """Add regional prices to marketplace items.

    For each item, adds 'regionalPrices' dict and 'bestRegionUSD' float.
    Also fetches and caches exchange rates.
    Returns the enriched items list.
    """
    product_ids = [item["productId"] for item in mkt_items if item.get("productId")]
    if not product_ids or not auth_token_xl:
        return mkt_items

    cache_dir = os.path.dirname(MARKETPLACE_FILE)
    regional = fetch_regional_prices(product_ids, auth_token_xl, cache_dir)
    rates = fetch_exchange_rates()

    enriched = 0
    for item in mkt_items:
        pid = item.get("productId", "")
        rp = {}
        for market in PRICE_REGIONS:
            region_data = regional.get(market, {})
            if pid in region_data:
                rp[market] = region_data[pid]
        if rp:
            item["regionalPrices"] = rp
            # Compute best (cheapest) regional price in gift-card USD
            best_usd = 0
            best_market = ""
            for market, prices in rp.items():
                price = prices.get("salePrice") or prices.get("price", 0)
                currency = prices.get("currency", "USD")
                rate = rates.get(currency, 1) or 1
                usd = (price / rate) * GC_FACTOR
                if usd > 0 and (best_usd == 0 or usd < best_usd):
                    best_usd = usd
                    best_market = market
            if best_usd > 0:
                item["bestRegionUSD"] = round(best_usd, 2)
                item["bestRegion"] = best_market
            enriched += 1

    print(f"[+] Regional prices: {enriched}/{len(mkt_items)} items enriched")
    return mkt_items


# ===========================================================================
# Step 5: Fetch Game Pass catalog
# ===========================================================================

def fetch_gamepass_subscriptions(market="GB"):
    """Fetch Game Pass catalog via public subscriptions endpoint.

    No auth required! Returns all tiers (pc, console, eaaccess, ultimate,
    gamepasscore, gamepassstandard, nakuconsole, nakupc, ubisoftplus, gtaplus).

    Returns dict with "items" (productId -> [tier_names]) and metadata,
    matching the shape expected by downstream code.
    """
    if is_cache_fresh(GAMEPASS_FILE):
        data = load_json(GAMEPASS_FILE)
        print(f"[+] Game Pass catalog loaded from cache ({len(data.get('items', {}))} product IDs)")
        return data

    print("[*] Fetching Game Pass catalog (subscriptions API)...")

    url = f"https://catalog.gamepass.com/subscriptions?market={market}&subscription=all"
    req = urllib.request.Request(url, headers={
        "User-Agent": "okhttp/4.12.0",
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        debug(f"  gamepass subscriptions failed: {e}")
        print(f"  Subscriptions API failed: {e}")
        return None

    # Build product -> tier mapping
    product_tiers = {}
    tier_counts = {}
    for tier_name, pid_list in data.items():
        if not isinstance(pid_list, list):
            continue
        tier_counts[tier_name] = len(pid_list)
        for pid in pid_list:
            if pid and isinstance(pid, str):
                if pid not in product_tiers:
                    product_tiers[pid] = []
                product_tiers[pid].append(tier_name)

    # Print tier summary
    for tier, count in sorted(tier_counts.items(), key=lambda x: -x[1]):
        print(f"    {tier}: {count}")
    print(f"[+] Game Pass (subscriptions): {len(product_tiers)} unique product IDs")

    result = {
        "items": product_tiers,
        "fetchedAt": time.time(),
        "source": "subscriptions",
        "tiers": tier_counts,
    }
    save_json(GAMEPASS_FILE, result)
    return result


def _read_varint(buf, pos):
    """Read a protobuf varint from buf at pos. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    return result, pos


def _parse_protobuf_product_ids(raw_bytes):
    """Extract product IDs from contentaccess protobuf response.

    The response has top-level field 1 (subscription plan, skip) and
    field 2 entries (games). Each field 2 is a length-delimited message
    whose sub-field 1 is the 12-char product ID string.
    """
    pids = []
    pos = 0
    end = len(raw_bytes)
    while pos < end:
        tag, pos = _read_varint(raw_bytes, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint — skip
            _, pos = _read_varint(raw_bytes, pos)
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(raw_bytes, pos)
            data = raw_bytes[pos:pos + length]
            pos += length
            if field_num == 2:
                # Parse sub-message for field 1 (product ID)
                inner_pos = 0
                inner_end = len(data)
                while inner_pos < inner_end:
                    itag, inner_pos = _read_varint(data, inner_pos)
                    ifn = itag >> 3
                    iwt = itag & 0x07
                    if iwt == 0:
                        _, inner_pos = _read_varint(data, inner_pos)
                    elif iwt == 2:
                        ilen, inner_pos = _read_varint(data, inner_pos)
                        idata = data[inner_pos:inner_pos + ilen]
                        inner_pos += ilen
                        if ifn == 1:
                            try:
                                pid = idata.decode("ascii")
                                if len(pid) == 12:
                                    pids.append(pid)
                            except (UnicodeDecodeError, ValueError):
                                pass
                            break  # got the product ID, skip rest
                    elif iwt == 5:
                        inner_pos += 4
                    elif iwt == 1:
                        inner_pos += 8
                    else:
                        break
        elif wire_type == 5:
            pos += 4
        elif wire_type == 1:
            pos += 8
        else:
            break
    return pids


def fetch_contentaccess_catalog(auth_token, market="US", offering="CLOUDGAMING"):
    """Fetch Game Pass catalog via contentaccess API (protobuf response).

    Uses the mp.microsoft.com RP token (auth_token.txt).
    Returns list of product IDs or None on failure.
    """
    url = (
        f"https://contentaccess.exp.xboxservices.com/all/v1"
        f"?market={market}&offering={offering}"
    )
    debug(f"fetch_contentaccess_catalog: {url}")
    headers = {
        "Authorization": auth_token,
        "calling-app-name": "XCT",
        "calling-app-version": "1.0",
        "Accept": "*/*",
    }

    req = urllib.request.Request(url, headers=headers)
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            raw = resp.read()
            debug(f"  contentaccess response: {len(raw)} bytes")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        debug(f"  contentaccess failed: {e}")
        return None

    pids = _parse_protobuf_product_ids(raw)
    debug(f"  contentaccess product IDs: {len(pids)}")
    return pids


def fetch_gamepass_catalog(auth_token=None):
    """Fetch Game Pass catalog.

    Priority: subscriptions API (public) > contentaccess (auth) > sigls (public).
    """
    if is_cache_fresh(GAMEPASS_FILE):
        data = load_json(GAMEPASS_FILE)
        print(f"[+] Game Pass catalog loaded from cache ({len(data.get('items', {}))} product IDs)")
        return data

    # --- 1. Try subscriptions API (public, best source) ---
    result = fetch_gamepass_subscriptions(market="GB")
    if result and result.get("items"):
        return result

    print("  Subscriptions API failed, trying contentaccess...")

    # --- 2. Try contentaccess API (auth required, protobuf) ---
    if auth_token:
        pids = fetch_contentaccess_catalog(auth_token, market="GB", offering="CLOUDGAMING")
        if pids:
            product_collections = {}
            for pid in pids:
                product_collections[pid] = ["Game Pass"]
            result = {
                "items": product_collections,
                "fetchedAt": time.time(),
                "source": "contentaccess",
            }
            print(f"[+] Game Pass (contentaccess): {len(product_collections)} product IDs")
            save_json(GAMEPASS_FILE, result)
            return result
        print("  contentaccess API failed, falling back to sigls...")

    # --- 3. Final fallback: sigls collections (public, partial) ---
    print("[*] Fetching Game Pass catalog (sigls fallback)...")
    product_collections = {}

    for coll_id, coll_name in GP_COLLECTIONS.items():
        url = (
            f"https://catalog.gamepass.com/sigls/v2"
            f"?id={coll_id}&language=en-GB&market=GB"
        )
        data = api_request(url, method="GET", headers={
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json",
        })
        if data is None:
            print(f"  WARNING: Failed to fetch '{coll_name}'")
            continue

        count = 0
        for entry in data:
            pid = entry.get("id", "")
            if pid and len(pid) == 12:
                if pid not in product_collections:
                    product_collections[pid] = []
                product_collections[pid].append(coll_name)
                count += 1
        print(f"  {coll_name}: {count} products")

    result = {
        "items": product_collections,
        "fetchedAt": time.time(),
        "source": "sigls",
    }
    print(f"[+] Game Pass (sigls): {len(product_collections)} unique product IDs")
    save_json(GAMEPASS_FILE, result)
    return result


def fetch_gamepass_details(gp_data, existing_catalog_us=None,
                          auth_token_xl=None):
    """
    Fetch catalog details for Game Pass items not already in the library catalog.
    Uses catalog v3 (single call) if auth_token_xl available, else DisplayCatalog.
    Returns a dict of { productId: { title, publisher, etc. } }
    """
    if existing_catalog_us is None:
        existing_catalog_us = {}

    if is_cache_fresh(GAMEPASS_DETAIL_FILE):
        details = load_json(GAMEPASS_DETAIL_FILE)
        print(f"[+] Game Pass details loaded from cache ({len(details)} products)")
        return details

    gp_pids = list(gp_data.get("items", {}).keys())
    need = [pid for pid in gp_pids if pid not in existing_catalog_us]

    print(f"[*] Game Pass details: {len(need)} need US catalog")

    us_new = {}

    if auth_token_xl and need:
        v3_us = fetch_catalog_v3(need, auth_token_xl, market="US", lang="en-US",
                                 cache_file=GP_CATALOG_US_TMP, label="GP Catalog v3 (US)")
        if v3_us:
            us_new = v3_us

    # Fallback to DisplayCatalog for any not resolved
    if not us_new and need:
        us_new = fetch_display_catalog(
            need, "US", "en-US", GP_CATALOG_US_TMP, "GP Display Catalog (US)")

    # Merge existing + new
    all_us = dict(existing_catalog_us)
    all_us.update(us_new)

    # Build Game Pass details
    details = {}
    product_collections = gp_data.get("items", {})
    for pid, colls in product_collections.items():
        cat = all_us.get(pid, {})
        details[pid] = {
            "productId":    pid,
            "title":        cat.get("title", ""),
            "description":  cat.get("description", ""),
            "developer":    cat.get("developer", ""),
            "publisher":    cat.get("publisher", ""),
            "boxArt":       cat.get("boxArt", ""),
            "heroImage":    cat.get("heroImage", ""),
            "image":        cat.get("image", ""),
            "category":     cat.get("category", ""),
            "releaseDate":  cat.get("releaseDate", ""),
            "platforms":    cat.get("platforms", []),
            "priceUSD":     cat.get("priceUSD", 0),
            "productType":  cat.get("category", ""),
            "collections":  colls,
            "owned":        False,  # will be set during merge
        }

    print(f"[+] Game Pass details resolved: {len(details)} products")
    save_json(GAMEPASS_DETAIL_FILE, details)
    return details


# ===========================================================================
# Step 6: Build HTML
# ===========================================================================

def build_html_template(gamertag=""):
    """Build the static HTML template. Contains no data — loads from data.js.

    All dropdowns are populated dynamically from LIB/GP/HISTORY data by JS.
    Only needs to be written once; subsequent scans only update data.js.
    """
    ls_key = f"xboxLibFlags_{gamertag}" if gamertag else "xboxLibFlags"
    page_title = "XCT"

    html = (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="UTF-8">\n'
        f'<title>{page_title}</title>\n'
        '<link rel="icon" href="data:image/svg+xml,<svg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 32 32%27><circle cx=%2716%27 cy=%2716%27 r=%2715%27 fill=%27%23107c10%27/><path d=%27M8.5 7.5C10.5 9 12.5 11.5 16 16c3.5-4.5 5.5-7 7.5-8.5a12.3 12.3 0 0 1 3 5.5c0 4-2 7.5-5 9.5C19 20 17 17 16 16c-1 1-3 4-5.5 6.5-3-2-5-5.5-5-9.5a12.3 12.3 0 0 1 3-5.5z%27 fill=%27white%27/></svg>">\n'
        '<style>\n'
        '*{margin:0;padding:0;box-sizing:border-box}\n'
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e0e0e0}\n"
        '.tabs{display:flex;align-items:center;background:#111;border-bottom:2px solid #107c10;position:sticky;top:0;z-index:100}\n'
        '.tab-cur{margin-left:auto;padding:4px 6px;background:#1a1a1a;color:#e0e0e0;border:1px solid #333;border-radius:4px;font-size:12px;cursor:pointer}\n'
        '.tab{padding:12px 20px;cursor:pointer;color:#888;font-size:14px;font-weight:500;border-bottom:3px solid transparent;transition:all .2s;white-space:nowrap}\n'
        '.tab:hover{color:#ccc;background:#1a1a1a}\n'
        '.tab.active{color:#107c10;border-bottom-color:#107c10;background:#0a0a0a}\n'
        '.tab .cnt{font-size:11px;color:#555;margin-left:4px}\n'
        '.tab.active .cnt{color:#107c10}\n'
        '.section{display:none;padding:16px;min-height:400px}\n'
        '.section.active{display:block}\n'
        'h2{color:#107c10;margin-bottom:4px;font-size:20px}\n'
        '.sub{color:#666;margin-bottom:12px;font-size:13px}\n'
        '.search-row{margin-bottom:8px}\n'
        '.search-row input{padding:7px 12px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:13px;width:100%}\n'
        '.filters{margin-bottom:12px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}\n'
        '.filters select{padding:7px 10px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:12px}\n'
        '.pill{padding:5px 12px;border:1px solid #333;background:#1a1a1a;color:#aaa;border-radius:16px;cursor:pointer;font-size:11px}\n'
        '.pill.active{background:#107c10;border-color:#107c10;color:#fff}\n'
        '.pill:hover{background:#222}\n'
        '.cbar{color:#666;font-size:12px;margin-bottom:6px}\n'
        '.cbar span{color:#107c10;font-weight:bold}\n'
        '.stbl{border-collapse:collapse;font-size:12px;margin-bottom:8px;width:auto}\n'
        '.stbl th{padding:2px 10px;color:#888;font-weight:normal;text-align:left;border-bottom:1px solid #333;white-space:nowrap}\n'
        '.stbl td{padding:2px 10px;text-align:left;color:#ccc;white-space:nowrap}\n'
        '.stbl td:first-child{color:#e0e0e0;font-weight:500}\n'
        '.stbl .stbl-gp td:first-child{color:#107c10}\n'
        '.stbl .stbl-div{border-left:1px solid #333}\n'
        '.stbl .cnt{color:#107c10;font-weight:bold}\n'
        '.stbl .usd{color:#42a5f5;font-weight:bold}\n'
        '.gtbl{border-collapse:collapse;font-size:13px;width:100%;margin-top:12px}\n'
        '.gtbl th{padding:8px 12px;color:#888;font-weight:500;text-align:left;border-bottom:1px solid #333;white-space:nowrap}\n'
        '.gtbl td{padding:6px 12px;border-bottom:1px solid #1a1a1a;color:#ccc;white-space:nowrap}\n'
        '.gtbl tr:hover{background:#1a1a1a}\n'
        '.gtbl td.num{text-align:right;font-variant-numeric:tabular-nums}\n'
        '.gtbl th.num{text-align:right}\n'
        '.gtbl .gt-name{color:#e0e0e0;font-weight:600}\n'
        '.gtbl .gt-ok{color:#107c10}\n'
        '.gtbl .gt-warn{color:#f59e0b}\n'
        '.gtbl .gt-err{color:#ef4444}\n'
        '.gtbl .gt-mono{font-family:monospace;font-size:11px;color:#888}\n'
        '.gtbl th.sortable{cursor:pointer;user-select:none}\n'
        '.gtbl th.sortable:hover{color:#e0e0e0}\n'
        '.gtbl th.sortable::after{content:"";display:inline-block;width:0;height:0;margin-left:5px;vertical-align:middle;border-left:4px solid transparent;border-right:4px solid transparent;border-bottom:4px solid #555}\n'
        '.gtbl th.sort-asc::after{border-bottom:4px solid #107c10;border-top:none}\n'
        '.gtbl th.sort-desc::after{border-bottom:none;border-top:4px solid #107c10}\n'
        '.cb-drop{position:relative;display:inline-block}\n'
        '.cb-btn{padding:7px 10px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:12px;cursor:pointer;white-space:nowrap;user-select:none}\n'
        '.cb-btn:hover{border-color:#555}\n'
        '.cb-btn.has-sel{border-color:#107c10;color:#107c10}\n'
        '.cb-panel{display:none;position:absolute;top:100%;left:0;margin-top:4px;background:#1a1a1a;border:1px solid #444;border-radius:6px;min-width:180px;max-height:70vh;overflow-y:auto;z-index:100;box-shadow:0 4px 16px rgba(0,0,0,.6);padding:4px 0}\n'
        '.cb-panel.open{display:block}\n'
        '.cb-panel label{display:flex;align-items:center;padding:4px 10px;font-size:12px;color:#ccc;cursor:pointer;gap:6px;white-space:nowrap}\n'
        '.cb-panel label:hover{background:#222}\n'
        '.cb-panel input[type=checkbox]{accent-color:#107c10}\n'
        '.cb-clear{padding:6px 10px;font-size:11px;color:#888;cursor:pointer;border-top:1px solid #333;margin-top:4px;text-align:center;user-select:none}\n'
        '.gt-plus{display:inline-block;margin-left:4px;padding:1px 5px;font-size:9px;background:#1a2a1a;color:#4caf50;border:1px solid #333;border-radius:8px;cursor:pointer;vertical-align:middle}\n'
        '.gt-plus:hover{background:#2a3a2a;border-color:#4caf50}\n'
        '.gt-popup{position:absolute;z-index:200;background:#1a1a1a;border:1px solid #444;border-radius:6px;padding:6px 0;box-shadow:0 4px 16px rgba(0,0,0,.6);min-width:140px}\n'
        '.gt-popup div{padding:4px 12px;font-size:12px;color:#ccc;white-space:nowrap}\n'
        '.gt-popup div:hover{background:#222}\n'
        '.pill-toggle{padding:7px 12px;border:1px solid #333;background:#1a1a1a;color:#e0e0e0;border-radius:6px;font-size:12px;cursor:pointer;white-space:nowrap;user-select:none}\n'
        '.pill-toggle:hover{border-color:#555}\n'
        '.pill-toggle.active{border-color:#107c10;color:#107c10;background:#0d1f0d}\n'
        '.cb-clear:hover{background:#222;color:#ccc}\n'
        '.cb-panel.cb-cols{column-gap:0}\n'
        '.cb-panel.cb-cols label{break-inside:avoid}\n'
        '.cb-panel.cb-cols .cb-clear{column-span:all}\n'
        '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px}\n'
        '.card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;overflow:hidden;cursor:pointer;transition:all .2s}\n'
        '.card:hover{border-color:#107c10;transform:translateY(-1px);box-shadow:0 3px 10px rgba(16,124,16,.12)}\n'
        '.card-img{width:100%;height:150px;object-fit:cover;background:#222}\n'
        '.card-body{padding:10px}\n'
        '.card-name{font-weight:600;font-size:14px;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.card-meta{font-size:11px;color:#666;margin-bottom:4px}\n'
        '.card-desc{font-size:11px;color:#888;line-height:1.4;max-height:2.8em;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}\n'
        '.card-badges{display:flex;gap:3px;flex-wrap:wrap;margin-top:6px}\n'
        '.badge{font-size:10px;padding:2px 6px;border-radius:10px;font-weight:500}\n'
        '.badge.series{background:#1a3a1a;color:#4caf50}\n'
        '.badge.one{background:#1a2a3a;color:#42a5f5}\n'
        '.badge.x360{background:#3a3a1a;color:#ffd54f}\n'
        '.badge.mobile{background:#3a1a3a;color:#ce93d8}\n'
        '.badge.pc{background:#1a3a3a;color:#4dd0e1}\n'
        '.badge.ach{background:#2a2a1a;color:#ffb74d}\n'
        '.badge.owned{background:#1a3a1a;color:#4caf50}\n'
        '.badge.new{background:#3a1a1a;color:#f44336}\n'
        '.badge.gp{background:#1a2a1a;color:#76ff03}\n'
        '.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:200;justify-content:center;align-items:center}\n'
        '.modal-overlay.active{display:flex}\n'
        '.modal{background:#1a1a1a;border:1px solid #333;border-radius:10px;max-width:650px;width:95%;max-height:90vh;overflow-y:auto}\n'
        '.modal-hero{width:100%;height:220px;object-fit:cover;background:#222}\n'
        '.modal-body{padding:16px}\n'
        '.modal-close{float:right;background:#333;border:none;color:#ccc;width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:16px;margin:8px}\n'
        '.modal-close:hover{background:#444}\n'
        '.modal-title{font-size:20px;font-weight:700;margin-bottom:4px}\n'
        '.modal-pub{color:#888;font-size:13px;margin-bottom:10px}\n'
        '.modal-desc{color:#bbb;font-size:13px;line-height:1.5;margin-bottom:12px}\n'
        '.modal-info{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;margin-bottom:12px}\n'
        '.modal-info .lbl{color:#666}\n'
        '.modal-info .val{color:#ccc}\n'
        '.modal-info a{color:#107c10}\n'
        '.ach-list{margin-top:10px}\n'
        '.ach-list h3{color:#ffb74d;font-size:13px;margin-bottom:6px}\n'
        '.ach-item{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #222;font-size:12px}\n'
        '.ach-item .gs{color:#ffb74d;font-weight:bold;min-width:35px}\n'
        '.lib-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px}\n'
        '.lib-card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:6px;padding:8px;display:flex;gap:8px;transition:border-color .2s;cursor:pointer}\n'
        '.lib-card:hover{border-color:#107c10}\n'
        '.lib-card img{width:50px;height:50px;object-fit:cover;border-radius:3px;flex-shrink:0;background:#222}\n'
        '.lib-card .info{flex:1;min-width:0}\n'
        '.lib-card .ln{font-weight:600;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.lib-card .lm{font-size:10px;color:#666}\n'
        '.lib-card .lp{font-size:11px;font-weight:600;margin-top:2px}\n'
        '.lib-card .lp .usd{color:#42a5f5}\n'
        '.s-active{color:#4caf50}.s-expired{color:#ff9800}.s-revoked{color:#f44336}\n'
        '.view-toggle{display:flex;gap:2px;margin-left:auto}\n'
        '.view-btn{padding:5px 8px;border:1px solid #333;background:#1a1a1a;color:#888;cursor:pointer;font-size:13px;line-height:1}\n'
        '.view-btn:first-child{border-radius:6px 0 0 6px}\n'
        '.view-btn:last-child{border-radius:0 6px 6px 0}\n'
        '.view-btn.active{background:#107c10;border-color:#107c10;color:#fff}\n'
        '.view-btn:hover:not(.active){background:#222}\n'
        '.list-view{display:flex;flex-direction:column;gap:1px}\n'
        '.list-view .lv-head{display:grid;grid-template-columns:40px 200px 110px 130px 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:6px 10px;background:#161616;border-bottom:1px solid #333;font-size:11px;font-weight:600;color:#888;min-width:max-content;position:sticky;top:47px;z-index:20}\n'
        '.list-view .lv-head div[data-sort]{cursor:pointer;user-select:none}\n'
        '.list-view .lv-head div[data-sort]:hover{color:#107c10}\n'
        '.list-view .lv-row{display:grid;grid-template-columns:40px 200px 110px 130px 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:5px 10px;background:#1a1a1a;border-bottom:1px solid #1e1e1e;align-items:center;cursor:pointer;font-size:12px;transition:background .15s;min-width:max-content}\n'
        '.list-view .lv-row:hover{background:#222}\n'
        '.list-view .lv-row img{width:36px;height:36px;object-fit:cover;border-radius:3px;background:#222}\n'
        '.list-view .lv-title{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.list-view .lv-pub{color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.list-view .lv-type{color:#888}\n'
        '.list-view .lv-usd{color:#42a5f5;font-weight:600;text-align:right}\n'
        '.list-view .lv-status{text-align:center}\n'
        '.gp-list .lv-head{grid-template-columns:50px 1fr 160px 120px 90px 80px}\n'
        '.gp-list .lv-row{grid-template-columns:50px 1fr 160px 120px 90px 80px}\n'
        '#mkt-list .lv-head{grid-template-columns:50px 1fr 140px 90px 90px repeat(10,80px) 80px}\n'
        '#mkt-list .lv-row{grid-template-columns:50px 1fr 140px 90px 90px repeat(10,80px) 80px}\n'
        '#mkt-list{overflow-x:auto}\n'
        '.lv-best{text-align:right;line-height:1.2}\n'
        '.lv-reg{text-align:right;font-size:11px;line-height:1.2}\n'
        '.rp-tbl{width:100%;border-collapse:collapse;font-size:12px;margin-top:10px}\n'
        '.rp-tbl th{text-align:right;padding:4px 6px;color:#888;border-bottom:1px solid #333;font-weight:600}\n'
        '.rp-tbl th:first-child{text-align:left}\n'
        '.rp-tbl td{padding:4px 6px;border-bottom:1px solid #222;text-align:right}\n'
        '.rp-tbl td:first-child{text-align:left;color:#ccc}\n'
        '.rp-best td{color:#4caf50 !important;font-weight:bold}\n'
        '#ctx-menu{display:none;position:fixed;background:#222;border:1px solid #444;border-radius:6px;z-index:300;min-width:160px;box-shadow:0 4px 16px rgba(0,0,0,.5);overflow:hidden}\n'
        '.ctx-opt{padding:8px 12px;cursor:pointer;font-size:12px;color:#ddd}\n'
        '.ctx-opt:hover{background:#333}\n'
        '.badge.trial{background:#3a2a1a;color:#ff9800}\n'
        '.badge.demo{background:#3a1a2a;color:#e91e63}\n'
        '.badge.flagged{background:#3a3a1a;color:#ffd54f}\n'
        '.hist-card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:8px;padding:14px;margin-bottom:8px;cursor:pointer;transition:border-color .2s}\n'
        '.hist-card:hover{border-color:#107c10}\n'
        '.hist-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}\n'
        '.hist-date{font-weight:600;font-size:14px;color:#e0e0e0}\n'
        '.hist-method{font-size:11px;color:#888;background:#222;padding:2px 8px;border-radius:10px}\n'
        '.hist-stats{display:flex;gap:16px;font-size:12px;color:#888;margin-bottom:6px}\n'
        ''
        '.hist-stats .usd{color:#42a5f5;font-weight:600}\n'
        '.hist-badges{display:flex;gap:6px;flex-wrap:wrap}\n'
        '.hist-badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:500}\n'
        '.hist-badge.added{background:#1a3a1a;color:#4caf50}\n'
        '.hist-badge.removed{background:#3a1a1a;color:#f44336}\n'
        '.hist-badge.changed{background:#3a3a1a;color:#ffd54f}\n'
        '.hist-detail{display:none;margin-top:10px;padding-top:10px;border-top:1px solid #2a2a2a}\n'
        '.hist-detail.open{display:block}\n'
        '.hist-section{margin-bottom:8px}\n'
        '.hist-section-title{font-size:12px;font-weight:600;margin-bottom:4px}\n'
        '.hist-section-title.add-title{color:#4caf50}\n'
        '.hist-section-title.rem-title{color:#f44336}\n'
        '.hist-section-title.chg-title{color:#ffd54f}\n'
        '.hist-item{font-size:11px;color:#aaa;padding:2px 0 2px 12px}\n'
        '.hist-diff{font-size:10px;color:#666;padding-left:24px}\n'
        '.hist-diff .old{color:#f44336;text-decoration:line-through}\n'
        '.hist-diff .new{color:#4caf50}\n'
        '</style>\n'
        '</head>\n'
        '<body>\n'

        # -- Loading spinner overlay --
        '<div id="loading-overlay" style="position:fixed;inset:0;background:#111;display:flex;'
        'flex-direction:column;align-items:center;justify-content:center;z-index:9999">'
        '<div style="width:48px;height:48px;border:4px solid #333;border-top-color:#107c10;'
        'border-radius:50%;animation:spin 0.8s linear infinite"></div>'
        '<div style="color:#888;margin-top:16px;font-size:14px">Loading...</div></div>\n'
        '<style>@keyframes spin{to{transform:rotate(360deg)}}</style>\n'

        # -- Tabs (counts populated by JS) --
        '<div class="tabs">\n'
        '<div class="tab active" onclick="switchTab(\'library\',this)">My Library <span class="cnt" id="tab-lib-cnt"></span></div>\n'
        '<div class="tab" id="tab-mkt" onclick="switchTab(\'marketplace\',this)" style="display:none">Marketplace <span class="cnt" id="tab-mkt-cnt"></span></div>\n'
        '<div class="tab" id="tab-gp" onclick="switchTab(\'gamepass\',this)" style="display:none">Game Pass Catalog <span class="cnt" id="tab-gp-cnt"></span></div>\n'
        '<div class="tab" id="tab-ph" onclick="switchTab(\'playhistory\',this)" style="display:none">Play History <span class="cnt" id="tab-ph-cnt"></span></div>\n'
        '<div class="tab" id="tab-hist" onclick="switchTab(\'history\',this)" style="display:none">Scan Log <span class="cnt" id="tab-hist-cnt"></span></div>\n'
        '<div class="tab" id="tab-acct" onclick="switchTab(\'gamertags\',this)" style="display:none">Gamertags <span class="cnt" id="tab-acct-cnt"></span></div>\n'
        '<select id="lib-cur" class="tab-cur" onchange="_onCur()">'
        '<option value="USD" selected>USD $</option>'
        '<option value="EUR">EUR €</option>'
        '<option value="GBP">GBP £</option>'
        '<option value="CAD">CAD CA$</option>'
        '<option value="AUD">AUD A$</option>'
        '<option value="NZD">NZD NZ$</option>'
        '<option value="JPY">JPY ¥</option>'
        '<option value="BRL">BRL R$</option>'
        '<option value="MXN">MXN MX$</option>'
        '<option value="INR">INR ₹</option>'
        '<option value="KRW">KRW ₩</option>'
        '<option value="TRY">TRY ₺</option>'
        '<option value="PLN">PLN zł</option>'
        '<option value="CHF">CHF</option>'
        '<option value="SEK">SEK kr</option>'
        '<option value="NOK">NOK kr</option>'
        '<option value="DKK">DKK kr</option>'
        '<option value="CZK">CZK Kč</option>'
        '<option value="HUF">HUF Ft</option>'
        '<option value="ILS">ILS ₪</option>'
        '<option value="SAR">SAR</option>'
        '<option value="AED">AED</option>'
        '<option value="ZAR">ZAR R</option>'
        '<option value="SGD">SGD S$</option>'
        '<option value="HKD">HKD HK$</option>'
        '<option value="TWD">TWD NT$</option>'
        '<option value="CLP">CLP CL$</option>'
        '<option value="COP">COP CO$</option>'
        '<option value="ARS">ARS AR$</option>'
        '<option value="PHP">PHP ₱</option>'
        '</select>\n'
        f'<div style="margin-left:auto;padding:0 14px;color:#555;font-size:11px;white-space:nowrap">XCT v{VERSION}</div>\n'
        '</div>\n'

        # -- Game Pass section --
        '<div class="section" id="gamepass">\n'
        '<h2>Game Pass Catalog</h2>\n'
        '<p class="sub" id="gp-sub"></p>\n'
        '<div class="filters">\n'
        '<input type="text" id="gp-search" placeholder="Search Game Pass..." oninput="filterGP()">\n'
        '<div class="pill active" onclick="setGPFilter(\'all\',this)">All</div>\n'
        '<div class="pill" onclick="setGPFilter(\'notOwned\',this)">Not Owned</div>\n'
        '<div class="pill" onclick="setGPFilter(\'owned\',this)">Owned</div>\n'
        '<div class="pill" onclick="setGPFilter(\'recent\',this)">Recently Added</div>\n'
        '<div class="pill" onclick="setGPFilter(\'popular\',this)">Most Popular</div>\n'
        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'gp\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'gp\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="cbar" id="gp-cbar"></div>\n'
        '<div class="grid" id="gp-grid" style="display:none"></div>\n'
        '<div class="list-view gp-list" id="gp-list"></div>\n'
        '</div>\n'

        # -- Library section (active by default) --
        '<div class="section active" id="library">\n'
        '<p class="sub" id="lib-sub"></p>\n'
        '<div class="cbar" id="lib-cbar"></div>\n'
        '<div class="search-row"><input type="text" id="lib-search" placeholder="Search library..." oninput="filterLib()"></div>\n'
        '<div class="filters">\n'
        '<div class="pill" onclick="clearAllFilters()" title="Reset all checkbox filters to default">Clear Filters</div>\n'
        '<div class="cb-drop" id="lib-gamertag" style="display:none"><div class="cb-btn" onclick="toggleCB(this)">Gamertag &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-status"><div class="cb-btn" onclick="toggleCB(this)">Status &#9662;</div><div class="cb-panel">'
        '<label><input type="checkbox" value="Active" checked onchange="filterLib()"> Active</label>'
        '<label><input type="checkbox" value="Expired" onchange="filterLib()"> Expired</label>'
        '<label><input type="checkbox" value="Revoked" onchange="filterLib()"> Revoked</label>'
        '<div class="cb-clear" onclick="cbToggleAll(this)">Clear All</div>'
        '</div></div>\n'
        '<div class="cb-drop" id="lib-type"><div class="cb-btn" onclick="toggleCB(this)">Type &#9662;</div><div class="cb-panel">'
        '<label><input type="checkbox" value="Game" checked onchange="filterLib()"> Game</label>'
        '<label><input type="checkbox" value="Durable" onchange="filterLib()"> DLC</label>'
        '<label><input type="checkbox" value="Application" onchange="filterLib()"> App</label>'
        '<label><input type="checkbox" value="Consumable" onchange="filterLib()"> Consumable</label>'
        '<label><input type="checkbox" value="Pass" onchange="filterLib()"> Pass</label>'
        '<label><input type="checkbox" value="_preorder" checked onchange="filterLib()"> Pre-orders</label>'
        '<label><input type="checkbox" value="_trials" onchange="filterLib()"> Trials/Demos</label>'
        '<label><input type="checkbox" value="_indie" onchange="filterLib()"> Indie</label>'
        '<label><input type="checkbox" value="_invalid" onchange="filterLib()"> Invalid</label>'
        '<div class="cb-clear" onclick="cbToggleAll(this)">Clear All</div>'
        '</div></div>\n'
        '<select id="lib-gp" onchange="filterLib()">'
        '<option value="owned">Owned</option>'
        '<option value="gamepass">Game Pass</option>'
        '<option value="all">All</option>'
        '</select>\n'
        '<div class="cb-drop" id="lib-cat"><div class="cb-btn" onclick="toggleCB(this)">Category &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-plat"><div class="cb-btn" onclick="toggleCB(this)">Platform &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-pub"><div class="cb-btn" onclick="toggleCB(this)">Publisher &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-dev"><div class="cb-btn" onclick="toggleCB(this)">Developer &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-ryear"><div class="cb-btn" onclick="toggleCB(this)">Release Year &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-ayear"><div class="cb-btn" onclick="toggleCB(this)">Purchased Year &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-sku"><div class="cb-btn" onclick="toggleCB(this)">SKU &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="lib-delist"><div class="cb-btn" onclick="toggleCB(this)">Listing Status &#9662;</div>'
        '<div class="cb-panel">'
        '<label><input type="checkbox" value="Listed" checked onchange="filterLib()"> Listed</label>'
        '<label><input type="checkbox" value="Delisted" checked onchange="filterLib()"> Delisted</label>'
        '<label><input type="checkbox" value="Hard Delisted" checked onchange="filterLib()"> Hard Delisted</label>'
        '</div></div>\n'
        '<select id="lib-sort" onchange="libSortCol=null;filterLib()"><option value="name">Sort: Name</option>'
        '<option value="priceDesc">Sort: Price (High-Low)</option>'
        '<option value="priceAsc">Sort: Price (Low-High)</option>'
        '<option value="pubAsc">Sort: Publisher A-Z</option>'
        '<option value="pubDesc">Sort: Publisher Z-A</option>'
        '<option value="relDesc" selected>Sort: Release (Newest)</option>'
        '<option value="relAsc">Sort: Release (Oldest)</option>'
        '<option value="acqDesc">Sort: Purchased (Newest)</option>'
        '<option value="acqAsc">Sort: Purchased (Oldest)</option>'
        '<option value="playDesc">Sort: Last Played (Recent)</option>'
        '<option value="playAsc">Sort: Last Played (Oldest)</option>'
        '<option value="platAsc">Sort: Platform A-Z</option></select>\n'
        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'lib\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'lib\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="lib-grid" id="lib-grid" style="display:none"></div>\n'
        '<div class="list-view" id="lib-list"></div>\n'
        '</div>\n'

        # -- Play History section --
        '<div class="section" id="playhistory">\n'
        '<h2>Play History</h2>\n'
        '<p class="sub" id="ph-sub">Games from TitleHub not in your Collections (disc, trials, rentals, etc.)</p>\n'
        '<div class="search-row"><input type="text" id="ph-search" placeholder="Search play history..." oninput="filterPH()"></div>\n'
        '<div class="filters">\n'
        '<div class="cb-drop" id="ph-gamertag" style="display:none"><div class="cb-btn" onclick="toggleCB(this)">Account &#9662;</div><div class="cb-panel"></div></div>\n'
        '<select id="ph-sort" onchange="filterPH()"><option value="playDesc" selected>Sort: Last Played (Recent)</option>'
        '<option value="playAsc">Sort: Last Played (Oldest)</option>'
        '<option value="name">Sort: Name</option></select>\n'
        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'ph\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'ph\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="cbar" id="ph-cbar"></div>\n'
        '<div class="lib-grid" id="ph-grid" style="display:none"></div>\n'
        '<div class="list-view" id="ph-list"></div>\n'
        '</div>\n'

        # -- Marketplace section --
        '<div class="section" id="marketplace">\n'
        '<h2>Marketplace</h2>\n'
        '<p class="sub" id="mkt-sub"></p>\n'
        '<div class="cbar" id="mkt-cbar"></div>\n'
        '<div class="search-row"><input type="text" id="mkt-search" placeholder="Search marketplace..." oninput="mktPage=0;filterMKT()"></div>\n'
        '<div class="filters">\n'
        '<div class="cb-drop" id="mkt-channel"><div class="cb-btn" onclick="toggleCB(this)">Channel &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="mkt-type"><div class="cb-btn" onclick="toggleCB(this)">Type &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="mkt-plat"><div class="cb-btn" onclick="toggleCB(this)">Platform &#9662;</div><div class="cb-panel"></div></div>\n'
        '<div class="cb-drop" id="mkt-pub"><div class="cb-btn" onclick="toggleCB(this)">Publisher &#9662;</div><div class="cb-panel"></div></div>\n'
        '<select id="mkt-sort" onchange="mktPage=0;filterMKT()"><option value="name">Sort: Name</option>'
        '<option value="priceDesc">Sort: Price (High-Low)</option>'
        '<option value="priceAsc">Sort: Price (Low-High)</option>'
        '<option value="bestAsc">Sort: Best Region (Cheapest)</option>'
        '<option value="bestDesc">Sort: Best Region (Priciest)</option>'
        '<option value="relDesc" selected>Sort: Release (Newest)</option>'
        '<option value="relAsc">Sort: Release (Oldest)</option></select>\n'


        '<div class="view-toggle"><button class="view-btn" onclick="setView(\'mkt\',\'grid\',this)" title="Grid">&#9638;</button>'
        '<button class="view-btn active" onclick="setView(\'mkt\',\'list\',this)" title="List">&#9776;</button></div>\n'
        '</div>\n'
        '<div class="grid" id="mkt-grid" style="display:none"></div>\n'
        '<div class="list-view gp-list" id="mkt-list"></div>\n'
        '<div class="pagination" id="mkt-pager" style="display:flex;justify-content:center;align-items:center;gap:8px;padding:16px 0;flex-wrap:wrap"></div>\n'
        '</div>\n'

        # -- Scan Log section --
        '<div class="section" id="history">\n'
        '<h2>Scan Log</h2>\n'
        '<p class="sub" id="hist-sub"></p>\n'
        '<div id="hist-cards"></div>\n'
        '</div>\n'

        # -- Gamertags section --
        '<div class="section" id="gamertags">\n'
        '<h2>Gamertags</h2>\n'
        '<p class="sub" id="acct-sub"></p>\n'
        '<div id="acct-table"></div>\n'
        '</div>\n'

        # -- Context menu + Modal --
        '<div id="ctx-menu"></div>\n'
        '<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">\n'
        '<div class="modal"><button class="modal-close" onclick="closeModal()">&times;</button>\n'
        '<img class="modal-hero" id="modal-hero" src="" alt="">\n'
        '<div class="modal-body" id="modal-body"></div></div></div>\n'

        # -- Load data from data.js, then app logic --
        '<script src="data.js"></script>\n'
        '<script>\n'
        "let gpF='all',mktPage=0;\n"
        "const MKT_PAGE_SIZE=1000;\n"
        "let views={gp:'list',lib:'list',ph:'list',mkt:'list'};\n"
        "const LS_KEY='" + ls_key + "';\n"
        "let libSortCol=null,libSortDir='asc';\n"
        "const _CUR={USD:[1,'$'],EUR:[0.92,'€'],GBP:[0.79,'£'],CAD:[1.36,'CA$'],AUD:[1.55,'A$'],"
        "NZD:[1.68,'NZ$'],JPY:[150,'¥'],BRL:[5.0,'R$'],MXN:[17.2,'MX$'],INR:[83.5,'₹'],"
        "KRW:[1320,'₩'],TRY:[32,'₺'],PLN:[4.0,'zł'],CHF:[0.88,'CHF '],SEK:[10.5,'kr '],"
        "NOK:[10.6,'kr '],DKK:[6.9,'kr '],CZK:[23.5,'Kč '],HUF:[365,'Ft '],ILS:[3.7,'₪'],"
        "SAR:[3.75,'SAR '],AED:[3.67,'AED '],ZAR:[18.5,'R'],SGD:[1.35,'S$'],HKD:[7.82,'HK$'],"
        "TWD:[32,'NT$'],CLP:[930,'CL$'],COP:[4000,'CO$'],ARS:[900,'AR$'],PHP:[56,'₱']};\n"
        "let _cc='USD';\n"
        "function _p(usd){if(!usd||usd<=0)return'';"
        "const[r,s]=_CUR[_cc]||_CUR.USD;const v=usd*r;"
        "const d=_cc==='JPY'||_cc==='KRW'||_cc==='CLP'||_cc==='COP'||_cc==='HUF'?0:2;"
        "return s+v.toLocaleString('en',{minimumFractionDigits:d,maximumFractionDigits:d})}\n"
        "function _pv(usd){return usd*((_CUR[_cc]||_CUR.USD)[0])}\n"
        "function _onCur(){_cc=document.getElementById('lib-cur').value;filterLib();filterGP();filterMKT();renderAccounts()}\n"
        "const _kinds=['Game','Durable'];\n"
        "const _kindN=['Games','DLC'];\n"
        "function _rowData(items){"
        "return _kinds.map(k=>{const a=items.filter(x=>x.productKind===k);"
        "let v=0;a.forEach(x=>{v+=(x.priceUSD||0)});return{cnt:a.length,val:v}})}\n"
        "function _buildSummaryTable(base,filtered){"
        "const _ownedRaw=base.filter(x=>x.owned);const _oSeen={};const ownedDD=_ownedRaw.filter(x=>{if(_oSeen[x.productId])return false;_oSeen[x.productId]=1;return true});"
        "const ownedGTs=new Set(_ownedRaw.map(x=>x.gamertag||'')).size||(_ownedRaw.length?1:0);"
        "const fGTs=new Set(filtered.map(x=>x.gamertag||'')).size||(filtered.length?1:0);"
        "const _gpRaw=base.filter(x=>x.onGamePass&&!x.owned);const _gpSeen={};const gpDD=_gpRaw.filter(x=>{if(_gpSeen[x.productId])return false;_gpSeen[x.productId]=1;return true});"
        "const libD=_rowData(ownedDD),filD=_rowData(filtered),gpD=_rowData(gpDD);"
        "let h='<table class=\"stbl\"><thead><tr><th></th>"
        "<th class=\"stbl-div\">#</th>"
        "<th class=\"stbl-div\">Games #</th><th>Games Value</th>"
        "<th class=\"stbl-div\">DLC #</th><th>DLC Value</th>"
        "<th class=\"stbl-div\">Total</th>"
        "<th class=\"stbl-div\">Gamertags</th></tr></thead><tbody>';\n"
        "function row(cls,lbl,d,gts){"
        "const tc=d.reduce((s,x)=>s+x.cnt,0);"
        "const tv=d.reduce((s,x)=>s+x.val,0);"
        "h+=`<tr${cls?' class=\"'+cls+'\"':''}><td>${lbl}</td>`;"
        "h+=`<td class=\"stbl-div\"><span class=\"cnt\">${tc.toLocaleString()}</span></td>`;"
        "d.forEach(x=>{"
        "h+=`<td class=\"stbl-div\"><span class=\"cnt\">${x.cnt?x.cnt.toLocaleString():'-'}</span></td>`;"
        "h+=`<td><span class=\"usd\">${_p(x.val)||'-'}</span></td>`});"
        "h+=`<td class=\"stbl-div\"><span class=\"usd\">${_p(tv)||'-'}</span></td>`;"
        "h+=`<td class=\"stbl-div\">${gts||''}</td></tr>`}\n"
        "row('','Library',libD,ownedGTs>1?ownedGTs:'');"
        "if(gpDD.length){row('stbl-gp','Game Pass',gpD,'')}"
        "row('','Current Filter',filD,fGTs);"
        "h+='</tbody></table>';return h}\n"
        '\n'

        # -- Column sort handler --
        "function sortByCol(col){if(libSortCol===col){libSortDir=libSortDir==='asc'?'desc':'asc'}else{libSortCol=col;libSortDir='asc'}"
        "filterLib()}\n"
        '\n'

        # -- Checkbox dropdown helpers --
        "function toggleCB(btn){const panel=btn.nextElementSibling;"
        "document.querySelectorAll('.cb-panel.open').forEach(p=>{if(p!==panel)p.classList.remove('open')});"
        "panel.classList.toggle('open')}\n"
        "function cbToggleAll(clr){const panel=clr.closest('.cb-panel');"
        "const boxes=panel.querySelectorAll('input[type=checkbox]');"
        "const anyChecked=[...boxes].some(c=>c.checked);"
        "boxes.forEach(c=>c.checked=!anyChecked);"
        "clr.textContent=anyChecked?'Select All':'Clear All';filterLib()}\n"
        "function clearAllFilters(){"
        "document.querySelectorAll('#library .cb-panel input[type=checkbox]').forEach(c=>c.checked=true);"
        "document.querySelectorAll('#library .cb-clear').forEach(c=>c.textContent='Clear All');"
        "document.getElementById('lib-gp').value='owned';"
        "filterLib()}\n"
        "document.addEventListener('click',function(e){"
        "if(!e.target.closest('.cb-drop'))document.querySelectorAll('.cb-panel.open').forEach(p=>p.classList.remove('open'))});\n"
        "function getCBVals(id){const el=document.getElementById(id);"
        "if(!el||el.style.display==='none')return null;"
        "const checked=[...el.querySelectorAll('input[type=checkbox]:checked')].map(c=>c.value);"
        "const total=el.querySelectorAll('input[type=checkbox]').length;"
        "const btn=el.querySelector('.cb-btn');"
        "const base=btn.dataset.label||btn.textContent.replace(/\\s*[\\u25BE\\u2713].*/,'');"
        "if(!btn.dataset.label)btn.dataset.label=base;"
        "if(checked.length===0||checked.length===total){"
        "btn.textContent=base+' \\u25BE';btn.classList.remove('has-sel')}"
        "else{btn.textContent=base+' ('+checked.length+') \\u25BE';btn.classList.add('has-sel')}"
        "return checked.length===total?null:checked}\n"
        '\n'

        # -- initDropdowns: populate checkbox panels from data --
        'function initDropdowns(){\n'
        "function fill(id,items,filterFn){const wrap=document.getElementById(id);if(!wrap)return;"
        "const panel=wrap.querySelector('.cb-panel');if(!panel)return;"
        "items.forEach(([v,l])=>{const lbl=document.createElement('label');"
        "lbl.innerHTML='<input type=\"checkbox\" value=\"'+v+'\" checked onchange=\"'+filterFn+'()\"> '+l;"
        "panel.appendChild(lbl)});"
        "const n=items.length;const cols=n>24?3:n>12?2:1;"
        "if(cols>1){panel.classList.add('cb-cols');panel.style.columnCount=cols;panel.style.minWidth=(cols*180)+'px'}"
        "const clr=document.createElement('div');clr.className='cb-clear';"
        "clr.textContent='Clear All';clr.onclick=function(){const boxes=panel.querySelectorAll('input');"
        "const anyChecked=[...boxes].some(c=>c.checked);boxes.forEach(c=>c.checked=!anyChecked);"
        "clr.textContent=anyChecked?'Select All':'Clear All';window[filterFn]();};"
        "panel.querySelectorAll('input').forEach(c=>c.addEventListener('change',()=>{"
        "const anyOn=[...panel.querySelectorAll('input')].some(x=>x.checked);"
        "clr.textContent=anyOn?'Clear All':'Select All';}));"
        "panel.appendChild(clr);}\n"
        # Publishers
        "const pubs={};LIB.forEach(x=>{const p=x.publisher||'';if(p)pubs[p]=(pubs[p]||0)+1});\n"
        "fill('lib-pub',Object.entries(pubs).sort((a,b)=>b[1]-a[1]).map(([p,c])=>[p,p+' ('+c+')']),\'filterLib\');\n"
        # Developers
        "const devs={};LIB.forEach(x=>{const d=x.developer||'';if(d)devs[d]=(devs[d]||0)+1});\n"
        "fill('lib-dev',Object.entries(devs).sort((a,b)=>b[1]-a[1]).map(([d,c])=>[d,d+' ('+c+')']),\'filterLib\');\n"
        # SKUs
        "const skus={};LIB.forEach(x=>{const s=x.skuId||'';if(s)skus[s]=(skus[s]||0)+1});\n"
        "fill('lib-sku',Object.entries(skus).sort((a,b)=>b[1]-a[1]).map(([s,c])=>[s,s+' ('+c+')']),\'filterLib\');\n"
        # Categories
        "const cats={};LIB.forEach(x=>{const c=x.category||'';if(c)cats[c]=(cats[c]||0)+1});\n"
        "fill('lib-cat',Object.entries(cats).sort((a,b)=>b[1]-a[1]).map(([c,n])=>[c,c+' ('+n+')']),\'filterLib\');\n"
        # Platforms
        "const plats={};LIB.forEach(x=>(x.platforms||[]).forEach(p=>{plats[p]=(plats[p]||0)+1}));\n"
        "fill('lib-plat',Object.entries(plats).sort((a,b)=>b[1]-a[1]).map(([p,c])=>[p,p+' ('+c+')']),\'filterLib\');\n"
        # Release years
        "const rys=new Set();LIB.forEach(x=>{const y=(x.releaseDate||'').slice(0,4);if(/^\\d{4}$/.test(y)&&y<'2800')rys.add(y)});\n"
        "fill('lib-ryear',[...rys].sort().reverse().map(y=>[y,y]),\'filterLib\');\n"
        # Acquired years
        "const ays=new Set();LIB.forEach(x=>{const y=(x.acquiredDate||'').slice(0,4);if(/^\\d{4}$/.test(y))ays.add(y)});\n"
        "fill('lib-ayear',[...ays].sort().reverse().map(y=>[y,y]),\'filterLib\');\n"
        # Gamertags (sorted by USD value desc, showing value)
        "const gts={};const gtVal={};LIB.forEach(x=>{const g=x.gamertag||'';if(g){gts[g]=(gts[g]||0)+1;gtVal[g]=(gtVal[g]||0)+(x.priceUSD||0)}});\n"
        "const gtKeys=Object.keys(gts);\n"
        "if(gtKeys.length>1){const el=document.getElementById('lib-gamertag');"
        "el.style.display='';const panel=el.querySelector('.cb-panel');"
        "gtKeys.sort((a,b)=>(gtVal[b]||0)-(gtVal[a]||0)).forEach(g=>{const lbl=document.createElement('label');"
        "const v=gtVal[g]||0;const vs=v>0?'$'+v.toLocaleString('en',{minimumFractionDigits:2,maximumFractionDigits:2}):'';"
        "lbl.innerHTML='<input type=\"checkbox\" value=\"'+g+'\" checked onchange=\"filterLib()\"> '+g+' ('+gts[g]+')'"
        "+(vs?' <span style=\"color:#42a5f5;font-size:10px\">'+vs+'</span>':'');"
        "panel.appendChild(lbl)});"
        "const cols=gtKeys.length>24?3:gtKeys.length>12?2:1;"
        "if(cols>1){panel.classList.add('cb-cols');panel.style.columnCount=cols;panel.style.minWidth=(cols*220)+'px'}"
        "const clr=document.createElement('div');clr.className='cb-clear';clr.textContent='Clear All';"
        "clr.onclick=function(){const boxes=panel.querySelectorAll('input');"
        "const anyChecked=[...boxes].some(c=>c.checked);boxes.forEach(c=>c.checked=!anyChecked);"
        "clr.textContent=anyChecked?'Select All':'Clear All';filterLib();};"
        "panel.querySelectorAll('input').forEach(c=>c.addEventListener('change',()=>{"
        "const anyOn=[...panel.querySelectorAll('input')].some(x=>x.checked);"
        "clr.textContent=anyOn?'Clear All':'Select All';}));"
        "panel.appendChild(clr);}\n"
        # PH gamertags
        "const phGts={};PH.forEach(x=>{const g=x.gamertag||'';if(g)phGts[g]=(phGts[g]||0)+1});\n"
        "const phGtKeys=Object.keys(phGts);\n"
        "if(phGtKeys.length>1){const el=document.getElementById('ph-gamertag');"
        "el.style.display='';const panel=el.querySelector('.cb-panel');"
        "phGtKeys.sort().forEach(g=>{const lbl=document.createElement('label');"
        "lbl.innerHTML='<input type=\"checkbox\" value=\"'+g+'\" checked onchange=\"filterPH()\"> '+g+' ('+phGts[g]+')';"
        "panel.appendChild(lbl)});"
        "const phCols=phGtKeys.length>24?3:phGtKeys.length>12?2:1;"
        "if(phCols>1){panel.classList.add('cb-cols');panel.style.columnCount=phCols;panel.style.minWidth=(phCols*180)+'px'}"
        "const clr=document.createElement('div');clr.className='cb-clear';clr.textContent='Clear All';"
        "clr.onclick=function(){const boxes=panel.querySelectorAll('input');"
        "const anyChecked=[...boxes].some(c=>c.checked);boxes.forEach(c=>c.checked=!anyChecked);"
        "clr.textContent=anyChecked?'Select All':'Clear All';filterPH();};"
        "panel.querySelectorAll('input').forEach(c=>c.addEventListener('change',()=>{"
        "const anyOn=[...panel.querySelectorAll('input')].some(x=>x.checked);"
        "clr.textContent=anyOn?'Clear All':'Select All';}));"
        "panel.appendChild(clr);}\n"
        # Tag pre-orders (release date after today, excluding bogus dates >= 2100)
        "const _today=new Date().toISOString().slice(0,10);"
        "LIB.forEach(x=>{const rd=x.releaseDate||'';x.isPreOrder=rd>_today&&rd.slice(0,4)<'2100'});\n"
        # Tab counts
        "document.getElementById('tab-lib-cnt').textContent=LIB.length;\n"
        "if(PH.length){document.getElementById('tab-ph').style.display='';document.getElementById('tab-ph-cnt').textContent=PH.length}\n"
        "if(GP.length){document.getElementById('tab-gp').style.display='';document.getElementById('tab-gp-cnt').textContent=GP.length}\n"
        "if(HISTORY.length){document.getElementById('tab-hist').style.display='';document.getElementById('tab-hist-cnt').textContent=HISTORY.length+' scans'}\n"
        # Marketplace dropdowns
        "if(typeof MKT!=='undefined'&&MKT.length){\n"
        "const _ownedPids=new Set(LIB.map(x=>x.productId));MKT.forEach(x=>{x.owned=_ownedPids.has(x.productId)});\n"
        "const _gpPids=new Set(GP.map(x=>x.productId));MKT.forEach(x=>{x.onGP=_gpPids.has(x.productId)});\n"
        "const _demoPids=new Set(MKT.filter(x=>(x.channels||[]).includes('Game Demos')).map(x=>x.productId));"
        "LIB.forEach(x=>{if(!x.isDemo&&_demoPids.has(x.productId))x.isDemo=true});\n"
        "MKT.forEach(x=>{const rd=x.releaseDate||'';x.isPreOrder=rd>_today&&rd.slice(0,4)<'2100'});\n"
        "document.getElementById('tab-mkt').style.display='';document.getElementById('tab-mkt-cnt').textContent=MKT.length;\n"
        # Channels
        "const mChs={};MKT.forEach(x=>(x.channels||[]).forEach(c=>{mChs[c]=(mChs[c]||0)+1}));\n"
        "fill('mkt-channel',Object.entries(mChs).sort((a,b)=>b[1]-a[1]).map(([c,n])=>[c,c+' ('+n+')']),\'filterMKT\');\n"
        "document.querySelectorAll('#mkt-channel .cb-panel input').forEach(c=>{c.checked=c.value==='New Games'});\n"
        # Types
        "const mTypes={};MKT.forEach(x=>{let t=x.productKind||'';if(t==='Durable')t='DLC';if(t)mTypes[t]=(mTypes[t]||0)+1});\n"
        "fill('mkt-type',Object.entries(mTypes).sort((a,b)=>b[1]-a[1]).map(([t,n])=>[t,t+' ('+n+')']),\'filterMKT\');\n"
        "document.querySelectorAll('#mkt-type .cb-panel input').forEach(c=>{c.checked=c.value==='Game'});\n"
        # Platforms
        "const mPlats={};MKT.forEach(x=>(x.platforms||[]).forEach(p=>{mPlats[p]=(mPlats[p]||0)+1}));\n"
        "fill('mkt-plat',Object.entries(mPlats).sort((a,b)=>b[1]-a[1]).map(([p,n])=>[p,p+' ('+n+')']),\'filterMKT\');\n"
        # Publishers
        "const mPubs={};MKT.forEach(x=>{const p=x.publisher||'';if(p)mPubs[p]=(mPubs[p]||0)+1});\n"
        "fill('mkt-pub',Object.entries(mPubs).sort((a,b)=>b[1]-a[1]).map(([p,n])=>[p,p+' ('+n+')']),\'filterMKT\');\n"
        "document.getElementById('mkt-sub').textContent=MKT.length+' products from Xbox Marketplace';\n"
        "}\n"
        "if(typeof ACCOUNTS!=='undefined'&&ACCOUNTS.length>0){"
        "document.getElementById('tab-acct').style.display='';document.getElementById('tab-acct-cnt').textContent=ACCOUNTS.length;"
        "renderAccounts()}\n"
        '}\n\n'

        "function switchTab(id,el){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));"
        "document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));"
        "document.getElementById(id).classList.add('active');el.classList.add('active')}\n"

        "function setGPFilter(f,el){gpF=f;document.querySelectorAll('#gamepass .pill').forEach(p=>p.classList.remove('active'));"
        "el.classList.add('active');filterGP()}\n"


        ""
        "function mktGoPage(p){mktPage=p;filterMKT();document.getElementById('marketplace').scrollIntoView({behavior:'smooth'})}\n"

        "function setView(tab,mode,el){views[tab]=mode;el.parentElement.querySelectorAll('.view-btn').forEach(b=>b.classList.remove('active'));"
        "el.classList.add('active');"
        "if(tab==='gp'){document.getElementById('gp-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('gp-list').style.display=mode==='list'?'flex':'none';filterGP()}"
        "else if(tab==='ph'){document.getElementById('ph-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('ph-list').style.display=mode==='list'?'flex':'none';filterPH()}"
        "else if(tab==='mkt'){document.getElementById('mkt-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('mkt-list').style.display=mode==='list'?'flex':'none';filterMKT()}"
        "else{document.getElementById('lib-grid').style.display=mode==='grid'?'grid':'none';"
        "document.getElementById('lib-list').style.display=mode==='list'?'flex':'none';filterLib()}}\n"
        '\n'

        "const _stored=JSON.parse(localStorage.getItem(LS_KEY)||'{}');\n"
        "let manualFlags=Object.assign({},typeof DEFAULT_FLAGS!=='undefined'?DEFAULT_FLAGS:{},_stored);\n"
        "function flagItem(pid,flag){if(flag){manualFlags[pid]=flag}else{delete manualFlags[pid]}"
        "localStorage.setItem(LS_KEY,JSON.stringify(manualFlags));filterLib()}\n"

        "function showFlagMenu(e,pid,title){e.preventDefault();e.stopPropagation();"
        "const f=manualFlags[pid]||'';"
        "const m=document.getElementById('ctx-menu');"
        "let opts=`<div style=\"padding:6px 10px;color:#888;font-size:11px;border-bottom:1px solid #333;"
        "max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">${title}</div>`;"
        "opts+=f==='beta'?`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}',null)\">Remove Beta/Demo flag</div>`"
        ":`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}','beta')\">Flag as Beta/Demo</div>`;"
        "opts+=f==='delisted'?`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}',null)\">Remove Delisted tag</div>`"
        ":`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}','delisted')\">Tag as Delisted</div>`;"
        "opts+=f==='hardDelisted'?`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}',null)\">Remove Hard Delisted tag</div>`"
        ":`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}','hardDelisted')\">Tag as Hard Delisted</div>`;"
        "opts+=f==='indie'?`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}',null)\">Remove Indie Game tag</div>`"
        ":`<div class=\"ctx-opt\" onclick=\"flagItem('${pid}','indie')\">Tag as Indie Game (No achievements)</div>`;"
        "m.innerHTML=opts;"
        "m.style.left=e.clientX+'px';m.style.top=e.clientY+'px';m.style.display='block';"
        "setTimeout(()=>document.addEventListener('click',()=>{m.style.display='none'},{once:true}),10)}\n"
        '\n'

        # -- filterGP --
        'function filterGP(){\n'
        "const el=document.getElementById('gp-search');if(!el||!GP.length)return;\n"
        "const q=el.value.toLowerCase();\n"
        "const g=document.getElementById('gp-grid');const l=document.getElementById('gp-list');\n"
        "g.innerHTML='';let c=0;"
        "let gh='',lh='<div class=\"lv-head\"><div></div><div>Title</div><div>Publisher</div>"
        "<div>Release</div><div style=\"text-align:right\">USD</div>"
        "<div style=\"text-align:center\">Status</div></div>';\n"
        'GP.forEach((item,i)=>{\n'
        "const t=(item.title||'').toLowerCase(),p=(item.publisher||'').toLowerCase();\n"
        "if(q&&!t.includes(q)&&!p.includes(q)&&!(item.productId||'').toLowerCase().includes(q))return;\n"
        "if(gpF==='notOwned'&&item.owned)return;\n"
        "if(gpF==='owned'&&!item.owned)return;\n"
        "if(gpF==='recent'&&!(item.collections||[]).includes('Recently Added'))return;\n"
        "if(gpF==='popular'&&!(item.collections||[]).includes('Most Popular'))return;\n"
        'c++;if(c>500)return;\n'
        "const owned=item.owned?'<span class=\"badge owned\">OWNED</span>':'<span class=\"badge new\">NOT OWNED</span>';\n"
        "const colls=(item.collections||[]).map(c=>'<span class=\"badge gp\">'+c+'</span>').join('');\n"
        "const img=item.heroImage||item.boxArt||'';\n"
        "const imgTag=img?`<img class=\"card-img\" src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:"
        "'<div class=\"card-img\" style=\"display:flex;align-items:center;justify-content:center;color:#333;font-size:36px\">'+(item.title||'?')[0]+'</div>';\n"
        "const usdP=_p(item.priceUSD);\n"
        "const priceTag=usdP?"
        "`<span style=\"color:#42a5f5;font-weight:600\">${usdP}</span>`:"
        "'<span style=\"color:#555;font-size:11px\">Free / Included</span>';\n"
        'gh+=`<div class="card" onclick="showGPDetail(${i})">${imgTag}<div class="card-body">'
        '<div class="card-name" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="card-meta">${item.publisher||\'\'} | ${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div style="margin:4px 0">${priceTag}</div>'
        '<div class="card-desc">${item.description||\'\'}</div>'
        '<div class="card-badges">${owned}${colls}</div></div></div>`;\n'
        "const thumbImg=img?`<img src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'';\n"
        "const ownedBadge=item.owned?'<span class=\"badge owned\" style=\"font-size:9px\">OWNED</span>'"
        ":'<span class=\"badge new\" style=\"font-size:9px\">NEW</span>';\n"
        'lh+=`<div class="lv-row" onclick="showGPDetail(${i})">${thumbImg}'
        '<div class="lv-title" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-type">${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div class="lv-usd">${usdP}</div>'
        '<div class="lv-status">${ownedBadge}</div></div>`;\n'
        '});\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "document.getElementById('gp-cbar').innerHTML=`<span>${c}</span> of ${GP.length} shown`}\n"
        '\n'

        # -- showGPDetail --
        'function showGPDetail(i){\n'
        'const item=GP[i];\n'
        "const img=item.heroImage||item.boxArt||'';\n"
        "document.getElementById('modal-hero').src=img;\n"
        "document.getElementById('modal-hero').style.display=img?'block':'none';\n"
        "const owned=item.owned?'<span class=\"badge owned\">IN YOUR LIBRARY</span>'"
        ":'<span class=\"badge new\">NOT OWNED</span>';\n"
        "const colls=(item.collections||[]).map(c=>'<span class=\"badge gp\">'+c+'</span>').join(' ');\n"
        "document.getElementById('modal-body').innerHTML=`\n"
        '<div class="modal-title">${item.title||\'Unknown\'}</div>\n'
        '<div class="modal-pub">${item.publisher||\'\'} ${item.developer&&item.developer!==item.publisher?\'/  \'+item.developer:\'\'}</div>\n'
        '<div style="margin-bottom:10px">${owned} ${colls}</div>\n'
        '<div class="modal-desc">${item.description||\'No description.\'}</div>\n'
        '<div class="modal-info">\n'
        '<div><span class="lbl">Product ID:</span></div><div class="val">${item.productId}</div>\n'
        '<div><span class="lbl">Release:</span></div><div class="val">${(item.releaseDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Type:</span></div><div class="val">${item.productType||\'\'}</div>\n'
        "${item.priceUSD>0?'<div><span class=\"lbl\">Price:</span></div><div class=\"val\" style=\"color:#42a5f5;font-weight:600\">'+_p(item.priceUSD)+'</div>':''}\n"
        '<div><span class="lbl">Store:</span></div><div class="val"><a href="https://www.xbox.com/en-GB/games/store/p/${item.productId}" target="_blank">${item.productId}</a></div>\n'
        "</div>`;\n"
        "document.getElementById('modal').classList.add('active')}\n"
        '\n'

        # -- showLibDetail --
        'function showLibDetail(pid){\n'
        "const item=LIB.find(x=>x.productId===pid);if(!item)return;\n"
        "const img=item.heroImage||item.boxArt||'';\n"
        "document.getElementById('modal-hero').src=img;\n"
        "document.getElementById('modal-hero').style.display=img?'block':'none';\n"
        "const flagged=manualFlags[item.productId]||'';\n"
        # Badges
        "let badges='';\n"
        "const sc=item.status==='Active'?'s-active':item.status==='Expired'?'s-expired':'s-revoked';\n"
        "badges+=`<span class=\"${sc}\" style=\"font-weight:600\">${item.status||''}</span> `;\n"
        "if(item.onGamePass)badges+='<span class=\"badge gp\">GAME PASS</span> ';\n"
        "if(item.isTrial)badges+='<span class=\"badge trial\">TRIAL</span> ';\n"
        "if(item.isDemo)badges+='<span class=\"badge demo\">DEMO</span> ';\n"
        "if(flagged==='beta')badges+='<span class=\"badge flagged\">BETA/DEMO</span> ';\n"
        "if(flagged==='delisted')badges+='<span class=\"badge\" style=\"background:#3a2a1a;color:#ff9800\">DELISTED</span> ';\n"
        "if(flagged==='hardDelisted')badges+='<span class=\"badge\" style=\"background:#3a1a1a;color:#f44336\">HARD DELISTED</span> ';\n"
        "if(flagged==='indie')badges+='<span class=\"badge\" style=\"background:#1a2a3a;color:#64b5f6\">INDIE</span> ';\n"
        "if(item.catalogInvalid)badges+='<span class=\"badge\" style=\"background:#3a1a1a;color:#f44336\">INVALID</span> ';\n"
        "if(item.isPreOrder)badges+='<span class=\"badge\" style=\"background:#2a2a1a;color:#ffd54f\">PRE-ORDER</span> ';\n"
        "if(item.owned)badges+='<span class=\"badge owned\">OWNED</span> ';\n"
        # Platform badges
        "const platBadges=(item.platforms||[]).map(p=>{"
        "const cls=p.includes('Series')?'series':p.includes('360')?'x360':p==='PC'?'pc':p.includes('One')?'one':'mobile';"
        "return '<span class=\"badge '+cls+'\">'+p+'</span>'}).join(' ');\n"
        "document.getElementById('modal-body').innerHTML=`\n"
        '<div class="modal-title">${item.title||\'Unknown\'}</div>\n'
        '<div class="modal-pub">${item.publisher||\'\'} ${item.developer&&item.developer!==item.publisher?\' / \'+item.developer:\'\'}</div>\n'
        '<div style="margin-bottom:10px">${badges} ${platBadges}</div>\n'
        '<div class="modal-desc">${item.description||\'No description.\'}</div>\n'
        '<div class="modal-info">\n'
        '<div><span class="lbl">Product ID:</span></div><div class="val">${item.productId}</div>\n'
        "${item.xboxTitleId?'<div><span class=\"lbl\">Xbox Title ID:</span></div><div class=\"val\">'+item.xboxTitleId+'</div>':''}\n"
        '<div><span class="lbl">Type:</span></div><div class="val">${item.productKind||\'\'}</div>\n'
        '<div><span class="lbl">Category:</span></div><div class="val">${item.category||\'\'}</div>\n'
        "'<div><span class=\"lbl\">Gamertag:</span></div><div class=\"val\">'+[...new Set(LIB.filter(x=>x.productId===item.productId).map(x=>x.gamertag||''))].join(', ')+'</div>'\n"
        '<div><span class="lbl">Release Date:</span></div><div class="val">${(item.releaseDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Acquired:</span></div><div class="val">${(item.acquiredDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Last Played:</span></div><div class="val">${(item.lastTimePlayed||\'\').substring(0,10)||\'Never\'}</div>\n'
        "${item.priceUSD>0?'<div><span class=\"lbl\">Price:</span></div><div class=\"val\" style=\"color:#42a5f5;font-weight:600\">'+_p(item.priceUSD)+'</div>':''}\n"
        "${item.currentPriceUSD>0&&item.currentPriceUSD<item.priceUSD?'<div><span class=\"lbl\">Sale:</span></div><div class=\"val\" style=\"color:#4caf50;font-weight:600\">'+_p(item.currentPriceUSD)+'</div>':''}\n"
        '<div><span class="lbl">SKU:</span></div><div class="val">${item.skuId||\'\'} ${item.skuType?\'(\'+item.skuType+\')\':\'\'}</div>\n'
        '<div><span class="lbl">Country:</span></div><div class="val">${item.purchasedCountry||\'\'}</div>\n'
        '<div><span class="lbl">Quantity:</span></div><div class="val">${item.quantity||1}</div>\n'
        '<div><span class="lbl">Start Date:</span></div><div class="val">${(item.startDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">End Date:</span></div><div class="val">${(item.endDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Game Pass:</span></div><div class="val">${item.onGamePass?\'Yes\':\'No\'}</div>\n'
        '<div><span class="lbl">Store:</span></div><div class="val"><a href="https://www.xbox.com/en-GB/games/store/p/${item.productId}" target="_blank">${item.productId}</a></div>\n'
        "</div>`;\n"
        "document.getElementById('modal').classList.add('active')}\n"
        '\n'

        # -- updateDropdownCounts: update checkbox labels with counts from items --
        "function _updCounts(dropId,items,keyFn){"
        "const el=document.getElementById(dropId);if(!el)return;"
        "const counts={};items.forEach(x=>{const keys=keyFn(x);if(Array.isArray(keys))keys.forEach(k=>{if(k)counts[k]=(counts[k]||0)+1});"
        "else if(keys)counts[keys]=(counts[keys]||0)+1});"
        "el.querySelectorAll('label').forEach(lbl=>{"
        "const cb=lbl.querySelector('input');if(!cb)return;"
        "const v=cb.value;const c=counts[v]||0;"
        "const txt=lbl.childNodes[lbl.childNodes.length-1];"
        "if(txt.nodeType===3){const base=v;txt.textContent=' '+base+' ('+c+')'}})}\n"
        # -- _primaryFilter: apply gamertag/status/type filters --
        "function _primaryFilter(gtVals,sVals,tVals){"
        "return LIB.filter(item=>{"
        "if(gtVals&&!gtVals.includes(item.gamertag||''))return false;"
        "if(sVals&&!sVals.includes(item.status))return false;"
        "if(tVals){const realTypes=tVals.filter(v=>v[0]!=='_');"
        "const showPO=tVals.includes('_preorder'),showTD=tVals.includes('_trials'),showInv=tVals.includes('_invalid'),showInd=tVals.includes('_indie');"
        "const flagged0=manualFlags[item.productId];"
        "const isTD0=item.isTrial||item.isDemo||flagged0==='beta';"
        "const isInv0=item.catalogInvalid;"
        "const isInd0=flagged0==='indie';"
        "const isPO0=item.isPreOrder;"
        "if(isPO0&&!showPO)return false;"
        "if(isTD0&&!showTD)return false;"
        "if(isInv0&&!showInv)return false;"
        "if(isInd0&&!showInd)return false;"
        "if(!isPO0&&!isTD0&&!isInv0&&!isInd0&&realTypes.length&&!realTypes.includes(item.productKind))return false;}"
        "return true})}\n"
        # -- filterLib --
        'function filterLib(){\n'
        "const gtVals=getCBVals('lib-gamertag');\n"
        "const q=document.getElementById('lib-search').value.toLowerCase();\n"
        "const sVals=getCBVals('lib-status');\n"
        "const tVals=getCBVals('lib-type');\n"
        "const so=document.getElementById('lib-sort').value;\n"
        "const catVals=getCBVals('lib-cat');\n"
        "const platVals=getCBVals('lib-plat');\n"
        "const pubVals=getCBVals('lib-pub');\n"
        "const devVals=getCBVals('lib-dev');\n"
        "const ryVals=getCBVals('lib-ryear');\n"
        "const ayVals=getCBVals('lib-ayear');\n"
        "const skuVals=getCBVals('lib-sku');\n"
        "const dlVals=getCBVals('lib-delist');\n"
        "const gpF=document.getElementById('lib-gp').value;\n"
        "const g=document.getElementById('lib-grid');const l=document.getElementById('lib-list');\n"
        # Step 1: apply primary filters (gamertag/status/type)
        "const _pf=_primaryFilter(gtVals,sVals,tVals);\n"
        # Step 2: update secondary dropdown counts based on primary-filtered items
        "_updCounts('lib-cat',_pf,x=>x.category||'');\n"
        "_updCounts('lib-plat',_pf,x=>x.platforms||[]);\n"
        "_updCounts('lib-pub',_pf,x=>x.publisher||'');\n"
        "_updCounts('lib-dev',_pf,x=>x.developer||'');\n"
        "_updCounts('lib-ryear',_pf,x=>{const y=(x.releaseDate||'').slice(0,4);return /^\\d{4}$/.test(y)&&y<'2800'?y:''});\n"
        "_updCounts('lib-ayear',_pf,x=>{const y=(x.acquiredDate||'').slice(0,4);return /^\\d{4}$/.test(y)?y:''});\n"
        "_updCounts('lib-sku',_pf,x=>x.skuId||'');\n"
        "_updCounts('lib-delist',_pf,x=>{const f=manualFlags[x.productId];return f==='hardDelisted'?'Hard Delisted':f==='delisted'?'Delisted':'Listed'});\n"
        # Step 3: apply all filters for final result
        'let _libBase=_pf.filter(item=>{\n'
        "if(catVals&&!catVals.includes(item.category||''))return false;\n"
        "if(platVals&&!(item.platforms||[]).some(p=>platVals.includes(p)))return false;\n"
        "if(pubVals&&!pubVals.includes(item.publisher||''))return false;\n"
        "if(devVals&&!devVals.includes(item.developer||''))return false;\n"
        "if(ryVals&&!ryVals.some(y=>(item.releaseDate||'').startsWith(y)))return false;\n"
        "if(ayVals&&!ayVals.some(y=>(item.acquiredDate||'').startsWith(y)))return false;\n"
        "if(skuVals&&!skuVals.includes(item.skuId||''))return false;\n"
        'const flagged=manualFlags[item.productId];\n'
        "if(dlVals){const ls=flagged==='hardDelisted'?'Hard Delisted':flagged==='delisted'?'Delisted':'Listed';"
        "if(!dlVals.includes(ls))return false;}\n"
        "if(gpF==='owned'&&!item.owned)return false;\n"
        "if(gpF==='gamepass'&&!(item.onGamePass&&!item.owned))return false;\n"
        "if(gpF==='all'&&!(item.owned||item.onGamePass))return false;\n"
        'return true});\n'
        "let filtered=q?_libBase.filter(item=>"
        "(item.title||'').toLowerCase().includes(q)||(item.publisher||'').toLowerCase().includes(q)"
        "||(item.productId||'').toLowerCase().includes(q)):_libBase;\n"
        "if(so==='name')filtered.sort((a,b)=>(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='priceDesc')filtered.sort((a,b)=>((b.priceUSD||0)-(a.priceUSD||0))||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='priceAsc')filtered.sort((a,b)=>{const ap=a.priceUSD||0,bp=b.priceUSD||0;"
        "if(!ap&&bp)return 1;if(ap&&!bp)return -1;return(ap-bp)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='pubAsc')filtered.sort((a,b)=>(a.publisher||'').localeCompare(b.publisher||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='pubDesc')filtered.sort((a,b)=>(b.publisher||'').localeCompare(a.publisher||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='relDesc')filtered.sort((a,b)=>{const ar=(a.releaseDate||'').slice(0,4)>='2100'?'':a.releaseDate||'';"
        "const br=(b.releaseDate||'').slice(0,4)>='2100'?'':b.releaseDate||'';"
        "if(!ar&&br)return 1;if(ar&&!br)return -1;"
        "return br.localeCompare(ar)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='relAsc')filtered.sort((a,b)=>{const ar=(a.releaseDate||'').slice(0,4)>='2100'?'':a.releaseDate||'';"
        "const br=(b.releaseDate||'').slice(0,4)>='2100'?'':b.releaseDate||'';"
        "if(!ar&&br)return 1;if(ar&&!br)return -1;"
        "return ar.localeCompare(br)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='acqDesc')filtered.sort((a,b)=>(b.acquiredDate||'').localeCompare(a.acquiredDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='acqAsc')filtered.sort((a,b)=>(a.acquiredDate||'').localeCompare(b.acquiredDate||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='playDesc')filtered.sort((a,b)=>(b.lastTimePlayed||'').localeCompare(a.lastTimePlayed||'')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='playAsc')filtered.sort((a,b)=>{const ap=a.lastTimePlayed||'',bp=b.lastTimePlayed||'';"
        "if(!ap&&bp)return 1;if(ap&&!bp)return -1;return ap.localeCompare(bp)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='platAsc')filtered.sort((a,b)=>((a.platforms||[])[0]||'zzz').localeCompare((b.platforms||[])[0]||'zzz')"
        "||(a.title||'').localeCompare(b.title||''));\n"
        "if(libSortCol){const d=libSortDir==='asc'?1:-1;"
        "const g={title:(a,b)=>(a.title||'').localeCompare(b.title||'')*d,"
        "gamertag:(a,b)=>(a.gamertag||'').localeCompare(b.gamertag||'')*d||(a.title||'').localeCompare(b.title||''),"
        "publisher:(a,b)=>(a.publisher||'').localeCompare(b.publisher||'')*d||(a.title||'').localeCompare(b.title||''),"
        "developer:(a,b)=>(a.developer||'').localeCompare(b.developer||'')*d||(a.title||'').localeCompare(b.title||''),"
        "category:(a,b)=>(a.category||'').localeCompare(b.category||'')*d||(a.title||'').localeCompare(b.title||''),"
        "platform:(a,b)=>((a.platforms||[])[0]||'').localeCompare((b.platforms||[])[0]||'')*d||(a.title||'').localeCompare(b.title||''),"
        "released:(a,b)=>{const ar=(a.releaseDate||'').slice(0,4)>='2100'?'':a.releaseDate||'',br=(b.releaseDate||'').slice(0,4)>='2100'?'':b.releaseDate||'';"
        "if(!ar&&br)return 1;if(ar&&!br)return -1;return ar.localeCompare(br)*d||(a.title||'').localeCompare(b.title||'')},"
        "purchased:(a,b)=>(a.acquiredDate||'').localeCompare(b.acquiredDate||'')*d||(a.title||'').localeCompare(b.title||''),"
        "lastPlayed:(a,b)=>(a.lastTimePlayed||'').localeCompare(b.lastTimePlayed||'')*d||(a.title||'').localeCompare(b.title||''),"
        "usd:(a,b)=>((a.priceUSD||0)-(b.priceUSD||0))*d||(a.title||'').localeCompare(b.title||'')};"
        "if(g[libSortCol])filtered.sort(g[libSortCol])}\n"
        '\n'
        # Deduplicate by productId across gamertags
        "const _pidMap={};"
        "filtered.forEach(item=>{const pid=item.productId;"
        "if(!_pidMap[pid]){_pidMap[pid]={item:item,gts:[item.gamertag||'']};return}"
        "const g=item.gamertag||'';if(!_pidMap[pid].gts.includes(g))_pidMap[pid].gts.push(g)});"
        "const deduped=[];const _gtsByPid={};"
        "filtered.forEach(item=>{const e=_pidMap[item.productId];"
        "if(e.item===item){item._allGTs=e.gts;deduped.push(item)}});"
        "filtered=deduped;\n"
        "const shown=filtered.length;\n"
        "function colArrow(c){return libSortCol===c?(libSortDir==='asc'?' \\u25B2':' \\u25BC'):''}\n"
        "let gh='',lh='<div class=\"lv-head\"><div></div>"
        "<div data-sort onclick=\"sortByCol(\\'title\\')\">Title'+colArrow('title')+'</div>"
        "<div data-sort title=\"Xbox Live gamertag that owns this item\" onclick=\"sortByCol(\\'gamertag\\')\">Gamertag'+colArrow('gamertag')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'publisher\\')\">Publisher'+colArrow('publisher')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'developer\\')\">Developer'+colArrow('developer')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'category\\')\">Category'+colArrow('category')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'platform\\')\">Platform'+colArrow('platform')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'released\\')\">Released'+colArrow('released')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'purchased\\')\">Purchased'+colArrow('purchased')+'</div>"
        "<div data-sort onclick=\"sortByCol(\\'lastPlayed\\')\">Last Played'+colArrow('lastPlayed')+'</div>"
        "<div data-sort style=\"text-align:right\" onclick=\"sortByCol(\\'usd\\')\">USD'+colArrow('usd')+'</div>"
        "<div>CC</div>"
        "<div>SKU</div>"
        "<div style=\"text-align:center\">Status</div>"
        "</div>';\n"
        'for(let i=0;i<shown;i++){const item=filtered[i];\n'
        'const flagged=manualFlags[item.productId];\n'
        "const sc=item.status==='Active'?'s-active':item.status==='Expired'?'s-expired':'s-revoked';\n"
        "const img=item.image?`<img src=\"${item.image}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'<div></div>';\n"
        "const usd=_p(item.priceUSD);\n"
        "const pr=usd?`<div class=\"lp\"><span class=\"usd\">${usd}</span></div>`:'';\n"
        "const gpBadge=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';\n"
        "const poBadge=item.isPreOrder?'<span class=\"badge\" style=\"font-size:9px;margin-left:4px;background:#2a2a1a;color:#ffd54f\">PRE-ORDER</span>':'';\n"
        "const trBadge=item.isTrial?'<span class=\"badge trial\" style=\"font-size:9px;margin-left:4px\">TRIAL</span>'"
        ":item.isDemo?'<span class=\"badge demo\" style=\"font-size:9px;margin-left:4px\">DEMO</span>':'';\n"
        "const flBadge=flagged==='beta'?'<span class=\"badge flagged\" style=\"font-size:9px;margin-left:4px\">FLAGGED</span>'"
        ":flagged==='delisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:4px;background:#3a2a1a;color:#ff9800\">DELISTED</span>'"
        ":flagged==='hardDelisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:4px;background:#3a1a1a;color:#f44336\">HARD DELISTED</span>'"
        ":flagged==='indie'?'<span class=\"badge\" style=\"font-size:9px;margin-left:4px;background:#1a2a3a;color:#64b5f6\">INDIE</span>':'';\n"
        "const invBadge=item.catalogInvalid?'<span class=\"badge\" style=\"font-size:9px;margin-left:4px;background:#3a1a1a;color:#f44336\">INVALID</span>':'';\n"
        "const safeTitle=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');\n"
        "const allGTs=item._allGTs||[item.gamertag||''];\n"
        "const gtExtra=allGTs.length>1?`<span class=\"gt-plus\" onclick=\"event.stopPropagation();showGTList(this,['`+allGTs.map(g=>g.replace(/'/g,\"\\\\'\")).join(`','`)+`'])\" title=\"${allGTs.length} gamertags\">+${allGTs.length-1}</span>`:'';\n"
        'gh+=`<div class="lib-card" onclick="showLibDetail(\'${item.productId}\')" oncontextmenu="showFlagMenu(event,\'${item.productId}\',\'${safeTitle}\')">'
        '${img}<div class="info"><div class="ln" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">'
        '${item.title||item.productId}${poBadge}${gpBadge}${trBadge}${flBadge}${invBadge}</div>'
        '<div class="lm">${item.publisher||\'\'} | ${item.productKind||\'\'} | ${item.category||\'\'} | '
        '<span class="${sc}">${item.status||\'\'}</span>${gtExtra}</div>${pr}</div></div>`;\n'
        ""
        "const usdL=_p(item.priceUSD);\n"
        "const statusBadge=`<span class=\"${sc}\">${item.status||''}</span>`;\n"
        "const poTag=item.isPreOrder?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#2a2a1a;color:#ffd54f\">PRE-ORDER</span>':'';\n"
        "const gpTag=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';\n"
        "const trTag=item.isTrial?'<span class=\"badge trial\" style=\"font-size:9px;margin-left:3px\">TRIAL</span>'"
        ":item.isDemo?'<span class=\"badge demo\" style=\"font-size:9px;margin-left:3px\">DEMO</span>':'';\n"
        "const flTag=flagged==='beta'?'<span class=\"badge flagged\" style=\"font-size:9px;margin-left:3px\">FLAGGED</span>'"
        ":flagged==='delisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a2a1a;color:#ff9800\">DELISTED</span>'"
        ":flagged==='hardDelisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a1a1a;color:#f44336\">HARD DELISTED</span>'"
        ":flagged==='indie'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#1a2a3a;color:#64b5f6\">INDIE</span>':'';\n"
        "const invTag=item.catalogInvalid?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a1a1a;color:#f44336\">INVALID</span>':'';\n"
        "const safeTitle2=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');\n"
        "const relD=(item.releaseDate||'').substring(0,10);\n"
        "const acqD=(item.acquiredDate||'').substring(0,10);\n"
        "const lpD=(item.lastTimePlayed||'').substring(0,10);\n"
        "const platStr=(item.platforms||[]).join(', ')||'';\n"
        'lh+=`<div class="lv-row" onclick="showLibDetail(\'${item.productId}\')" oncontextmenu="showFlagMenu(event,\'${item.productId}\',\'${safeTitle2}\')">'
        '${img}<div class="lv-title" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">'
        '${item.title||item.productId}${poTag}${gpTag}${trTag}${flTag}${invTag}</div>'
        '<div class="lv-type" style="color:#aaa">${item.gamertag||\'\'}${gtExtra}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-pub">${item.developer||\'\'}</div>'
        '<div class="lv-type">${item.category||\'\'}</div>'
        '<div class="lv-type">${platStr}</div>'
        '<div class="lv-type">${relD}</div>'
        '<div class="lv-type">${acqD}</div>'
        '<div class="lv-type">${lpD}</div>'
        ''
        '<div class="lv-usd">${usdL}</div>'
        '<div class="lv-type" title="${item.purchasedCountry||\'\'}">${item.purchasedCountry||\'\'}</div>'
        '<div class="lv-type">${item.skuId||\'\'}</div>'
        '<div class="lv-status">${statusBadge}</div></div>`}\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "document.getElementById('lib-cbar').innerHTML=_buildSummaryTable(_pf,filtered)}\n"
        '\n'

        "function closeModal(){document.getElementById('modal').classList.remove('active')}\n"
        "document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});\n"
        "function showGTList(el,gts){document.querySelectorAll('.gt-popup').forEach(p=>p.remove());"
        "const pop=document.createElement('div');pop.className='gt-popup';"
        "gts.forEach(g=>{const d=document.createElement('div');d.textContent=g;pop.appendChild(d)});"
        "el.style.position='relative';el.appendChild(pop);"
        "const close=e=>{if(!el.contains(e.target)){pop.remove();document.removeEventListener('click',close)}};"
        "setTimeout(()=>document.addEventListener('click',close),0)}\n"
        '\n'

        # -- filterPH (Play History) --
        'function filterPH(){\n'
        "const phGtVals=getCBVals('ph-gamertag');\n"
        "const q=document.getElementById('ph-search').value.toLowerCase();\n"
        "const so=document.getElementById('ph-sort').value;\n"
        "const g=document.getElementById('ph-grid');const l=document.getElementById('ph-list');\n"
        'let filtered=PH.filter(item=>{\n'
        "if(phGtVals&&!phGtVals.includes(item.gamertag||''))return false;\n"
        "if(q&&!(item.title||'').toLowerCase().includes(q)&&!(item.publisher||'').toLowerCase().includes(q))return false;\n"
        'return true});\n'
        "if(so==='name')filtered.sort((a,b)=>(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='playDesc')filtered.sort((a,b)=>(b.lastTimePlayed||'').localeCompare(a.lastTimePlayed||''));\n"
        "else if(so==='playAsc')filtered.sort((a,b)=>{const ap=a.lastTimePlayed||'',bp=b.lastTimePlayed||'';"
        "if(!ap&&bp)return 1;if(ap&&!bp)return -1;return ap.localeCompare(bp)});\n"
        "const shown=Math.min(filtered.length,views.ph==='list'?2000:500);\n"
        "let gh='',lh='<div class=\"lv-head\">"
        "<div></div>"
        "<div>Title</div>"
        "<div>Publisher</div>"
        "<div>Category</div>"
        "<div>Platform</div>"
        "<div>Last Played</div>"
        "<div></div><div></div><div></div><div></div><div></div><div></div>"
        "</div>';\n"
        'for(let i=0;i<shown;i++){const item=filtered[i];\n'
        "const img=item.image?`<img src=\"${item.image}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'<div></div>';\n"
        "const lpD=(item.lastTimePlayed||'').substring(0,10);\n"
        "const platStr=(item.platforms||[]).join(', ')||'';\n"
        "const gpTag=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';\n"
        'gh+=`<div class="lib-card">${img}<div class="info"><div class="ln">${item.title||item.productId}${gpTag}</div>'
        '<div class="lm">${item.publisher||\'\'} | ${platStr}</div>'
        '${lpD?`<div class="lm">Played: ${lpD}</div>`:\'\'}</div></div>`;\n'
        'lh+=`<div class="lv-row">${img}'
        '<div class="lv-title" title="${(item.title||\'\').replace(/\"/g,\'&quot;\')}">${item.title||item.productId}${gpTag}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-type">${item.category||\'\'}</div>'
        '<div class="lv-type">${platStr}</div>'
        '<div class="lv-type">${lpD}</div>'
        '<div></div><div></div><div></div><div></div><div></div><div></div></div>`}\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "document.getElementById('ph-cbar').innerHTML=`<span>${filtered.length}</span>"
        "${filtered.length>shown?' (showing '+shown+')':''} play history items`}\n"
        '\n'

        # -- Regional pricing helpers --
        "const _RORD=['AR','BR','TR','IS','NG','TW','NZ','CO','HK','US'];\n"
        "const _RNAME={AR:'Argentina',BR:'Brazil',TR:'Turkey',IS:'Iceland',NG:'Nigeria',TW:'Taiwan',NZ:'New Zealand',CO:'Colombia',HK:'Hong Kong',US:'USA'};\n"
        "const _RSYM={AR:'AR$',BR:'R$',TR:'\\u20ba',IS:'kr',NG:'\\u20a6',TW:'NT$',NZ:'NZ$',CO:'CO$',HK:'HK$',US:'$'};\n"
        "const _RCC={AR:'ARS',BR:'BRL',TR:'TRY',IS:'ISK',NG:'NGN',TW:'TWD',NZ:'NZD',CO:'COP',HK:'HKD',US:'USD'};\n"
        "function _bestReg(item){"
        "if(!item.regionalPrices||typeof RATES==='undefined')return null;"
        "let best=null;"
        "for(const[mkt,rp]of Object.entries(item.regionalPrices)){"
        "const p=rp.salePrice>0?rp.salePrice:rp.price;"
        "const rate=RATES[rp.currency]||1;"
        "const usd=(p/rate)*GC_FACTOR;"
        "if(usd>0&&(!best||usd<best.usd)){best={mkt,usd,local:p,cc:rp.currency}}}"
        "return best}\n"
        "function _regCell(item,mkt){"
        "if(!item.regionalPrices||typeof RATES==='undefined')return '<div class=\"lv-reg\" style=\"color:#333\">-</div>';"
        "const rp=item.regionalPrices[mkt];"
        "if(!rp)return '<div class=\"lv-reg\" style=\"color:#333\">-</div>';"
        "const p=rp.salePrice>0?rp.salePrice:rp.price;"
        "const rate=RATES[rp.currency]||1;"
        "const usd=(p/rate)*GC_FACTOR;"
        "if(usd<=0)return '<div class=\"lv-reg\" style=\"color:#333\">-</div>';"
        "const br=_bestReg(item);"
        "const isBest=br&&br.mkt===mkt;"
        "const col=isBest?'#4caf50':'#e91e63';"
        "const w=isBest?'font-weight:700':'';"
        "return `<div class=\"lv-reg\" style=\"color:${col};${w}\">$${usd.toFixed(2)}</div>`}\n"
        "function _regionTbl(item){"
        "if(!item.regionalPrices||typeof RATES==='undefined'||!Object.keys(RATES).length)return '';"
        "let bestUsd=Infinity;"
        "_RORD.forEach(m=>{const rp=item.regionalPrices[m];if(!rp)return;"
        "const p=rp.salePrice>0?rp.salePrice:rp.price;"
        "const rate=RATES[rp.currency]||1;const u=(p/rate)*GC_FACTOR;"
        "if(u>0&&u<bestUsd)bestUsd=u});"
        "let h='<table class=\"rp-tbl\"><tr><th style=\"text-align:left\">Region</th>"
        "<th>Price</th><th>Sale</th><th>USD (GC \u00d70.81)</th></tr>';"
        "_RORD.forEach(m=>{const rp=item.regionalPrices[m];"
        "if(!rp){h+='<tr><td>'+(_RNAME[m]||m)+'</td><td style=\"color:#555\">-</td><td style=\"color:#555\">-</td><td style=\"color:#555\">-</td></tr>';return}"
        "const sym=_RSYM[m]||'';const rate=RATES[rp.currency]||1;"
        "const nd=(['ISK','COP','NGN'].includes(rp.currency))?0:2;"
        "const fmt=v=>sym+v.toLocaleString('en',{minimumFractionDigits:nd,maximumFractionDigits:nd});"
        "const priceStr=fmt(rp.price);"
        "const saleStr=rp.salePrice>0?fmt(rp.salePrice):'-';"
        "const effP=rp.salePrice>0?rp.salePrice:rp.price;"
        "const gcUsd=(effP/rate)*GC_FACTOR;"
        "const isBest=Math.abs(gcUsd-bestUsd)<0.01&&bestUsd<Infinity;"
        "h+='<tr'+(isBest?' class=\"rp-best\"':'')+'>';"
        "h+='<td>'+(_RNAME[m]||m)+'</td>';"
        "h+='<td>'+priceStr+'</td>';"
        "h+='<td>'+(rp.salePrice>0?'<span style=\"color:#4caf50\">'+saleStr+'</span>':saleStr)+'</td>';"
        "h+='<td style=\"color:'+(isBest?'#4caf50':'#e91e63')+';font-weight:600\">$'+gcUsd.toFixed(2)+'</td></tr>'});"
        "h+='</table>';return '<div style=\"margin-top:12px\">"
        "<div style=\"font-weight:600;margin-bottom:6px;color:#ccc\">Regional Prices "
        "<span style=\"font-size:11px;color:#888\">(Gift Card USD = local price \\u00f7 rate \\u00d7 0.81)</span></div>'+h+'</div>'}\n"
        '\n'

        # -- filterMKT (Marketplace) --
        'function filterMKT(){\n'
        "if(typeof MKT==='undefined'||!MKT.length)return;\n"
        "const q=document.getElementById('mkt-search').value.toLowerCase();\n"
        "const chVals=getCBVals('mkt-channel');\n"
        "const tVals=getCBVals('mkt-type');\n"
        "const platVals=getCBVals('mkt-plat');\n"
        "const pubVals=getCBVals('mkt-pub');\n"
        "const so=document.getElementById('mkt-sort').value;\n"


        "const g=document.getElementById('mkt-grid');const l=document.getElementById('mkt-list');\n"
        'let filtered=MKT.filter(item=>{\n'
        "if(q&&!(item.title||'').toLowerCase().includes(q)&&!(item.publisher||'').toLowerCase().includes(q)"
        "&&!(item.productId||'').toLowerCase().includes(q))return false;\n"
        "if(chVals&&!(item.channels||[]).some(c=>chVals.includes(c)))return false;\n"
        "if(tVals){const tk=item.productKind==='Durable'?'DLC':item.productKind;if(!tVals.includes(tk))return false}\n"
        "if(platVals&&!(item.platforms||[]).some(p=>platVals.includes(p)))return false;\n"
        "if(pubVals&&!pubVals.includes(item.publisher||''))return false;\n"


        'return true});\n'
        "if(so==='name')filtered.sort((a,b)=>(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='priceDesc')filtered.sort((a,b)=>((b.priceUSD||0)-(a.priceUSD||0))||(a.title||'').localeCompare(b.title||''));\n"
        "else if(so==='priceAsc')filtered.sort((a,b)=>{const ap=a.priceUSD||0,bp=b.priceUSD||0;"
        "if(!ap&&bp)return 1;if(ap&&!bp)return -1;return(ap-bp)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='relDesc')filtered.sort((a,b)=>{const ar=(a.releaseDate||'').slice(0,4)>='2100'?'':a.releaseDate||'';"
        "const br=(b.releaseDate||'').slice(0,4)>='2100'?'':b.releaseDate||'';"
        "if(!ar&&br)return 1;if(ar&&!br)return -1;"
        "return br.localeCompare(ar)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='relAsc')filtered.sort((a,b)=>{const ar=(a.releaseDate||'').slice(0,4)>='2100'?'':a.releaseDate||'';"
        "const br=(b.releaseDate||'').slice(0,4)>='2100'?'':b.releaseDate||'';"
        "if(!ar&&br)return 1;if(ar&&!br)return -1;"
        "return ar.localeCompare(br)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='bestAsc')filtered.sort((a,b)=>{"
        "const ab=_bestReg(a),bb=_bestReg(b);"
        "const au=ab?ab.usd:Infinity,bu=bb?bb.usd:Infinity;"
        "if(au===Infinity&&bu===Infinity)return(a.title||'').localeCompare(b.title||'');"
        "if(au===Infinity)return 1;if(bu===Infinity)return -1;"
        "return(au-bu)||(a.title||'').localeCompare(b.title||'')});\n"
        "else if(so==='bestDesc')filtered.sort((a,b)=>{"
        "const ab=_bestReg(a),bb=_bestReg(b);"
        "const au=ab?ab.usd:0,bu=bb?bb.usd:0;"
        "return(bu-au)||(a.title||'').localeCompare(b.title||'')});\n"
        "const totalPages=Math.ceil(filtered.length/MKT_PAGE_SIZE);\n"
        "if(mktPage>=totalPages)mktPage=Math.max(0,totalPages-1);\n"
        "const pgStart=mktPage*MKT_PAGE_SIZE;\n"
        "const pgEnd=Math.min(pgStart+MKT_PAGE_SIZE,filtered.length);\n"
        "const pageItems=filtered.slice(pgStart,pgEnd);\n"
        "let gh='',lh='<div class=\"lv-head\"><div></div><div>Title</div><div>Publisher</div>"
        "<div>Release</div><div style=\"text-align:right\">USD</div>"
        "'+_RORD.map(m=>'<div style=\"text-align:right;font-size:10px\">'+m+'</div>').join('')+'"
        "<div style=\"text-align:center\">Status</div></div>';\n"
        'for(let i=0;i<pageItems.length;i++){const item=pageItems[i];\n'
        "const owned=item.owned?'<span class=\"badge owned\" style=\"font-size:9px\">OWNED</span>'"
        ":'<span class=\"badge new\" style=\"font-size:9px\">NEW</span>';\n"
        "const gpBadge=item.onGP?'<span class=\"badge gp\" style=\"font-size:9px\">GAME PASS</span>':'';\n"
        "const chBadges=(item.channels||[]).map(c=>'<span class=\"badge gp\" style=\"font-size:9px\">'+c+'</span>').join('');\n"
        "const img=item.heroImage||item.boxArt||'';\n"
        "const imgTag=img?`<img class=\"card-img\" src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:"
        "'<div class=\"card-img\" style=\"display:flex;align-items:center;justify-content:center;color:#333;font-size:36px\">'+(item.title||'?')[0]+'</div>';\n"
        "const usd=_p(item.priceUSD);\n"
        "const saleTag=item.currentPriceUSD>0&&item.currentPriceUSD<item.priceUSD?"
        "`<span style=\"color:#4caf50;font-weight:600;margin-left:4px\">${_p(item.currentPriceUSD)}</span>`:'';\n"
        "const priceTag=usd?"
        "`<span style=\"color:#42a5f5;font-weight:600\">${usd}</span>${saleTag}`:"
        "'<span style=\"color:#555;font-size:11px\">Free</span>';\n"
        "const br=_bestReg(item);\n"
        "const bestCard=br?`<div style=\"margin:2px 0;color:#e91e63;font-weight:600;font-size:11px\">Best: $${br.usd.toFixed(2)} (${br.mkt})</div>`:'';\n"
        'gh+=`<div class="card" onclick="showMKTDetail(${MKT.indexOf(item)})">${imgTag}<div class="card-body">'
        '<div class="card-name" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="card-meta">${item.publisher||\'\'} | ${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div style="margin:4px 0">${priceTag}</div>'
        '${bestCard}'
        '<div class="card-badges">${owned}${gpBadge}${chBadges}</div></div></div>`;\n'
        "const thumbImg=img?`<img src=\"${img}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'';\n"
        'lh+=`<div class="lv-row" onclick="showMKTDetail(${MKT.indexOf(item)})">${thumbImg}'
        '<div class="lv-title" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">${item.title||\'Unknown\'}</div>'
        '<div class="lv-pub">${item.publisher||\'\'}</div>'
        '<div class="lv-type">${(item.releaseDate||\'\').substring(0,10)}</div>'
        '<div class="lv-usd">${usd}${saleTag}</div>'
        "${_RORD.map(m=>_regCell(item,m)).join('')}"
        '<div class="lv-status">${owned}${gpBadge}</div></div>`}\n'
        "g.innerHTML=gh;l.innerHTML=lh;\n"
        "const ownedCnt=filtered.filter(x=>x.owned).length;\n"
        "const gpCnt=filtered.filter(x=>x.onGP).length;\n"
        "document.getElementById('mkt-cbar').innerHTML=`<span>${filtered.length}</span>"
        "${totalPages>1?` (page ${mktPage+1}/${totalPages}, showing ${pgStart+1}-${pgEnd})`:''} of ${MKT.length} — "
        "<span style=\"color:#4caf50\">${ownedCnt} owned</span>"
        "${gpCnt?' — <span style=\"color:#107c10\">'+gpCnt+' on Game Pass</span>':''}`;\n"
        # Pagination controls
        "let pgH='';\n"
        "if(totalPages>1){\n"
        "pgH+='<button style=\"padding:6px 12px;background:#333;color:#fff;border:1px solid #555;border-radius:4px;cursor:pointer'+(mktPage===0?';opacity:.4;cursor:default':'')+`\" ${mktPage===0?'disabled':''} onclick=\"mktGoPage(${mktPage-1})\">&#9664; Prev</button>`;\n"
        "const maxBtns=9,half=Math.floor(maxBtns/2);\n"
        "let lo=Math.max(0,mktPage-half),hi=Math.min(totalPages-1,lo+maxBtns-1);\n"
        "lo=Math.max(0,hi-maxBtns+1);\n"
        "if(lo>0)pgH+='<button style=\"padding:6px 10px;background:#222;color:#aaa;border:1px solid #444;border-radius:4px;cursor:pointer\" onclick=\"mktGoPage(0)\">1</button><span style=\"color:#666\">...</span>';\n"
        "for(let p=lo;p<=hi;p++){"
        "const active=p===mktPage?'background:#107c10;color:#fff;font-weight:bold':'background:#222;color:#ccc';"
        "pgH+=`<button style=\"padding:6px 10px;${active};border:1px solid #555;border-radius:4px;cursor:pointer\" onclick=\"mktGoPage(${p})\">${p+1}</button>`}\n"
        "if(hi<totalPages-1)pgH+='<span style=\"color:#666\">...</span><button style=\"padding:6px 10px;background:#222;color:#aaa;border:1px solid #444;border-radius:4px;cursor:pointer\" onclick=\"mktGoPage('+(totalPages-1)+')\">'+totalPages+'</button>';\n"
        "pgH+='<button style=\"padding:6px 12px;background:#333;color:#fff;border:1px solid #555;border-radius:4px;cursor:pointer'+(mktPage>=totalPages-1?';opacity:.4;cursor:default':'')+`\" ${mktPage>=totalPages-1?'disabled':''} onclick=\"mktGoPage(${mktPage+1})\">Next &#9654;</button>`}\n"
        "document.getElementById('mkt-pager').innerHTML=pgH}\n"
        '\n'

        # -- showMKTDetail --
        'function showMKTDetail(i){\n'
        'const item=MKT[i];if(!item)return;\n'
        "const img=item.heroImage||item.boxArt||'';\n"
        "document.getElementById('modal-hero').src=img;\n"
        "document.getElementById('modal-hero').style.display=img?'block':'none';\n"
        "const owned=item.owned?'<span class=\"badge owned\">IN YOUR LIBRARY</span>'"
        ":'<span class=\"badge new\">NOT OWNED</span>';\n"
        "const gpTag=item.onGP?'<span class=\"badge gp\">GAME PASS</span>':'';\n"
        "const chBadges=(item.channels||[]).map(c=>'<span class=\"badge gp\">'+c+'</span>').join(' ');\n"
        "const platBadges=(item.platforms||[]).map(p=>{"
        "const cls=p.includes('Series')?'series':p.includes('360')?'x360':p==='PC'?'pc':p.includes('One')?'one':'mobile';"
        "return '<span class=\"badge '+cls+'\">'+p+'</span>'}).join(' ');\n"
        "document.getElementById('modal-body').innerHTML=`\n"
        '<div class="modal-title">${item.title||\'Unknown\'}</div>\n'
        '<div class="modal-pub">${item.publisher||\'\'} ${item.developer&&item.developer!==item.publisher?\'/  \'+item.developer:\'\'}</div>\n'
        '<div style="margin-bottom:10px">${owned} ${gpTag} ${chBadges} ${platBadges}</div>\n'
        '<div class="modal-info">\n'
        '<div><span class="lbl">Product ID:</span></div><div class="val">${item.productId}</div>\n'
        "${item.xboxTitleId?'<div><span class=\"lbl\">Xbox Title ID:</span></div><div class=\"val\">'+item.xboxTitleId+'</div>':''}\n"
        '<div><span class="lbl">Release:</span></div><div class="val">${(item.releaseDate||\'\').substring(0,10)}</div>\n'
        '<div><span class="lbl">Type:</span></div><div class="val">${item.productKind||\'\'}</div>\n'
        '<div><span class="lbl">Category:</span></div><div class="val">${item.category||\'\'}</div>\n'
        "${item.priceUSD>0?'<div><span class=\"lbl\">Price:</span></div><div class=\"val\" style=\"color:#42a5f5;font-weight:600\">'+_p(item.priceUSD)+'</div>':''}\n"
        "${item.currentPriceUSD>0&&item.currentPriceUSD<item.priceUSD?'<div><span class=\"lbl\">Sale:</span></div><div class=\"val\" style=\"color:#4caf50;font-weight:600\">'+_p(item.currentPriceUSD)+'</div>':''}\n"
        '<div><span class="lbl">Store:</span></div><div class="val"><a href="https://www.xbox.com/en-GB/games/store/p/${item.productId}" target="_blank">${item.productId}</a></div>\n'
        "</div>\n"
        "${_regionTbl(item)}`;\n"
        "document.getElementById('modal').classList.add('active')}\n"
        '\n'

        # -- renderHistory --
        'function renderHistory(){\n'
        "const el=document.getElementById('hist-cards');if(!el||!HISTORY.length)return;\n"
        "document.getElementById('hist-sub').textContent=HISTORY.length+' scans recorded';\n"
        "let h='';\n"
        'HISTORY.forEach((scan,i)=>{\n'
        "const ts=(scan.timestamp||'').replace('T',' ').replace(/-/g,':');\n"
        "const cl=scan.changelog||{};\n"
        "const nNew=(cl.newItems||[]).length;\n"
        "const nRem=(cl.removedItems||[]).length;\n"
        "const nChg=(cl.changedItems||[]).length;\n"
        "const badges=(nNew?`<span class=\"hist-badge added\">+${nNew} new</span>`:'')"
        "+(nRem?`<span class=\"hist-badge removed\">-${nRem} removed</span>`:'')"
        "+(nChg?`<span class=\"hist-badge changed\">~${nChg} changed</span>`:'');\n"
        "const usd=scan.totalUSD>0?`<span class=\"usd\">$${scan.totalUSD.toLocaleString('en',{minimumFractionDigits:2})}</span>`:'';\n"
        "let detail='';\n"
        "if(nNew){\n"
        "detail+='<div class=\"hist-section\"><div class=\"hist-section-title add-title\">New Items ('+nNew+')</div>';\n"
        "(cl.newItems||[]).forEach(it=>{detail+='<div class=\"hist-item\">+ '+(it.title||it.productId)+'</div>'});\n"
        "detail+='</div>'}\n"
        "if(nRem){\n"
        "detail+='<div class=\"hist-section\"><div class=\"hist-section-title rem-title\">Removed Items ('+nRem+')</div>';\n"
        "(cl.removedItems||[]).forEach(it=>{detail+='<div class=\"hist-item\">- '+(it.title||it.productId)+'</div>'});\n"
        "detail+='</div>'}\n"
        "if(nChg){\n"
        "detail+='<div class=\"hist-section\"><div class=\"hist-section-title chg-title\">Changed Items ('+nChg+')</div>';\n"
        "(cl.changedItems||[]).slice(0,50).forEach(it=>{\n"
        "detail+='<div class=\"hist-item\">~ '+(it.title||it.productId)+'</div>';\n"
        "const ch=it.changes||{};\n"
        "Object.keys(ch).forEach(f=>{\n"
        "const o=typeof ch[f].old==='object'?JSON.stringify(ch[f].old):String(ch[f].old||'');\n"
        "const n=typeof ch[f].new==='object'?JSON.stringify(ch[f].new):String(ch[f].new||'');\n"
        "detail+=`<div class=\"hist-diff\">${f}: <span class=\"old\">${o}</span> &rarr; <span class=\"new\">${n}</span></div>`})});\n"
        "detail+='</div>'}\n"
        "h+=`<div class=\"hist-card\" onclick=\"toggleHistDetail(this)\">\n"
        "<div class=\"hist-header\"><span class=\"hist-date\">${ts}</span>${scan.gamertag?`<span class=\"hist-method\">${scan.gamertag}</span>`:''}<span class=\"hist-method\">${scan.method||'auto'}</span></div>\n"
        "<div class=\"hist-stats\"><span>${scan.itemCount} items</span>"
        "${usd?`<span>${usd}</span>`:''}</div>\n"
        "<div class=\"hist-badges\">${badges||'<span style=\"color:#555;font-size:11px\">First scan</span>'}</div>\n"
        "<div class=\"hist-detail\">${detail||'<div style=\"color:#555;font-size:12px\">No changes in this scan.</div>'}</div>\n"
        "</div>`});\n"
        "el.innerHTML=h}\n"
        "function toggleHistDetail(card){card.querySelector('.hist-detail').classList.toggle('open')}\n"
        '\n'

        # -- renderAccounts --
        "let _acctSort={col:'gamertag',dir:'asc'};\n"
        "function _acctSortBy(col){"
        "if(_acctSort.col===col){_acctSort.dir=_acctSort.dir==='asc'?'desc':'asc'}"
        "else{_acctSort.col=col;_acctSort.dir='asc'}"
        "renderAccounts()}\n"
        "function renderAccounts(){\n"
        "if(typeof ACCOUNTS==='undefined'||!ACCOUNTS.length)return;\n"
        "const el=document.getElementById('acct-table');\n"
        "const sub=document.getElementById('acct-sub');\n"
        "sub.textContent=ACCOUNTS.length+' accounts';\n"
        # Compute per-gamertag stats from LIB
        "const gtStats={};\n"
        "LIB.forEach(item=>{\n"
        "const g=item.gamertag||'';\n"
        "if(!gtStats[g])gtStats[g]={items:0,games:0,dlc:0,gameVal:0,dlcVal:0,value:0};\n"
        "gtStats[g].items++;\n"
        "if(item.productKind==='Game'){gtStats[g].games++;gtStats[g].gameVal+=(item.priceUSD||0)}\n"
        "if(item.productKind==='Durable'){gtStats[g].dlc++;gtStats[g].dlcVal+=(item.priceUSD||0)}\n"
        "gtStats[g].value+=(item.priceUSD||0);\n"
        "});\n"
        # Build sortable rows data
        "const rows=ACCOUNTS.map(a=>{\n"
        "const s=gtStats[a.gamertag]||{items:0,games:0,dlc:0,gameVal:0,dlcVal:0,value:0};\n"
        "return{...a,...s}});\n"
        # Sort
        "const col=_acctSort.col,dir=_acctSort.dir==='asc'?1:-1;\n"
        "rows.sort((a,b)=>{\n"
        "let va=a[col],vb=b[col];\n"
        "if(typeof va==='string'){va=(va||'').toLowerCase();vb=(vb||'').toLowerCase();"
        "return va<vb?-dir:va>vb?dir:0}\n"
        "return((va||0)-(vb||0))*dir});\n"
        # Column definitions
        "const cols=[\n"
        "{key:'gamertag',label:'Gamertag'},\n"
        "{key:'xuid',label:'XUID'},\n"
        "{key:'uhs',label:'UHS'},\n"
        "{key:'deviceId',label:'Device ID'},\n"
        "{key:'authMode',label:'Auth Mode'},\n"
        "{key:'tokenAge',label:'Token Age'},\n"
        "{key:'items',label:'#',num:1},\n"
        "{key:'games',label:'Games #',num:1},\n"
        "{key:'gameVal',label:'Games Value',num:1},\n"
        "{key:'dlc',label:'DLC #',num:1},\n"
        "{key:'dlcVal',label:'DLC Value',num:1},\n"
        "{key:'value',label:'Total Value',num:1}];\n"
        # Build header
        "let h='<table class=\"gtbl\"><thead><tr>';\n"
        "cols.forEach(c=>{\n"
        "const cls=['sortable'];if(c.num)cls.push('num');\n"
        "if(_acctSort.col===c.key)cls.push(_acctSort.dir==='asc'?'sort-asc':'sort-desc');\n"
        "h+=`<th class=\"${cls.join(' ')}\" onclick=\"_acctSortBy('${c.key}')\">${c.label}</th>`});\n"
        "h+='</tr></thead><tbody>';\n"
        # Build rows
        "rows.forEach(r=>{\n"
        # Token age formatting
        "let age='',ageCls='gt-mono';\n"
        "if(r.tokenAge<0){age='No token';ageCls='gt-err'}\n"
        "else if(r.tokenAge<3600){age=Math.floor(r.tokenAge/60)+'m';ageCls='gt-ok'}\n"
        "else if(r.tokenAge<86400){age=Math.floor(r.tokenAge/3600)+'h';ageCls='gt-ok'}\n"
        "else{const d=Math.floor(r.tokenAge/86400);age=d+'d';ageCls=d>7?'gt-err':'gt-warn'}\n"
        "h+='<tr>';\n"
        "h+=`<td class=\"gt-name\">${r.gamertag}</td>`;\n"
        "h+=`<td class=\"gt-mono\">${r.xuid||'-'}</td>`;\n"
        "h+=`<td class=\"gt-mono\">${r.uhs||'-'}</td>`;\n"
        "h+=`<td class=\"gt-mono\">${r.deviceId?r.deviceId.substring(0,8)+'...':'-'}</td>`;\n"
        "h+=`<td>${r.authMode==='device-bound'?'<span class=\"gt-ok\">Device-bound</span>':'<span class=\"gt-warn\">Simple</span>'}</td>`;\n"
        "h+=`<td class=\"${ageCls}\">${age}</td>`;\n"
        "h+=`<td class=\"num\">${r.items.toLocaleString()}</td>`;\n"
        "h+=`<td class=\"num\">${r.games.toLocaleString()}</td>`;\n"
        "h+=`<td class=\"num\">${_p(r.gameVal)||'-'}</td>`;\n"
        "h+=`<td class=\"num\">${r.dlc.toLocaleString()}</td>`;\n"
        "h+=`<td class=\"num\">${_p(r.dlcVal)||'-'}</td>`;\n"
        "h+=`<td class=\"num\">${_p(r.value)||'-'}</td>`;\n"
        "h+='</tr>'});\n"
        "h+='</tbody></table>';\n"
        "el.innerHTML=h;\n"
        "}\n\n"

        "if(GP.length){const _gpPids=new Set(GP.map(g=>g.productId));"
        "LIB.forEach(x=>{x.onGamePass=_gpPids.has(x.productId)})}\n"
        'initDropdowns();filterLib();filterPH();filterGP();filterMKT();renderHistory();\n'
        "document.getElementById('loading-overlay').style.display='none';\n"
        '</script></body></html>'
    )

    return html


def write_data_js(library, gp_items, scan_history, data_js_path, play_history=None,
                  marketplace=None, accounts_meta=None):
    """Write the data.js file that the static HTML template loads.

    Contains const LIB, GP, PH, MKT, HISTORY, and ACCOUNTS arrays.
    """
    if scan_history is None:
        scan_history = []
    if gp_items is None:
        gp_items = []
    if play_history is None:
        play_history = []
    if marketplace is None:
        marketplace = []
    if accounts_meta is None:
        accounts_meta = []

    # Load exchange rates from global cache (if available)
    rates = {}
    if os.path.isfile(EXCHANGE_RATES_FILE):
        try:
            rates_data = load_json(EXCHANGE_RATES_FILE)
            rates = rates_data.get("rates", {})
        except Exception:
            pass

    content = (
        "const LIB=" + json.dumps(library, ensure_ascii=False) + ";\n"
        "const GP=" + json.dumps(gp_items, ensure_ascii=False) + ";\n"
        "const PH=" + json.dumps(play_history, ensure_ascii=False) + ";\n"
        "const MKT=" + json.dumps(marketplace, ensure_ascii=False) + ";\n"
        "const HISTORY=" + json.dumps(scan_history, ensure_ascii=False) + ";\n"
        "const DEFAULT_FLAGS=" + json.dumps(DEFAULT_FLAGS, ensure_ascii=False) + ";\n"
        "const ACCOUNTS=" + json.dumps(accounts_meta, ensure_ascii=False) + ";\n"
        "const RATES=" + json.dumps(rates, ensure_ascii=False) + ";\n"
        "const GC_FACTOR=" + str(GC_FACTOR) + ";\n"
    )
    with open(data_js_path, "w", encoding="utf-8") as f:
        f.write(content)

    size_kb = len(content.encode("utf-8")) / 1024
    print(f"[+] Data written: {data_js_path} ({size_kb:.0f} KB)")


# ===========================================================================
# Scan History
# ===========================================================================

CHANGELOG_FIELDS = [
    "status", "priceUSD", "currentPriceUSD",
    "title", "publisher", "developer", "category", "releaseDate",
    "onGamePass", "isTrial", "isDemo", "productKind", "platforms",
    "lastTimePlayed",
]


def compute_changelog(prev_library, curr_library, prev_timestamp):
    """Compare two library snapshots and return a changelog dict.

    Tracks all fields in CHANGELOG_FIELDS. Returns:
    {previousScan, newItems[], removedItems[], changedItems[]}
    where each changedItem has per-field {old, new} diffs.
    """
    prev_by_pid = {item["productId"]: item for item in prev_library}
    curr_by_pid = {item["productId"]: item for item in curr_library}

    prev_pids = set(prev_by_pid.keys())
    curr_pids = set(curr_by_pid.keys())

    new_pids = curr_pids - prev_pids
    removed_pids = prev_pids - curr_pids
    common_pids = prev_pids & curr_pids

    new_items = []
    for pid in sorted(new_pids):
        item = curr_by_pid[pid]
        new_items.append({
            "productId": pid,
            "title": item.get("title", ""),
            "productKind": item.get("productKind", ""),
        })

    removed_items = []
    for pid in sorted(removed_pids):
        item = prev_by_pid[pid]
        removed_items.append({
            "productId": pid,
            "title": item.get("title", ""),
            "productKind": item.get("productKind", ""),
        })

    changed_items = []
    for pid in sorted(common_pids):
        prev_item = prev_by_pid[pid]
        curr_item = curr_by_pid[pid]
        diffs = {}
        for field in CHANGELOG_FIELDS:
            old_val = prev_item.get(field, "")
            new_val = curr_item.get(field, "")
            # Normalize for comparison
            if isinstance(old_val, list):
                old_val = sorted(old_val) if old_val else []
            if isinstance(new_val, list):
                new_val = sorted(new_val) if new_val else []
            if old_val != new_val:
                diffs[field] = {"old": old_val, "new": new_val}
        if diffs:
            changed_items.append({
                "productId": pid,
                "title": curr_item.get("title", "") or prev_item.get("title", ""),
                "changes": diffs,
            })

    return {
        "previousScan": prev_timestamp,
        "newItems": new_items,
        "removedItems": removed_items,
        "changedItems": changed_items,
    }


def load_previous_scan(gamertag):
    """Load the most recent scan for an account, or None."""
    history_dir = os.path.join(account_dir(gamertag), "history")
    if not os.path.isdir(history_dir):
        return None
    scans = sorted(
        [f for f in os.listdir(history_dir) if f.startswith("scan_") and f.endswith(".json")],
        reverse=True,
    )
    if not scans:
        return None
    try:
        return load_json(os.path.join(history_dir, scans[0]))
    except (json.JSONDecodeError, IOError):
        return None


def save_scan(gamertag, library, method):
    """Save a scan snapshot and return the changelog vs previous scan.

    Saves to accounts/{gamertag}/history/scan_YYYY-MM-DDTHH-MM-SS.json.
    Returns the changelog dict (or empty changelog if first scan).
    """
    history_dir = os.path.join(account_dir(gamertag), "history")
    os.makedirs(history_dir, exist_ok=True)

    timestamp = _dt.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

    # Compute changelog vs previous scan
    prev = load_previous_scan(gamertag)
    if prev and prev.get("library"):
        changelog = compute_changelog(prev["library"], library, prev.get("timestamp", ""))
    else:
        changelog = {
            "previousScan": None,
            "newItems": [],
            "removedItems": [],
            "changedItems": [],
        }

    # Compute totals
    total_usd = sum((x.get("priceUSD") or 0) for x in library)

    scan = {
        "timestamp": timestamp,
        "gamertag": gamertag,
        "method": method or "auto",
        "itemCount": len(library),
        "totalUSD": round(total_usd, 2),
        "changelog": changelog,
        "library": library,
    }

    scan_file = os.path.join(history_dir, f"scan_{timestamp}.json")
    save_json(scan_file, scan)
    debug(f"save_scan: saved {scan_file} ({len(library)} items)")
    print(f"[+] Scan saved: {scan_file}")

    return changelog


def load_all_scans(gamertag, max_scans=100):
    """Load metadata for all scans (strips library arrays to save memory).

    Returns list of scan metadata dicts, most recent first, capped at max_scans.
    """
    history_dir = os.path.join(account_dir(gamertag), "history")
    if not os.path.isdir(history_dir):
        return []
    scan_files = sorted(
        [f for f in os.listdir(history_dir) if f.startswith("scan_") and f.endswith(".json")],
        reverse=True,
    )[:max_scans]

    scans = []
    for fname in scan_files:
        try:
            data = load_json(os.path.join(history_dir, fname))
            # Strip the library array to keep metadata light
            data.pop("library", None)
            scans.append(data)
        except (json.JSONDecodeError, IOError):
            continue
    return scans


def print_changelog(changelog):
    """Print changelog summary to console."""
    new_count = len(changelog.get("newItems", []))
    removed_count = len(changelog.get("removedItems", []))
    changed_count = len(changelog.get("changedItems", []))

    if not (new_count or removed_count or changed_count):
        if changelog.get("previousScan"):
            print("  No changes since last scan.")
        else:
            print("  First scan — no previous data to compare.")
        return

    prev = changelog.get("previousScan", "unknown")
    print(f"\n  Changes since {prev}:")
    print(f"    +{new_count} new | -{removed_count} removed | ~{changed_count} changed")

    # Show top new items
    if new_count:
        print(f"\n  New items ({min(new_count, 10)} of {new_count}):")
        for item in changelog["newItems"][:10]:
            title = item.get("title") or item.get("productId")
            print(f"    + {title}")

    # Show top removed items
    if removed_count:
        print(f"\n  Removed items ({min(removed_count, 10)} of {removed_count}):")
        for item in changelog["removedItems"][:10]:
            title = item.get("title") or item.get("productId")
            print(f"    - {title}")

    # Show top changed items
    if changed_count:
        print(f"\n  Changed items ({min(changed_count, 10)} of {changed_count}):")
        for item in changelog["changedItems"][:10]:
            title = item.get("title") or item.get("productId")
            fields = ", ".join(item.get("changes", {}).keys())
            print(f"    ~ {title} [{fields}]")
    print()


# ===========================================================================
# Data source prompt
# ===========================================================================

def prompt_data_source(gamertag):
    """Prompt user to choose data source for entitlement fetching.

    Returns "collection", "titlehub", "both", or None (default=both).
    """
    acct = account_dir(gamertag)
    has_collection = os.path.isfile(os.path.join(acct, "auth_token.txt"))
    has_titlehub = (os.path.isfile(os.path.join(acct, "auth_token_xl.txt"))
                    and os.path.isfile(os.path.join(acct, "xuid.txt")))

    col_status = "token available" if has_collection else "no token"
    th_status = "token available" if has_titlehub else "no token"

    print()
    print("  Data source:")
    print(f"    [B] Both (recommended)      - full collection + game metadata")
    print(f"    [C] Collections API only    - {col_status} — all entitlements (~5000)")
    print(f"    [T] TitleHub only           - {th_status} — games with metadata (~1000)")
    print(f"    [F] Import HAR file         - extract token from .har then process")
    print()

    pick = input("  Pick [B/C/T/F, default=B]: ").strip().upper()

    if pick == "F":
        # Import fresh token from HAR file, then use Collections API
        print()
        har_files = sorted(glob.glob(os.path.join(SCRIPT_DIR, "*.har")),
                           key=os.path.getmtime, reverse=True)
        har_arg = None
        if har_files:
            print("  Available HAR files:")
            for i, hf in enumerate(har_files, 1):
                age_s = time.time() - os.path.getmtime(hf)
                age_m = int(age_s / 60)
                age_str = f"{age_m}m ago" if age_m < 60 else f"{age_m // 60}h ago"
                print(f"    [{i}] {os.path.basename(hf)} ({age_str})")
            print()
            hp = input(f"  Pick HAR file [1-{len(har_files)}] or filename: ").strip()
            if hp:
                try:
                    idx = int(hp) - 1
                    if 0 <= idx < len(har_files):
                        har_arg = har_files[idx]
                    else:
                        print("  Invalid selection, using most recent.")
                except ValueError:
                    # Treat as filename
                    har_arg = hp
        har_extract(har_arg)
        # har_extract saves to an account dir — re-check this account's token
        has_collection = os.path.isfile(os.path.join(acct, "auth_token.txt"))
        if not has_collection:
            print("  Token was saved to a different account. Falling back to Both.")
            return "both"
        return "collection"
    elif pick == "C":
        if not has_collection:
            print()
            print("  No Collections API token found.")
            answer = input("  Import from HAR file now? [Y/n]: ").strip().lower()
            if answer not in ("n", "no"):
                har_extract()
            has_collection = os.path.isfile(os.path.join(acct, "auth_token.txt"))
            if not has_collection:
                print("  Still no token — falling back to Both.")
                return "both"
        return "collection"
    elif pick == "T":
        if not has_titlehub:
            print("  No TitleHub tokens found. Use device code auth first.")
            print("  Falling back to Both.")
            return "both"
        return "titlehub"
    else:
        return "both"


# ===========================================================================
# Process a single account
# ===========================================================================

def process_account(gamertag, method=None):
    """Run the full pipeline for a single account.

    method: "both" (Collections+TitleHub merged), "collection", "titlehub",
            or None (prompt user, default=both).
    """
    debug(f"process_account: gamertag={gamertag} method={method}")
    set_account_paths(gamertag)
    # Log all files in account dir
    acct = account_dir(gamertag)
    if os.path.isdir(acct):
        debug(f"  account dir: {os.listdir(acct)}")
    banner(gamertag)
    start_time = time.time()

    # -- Prompt for data source if not specified --
    if method is None:
        method = prompt_data_source(gamertag)

    # -- Step 1: Auth tokens --
    auth_token = read_auth_token(optional=(method == "titlehub"))
    auth_token_xl = _read_xl_token()
    if auth_token:
        debug(f"  auth_token (mp): {len(auth_token)}ch")
    else:
        debug("  auth_token: None (titlehub-only mode)")
    if auth_token_xl:
        debug(f"  auth_token_xl: {len(auth_token_xl)}ch")

    # -- Step 2: Entitlements --
    entitlements = fetch_entitlements(auth_token, gamertag=gamertag, method=method)
    product_ids = list(dict.fromkeys(e["productId"] for e in entitlements if e["productId"]))
    print(f"  Unique product IDs: {len(product_ids)}")

    # -- Step 2b: Content Access (Xbox 360 / backward-compat discovery) --
    ca_new_pids = []
    if auth_token:
        ca_pids = fetch_contentaccess(auth_token, cache_file=CONTENTACCESS_FILE)
        if ca_pids:
            existing_pids = set(product_ids)
            ca_new_pids = [pid for pid in ca_pids if pid not in existing_pids]
            if ca_new_pids:
                print(f"  Content Access found {len(ca_new_pids)} additional product IDs "
                      f"(not in Collections API)")
                for pid in ca_new_pids:
                    entitlements.append({
                        "productId": pid,
                        "productKind": "",
                        "status": "Active",
                        "acquiredDate": "",
                        "startDate": "",
                        "endDate": "",
                        "isTrial": False,
                        "skuType": "",
                        "skuId": "",
                        "purchasedCountry": "",
                        "quantity": 1,
                        "_contentaccess_only": True,
                    })
                product_ids = list(dict.fromkeys(
                    e["productId"] for e in entitlements if e["productId"]))
                # Re-save entitlements with contentaccess items included
                save_json(ENTITLEMENTS_FILE, entitlements)
                print(f"  Updated product IDs: {len(product_ids)}")

    # -- Step 3: Catalog enrichment (US market only) --
    catalog_us = None
    if auth_token_xl:
        catalog_us = fetch_catalog_v3(
            product_ids, auth_token_xl, market="US", lang="en-US",
            cache_file=CATALOG_V3_US_FILE, label="Catalog v3 (US)")

    if not catalog_us:
        print("  Catalog v3 unavailable, falling back to Display Catalog...")
        catalog_us = fetch_display_catalog(
            product_ids, "US", "en-US", CATALOG_US_FILE, "Display Catalog (US)")
    else:
        # Backfill: Catalog v3 returns empty shells for Xbox 360 / legacy items.
        # Use Display Catalog to resolve any product IDs with no title.
        empty_ids = [pid for pid in product_ids
                     if pid in catalog_us and not catalog_us[pid].get("title")]
        if empty_ids:
            print(f"  Catalog v3 returned {len(empty_ids)} empty entries, "
                  f"backfilling from Display Catalog...")
            backfill = fetch_display_catalog(
                empty_ids, "US", "en-US", CATALOG_US_FILE, "Display Catalog (US backfill)")
            if backfill:
                filled = sum(1 for pid in empty_ids
                             if pid in backfill and backfill[pid].get("title"))
                catalog_us.update(backfill)
                # Update v3 cache so build_index picks up resolved entries
                if CATALOG_V3_US_FILE and os.path.isfile(CATALOG_V3_US_FILE):
                    v3_data = load_json(CATALOG_V3_US_FILE)
                    for pid in empty_ids:
                        if pid in backfill and backfill[pid].get("title"):
                            v3_data[pid] = backfill[pid]
                    save_json(CATALOG_V3_US_FILE, v3_data)
                print(f"  Backfilled {filled}/{len(empty_ids)} items from Display Catalog")

    # -- Step 3b: Identify Xbox 360 games from contentaccess items --
    # Collect ALL contentaccess-only product IDs (new + previously added)
    ca_all_pids = ca_new_pids[:]
    if not ca_all_pids:
        ca_all_pids = [e["productId"] for e in entitlements if e.get("_contentaccess_only")]

    if ca_all_pids and auth_token_xl:
        # Supplementary catalog v3 fetch for contentaccess IDs missing from catalog
        missing_pids = [pid for pid in ca_all_pids
                        if not catalog_us or pid not in catalog_us
                        or not catalog_us.get(pid, {}).get("title")]
        if missing_pids:
            print(f"  Fetching catalog for {len(missing_pids)} contentaccess-only items...")
            ca_catalog = fetch_catalog_v3(
                missing_pids, auth_token_xl, market="US", lang="en-US",
                cache_file=None, label="Catalog v3 (contentaccess)")
            if ca_catalog:
                if catalog_us is None:
                    catalog_us = {}
                catalog_us.update(ca_catalog)
                if CATALOG_V3_US_FILE:
                    v3_data = load_json(CATALOG_V3_US_FILE) if os.path.isfile(CATALOG_V3_US_FILE) else {}
                    v3_data.update(ca_catalog)
                    save_json(CATALOG_V3_US_FILE, v3_data)

        # Find items with XBOXTITLEID that don't already have "Xbox 360" platform
        if catalog_us:
            pid_to_titleid = {}
            for pid in ca_all_pids:
                cat_entry = catalog_us.get(pid, {})
                if "Xbox 360" in cat_entry.get("platforms", []):
                    continue  # already tagged
                for alt in cat_entry.get("alternateIds", []):
                    if alt.get("idType") == "XBOXTITLEID":
                        pid_to_titleid[pid] = alt["id"]
                        break

            if pid_to_titleid:
                title_ids = list(pid_to_titleid.values())
                print(f"  Checking {len(title_ids)} contentaccess items via TitleHub batch...")
                th_results = fetch_titlehub_batch(title_ids, auth_token_xl)

                xbox360_count = 0
                for pid, title_data in th_results.items():
                    devices = title_data.get("devices", [])
                    if "Xbox360" in devices:
                        if pid in catalog_us:
                            catalog_us[pid]["platforms"] = ["Xbox 360"]
                            for dev in devices:
                                mapped = {"XboxOne": "Xbox One",
                                          "XboxSeries": "Xbox Series X|S",
                                          "PC": "PC"}.get(dev)
                                if mapped and mapped not in catalog_us[pid]["platforms"]:
                                    catalog_us[pid]["platforms"].append(mapped)
                        xbox360_count += 1

                if xbox360_count:
                    print(f"  Tagged {xbox360_count} Xbox 360 games")
                    if CATALOG_V3_US_FILE:
                        v3_data = load_json(CATALOG_V3_US_FILE) if os.path.isfile(CATALOG_V3_US_FILE) else {}
                        for pid in th_results:
                            if pid in catalog_us:
                                v3_data[pid] = catalog_us[pid]
                        save_json(CATALOG_V3_US_FILE, v3_data)
            else:
                # Check if already tagged from a previous run
                already_360 = sum(1 for pid in ca_all_pids
                                  if "Xbox 360" in catalog_us.get(pid, {}).get("platforms", []))
                if already_360:
                    print(f"  Xbox 360: {already_360} items already tagged")

    # -- Step 3c: Merge into library --
    library, play_history = merge_library(entitlements, catalog_us, gamertag=gamertag)
    if play_history:
        print(f"  Play history (TitleHub-only): {len(play_history)} items")

    # Count trials/demos
    trial_count = sum(1 for x in library if x.get("isTrial"))
    demo_count  = sum(1 for x in library if x.get("isDemo"))
    print(f"  Trial entitlements: {trial_count}")
    print(f"  Catalog demos: {demo_count}")

    # -- Compute value summaries --
    total_usd = sum((x.get("priceUSD") or 0) for x in library)
    priced    = sum(1 for x in library if (x.get("priceUSD") or 0) > 0)

    print()
    print(f"  Library value: USD {total_usd:,.2f} ({priced} priced)")

    # Game Pass catalog is NOT fetched during per-account scan.
    # Use the [G] menu option or process_gamepass_library() for GP data.
    gp_items = []

    # -- Save method-specific library files --
    save_json(LIBRARY_FILE, library)
    save_json(PLAY_HISTORY_FILE, play_history)
    if method == "collection":
        save_json(LIBRARY_COLLECTION_FILE, library)
    elif method == "titlehub":
        save_json(LIBRARY_TITLEHUB_FILE, library)

    # -- Save scan and print changelog --
    changelog = save_scan(gamertag, library, method)
    print_changelog(changelog)

    # -- Load scan history for HTML --
    scan_history = load_all_scans(gamertag)

    # -- Step 5: Write per-account data.js --
    acct_meta = collect_account_metadata()
    acct = account_dir(gamertag)
    data_js_path = os.path.join(acct, "data.js")
    mkt_items = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
    write_data_js(library, gp_items, scan_history, data_js_path, play_history,
                  marketplace=mkt_items, accounts_meta=acct_meta)

    html = build_html_template(gamertag=gamertag)
    with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Template: {OUTPUT_HTML_FILE}")

    # -- Step 6: Write combined data.js (all accounts) --
    combined_library = list(library)
    combined_ph = list(play_history)
    combined_history = list(scan_history)
    combined_mkt = list(mkt_items)
    accounts = load_accounts()
    for other_gt in accounts:
        if other_gt == gamertag:
            continue
        other_lib_file = account_path(other_gt, "library.json")
        if os.path.isfile(other_lib_file):
            other_lib = load_json(other_lib_file)
            if other_lib:
                combined_library.extend(other_lib)
                set_account_paths(other_gt)
                combined_history.extend(load_all_scans(other_gt, max_scans=50))
                other_ph_file = account_path(other_gt, "play_history.json")
                if os.path.isfile(other_ph_file):
                    other_ph = load_json(other_ph_file)
                    if other_ph:
                        combined_ph.extend(other_ph)
                if not combined_mkt:
                    other_mkt_file = account_path(other_gt, "marketplace.json")
                    if os.path.isfile(other_mkt_file):
                        combined_mkt = load_json(other_mkt_file) or []
    # Restore paths for current account
    set_account_paths(gamertag)

    if len(combined_library) > len(library):
        combined_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
        combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
        write_data_js(combined_library, gp_items, combined_history[:100], combined_data_js, combined_ph,
                      marketplace=combined_mkt, accounts_meta=acct_meta)
        combined_html = os.path.join(ACCOUNTS_DIR, "XCT.html")
        html = build_html_template(gamertag="All Accounts")
        with open(combined_html, "w", encoding="utf-8") as f:
            f.write(html)
        OUTPUT_HTML_COMBINED = combined_html
    else:
        OUTPUT_HTML_COMBINED = OUTPUT_HTML_FILE

    elapsed = time.time() - start_time
    print(f"  Library: {len(library)} items")
    if len(combined_library) > len(library):
        print(f"  Combined: {len(combined_library)} items (all accounts)")
    print(f"  Completed in {elapsed:.1f}s")
    print()

    return OUTPUT_HTML_COMBINED, library


# ===========================================================================
# Build Index (rebuild HTML + data.js from cached data, no API calls)
# ===========================================================================

def _load_gp_details():
    """Load Game Pass details from any account that has them cached."""
    accounts = load_accounts()
    for gt in accounts:
        gp_file = account_path(gt, "gamepass_details.json")
        if os.path.isfile(gp_file):
            details = load_json(gp_file)
            if details:
                return list(details.values())
    return []


def build_index():
    """Re-merge cached data and regenerate data.js + HTML for all accounts.

    Uses existing entitlements.json and catalog_v3_us.json (or catalog_us.json)
    in each account directory — no network requests.
    """
    accounts = load_accounts()
    if not accounts:
        print("No accounts found.")
        return

    gamertags = list(accounts.keys())
    acct_meta = collect_account_metadata()
    gp_items = _load_gp_details()
    if gp_items:
        print(f"  Game Pass: {len(gp_items)} items loaded from cache")
    combined_library = []
    combined_ph = []
    combined_history = []
    combined_mkt = []

    for gt in gamertags:
        set_account_paths(gt)
        acct = account_dir(gt)

        # Load cached entitlements
        ent_file = os.path.join(acct, "entitlements.json")
        if not os.path.isfile(ent_file):
            print(f"  [{gt}] No cached entitlements — skipping")
            continue

        entitlements = load_json(ent_file)

        # Load cached catalog — merge v3 + legacy (Display Catalog backfill)
        cat_v3_file = os.path.join(acct, "catalog_v3_us.json")
        cat_legacy_file = os.path.join(acct, "catalog_us.json")
        catalog = {}
        if os.path.isfile(cat_v3_file):
            catalog = load_json(cat_v3_file)
        if os.path.isfile(cat_legacy_file):
            legacy = load_json(cat_legacy_file)
            # Backfill: legacy catalog resolves Xbox 360/legacy items that v3 returns as empty shells
            for pid, data in legacy.items():
                if data.get("title") and (pid not in catalog or not catalog[pid].get("title")):
                    catalog[pid] = data

        # Re-merge
        library, play_hist = merge_library(entitlements, catalog, gamertag=gt)
        save_json(os.path.join(acct, "library.json"), library)
        save_json(os.path.join(acct, "play_history.json"), play_hist)
        print(f"  [{gt}] {len(library)} items, {len(play_hist)} play history")

        # Load scan history
        scan_history = load_all_scans(gt)

        # Write per-account data.js
        mkt_file = os.path.join(acct, "marketplace.json")
        acct_mkt = load_json(mkt_file) if os.path.isfile(mkt_file) else []
        write_data_js(library, gp_items, scan_history, os.path.join(acct, "data.js"), play_hist,
                      marketplace=acct_mkt, accounts_meta=acct_meta)

        # Force-rebuild per-account HTML
        html_path = os.path.join(acct, "XCT.html")
        html = build_html_template(gamertag=gt)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        combined_library.extend(library)
        combined_ph.extend(play_hist)
        combined_history.extend(scan_history)
        if acct_mkt and not combined_mkt:
            combined_mkt = acct_mkt

    # Backfill xboxTitleId on marketplace items from catalog cache
    if combined_mkt:
        needs_tid = any(not x.get("xboxTitleId") for x in combined_mkt)
        if needs_tid:
            # Build catalog lookup from all accounts' v3 caches
            cat_lookup = {}
            for gt in gamertags:
                v3f = os.path.join(account_dir(gt), "catalog_v3_us.json")
                if os.path.isfile(v3f):
                    for pid, info in load_json(v3f).items():
                        if pid not in cat_lookup:
                            cat_lookup[pid] = info
            for item in combined_mkt:
                if not item.get("xboxTitleId"):
                    cat = cat_lookup.get(item["productId"], {})
                    item["xboxTitleId"] = next(
                        (a["id"] for a in cat.get("alternateIds", [])
                         if a.get("idType") == "XBOXTITLEID"), "")

    # Write combined data.js + HTML
    acct_meta = collect_account_metadata()
    combined_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
    combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
    write_data_js(combined_library, gp_items, combined_history[:100], combined_data_js, combined_ph,
                  marketplace=combined_mkt, accounts_meta=acct_meta)

    combined_html = os.path.join(ACCOUNTS_DIR, "XCT.html")
    html = build_html_template(gamertag="All Accounts")
    with open(combined_html, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Index rebuilt: {len(combined_library)} items across {len(gamertags)} accounts")
    return combined_html


# ===========================================================================
# Marketplace Processing (bronze.xboxservices.com DynamicChannels)
# ===========================================================================

def process_gamepass_library():
    """Fetch Game Pass catalog, enrich with catalog details, and rebuild HTML."""
    accounts = load_accounts()
    gamertags = list(accounts.keys())
    if not gamertags:
        print("[!] No accounts configured.")
        return

    # Pick an account for auth token (needed for catalog enrichment)
    gt = _pick_account(gamertags, "Game Pass catalog using which account?", allow_all=False)
    if not gt:
        return
    set_account_paths(gt)

    if _is_token_expired(gt):
        print(f"[*] Token is >12h old, refreshing...")
        _auto_refresh_token(gt)

    auth_token_xl = _read_xl_token()

    # Step 1: Fetch Game Pass catalog (public, no auth needed)
    print("[*] Fetching Game Pass catalog...")
    gp_data = fetch_gamepass_catalog()
    if not gp_data or not gp_data.get("items"):
        print("[!] Failed to fetch Game Pass catalog")
        return

    gp_pids = list(gp_data["items"].keys())
    print(f"  Game Pass catalog: {len(gp_pids)} products")

    # Step 2: Enrich with catalog details
    existing_catalog = {}
    if os.path.isfile(CATALOG_V3_US_FILE):
        existing_catalog = load_json(CATALOG_V3_US_FILE)
    gp_details = fetch_gamepass_details(gp_data, existing_catalog_us=existing_catalog,
                                        auth_token_xl=auth_token_xl)

    # Step 3: Mark owned items (check all accounts' entitlements)
    owned_pids = set()
    for g in gamertags:
        ent_file = account_path(g, "entitlements.json")
        if os.path.isfile(ent_file):
            ents = load_json(ent_file)
            if ents:
                owned_pids.update(e["productId"] for e in ents
                                  if e.get("productId") and not e.get("_contentaccess_only")
                                  and not e.get("_titlehub_only"))

    gp_items = list(gp_details.values())
    for item in gp_items:
        item["owned"] = item["productId"] in owned_pids
    owned_count = sum(1 for x in gp_items if x["owned"])
    print(f"  Owned: {owned_count}/{len(gp_items)}")

    # Step 4: Rebuild data.js + HTML for all accounts with GP data
    acct_meta = collect_account_metadata()

    # Per-account rebuild
    for g in gamertags:
        set_account_paths(g)
        acct = account_dir(g)
        lib_file = os.path.join(acct, "library.json")
        if not os.path.isfile(lib_file):
            continue
        library = load_json(lib_file)
        ph_file = os.path.join(acct, "play_history.json")
        play_hist = load_json(ph_file) if os.path.isfile(ph_file) else []
        scan_history = load_all_scans(g)
        mkt_file = os.path.join(acct, "marketplace.json")
        acct_mkt = load_json(mkt_file) if os.path.isfile(mkt_file) else []
        write_data_js(library, gp_items, scan_history, os.path.join(acct, "data.js"),
                      play_hist, marketplace=acct_mkt, accounts_meta=acct_meta)

    # Combined rebuild
    combined_library = []
    combined_ph = []
    combined_history = []
    combined_mkt = []
    for g in gamertags:
        set_account_paths(g)
        acct = account_dir(g)
        lib_file = os.path.join(acct, "library.json")
        if os.path.isfile(lib_file):
            lib = load_json(lib_file)
            if lib:
                combined_library.extend(lib)
        ph_file = os.path.join(acct, "play_history.json")
        if os.path.isfile(ph_file):
            ph = load_json(ph_file)
            if ph:
                combined_ph.extend(ph)
        combined_history.extend(load_all_scans(g, max_scans=50))
        if not combined_mkt:
            mkt_file = os.path.join(acct, "marketplace.json")
            if os.path.isfile(mkt_file):
                combined_mkt = load_json(mkt_file) or []

    combined_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
    combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
    write_data_js(combined_library, gp_items, combined_history[:100], combined_data_js,
                  combined_ph, marketplace=combined_mkt, accounts_meta=acct_meta)

    print(f"\n[+] Game Pass catalog written to data.js ({len(gp_items)} items)")
    print()


def _is_token_expired(gamertag):
    """Check if the account's token is likely expired (>12 hours old)."""
    token_file = account_path(gamertag, "auth_token.txt")
    if not os.path.isfile(token_file):
        return True
    age_h = (time.time() - os.path.getmtime(token_file)) / 3600
    return age_h > 12


def _auto_refresh_token(gamertag):
    """Attempt to silently refresh an account's token. Returns True on success."""
    print(f"[*] Auto-refreshing token for {gamertag}...")
    success = refresh_account_token(gamertag)
    if success:
        # Re-set paths so globals point to fresh token files
        set_account_paths(gamertag)
        print(f"[+] Token refreshed for {gamertag}")
    else:
        print(f"[!] Token refresh failed for {gamertag}")
    return success


def process_marketplace(gamertag, channels=None):
    """Fetch marketplace channels, enrich with catalog v3, and rebuild HTML.

    channels: list of DynamicChannel names to fetch, or None for all.
    Auto-refreshes token on expiry (401) or if token is >12h old.
    """
    set_account_paths(gamertag)
    acct = account_dir(gamertag)
    banner(gamertag)

    # Proactive token refresh if token looks stale
    if _is_token_expired(gamertag):
        print(f"[*] Token is >12h old, refreshing before marketplace scan...")
        _auto_refresh_token(gamertag)

    auth_token = read_auth_token(optional=False)
    auth_token_xl = _read_xl_token()
    if not auth_token:
        print("[!] auth_token.txt required for marketplace endpoints")
        return None, []
    if not auth_token_xl:
        print("[!] auth_token_xl.txt required for catalog enrichment")
        return None, []

    if channels is None:
        channels = list(MARKETPLACE_CHANNELS.keys())

    # Fetch each channel (bronze uses mp.microsoft.com RP token)
    # On 401, auto-refresh and retry once
    def _fetch_channels():
        _auth = read_auth_token(optional=False)
        _pids_map = {}
        _all = set()
        for ch in channels:
            pids = fetch_dynamic_channel(ch, _auth)
            _pids_map[ch] = pids
            _all.update(pids)
        return _pids_map, _all

    print(f"[*] Fetching {len(channels)} marketplace channels...")
    try:
        channel_pids, all_pids = _fetch_channels()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[*] Token expired — auto-refreshing...")
            if _auto_refresh_token(gamertag):
                auth_token = read_auth_token(optional=False)
                auth_token_xl = _read_xl_token()
                print(f"[*] Retrying {len(channels)} marketplace channels...")
                try:
                    channel_pids, all_pids = _fetch_channels()
                except Exception:
                    print("[!] Still failing after token refresh")
                    return None, []
            else:
                return None, []
        else:
            print(f"[!] HTTP {e.code} fetching channels")
            return None, []

    if not all_pids:
        print("[!] No products found across channels")
        return None, []

    print(f"  Total unique products: {len(all_pids)}")

    # Enrich with catalog v3 (US market)
    catalog = fetch_catalog_v3(
        list(all_pids), auth_token_xl, market="US", lang="en-US",
        cache_file=None, label="Catalog v3 (marketplace)")
    if not catalog:
        catalog = {}

    # Load entitlements to check "owned" status
    owned_pids = set()
    if os.path.isfile(ENTITLEMENTS_FILE):
        entitlements = load_json(ENTITLEMENTS_FILE)
        owned_pids = set(e["productId"] for e in entitlements if e.get("productId"))

    # Build marketplace items
    mkt_items = []
    for pid in sorted(all_pids):
        cat = catalog.get(pid, {})
        if cat.get("_invalid"):
            continue

        item_channels = []
        for ch, pids in channel_pids.items():
            if pid in pids:
                item_channels.append(MARKETPLACE_CHANNELS.get(ch, ch))

        mkt_items.append({
            "productId": pid,
            "title": cat.get("title", ""),
            "publisher": cat.get("publisher", ""),
            "developer": cat.get("developer", ""),
            "category": cat.get("category", ""),
            "releaseDate": cat.get("releaseDate", ""),
            "platforms": cat.get("platforms", []),
            "priceUSD": cat.get("priceUSD", 0),
            "currentPriceUSD": cat.get("currentPriceUSD", 0),
            "image": cat.get("image", ""),
            "boxArt": cat.get("boxArt", ""),
            "heroImage": cat.get("heroImage", ""),
            "productKind": _norm_kind(cat.get("productKind", "")),
            "channels": item_channels,
            "owned": pid in owned_pids,
            "xboxTitleId": next((a["id"] for a in cat.get("alternateIds", [])
                                 if a.get("idType") == "XBOXTITLEID"), ""),
        })

    # Remove items with no catalog data (no title)
    mkt_items = [x for x in mkt_items if x.get("title")]
    print(f"  Marketplace items: {len(mkt_items)} with catalog data")

    # Regional pricing enrichment
    mkt_items = enrich_regional_prices(mkt_items, auth_token_xl)

    # Save marketplace cache
    save_json(MARKETPLACE_FILE, mkt_items)

    # Reload existing library data to preserve it in data.js
    library = load_json(LIBRARY_FILE) if os.path.isfile(LIBRARY_FILE) else []
    play_history = load_json(PLAY_HISTORY_FILE) if os.path.isfile(PLAY_HISTORY_FILE) else []
    scan_history = load_all_scans(gamertag)

    # Write data.js with marketplace data
    acct_meta = collect_account_metadata()
    data_js_path = os.path.join(acct, "data.js")
    write_data_js(library, _load_gp_details(), scan_history, data_js_path, play_history,
                  marketplace=mkt_items, accounts_meta=acct_meta)

    # Rebuild HTML template (to include marketplace tab)
    html = build_html_template(gamertag=gamertag)
    with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    # Update combined view if multiple accounts exist
    accounts = load_accounts()
    if len(accounts) > 1:
        combined_library = list(library)
        combined_ph = list(play_history)
        combined_history = list(scan_history)
        for other_gt in accounts:
            if other_gt == gamertag:
                continue
            other_lib_file = account_path(other_gt, "library.json")
            if os.path.isfile(other_lib_file):
                other_lib = load_json(other_lib_file)
                if other_lib:
                    combined_library.extend(other_lib)
                    combined_history.extend(load_all_scans(other_gt, max_scans=50))
                    other_ph_file = account_path(other_gt, "play_history.json")
                    if os.path.isfile(other_ph_file):
                        other_ph = load_json(other_ph_file)
                        if other_ph:
                            combined_ph.extend(other_ph)
        combined_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
        combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
        write_data_js(combined_library, _load_gp_details(), combined_history[:100], combined_data_js,
                      combined_ph, marketplace=mkt_items, accounts_meta=acct_meta)
        combined_html = os.path.join(ACCOUNTS_DIR, "XCT.html")
        html = build_html_template(gamertag="All Accounts")
        with open(combined_html, "w", encoding="utf-8") as f:
            f.write(html)

    print(f"[+] Done: {OUTPUT_HTML_FILE}")
    return OUTPUT_HTML_FILE, mkt_items


def process_marketplace_all_regions(gamertag):
    """Fetch marketplace channels across ALL regions, merge, enrich, rebuild.

    Scans DynamicChannels for GB + every PRICE_REGIONS market.  Products are
    tagged with the regions they appear in, then enriched with catalog v3 (US)
    and regional pricing.  The result merges into existing marketplace data so
    browse/discovery items are preserved.
    """
    ALL_MARKETS = {"GB": {"locale": "en-GB", "name": "UK"}}
    ALL_MARKETS.update({cc: info for cc, info in PRICE_REGIONS.items()})

    set_account_paths(gamertag)
    acct = account_dir(gamertag)
    banner(gamertag)

    # Proactive token refresh
    if _is_token_expired(gamertag):
        print("[*] Token is >12h old, refreshing before all-regions scan...")
        _auto_refresh_token(gamertag)

    auth_token = read_auth_token(optional=False)
    auth_token_xl = _read_xl_token()
    if not auth_token:
        print("[!] auth_token.txt required for marketplace endpoints")
        return None, []
    if not auth_token_xl:
        print("[!] auth_token_xl.txt required for catalog enrichment")
        return None, []

    channels = list(MARKETPLACE_CHANNELS.keys())

    # pid -> { "channels": set(), "regions": set() }
    pid_meta = {}

    def _fetch_all_regions():
        """Fetch channels for every market. Raises HTTPError 401 on expiry."""
        _auth = read_auth_token(optional=False)
        for cc, info in ALL_MARKETS.items():
            locale = info["locale"]
            name = info["name"]
            print(f"\n  --- {name} ({cc}) ---")
            for ch in channels:
                pids = fetch_dynamic_channel(ch, _auth, market=cc, lang=locale)
                ch_label = MARKETPLACE_CHANNELS.get(ch, ch)
                for pid in pids:
                    if pid not in pid_meta:
                        pid_meta[pid] = {"channels": set(), "regions": set()}
                    pid_meta[pid]["channels"].add(ch_label)
                    pid_meta[pid]["regions"].add(cc)

    print(f"[*] Scanning {len(channels)} channels × {len(ALL_MARKETS)} regions...")
    try:
        _fetch_all_regions()
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[*] Token expired — auto-refreshing...")
            if _auto_refresh_token(gamertag):
                auth_token = read_auth_token(optional=False)
                auth_token_xl = _read_xl_token()
                pid_meta.clear()
                print(f"[*] Retrying {len(channels)} channels × {len(ALL_MARKETS)} regions...")
                try:
                    _fetch_all_regions()
                except Exception:
                    print("[!] Still failing after token refresh")
                    return None, []
            else:
                return None, []
        else:
            print(f"[!] HTTP {e.code} fetching channels")
            return None, []

    all_pids = set(pid_meta.keys())
    if not all_pids:
        print("[!] No products found across any region")
        return None, []

    print(f"\n  Total unique products across all regions: {len(all_pids)}")

    # Enrich with catalog v3 (US market for English metadata)
    catalog = fetch_catalog_v3(
        list(all_pids), auth_token_xl, market="US", lang="en-US",
        cache_file=None, label="Catalog v3 (all-regions marketplace)")
    if not catalog:
        catalog = {}

    # Load entitlements for "owned" status
    owned_pids = set()
    if os.path.isfile(ENTITLEMENTS_FILE):
        entitlements = load_json(ENTITLEMENTS_FILE)
        owned_pids = set(e["productId"] for e in entitlements if e.get("productId"))

    # Build marketplace items
    mkt_items = []
    for pid in sorted(all_pids):
        cat = catalog.get(pid, {})
        if cat.get("_invalid"):
            continue

        meta = pid_meta[pid]
        mkt_items.append({
            "productId": pid,
            "title": cat.get("title", ""),
            "publisher": cat.get("publisher", ""),
            "developer": cat.get("developer", ""),
            "category": cat.get("category", ""),
            "releaseDate": cat.get("releaseDate", ""),
            "platforms": cat.get("platforms", []),
            "priceUSD": cat.get("priceUSD", 0),
            "currentPriceUSD": cat.get("currentPriceUSD", 0),
            "image": cat.get("image", ""),
            "boxArt": cat.get("boxArt", ""),
            "heroImage": cat.get("heroImage", ""),
            "productKind": _norm_kind(cat.get("productKind", "")),
            "channels": sorted(meta["channels"]),
            "regions": sorted(meta["regions"]),
            "owned": pid in owned_pids,
            "xboxTitleId": next((a["id"] for a in cat.get("alternateIds", [])
                                 if a.get("idType") == "XBOXTITLEID"), ""),
        })

    # Remove items with no catalog data
    mkt_items = [x for x in mkt_items if x.get("title")]
    print(f"  All-regions marketplace items: {len(mkt_items)} with catalog data")

    # Regional pricing enrichment
    mkt_items = enrich_regional_prices(mkt_items, auth_token_xl)

    # Merge with existing marketplace data (preserves browse/discovery items)
    existing = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
    mkt_items = _merge_marketplace(existing, mkt_items)

    # Save marketplace cache
    save_json(MARKETPLACE_FILE, mkt_items)

    # Reload existing library data to preserve it in data.js
    library = load_json(LIBRARY_FILE) if os.path.isfile(LIBRARY_FILE) else []
    play_history = load_json(PLAY_HISTORY_FILE) if os.path.isfile(PLAY_HISTORY_FILE) else []
    scan_history = load_all_scans(gamertag)

    # Write data.js with marketplace data
    acct_meta = collect_account_metadata()
    data_js_path = os.path.join(acct, "data.js")
    write_data_js(library, _load_gp_details(), scan_history, data_js_path, play_history,
                  marketplace=mkt_items, accounts_meta=acct_meta)

    # Rebuild HTML template
    html = build_html_template(gamertag=gamertag)
    with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)

    # Update combined view if multiple accounts exist
    accounts = load_accounts()
    if len(accounts) > 1:
        combined_library = list(library)
        combined_ph = list(play_history)
        combined_history = list(scan_history)
        for other_gt in accounts:
            if other_gt == gamertag:
                continue
            other_lib_file = account_path(other_gt, "library.json")
            if os.path.isfile(other_lib_file):
                other_lib = load_json(other_lib_file)
                if other_lib:
                    combined_library.extend(other_lib)
                    combined_history.extend(load_all_scans(other_gt, max_scans=50))
                    other_ph_file = account_path(other_gt, "play_history.json")
                    if os.path.isfile(other_ph_file):
                        other_ph = load_json(other_ph_file)
                        if other_ph:
                            combined_ph.extend(other_ph)
        combined_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)
        combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
        write_data_js(combined_library, _load_gp_details(), combined_history[:100], combined_data_js,
                      combined_ph, marketplace=mkt_items, accounts_meta=acct_meta)
        combined_html = os.path.join(ACCOUNTS_DIR, "XCT.html")
        html = build_html_template(gamertag="All Accounts")
        with open(combined_html, "w", encoding="utf-8") as f:
            f.write(html)

    print(f"[+] Done: {OUTPUT_HTML_FILE}")
    return OUTPUT_HTML_FILE, mkt_items


# ===========================================================================
# Web Browse catalog scraper (emerald.xboxservices.com)
# ===========================================================================

BROWSE_REGIONS = {
    "en-US": "US",
    "en-GB": "GB",
    "ja-JP": "JP",
    "zh-CN": "CN",
    "de-DE": "DE",
    "es-ES": "ES",
    "fr-FR": "FR",
}


def _browse_state_file(locale):
    """Return per-locale state file path."""
    code = BROWSE_REGIONS.get(locale, locale).lower()
    return os.path.join(SCRIPT_DIR, f"browse_catalog_{code}.json")


def fetch_browse_all(auth_token, locale="en-US"):
    """Scrape the full Xbox Marketplace catalog via the emerald browse endpoint.

    Paginates through all products using continuation tokens.
    Saves progress to browse_catalog_{region}.json for resume support.
    Returns list of all product summaries.
    """
    state_file = _browse_state_file(locale)
    region = BROWSE_REGIONS.get(locale, locale)
    url = f"https://emerald.xboxservices.com/xboxcomfd/browse?locale={locale}"
    sort_key = "Title Asc"
    channel_key = "BROWSE_CHANNELID=_FILTERS=ORDERBY=TITLE ASC"
    page_size = 25  # fixed by the API

    # Build base64-encoded filters
    filters_obj = {"orderby": {"id": "orderby", "choices": [{"id": sort_key}]}}
    filters_b64 = base64.b64encode(json.dumps(filters_obj).encode()).decode()

    # Load existing state for resume
    state = None
    if os.path.isfile(state_file):
        try:
            state = load_json(state_file)
        except Exception:
            state = None

    if (state and state.get("version") == 1
            and state.get("sort") == sort_key
            and state.get("locale") == locale):
        products = state.get("products", [])
        encoded_ct = state.get("encoded_ct", "")
        total_items = state.get("total_items", 0)
        has_more = state.get("has_more", True)
        seen_ids = set(state.get("seen_ids", []))
        errors = state.get("errors", 0)
        if not has_more:
            print(f"[+] [{region}] Browse catalog already complete: {len(products)} products")
            return products
        print(f"[*] [{region}] Resuming browse catalog: {len(products)}/{total_items} products, "
              f"page {len(products) // page_size + 1}")
    else:
        products = []
        encoded_ct = ""
        total_items = 0
        has_more = True
        seen_ids = set()
        errors = 0
        state = {
            "version": 1,
            "sort": sort_key,
            "locale": locale,
            "started": _dt.datetime.now().isoformat(timespec="seconds"),
        }
        print(f"[*] [{region}] Starting browse catalog scrape (Title A-Z)")

    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "x-ms-api-version": "1.1",
        "Accept": "*/*",
        "Origin": "https://www.xbox.com",
        "Referer": "https://www.xbox.com/",
    }

    t0 = time.time()
    page = len(products) // page_size + 1

    def _save_state():
        state["last_updated"] = _dt.datetime.now().isoformat(timespec="seconds")
        state["products"] = products
        state["encoded_ct"] = encoded_ct
        state["total_items"] = total_items
        state["has_more"] = has_more
        state["seen_ids"] = list(seen_ids)
        state["errors"] = errors
        state["pages_completed"] = page - 1
        save_json(state_file, state)

    try:
        while has_more:
            body = {
                "Filters": filters_b64,
                "ReturnFilters": page == 1,
                "ChannelKeyToBeUsedInResponse": channel_key,
                "ChannelId": "",
            }
            if encoded_ct:
                body["EncodedCT"] = encoded_ct

            cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
            headers["MS-CV"] = cv
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
                    err_body = ""
                    try:
                        err_body = e.read().decode("utf-8", errors="replace")[:300]
                    except Exception:
                        pass
                    if e.code == 401:
                        print(f"\n[!] HTTP 401 — token rejected. "
                              f"Try a different token or refresh.")
                        _save_state()
                        return products
                    if e.code == 403 and attempt < 5:
                        # WAF/CDN rate-limit block — long backoff
                        wait = [10, 20, 40, 60, 120][attempt]
                        print(f"\n    HTTP 403 — WAF blocked, waiting {wait}s "
                              f"(attempt {attempt + 1}/6)...")
                        time.sleep(wait)
                        continue
                    if e.code == 429 and attempt < 5:
                        wait = 2 ** (attempt + 1)
                        print(f"\n    HTTP 429 — rate limited, waiting {wait}s...")
                        time.sleep(wait)
                        continue
                    if e.code >= 500 and attempt < 5:
                        wait = 2 ** (attempt + 1)
                        print(f"\n    HTTP {e.code} — server error, retry in {wait}s...")
                        time.sleep(wait)
                        continue
                    print(f"\n[!] HTTP {e.code}: {err_body[:200]}")
                    break
                except Exception as ex:
                    if attempt < 5:
                        time.sleep(2 ** attempt)
                        continue
                    print(f"\n[!] Request failed: {ex}")
                    break

            if not success:
                errors += 1
                if errors > 20:
                    print(f"\n[!] Too many errors ({errors}), stopping.")
                    _save_state()
                    return products
                # Skip this page and try next with same CT
                page += 1
                continue

            # Extract channel data
            channels = resp_data.get("channels", {})
            channel = channels.get(channel_key, {})

            if not channel and channels:
                # Try first available channel (key might differ slightly)
                channel = next(iter(channels.values()))

            if not channel:
                print(f"\n[!] No channel data in response on page {page}")
                errors += 1
                if errors > 10:
                    _save_state()
                    return products
                break

            total_items = channel.get("totalItems", total_items)
            encoded_ct = channel.get("encodedCT", "")
            has_more = bool(encoded_ct)

            # Extract product summaries
            page_products = resp_data.get("productSummaries", [])
            new_count = 0
            for p in page_products:
                pid = p.get("productId", "")
                if pid and pid not in seen_ids:
                    seen_ids.add(pid)
                    products.append(p)
                    new_count += 1

            # Progress
            elapsed = time.time() - t0
            total_pages = (total_items + page_size - 1) // page_size if total_items else 0
            if page > 1 and elapsed > 0:
                pages_per_sec = (page - (len(state.get("products", [])) // page_size + 1) + 1) / elapsed
                remaining = (total_pages - page) / max(pages_per_sec, 0.01)
                eta_m = remaining / 60
            else:
                eta_m = 0
            print(f"\r  Page {page}/{total_pages}  "
                  f"+{new_count} new  total={len(products)}/{total_items}  "
                  f"errors={errors}  "
                  f"ETA {eta_m:.0f}m   ", end="", flush=True)

            # Checkpoint every 25 pages
            if page % 25 == 0:
                _save_state()
                print(f"\n  [checkpoint] page {page}, "
                      f"{len(products)} products, "
                      f"{elapsed:.0f}s elapsed")

            page += 1
            time.sleep(0.5)  # politeness delay (0.5s to avoid WAF blocks)

    except KeyboardInterrupt:
        print(f"\n\n[!] [{region}] Interrupted at page {page}")
        _save_state()
        print(f"    Progress saved: {len(products)} products")
        return products

    # Final save
    has_more = False
    _save_state()
    print(f"\n\n[+] [{region}] Browse catalog complete: {len(products)} products "
          f"in {page - 1} pages, {errors} errors")
    return products


# Map emerald "availableOn" values to display names
BROWSE_PLATFORM_MAP = {
    "XboxSeriesX":    "Xbox Series X|S",
    "XboxOne":        "Xbox One",
    "PC":             "PC",
    "XCloud":         "Cloud",
    "Handheld":       "Handheld",
    "Mobile":         "Mobile",
}


def browse_to_marketplace(products, gamertag=""):
    """Convert emerald browse productSummaries to marketplace item format."""
    # Load entitlements to check "owned" status
    owned_pids = set()
    if os.path.isfile(ENTITLEMENTS_FILE):
        try:
            entitlements = load_json(ENTITLEMENTS_FILE)
            owned_pids = set(e["productId"] for e in entitlements if e.get("productId"))
        except Exception:
            pass

    mkt_items = []
    for p in products:
        pid = p.get("productId", "")
        if not pid:
            continue
        title = p.get("title", "")
        if not title:
            continue

        # Map platforms
        platforms = []
        for plat in p.get("availableOn", []):
            mapped = BROWSE_PLATFORM_MAP.get(plat, plat)
            if mapped and mapped not in platforms:
                platforms.append(mapped)

        # Extract prices
        prices = p.get("specificPrices", {})
        purchase = prices.get("purchaseable", [])
        msrp = 0
        current = 0
        if purchase:
            msrp = purchase[0].get("msrp", 0) or 0
            current = purchase[0].get("listPrice", 0) or 0

        # Images
        images = p.get("images", {})
        box_art = images.get("boxArt", {}).get("url", "")
        poster = images.get("poster", {}).get("url", "")
        hero = images.get("superHeroArt", {}).get("url", "")

        # Categories as channel
        categories = p.get("categories", [])

        mkt_items.append({
            "productId": pid,
            "title": title,
            "publisher": p.get("publisherName", ""),
            "developer": p.get("developerName", ""),
            "category": categories[0] if categories else "",
            "releaseDate": p.get("releaseDate", ""),
            "platforms": platforms,
            "priceUSD": msrp,
            "currentPriceUSD": current,
            "image": poster or box_art,
            "boxArt": box_art,
            "heroImage": hero,
            "productKind": _norm_kind(p.get("productKind", "")),
            "channels": ["Browse Catalog"],
            "owned": pid in owned_pids,
            "xboxTitleId": "",
            "description": p.get("shortDescription", ""),
            "averageRating": p.get("averageRating", 0),
            "ratingCount": p.get("ratingCount", 0),
        })

    print(f"[+] Converted {len(mkt_items)} browse products to marketplace format")
    return mkt_items


def _merge_marketplace(existing, new_items):
    """Merge new marketplace items into existing, combining channel lists.

    Items matched by productId. Existing items keep their data but gain new
    channels. New items not in existing are appended.
    """
    by_pid = {}
    for item in existing:
        pid = item.get("productId", "")
        if pid:
            by_pid[pid] = item

    added = 0
    updated = 0
    for item in new_items:
        pid = item.get("productId", "")
        if not pid:
            continue
        if pid in by_pid:
            # Merge channels
            old_channels = by_pid[pid].get("channels", [])
            new_channels = item.get("channels", [])
            merged = list(old_channels)
            for ch in new_channels:
                if ch not in merged:
                    merged.append(ch)
            by_pid[pid]["channels"] = merged
            # Update owned status (may have changed)
            by_pid[pid]["owned"] = item.get("owned", by_pid[pid].get("owned", False))
            updated += 1
        else:
            by_pid[pid] = item
            added += 1

    print(f"  Merge: {updated} updated, {added} new, {len(by_pid)} total")
    return list(by_pid.values())


def fetch_browse_all_regions(auth_token, gamertag=""):
    """Scan all regions and merge results, tagging region-exclusive items.

    Scans each locale in BROWSE_REGIONS, then:
    - Items in ALL regions get channel "Browse Catalog"
    - Items missing from US get flagged with country codes where they DO appear
    """
    region_products = {}  # locale -> {pid: product_summary}

    first_region = True
    for locale, code in BROWSE_REGIONS.items():
        if not first_region:
            print(f"\n  Cooling down 15s between regions...")
            time.sleep(15)
        first_region = False
        print(f"\n{'=' * 60}")
        print(f"  Region: {code} ({locale})")
        print(f"{'=' * 60}\n")
        products = fetch_browse_all(auth_token, locale=locale)
        pid_map = {}
        for p in products:
            pid = p.get("productId", "")
            if pid:
                pid_map[pid] = p
        region_products[locale] = pid_map
        print(f"  [{code}] {len(pid_map)} products")

    # Determine which regions each product appears in
    all_pids = set()
    for pid_map in region_products.values():
        all_pids.update(pid_map.keys())

    us_pids = set(region_products.get("en-US", {}).keys())

    # Build unified product list with region tags
    # Use US data as primary, fall back to first region that has the item
    unified = []
    region_exclusive_count = 0

    for pid in sorted(all_pids):
        # Find regions this product appears in
        found_in = []
        for locale, code in BROWSE_REGIONS.items():
            if pid in region_products[locale]:
                found_in.append(code)

        # Pick best product data (prefer US, then GB, then first available)
        product = None
        for pref_locale in ["en-US", "en-GB"]:
            if pid in region_products.get(pref_locale, {}):
                product = region_products[pref_locale][pid]
                break
        if not product:
            for pid_map in region_products.values():
                if pid in pid_map:
                    product = pid_map[pid]
                    break

        if not product:
            continue

        # Tag region exclusives (not in US catalog)
        region_tags = []
        if pid not in us_pids:
            region_tags = found_in
            region_exclusive_count += 1

        # Store regions info on the product for browse_to_marketplace
        product["_regions"] = found_in
        product["_region_tags"] = region_tags
        unified.append(product)

    print(f"\n{'=' * 60}")
    print(f"  Multi-region scan summary:")
    for locale, code in BROWSE_REGIONS.items():
        print(f"    {code}: {len(region_products.get(locale, {}))} products")
    print(f"    Combined: {len(unified)} unique products")
    print(f"    Region exclusives (not in US): {region_exclusive_count}")
    print(f"{'=' * 60}")

    return unified


def browse_to_marketplace_multi(products, gamertag=""):
    """Convert multi-region browse products to marketplace items with region tags."""
    owned_pids = set()
    if os.path.isfile(ENTITLEMENTS_FILE):
        try:
            entitlements = load_json(ENTITLEMENTS_FILE)
            owned_pids = set(e["productId"] for e in entitlements if e.get("productId"))
        except Exception:
            pass

    mkt_items = []
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

        prices = p.get("specificPrices", {})
        purchase = prices.get("purchaseable", [])
        msrp = 0
        current = 0
        if purchase:
            msrp = purchase[0].get("msrp", 0) or 0
            current = purchase[0].get("listPrice", 0) or 0

        images = p.get("images", {})
        box_art = images.get("boxArt", {}).get("url", "")
        poster = images.get("poster", {}).get("url", "")
        hero = images.get("superHeroArt", {}).get("url", "")

        categories = p.get("categories", [])
        region_tags = p.get("_region_tags", [])

        # Build channel list
        channels = ["Browse Catalog"]
        for code in region_tags:
            tag = f"Region: {code}"
            if tag not in channels:
                channels.append(tag)

        mkt_items.append({
            "productId": pid,
            "title": title,
            "publisher": p.get("publisherName", ""),
            "developer": p.get("developerName", ""),
            "category": categories[0] if categories else "",
            "releaseDate": p.get("releaseDate", ""),
            "platforms": platforms,
            "priceUSD": msrp,
            "currentPriceUSD": current,
            "image": poster or box_art,
            "boxArt": box_art,
            "heroImage": hero,
            "productKind": _norm_kind(p.get("productKind", "")),
            "channels": channels,
            "owned": pid in owned_pids,
            "xboxTitleId": "",
            "description": p.get("shortDescription", ""),
            "averageRating": p.get("averageRating", 0),
            "ratingCount": p.get("ratingCount", 0),
            "regions": p.get("_regions", []),
        })

    region_only = sum(1 for x in mkt_items if len(x["channels"]) > 1)
    print(f"[+] Converted {len(mkt_items)} products ({region_only} region-tagged)")
    return mkt_items


# ===========================================================================
# TitleHub coarse ID scanner
# ===========================================================================


def _titlehub_scan_file(locale):
    """Return per-locale TitleHub scan state file path."""
    code = BROWSE_REGIONS.get(locale, locale).lower()
    return os.path.join(SCRIPT_DIR, f"titlehub_scan_{code}.json")


def scan_titlehub_coarse(auth_token_xl, locale="en-GB"):
    """Probe TitleHub IDs from 1B to 2B in steps of 1000 to map title density.

    Sends batches of 500 probe IDs to the TitleHub batch endpoint.
    Supports resume via titlehub_scan_{region}.json checkpoint file.
    Returns dict of {titleId: title_data}.
    """
    state_file = _titlehub_scan_file(locale)
    region = BROWSE_REGIONS.get(locale, locale)
    range_start = 1_000_000_000
    range_end   = 2_000_000_000
    step        = 1000
    batch_size  = 500
    total_probes = (range_end - range_start) // step  # 1,000,000
    total_batches = (total_probes + batch_size - 1) // batch_size  # 2,000

    # Load or initialize state
    state = None
    if os.path.isfile(state_file):
        try:
            state = load_json(state_file)
        except Exception:
            state = None

    if (state and state.get("version") == 1
            and state.get("range_start") == range_start
            and state.get("step") == step
            and state.get("batches_completed", 0) < total_batches):
        start_batch = state["batches_completed"]
        titles = state.get("titles", {})
        errors = state.get("errors", 0)
        print(f"[*] [{region}] Resuming coarse scan from batch {start_batch}/{total_batches} "
              f"({len(titles)} titles found so far)")
    else:
        start_batch = 0
        titles = {}
        errors = 0
        state = {
            "version": 1,
            "range_start": range_start,
            "range_end": range_end,
            "step": step,
            "batch_size": batch_size,
            "locale": locale,
            "started": _dt.datetime.now().isoformat(timespec="seconds"),
            "last_updated": "",
            "next_probe_index": 0,
            "total_probes": total_probes,
            "batches_completed": 0,
            "batches_total": total_batches,
            "titles_found": 0,
            "errors": 0,
            "titles": {},
        }
        print(f"[*] [{region}] Starting coarse TitleHub scan: {total_probes:,} probes in "
              f"{total_batches:,} batches (step={step})")

    if start_batch >= total_batches:
        print(f"[+] [{region}] Scan already complete: {len(titles)} titles")
        return titles

    url = "https://titlehub.xboxlive.com/titles/batch/decoration/Image,ProductId"
    t0 = time.time()

    def _save_state(batch_idx):
        state["last_updated"] = _dt.datetime.now().isoformat(timespec="seconds")
        state["batches_completed"] = batch_idx
        state["next_probe_index"] = batch_idx * batch_size
        state["titles_found"] = len(titles)
        state["errors"] = errors
        state["titles"] = titles
        save_json(state_file, state)

    try:
        for b in range(start_batch, total_batches):
            probe_start = b * batch_size
            probe_ids = [
                str(range_start + (probe_start + j) * step)
                for j in range(batch_size)
                if (probe_start + j) < total_probes
            ]

            cv = base64.b64encode(os.urandom(12)).decode().rstrip("=") + ".0"
            body = json.dumps({"pfns": None, "titleIds": probe_ids}).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers={
                "Authorization": auth_token_xl,
                "Content-Type": "application/json",
                "x-xbl-contract-version": "2",
                "Accept-Language": locale,
                "MS-CV": cv,
                "Accept": "application/json",
            })

            hits = 0
            for attempt in range(5):
                try:
                    with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as resp:
                        data = json.loads(resp.read())
                    for title in data.get("titles", []):
                        tid = str(title.get("titleId", ""))
                        if tid and tid not in titles:
                            titles[tid] = {
                                "titleId": tid,
                                "name": title.get("name", ""),
                                "productId": title.get("productId", ""),
                                "devices": title.get("devices", []),
                                "image": (title.get("images", [{}])[0].get("url", "")
                                          if title.get("images") else ""),
                            }
                            hits += 1
                    break
                except urllib.error.HTTPError as e:
                    if e.code == 401:
                        print(f"\n[!] HTTP 401 — token expired. Refresh token and retry.")
                        _save_state(b)
                        return titles
                    if e.code == 429 and attempt < 4:
                        wait = 2 ** (attempt + 1)
                        print(f"\n    HTTP 429 — rate limited, waiting {wait}s...")
                        time.sleep(wait)
                        continue
                    errors += 1
                    break
                except Exception:
                    if attempt < 4:
                        time.sleep(2 ** attempt)
                        continue
                    errors += 1
                    break

            # Progress line
            done = b + 1
            elapsed = time.time() - t0
            batches_done_session = done - start_batch
            if batches_done_session > 0:
                eta_s = elapsed / batches_done_session * (total_batches - done)
                eta_m = eta_s / 60
            else:
                eta_m = 0
            id_lo = range_start + b * batch_size * step
            id_hi = id_lo + batch_size * step
            rate = len(titles) / max(done, 1) * 100 / batch_size
            print(f"\r  [{region}] Batch {done}/{total_batches}  "
                  f"IDs {id_lo}-{id_hi}  "
                  f"+{hits} hits  total={len(titles)}  "
                  f"rate={rate:.2f}%  "
                  f"ETA {eta_m:.0f}m   ", end="", flush=True)

            # Checkpoint every 50 batches
            if done % 50 == 0:
                _save_state(done)
                print(f"\n  [checkpoint] batch {done}/{total_batches}, "
                      f"{len(titles)} titles, {errors} errors, "
                      f"{elapsed:.0f}s elapsed")

            time.sleep(0.1)  # baseline politeness delay

    except KeyboardInterrupt:
        print(f"\n\n[!] [{region}] Interrupted at batch {b + 1}/{total_batches}")
        _save_state(b + 1)
        print(f"    Progress saved to {state_file}")
        return titles

    # Final save
    _save_state(total_batches)
    print(f"\n\n[+] [{region}] Scan complete: {len(titles)} titles found in "
          f"{total_batches} batches, {errors} errors")
    return titles


def scan_titlehub_all_regions(auth_token_xl):
    """Run coarse TitleHub scan across all regions, merge and tag exclusives."""
    region_titles = {}  # locale -> {tid: title_data}

    for locale, code in BROWSE_REGIONS.items():
        print(f"\n{'=' * 60}")
        print(f"  TitleHub region: {code} ({locale})")
        print(f"{'=' * 60}\n")
        titles = scan_titlehub_coarse(auth_token_xl, locale=locale)
        region_titles[locale] = titles
        print(f"  [{code}] {len(titles)} titles")

    # Merge all titles, tag region exclusives
    all_tids = set()
    for titles in region_titles.values():
        all_tids.update(titles.keys())

    gb_tids = set(region_titles.get("en-GB", {}).keys())
    us_tids = set(region_titles.get("en-US", {}).keys())
    base_tids = gb_tids | us_tids  # titles in either US or GB

    merged = {}
    region_exclusive_count = 0
    for tid in sorted(all_tids):
        # Find which regions have this title
        found_in = []
        for locale, code in BROWSE_REGIONS.items():
            if tid in region_titles[locale]:
                found_in.append(code)

        # Pick best data (prefer GB, then US, then first available)
        title_data = None
        for pref in ["en-GB", "en-US"]:
            if tid in region_titles.get(pref, {}):
                title_data = dict(region_titles[pref][tid])
                break
        if not title_data:
            for titles in region_titles.values():
                if tid in titles:
                    title_data = dict(titles[tid])
                    break

        if not title_data:
            continue

        title_data["_regions"] = found_in
        if tid not in base_tids:
            title_data["_region_tags"] = found_in
            region_exclusive_count += 1
        else:
            title_data["_region_tags"] = []

        merged[tid] = title_data

    print(f"\n{'=' * 60}")
    print(f"  TitleHub multi-region summary:")
    for locale, code in BROWSE_REGIONS.items():
        print(f"    {code}: {len(region_titles.get(locale, {}))} titles")
    print(f"    Combined: {len(merged)} unique titles")
    print(f"    Region exclusives (not in US/GB): {region_exclusive_count}")
    print(f"{'=' * 60}")

    print_density_report(merged)
    return merged


def print_density_report(titles):
    """Print density histogram and top-10 densest sub-ranges."""
    if not titles:
        print("\n  No titles found — nothing to report.")
        return

    range_start = 1_000_000_000
    range_end   = 2_000_000_000

    # 100M buckets (10 buckets)
    bucket_size = 100_000_000
    buckets = [0] * 10
    # 10M sub-ranges (100 sub-ranges)
    sub_size = 10_000_000
    sub_buckets = [0] * 100

    for tid_str in titles:
        try:
            tid = int(tid_str)
        except ValueError:
            continue
        if range_start <= tid < range_end:
            buckets[(tid - range_start) // bucket_size] += 1
            sub_buckets[(tid - range_start) // sub_size] += 1

    max_count = max(buckets) if buckets else 1
    bar_width = 40

    print(f"\n  === Density Report ({len(titles)} titles) ===\n")
    print("  100M Bucket Histogram:")
    for i, count in enumerate(buckets):
        lo = range_start + i * bucket_size
        hi = lo + bucket_size
        bar_len = int(count / max(max_count, 1) * bar_width)
        bar = "#" * bar_len
        print(f"    {lo/1e9:.1f}B-{hi/1e9:.1f}B  {bar:<{bar_width}} {count:>5}")

    # Top 10 densest 10M sub-ranges
    ranked = sorted(enumerate(sub_buckets), key=lambda x: x[1], reverse=True)
    top10 = [(i, c) for i, c in ranked if c > 0][:10]
    if top10:
        print(f"\n  Top {len(top10)} densest 10M sub-ranges:")
        for i, count in top10:
            lo = range_start + i * sub_size
            hi = lo + sub_size
            print(f"    {lo:>13,} - {hi:>13,}  ({count} titles)")


# ===========================================================================
# Process all accounts
# ===========================================================================

def process_all_accounts():
    """Refresh tokens, process all accounts, and build a combined HTML.

    Prompts for data source once and applies to all accounts.
    """
    accounts = load_accounts()
    if not accounts:
        print("No accounts found. Use 'add' to set up an account.")
        return

    gamertags = list(accounts.keys())

    # Single data-source prompt for all accounts
    print()
    print("  Data source for all accounts:")
    print("    [B] Both (recommended)      - full collection + game metadata")
    print("    [C] Collections API only    - all entitlements (~5000)")
    print("    [T] TitleHub only           - games with metadata (~1000)")
    print()
    pick = input("  Pick [B/C/T, default=B]: ").strip().upper()
    if pick == "C":
        method = "collection"
    elif pick == "T":
        method = "titlehub"
    else:
        method = "both"

    results = []
    all_libraries = []

    for gt in gamertags:
        print()
        print("=" * 64)
        print(f"  Processing: {gt}")
        print("=" * 64)

        # Refresh token
        print(f"\n[*] Refreshing token for {gt}...")
        ok = refresh_account_token(gt)
        if not ok:
            print(f"[!] Token refresh failed for {gt} — skipping")
            results.append((gt, False, "Token refresh failed"))
            continue

        # Process account with chosen method
        try:
            html_file, lib = process_account(gt, method=method)
            results.append((gt, True, html_file))
            all_libraries.extend(lib)
        except Exception as e:
            print(f"[!] Failed to process {gt}: {e}")
            results.append((gt, False, str(e)))

    # Summary
    print()
    print("=" * 64)
    print("  Summary")
    print("=" * 64)
    for gt, ok, info in results:
        status = "OK" if ok else "FAILED"
        print(f"  {gt}: {status}" + (f" — {info}" if not ok else ""))

    # Build combined HTML if we have libraries from multiple accounts
    if all_libraries:
        # Collect scan history + marketplace from all accounts
        all_scan_history = []
        all_mkt = []
        for gt in gamertags:
            set_account_paths(gt)
            all_scan_history.extend(load_all_scans(gt, max_scans=50))
            if not all_mkt and os.path.isfile(MARKETPLACE_FILE):
                all_mkt = load_json(MARKETPLACE_FILE) or []
        # Sort combined history by timestamp descending
        all_scan_history.sort(key=lambda s: s.get("timestamp", ""), reverse=True)

        print()
        combined_path = os.path.join(ACCOUNTS_DIR, "XCT.html")
        combined_data_js = os.path.join(ACCOUNTS_DIR, "data.js")
        os.makedirs(ACCOUNTS_DIR, exist_ok=True)

        acct_meta = collect_account_metadata()
        write_data_js(all_libraries, _load_gp_details(), all_scan_history[:100], combined_data_js,
                      marketplace=all_mkt, accounts_meta=acct_meta)

        if not os.path.isfile(combined_path):
            print("[*] Creating combined HTML template...")
            combined_html = build_html_template(gamertag="All Accounts")
            with open(combined_path, "w", encoding="utf-8") as f:
                f.write(combined_html)

        print(f"[+] Combined: {combined_path} ({len(all_libraries)} items)")

        file_url = "file:///" + combined_path.replace("\\", "/").replace(" ", "%20")
        print(f"[*] Opening combined HTML: {file_url}")
        webbrowser.open(file_url)


def process_contentaccess_only(gamertag):
    """Run only the Content Access + Xbox 360 identification pipeline.

    Skips the full Collections/TitleHub entitlements fetch.
    Uses existing entitlements from cache, adds any new contentaccess IDs,
    fetches catalog for new items, identifies Xbox 360 via TitleHub batch,
    and rebuilds the library.
    """
    set_account_paths(gamertag)
    acct = account_dir(gamertag)
    banner(gamertag)

    auth_token = read_auth_token(optional=False)
    auth_token_xl = _read_xl_token()
    if not auth_token:
        print("[!] auth_token.txt required for Content Access")
        return None, []
    if not auth_token_xl:
        print("[!] auth_token_xl.txt required for TitleHub batch")
        return None, []

    # Load existing entitlements from cache
    if os.path.isfile(ENTITLEMENTS_FILE):
        entitlements = load_json(ENTITLEMENTS_FILE)
        print(f"[+] Loaded {len(entitlements)} existing entitlements from cache")
    else:
        print("[!] No cached entitlements — run a full scan first")
        return None, []

    existing_pids = set(e["productId"] for e in entitlements if e["productId"])

    # Force-refresh contentaccess (delete cache to bypass TTL)
    if os.path.isfile(CONTENTACCESS_FILE):
        os.remove(CONTENTACCESS_FILE)

    ca_pids = fetch_contentaccess(auth_token, cache_file=CONTENTACCESS_FILE)
    if not ca_pids:
        print("[!] Content Access returned no data")
        return None, []

    ca_new_pids = [pid for pid in ca_pids if pid not in existing_pids]
    print(f"  Content Access: {len(ca_pids)} total, {len(ca_new_pids)} new")

    if not ca_new_pids:
        print("  No new items from Content Access")
    else:
        for pid in ca_new_pids:
            entitlements.append({
                "productId": pid,
                "productKind": "",
                "status": "Active",
                "acquiredDate": "",
                "startDate": "",
                "endDate": "",
                "isTrial": False,
                "skuType": "",
                "skuId": "",
                "purchasedCountry": "",
                "quantity": 1,
                "_contentaccess_only": True,
            })
        save_json(ENTITLEMENTS_FILE, entitlements)

    # Fetch catalog for new items
    if ca_new_pids:
        print(f"  Fetching catalog for {len(ca_new_pids)} new items...")
        ca_catalog = fetch_catalog_v3(
            ca_new_pids, auth_token_xl, market="US", lang="en-US",
            cache_file=None, label="Catalog v3 (contentaccess)")
        if ca_catalog:
            # Merge into existing v3 cache
            v3_data = load_json(CATALOG_V3_US_FILE) if os.path.isfile(CATALOG_V3_US_FILE) else {}
            v3_data.update(ca_catalog)
            save_json(CATALOG_V3_US_FILE, v3_data)

    # Load full catalog for merge
    catalog_us = load_json(CATALOG_V3_US_FILE) if os.path.isfile(CATALOG_V3_US_FILE) else {}

    # Identify Xbox 360 games via TitleHub batch
    # Check ALL contentaccess-only items, not just newly added ones
    ca_all_pids = [e["productId"] for e in entitlements if e.get("_contentaccess_only")]
    pid_to_titleid = {}
    for pid in ca_all_pids:
        cat_entry = catalog_us.get(pid, {})
        if "Xbox 360" in cat_entry.get("platforms", []):
            continue  # already tagged
        for alt in cat_entry.get("alternateIds", []):
            if alt.get("idType") == "XBOXTITLEID":
                pid_to_titleid[pid] = alt["id"]
                break

    if pid_to_titleid:
        title_ids = list(pid_to_titleid.values())
        print(f"  Checking {len(title_ids)} items via TitleHub batch for Xbox 360...")
        th_results = fetch_titlehub_batch(title_ids, auth_token_xl)

        xbox360_count = 0
        for pid, title_data in th_results.items():
            devices = title_data.get("devices", [])
            if "Xbox360" in devices:
                if pid in catalog_us:
                    catalog_us[pid]["platforms"] = ["Xbox 360"]
                    for dev in devices:
                        mapped = {"XboxOne": "Xbox One",
                                  "XboxSeries": "Xbox Series X|S",
                                  "PC": "PC"}.get(dev)
                        if mapped and mapped not in catalog_us[pid]["platforms"]:
                            catalog_us[pid]["platforms"].append(mapped)
                xbox360_count += 1

        if xbox360_count:
            print(f"  Tagged {xbox360_count} Xbox 360 games")
            save_json(CATALOG_V3_US_FILE, catalog_us)
    else:
        already_360 = sum(1 for pid in ca_all_pids
                          if "Xbox 360" in catalog_us.get(pid, {}).get("platforms", []))
        if already_360:
            print(f"  Xbox 360: {already_360} items already tagged")

    # Merge and rebuild
    library, play_history = merge_library(entitlements, catalog_us, gamertag=gamertag)
    print(f"  Library: {len(library)} items, Play history: {len(play_history)} items")

    save_json(LIBRARY_FILE, library)
    save_json(PLAY_HISTORY_FILE, play_history)

    scan_history = load_all_scans(gamertag)
    data_js_path = os.path.join(acct, "data.js")
    ca_mkt = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
    acct_meta = collect_account_metadata()
    write_data_js(library, _load_gp_details(), scan_history, data_js_path, play_history,
                  marketplace=ca_mkt, accounts_meta=acct_meta)

    if not os.path.isfile(OUTPUT_HTML_FILE):
        html = build_html_template(gamertag=gamertag)
        with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
            f.write(html)

    print(f"[+] Done: {OUTPUT_HTML_FILE}")
    return OUTPUT_HTML_FILE, library


# ===========================================================================
# Unified Interactive Menu
# ===========================================================================

def _pick_account(gamertags, prompt="Which account?", allow_all=True):
    """Prompt user to pick an account. Returns gamertag, '*', or None."""
    if len(gamertags) == 1:
        return gamertags[0]
    print()
    for i, gt in enumerate(gamertags, 1):
        print(f"    [{i}] {gt}")
    if allow_all:
        print(f"    [*] All accounts")
    print()
    sp = input(f"  {prompt} [1-{len(gamertags)}{', *' if allow_all else ''}]: ").strip()
    if allow_all and sp == "*":
        return "*"
    try:
        idx = int(sp) - 1
        if 0 <= idx < len(gamertags):
            return gamertags[idx]
    except ValueError:
        pass
    print("  Invalid selection.")
    return None


def interactive_menu():
    """Unified interactive menu for all operations."""
    accounts = load_accounts()

    if not accounts:
        print("No accounts found. Starting new account setup...")
        print()
        cmd_add()
        # After adding, fall through to menu loop
        accounts = load_accounts()
        if not accounts:
            return

    while True:
        accounts = load_accounts()
        gamertags = list(accounts.keys())

        if not gamertags:
            print("No accounts configured.")
            return

        print_header()
        print("  Accounts (process library):")

        for i, gt in enumerate(gamertags, 1):
            age = token_age_str(gt)
            print(f"    [{i}] {gt} (token: {age})")

        print()
        print("  Scan endpoints:")
        print("    [E] Collections API only")
        print("    [T] TitleHub only")
        print("    [S] Content Access only (Xbox 360)")
        print()
        print("  Catalogs:")
        print("    [G] Game Pass Library")
        print("    [M] Full Marketplace")
        print("    [L] Full Marketplace (all regions)")
        print("    [P] Regional Prices (enrich marketplace)")
        print("    [N] New Games")
        print("    [C] Coming Soon")
        print("    [F] Game Demos")
        print()
        print("  Discovery:")
        print("    [W] Web Browse catalog (US only)")
        print("    [Z] Web Browse catalog (all 7 regions)")
        print("    [H] TitleHub ID scan (coarse, all regions)")
        print("    [Y] Full discovery (Marketplace + Browse + TitleHub, all regions)")
        print()
        print("  Account management:")
        print("    [A] Add new account")
        print("    [R] Refresh token on existing account")
        print("    [D] Delete an account")
        print("    [*] Process all accounts")
        print("    [X] Clear cache + rescan all accounts")
        print("    [B] Build index (rebuild HTML from cache)")
        print("    [Q] Quit")
        print()

        pick = input(f"  Pick [1-{len(gamertags)}, E, T, S, G, M, L, P, N, C, F, W, Z, H, Y, A, R, D, *, X, B, Q]: ").strip()
        pu = pick.upper()

        if pu == "Q":
            break
        elif pu == "A":
            cmd_add()
            continue
        elif pu == "R":
            if len(gamertags) == 1:
                gt = gamertags[0]
            else:
                print()
                for i, gt in enumerate(gamertags, 1):
                    print(f"    [{i}] {gt} (token: {token_age_str(gt)})")
                print()
                rp = input(f"  Refresh which account? [1-{len(gamertags)}]: ").strip()
                try:
                    idx = int(rp) - 1
                    if 0 <= idx < len(gamertags):
                        gt = gamertags[idx]
                    else:
                        print("  Invalid selection.")
                        continue
                except ValueError:
                    print("  Invalid selection.")
                    continue
            print(f"\n[*] Refreshing token for {gt}...")
            refresh_account_token(gt)
            process_now = input("\n  Process library now? [Y/n]: ").strip().lower()
            if process_now not in ("n", "no"):
                html_file, _lib = process_account(gt)
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
            continue
        elif pu == "D":
            if len(gamertags) == 1:
                gt = gamertags[0]
                delete_account(gt)
            else:
                print()
                for i, gt in enumerate(gamertags, 1):
                    print(f"    [{i}] {gt}")
                print()
                dp = input(f"  Delete which account? [1-{len(gamertags)}]: ").strip()
                try:
                    idx = int(dp) - 1
                    if 0 <= idx < len(gamertags):
                        delete_account(gamertags[idx])
                    else:
                        print("  Invalid selection.")
                except ValueError:
                    print("  Invalid selection.")
            continue
        elif pick == "*":
            process_all_accounts()
            continue
        elif pu == "E":
            gt = _pick_account(gamertags, "Collections API scan for which account?")
            if gt == "*":
                for g in gamertags:
                    if _is_token_expired(g):
                        _auto_refresh_token(g)
                    process_account(g, method="collection")
                build_index()
            elif gt:
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                html_file, _lib = process_account(gt, method="collection")
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                webbrowser.open(file_url)
            continue
        elif pu == "T":
            gt = _pick_account(gamertags, "TitleHub scan for which account?")
            if gt == "*":
                for g in gamertags:
                    if _is_token_expired(g):
                        _auto_refresh_token(g)
                    process_account(g, method="titlehub")
                build_index()
            elif gt:
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                html_file, _lib = process_account(gt, method="titlehub")
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                webbrowser.open(file_url)
            continue
        elif pu == "S":
            gt = _pick_account(gamertags, "Content Access scan for which account?")
            if gt == "*":
                for g in gamertags:
                    if _is_token_expired(g):
                        _auto_refresh_token(g)
                    process_contentaccess_only(g)
                html_file = build_index()
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            elif gt:
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                html_file, _lib = process_contentaccess_only(gt)
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "X":
            print()
            print("  This will delete all cached API data and rescan every account.")
            confirm = input("  Are you sure? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                for gt in gamertags:
                    clear_api_cache(gt)
                process_all_accounts()
            continue
        elif pu == "B":
            html_file = build_index()
            if html_file:
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
            continue
        elif pu == "G":
            process_gamepass_library()
            continue
        elif pu == "M":
            gt = _pick_account(gamertags, "Marketplace scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                html_file, _mkt = process_marketplace(gt)
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "L":
            gt = _pick_account(gamertags, "All-regions marketplace using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                html_file, _mkt = process_marketplace_all_regions(gt)
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "P":
            gt = _pick_account(gamertags, "Regional prices using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                set_account_paths(gt)
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                acct = account_dir(gt)
                auth_token_xl = _read_xl_token()
                if not auth_token_xl:
                    print("[!] auth_token_xl.txt required for regional pricing")
                    continue
                mkt_file = os.path.join(acct, "marketplace.json")
                if not os.path.isfile(mkt_file):
                    print("[!] No marketplace.json found. Run [M] Full Marketplace first.")
                    continue
                mkt_items = load_json(mkt_file)
                print(f"[*] Enriching {len(mkt_items)} marketplace items with regional prices...")
                mkt_items = enrich_regional_prices(mkt_items, auth_token_xl)
                save_json(mkt_file, mkt_items)
                # Rebuild data.js and HTML
                library = load_json(LIBRARY_FILE) if os.path.isfile(LIBRARY_FILE) else []
                play_history = load_json(PLAY_HISTORY_FILE) if os.path.isfile(PLAY_HISTORY_FILE) else []
                scan_history = load_all_scans(gt)
                acct_meta = collect_account_metadata()
                data_js_path = os.path.join(acct, "data.js")
                write_data_js(library, _load_gp_details(), scan_history, data_js_path, play_history,
                              marketplace=mkt_items, accounts_meta=acct_meta)
                html = build_html_template(gamertag=gt)
                with open(OUTPUT_HTML_FILE, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"[+] Done: {OUTPUT_HTML_FILE}")
                file_url = "file:///" + OUTPUT_HTML_FILE.replace("\\", "/").replace(" ", "%20")
                webbrowser.open(file_url)
            continue
        elif pu == "N":
            gt = _pick_account(gamertags, "New Games scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                html_file, _mkt = process_marketplace(gt, channels=["MobileNewGames"])
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "C":
            gt = _pick_account(gamertags, "Coming Soon scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                html_file, _mkt = process_marketplace(gt, channels=["GamesComingSoon"])
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "F":
            gt = _pick_account(gamertags, "Game Demos scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                html_file, _mkt = process_marketplace(gt, channels=["GameDemos"])
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "W":
            gt = _pick_account(gamertags, "Browse catalog using which account?", allow_all=False)
            if gt:
                set_account_paths(gt)
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                # Try both tokens — emerald endpoint RP is unknown
                auth = read_auth_token(optional=True)
                auth_xl = _read_xl_token()
                token = auth_xl or auth
                if not token:
                    print(f"[!] No auth token for {gt}. Refresh token first.")
                else:
                    print(f"  Using {'xl' if token == auth_xl else 'mp'} token")
                    products = fetch_browse_all(token)
                    if products:
                        browse_items = browse_to_marketplace(products, gt)
                        # Merge with existing marketplace data (keep old channels)
                        existing = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
                        mkt_items = _merge_marketplace(existing, browse_items)
                        save_json(MARKETPLACE_FILE, mkt_items)
                        print(f"[+] Saved {len(mkt_items)} marketplace items")
                        # Rebuild all HTML (per-account + combined index)
                        html_file = build_index()
                        if html_file:
                            file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                            webbrowser.open(file_url)
            continue
        elif pu == "Z":
            gt = _pick_account(gamertags, "Multi-region browse using which account?", allow_all=False)
            if gt:
                set_account_paths(gt)
                if _is_token_expired(gt):
                    _auto_refresh_token(gt)
                auth = read_auth_token(optional=True)
                auth_xl = _read_xl_token()
                token = auth_xl or auth
                if not token:
                    print(f"[!] No auth token for {gt}. Refresh token first.")
                else:
                    print(f"  Using {'xl' if token == auth_xl else 'mp'} token")
                    products = fetch_browse_all_regions(token, gt)
                    if products:
                        browse_items = browse_to_marketplace_multi(products, gt)
                        existing = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
                        mkt_items = _merge_marketplace(existing, browse_items)
                        save_json(MARKETPLACE_FILE, mkt_items)
                        print(f"[+] Saved {len(mkt_items)} marketplace items")
                        html_file = build_index()
                        if html_file:
                            file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                            webbrowser.open(file_url)
            continue
        elif pu == "Y":
            gt = _pick_account(gamertags, "Full discovery using which account?", allow_all=False)
            if gt:
                html_file = None

                # Step 1: Marketplace channels (bronze endpoint)
                print("\n=== Step 1/3: Marketplace channels ===\n")
                html_file, _mkt = process_marketplace(gt)

                # Step 2: Browse catalog all regions (emerald endpoint) + merge
                print("\n=== Step 2/3: Browse catalog (all regions) ===\n")
                set_account_paths(gt)
                auth = read_auth_token(optional=True)
                auth_xl = _read_xl_token()
                token = auth_xl or auth
                if token:
                    print(f"  Using {'xl' if token == auth_xl else 'mp'} token")
                    products = fetch_browse_all_regions(token, gt)
                    if products:
                        browse_items = browse_to_marketplace_multi(products, gt)
                        existing = load_json(MARKETPLACE_FILE) if os.path.isfile(MARKETPLACE_FILE) else []
                        mkt_items = _merge_marketplace(existing, browse_items)
                        save_json(MARKETPLACE_FILE, mkt_items)
                        print(f"[+] Saved {len(mkt_items)} marketplace items")
                else:
                    print("[!] No auth token for browse — skipping step 2")

                # Step 3: TitleHub coarse scan (all regions)
                print("\n=== Step 3/3: TitleHub ID scan (all regions) ===\n")
                set_account_paths(gt)
                xl_token = _read_xl_token()
                if xl_token:
                    scan_titlehub_all_regions(xl_token)
                else:
                    print("[!] No xl token — skipping TitleHub scan")

                # Final rebuild
                html_file = build_index()
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
            continue
        elif pu == "H":
            gt = _pick_account(gamertags, "TitleHub scan using which account?", allow_all=False)
            if gt:
                set_account_paths(gt)
                xl_token = _read_xl_token()
                if not xl_token:
                    print(f"[!] No xl token for {gt}. Refresh token first.")
                else:
                    scan_titlehub_all_regions(xl_token)
            continue
        else:
            try:
                idx = int(pick) - 1
                if 0 <= idx < len(gamertags):
                    gt = gamertags[idx]
                    # Refresh token (clears API cache) so we always get fresh data
                    print(f"\n[*] Refreshing token for {gt}...")
                    refresh_account_token(gt)
                    html_file, _lib = process_account(gt, method="both")
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    print(f"[*] Opening in browser: {file_url}")
                    webbrowser.open(file_url)
                    continue
                else:
                    print("  Invalid selection.")
            except ValueError:
                print("  Invalid selection.")


# ===========================================================================
# Auto-Update
# ===========================================================================

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/freshdex/xbox-collection-tracker/main"
UPDATE_FILES = ["XCT.py", "xbox_auth.py", "requirements.txt", "tags.json"]

def _parse_version(v):
    """Parse version string like '1.2' into comparable tuple (1, 2)."""
    return tuple(int(x) for x in v.strip().split("."))

def check_for_updates():
    """Check GitHub for a newer version and offer to auto-update."""
    try:
        req = urllib.request.Request(f"{GITHUB_RAW_BASE}/version.txt")
        with urllib.request.urlopen(req, timeout=5) as resp:
            remote_version_str = resp.read().decode("utf-8").strip()
        remote_version = _parse_version(remote_version_str)
        local_version = _parse_version(VERSION)
        if remote_version <= local_version:
            return
        print(f"[*] New version available: v{remote_version_str} (current: v{VERSION})")
        answer = input("    Update now? [y/N]: ").strip().lower()
        if answer != "y":
            print("    Skipping update.")
            return
        print(f"    Downloading v{remote_version_str}...")
        for filename in UPDATE_FILES:
            url = f"{GITHUB_RAW_BASE}/{filename}"
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = resp.read()
                target = os.path.join(SCRIPT_DIR, filename)
                tmp = target + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(data)
                os.replace(tmp, target)
                print(f"      Updated {filename}")
            except Exception as e:
                print(f"      SKIP {filename}: {e}")
        print(f"[*] Updated to v{remote_version_str} — please restart.")
        sys.exit(0)
    except Exception:
        pass  # No internet / GitHub down — silently continue


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    args = sys.argv[1:]
    if "--no-update" in args:
        args.remove("--no-update")
    else:
        check_for_updates()
    debug(f"main: args={args}")

    # Log account state at startup
    accounts = load_accounts()
    debug(f"  registered accounts: {list(accounts.keys())}")
    for gt in accounts:
        acct = account_dir(gt)
        if os.path.isdir(acct):
            debug(f"  {gt} files: {os.listdir(acct)}")
        else:
            debug(f"  {gt} dir MISSING")

    # Handle CLI arg first, then fall through to interactive menu
    if args:
        if args[0] == "add":
            cmd_add()
        elif args[0] == "extract":
            arg = args[1] if len(args) >= 2 else None
            har_extract(arg)
        elif args[0] == "--all":
            process_all_accounts()
        elif args[0] == "build":
            html_file = build_index()
            if html_file:
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
        else:
            # Treat as gamertag
            gamertag = args[0]
            accounts = load_accounts()
            if gamertag not in accounts:
                print(f"ERROR: Account '{gamertag}' not found in accounts.json")
                print(f"  Known accounts: {', '.join(accounts.keys()) or '(none)'}")
                print("  Run `python XCT.py add` to set up an account.")
            else:
                # Refresh token
                print(f"[*] Refreshing token for {gamertag}...")
                refresh_account_token(gamertag)

                html_file, _lib = process_account(gamertag)
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)

    # Always enter interactive menu
    interactive_menu()


if __name__ == "__main__":
    main()
