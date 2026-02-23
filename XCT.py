#!/usr/bin/env python3
"""
XCT — Xbox Collection Tracker by Freshdex (version set in VERSION constant)
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
  python XCT.py preview            # Rebuild HTML only (no data, fast)
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
import subprocess
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
VERSION = "1.6.3"
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

# ---------------------------------------------------------------------------
# Auto-update — runs first so bugs in the rest of the script don't block it
# ---------------------------------------------------------------------------
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/freshdex/xbox-collection-tracker/main"
UPDATE_FILES = ["XCT.py", "xbox_auth.py", "requirements.txt", "tags.json", "gfwl_links.json"]

def _parse_version(v):
    """Parse version string like '1.2' or '1.4.1' into comparable tuple."""
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
                with urllib.request.urlopen(req, timeout=15) as resp:
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

    # Copy code to clipboard if possible
    try:
        import subprocess as _sp
        _sp.Popen(["clip"], stdin=_sp.PIPE, creationflags=0x08000000).communicate(user_code.encode())
        _clip_ok = True
    except Exception:
        _clip_ok = False

    print()
    print("=" * 56)
    print(f"  Go to:   {verification_uri}")
    print(f"  Enter:   {user_code}" + ("  (copied to clipboard)" if _clip_ok else ""))
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
        gamertag = input("  Enter gamertag label: ").strip()
        if not gamertag:
            gamertag = f"Gamertag_{xuid[:8] if xuid else 'unknown'}"

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
    print(f"[+] Gamertag: {gamertag}")
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
        print("  XCT — Add New Gamertag")
        print("=" * 56)
        print()
        gamertag = sisu_auth_for_account()
        if gamertag:
            print()
            scan_now = input("  Process full collection scan now? [Y/n]: ").strip().lower()
            if scan_now not in ("n", "no"):
                html_file, _lib = process_account(gamertag, method="both")
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
        print()
        again = input("Add another gamertag? [y/N]: ").strip().lower()
        if again not in ("y", "yes"):
            break
        print()


def delete_account(gamertag):
    """Delete an account and all its data."""
    import shutil
    accounts = load_accounts()
    if gamertag not in accounts:
        print(f"[!] Gamertag '{gamertag}' not found.")
        return
    confirm = input(f"  Delete gamertag '{gamertag}' and all its data? [y/N]: ").strip().lower()
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
    print(f"[+] Gamertag '{gamertag}' deleted.")


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
        print(f"[*] No auth state for {gamertag} (HAR-only gamertag)")
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
        label = input(f"  Enter gamertag label (uhs={uhs}): ").strip()
        if not label:
            label = f"Gamertag_{uhs[:8]}"

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
    print(f"[+] Gamertag: {label}")
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
    print(f"  Xbox Collection Tracker v{VERSION} by Freshdex")
    print()


def _op_summary(label, success=True, detail="", elapsed=0):
    """Print a post-operation summary banner."""
    mark = "+" if success else "!"
    m, s = divmod(int(elapsed), 60)
    time_str = f"{m}m {s:02d}s" if m else f"{s}s"
    print()
    print(f"  [{mark}] {label}  [{time_str}]")
    if detail:
        print(f"      {detail}")
    print()
    input("  Press Enter to continue...")


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
        print("  Run `python XCT.py add` to set up a gamertag.")
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

    print("[*] Fetching collection from TitleHub...")
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
        print(f"[+] Collection loaded from cache ({len(items)} items)")
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

    lp = product.get("LocalizedProperties") or []
    lp0 = lp[0] if lp else {}

    # -- Title, description, developer, publisher (always extract) --
    result["title"] = lp0.get("ProductTitle", "")
    result["description"] = lp0.get("ShortDescription", "")
    result["developer"] = lp0.get("DeveloperName", "")
    result["publisher"] = lp0.get("PublisherName", "")

    # -- Images: find BoxArt and Hero/SuperHeroArt --
    images = lp0.get("Images") or []
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
    skus = product.get("DisplaySkuAvailabilities") or []

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
        for pkg in (sku_props.get("Packages") or []):
            for pdep in (pkg.get("PlatformDependencies") or []):
                pname = pdep.get("PlatformName", "")
                mapped = PLATFORM_MAP.get(pname, pname)
                if mapped:
                    platforms.add(mapped)

        avails = sku_entry.get("Availabilities") or []
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
            "onGamePass":      False,  # set by JS cross-ref with fresh GP data
            "owned":           True,
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
    page_title = f"Xbox Collection Tracker v{VERSION} by Freshdex"

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
        '.tab-cur{margin-left:12px;padding:4px 6px;background:#1a1a1a;color:#e0e0e0;border:1px solid #333;border-radius:4px;font-size:12px;cursor:pointer}\n'
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
        '.gfwl-table td{padding:5px 8px;vertical-align:middle}\n'
        '.gfwl-nopkg td{opacity:0.5}\n'
        '.gfwl-links{white-space:nowrap}\n'
        '.gfwl-mlink{display:inline-block;margin:1px 2px;padding:2px 6px;border-radius:4px;font-size:11px;text-decoration:none;background:#1e3a2e;color:#4ec9a0;border:1px solid #2a5c42}\n'
        '.gfwl-mlink:hover{background:#2a5c42}\n'
        '.gfwl-base{background:#1e3a2e;color:#4ec9a0;padding:1px 5px;border-radius:3px;font-size:10px}\n'
        '.gfwl-dlc{background:#1e2a3a;color:#4ea0c9;padding:1px 5px;border-radius:3px;font-size:10px}\n'
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
        '.list-view .lv-head{display:grid;grid-template-columns:40px minmax(200px,1fr) 110px 130px 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:6px 10px;background:#161616;border-bottom:1px solid #333;font-size:11px;font-weight:600;color:#888;min-width:max-content;position:sticky;top:47px;z-index:20}\n'
        '.list-view .lv-head div[data-sort]{cursor:pointer;user-select:none}\n'
        '.list-view .lv-head div[data-sort]:hover{color:#107c10}\n'
        '.list-view .lv-row{display:grid;grid-template-columns:40px minmax(200px,1fr) 110px 130px 130px 110px 90px 80px 80px 80px 80px 36px 42px 70px;gap:6px;padding:5px 10px;background:#1a1a1a;border-bottom:1px solid #1e1e1e;align-items:center;cursor:pointer;font-size:12px;transition:background .15s;min-width:max-content}\n'
        '.list-view .lv-row:hover{background:#222}\n'
        '.list-view .lv-row img{width:36px;height:36px;object-fit:cover;border-radius:3px;background:#222}\n'
        '.list-view .lv-title{font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.list-view .lv-pub{color:#888;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}\n'
        '.list-view .lv-type{color:#888}\n'
        '.list-view .lv-usd{color:#42a5f5;font-weight:600;text-align:right}\n'
        '.list-view .lv-status{text-align:center}\n'
        '.dlc-img-wrap{position:relative;display:inline-block}\n'
        '.dlc-toggle{position:absolute;bottom:1px;right:1px;width:16px;height:16px;border-radius:50%;background:#107c10;color:#fff;border:none;cursor:pointer;font-size:12px;line-height:16px;text-align:center;padding:0;z-index:5;opacity:.9}\n'
        '.dlc-toggle:hover{opacity:1;transform:scale(1.15)}\n'
        '.dlc-child{background:#141414 !important;border-left:3px solid #107c10}\n'
        '.dlc-child:hover{background:#1c1c1c !important}\n'
        '.dlc-count{font-size:9px;margin-left:4px;background:#1a2e1a;color:#4caf50;padding:1px 5px;border-radius:8px;vertical-align:middle}\n'
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
        '.badge.usb{background:#1a1a3a;color:#90caf9}\n'
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
        '/* Import/Export buttons */\n'
        '.xct-iobtn{background:#222;color:#aaa;border:1px solid #444;padding:4px 10px;font-size:11px;cursor:pointer;border-radius:3px}\n'
        '.xct-iobtn:hover{background:#333;color:#fff}\n'
        '/* Import badge on library cards */\n'
        '.imp-badge{display:inline-block;background:#444;color:#aaa;font-size:9px;padding:1px 5px;border-radius:3px;margin-left:4px;vertical-align:middle}\n'
        '/* Imports section cards */\n'
        '.imp-card{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:12px 16px;margin:8px 0;display:flex;justify-content:space-between;align-items:center}\n'
        '.imp-left{flex:1}\n'
        '.imp-label{font-size:14px;color:#e0e0e0;font-weight:bold}\n'
        '.imp-meta{font-size:11px;color:#888;margin-top:4px}\n'
        '.imp-gts{font-size:11px;color:#666;margin-top:2px}\n'
        '.imp-rm{background:#c62828;color:#fff;border:none;padding:4px 12px;font-size:11px;cursor:pointer;border-radius:3px}\n'
        '.imp-rm:hover{background:#e53935}\n'
        '.cb-divider{padding:6px 8px;color:#888;font-size:10px;border-top:1px solid #333;margin-top:4px;display:flex;align-items:center;gap:6px;column-span:all}\n'
        '.cb-divider button{background:none;border:none;color:#c62828;cursor:pointer;font-size:12px;padding:0 2px}\n'
        '.cb-divider button:hover{color:#e53935}\n'
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
        '<div class="tab active" onclick="switchTab(\'library\',this)">My Collection <span class="cnt" id="tab-lib-cnt"></span></div>\n'
        '<div class="tab" id="tab-mkt" onclick="switchTab(\'marketplace\',this)" style="display:none">Marketplace <span class="cnt" id="tab-mkt-cnt"></span></div>\n'
        '<div class="tab" id="tab-gp" onclick="switchTab(\'gamepass\',this)" style="display:none">Game Pass <span class="cnt" id="tab-gp-cnt"></span></div>\n'
        '<div class="tab" id="tab-ph" onclick="switchTab(\'playhistory\',this)" style="display:none">Play History <span class="cnt" id="tab-ph-cnt"></span></div>\n'
        '<div class="tab" id="tab-hist" onclick="switchTab(\'history\',this)" style="display:none">Scan Log <span class="cnt" id="tab-hist-cnt"></span></div>\n'
        '<div class="tab" id="tab-acct" onclick="switchTab(\'gamertags\',this)" style="display:none">Gamertags <span class="cnt" id="tab-acct-cnt"></span></div>\n'
        '<div class="tab" id="tab-gfwl" onclick="switchTab(\'gfwl\',this)" style="display:none">GFWL <span class="cnt" id="tab-gfwl-cnt"></span></div>\n'
        '<div class="tab" id="tab-imp" onclick="switchTab(\'imports\',this)" style="display:none">Imports <span class="cnt" id="tab-imp-cnt"></span></div>\n'
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
        f'<div style="margin-left:6px;padding:0 8px;color:#555;font-size:11px;white-space:nowrap">XCT v{VERSION}</div>\n'
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
        '<div class="search-row" style="display:flex;gap:8px;align-items:center">'
        '<input type="text" id="lib-search" placeholder="Search collection..." oninput="filterLib()" style="flex:1">'
        '<button class="xct-iobtn" onclick="xctExport()" title="Export your collection as a shareable JSON file">Export</button>'
        '<button class="xct-iobtn" onclick="document.getElementById(\'imp-file\').click()" title="Import a collection from a JSON file">Import</button>'
        '<input type="file" id="imp-file" accept=".json" style="display:none" onchange="xctImport(this)">'
        '</div>\n'
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
        '<label><input type="checkbox" value="Durable" checked onchange="filterLib()"> DLC</label>'
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
        '<select id="lib-dlc" onchange="filterLib()">'
        '<option value="all">DLC: All</option>'
        '<option value="has">Has DLC</option>'
        '<option value="no">No DLC</option>'
        '</select>\n'
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
        '<div class="cb-drop" id="ph-gamertag" style="display:none"><div class="cb-btn" onclick="toggleCB(this)">Gamertag &#9662;</div><div class="cb-panel"></div></div>\n'
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
        '<select id="mkt-owned" onchange="mktPage=0;filterMKT()">'
        '<option value="all">All</option>'
        '<option value="owned">Owned</option>'
        '<option value="notowned">Not Owned</option>'
        '</select>\n'
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

        # -- Imports section --
        '<div class="section" id="imports">\n'
        '<h2>Imports</h2>\n'
        '<p class="sub" id="imp-sub"></p>\n'
        '<div style="margin-bottom:12px">'
        '<button class="xct-iobtn" onclick="document.getElementById(\'imp-file2\').click()">Import Collection</button>'
        '<input type="file" id="imp-file2" accept=".json" style="display:none" onchange="xctImport(this)">'
        '</div>\n'
        '<div id="imp-list"></div>\n'
        '</div>\n'

        # -- GFWL section --
        '<div class="section" id="gfwl">\n'
        '<h2>Games for Windows - LIVE</h2>\n'
        '<p class="sub" id="gfwl-sub"></p>\n'
        '<div class="search-row"><input type="text" id="gfwl-search" placeholder="Search GFWL games..." oninput="filterGFWL()"></div>\n'
        '<div id="gfwl-list"></div>\n'
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
        "const _expandedTids=new Set();\n"
        "function toggleDlcGroup(tid,event){event.stopPropagation();"
        "if(_expandedTids.has(tid))_expandedTids.delete(tid);else _expandedTids.add(tid);"
        "filterLib()}\n"
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
        "row('','Collection',libD,ownedGTs>1?ownedGTs:'');"
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
        "document.getElementById('lib-gp').value='all';"
        "document.getElementById('lib-dlc').value='all';"
        "document.getElementById('lib-sort').value='name';libSortCol=null;"
        "document.getElementById('lib-search').value='';"
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
        "const _all=LIB.concat(_impLib||[]);\n"
        "const pubs={};_all.forEach(x=>{const p=x.publisher||'';if(p)pubs[p]=(pubs[p]||0)+1});\n"
        "fill('lib-pub',Object.entries(pubs).sort((a,b)=>b[1]-a[1]).map(([p,c])=>[p,p+' ('+c+')']),\'filterLib\');\n"
        # Developers
        "const devs={};_all.forEach(x=>{const d=x.developer||'';if(d)devs[d]=(devs[d]||0)+1});\n"
        "fill('lib-dev',Object.entries(devs).sort((a,b)=>b[1]-a[1]).map(([d,c])=>[d,d+' ('+c+')']),\'filterLib\');\n"
        # SKUs
        "const skus={};_all.forEach(x=>{const s=x.skuId||'';if(s)skus[s]=(skus[s]||0)+1});\n"
        "fill('lib-sku',Object.entries(skus).sort((a,b)=>b[1]-a[1]).map(([s,c])=>[s,s+' ('+c+')']),\'filterLib\');\n"
        # Categories
        "const cats={};_all.forEach(x=>{const c=x.category||'';if(c)cats[c]=(cats[c]||0)+1});\n"
        "fill('lib-cat',Object.entries(cats).sort((a,b)=>b[1]-a[1]).map(([c,n])=>[c,c+' ('+n+')']),\'filterLib\');\n"
        # Platforms
        "const plats={};_all.forEach(x=>(x.platforms||[]).forEach(p=>{plats[p]=(plats[p]||0)+1}));\n"
        "fill('lib-plat',Object.entries(plats).sort((a,b)=>b[1]-a[1]).map(([p,c])=>[p,p+' ('+c+')']),\'filterLib\');\n"
        # Release years
        "const rys=new Set();_all.forEach(x=>{const y=(x.releaseDate||'').slice(0,4);if(/^\\d{4}$/.test(y)&&y<'2800')rys.add(y)});\n"
        "fill('lib-ryear',[...rys].sort().reverse().map(y=>[y,y]),\'filterLib\');\n"
        # Acquired years
        "const ays=new Set();_all.forEach(x=>{const y=(x.acquiredDate||'').slice(0,4);if(/^\\d{4}$/.test(y))ays.add(y)});\n"
        "fill('lib-ayear',[...ays].sort().reverse().map(y=>[y,y]),\'filterLib\');\n"
        # Gamertags — native section + per-import sections with remove buttons
        "const nGts={},nGtV={};\n"
        "LIB.forEach(x=>{const g=x.gamertag||'';if(g){nGts[g]=(nGts[g]||0)+1;nGtV[g]=(nGtV[g]||0)+(x.priceUSD||0)}});\n"
        "const _idx=_impIdx();\n"
        "const iGrps={};\n"
        "(_impLib||[]).forEach(x=>{const iid=x._importId;if(!iGrps[iid])iGrps[iid]={gts:{},vals:{}};"
        "const g=x.gamertag||'';if(g){iGrps[iid].gts[g]=(iGrps[iid].gts[g]||0)+1;iGrps[iid].vals[g]=(iGrps[iid].vals[g]||0)+(x.priceUSD||0)}});\n"
        "const _allGtSet=new Set(Object.keys(nGts));\n"
        "_idx.forEach(m=>{const gr=iGrps[m.id];if(gr)Object.keys(gr.gts).forEach(g=>_allGtSet.add(g))});\n"
        "function _gtLabel(g,cnt,val){"
        "const vs=val>0?'$'+val.toLocaleString('en',{minimumFractionDigits:2,maximumFractionDigits:2}):'';"
        "const lbl=document.createElement('label');"
        "lbl.innerHTML='<input type=\"checkbox\" value=\"'+g+'\" checked onchange=\"filterLib()\"> '+g+' ('+cnt+')'"
        "+(vs?' <span style=\"color:#42a5f5;font-size:10px\">'+vs+'</span>':'');"
        "return lbl}\n"
        "if(_allGtSet.size>1){\n"
        "const el=document.getElementById('lib-gamertag');"
        "el.style.display='';const panel=el.querySelector('.cb-panel');\n"
        # Native gamertags
        "const nKeys=Object.keys(nGts).sort((a,b)=>(nGtV[b]||0)-(nGtV[a]||0));\n"
        "nKeys.forEach(g=>panel.appendChild(_gtLabel(g,nGts[g],nGtV[g]||0)));\n"
        # Import groups
        "_idx.forEach((m,i)=>{\n"
        "const gr=iGrps[m.id];if(!gr)return;\n"
        "const ik=Object.keys(gr.gts);if(!ik.length)return;\n"
        "const dv=document.createElement('div');dv.className='cb-divider';\n"
        "dv.innerHTML='Import #'+(i+1)+': '+_esc(m.label)"
        "+' <button onclick=\"_removeImport(\\''+m.id+'\\')\" title=\"Remove import\">&times;</button>';\n"
        "panel.appendChild(dv);\n"
        "ik.sort((a,b)=>(gr.vals[b]||0)-(gr.vals[a]||0)).forEach(g=>panel.appendChild(_gtLabel(g,gr.gts[g],gr.vals[g]||0)));\n"
        "});\n"
        # Columns + Clear All
        "const cols=_allGtSet.size>24?3:_allGtSet.size>12?2:1;\n"
        "if(cols>1){panel.classList.add('cb-cols');panel.style.columnCount=cols;panel.style.minWidth=(cols*220)+'px'}\n"
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
        "document.getElementById('tab-lib-cnt').textContent=LIB.length+(_impLib?_impLib.length:0);\n"
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

        # -- Import/Export JS (IndexedDB for library data, localStorage for metadata index) --
        "const IMP_DB_NAME='xct_imports_db',IMP_DB_VER=1,IMP_STORE='imports',IMP_IDX_KEY='xct_imp_idx';\n"
        "let _impLib=[];\n"
        "function _esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')}\n"

        "function _impDB(){\n"
        "return new Promise((resolve,reject)=>{\n"
        "const req=indexedDB.open(IMP_DB_NAME,IMP_DB_VER);\n"
        "req.onupgradeneeded=()=>{const db=req.result;if(!db.objectStoreNames.contains(IMP_STORE))db.createObjectStore(IMP_STORE)};\n"
        "req.onsuccess=()=>resolve(req.result);\n"
        "req.onerror=()=>reject(req.error);\n"
        "})}\n"

        "function _impPut(id,data){\n"
        "return _impDB().then(db=>new Promise((resolve,reject)=>{\n"
        "const tx=db.transaction(IMP_STORE,'readwrite');\n"
        "tx.objectStore(IMP_STORE).put(data,id);\n"
        "tx.oncomplete=()=>resolve();\n"
        "tx.onerror=()=>reject(tx.error);\n"
        "}))}\n"

        "function _impGet(id){\n"
        "return _impDB().then(db=>new Promise((resolve,reject)=>{\n"
        "const tx=db.transaction(IMP_STORE,'readonly');\n"
        "const req=tx.objectStore(IMP_STORE).get(id);\n"
        "req.onsuccess=()=>resolve(req.result);\n"
        "req.onerror=()=>reject(req.error);\n"
        "}))}\n"

        "function _impDel(id){\n"
        "return _impDB().then(db=>new Promise((resolve,reject)=>{\n"
        "const tx=db.transaction(IMP_STORE,'readwrite');\n"
        "tx.objectStore(IMP_STORE).delete(id);\n"
        "tx.oncomplete=()=>resolve();\n"
        "tx.onerror=()=>reject(tx.error);\n"
        "}))}\n"

        "function _impIdx(){\n"
        "try{return JSON.parse(localStorage.getItem(IMP_IDX_KEY)||'[]')}catch(e){return[]}\n"
        "}\n"

        "function _loadImports(){\n"
        "const idx=_impIdx();\n"
        "if(!idx.length)return Promise.resolve();\n"
        "return Promise.all(idx.map(m=>_impGet(m.id).then(lib=>{\n"
        "if(!lib||!lib.length)return;\n"
        "lib.forEach(item=>{item._imported=true;item._importId=m.id;item._importLabel=m.label;_impLib.push(item)});\n"
        "}).catch(()=>{})));\n"
        "}\n"

        "function xctExport(){\n"
        "const items=LIB.filter(x=>!(x.onGamePass&&!x.owned));\n"
        "if(!items.length){alert('No items to export.');return}\n"
        "const _gtc={};items.forEach(x=>{const g=x.gamertag||'';if(g)_gtc[g]=(_gtc[g]||0)+1});\n"
        "const gts=Object.keys(_gtc).sort((a,b)=>_gtc[b]-_gtc[a]);\n"
        "const stripped=items.map(x=>{\n"
        "const o=Object.assign({},x);\n"
        "delete o.description;delete o.heroImage;\n"
        "delete o.onGamePass;delete o._allGTs;delete o.isPreOrder;\n"
        "delete o._imported;\n"
        "return o;\n"
        "});\n"
        "const data={xct:1,date:new Date().toISOString().slice(0,10),gamertags:gts,library:stripped};\n"
        "const blob=new Blob([JSON.stringify(data)],{type:'application/json'});\n"
        "const a=document.createElement('a');\n"
        "a.href=URL.createObjectURL(blob);\n"
        "const _sgt=(gts[0]||'unknown').replace(/[^a-zA-Z0-9_-]/g,'_');\n"
        "a.download='xct_export_'+_sgt+'_'+gts.length+'gt_'+data.date+'.json';\n"
        "a.click();\n"
        "URL.revokeObjectURL(a.href);\n"
        "}\n"

        "function xctImport(input){\n"
        "const file=input.files[0];\n"
        "if(!file)return;\n"
        "const reader=new FileReader();\n"
        "reader.onload=function(e){\n"
        "let data;\n"
        "try{data=JSON.parse(e.target.result)}catch(err){alert('Invalid JSON file.');return}\n"
        "if(!data.xct||!Array.isArray(data.library)){alert('Not a valid XCT export file.');return}\n"
        "if(!data.library.length){alert('Export file contains no collection items.');return}\n"
        "const gtCounts={};\n"
        "data.library.forEach(x=>{const g=x.gamertag||'Unknown';gtCounts[g]=(gtCounts[g]||0)+1});\n"
        "const sorted=Object.entries(gtCounts).sort((a,b)=>b[1]-a[1]);\n"
        "let label=sorted[0][0];\n"
        "if(sorted.length>1)label+=' +'+(sorted.length-1);\n"
        "const id='imp_'+Date.now();\n"
        "const meta={id:id,label:label,date:data.date||new Date().toISOString().slice(0,10),gamertags:data.gamertags||sorted.map(x=>x[0]),count:data.library.length};\n"
        "_impPut(id,data.library).then(()=>{\n"
        "const idx=_impIdx();idx.push(meta);\n"
        "localStorage.setItem(IMP_IDX_KEY,JSON.stringify(idx));\n"
        "location.reload();\n"
        "}).catch(err=>{alert('Failed to store import: '+err);});\n"
        "};\n"
        "reader.readAsText(file);\n"
        "input.value='';\n"
        "}\n"

        "function _removeImport(id){\n"
        "const m=_impIdx().find(x=>x.id===id);\n"
        "if(!confirm('Remove imported collection'+(m?' \"'+m.label+'\"':'')+' ('+((m&&m.count)||'?')+' items)?'))return;\n"
        "_impDel(id).then(()=>{\n"
        "const idx=_impIdx().filter(x=>x.id!==id);\n"
        "localStorage.setItem(IMP_IDX_KEY,JSON.stringify(idx));\n"
        "location.reload();\n"
        "}).catch(()=>{location.reload()});\n"
        "}\n"

        "function renderImports(){\n"
        "const imps=_impIdx();\n"
        "if(!imps.length)return;\n"
        "document.getElementById('tab-imp').style.display='';\n"
        "document.getElementById('tab-imp-cnt').textContent=imps.length;\n"
        "document.getElementById('imp-sub').textContent=imps.length+' imported collection'+(imps.length>1?'s':'');\n"
        "const el=document.getElementById('imp-list');\n"
        "let h='';\n"
        "imps.forEach(imp=>{\n"
        "h+='<div class=\"imp-card\"><div class=\"imp-left\">'\n"
        "+'<div class=\"imp-label\">'+_esc(imp.label)+'</div>'\n"
        "+'<div class=\"imp-meta\">'+_esc(imp.count)+' items &middot; exported '+_esc(imp.date)+'</div>'\n"
        "+'<div class=\"imp-gts\">Gamertags: '+imp.gamertags.map(g=>_esc(g)).join(', ')+'</div>'\n"
        "+'</div>'\n"
        "+'<button class=\"imp-rm\" onclick=\"_removeImport(\\''+imp.id+'\\')\" >Remove</button>'\n"
        "+'</div>';\n"
        "});\n"
        "el.innerHTML=h;\n"
        "}\n"

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
        "const _usbR=typeof USB_DB!=='undefined'&&USB_DB?USB_DB[pid]:null;\n"
        "if(_usbR){\n"
        "let uh='<div class=\"modal-info\" style=\"margin-top:12px\"><div style=\"color:#90caf9;font-weight:600;margin-bottom:6px;border-bottom:1px solid #222;padding-bottom:4px\">&#9654; On USB Drive</div>';\n"
        "if(_usbR.contentId)uh+=`<div><span class=\"lbl\">Content ID:</span></div><div class=\"val\" style=\"font-family:monospace;font-size:11px\">${_usbR.contentId}</div>`;\n"
        "if(_usbR.buildVersion)uh+=`<div><span class=\"lbl\">Build Version:</span></div><div class=\"val\">${_usbR.buildVersion}</div>`;\n"
        "if(_usbR.buildId)uh+=`<div><span class=\"lbl\">Build ID:</span></div><div class=\"val\" style=\"font-family:monospace;font-size:11px\">${_usbR.buildId}</div>`;\n"
        "if(_usbR.platform)uh+=`<div><span class=\"lbl\">Platform:</span></div><div class=\"val\">${_usbR.platform}</div>`;\n"
        "if(_usbR.sizeBytes)uh+=`<div><span class=\"lbl\">Size:</span></div><div class=\"val\">${(_usbR.sizeBytes/1e9).toFixed(2)} GB</div>`;\n"
        "if(_usbR.contentTypes)uh+=`<div><span class=\"lbl\">Content Types:</span></div><div class=\"val\">${_usbR.contentTypes}</div>`;\n"
        "if(_usbR.devices)uh+=`<div><span class=\"lbl\">Devices:</span></div><div class=\"val\">${_usbR.devices}</div>`;\n"
        "if(_usbR.language)uh+=`<div><span class=\"lbl\">Language:</span></div><div class=\"val\">${_usbR.language}</div>`;\n"
        "if(_usbR.planId)uh+=`<div><span class=\"lbl\">Plan ID:</span></div><div class=\"val\" style=\"font-family:monospace;font-size:11px\">${_usbR.planId}</div>`;\n"
        "if(_usbR.cdnUrls&&_usbR.cdnUrls.length){_usbR.cdnUrls.forEach((u,i)=>{uh+=`<div><span class=\"lbl\">CDN ${i+1}:</span></div><div class=\"val\" style=\"word-break:break-all;font-size:10px\"><a href=\"${u}\" target=\"_blank\" style=\"color:#90caf9\">${u}</a></div>`})}\n"
        "uh+='</div>';\n"
        "document.getElementById('modal-body').innerHTML+=uh}\n"
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
        "return LIB.concat(_impLib||[]).filter(item=>{"
        "if(gtVals&&!gtVals.includes(item.gamertag||''))return false;"
        "if(sVals&&!sVals.includes(item.status))return false;"
        "if(tVals){if(!tVals.length)return false;"
        "const realTypes=tVals.filter(v=>v[0]!=='_');"
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
        "if(!isPO0&&!isTD0&&!isInv0&&!isInd0&&(!realTypes.length||!realTypes.includes(item.productKind)))return false;}"
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
        "const dlcF=document.getElementById('lib-dlc').value;\n"
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

        # DLC grouping: build tid→{games,dlc} map, identify parents/children
        "const _tidMap={};"
        "filtered.forEach(item=>{const tid=item.xboxTitleId;"
        "if(!tid)return;"
        "if(!_tidMap[tid])_tidMap[tid]={games:[],dlc:[]};"
        "if(item.productKind==='Game')_tidMap[tid].games.push(item);"
        "else if(item.productKind==='Durable')_tidMap[tid].dlc.push(item)});\n"
        "const _dlcParents=new Set(),_dlcChildren=new Set();"
        "Object.values(_tidMap).forEach(g=>{if(g.games.length>0&&g.dlc.length>0){"
        "g.games.forEach(p=>_dlcParents.add(p.productId));"
        "g.dlc.forEach(c=>_dlcChildren.add(c.productId))}});\n"
        "if(dlcF==='has')filtered=filtered.filter(item=>_dlcParents.has(item.productId)||_dlcChildren.has(item.productId));"
        "else if(dlcF==='no')filtered=filtered.filter(item=>!_dlcParents.has(item.productId)&&!_dlcChildren.has(item.productId));\n"

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
        # _renderRow helper for list view rows
        "function _renderRow(item,extraCls,dlcCount){"
        "const fl=manualFlags[item.productId];"
        "const sc2=item.status==='Active'?'s-active':item.status==='Expired'?'s-expired':'s-revoked';"
        "const imgTag=item.image?`<img src=\"${item.image}\" loading=\"lazy\" onerror=\"this.style.display='none'\">`:'<div></div>';"
        "let imgHtml=imgTag;"
        "if(dlcCount>0){const tid=item.xboxTitleId;const exp=_expandedTids.has(tid);imgHtml=`<div class=\"dlc-img-wrap\">${imgTag}<button class=\"dlc-toggle\" onclick=\"toggleDlcGroup('${tid}',event)\">${exp?'\\u2212':'+'}</button></div>`}"
        "const usdR=_p(item.priceUSD);"
        "const sb=`<span class=\"${sc2}\">${item.status||''}</span>`;"
        "const po2=item.isPreOrder?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#2a2a1a;color:#ffd54f\">PRE-ORDER</span>':'';"
        "const gp2=item.onGamePass?'<span class=\"badge gp\" style=\"font-size:9px;margin-left:4px\">GP</span>':'';"
        "const tr2=item.isTrial?'<span class=\"badge trial\" style=\"font-size:9px;margin-left:3px\">TRIAL</span>'"
        ":item.isDemo?'<span class=\"badge demo\" style=\"font-size:9px;margin-left:3px\">DEMO</span>':'';"
        "const fl2=fl==='beta'?'<span class=\"badge flagged\" style=\"font-size:9px;margin-left:3px\">FLAGGED</span>'"
        ":fl==='delisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a2a1a;color:#ff9800\">DELISTED</span>'"
        ":fl==='hardDelisted'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a1a1a;color:#f44336\">HARD DELISTED</span>'"
        ":fl==='indie'?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#1a2a3a;color:#64b5f6\">INDIE</span>':'';"
        "const iv2=item.catalogInvalid?'<span class=\"badge\" style=\"font-size:9px;margin-left:3px;background:#3a1a1a;color:#f44336\">INVALID</span>':'';"
        "const dlcBadge=dlcCount>0?`<span class=\"dlc-count\">${dlcCount} DLC</span>`:'';"
        "const usbBadge2=(typeof USB_DB!=='undefined'&&USB_DB&&USB_DB[item.productId])?'<span class=\"badge usb\" style=\"font-size:9px;margin-left:4px\">USB</span>':'';"
        "const st=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');"
        "const aGTs=item._allGTs||[item.gamertag||''];"
        "const gtE=aGTs.length>1?`<span class=\"gt-plus\" onclick=\"event.stopPropagation();showGTList(this,['`+aGTs.map(g=>g.replace(/'/g,\"\\\\'\")).join(`','`)+`'])\" title=\"${aGTs.length} gamertags\">+${aGTs.length-1}</span>`:'';"
        "const relD2=(item.releaseDate||'').substring(0,10);"
        "const acqD2=(item.acquiredDate||'').substring(0,10);"
        "const lpD2=(item.lastTimePlayed||'').substring(0,10);"
        "const plS=(item.platforms||[]).join(', ')||'';"
        "return `<div class=\"lv-row ${extraCls}\" onclick=\"showLibDetail('${item.productId}')\" oncontextmenu=\"showFlagMenu(event,'${item.productId}','${st}')\">"
        "${imgHtml}<div class=\"lv-title\" title=\"${(item.title||'').replace(/\"/g,'&quot;')}\">"
        "${item.title||item.productId}${po2}${gp2}${tr2}${fl2}${iv2}${dlcBadge}${usbBadge2}</div>"
        "<div class=\"lv-type\" style=\"color:#aaa\">${item.gamertag||''}${gtE}${item._imported?' <span class=\"imp-badge\">imp</span>':''}</div>"
        "<div class=\"lv-pub\">${item.publisher||''}</div>"
        "<div class=\"lv-pub\">${item.developer||''}</div>"
        "<div class=\"lv-type\">${item.category||''}</div>"
        "<div class=\"lv-type\">${plS}</div>"
        "<div class=\"lv-type\">${relD2}</div>"
        "<div class=\"lv-type\">${acqD2}</div>"
        "<div class=\"lv-type\">${lpD2}</div>"
        "<div class=\"lv-usd\">${usdR}</div>"
        "<div class=\"lv-type\" title=\"${item.purchasedCountry||''}\">${item.purchasedCountry||''}</div>"
        "<div class=\"lv-type\">${item.skuId||''}</div>"
        "<div class=\"lv-status\">${sb}</div></div>`}\n"

        # Build _filteredPids for fast lookup of which items are in filtered list
        "const _filteredPids=new Set(filtered.map(x=>x.productId));\n"

        # Rendering loop with DLC nesting (list) and flat (grid)
        "const _renderedDlc=new Set();\n"
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
        "const usbBadge=(typeof USB_DB!=='undefined'&&USB_DB&&USB_DB[item.productId])?'<span class=\"badge usb\" style=\"font-size:9px;margin-left:4px\">USB</span>':'';\n"
        "const safeTitle=(item.title||'').replace(/'/g,\"\\\\\\'\" ).replace(/\"/g,'&quot;');\n"
        "const allGTs=item._allGTs||[item.gamertag||''];\n"
        "const gtExtra=allGTs.length>1?`<span class=\"gt-plus\" onclick=\"event.stopPropagation();showGTList(this,['`+allGTs.map(g=>g.replace(/'/g,\"\\\\'\")).join(`','`)+`'])\" title=\"${allGTs.length} gamertags\">+${allGTs.length-1}</span>`:'';\n"

        # Grid view: always flat, render every item
        'gh+=`<div class="lib-card" onclick="showLibDetail(\'${item.productId}\')" oncontextmenu="showFlagMenu(event,\'${item.productId}\',\'${safeTitle}\')">'
        '${img}<div class="info"><div class="ln" title="${(item.title||\'\').replace(/"/g,\'&quot;\')}">'
        '${item.title||item.productId}${poBadge}${gpBadge}${trBadge}${flBadge}${invBadge}${usbBadge}${item._imported?\'<span class="imp-badge">imported</span>\':\'\'}</div>'
        '<div class="lm">${item.publisher||\'\'} | ${item.productKind||\'\'} | ${item.category||\'\'} | '
        '<span class="${sc}">${item.status||\'\'}</span>${gtExtra}</div>${pr}</div></div>`;\n'

        # List view: DLC nesting
        "if(_renderedDlc.has(item.productId)){continue}\n"
        "const _isParent=_dlcParents.has(item.productId);\n"
        "const _tid=item.xboxTitleId;\n"
        "const _dlcGroup=(_isParent&&_tid&&_tidMap[_tid])?_tidMap[_tid].dlc.filter(d=>_filteredPids.has(d.productId)):[];\n"
        "if(_isParent&&_dlcGroup.length>0){\n"
        "lh+=_renderRow(item,'',_dlcGroup.length);\n"
        "if(_expandedTids.has(_tid)){\n"
        "_dlcGroup.forEach(d=>{lh+=_renderRow(d,'dlc-child',0);_renderedDlc.add(d.productId)})\n"
        "}else{\n"
        "_dlcGroup.forEach(d=>_renderedDlc.add(d.productId))\n"
        "}\n"
        "}else{\n"
        "lh+=_renderRow(item,'',0)\n"
        "}}\n"
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
        "const ownF=document.getElementById('mkt-owned').value;\n"
        "const so=document.getElementById('mkt-sort').value;\n"


        "const g=document.getElementById('mkt-grid');const l=document.getElementById('mkt-list');\n"
        'let filtered=MKT.filter(item=>{\n'
        "if(q&&!(item.title||'').toLowerCase().includes(q)&&!(item.publisher||'').toLowerCase().includes(q)"
        "&&!(item.productId||'').toLowerCase().includes(q))return false;\n"
        "if(chVals&&!(item.channels||[]).some(c=>chVals.includes(c)))return false;\n"
        "if(tVals){const tk=item.productKind==='Durable'?'DLC':item.productKind;if(!tVals.includes(tk))return false}\n"
        "if(platVals&&!(item.platforms||[]).some(p=>platVals.includes(p)))return false;\n"
        "if(pubVals&&!pubVals.includes(item.publisher||''))return false;\n"
        "if(ownF==='owned'&&!item.owned)return false;\n"
        "if(ownF==='notowned'&&item.owned)return false;\n"


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
        "sub.textContent=ACCOUNTS.length+' gamertags';\n"
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

        # -- GFWL tab logic --
        "let _gfwlQ='';\n"
        "function filterGFWL(){_gfwlQ=document.getElementById('gfwl-search').value.toLowerCase().trim();renderGFWL();}\n"
        "function renderGFWL(){\n"
        "  const el=document.getElementById('gfwl-list');\n"
        "  if(!el||typeof GFWL==='undefined'||!GFWL.length)return;\n"
        "  document.getElementById('tab-gfwl').style.display='';\n"
        "  const filtered=GFWL.filter(g=>!_gfwlQ||g.name.toLowerCase().includes(_gfwlQ)||g.tid.toLowerCase().includes(_gfwlQ));\n"
        "  document.getElementById('tab-gfwl-cnt').textContent=filtered.length;\n"
        "  document.getElementById('gfwl-sub').textContent=GFWL.length+' achievement games · '+filtered.length+' shown';\n"
        "  function fmtSz(b){if(!b)return '-';if(b>=1e9)return(b/1e9).toFixed(1)+' GB';if(b>=1e6)return(b/1e6).toFixed(0)+' MB';return(b/1024).toFixed(0)+' KB';}\n"
        "  function offerLabel(s){if(s==='e0000001')return '<span class=\"gfwl-base\">Base</span>';if(s.startsWith('e000'))return '<span class=\"gfwl-dlc\">DLC</span>';return '<span class=\"gfwl-dlc\">Pack</span>';}\n"
        "  let h='<table class=\"gtbl gfwl-table\" style=\"width:100%\"><thead><tr><th>Game</th><th>Title ID</th><th class=\"num\">Pkgs</th><th class=\"num\">Size</th><th>Manifest Links</th></tr></thead><tbody>';\n"
        "  filtered.forEach(g=>{\n"
        "    const hasPkgs=g.packages&&g.packages.length>0;\n"
        "    const pkgHtml=hasPkgs?g.packages.slice(0,8).map(p=>`<a class=\"gfwl-mlink\" href=\"${p.manifest_url.replace('download.xbox.com','download-ssl.xbox.com')}\" target=\"_blank\" title=\"${p.content_id}\\n${fmtSz(p.package_size)}\">${offerLabel(p.offer_suffix)}</a>`).join('')+(g.packages.length>8?` <span style=\"color:#888\">+${g.packages.length-8} more</span>`:''):'<span style=\"color:#888\">—</span>';\n"
        "    h+=`<tr class=\"${hasPkgs?'':'gfwl-nopkg'}\"><td>${g.name}</td><td class=\"gt-mono\" style=\"font-size:11px\">${g.tid}${g.short_id?' <span style=\"color:#888\">(${g.short_id})</span>':''}</td><td class=\"num\">${hasPkgs?g.packages.length:'—'}</td><td class=\"num\">${fmtSz(g.total_size)}</td><td class=\"gfwl-links\">${pkgHtml}</td></tr>`;\n"
        "  });\n"
        "  h+='</tbody></table>';\n"
        "  el.innerHTML=h;\n"
        "}\n"

        '_loadImports().catch(()=>{}).then(()=>{\n'
        'try{initDropdowns();filterLib();filterPH();filterGP();filterMKT();renderHistory();renderImports();}catch(e){console.error("init error",e)}\n'
        'renderGFWL();\n'
        "document.getElementById('loading-overlay').style.display='none';\n"
        '});\n'
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

    # Load USB drive database if available
    usb_db = {}
    usb_db_file = os.path.join(SCRIPT_DIR, "usb_db.json")
    if os.path.isfile(usb_db_file):
        try:
            usb_db = load_json(usb_db_file) or {}
        except Exception:
            pass

    # Load GFWL achievement games catalog
    GFWL_71_TIDS = {
        '4E4D0FA2','48450FA0','4D530FA3','534307FF','5343080C','57520FA0',
        '5A450FA0','534307FA','5454085C','5454086F','58410A6D','415807D5',
        '45410935','58410A1C','44540FA0','4E4D0FA1','43430803','4343080E',
        '43430FA2','434D0820','434D0FA0','434D0831','434D0FA1','4D53090A',
        '425307D6','454D07D4','434D082F','4D530901','4D530842','57520FA3',
        '5454083B','4D53080F','4D5707E4','4D530FA7','4D530FA8','5451081F',
        '534307EB','43430808','434307DE','584109F1','4D5308D2','57520FA2',
        '4D530FA5','434D083E','58410A10','41560829','54510837','434307F7',
        '43430FA1','48450FA1','535007E3','544707D4','4D5307D6','4C4107EB',
        '53450826','434307F4','43430FA5','43430FA0','49470FA1','534507F6',
        '584109EB','4D530FA2','425607F3','534507F0','5345082C','53450FA2',
        '4D530841','5451082D','58410A01','584109F0',
        '424107DF',  # Legend of the Galactic Heroes
    }
    gfwl_data = []
    gfwl_file = os.path.join(SCRIPT_DIR, "gfwl_links.json")
    if os.path.isfile(gfwl_file):
        try:
            gfwl_raw = load_json(gfwl_file) or {}
            for tid, v in gfwl_raw.items():
                if tid in GFWL_71_TIDS:
                    gfwl_data.append({
                        'tid': tid,
                        'name': v['name'],
                        'short_id': v.get('short_id', ''),
                        'packages': v.get('packages', []),
                        'total_size': v.get('total_size', 0),
                    })
            gfwl_data.sort(key=lambda x: x['name'].lower())
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
        "const USB_DB=" + json.dumps(usb_db, ensure_ascii=False) + ";\n"
        "const GFWL=" + json.dumps(gfwl_data, ensure_ascii=False) + ";\n"
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
    print(f"    [Enter] Both (recommended)  - full collection + game metadata")
    print(f"    [C] Collections API only    - {col_status} — all entitlements (~5000)")
    print(f"    [T] TitleHub only           - {th_status} — games with metadata (~1000)")
    print(f"    [F] Import HAR file         - extract token from .har then process")
    print(f"    [B] Back")
    print()

    pick = input("  Pick [Enter=Both / C/T/F / B=back]: ").strip().upper()
    if pick == "B":
        return None

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
            print("  Token was saved to a different gamertag. Falling back to Both.")
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
        if method is None:
            return None, []

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
    print(f"  Collection value: USD {total_usd:,.2f} ({priced} priced)")

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
    print(f"  Collection: {len(library)} items")
    if len(combined_library) > len(library):
        print(f"  Combined: {len(combined_library)} items (all gamertags)")
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
        print("No gamertags found.")
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
        print(f"  [{gt}] {len(library)} collection items, {len(play_hist)} play history")

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

    print(f"\n[+] Index rebuilt: {len(combined_library)} items across {len(gamertags)} gamertags")
    return combined_html


# ===========================================================================
# Marketplace Processing (bronze.xboxservices.com DynamicChannels)
# ===========================================================================

def process_gamepass_library():
    """Fetch Game Pass catalog, enrich with catalog details, and rebuild HTML."""
    accounts = load_accounts()
    gamertags = list(accounts.keys())
    if not gamertags:
        print("[!] No gamertags configured.")
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
        print("No gamertags found. Use 'add' to set up a gamertag.")
        return

    gamertags = list(accounts.keys())

    # Single data-source prompt for all accounts
    print()
    print("  Data source for all gamertags:")
    print("    [Enter] Both (recommended)  - full collection + game metadata")
    print("    [C] Collections API only    - all entitlements (~5000)")
    print("    [T] TitleHub only           - games with metadata (~1000)")
    print("    [B] Back")
    print()
    pick = input("  Pick [Enter=Both / C/T / B=back]: ").strip().upper()
    if pick == "B":
        return
    elif pick == "C":
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
    print(f"  Collection: {len(library)} items, Play history: {len(play_history)} items")

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
# Xbox Drive Converter
# Ports the logic from XboxOneStorageConverter (C#) to Python.
# Xbox external drives use a custom MBR signature at offset 0x1FE:
#   Xbox mode: 0x99 0xCC  — unreadable by Windows, usable by Xbox
#   PC mode:   0x55 0xAA  — with first 0x1B8 bytes zeroed (no partition table)
# Changing mode requires writing those two bytes; needs Administrator on Windows.
# Refresh Disks = diskpart rescan (same as Disk Management > Action > Rescan Disks).
# ===========================================================================

_XDC_MBR_SIZE       = 512
_XDC_SIG_OFFSET     = 0x1FE
_XDC_XBOX_SIG       = bytes([0x99, 0xCC])
_XDC_PC_SIG         = bytes([0x55, 0xAA])


def _xdc_list_physical_drives():
    """List physical drives via PowerShell WMI. Returns list of (deviceId, caption)."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_DiskDrive | ForEach-Object { $_.DeviceID + '|' + $_.Caption }"],
            capture_output=True, text=True, timeout=15)
        drives = []
        for line in r.stdout.strip().splitlines():
            line = line.strip()
            if '|' in line:
                dev, _, cap = line.partition('|')
                drives.append((dev.strip(), cap.strip()))
        return drives
    except Exception as e:
        print(f"[!] Drive enumeration failed: {e}")
        return []


def _xdc_read_mbr(device_id):
    """Open a physical drive and read its 512-byte MBR. Returns bytes or None."""
    import ctypes
    handle = ctypes.windll.kernel32.CreateFileW(
        device_id,
        0x80000000,        # GENERIC_READ
        0x00000001,        # FILE_SHARE_READ
        None, 3, 0, None)  # OPEN_EXISTING
    if handle in (-1, 0):
        return None
    try:
        buf = ctypes.create_string_buffer(_XDC_MBR_SIZE)
        n   = ctypes.c_ulong(0)
        ctypes.windll.kernel32.ReadFile(handle, buf, _XDC_MBR_SIZE, ctypes.byref(n), None)
        return bytes(buf.raw)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _xdc_write_mbr(device_id, mbr_data):
    """Open a physical drive exclusively and write 512-byte MBR. Returns (ok, errmsg)."""
    import ctypes
    handle = ctypes.windll.kernel32.CreateFileW(
        device_id,
        0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
        0,                         # exclusive (no sharing)
        None, 3, 0, None)
    if handle in (-1, 0):
        err = ctypes.windll.kernel32.GetLastError()
        if err == 5:
            return False, "Access denied — run XCT as Administrator."
        return False, f"Could not open drive (Windows error {err})."
    try:
        ctypes.windll.kernel32.SetFilePointer(handle, 0, None, 0)
        n = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.WriteFile(handle, bytes(mbr_data), _XDC_MBR_SIZE, ctypes.byref(n), None)
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            return False, f"Write failed (Windows error {err})."
        return True, "OK"
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _xdc_scan_xbox_drives():
    """
    Enumerate all physical drives and identify Xbox external storage by MBR signature.
    Returns list of dicts: {deviceId, caption, mode}  (mode: 'Xbox Mode' | 'PC Mode').
    """
    found = []
    for device_id, caption in _xdc_list_physical_drives():
        mbr = _xdc_read_mbr(device_id)
        if mbr is None:
            continue
        sig = mbr[_XDC_SIG_OFFSET:_XDC_SIG_OFFSET + 2]
        if sig == _XDC_XBOX_SIG:
            found.append({"deviceId": device_id, "caption": caption, "mode": "Xbox Mode"})
        elif sig == _XDC_PC_SIG and all(b == 0 for b in mbr[:0x1B8]):
            # PC signature but zeroed partition table = Xbox drive switched to PC mode
            found.append({"deviceId": device_id, "caption": caption, "mode": "PC Mode"})
    return found


def _xdc_change_mode(device_id, to_xbox):
    """
    Rewrite the MBR signature to Xbox (0x99,0xCC) or PC (0x55,0xAA).
    Returns (success, message).  Requires Administrator.
    """
    mbr = _xdc_read_mbr(device_id)
    if mbr is None:
        return False, "Could not read MBR — check permissions."
    mbr = bytearray(mbr)
    target_sig = _XDC_XBOX_SIG if to_xbox else _XDC_PC_SIG
    current_sig = bytes(mbr[_XDC_SIG_OFFSET:_XDC_SIG_OFFSET + 2])
    if current_sig == target_sig:
        return True, f"Drive is already in {'Xbox' if to_xbox else 'PC'} mode."
    mbr[_XDC_SIG_OFFSET]     = target_sig[0]
    mbr[_XDC_SIG_OFFSET + 1] = target_sig[1]
    return _xdc_write_mbr(device_id, mbr)


def _xdc_rescan():
    """
    Run 'diskpart rescan' — equivalent of Disk Management > Action > Rescan Disks.
    Forces Windows to re-detect all storage devices. Returns (ok, output).
    """
    import tempfile
    try:
        tf = tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False)
        tf.write("rescan\nexit\n")
        tf_name = tf.name
        tf.close()
        r = subprocess.run(["diskpart", "/s", tf_name],
                           capture_output=True, text=True, timeout=30)
        os.unlink(tf_name)
        return r.returncode == 0, r.stdout.strip()
    except Exception as e:
        return False, str(e)


def _xdc_pick_drive(drives, prompt):
    """Show drive list and return chosen drive dict, or None on cancel."""
    print()
    print(f"  {'#':>2}  {'Caption':<38}  {'Mode':<12}  Device")
    print("  " + "─" * 75)
    for i, d in enumerate(drives, 1):
        print(f"  {i:>2}  {d['caption']:<38}  {d['mode']:<12}  {d['deviceId']}")
    print()
    if len(drives) == 1:
        return drives[0]
    sel = input(f"  {prompt} [1-{len(drives)}]: ").strip()
    try:
        idx = int(sel) - 1
        if 0 <= idx < len(drives):
            return drives[idx]
    except ValueError:
        pass
    print("  Invalid selection.")
    return None


def process_drive_converter():
    """Interactive Xbox drive mode converter (PC ↔ Xbox MBR signature)."""
    import ctypes as _ct
    try:
        is_admin = bool(_ct.windll.shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False

    print("\n[Xbox Drive Converter]")
    if not is_admin:
        print("  [!] Not running as Administrator — convert operations will fail.")
        print("      Right-click Command Prompt > Run as Administrator, then relaunch XCT.")
    print()
    print("    [1] Convert to PC mode   (makes drive visible to Windows/Explorer)")
    print("    [2] Refresh Disks        (rescan hardware — like Disk Management > Rescan Disks)")
    print("    [3] Convert to Xbox mode (makes drive usable by Xbox)")
    print("    [B] Back")
    print()
    choice = input("  Choice: ").strip().upper()

    if choice == "2":
        print("[*] Rescanning disks...")
        ok, out = _xdc_rescan()
        if ok:
            print("[+] Rescan complete. Windows has re-detected all storage devices.")
        else:
            print(f"[!] Rescan failed: {out}")
        return

    if choice not in ("1", "3"):  # B or anything else → back
        return

    to_xbox      = (choice == "3")
    action_label = "Xbox mode" if to_xbox else "PC mode"

    print(f"[*] Scanning for Xbox external storage devices...")
    drives = _xdc_scan_xbox_drives()
    if not drives:
        print("[!] No Xbox external storage devices detected.")
        print("    Plug in the drive, then use [2] Refresh Disks and try again.")
        return

    drv = _xdc_pick_drive(drives, "Which drive?")
    if drv is None:
        return

    if (to_xbox and drv["mode"] == "Xbox Mode") or (not to_xbox and drv["mode"] == "PC Mode"):
        print(f"  Drive is already in {action_label}.")
        return

    print(f"\n  {drv['caption']}  ({drv['deviceId']})  →  {action_label}")
    if to_xbox:
        print("  WARNING: Drive will be inaccessible to Windows until converted back to PC mode.")
    else:
        print("  WARNING: You may need to assign a drive letter in Disk Management afterwards.")
    print()
    confirm = input("  Confirm? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return

    ok, msg = _xdc_change_mode(drv["deviceId"], to_xbox)
    if ok:
        print(f"[+] Conversion successful — drive is now in {action_label}.")
        if not to_xbox:
            print("[*] Use Disk Management (diskmgmt.msc) to assign a drive letter if needed.")
    else:
        print(f"[!] Failed: {msg}")


# ===========================================================================
# USB Drive Scanner
# ===========================================================================

def scan_usb_drive(drive_letter="E"):
    """
    Scan an Xbox USB drive for installed game packages.
    Reads .xvs (Xbox Virtual Signature) files which are UTF-16LE JSON containing
    StoreId (Microsoft Store product ID) and package metadata.
    Returns list of dicts: {contentId, storeId, packageName, buildVersion, platform, sizeBytes}.
    """
    drive_path = drive_letter.rstrip(":/\\") + ":/"
    if not os.path.isdir(drive_path):
        print(f"[!] Drive {drive_path!r} not found or not accessible.")
        return []
    try:
        all_files = os.listdir(drive_path)
    except Exception as e:
        print(f"[!] Cannot list {drive_path}: {e}")
        return []

    xvs_files = [f for f in all_files if f.endswith('.xvs')]
    if not xvs_files:
        print(f"[!] No .xvs files found on {drive_path}. Is this an Xbox external drive?")
        return []

    print(f"[*] Scanning {drive_path}: {len(xvs_files)} package(s) found")
    results = []
    _XBL_PREFIX = "[XBL:]" + chr(92)  # "[XBL:]\"

    def _clean_cdn_url(u):
        """Strip [XBL:]\\ or [XBL:]/ prefix and strip ,sid=... session params."""
        if u.startswith(_XBL_PREFIX):
            u = u[len(_XBL_PREFIX):]
        elif u.startswith("[XBL:]/"):
            u = u[7:]
        return u.split(",")[0]

    for xvs_file in sorted(xvs_files):
        content_id = xvs_file[:-4]
        try:
            raw = open(drive_path + xvs_file, 'rb').read()
            obj = json.loads(raw.decode('utf-16-le'))
            req = obj.get("Request", {})
            store_id = req.get("StoreId", "")
            sources = req.get("Sources", {})
            pkg_name = ""
            # Extract primary CDN URLs (main .xvc package, deduplicated by removing mirror dupes)
            cdn_urls = []
            fg_paths = sources.get("ForegroundCrdPaths", [])
            for u in fg_paths:
                clean = _clean_cdn_url(u)
                if clean.startswith("http") and clean not in cdn_urls:
                    cdn_urls.append(clean)
                if not pkg_name:
                    import re as _re
                    m = _re.search(r'/([A-Za-z][^/]+?_[\d.]+_[^/]+\.xvc)', clean)
                    if m:
                        pkg_name = m.group(1).split('_')[0]
            status = obj.get("Status", {})
            source = status.get("Source", {})
            current = source.get("Current", {})
            prior = source.get("Prior", {})
            build_version = current.get("BuildVersion", "")
            build_id = current.get("BuildId", "")
            platform = current.get("Platform", "")
            total_bytes = status.get("Progress", {}).get("Package", {}).get("TotalBytes", 0)
            fast_start = status.get("FastStartState", "")
            specifiers = sources.get("Specifiers", {})
            content_types = specifiers.get("ContentTypes", "")
            devices = specifiers.get("Devices", "")
            language = specifiers.get("Languages", "")
            plan_id = specifiers.get("PlanId", "")
            operation = specifiers.get("Operation", "")
            results.append({
                "contentId": content_id,
                "storeId": store_id,
                "packageName": pkg_name,
                "buildVersion": build_version,
                "buildId": build_id,
                "platform": platform,
                "sizeBytes": total_bytes,
                "cdnUrls": cdn_urls,
                "contentTypes": content_types,
                "devices": devices,
                "language": language,
                "planId": plan_id,
                "operation": operation,
                "fastStartState": fast_start,
                "priorBuildVersion": prior.get("BuildVersion", ""),
                "priorBuildId": prior.get("BuildId", ""),
            })
        except Exception as e:
            results.append({"contentId": content_id, "storeId": "", "packageName": "",
                            "buildVersion": "", "platform": "", "sizeBytes": 0,
                            "cdnUrls": [], "error": str(e)})
    return results


def build_usb_db(drive_letter="E"):
    """
    Scan all .xvs files on the drive and save full metadata to usb_db.json.
    Keyed by storeId (Microsoft Store product ID = productId in the library).
    Merges with any existing usb_db.json to accumulate data across scans.
    Before overwriting, saves a timestamped snapshot so version diffs are possible.
    """
    items = scan_usb_drive(drive_letter)
    if not items:
        return
    output_path = os.path.join(SCRIPT_DIR, "usb_db.json")
    existing = {}
    if os.path.isfile(output_path):
        try:
            existing = load_json(output_path) or {}
        except Exception:
            pass
        # Auto-snapshot the previous state before overwriting
        _usb_db_snapshot(existing)

    updated = 0
    for item in items:
        sid = item.get("storeId")
        if sid:
            existing[sid] = item
            updated += 1
        elif item.get("contentId"):
            existing["_content_" + item["contentId"]] = item
            updated += 1
    save_json(output_path, existing)
    print(f"[+] USB database saved: {output_path} ({updated} entries)")
    print(f"    Total entries in DB: {len(existing)}")
    print(f"    Rebuild HTML (option B from main menu) to apply to XCT.html")


def _usb_db_snapshot(db_dict):
    """
    Save a timestamped snapshot of usb_db to usb_db_snapshots/ directory.
    Called automatically before each [I] rescan so we can diff before/after.
    """
    snap_dir = os.path.join(SCRIPT_DIR, "usb_db_snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    snap_path = os.path.join(snap_dir, f"usb_db_{ts}.json")
    try:
        save_json(snap_path, db_dict)
        # Keep only the 10 most recent snapshots to avoid disk clutter
        snaps = sorted(
            [f for f in os.listdir(snap_dir) if f.startswith("usb_db_") and f.endswith(".json")],
            reverse=True)
        for old in snaps[10:]:
            try:
                os.remove(os.path.join(snap_dir, old))
            except OSError:
                pass
        print(f"    [snapshot] {snap_path}")
    except Exception as e:
        pass  # Snapshot failure is non-fatal


def _extract_plan_uuid(cdn_url, content_id):
    """Extract the planUUID segment from a CDN URL using contentId as anchor."""
    parsed = _cdn_parse(cdn_url, content_id)
    if not parsed:
        return None
    # planUUID is one segment before contentId in the URL path
    # URL: assets1.xboxlive.com/{shard}/{planUUID}/{contentId}/...
    parts = parsed["parts"]
    cid_lo = content_id.lower()
    cid_idx = next((i for i, s in enumerate(parts) if s.lower() == cid_lo), None)
    if cid_idx and cid_idx >= 2:
        return parts[cid_idx - 1]   # planUUID
    return None


def _cdn_diff_snapshots(snap_old, snap_new):
    """
    Compare two usb_db dicts.  For each game where the CDN planUUID changed
    (i.e. the game was updated), construct the prior-version URL using:
      - OLD planUUID   (from snap_old cdnUrls)
      - priorBuildId   (from snap_new — the new XVS knows its immediate predecessor)
      - priorBuildVersion (from snap_new)
      - contentId      (stable)
    Returns list of dicts with probe results.
    """
    found = []
    for sid, new_item in snap_new.items():
        if sid.startswith("_content_"):
            continue
        old_item = snap_old.get(sid)
        if not old_item:
            continue

        old_urls = old_item.get("cdnUrls", [])
        new_urls = new_item.get("cdnUrls", [])
        if not old_urls or not new_urls:
            continue

        content_id = new_item.get("contentId") or old_item.get("contentId")
        if not content_id:
            continue

        old_plan = _extract_plan_uuid(old_urls[0], content_id)
        new_plan = _extract_plan_uuid(new_urls[0], content_id)

        if not old_plan or not new_plan or old_plan == new_plan:
            continue  # planUUID unchanged — no update detected

        # Game was updated — planUUID changed!
        prior_ver_hex = new_item.get("priorBuildVersion", "")
        prior_bid     = new_item.get("priorBuildId", "")
        old_build_ver = old_item.get("buildVersion", "")
        old_build_id  = old_item.get("buildId", "")

        if not prior_bid:
            continue

        # Verify: prior build in new XVS should match what was current before
        # (priorBuildId == old buildId confirms we're looking at the right transition)
        version_match = (prior_bid.lower() == old_build_id.lower()) if old_build_id else "unknown"

        # Construct the prior URL: old planUUID + contentId + prior version segment + old filename
        old_parsed = _cdn_parse(old_urls[0], content_id)
        if not old_parsed:
            continue

        prior_human = _xbox_ver_decode(prior_ver_hex) if prior_ver_hex else ""
        if not prior_human:
            continue

        prior_seg = f"{prior_human}.{prior_bid}"

        # Build the URL using the OLD planUUID (from old_parsed["content_root"])
        # but with the prior version segment replacing the current version
        # old_parsed["content_root"] = scheme://host/shard/planUUID/contentId
        # We need: scheme://host/shard/OLD_planUUID/contentId/PRIOR_seg/PRIOR_pkg
        old_pkg  = old_parsed["pkg_name"]
        new_ver  = _xbox_ver_decode(new_item.get("buildVersion", ""))
        prior_pkg = old_pkg.replace(new_ver, prior_human, 1) if new_ver and new_ver in old_pkg else old_pkg

        # Rebuild with new planUUID path replaced by old planUUID path
        parts = list(old_parsed["parts"])
        parts[old_parsed["ver_idx"]] = prior_seg
        parts[old_parsed["pkg_idx"]] = prior_pkg
        candidate_url = old_parsed["scheme_host"] + "/" + "/".join(parts)

        found.append({
            "storeId":      sid,
            "contentId":    content_id,
            "old_plan":     old_plan,
            "new_plan":     new_plan,
            "prior_human":  prior_human,
            "prior_bid":    prior_bid,
            "version_match": version_match,
            "url":          candidate_url,
        })
    return found


def process_cdn_snapshot_compare():
    """
    Compare two usb_db snapshots to find games that updated (planUUID changed),
    then probe the old-planUUID URL for the prior version.
    """
    snap_dir = os.path.join(SCRIPT_DIR, "usb_db_snapshots")
    current_path = os.path.join(SCRIPT_DIR, "usb_db.json")

    print("\n[USB DB Snapshot Compare — find updated games]")

    # List available snapshots
    snaps = []
    if os.path.isdir(snap_dir):
        snaps = sorted(
            [f for f in os.listdir(snap_dir) if f.startswith("usb_db_") and f.endswith(".json")],
            reverse=True)

    if not snaps:
        print("[!] No snapshots found. Snapshots are auto-saved by [I] before each rescan.")
        print(f"    Expected location: {snap_dir}")
        return

    print(f"\n  Available snapshots ({len(snaps)}):")
    for i, s in enumerate(snaps, 1):
        ts = s.replace("usb_db_", "").replace(".json", "")
        ts_fmt = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}" if len(ts) >= 15 else ts
        print(f"    [{i}] {ts_fmt}  ({s})")
    print(f"    [C] Use current usb_db.json as 'new'")
    print()
    old_pick = input("  Use which snapshot as BEFORE (old)? [number / B=back]: ").strip()
    if old_pick.upper() == "B":
        return
    try:
        old_idx = int(old_pick) - 1
        if not (0 <= old_idx < len(snaps)):
            raise ValueError
        old_path = os.path.join(snap_dir, snaps[old_idx])
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
        return

    new_pick = input("  Use which as AFTER (new)? [number / C=current / B=back]: ").strip().upper()
    if new_pick == "B":
        return
    if new_pick == "C":
        new_path = current_path
    else:
        try:
            new_idx = int(new_pick) - 1
            new_path = os.path.join(snap_dir, snaps[new_idx])
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            return

    print(f"\n  OLD: {os.path.basename(old_path)}")
    print(f"  NEW: {os.path.basename(new_path)}")
    print()

    snap_old = load_json(old_path) or {}
    snap_new = load_json(new_path) or {}

    print(f"[*] Comparing {len(snap_old)} old vs {len(snap_new)} new entries ...")
    candidates = _cdn_diff_snapshots(snap_old, snap_new)

    if not candidates:
        print("  No planUUID changes detected — no game updates found between these snapshots.")
        print("  (If a game updated but planUUID stayed the same, prior URL probing won't help.)")
        return

    catalog_map = _build_catalog_map()
    print(f"\n  {len(candidates)} updated game(s) found (planUUID changed):\n")
    print(f"  {'#':>3}  {'Match':^5}  Title")
    print("  " + "─" * 60)
    for i, c in enumerate(candidates, 1):
        sid   = c["storeId"]
        title = catalog_map.get(sid, {}).get("title", sid)
        match = "✓" if c["version_match"] is True else ("?" if c["version_match"] == "unknown" else "✗")
        print(f"  {i:>3}  {match:^5}  {title[:50]}")
        print(f"          old plan: {c['old_plan']}")
        print(f"          new plan: {c['new_plan']}")
        print(f"          prior v:  {c['prior_human']}.{c['prior_bid']}")

    print()
    ans = input("  Probe CDN for all prior-version URLs? [Y/n]: ").strip().lower()
    if ans == "n":
        return

    all_found = []
    for i, c in enumerate(candidates, 1):
        sid   = c["storeId"]
        title = catalog_map.get(sid, {}).get("title", sid)
        url   = c["url"]
        print(f"\r  [{i:>2}/{len(candidates)}] {title[:50]:<50}  ", end="", flush=True)
        result = _cdn_head(url)
        if result is True:
            print(f"✓ FOUND!")
            print(f"    {url}")
            all_found.append({"title": title, "storeId": sid, "url": url,
                              "prior_human": c["prior_human"], "exists": True, "body": None})
        elif result is False:
            print("404")
        else:
            print("ERR")

    print()
    if all_found:
        out = os.path.join(SCRIPT_DIR, "cdn_older_versions.json")
        save_json(out, all_found)
        print(f"[+] Saved: {out}")
        ans2 = input(f"  Download {len(all_found)} prior-version package(s)? [y/N]: ").strip().lower()
        if ans2 == "y":
            dest = input("  Destination folder: ").strip().strip('"').strip("'")
            if dest:
                os.makedirs(dest, exist_ok=True)
                for f in all_found:
                    fname = f["url"].rsplit("/", 1)[-1]
                    _download_with_progress(f["url"], os.path.join(dest, fname), 0)
    else:
        print("  All prior-version URLs returned 404.")
        print("  → If planUUID also stays constant, the packages may be at the same path.")
        print("    Check the [A] CDN sweep option — it may now find them.")


def _build_catalog_map():
    """Build a productId → metadata dict from all cached library and marketplace data."""
    catalog_map = {}
    accounts = load_accounts()
    for gamertag in accounts:
        for fname in ("library.json", "marketplace.json"):
            fpath = account_path(gamertag, fname)
            if not os.path.isfile(fpath):
                continue
            items = load_json(fpath) or []
            for item in items:
                pid = item.get("productId", "")
                if pid and pid not in catalog_map:
                    catalog_map[pid] = {
                        "title": item.get("title", ""),
                        "publisher": item.get("publisher", ""),
                        "platforms": item.get("platforms", []),
                        "image": item.get("boxArt") or item.get("heroImage") or item.get("image") or "",
                        "productKind": item.get("productKind", ""),
                    }
    return catalog_map


def _build_freshdex_db():
    """Build Freshdex database: all PC/Windows8x games from cached library data."""
    seen = {}
    accounts = load_accounts()
    for gamertag in accounts:
        for fname in ("library.json", "marketplace.json"):
            fpath = account_path(gamertag, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                items = load_json(fpath) or []
            except (json.JSONDecodeError, IOError):
                continue
            for item in items:
                pid = item.get("productId", "")
                if not pid or pid in seen:
                    continue
                if item.get("productKind") != "Game":
                    continue
                plats = item.get("platforms", [])
                if not any(p in ("PC", "Windows.Windows8x") for p in plats):
                    continue
                seen[pid] = {
                    "productId": pid,
                    "title": item.get("title", ""),
                    "publisher": item.get("publisher", ""),
                    "category": item.get("category", ""),
                    "releaseDate": item.get("releaseDate", ""),
                    "platforms": plats,
                }
    return sorted(seen.values(), key=lambda x: x.get("title", "").lower())


def process_usb_drive(drive_letter=None):
    """Scan an Xbox USB drive and print/save an indexed game list."""
    print("\n[USB Drive Scanner]")
    if not drive_letter:
        drive_letter = input("  Drive letter (default: E): ").strip() or "E"
        drive_letter = drive_letter.rstrip(":/\\").upper()

    usb_items = scan_usb_drive(drive_letter)
    if not usb_items:
        return

    print("[*] Matching against local catalog data...")
    catalog_map = _build_catalog_map()

    enriched = []
    for item in usb_items:
        store_id = item.get("storeId", "")
        meta = catalog_map.get(store_id, {})
        title = meta.get("title", "")
        if not title:
            # Fall back to package name: strip publisher prefix (e.g. "JustForGamesSAS.How2Escape")
            pkg = item.get("packageName", "")
            parts = pkg.split(".", 1)
            title = parts[1] if len(parts) > 1 else (pkg or store_id or item["contentId"])
        enriched.append({
            **item,
            "title": title,
            "publisher": meta.get("publisher", ""),
            "platforms": meta.get("platforms", []),
            "image": meta.get("image", ""),
            "productKind": meta.get("productKind", ""),
            "inLibrary": bool(meta),
        })

    enriched.sort(key=lambda x: x.get("title", "").lower())

    matched = sum(1 for x in enriched if x.get("inLibrary"))
    total_gb = sum(x.get("sizeBytes", 0) for x in enriched) / 1e9

    print()
    w = 44
    print(f"{'#':>4}  {'Title':<{w}} {'StoreId':<14} {'Size':>7}  {'Status'}")
    print("─" * (4 + 2 + w + 1 + 14 + 1 + 7 + 2 + 10))
    for i, item in enumerate(enriched, 1):
        title = item.get("title", "")[:w]
        sid = item.get("storeId", "") or "?"
        gb = f"{item.get('sizeBytes', 0) / 1e9:.2f} GB" if item.get("sizeBytes") else "    ?"
        status = "in collection" if item.get("inLibrary") else ("no match" if item.get("storeId") else "no xvs data")
        print(f"{i:>4}  {title:<{w}} {sid:<14} {gb:>7}  {status}")
    print("─" * (4 + 2 + w + 1 + 14 + 1 + 7 + 2 + 10))
    print(f"  {len(enriched)} packages | {matched} matched to collection | {total_gb:.1f} GB total")

    index_file = os.path.join(SCRIPT_DIR, "usb_index.json")
    save_json(index_file, enriched)
    print(f"[+] Index saved: {index_file}")

    # Action menu
    print()
    print("  What next?")
    print("    [C] Copy files from drive to folder")
    print("    [D] Download from Xbox CDN")
    print("    [B] Back")
    print()
    action = input("  Choice: ").strip().upper()

    if action in ("C", "D"):
        dest = input("  Destination folder path (B=back): ").strip().strip('"').strip("'")
        if not dest or dest.upper() == "B":
            return
        sel = input("  Which games? [all / numbers e.g. 1 3 5-8 / B=back]: ").strip().lower()
        if sel == "b":
            return
        if not sel or sel == "all":
            indices = None
        else:
            indices = []
            for tok in sel.split():
                if "-" in tok:
                    try:
                        a, b = tok.split("-", 1)
                        indices.extend(range(int(a) - 1, int(b)))
                    except ValueError:
                        pass
                else:
                    try:
                        indices.append(int(tok) - 1)
                    except ValueError:
                        pass
        if action == "C":
            backup_usb_games(enriched, drive_letter + ":/", dest, indices)
        else:
            download_from_cdn(enriched, dest, indices)


def _copy_with_progress(src, dst, label=""):
    """Copy src to dst in chunks, printing a progress bar. Returns bytes copied."""
    CHUNK = 8 * 1024 * 1024  # 8 MB
    size = os.path.getsize(src)
    copied = 0
    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
        while True:
            buf = fsrc.read(CHUNK)
            if not buf:
                break
            fdst.write(buf)
            copied += len(buf)
            pct = copied * 100 // size if size else 100
            filled = 30 * copied // size if size else 30
            bar = "#" * filled + "-" * (30 - filled)
            lbl = label[:38] if len(label) <= 38 else label[:36] + ".."
            print(f"\r    [{bar}] {pct:3d}%  {copied/1073741824:.2f}/{size/1073741824:.2f} GB  {lbl:<38}",
                  end="", flush=True)
    print()
    try:
        import shutil as _sh
        _sh.copystat(src, dst)
    except Exception:
        pass
    return copied


def backup_usb_games(enriched, drive_path, dest_path, indices=None):
    """
    Copy Xbox game packages from drive_path to dest_path.
    Each game consists of a main XVD file (no extension) plus .xct/.xvi/.xvs companions.
    Skips files that already exist at the destination with the same size.
    """
    import shutil

    to_copy = [enriched[i] for i in indices if 0 <= i < len(enriched)] if indices is not None else enriched
    if not to_copy:
        print("[!] Nothing selected to backup.")
        return

    total_bytes = sum(item.get("sizeBytes", 0) for item in to_copy)
    print(f"\n[*] Backing up {len(to_copy)} package(s) — approx {total_bytes / 1e9:.1f} GB")

    # Check destination free space
    try:
        os.makedirs(dest_path, exist_ok=True)
        free = shutil.disk_usage(dest_path).free
        if total_bytes > 0 and free < total_bytes:
            print(f"[!] Warning: destination has {free/1e9:.1f} GB free but ~{total_bytes/1e9:.1f} GB needed")
            ans = input("    Continue anyway? [y/N]: ").strip().lower()
            if ans != "y":
                print("    Cancelled.")
                return
    except Exception as e:
        print(f"[!] Could not check destination: {e}")
        return

    COMPANIONS = ["", ".xct", ".xvi", ".xvs"]
    total_copied = 0
    total_skipped = 0
    errors = 0

    for n, item in enumerate(to_copy, 1):
        cid = item["contentId"]
        title = item.get("title", cid)
        sid = item.get("storeId", "")
        print(f"\n  [{n}/{len(to_copy)}] {title[:60]}")
        if sid:
            print(f"    StoreId: {sid}   ContentId: {cid}")

        for ext in COMPANIONS:
            src = os.path.join(drive_path, cid + ext)
            dst = os.path.join(dest_path, cid + ext)

            if not os.path.exists(src):
                continue

            src_size = os.path.getsize(src)

            if os.path.exists(dst) and os.path.getsize(dst) == src_size:
                print(f"    {cid + ext:<55}  already exists, skipping")
                total_skipped += 1
                continue

            try:
                if not ext:
                    # Large main XVD — copy with progress bar
                    total_copied += _copy_with_progress(src, dst, cid + ext)
                else:
                    # Small companion file — quick copy
                    shutil.copy2(src, dst)
                    print(f"    {cid + ext:<55}  {src_size / 1024:.0f} KB")
            except Exception as e:
                print(f"\n    [!] Failed to copy {cid + ext}: {e}")
                errors += 1

    print()
    print(f"[+] Backup done: {total_copied / 1e9:.2f} GB copied, "
          f"{total_skipped} file(s) skipped, {errors} error(s)")
    print(f"[+] Destination: {dest_path}")


def _download_with_progress(url, dest_file, expected_size=0, timeout=120):
    """
    Download url to dest_file with a progress bar. Resumes if a partial file exists.
    Tries each url in turn on failure. Returns bytes downloaded, or -1 on error.
    """
    CHUNK = 8 * 1024 * 1024  # 8 MB
    resume_from = 0
    if os.path.exists(dest_file):
        resume_from = os.path.getsize(dest_file)
        if expected_size and resume_from == expected_size:
            print(f"    Already complete, skipping.")
            return 0

    headers = {}
    if resume_from:
        headers["Range"] = f"bytes={resume_from}-"
        print(f"    Resuming from {resume_from / 1e9:.2f} GB")

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            total = int(resp.headers.get("Content-Length", 0)) + resume_from
            if not total and expected_size:
                total = expected_size
            downloaded = resume_from
            mode = "ab" if resume_from else "wb"
            label = os.path.basename(url)[:38]
            with open(dest_file, mode) as f:
                while True:
                    buf = resp.read(CHUNK)
                    if not buf:
                        break
                    f.write(buf)
                    downloaded += len(buf)
                    if total:
                        pct = downloaded * 100 // total
                        filled = 30 * downloaded // total
                    else:
                        pct, filled = 0, 0
                    bar = "#" * filled + "-" * (30 - filled)
                    print(f"\r    [{bar}] {pct:3d}%  {downloaded/1073741824:.2f}/{total/1073741824:.2f} GB  {label:<38}",
                          end="", flush=True)
            print()
            return downloaded - resume_from
    except urllib.error.HTTPError as e:
        if e.code == 416:
            print(f"    Already complete, skipping.")
            return 0
        print(f"\n    [!] HTTP {e.code}: {e.reason}")
        return -1
    except Exception as e:
        print(f"\n    [!] {e}")
        return -1


def download_from_cdn(enriched, dest_path, indices=None):
    """
    Download Xbox game packages from CDN using URLs extracted from .xvs files.
    Files are saved with uppercase UUID filenames (no extension) per sideload convention.
    Resumable: skips or resumes partially downloaded files.
    """
    import shutil

    to_dl = [enriched[i] for i in indices if 0 <= i < len(enriched)] if indices is not None else enriched
    if not to_dl:
        print("[!] Nothing selected.")
        return

    no_url = [x for x in to_dl if not x.get("cdnUrls")]
    if no_url:
        print(f"[!] {len(no_url)} package(s) have no CDN URL and will be skipped.")
    to_dl = [x for x in to_dl if x.get("cdnUrls")]
    if not to_dl:
        return

    total_bytes = sum(x.get("sizeBytes", 0) for x in to_dl)
    print(f"\n[*] Downloading {len(to_dl)} package(s) — approx {total_bytes / 1e9:.1f} GB")

    try:
        os.makedirs(dest_path, exist_ok=True)
        free = shutil.disk_usage(dest_path).free
        if total_bytes > 0 and free < total_bytes:
            print(f"[!] Warning: destination has {free/1e9:.1f} GB free but ~{total_bytes/1e9:.1f} GB needed")
            if input("    Continue anyway? [y/N]: ").strip().lower() != "y":
                print("    Cancelled.")
                return
    except Exception as e:
        print(f"[!] Could not check destination: {e}")
        return

    total_downloaded = 0
    errors = 0

    for n, item in enumerate(to_dl, 1):
        cid = item["contentId"].upper()   # uppercase per sideload convention
        title = item.get("title", cid)
        sid = item.get("storeId", "")
        cdn_urls = item.get("cdnUrls", [])
        expected = item.get("sizeBytes", 0)

        print(f"\n  [{n}/{len(to_dl)}] {title[:60]}")
        if sid:
            print(f"    StoreId: {sid}")
        print(f"    Saving as: {cid}  ({expected/1e9:.2f} GB)")

        dest_file = os.path.join(dest_path, cid)
        got = -1
        for url in cdn_urls:
            print(f"    CDN: {url[:80]}")
            got = _download_with_progress(url, dest_file, expected)
            if got >= 0:
                break
            print(f"    Trying next mirror...")

        if got < 0:
            print(f"    [!] All mirrors failed for {cid}")
            errors += 1
        else:
            total_downloaded += got

    print()
    print(f"[+] Download done: {total_downloaded / 1e9:.2f} GB downloaded, {errors} error(s)")
    print(f"[+] Destination: {dest_path}")


# ===========================================================================
# CDN Version Discovery
#
# Xbox CDN URL format:
#   http://assets{N}.xboxlive.com/{shard}/{planUUID}/{contentId}/{ver}.{buildId}/{pkg}.xvc
#
# buildVersion in XVS is a 16-char hex string encoding 4×uint16 big-endian:
#   "0001000000040000" → major=1, minor=0, patch=4, rev=0 → "1.0.4.0"
#
# We have priorBuildVersion + priorBuildId in the USB DB, so we can
# reconstruct the prior version's URL exactly. Beyond that, we probe for
# manifest/index files at the content root that could reveal all buildIds.
# ===========================================================================

def _xbox_ver_decode(hex_str):
    """
    Decode an Xbox build version hex string to a human-readable dotted version.
    "0001000000040000" → "1.0.4.0"  (4 × uint16 big-endian, leading zeros stripped)
    Returns the original string unchanged if it cannot be decoded.
    """
    if not hex_str or len(hex_str) < 16:
        return hex_str
    try:
        parts = [int(hex_str[i:i+4], 16) for i in range(0, 16, 4)]
        return ".".join(str(p) for p in parts)
    except ValueError:
        return hex_str


def _cdn_parse(url, content_id):
    """
    Parse a CDN URL into components, using the contentId UUID as an anchor.
    Returns dict or None if the contentId cannot be located in the URL.
    """
    from urllib.parse import urlparse
    p      = urlparse(url)
    parts  = p.path.strip("/").split("/")
    cid_lo = content_id.lower()

    cid_idx = next((i for i, seg in enumerate(parts) if seg.lower() == cid_lo), None)
    if cid_idx is None or cid_idx + 2 > len(parts) - 1:
        return None

    ver_idx = cid_idx + 1
    pkg_idx = cid_idx + 2          # package is always the segment after version
    return {
        "scheme_host":   f"{p.scheme}://{p.netloc}",
        "parts":         parts,
        "ver_idx":       ver_idx,
        "pkg_idx":       pkg_idx,
        "ver_seg":       parts[ver_idx],
        "pkg_name":      parts[pkg_idx],
        "content_root":  f"{p.scheme}://{p.netloc}/" + "/".join(parts[:ver_idx]),
    }


def _cdn_rebuild(parsed, new_ver_seg, new_pkg=None):
    """Reconstruct a CDN URL with a replacement version segment (and optionally package name)."""
    parts = list(parsed["parts"])
    parts[parsed["ver_idx"]] = new_ver_seg
    if new_pkg:
        parts[parsed["pkg_idx"]] = new_pkg
    return parsed["scheme_host"] + "/" + "/".join(parts)


def _cdn_head(url, timeout=8):
    """
    Send a HEAD request. Returns True (200/206), False (404), or None (other/error).
    """
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Microsoft-Delivery-Optimization/10.0")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status in (200, 206)
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def _cdn_get_text(url, timeout=8):
    """Fetch a URL and return its text body, or None on failure."""
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Microsoft-Delivery-Optimization/10.0")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def discover_cdn_versions(item):
    """
    Probe the Xbox CDN for older versions of the given USB item.

    Strategy 1 — Prior version from XVS:
        priorBuildVersion (hex) decoded → human version string
        priorBuildId → GUID used directly in the URL version segment
        → Try same package filename, then also with version replaced in filename

    Strategy 2 — Manifest/index discovery at content root:
        Probe well-known filenames at the URL level above the version directory.
        If a JSON manifest is found it may list all available buildIds.

    Returns list of dicts: {url, label, exists, body}
    """
    results = []

    cdn_urls = item.get("cdnUrls", [])
    content_id = item.get("contentId", "")
    build_ver_hex = item.get("buildVersion", "")
    prior_ver_hex = item.get("priorBuildVersion", "")
    prior_bid     = item.get("priorBuildId", "")

    if not cdn_urls or not content_id:
        return results

    base_url   = cdn_urls[0]
    parsed     = _cdn_parse(base_url, content_id)
    if not parsed:
        return results

    human_ver  = _xbox_ver_decode(build_ver_hex)

    # ── Strategy 1: prior version ────────────────────────────────────────────
    if prior_ver_hex and prior_bid:
        prior_human = _xbox_ver_decode(prior_ver_hex)
        prior_seg   = f"{prior_human}.{prior_bid}"

        if prior_seg != parsed["ver_seg"]:
            # 1a: same package filename
            url_a  = _cdn_rebuild(parsed, prior_seg)
            ex_a   = _cdn_head(url_a)
            results.append({"url": url_a, "label": f"v{prior_human} prior — same filename",
                             "exists": ex_a, "body": None})

            # 1b: version replaced inside the package filename
            old_pkg = parsed["pkg_name"]
            new_pkg = old_pkg.replace(human_ver, prior_human, 1) if human_ver in old_pkg else None
            if new_pkg and new_pkg != old_pkg:
                url_b = _cdn_rebuild(parsed, prior_seg, new_pkg)
                ex_b  = _cdn_head(url_b)
                results.append({"url": url_b, "label": f"v{prior_human} prior — renamed pkg",
                                 "exists": ex_b, "body": None})

    # ── Strategy 2: manifest / index files at content root ───────────────────
    content_root = parsed["content_root"]
    manifest_names = [
        "packages.json", "index.json", "ContentMetadata.json",
        "packagespec.json", "manifest.json", "buildindex.json",
        "packagelist.json", "versions.json",
    ]
    for name in manifest_names:
        murl = f"{content_root}/{name}"
        ex = _cdn_head(murl)
        if ex:
            body = _cdn_get_text(murl)
            results.append({"url": murl, "label": f"manifest: {name}",
                             "exists": True, "body": body})

    return results


def _parse_selection(sel_str, max_idx):
    """Parse a selection string like '1 3 5-8' into a list of 0-based indices."""
    indices = []
    for tok in sel_str.split():
        if "-" in tok:
            try:
                a, b = tok.split("-", 1)
                indices.extend(range(int(a) - 1, int(b)))
            except ValueError:
                pass
        else:
            try:
                indices.append(int(tok) - 1)
            except ValueError:
                pass
    return [i for i in indices if 0 <= i < max_idx]


def _cdn_load_items():
    """Load and enrich items from usb_db.json. Returns sorted list or None on error."""
    usb_db_file = os.path.join(SCRIPT_DIR, "usb_db.json")
    if not os.path.isfile(usb_db_file):
        print("[!] No usb_db.json found. Run [I] (Save USB metadata) first.")
        return None
    usb_db = load_json(usb_db_file) or {}
    items = [v for v in usb_db.values() if not v.get("contentId", "").startswith("_content_")]
    if not items:
        print("[!] USB DB is empty.")
        return None
    catalog_map = _build_catalog_map()
    for item in items:
        sid = item.get("storeId", "")
        item["_title"] = (catalog_map.get(sid, {}).get("title", "")
                          or item.get("packageName", sid or "?"))
    items.sort(key=lambda x: x.get("_title", "").lower())
    return items


def _cdn_finish(all_found):
    """Print summary, save results, offer download."""
    print()
    downloadable = [f for f in all_found if f.get("url", "").endswith(".xvc")]
    if all_found:
        print(f"  ✓ {len(all_found)} URL(s) found.")
        out = os.path.join(SCRIPT_DIR, "cdn_older_versions.json")
        save_json(out, [{k: v for k, v in f.items() if k != "body"} for f in all_found])
        print(f"[+] Saved: {out}")
        if downloadable:
            print()
            ans = input(f"  Download {len(downloadable)} older .xvc package(s)? [y/N]: ").strip().lower()
            if ans == "y":
                dest = input("  Destination folder: ").strip().strip('"').strip("'")
                if dest:
                    os.makedirs(dest, exist_ok=True)
                    for f in downloadable:
                        fname = f["url"].rsplit("/", 1)[-1]
                        _download_with_progress(f["url"], os.path.join(dest, fname), 0)
    else:
        print("  Nothing found. Older versions may have been purged from the CDN.")


def _cdn_sweep_all(items):
    """
    Fast sweep of all items: probe only the prior-version renamed-package URL
    (the most accurate variant) plus manifest files. Shows one progress line
    per game, only printing results for hits.
    Returns list of found dicts.
    """
    # Only check items that have what we need
    candidates = [x for x in items
                  if x.get("cdnUrls") and x.get("buildVersion")
                  and x.get("priorBuildVersion") and x.get("priorBuildId")]
    skipped = len(items) - len(candidates)

    print(f"\n[*] Sweeping {len(candidates)} games"
          + (f" ({skipped} skipped — no CDN/prior data)" if skipped else "")
          + " ...")
    print()

    all_found = []
    w = 52  # title display width

    for n, item in enumerate(candidates, 1):
        title     = item.get("_title", "?")
        title_tr  = title[:w]
        print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}", end="", flush=True)

        content_id    = item.get("contentId", "")
        build_ver_hex = item.get("buildVersion", "")
        prior_ver_hex = item.get("priorBuildVersion", "")
        prior_bid     = item.get("priorBuildId", "")
        base_url      = item["cdnUrls"][0]

        parsed     = _cdn_parse(base_url, content_id)
        if not parsed:
            continue

        human_ver   = _xbox_ver_decode(build_ver_hex)
        prior_human = _xbox_ver_decode(prior_ver_hex)
        prior_seg   = f"{prior_human}.{prior_bid}"

        if prior_seg == parsed["ver_seg"]:
            continue  # prior == current, nothing to try

        # Best-effort: renamed-package URL only (most correct variant)
        old_pkg = parsed["pkg_name"]
        new_pkg = old_pkg.replace(human_ver, prior_human, 1) if human_ver in old_pkg else old_pkg
        url     = _cdn_rebuild(parsed, prior_seg, new_pkg)
        exists  = _cdn_head(url)

        if exists is True:
            print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}  ✓ FOUND v{prior_human}")
            all_found.append({"title": title, "url": url,
                              "label": f"v{prior_human} prior", "exists": True, "body": None})
        # else: stay quiet — just show the rolling progress line

        # Manifest probe (silent unless found)
        content_root = parsed["content_root"]
        for name in ("packages.json", "index.json", "ContentMetadata.json",
                     "packagespec.json", "versions.json"):
            murl = f"{content_root}/{name}"
            mex  = _cdn_head(murl)
            if mex:
                body = _cdn_get_text(murl)
                print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}  ✓ MANIFEST {name}")
                all_found.append({"title": title, "url": murl,
                                  "label": f"manifest: {name}", "exists": True, "body": body})

    print()  # newline after the rolling progress line
    return all_found


# ── Windows Update Catalog strategy ──────────────────────────────────────────
#
# Xbox games are delivered via the Windows Update infrastructure.  Each product
# has a WuCategoryId which can be used to search the public Microsoft Update
# Catalog (catalog.update.microsoft.com).  The catalog keeps historical entries
# even after the Xbox CDN purges old packages, so it's the best public source
# for older version packages.
#
# Flow:
#   1. DisplayCatalog API → WuCategoryId (public, no auth required)
#   2. WU Catalog search  → list of update entries (each = one published version)
#   3. DownloadDialog API → fresh download URLs per entry (URL is time-limited
#      but the update ID is stable and can always be re-used to get a fresh URL)
# =============================================================================

def _display_catalog_get_wuid(store_id, timeout=12):
    """
    Query the public DisplayCatalog API (no auth) to get the WuCategoryId for
    an Xbox/Store product.  Returns the WuCategoryId string, or None.
    """
    import urllib.request
    url = (f"https://displaycatalog.mp.microsoft.com/v7.0/products/{store_id}"
           f"?market=US&languages=en-us&MS-CV=DGU1mcuYo0WMMp")
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "WindowsShellClient/9.0.40929.0 (Windows)")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        for dsa in data.get("Product", {}).get("DisplaySkuAvailabilities", []):
            fd = (dsa.get("Sku", {})
                     .get("Properties", {})
                     .get("FulfillmentData", {}))
            wuid = fd.get("WuCategoryId") or fd.get("WuBundleCategoryId")
            if wuid:
                return wuid
    except Exception:
        pass
    return None


def _wu_catalog_search(wu_cat_id, timeout=20):
    """
    Search the Microsoft Update Catalog for entries matching wu_cat_id.
    Returns list of dicts: {update_id, uid_info, title, date, size}
    """
    import urllib.request, urllib.parse, re, html as _html
    url = ("https://www.catalog.update.microsoft.com/Search.aspx"
           f"?q={urllib.parse.quote(wu_cat_id)}")
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        req.add_header("Accept", "text/html,application/xhtml+xml")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            page = r.read().decode("utf-8", errors="replace")
    except Exception:
        return []

    results = []
    # Each update row contains onclick="goToDetails('GUID_RevNum')"
    detail_pat = re.compile(r"goToDetails\(['\"]([0-9a-fA-F\-]+(?:_\d+)?)['\"]",  re.I)
    row_pat    = re.compile(r"<tr[^>]*>\s*(.*?)\s*</tr>", re.DOTALL | re.I)
    td_pat     = re.compile(r"<td[^>]*>(.*?)</td>",       re.DOTALL | re.I)
    tag_pat    = re.compile(r"<[^>]+>")

    for row in row_pat.finditer(page):
        row_html = row.group(1)
        dm = detail_pat.search(row_html)
        if not dm:
            continue
        uid_info  = dm.group(1)
        update_id = uid_info.split("_")[0]
        cells = [_html.unescape(tag_pat.sub("", td.group(1))).strip()
                 for td in td_pat.finditer(row_html)]
        results.append({
            "update_id": update_id,
            "uid_info":  uid_info,
            "title":     cells[1] if len(cells) > 1 else "",
            "date":      cells[4] if len(cells) > 4 else "",
            "size":      cells[6] if len(cells) > 6 else "",
        })
    return results


def _wu_catalog_get_links(uid_info_list, timeout=20):
    """
    POST to DownloadDialog.aspx to get download URLs for a list of uid_info strings
    (format: 'updateID' or 'updateID_revisionNum').
    Returns list of URL strings (may be empty if no packages found or they expired).
    """
    import urllib.request, urllib.parse, json as _json, re
    if not uid_info_list:
        return []
    payload = [{"size": 0, "uidInfo": ui, "updateID": ui.split("_")[0]}
               for ui in uid_info_list]
    body = urllib.parse.urlencode(
        {"updateIDs": _json.dumps(payload), "updateIDsBlockedForImport": ""}
    ).encode("utf-8")
    url = "https://www.catalog.update.microsoft.com/DownloadDialog.aspx"
    try:
        req = urllib.request.Request(url, data=body)
        req.add_header("User-Agent",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Referer",      "https://www.catalog.update.microsoft.com/")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            page = r.read().decode("utf-8", errors="replace")
    except Exception:
        return []
    # Response embeds download URLs in JavaScript — grab anything that looks like a file
    url_pat = re.compile(
        r'https?://[^\s\'"<>]+\.(?:xvc|exe|cab|msi|appx|msix|appxbundle|xar|zip)',
        re.I)
    return list(dict.fromkeys(url_pat.findall(page)))  # deduplicated, order-preserved


def _cdn_sweep_wu_catalog(items):
    """
    For each item with a storeId:
      1. Fetch WuCategoryId from DisplayCatalog API (cached in usb_db.json)
      2. Search Microsoft Update Catalog for all published update entries
         NOTE: Xbox console (XVC) packages may not appear in WU Catalog — it
         depends on whether the publisher submitted them to the WU feed.
         Windows Store / MSIXVC packages are more likely to appear.
      3. If multiple entries exist → older versions are available
      4. Fetch download links from DownloadDialog for all entries
    Returns list of found dicts (one per game that has older versions).
    """
    import time

    candidates = [x for x in items if x.get("storeId")]
    skipped    = len(items) - len(candidates)
    print(f"\n[*] Scanning {len(candidates)} games via Windows Update Catalog"
          + (f" ({skipped} skipped — no storeId)" if skipped else "") + " ...")
    print("    Step 1: displaycatalog.mp.microsoft.com → WuCategoryId")
    print("    Step 2: catalog.update.microsoft.com   → update history")
    print()

    # Load usb_db for WuCategoryId caching
    db_path  = os.path.join(SCRIPT_DIR, "usb_db.json")
    usb_db   = (load_json(db_path) or {}) if os.path.isfile(db_path) else {}
    db_dirty = False
    all_found = []
    w = 46

    for n, item in enumerate(candidates, 1):
        sid      = item["storeId"]
        title    = item.get("_title", sid)
        title_tr = title[:w]
        print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}  [WuCategoryId…]  ", end="", flush=True)

        # Check cache first to avoid re-fetching
        wuid = (usb_db.get(sid) or {}).get("wuCategoryId") or item.get("wuCategoryId")
        if not wuid:
            wuid = _display_catalog_get_wuid(sid)
            if wuid and sid in usb_db:
                usb_db[sid]["wuCategoryId"] = wuid
                db_dirty = True

        if not wuid:
            continue  # DisplayCatalog has no WuCategoryId for this title

        print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}  [WU search…]     ", end="", flush=True)
        time.sleep(0.25)  # gentle rate-limiting
        updates = _wu_catalog_search(wuid)
        if not updates:
            continue

        if len(updates) > 1:
            print(f"\r  [{n:>3}/{len(candidates)}] {title_tr:<{w}}  ✓ {len(updates)} entries in WU Catalog")
            # Fetch download links for all entries (not just current)
            uid_infos = [u["uid_info"] for u in updates]
            links     = _wu_catalog_get_links(uid_infos)
            all_found.append({
                "title":   title,
                "storeId": sid,
                "wuCatId": wuid,
                "updates": updates,
                "links":   links,
                "label":   f"{len(updates)} WU versions — {len(links)} link(s)",
                "url":     links[0] if links else "",
                "exists":  True,
                "body":    None,
            })
        # single entry = only current version published, nothing older

    print()

    if db_dirty:
        save_json(db_path, usb_db)
        print(f"[+] WuCategoryId cache saved to usb_db.json")

    return all_found


def _cdn_refresh_wu_links(wu_cat_id, timeout=20):
    """
    Re-fetch fresh download links for ALL update entries under wu_cat_id.
    Use this when previously-saved links have expired.
    Returns list of URL strings.
    """
    updates = _wu_catalog_search(wu_cat_id, timeout=timeout)
    if not updates:
        return []
    uid_infos = [u["uid_info"] for u in updates]
    return _wu_catalog_get_links(uid_infos, timeout=timeout)


def process_gfwl_download():
    """
    Download GFWL (Games for Windows - LIVE) game packages.
    Uses download-ssl.xbox.com which bypasses the Akamai 403 block on download.xbox.com.
    URL format: http://download-ssl.xbox.com/content/gfwl/{TID}/{SHA1}_{N}.cab
    """
    GFWL_71_TIDS = {
        '4E4D0FA2','48450FA0','4D530FA3','534307FF','5343080C','57520FA0',
        '5A450FA0','534307FA','5454085C','5454086F','58410A6D','415807D5',
        '45410935','58410A1C','44540FA0','4E4D0FA1','43430803','4343080E',
        '43430FA2','434D0820','434D0FA0','434D0831','434D0FA1','4D53090A',
        '425307D6','454D07D4','434D082F','4D530901','4D530842','57520FA3',
        '5454083B','4D53080F','4D5707E4','4D530FA7','4D530FA8','5451081F',
        '534307EB','43430808','434307DE','584109F1','4D5308D2','57520FA2',
        '4D530FA5','434D083E','58410A10','41560829','54510837','434307F7',
        '43430FA1','48450FA1','535007E3','544707D4','4D5307D6','4C4107EB',
        '53450826','434307F4','43430FA5','43430FA0','49470FA1','534507F6',
        '584109EB','4D530FA2','425607F3','534507F0','5345082C','53450FA2',
        '4D530841','5451082D','58410A01','584109F0',
        '424107DF',  # Legend of the Galactic Heroes
    }

    gfwl_file = os.path.join(SCRIPT_DIR, "gfwl_links.json")
    if not os.path.isfile(gfwl_file):
        print("[!] gfwl_links.json not found.")
        return

    try:
        gfwl_raw = load_json(gfwl_file) or {}
    except Exception as e:
        print(f"[!] Error loading gfwl_links.json: {e}")
        return

    games = []
    for tid, v in gfwl_raw.items():
        if tid in GFWL_71_TIDS:
            games.append({
                'tid': tid,
                'name': v.get('name', tid),
                'packages': v.get('packages', []),
                'total_size': v.get('total_size', 0),
            })
    games.sort(key=lambda x: x['name'].lower())

    if not games:
        print("[!] No GFWL achievement games found in gfwl_links.json.")
        return

    def fmt_size(b):
        if not b:
            return '?'
        if b >= 1e9:
            return f"{b/1e9:.2f}GB"
        if b >= 1e6:
            return f"{b/1e6:.0f}MB"
        return f"{b//1024}KB"

    print(f"\n[GFWL Game Downloader]  {len(games)} achievement games")
    print()
    print(f"  {'#':>3}  {'Title ID':>10}  {'Pkgs':>4}  {'Size':>9}  Name")
    print("  " + "─" * 75)
    for i, g in enumerate(games, 1):
        pkg_count = len(g['packages'])
        flag = '' if pkg_count else '  (no pkg data)'
        print(f"  {i:>3}  {g['tid']:>10}  {pkg_count:>4}  {fmt_size(g['total_size']):>9}  {g['name']}{flag}")
    print()

    game = None
    while game is None:
        sel = input(f"  Select [1-{len(games)} / B=back]: ").strip()
        if sel.upper() == "B":
            return
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(games):
                game = games[idx]
            else:
                print("  Out of range.")
        except ValueError:
            print("  Enter a number.")

    pkgs = game['packages']
    if not pkgs:
        print(f"\n[!] {game['name']} has no package data in gfwl_links.json.")
        return

    has_base = any(p.get('offer_suffix') == 'e0000001' for p in pkgs)

    def offer_label(pkg):
        s = pkg.get('offer_suffix', '')
        if pkg.get('type'):
            return pkg.get('type')
        if s == 'e0000001':
            return 'Base'
        if s.startswith('e0000'):
            try:
                n = int(s[5:], 16)
                return f'DLC-{n - 1}'
            except ValueError:
                return 'DLC'
        # 0ecf/0100/0130/0140 = tiny service/license config blobs
        if s[:4] in ('0ecf', '0100', '0130', '0140', '0200', '022f', '033f', '0002'):
            return 'Config'
        # 0ebf/0edf/0ec0/0ccf/0bbf/0ebd = game content chunks OR trailers
        # When a Base installer exists, these are supplementary (trailers/bonus video)
        if s[:4] in ('0ebf', '0edf', '0ec0', '0ccf', '0bbf', '0ebd'):
            return 'Trailer' if has_base else 'Content'
        return 'Pack'

    print(f"\n  Selected: {game['name']}  [{game['tid']}]")
    print()

    # Summarise what types are present so the user knows what to download
    labels      = [offer_label(p) for p in pkgs]
    has_trailer = 'Trailer' in labels
    has_content = 'Content' in labels
    has_config  = 'Config'  in labels
    if has_base:
        legend = "  Type legend:  Base = main game installer  |  DLC = paid DLC"
        if has_trailer: legend += "  |  Trailer = bonus video/trailer"
        if has_config:  legend += "  |  Config = tiny license config"
        if 'Demo' in labels: legend += "  |  Demo = playable demo"
        print(legend)
    else:
        print("  Note: no standard Base installer — Content chunks ARE the game (download all Content)")
    print()
    print(f"  {'#':>3}  {'Type':>7}  {'Offer ID':>10}  {'Size':>9}  SHA-1 Content ID")
    print("  " + "─" * 78)
    for i, p in enumerate(pkgs, 1):
        s = p.get('offer_suffix', '')
        label = offer_label(p)
        cid = p.get('content_id', '?')
        size = fmt_size(p.get('package_size', 0))
        print(f"  {i:>3}  {label:>7}  {s:>10}  {size:>9}  {cid}")
    print()

    pkg_sel = input(f"  Download which? [1-{len(pkgs)} / Enter=all / B=back]: ").strip()

    if pkg_sel.upper() == "B":
        return
    if not pkg_sel:
        selected_pkgs = pkgs
    else:
        indices = _parse_selection(pkg_sel.replace(',', ' '), len(pkgs))
        selected_pkgs = [pkgs[i] for i in indices]

    if not selected_pkgs:
        print("[!] Nothing selected.")
        return

    default_dest = os.path.join(SCRIPT_DIR, "gfwl_downloads")
    print()
    dest = input(f"  Destination folder [Enter={default_dest} / B=back]: ").strip().strip('"').strip("'")
    if dest.upper() == "B":
        return
    if not dest:
        dest = default_dest

    safe_name = "".join(c if c.isalnum() or c in " ._-" else "_" for c in game['name']).strip()
    game_dir = os.path.join(dest, safe_name)
    os.makedirs(game_dir, exist_ok=True)
    print(f"\n  Saving to: {game_dir}")

    tid_upper = game['tid'].upper()
    tid_lower = game['tid'].lower()

    for pkg in selected_pkgs:
        s     = pkg.get('offer_suffix', '')
        sha1  = pkg.get('content_id', '').upper()
        label = offer_label(pkg)
        print(f"\n  ▸ {label} ({s})")

        if label in ('Base', 'DLC'):
            # Standard catalog offers: /content/gfwl/{TID}/{SHA1}_{N}.cab
            if not sha1:
                print("    [!] No content_id for this package, skipping.")
                continue
            parts = []
            for n in range(1, 50):
                url = f"http://download-ssl.xbox.com/content/gfwl/{tid_upper}/{sha1}_{n}.cab"
                sys.stdout.write(f"    Probing part {n}...    \r")
                sys.stdout.flush()
                ok = _cdn_head(url)
                if ok:
                    parts.append(url)
                else:
                    break
            sys.stdout.write("                          \r")
            if not parts:
                print(f"    [!] No parts found (all 404).")
                continue
            print(f"    {len(parts)} part(s) found.")
            for url in parts:
                fname = url.rsplit("/", 1)[-1]
                _download_with_progress(url, os.path.join(game_dir, fname), timeout=300)
        else:
            # Content/Config/Pack: /content/{tid}/{tid}{offer_suffix}.cab  (single file)
            # Build a list of candidate suffixes: stored value first, then try with 0e prefix
            # (data sometimes records 0bbf/0cbf/0dbf when the CDN actually uses 0ebf etc.)
            candidates = [s.upper(), s]
            if len(s) >= 4 and s[0] == '0' and s[1] != 'e' and s[2:4] in ('bf', 'cf', 'df'):
                fallback = '0e' + s[2:]
                candidates.extend([fallback.upper(), fallback])
            found_url = None
            for cand in candidates:
                u = f"http://download-ssl.xbox.com/content/{tid_lower}/{tid_lower}{cand}.cab"
                sys.stdout.write(f"    Probing {cand}...    \r")
                sys.stdout.flush()
                if _cdn_head(u):
                    found_url = u
                    break
            sys.stdout.write("                          \r")
            if not found_url:
                tried = ', '.join(candidates)
                print(f"    [!] Not found (404) — tried: {tried}")
                continue
            fname = found_url.rsplit("/", 1)[-1]
            _download_with_progress(found_url, os.path.join(game_dir, fname), timeout=300)

    print(f"\n[+] Download complete. Files in: {game_dir}")

    # --- Auto-extract with 7-Zip ---
    sz = None
    for path in [r"C:\Program Files\7-Zip\7z.exe",
                 r"C:\Program Files (x86)\7-Zip\7z.exe"]:
        if os.path.isfile(path):
            sz = path
            break
    if not sz:
        try:
            r = subprocess.run(["where", "7z"], capture_output=True, text=True)
            if r.returncode == 0:
                sz = r.stdout.strip().splitlines()[0]
        except Exception:
            pass

    if not sz:
        print("\n  [!] 7-Zip not found. Extract .cab files manually and run Game.msi / Setup.exe.")
        return

    cab_files = sorted(f for f in os.listdir(game_dir) if f.lower().endswith('.cab'))
    installer = None
    for cab in cab_files:
        cab_path   = os.path.join(game_dir, cab)
        extract_dir = os.path.join(game_dir, os.path.splitext(cab)[0])
        os.makedirs(extract_dir, exist_ok=True)
        print(f"\n  Extracting {cab}...")
        r = subprocess.run([sz, 'x', cab_path, f'-o{extract_dir}', '-y'],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  [!] 7-Zip error: {r.stderr.strip()[:200]}")
            continue
        # Search for installer inside extracted tree
        for root, _dirs, files in os.walk(extract_dir):
            for fname in files:
                if fname.lower() in ('game.msi', 'setup.msi', 'setup.exe', 'install.exe'):
                    installer = os.path.join(root, fname)
                    break
            if installer:
                break

    if not installer:
        print(f"\n  No installer found in extracted files. Check: {game_dir}")
        return

    print(f"\n  Launching installer: {installer}")
    if installer.lower().endswith('.msi'):
        subprocess.Popen(['msiexec', '/i', installer])
    else:
        subprocess.Popen([installer])


# =============================================================================
# fe3 SOAP API — direct Microsoft delivery CDN (no third-party proxy)
#
# 3-step flow (same as alt-app-installer / store.rg-adguard internally):
#   1. GetCookie         → anonymous WU cookie
#   2. SyncUpdates       → package filenames + UpdateID/RevisionNumber
#   3. GetExtUpdateInfo2 → time-limited CDN download URLs
# =============================================================================

_FE3_COOKIE_XML = (
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:a="http://www.w3.org/2005/08/addressing"'
    ' xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
    '<Header>'
    '<a:Action mustUnderstand="1">'
    'http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie'
    '</a:Action>'
    '<a:To mustUnderstand="1">'
    'https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx'
    '</a:To>'
    '<Security mustUnderstand="1"'
    ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
    '<WindowsUpdateTicketsToken'
    ' xmlns="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"'
    ' u:id="ClientMSA">'
    '</WindowsUpdateTicketsToken>'
    '</Security>'
    '</Header>'
    '<Body></Body>'
    '</Envelope>'
)

_FE3_INSTALLED_IDS = [
    1, 2, 3, 11, 19, 544, 549, 2359974, 2359977, 5169044, 8788830, 23110993,
    23110994, 54341900, 54343656, 59830006, 59830007, 59830008, 60484010,
    62450018, 62450019, 62450020, 66027979, 66053150, 97657898, 98822896,
    98959022, 98959023, 98959024, 98959025, 98959026, 104433538, 104900364,
    105489019, 117765322, 129905029, 130040031, 132387090, 132393049, 133399034,
    138537048, 140377312, 143747671, 158941041, 158941042, 158941043, 158941044,
    159123858, 159130928, 164836897, 164847386, 164848327, 164852241, 164852246,
    164852252, 164852253,
]

_FE3_CACHED_IDS = [
    10, 17, 2359977, 5143990, 5169043, 5169047, 8806526, 9125350, 9154769,
    10809856, 23110995, 23110996, 23110999, 23111000, 23111001, 23111002,
    23111003, 23111004, 24513870, 28880263, 30077688, 30486944, 30526991,
    30528442, 30530496, 30530501, 30530504, 30530962, 30535326, 30536242,
    30539913, 30545142, 30545145, 30545488, 30546212, 30547779, 30548797,
    30548860, 30549262, 30551160, 30551161, 30551164, 30553016, 30553744,
    30554014, 30559008, 30559011, 30560006, 30560011, 30561006, 30563261,
    30565215, 30578059, 30664998, 30677904, 30681618, 30682195, 30685055,
    30702579, 30708772, 30709591, 30711304, 30715418, 30720106, 30720273,
    30732075, 30866952, 30866964, 30870749, 30877852, 30878437, 30890151,
    30892149, 30990917, 31049444, 31190936, 31196961, 31197811, 31198836,
    31202713, 31203522, 31205442, 31205557, 31207585, 31208440, 31208451,
    31209591, 31210536, 31211625, 31212713, 31213588, 31218518, 31219420,
    31220279, 31220302, 31222086, 31227080, 31229030, 31238236, 31254198,
    31258008, 36436779, 36437850, 36464012, 41916569, 47249982, 47283134,
    58577027, 58578040, 58578041, 58628920, 59107045, 59125697, 59142249,
    60466586, 60478936, 66450441, 66467021, 66479051, 75202978, 77436021,
    77449129, 85159569, 90199702, 90212090, 96911147, 97110308, 98528428,
    98665206, 98837995, 98842922, 98842977, 98846632, 98866485, 98874250,
    98879075, 98904649, 98918872, 98945691, 98959458, 98984707, 100220125,
    100238731, 100662329, 100795834, 100862457, 103124811, 103348671, 104369981,
    104372472, 104385324, 104465831, 104465834, 104467697, 104473368, 104482267,
    104505005, 104523840, 104550085, 104558084, 104659441, 104659675, 104664678,
    104668274, 104671092, 104673242, 104674239, 104679268, 104686047, 104698649,
    104751469, 104752478, 104755145, 104761158, 104762266, 104786484, 104853747,
    104873258, 104983051, 105063056, 105116588, 105178523, 105318602, 105362613,
    105364552, 105368563, 105369591, 105370746, 105373503, 105373615, 105376634,
    105377546, 105378752, 105379574, 105381626, 105382587, 105425313, 105495146,
    105862607, 105939029, 105995585, 106017178, 106129726, 106768485, 107825194,
    111906429, 115121473, 115578654, 116630363, 117835105, 117850671, 118638500,
    118662027, 118872681, 118873829, 118879289, 118889092, 119501720, 119551648,
    119569538, 119640702, 119667998, 119674103, 119697201, 119706266, 119744627,
    119773746, 120072697, 120144309, 120214154, 120357027, 120392612, 120399120,
    120553945, 120783545, 120797092, 120881676, 120889689, 120999554, 121168608,
    121268830, 121341838, 121729951, 121803677, 122165810, 125408034, 127293130,
    127566683, 127762067, 127861893, 128571722, 128647535, 128698922, 128701748,
    128771507, 129037212, 129079800, 129175415, 129317272, 129319665, 129365668,
    129378095, 129424803, 129590730, 129603714, 129625954, 129692391, 129714980,
    129721097, 129886397, 129968371, 129972243, 130009862, 130033651, 130040030,
    130040032, 130040033, 130091954, 130100640, 130131267, 130131921, 130144837,
    130171030, 130172071, 130197218, 130212435, 130291076, 130402427, 130405166,
    130676169, 130698471, 130713390, 130785217, 131396908, 131455115, 131682095,
    131689473, 131701956, 132142800, 132525441, 132765492, 132801275, 133399034,
    134522926, 134524022, 134528994, 134532942, 134536993, 134538001, 134547533,
    134549216, 134549317, 134550159, 134550214, 134550232, 134551154, 134551207,
    134551390, 134553171, 134553237, 134554199, 134554227, 134555229, 134555240,
    134556118, 134557078, 134560099, 134560287, 134562084, 134562180, 134563287,
    134565083, 134566130, 134568111, 134624737, 134666461, 134672998, 134684008,
    134916523, 135100527, 135219410, 135222083, 135306997, 135463054, 135779456,
    135812968, 136097030, 136131333, 136146907, 136157556, 136320962, 136450641,
    136466000, 136745792, 136761546, 136840245, 138160034, 138181244, 138210071,
    138210107, 138232200, 138237088, 138277547, 138287133, 138306991, 138324625,
    138341916, 138372035, 138372036, 138375118, 138378071, 138380128, 138380194,
    138534411, 138618294, 138931764, 139536037, 139536038, 139536039, 139536040,
    140367832, 140406050, 140421668, 140422973, 140423713, 140436348, 140483470,
    140615715, 140802803, 140896470, 141189437, 141192744, 141382548, 141461680,
    141624996, 141627135, 141659139, 141872038, 141993721, 142006413, 142045136,
    142095667, 142227273, 142250480, 142518788, 142544931, 142546314, 142555433,
    142653044, 143191852, 143258496, 143299722, 143331253, 143432462, 143632431,
    143695326, 144219522, 144590916, 145410436, 146720405, 150810438, 151258773,
    151315554, 151400090, 151429441, 151439617, 151453617, 151466296, 151511132,
    151636561, 151823192, 151827116, 151850642, 152016572, 153111675, 153114652,
    153123147, 153267108, 153389799, 153395366, 153718608, 154171028, 154315227,
    154559688, 154978771, 154979742, 154985773, 154989370, 155044852, 155065458,
    155578573, 156403304, 159085959, 159776047, 159816630, 160733048, 160733049,
    160733050, 160733051, 160733056, 164824922, 164824924, 164824926, 164824930,
    164831646, 164831647, 164831648, 164831650, 164835050, 164835051, 164835052,
    164835056, 164835057, 164835059, 164836898, 164836899, 164836900, 164845333,
    164845334, 164845336, 164845337, 164845341, 164845342, 164845345, 164845346,
    164845349, 164845350, 164845353, 164845355, 164845358, 164845361, 164845364,
    164847387, 164847388, 164847389, 164847390, 164848328, 164848329, 164848330,
    164849448, 164849449, 164849451, 164849452, 164849454, 164849455, 164849457,
    164849461, 164850219, 164850220, 164850222, 164850223, 164850224, 164850226,
    164850227, 164850228, 164850229, 164850231, 164850236, 164850237, 164850240,
    164850242, 164850243, 164852242, 164852243, 164852244, 164852247, 164852248,
    164852249, 164852250, 164852251, 164852254, 164852256, 164852257, 164852258,
    164852259, 164852260, 164852261, 164852262, 164853061, 164853063, 164853071,
    164853072, 164853075, 168118980, 168118981, 168118983, 168118984, 168180375,
    168180376, 168180378, 168180379, 168270830, 168270831, 168270833, 168270834,
    168270835,
]

_FE3_SYNC_XML = (
    '<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"'
    ' xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Header>'
    '<a:Action s:mustUnderstand="1">'
    'http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates'
    '</a:Action>'
    '<a:MessageID>urn:uuid:175df68c-4b91-41ee-b70b-f2208c65438e</a:MessageID>'
    '<a:To s:mustUnderstand="1">'
    'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx'
    '</a:To>'
    '<o:Security s:mustUnderstand="1"'
    ' xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
    '<Timestamp'
    ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
    '<Created>2017-08-05T02:03:05.038Z</Created>'
    '<Expires>2017-08-05T02:08:05.038Z</Expires>'
    '</Timestamp>'
    '<wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA"'
    ' xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"'
    ' xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization">'
    '<TicketType Name="MSA" Version="1.0" Policy="MBI_SSL">{ring}</TicketType>'
    '</wuws:WindowsUpdateTicketsToken>'
    '</o:Security>'
    '</s:Header>'
    '<s:Body>'
    '<SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
    '<cookie><Expiration>2045-03-11T02:02:48Z</Expiration>'
    '<EncryptedData>{cookie}</EncryptedData></cookie>'
    '<parameters>'
    '<ExpressQuery>false</ExpressQuery>'
    '<InstalledNonLeafUpdateIDs>{installed_ints}</InstalledNonLeafUpdateIDs>'
    '<OtherCachedUpdateIDs>{cached_ints}</OtherCachedUpdateIDs>'
    '<SkipSoftwareSync>false</SkipSoftwareSync>'
    '<NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>'
    '<FilterAppCategoryIds>'
    '<CategoryIdentifier><Id>{cat_id}</Id></CategoryIdentifier>'
    '</FilterAppCategoryIds>'
    '<TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled>'
    '<AlsoPerformRegularSync>false</AlsoPerformRegularSync>'
    '<ComputerSpec/>'
    '<ExtendedUpdateInfoParameters>'
    '<XmlUpdateFragmentTypes>'
    '<XmlUpdateFragmentType>Extended</XmlUpdateFragmentType>'
    '</XmlUpdateFragmentTypes>'
    '<Locales><string>en-US</string><string>en</string></Locales>'
    '</ExtendedUpdateInfoParameters>'
    '<ClientPreferredLanguages><string>en-US</string></ClientPreferredLanguages>'
    '<ProductsParameters>'
    '<SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>'
    '<DeviceAttributes>'
    'BranchReadinessLevel=CB;CurrentBranch=rs_prerelease;FlightRing={ring};'
    'FlightingBranchName=external;IsFlightingEnabled=1;InstallLanguage=en-US;'
    'OSUILocale=en-US;InstallationType=Client;DeviceFamily=Windows.Desktop;'
    '</DeviceAttributes>'
    '<CallerAttributes>Interactive=1;IsSeeker=0;</CallerAttributes>'
    '<Products/>'
    '</ProductsParameters>'
    '</parameters>'
    '</SyncUpdates>'
    '</s:Body>'
    '</s:Envelope>'
)

_FE3_FILEURL_XML = (
    '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:a="http://www.w3.org/2005/08/addressing"'
    ' xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
    '<Header>'
    '<a:Action mustUnderstand="1">'
    'http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo2'
    '</a:Action>'
    '<a:To mustUnderstand="1">'
    'https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured'
    '</a:To>'
    '<Security mustUnderstand="1"'
    ' xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
    '<WindowsUpdateTicketsToken'
    ' xmlns="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"'
    ' u:id="ClientMSA">'
    '</WindowsUpdateTicketsToken>'
    '</Security>'
    '</Header>'
    '<Body>'
    '<GetExtendedUpdateInfo2'
    ' xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">'
    '<updateIDs>'
    '<UpdateIdentity>'
    '<UpdateID>{update_id}</UpdateID>'
    '<RevisionNumber>{revision}</RevisionNumber>'
    '</UpdateIdentity>'
    '</updateIDs>'
    '<infoTypes>'
    '<XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType>'
    '<XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType>'
    '</infoTypes>'
    '<deviceAttributes>FlightRing={ring};</deviceAttributes>'
    '</GetExtendedUpdateInfo2>'
    '</Body>'
    '</Envelope>'
)

_FE3_ENDPOINT = "https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx"
_FE3_HEADERS  = {"Content-Type": "application/soap+xml; charset=utf-8"}


def _fe3_get_cookie(timeout=30):
    """Get anonymous WU cookie from fe3 delivery API."""
    req = urllib.request.Request(_FE3_ENDPOINT, data=_FE3_COOKIE_XML.encode(),
                                headers=_FE3_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        from xml.dom import minidom
        doc = minidom.parseString(resp.read())
    return doc.getElementsByTagName("EncryptedData")[0].firstChild.nodeValue


def _fe3_sync_updates(cookie, cat_id, ring="Retail", timeout=30):
    """
    Query fe3 SyncUpdates for package metadata.
    Returns dict of {filename: {"update_id": str, "revision": str, "size": int}}.
    """
    import html as _html_mod
    from xml.dom import minidom

    installed_xml = "".join(f"<int>{i}</int>" for i in _FE3_INSTALLED_IDS)
    cached_xml    = "".join(f"<int>{i}</int>" for i in _FE3_CACHED_IDS)
    body = _FE3_SYNC_XML.format(
        cookie=cookie, cat_id=cat_id, ring=ring,
        installed_ints=installed_xml, cached_ints=cached_xml,
    ).encode()

    req = urllib.request.Request(_FE3_ENDPOINT, data=body, headers=_FE3_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")

    doc = minidom.parseString(_html_mod.unescape(raw))

    # Map internal IDs → (display_filename, size)
    filenames = {}
    for node in doc.getElementsByTagName("Files"):
        try:
            fe = node.firstChild
            iid = node.parentNode.parentNode.getElementsByTagName("ID")[0].firstChild.nodeValue
            fname = f"{fe.getAttribute('InstallerSpecificIdentifier')}_{fe.getAttribute('FileName')}"
            size_str = fe.getAttribute("Size")
            filenames[iid] = (fname, int(size_str) if size_str else 0)
        except (AttributeError, IndexError, ValueError):
            continue

    # Map filenames → (UpdateID, RevisionNumber)
    results = {}
    for node in doc.getElementsByTagName("SecuredFragment"):
        try:
            iid = node.parentNode.parentNode.parentNode.getElementsByTagName("ID")[0].firstChild.nodeValue
            fname, size = filenames[iid]
            uid_node = node.parentNode.parentNode.firstChild
            results[fname] = {
                "update_id": uid_node.getAttribute("UpdateID"),
                "revision":  uid_node.getAttribute("RevisionNumber"),
                "size":      size,
            }
        except (KeyError, AttributeError, IndexError):
            continue

    return results


def _fe3_get_url(update_id, revision, ring="Retail", timeout=30):
    """Get CDN download URL for a single package via GetExtendedUpdateInfo2."""
    from xml.dom import minidom

    body = _FE3_FILEURL_XML.format(
        update_id=update_id, revision=revision, ring=ring,
    ).encode()
    url = _FE3_ENDPOINT + "/secured"
    req = urllib.request.Request(url, data=body, headers=_FE3_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        doc = minidom.parseString(resp.read())

    for loc in doc.getElementsByTagName("FileLocation"):
        url_els = loc.getElementsByTagName("Url")
        if url_els and url_els[0].firstChild:
            dl_url = url_els[0].firstChild.nodeValue
            if len(dl_url) != 99:   # skip blockmap URLs (always 99 chars)
                return dl_url
    return None


def _detect_arch():
    """Return MS Store architecture string for this machine (x64/x86/arm/arm64)."""
    import platform
    m = platform.machine().lower()
    if m in ("amd64", "x86_64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if "arm" in m:
        return "arm"
    return "x86"


def _pkg_arch(filename):
    """Extract architecture from MS Store package filename, or 'neutral'."""
    fn = filename.lower()
    for arch in ("arm64", "x64", "x86", "arm"):
        if f"_{arch}__" in fn:
            return arch
    if "_neutral_" in fn or "_neutral__" in fn:
        return "neutral"
    return "neutral"


_APPX_DEP_PREFIXES = (
    "Microsoft.VCLibs.",
    "Microsoft.NET.Native.Runtime.",
    "Microsoft.NET.Native.Framework.",
    "Microsoft.UI.Xaml.",
    "Microsoft.DirectX.",
    "Microsoft.Services.Store.Engagement.",
)


def _is_appx_dependency(filename):
    """Check if a package filename is a known framework dependency."""
    return any(filename.startswith(p) for p in _APPX_DEP_PREFIXES)


def _dedup_deps(deps):
    """Deduplicate dependency filenames by package family, keeping highest version.

    Filenames look like: Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe_<hash>.appx
    Package family = name + arch + publisher (everything except version).
    Windows rejects duplicate package families in -DependencyPath.
    """
    by_family = {}
    for f in deps:
        # Split: Name_Version_Arch__Publisher_Hash.ext
        parts = f.split("_")
        if len(parts) >= 4:
            # Family key = name + arch + publisher (skip version at [1] and hash at end)
            family = (parts[0], parts[2], parts[3])  # name, arch, __publisher
            ver = parts[1]
            if family not in by_family or ver > by_family[family][1]:
                by_family[family] = (f, ver)
        else:
            by_family[f] = (f, "")
    return [v[0] for v in by_family.values()]


def _appx_install(dest, downloaded_files):
    """Install downloaded packages via PowerShell Add-AppxPackage."""
    # Filter out Xbox-only encrypted bundles (.eappxbundle) — not installable on PC
    skipped = [f for f in downloaded_files if f.lower().endswith(".eappxbundle")]
    installable = [f for f in downloaded_files if not f.lower().endswith(".eappxbundle")]
    if skipped:
        for f in skipped:
            print(f"  Skipping (Xbox-only): {f}")

    deps = _dedup_deps([f for f in installable if _is_appx_dependency(f)])
    mains = [f for f in installable if not _is_appx_dependency(f)]

    # Sort mains by size descending (largest first = likely the bundle)
    mains.sort(key=lambda f: os.path.getsize(os.path.join(dest, f)), reverse=True)

    if not mains:
        for f in deps:
            path = os.path.join(dest, f)
            print(f"  Installing dependency: {f}")
            r = subprocess.run(["powershell", "-Command",
                f'Add-AppxPackage -Path "{path}"'],
                capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                print(f"  [!] Failed: {r.stderr.strip()}")
            else:
                print(f"  [+] OK")
        return

    dep_paths = ",".join(f'"{os.path.join(dest, d)}"' for d in deps) if deps else ""

    for f in mains:
        main_path = os.path.join(dest, f)
        if dep_paths:
            cmd = f'Add-AppxPackage -Path "{main_path}" -DependencyPath {dep_paths}'
        else:
            cmd = f'Add-AppxPackage -Path "{main_path}"'

        print(f"  Installing: {f}")
        if deps:
            print(f"  Dependencies: {', '.join(deps)}")
        r = subprocess.run(["powershell", "-Command", cmd],
            capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            print(f"  [!] Failed: {r.stderr.strip()}")
        else:
            print(f"  [+] Installed successfully")


def _fe3_get_links(value, input_type="ProductId", ring="Retail"):
    """
    Fetch MS Store package links via Microsoft's fe3 delivery API.
    input_type: ProductId | CategoryId | PackageFamilyName | url
    ring:       Retail | RP | WIF | WIS
    Returns list of {"filename": str, "url": str, "size": int}.
    """
    # --- Step 1: Resolve WuCategoryId ---
    if input_type == "CategoryId":
        cat_id = value
    elif input_type == "ProductId":
        cat_id = _display_catalog_get_wuid(value)
        if not cat_id:
            raise RuntimeError(f"Could not resolve WuCategoryId for ProductId {value}")
    elif input_type == "PackageFamilyName":
        se_url = (f"https://storeedgefd.dsx.mp.microsoft.com/v9.0/products/{value}"
                  f"?market=US&locale=en-us&deviceFamily=Windows.Desktop")
        req = urllib.request.Request(se_url)
        req.add_header("User-Agent", "WindowsShellClient/9.0.40929.0 (Windows)")
        cat_id = None
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            for sku in data.get("Payload", {}).get("Skus", []):
                fd = sku.get("FulfillmentData", {})
                cat_id = fd.get("WuCategoryId") or fd.get("WuBundleCategoryId")
                if cat_id:
                    break
        except Exception:
            pass
        if not cat_id:
            raise RuntimeError(f"Could not resolve WuCategoryId for PFN {value}")
    elif input_type == "url":
        # Extract 12-char ProductId from store URL
        parts = value.rstrip("/").split("/")
        pid = None
        for part in reversed(parts):
            if re.match(r'^[A-Za-z0-9]{12}$', part):
                pid = part
                break
        if not pid:
            raise RuntimeError(f"Could not extract ProductId from URL: {value}")
        cat_id = _display_catalog_get_wuid(pid)
        if not cat_id:
            raise RuntimeError(f"Could not resolve WuCategoryId for ProductId {pid}")
    else:
        raise RuntimeError(f"Unknown input_type: {input_type}")

    print(f"  WuCategoryId: {cat_id}")

    # --- Step 2: Get cookie ---
    cookie = _fe3_get_cookie()

    # --- Step 3: Sync updates (get package list + UpdateIDs) ---
    updates = _fe3_sync_updates(cookie, cat_id, ring)
    if not updates:
        return []

    # --- Step 4: Resolve download URLs ---
    results = []
    for fname, info in updates.items():
        dl_url = _fe3_get_url(info["update_id"], info["revision"], ring)
        if dl_url:
            results.append({
                "filename": fname,
                "url":      dl_url,
                "size":     info.get("size", 0),
            })

    return results


def _freshdex_pick_game(db):
    """Freshdex interactive filter + paginated picker. Returns productId or None."""
    PAGE_SIZE = 50

    def _show_page(items, offset):
        """Print one page of items starting at offset. Returns number shown."""
        end = min(offset + PAGE_SIZE, len(items))
        for i in range(offset, end):
            g = items[i]
            yr = g["releaseDate"][:4] if len(g.get("releaseDate", "")) >= 4 else "    "
            cat = g.get("category", "")[:22]
            title = g.get("title", "")[:44]
            print(f"  {i+1:>4}  {g['productId']:>12}  {yr}  {cat:<22}  {title}")
        return end - offset

    def _paginated_pick(items):
        """Paginate items and let user pick by number. Returns productId or None."""
        if not items:
            print("  [!] No matches.")
            return None
        print()
        print(f"  {'#':>4}  {'ProductId':>12}  Year  {'Category':<22}  Title")
        print("  " + "─" * 92)
        offset = 0
        shown = _show_page(items, offset)
        offset += shown
        while True:
            print()
            if offset < len(items):
                prompt = f"  [{offset}/{len(items)}] Enter=next page / number=pick / B=back: "
            else:
                prompt = "  Pick game number (B=back): "
            sel = input(prompt).strip()
            if sel.upper() == "B":
                return None
            if sel == "" and offset < len(items):
                shown = _show_page(items, offset)
                offset += shown
                continue
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(items):
                    return items[idx]
            except ValueError:
                pass
            print("  [!] Invalid selection.")

    # --- Filter menu ---
    print()
    print("  Filter by:")
    print("    [A-Z] Starting letter")
    print("    [#]   Non-alpha titles")
    print("    [Y]   Release year")
    print("    [G]   Genre/category")
    print("    [P]   Platform (Windows 8/8.1 or 10/11)")
    print("    [S]   Search by title")
    print("    [Enter] List all")
    print("    [B]   Back")
    print()
    filt = input("  Filter: ").strip()

    if filt.upper() == "B":
        return None

    if filt == "":
        # List all
        print(f"\n  Listing all {len(db)} games:")
        return _paginated_pick(db)

    if filt == "#":
        # Non-alpha titles
        items = [g for g in db if g["title"] and not g["title"][0].isalpha()]
        print(f"\n  {len(items)} games starting with non-alpha characters:")
        return _paginated_pick(items)

    if len(filt) == 1 and filt.isalpha():
        # Letter filter
        letter = filt.upper()
        items = [g for g in db if g["title"].upper().startswith(letter)]
        print(f"\n  {len(items)} games starting with '{letter}':")
        return _paginated_pick(items)

    fu = filt.upper()

    if fu == "Y":
        yr = input("  Release year (e.g. 2015 / B=back): ").strip()
        if not yr or yr.upper() == "B":
            return None
        items = [g for g in db if g.get("releaseDate", "").startswith(yr)]
        print(f"\n  {len(items)} games from {yr}:")
        return _paginated_pick(items)

    if fu == "G":
        # Collect unique categories
        cats = {}
        for g in db:
            c = g.get("category", "")
            if c:
                cats[c] = cats.get(c, 0) + 1
        if not cats:
            print("  [!] No category data available.")
            return None
        cat_list = sorted(cats.keys(), key=str.lower)
        print()
        for i, c in enumerate(cat_list, 1):
            print(f"    {i:>2}. {c} ({cats[c]})")
        print()
        sel = input("  Pick category number (B=back): ").strip()
        if sel.upper() == "B":
            return None
        try:
            chosen_cat = cat_list[int(sel) - 1]
        except (ValueError, IndexError):
            print("  [!] Invalid selection.")
            return None
        items = [g for g in db if g.get("category") == chosen_cat]
        print(f"\n  {len(items)} games in '{chosen_cat}':")
        return _paginated_pick(items)

    if fu == "S":
        q = input("  Search (B=back): ").strip().lower()
        if not q or q == "b":
            return None
        items = [g for g in db
                 if q in g.get("title", "").lower()
                 or q in g.get("publisher", "").lower()
                 or q in g.get("productId", "").lower()]
        print(f"\n  {len(items)} matches for '{q}':")
        return _paginated_pick(items)

    if fu == "P":
        print()
        print("    [1] Windows 8/8.1 only")
        print("    [2] Windows 10/11 only")
        print("    [3] Both (Win 8/8.1 + Win 10/11)")
        print("    [B] Back")
        print()
        ps = input("  Platform: ").strip()
        if ps == "1":
            items = [g for g in db if "Windows.Windows8x" in g.get("platforms", []) and "PC" not in g.get("platforms", [])]
            print(f"\n  {len(items)} Windows 8/8.1 only games:")
        elif ps == "2":
            items = [g for g in db if "PC" in g.get("platforms", []) and "Windows.Windows8x" not in g.get("platforms", [])]
            print(f"\n  {len(items)} Windows 10/11 only games:")
        elif ps == "3":
            items = [g for g in db if "PC" in g.get("platforms", []) and "Windows.Windows8x" in g.get("platforms", [])]
            print(f"\n  {len(items)} games on both Windows 8/8.1 and Windows 10/11:")
        else:
            print("  [!] Invalid selection.")
            return None
        return _paginated_pick(items)

    print("  [!] Invalid filter.")
    return None


def process_store_packages():
    """Interactive MS Store package fetcher via Microsoft fe3 delivery API."""
    print("\n[Microsoft Store (Win8/8.1/10) CDN Installer]")
    # Quick count of PC/Windows games for menu label
    _pc_count = 0
    try:
        _accts = load_accounts()
        _seen_pids = set()
        for _gt in _accts:
            for _fn in ("library.json", "marketplace.json"):
                _fp = account_path(_gt, _fn)
                if os.path.isfile(_fp):
                    for _it in (load_json(_fp) or []):
                        _pid = _it.get("productId", "")
                        if _pid and _pid not in _seen_pids and _it.get("productKind") == "Game" and any(p in ("PC", "Windows.Windows8x") for p in _it.get("platforms", [])):
                            _seen_pids.add(_pid)
            _pc_count = len(_seen_pids)
    except Exception:
        pass
    _XBOX_APPS = [
        ("Microsoft Store",              "9WZDNCRFJBMP"),
        ("Xbox",                         "9MV0B5HZVK9Z"),
        ("Xbox Console Companion",       "9WZDNCRFJBD8"),
        ("Xbox Insider Hub",             "9PLDPG46G47Z"),
        ("Xbox Game Bar",                "9NZKPSTSNW4P"),
        ("Xbox Game Bar Plugin",         "9NBLGGH537C2"),
        ("Xbox Accessories",             "9NBLGGH30XJ3"),
        ("Xbox Identity Provider",       "9WZDNCRD1HKW"),
        ("Xbox Live In-Game Experience", "9NKNC0LD5NN6"),
        ("Xbox Speech to Text Overlay",  "9P086NHDNB9W"),
    ]

    print()
    print("  Input type:")
    print(f"    [F] Your Collection ({_pc_count} Games)" if _pc_count else "    [F] Your Collection")
    print(f"    [X] Xbox Apps & Utilities ({len(_XBOX_APPS)})")
    print("    [1] ProductId         e.g. 9NBLGGH5R558")
    print("    [2] CategoryId        e.g. e89c9ccf-de94-45ed-9cd4-7e11d05c3da4 (WuCategoryId)")
    print("    [3] PackageFamilyName e.g. Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe")
    print("    [4] URL               e.g. https://www.microsoft.com/store/productId/9NBLGGH5R558")
    print("    [B] Back")
    print()
    choice = input("  Choice [F]: ").strip().upper() or "F"
    if choice == "B":
        return
    print()

    type_map = {"1": "ProductId", "2": "CategoryId", "3": "PackageFamilyName", "4": "url"}

    if choice == "F":
        db = _build_freshdex_db()
        if not db:
            print("[!] No Windows games found. Run collection scans first.")
            return
        print(f"  Your Collection: {len(db)} Windows games indexed")
        game = _freshdex_pick_game(db)
        if not game:
            return
        value = game["productId"]
        input_type = "ProductId"
        print()
        print(f"  Title:     {game.get('title', '')}")
        print(f"  Publisher: {game.get('publisher', '')}")
        print(f"  Category:  {game.get('category', '')}")
        print(f"  Released:  {game.get('releaseDate', '')[:10]}")
        print(f"  Platforms: {', '.join(game.get('platforms', []))}")
        print(f"  ProductId: {value}")
    elif choice == "X":
        print("  Xbox Apps & Utilities:")
        for _xi, (_xname, _xpid) in enumerate(_XBOX_APPS, 1):
            print(f"    [{_xi:>2}] {_xname:<33} {_xpid}")
        print()
        _xpick = input(f"  Choice [1-{len(_XBOX_APPS)} / B=back]: ").strip()
        if _xpick.upper() == "B":
            return
        if not _xpick.isdigit() or int(_xpick) < 1 or int(_xpick) > len(_XBOX_APPS):
            return
        _xname, value = _XBOX_APPS[int(_xpick) - 1]
        input_type = "ProductId"
        print()
        print(f"  {_xname} — {value}")
    elif choice in type_map:
        input_type = type_map[choice]
        value = input(f"  Enter {input_type} (B=back): ").strip()
        if not value or value.upper() == "B":
            return
    else:
        return

    print()
    print("  Ring:")
    print("    [1] RP (Release Preview)")
    print("    [2] Retail")
    print("    [3] WIF (Windows Insider Fast)")
    print("    [4] WIS (Windows Insider Slow)")
    print("    [Enter] Scan all rings")
    print("    [B] Back")
    print()
    _ring_pick = input("  Ring [Enter=all]: ").strip()
    if _ring_pick.upper() == "B":
        return
    _ring_map = {"1": "RP", "2": "Retail", "3": "WIF", "4": "WIS"}
    _ring_order = [("RP", "Release Preview"), ("Retail", "Retail"), ("WIF", "Windows Insider Fast"), ("WIS", "Windows Insider Slow")]

    if _ring_pick == "" or _ring_pick == "*":
        print()
        print(f"[*] Scanning all rings for {input_type}={value} ...")
        print()
        # --- Resolve WuCategoryId + cookie once ---
        try:
            if input_type == "CategoryId":
                _scan_catid = value
            elif input_type == "ProductId":
                _scan_catid = _display_catalog_get_wuid(value)
                if not _scan_catid:
                    print(f"  [!] Could not resolve WuCategoryId for {value}")
                    return
            elif input_type == "PackageFamilyName":
                _se_url = (f"https://storeedgefd.dsx.mp.microsoft.com/v9.0/products/{value}"
                           f"?market=US&locale=en-us&deviceFamily=Windows.Desktop")
                _se_req = urllib.request.Request(_se_url)
                _se_req.add_header("User-Agent", "WindowsShellClient/9.0.40929.0 (Windows)")
                _scan_catid = None
                with urllib.request.urlopen(_se_req, timeout=15) as _se_resp:
                    _se_data = json.loads(_se_resp.read().decode())
                for _se_sku in _se_data.get("Payload", {}).get("Skus", []):
                    _scan_catid = _se_sku.get("FulfillmentData", {}).get("WuCategoryId") or _se_sku.get("FulfillmentData", {}).get("WuBundleCategoryId")
                    if _scan_catid:
                        break
                if not _scan_catid:
                    print(f"  [!] Could not resolve WuCategoryId for PFN {value}")
                    return
            elif input_type == "url":
                _u_parts = value.rstrip("/").split("/")
                _u_pid = None
                for _u_p in reversed(_u_parts):
                    if re.match(r'^[A-Za-z0-9]{12}$', _u_p):
                        _u_pid = _u_p
                        break
                if not _u_pid:
                    print(f"  [!] Could not extract ProductId from URL")
                    return
                _scan_catid = _display_catalog_get_wuid(_u_pid)
                if not _scan_catid:
                    print(f"  [!] Could not resolve WuCategoryId for {_u_pid}")
                    return
            else:
                return
            print(f"  WuCategoryId: {_scan_catid}")
            _scan_cookie = _fe3_get_cookie()
        except Exception as _e:
            print(f"  [!] Setup error: {_e}")
            return
        # --- Query all 4 rings in parallel (metadata only, no download URLs) ---
        from concurrent.futures import ThreadPoolExecutor
        def _probe_ring(_rcode):
            try:
                updates = _fe3_sync_updates(_scan_cookie, _scan_catid, _rcode)
                if not updates:
                    return (_rcode, {}, None)
                return (_rcode, updates, None)
            except Exception as _e:
                return (_rcode, {}, str(_e))
        _ring_raw = {}
        with ThreadPoolExecutor(max_workers=4) as _tp:
            for _rcode, _updates, _err in _tp.map(_probe_ring, [r for r, _ in _ring_order]):
                _ring_raw[_rcode] = (_updates, _err)
        # --- Build display data ---
        _any_hit = False
        _ring_results = []
        _all_versions = set()
        _common_versions = None
        for _rcode, _rname in _ring_order:
            _updates, _err = _ring_raw[_rcode]
            if _err:
                _ring_results.append((_rcode, _rname, 0, set(), 0, _err))
                continue
            if not _updates:
                _ring_results.append((_rcode, _rname, 0, set(), 0, None))
                continue
            _any_hit = True
            _versions = set()
            _tsz = 0
            for _fname, _info in _updates.items():
                _tsz += _info.get("size", 0)
                _vm = re.search(r'_(\d+\.\d+\.\d+\.\d+)_', _fname)
                if _vm:
                    _versions.add(_vm.group(1))
            _all_versions.update(_versions)
            if _common_versions is None:
                _common_versions = set(_versions)
            else:
                _common_versions &= _versions
            _ring_results.append((_rcode, _rname, len(_updates), _versions, _tsz, None))
        print()
        # --- Display results ---
        for _rcode, _rname, _cnt, _versions, _tsz, _err in _ring_results:
            print(f"  {_rcode} ({_rname}):")
            if _err:
                print(f"    ERROR — {_err}")
                print()
                continue
            if not _cnt:
                print(f"    No packages")
                print()
                continue
            if _tsz >= 1073741824:
                _szstr = f"{_tsz / 1073741824:.2f} GB"
            elif _tsz >= 1048576:
                _szstr = f"{_tsz / 1048576:.1f} MB"
            else:
                _szstr = f"{_tsz / 1024:.0f} KB"
            print(f"    {_cnt} packages — {_szstr}")
            for _v in sorted(_versions):
                if _common_versions is not None and _v not in _common_versions:
                    print(f"    * v{_v}  ← UNIQUE")
                else:
                    print(f"      v{_v}")
            print()
        if _all_versions and _common_versions == _all_versions:
            print("  All rings identical.")
            print()
        if not _any_hit:
            print("  [!] No packages found on any ring.")
            print()
        _cont = input("  Download from a specific ring? [1-4 / B=back]: ").strip()
        if _cont.upper() == "B" or _cont not in _ring_map:
            return
        ring = _ring_map[_cont]
    else:
        ring = _ring_map.get(_ring_pick, "RP")

    print()
    print(f"[*] Fetching packages ({input_type}={value}, ring={ring}) ...")

    try:
        links = _fe3_get_links(value, input_type=input_type, ring=ring)
    except Exception as e:
        print(f"[!] {e}")
        return

    if not links:
        print("[!] No packages found. Try a different ring or input type.")
        return

    # --- Architecture filtering ---
    arch = _detect_arch()
    matching = [lnk for lnk in links if _pkg_arch(lnk["filename"]) in (arch, "neutral")]
    display_list = matching
    show_all = False

    def _print_table(pkg_list):
        print(f"  {'#':>3}  {'Size':>10}  Filename")
        print("  " + "─" * 90)
        for i, lnk in enumerate(pkg_list, 1):
            sz = lnk["size"]
            if   sz >= 1073741824: sz_str = f"{sz / 1073741824:.2f} GB"
            elif sz >= 1048576:    sz_str = f"{sz / 1048576:.1f} MB"
            elif sz >= 1024:       sz_str = f"{sz / 1024:.0f} KB"
            elif sz > 0:           sz_str = f"{sz} B"
            else:                  sz_str = "?"
            print(f"  {i:>3}  {sz_str:>10}  {lnk['filename']}")

    print(f"\n  {len(links)} package(s) found  —  arch: {arch}  ({len(matching)} matching + neutral)\n")
    _print_table(display_list)
    print()

    sel = input("  Which file(s) to download? [numbers / Enter=all / A=all architectures / B=back]: ").strip()
    if sel.upper() == "A":
        display_list = links
        show_all = True
        print(f"\n  Showing all {len(links)} packages:\n")
        _print_table(display_list)
        print()
        sel = input("  Which file(s) to download? [numbers / Enter=all / B=back]: ").strip()

    if sel.upper() == "B":
        return
    if sel == "":
        targets = display_list
    else:
        targets = [display_list[i] for i in _parse_selection(sel, len(display_list))]
    if not targets:
        print("[!] Nothing selected.")
        return

    default_dest = os.path.join(SCRIPT_DIR, "store_downloads")
    dest = input(f"  Destination folder [{default_dest} / B=back]: ").strip().strip('"').strip("'")
    if dest.upper() == "B":
        return
    dest = dest or default_dest
    os.makedirs(dest, exist_ok=True)
    print()
    downloaded = []
    for lnk in targets:
        fname = lnk["filename"]
        out_path = os.path.join(dest, fname)
        print(f"  ▸ {fname}")
        _download_with_progress(lnk["url"], out_path, expected_size=lnk.get("size", 0))
        downloaded.append(fname)
    print(f"\n[+] Done. Files in: {dest}")

    # --- Offer Add-AppxPackage install ---
    if downloaded:
        print()
        install = input("  Install downloaded packages via Add-AppxPackage? [Y/n]: ").strip().lower()
        if install in ("", "y", "yes"):
            print()
            try:
                _appx_install(dest, downloaded)
            except subprocess.TimeoutExpired:
                print("  [!] Install timed out.")
            except Exception as e:
                print(f"  [!] Install error: {e}")


def _cdn_backup_games(items, select_all=False):
    """Download current-version game packages from Xbox CDN. Used by USB tool submenu."""
    downloadable = [x for x in items if x.get("cdnUrls") and x.get("contentId")]
    if not downloadable:
        print("[!] No items with CDN URLs in USB DB. Run scan + save first.")
        return
    print()
    print(f"  {'#':>3}  {'Size':>8}  {'Ver':>10}  Title")
    print("  " + "─" * 70)
    for i, item in enumerate(downloadable, 1):
        sz    = item.get("sizeBytes", 0)
        sz_gb = f"{sz/1e9:.2f}GB" if sz else "?"
        ver   = _xbox_ver_decode(item.get("buildVersion", "")) if item.get("buildVersion") else "?"
        print(f"  {i:>3}  {sz_gb:>8}  {ver:>10}  {item.get('_title','')[:50]}")
    print()
    if select_all:
        targets = downloadable
    else:
        sel = input("  Which game(s) to download? [numbers e.g. 1 3 5-8 / *=all / B=back]: ").strip()
        if sel.upper() == "B":
            return
        if sel == "*":
            targets = downloadable
        else:
            targets = [downloadable[i] for i in _parse_selection(sel, len(downloadable))]
    if not targets:
        print("[!] Nothing selected.")
        return
    total_bytes = sum(t.get("sizeBytes", 0) for t in targets)
    print(f"\n  {len(targets)} package(s) selected  ({total_bytes/1e9:.2f} GB total)")
    dest = input("  Destination folder (B=back): ").strip().strip('"').strip("'")
    if not dest or dest.upper() == "B":
        return
    os.makedirs(dest, exist_ok=True)
    for item in targets:
        url    = item["cdnUrls"][0]
        fname  = url.rsplit("/", 1)[-1]
        outf   = os.path.join(dest, fname)
        size   = item.get("sizeBytes", 0)
        title  = item.get("_title", fname)
        print(f"\n  ▸ {title}")
        _download_with_progress(url, outf, size)
    print(f"\n[+] Done. Files saved to: {dest}")


def process_xbox_usb_tool():
    """Xbox One/Series X|S USB Hard Drive Tool — submenu."""
    print("\n[Xbox One / Series X|S USB Hard Drive Tool]")
    print()
    print("    [V] Drive converter (PC ↔ Xbox MBR mode)")
    print("    [S] Scan, index and save metadata to usb_db.json")
    print("    [C] CDN backup a game")
    print("    [A] CDN backup all games")
    print("    [D] Discover previous versions")
    print("    [B] Back")
    print()
    mode = input("  Choice: ").strip().upper()

    if mode == "B" or not mode:
        return
    elif mode == "V":
        process_drive_converter()
    elif mode == "S":
        drive_letter = input("  Drive letter (default: E / B=back): ").strip() or "E"
        if drive_letter.upper() == "B":
            return
        drive_letter = drive_letter.rstrip(":/\\").upper()
        process_usb_drive(drive_letter)
        build_usb_db(drive_letter)
    elif mode == "C":
        items = _cdn_load_items()
        if items:
            _cdn_backup_games(items, select_all=False)
    elif mode == "A":
        items = _cdn_load_items()
        if items:
            _cdn_backup_games(items, select_all=True)
    elif mode == "D":
        process_cdn_version_discovery()


def process_cdn_version_discovery():
    """
    Discover older Xbox game package versions.
    Modes:
      [C] Compare snapshots — diff two usb_db scans to find updated games + probe old URLs
      [A] Xbox CDN sweep   — probe prior-version URLs derived from XVS priorBuildId/Version
      [W] WU Catalog scan  — query Windows Update Catalog for full version history
      [S] Select game      — verbose per-game probe (CDN strategy)
      [R] Refresh WU links — re-fetch download links for a previously-found WuCategoryId
    """
    print("\n[CDN / Version Discovery]")
    print()
    print("    [C] Compare snapshots  — diff two usb_db scans to find updated games + probe old URLs")
    print("    [A] Xbox CDN sweep     — probe prior-version URLs from XVS data (fast, silent 404s)")
    print("    [W] Windows Update Catalog — query update history via WuCategoryId (experimental)")
    print("    [S] Select game        — verbose CDN probe for specific game(s)")
    print("    [R] Refresh WU links   — re-fetch fresh download links by WuCategoryId")
    print("    [B] Back")
    print()
    mode = input("  Choice: ").strip().upper()

    if mode == "B" or not mode:
        return

    items = _cdn_load_items()
    if not items:
        return

    total   = len(items)
    has_cdn = sum(1 for x in items if x.get("cdnUrls"))
    has_pri = sum(1 for x in items if x.get("priorBuildVersion") and x.get("priorBuildId"))
    print(f"[*] {total} entries  |  {has_cdn} with CDN URL  |  {has_pri} with prior version data")
    print()

    if mode == "C":
        process_cdn_snapshot_compare()
        return

    elif mode == "A":
        all_found = _cdn_sweep_all(items)
        if all_found:
            print(f"  Games with prior versions on CDN: {len([f for f in all_found if f['url'].endswith('.xvc')])}")
            for f in all_found:
                if f["url"].endswith(".xvc"):
                    print(f"    {f['title']:<50}  {f['label']}")
                    print(f"      {f['url']}")
                elif "manifest" in f["label"]:
                    print(f"    {f['title']:<50}  {f['label']}")
                    if f.get("body"):
                        preview = f["body"][:300].replace("\n", " ")
                        print(f"      preview: {preview}")
        _cdn_finish(all_found)

    elif mode == "W":
        all_found = _cdn_sweep_wu_catalog(items)
        if all_found:
            print(f"\n  Games with multiple versions in WU Catalog: {len(all_found)}")
            print()
            for f in all_found:
                print(f"  ▸ {f['title']}")
                for upd in f.get("updates", []):
                    print(f"      {upd.get('date',''):>12}  {upd.get('title','')[:60]}  [{upd.get('size','')}]")
                if f.get("links"):
                    print(f"      Download links ({len(f['links'])}):")
                    for lnk in f["links"][:5]:
                        print(f"        {lnk}")
                    if len(f["links"]) > 5:
                        print(f"        … and {len(f['links'])-5} more")
                print()
            # Save to file
            out = os.path.join(SCRIPT_DIR, "cdn_older_versions.json")
            save_json(out, [{k: v for k, v in f.items() if k != "body"} for f in all_found])
            print(f"[+] Saved: {out}")
            # Offer download if we have .xvc links
            xvc_links = [lnk for f in all_found for lnk in f.get("links", [])
                         if lnk.lower().endswith(".xvc")]
            if xvc_links:
                ans = input(f"\n  Download {len(xvc_links)} .xvc package(s)? [y/N]: ").strip().lower()
                if ans == "y":
                    dest = input("  Destination folder: ").strip().strip('"').strip("'")
                    if dest:
                        os.makedirs(dest, exist_ok=True)
                        for lnk in xvc_links:
                            fname = lnk.rsplit("/", 1)[-1].split("?")[0]
                            _download_with_progress(lnk, os.path.join(dest, fname), 0)
        else:
            print("  Nothing found.  Games may only have one published WU Catalog entry,")
            print("  or WuCategoryId is unavailable (not all titles have one).")

    elif mode == "S":
        print()
        print(f"  {'#':>3}  {'CDN':^3}  {'PRIOR':^5}  Title")
        print("  " + "─" * 62)
        for i, item in enumerate(items, 1):
            has_cdn_flag   = "✓" if item.get("cdnUrls") else " "
            has_prior_flag = "✓" if item.get("priorBuildVersion") and item.get("priorBuildId") else " "
            print(f"  {i:>3}  {has_cdn_flag:^3}  {has_prior_flag:^5}  {item.get('_title','')[:50]}")
        print()
        sel = input("  Which game(s)? [numbers e.g. 1 3 5-8 / B=back]: ").strip().lower()
        if sel == "b":
            return
        targets = [items[i] for i in _parse_selection(sel, len(items))]
        if not targets:
            print("[!] Nothing selected.")
            return
        print()
        all_found = []
        for item in targets:
            title = item.get("_title", "?")
            print(f"  ── {title}")
            if not item.get("cdnUrls"):
                print("     (no CDN URL — skipping)")
                continue
            if not item.get("buildVersion"):
                print("     (no buildVersion — re-run [I])")
                continue
            results = discover_cdn_versions(item)
            if not results:
                print("     (could not parse URL — contentId not in path)")
                continue
            any_hit = False
            for r in results:
                status = "FOUND" if r["exists"] is True else (" 404 " if r["exists"] is False else " ERR ")
                print(f"     [{status}] {r['label']}")
                if r["exists"]:
                    print(f"             {r['url']}")
                    if r.get("body"):
                        print(f"             → {r['body'][:300].replace(chr(10),' ')}...")
                    all_found.append({"title": title, **r})
                    any_hit = True
            if not any_hit:
                print("     (nothing found)")
        _cdn_finish(all_found)

    elif mode == "R":
        # Re-fetch fresh download links for a previously-found WuCategoryId
        wuid = input("  WuCategoryId (paste / B=back): ").strip()
        if not wuid or wuid.upper() == "B":
            return
        print(f"[*] Re-fetching links for {wuid} ...")
        links = _cdn_refresh_wu_links(wuid)
        if links:
            print(f"  {len(links)} link(s):")
            for lnk in links:
                print(f"    {lnk}")
            ans = input(f"\n  Download {len(links)} file(s)? [y/N]: ").strip().lower()
            if ans == "y":
                dest = input("  Destination folder: ").strip().strip('"').strip("'")
                if dest:
                    os.makedirs(dest, exist_ok=True)
                    for lnk in links:
                        fname = lnk.rsplit("/", 1)[-1].split("?")[0]
                        _download_with_progress(lnk, os.path.join(dest, fname), 0)
        else:
            print("  No links found — update may no longer be available.")


# ===========================================================================
# Unified Interactive Menu
# ===========================================================================

def _pick_account(gamertags, prompt="Which account?", allow_all=True):
    """Prompt user to pick an account. Returns gamertag, '*', or None."""
    if not gamertags:
        print("  [!] No gamertags configured. Use [A] to add one first.")
        return None
    if len(gamertags) == 1:
        return gamertags[0]
    print()
    for i, gt in enumerate(gamertags, 1):
        print(f"    [{i}] {gt}")
    if allow_all:
        print(f"    [*] All gamertags")
    print()
    sp = input(f"  {prompt} [1-{len(gamertags)}{', *' if allow_all else ''}, B=back]: ").strip()
    if sp.upper() == "B":
        return None
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
    while True:
        accounts = load_accounts()
        gamertags = list(accounts.keys())

        print_header()
        if gamertags:
            print(f"  Gamertags ({len(gamertags)}):")
            print(f"    [0] Show list")
            print(f"    [*] Process all")
            print(f"    [A] Add new gamertag")
            print(f"    [R] Refresh token")
            print(f"    [D] Delete a gamertag")
            print(f"    [X] Clear cache + rescan all")
        else:
            print("  Gamertags:  (none)")
            print("    [A] Add a gamertag to unlock collection features")
        print()
        print("  Scan endpoints:")
        print("    [E] Collections API only")
        print("    [T] TitleHub only")
        print("    [S] Content Access only (Xbox 360)")
        print()
        print("  Catalogs:")
        print("    [G] Game Pass Catalog")
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
        print("  Build:")
        print("    [B] Build/Rebuild Index")
        print()
        print("  Utilities:")
        print("    [K] Xbox One / Series X|S USB Hard Drive Tool")
        print("    [I] Xbox One / Series X|S CDN Installer")
        print("    [U] Xbox One / Series X|S Hard Delist Installer")
        print("    [O] Microsoft Store (Win8/8.1/10) CDN Installer")
        print("    [J] Games for Windows Live (GFWL) CDN Installer")
        print()
        print("    [Q] Quit")
        print()

        pick = input(f"  Pick [0, E, T, S, M, L, P, N, C, F, W, Z, H, Y, A, R, D, *, X, B, K, I, U, O, J, G, Q]: ").strip()
        pu = pick.upper()

        _no_accts = not gamertags

        if pu == "Q":
            break
        elif pick == "0":
            if _no_accts:
                print("  [!] No gamertags configured. Use [A] to add one first.")
                continue
            print()
            for i, gt in enumerate(gamertags, 1):
                age = token_age_str(gt)
                print(f"    [{i:>2}] {gt}  (token: {age})")
            print()
            ap = input(f"  Process which gamertag? [1-{len(gamertags)} / B=back]: ").strip()
            if ap.upper() == "B":
                continue
            try:
                idx = int(ap) - 1
                if 0 <= idx < len(gamertags):
                    gt = gamertags[idx]
                    _t0 = time.time()
                    try:
                        print(f"\n[*] Refreshing token for {gt}...")
                        refresh_account_token(gt)
                        html_file, _lib = process_account(gt, method="both")
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        print(f"[*] Opening in browser: {file_url}")
                        webbrowser.open(file_url)
                        _op_summary("Process gamertag", detail=f"{gt} — {len(_lib):,} items", elapsed=time.time() - _t0)
                    except Exception as _e:
                        _op_summary("Process gamertag", success=False, detail=str(_e), elapsed=time.time() - _t0)
                else:
                    print("  Invalid selection.")
            except ValueError:
                print("  Invalid selection.")
            continue
        elif pu == "A":
            cmd_add()
            continue
        elif pu == "R":
            if _no_accts:
                print("  [!] No gamertags configured. Use [A] to add one first.")
                continue
            if len(gamertags) == 1:
                gt = gamertags[0]
            else:
                print()
                for i, gt in enumerate(gamertags, 1):
                    print(f"    [{i}] {gt} (token: {token_age_str(gt)})")
                print()
                rp = input(f"  Refresh which gamertag? [1-{len(gamertags)} / B=back]: ").strip()
                if rp.upper() == "B":
                    continue
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
            _t0 = time.time()
            try:
                print(f"\n[*] Refreshing token for {gt}...")
                refresh_account_token(gt)
                process_now = input("\n  Process collection now? [Y/n]: ").strip().lower()
                if process_now not in ("n", "no"):
                    html_file, _lib = process_account(gt)
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        print(f"[*] Opening in browser: {file_url}")
                        webbrowser.open(file_url)
                _op_summary("Refresh token", detail=f"{gt}", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("Refresh token", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "D":
            if _no_accts:
                print("  [!] No gamertags configured. Use [A] to add one first.")
                continue
            gt = None
            if len(gamertags) == 1:
                gt = gamertags[0]
            else:
                print()
                for i, g in enumerate(gamertags, 1):
                    print(f"    [{i}] {g}")
                print()
                dp = input(f"  Delete which gamertag? [1-{len(gamertags)} / B=back]: ").strip()
                if dp.upper() == "B":
                    continue
                try:
                    idx = int(dp) - 1
                    if 0 <= idx < len(gamertags):
                        gt = gamertags[idx]
                    else:
                        print("  Invalid selection.")
                except ValueError:
                    print("  Invalid selection.")
            if gt:
                _t0 = time.time()
                try:
                    delete_account(gt)
                    _op_summary("Delete gamertag", detail=f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Delete gamertag", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pick == "*":
            if _no_accts:
                print("  [!] No gamertags configured. Use [A] to add one first.")
                continue
            _t0 = time.time()
            try:
                process_all_accounts()
                _op_summary("Process all gamertags", detail="Done", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("Process all gamertags", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "E":
            gt = _pick_account(gamertags, "Collections API scan for which account?")
            if gt == "*":
                _t0 = time.time()
                try:
                    for g in gamertags:
                        if _is_token_expired(g):
                            _auto_refresh_token(g)
                        process_account(g, method="collection")
                    build_index()
                    _op_summary("Collections API scan", detail="All gamertags", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Collections API scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            elif gt:
                _t0 = time.time()
                try:
                    if _is_token_expired(gt):
                        _auto_refresh_token(gt)
                    html_file, _lib = process_account(gt, method="collection")
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
                    _op_summary("Collections API scan", detail=f"{gt} — {len(_lib):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Collections API scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "T":
            gt = _pick_account(gamertags, "TitleHub scan for which account?")
            if gt == "*":
                _t0 = time.time()
                try:
                    for g in gamertags:
                        if _is_token_expired(g):
                            _auto_refresh_token(g)
                        process_account(g, method="titlehub")
                    build_index()
                    _op_summary("TitleHub scan", detail="All gamertags", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("TitleHub scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            elif gt:
                _t0 = time.time()
                try:
                    if _is_token_expired(gt):
                        _auto_refresh_token(gt)
                    html_file, _lib = process_account(gt, method="titlehub")
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    webbrowser.open(file_url)
                    _op_summary("TitleHub scan", detail=f"{gt} — {len(_lib):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("TitleHub scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "S":
            gt = _pick_account(gamertags, "Content Access scan for which account?")
            if gt == "*":
                _t0 = time.time()
                try:
                    for g in gamertags:
                        if _is_token_expired(g):
                            _auto_refresh_token(g)
                        process_contentaccess_only(g)
                    html_file = build_index()
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Content Access scan", detail="All gamertags", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Content Access scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            elif gt:
                _t0 = time.time()
                try:
                    if _is_token_expired(gt):
                        _auto_refresh_token(gt)
                    html_file, _lib = process_contentaccess_only(gt)
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Content Access scan", detail=f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Content Access scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "X":
            if _no_accts:
                print("  [!] No gamertags configured. Use [A] to add one first.")
                continue
            print()
            print("  This will delete all cached API data and rescan every gamertag.")
            confirm = input("  Are you sure? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                _t0 = time.time()
                try:
                    for gt in gamertags:
                        clear_api_cache(gt)
                    process_all_accounts()
                    _op_summary("Clear cache + rescan", detail="All gamertags rescanned", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Clear cache + rescan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "B":
            _t0 = time.time()
            try:
                html_file = build_index()
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    print(f"[*] Opening in browser: {file_url}")
                    webbrowser.open(file_url)
                _op_summary("Build index", detail="HTML rebuilt from cache", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("Build index", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "G":
            _t0 = time.time()
            try:
                process_gamepass_library()
                _op_summary("Game Pass catalog", detail="Done", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("Game Pass catalog", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "M":
            gt = _pick_account(gamertags, "Marketplace scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
                    html_file, _mkt = process_marketplace(gt)
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Marketplace scan", detail=f"{gt} — {len(_mkt):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Marketplace scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "L":
            gt = _pick_account(gamertags, "All-regions marketplace using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
                    html_file, _mkt = process_marketplace_all_regions(gt)
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Marketplace (all regions)", detail=f"{gt} — {len(_mkt):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Marketplace (all regions)", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "P":
            gt = _pick_account(gamertags, "Regional prices using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
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
                    _op_summary("Regional prices", detail=f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Regional prices", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "N":
            gt = _pick_account(gamertags, "New Games scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
                    html_file, _mkt = process_marketplace(gt, channels=["MobileNewGames"])
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("New Games scan", detail=f"{gt} — {len(_mkt):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("New Games scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "C":
            gt = _pick_account(gamertags, "Coming Soon scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
                    html_file, _mkt = process_marketplace(gt, channels=["GamesComingSoon"])
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Coming Soon scan", detail=f"{gt} — {len(_mkt):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Coming Soon scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "F":
            gt = _pick_account(gamertags, "Game Demos scan using which account?")
            if gt == "*":
                gt = gamertags[0]
            if gt:
                _t0 = time.time()
                try:
                    html_file, _mkt = process_marketplace(gt, channels=["GameDemos"])
                    if html_file:
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        webbrowser.open(file_url)
                    _op_summary("Game Demos scan", detail=f"{gt} — {len(_mkt):,} items", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Game Demos scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "W":
            gt = _pick_account(gamertags, "Browse catalog using which account?", allow_all=False)
            if gt:
                _t0 = time.time()
                try:
                    set_account_paths(gt)
                    if _is_token_expired(gt):
                        _auto_refresh_token(gt)
                    # Try both tokens — emerald endpoint RP is unknown
                    auth = read_auth_token(optional=True)
                    auth_xl = _read_xl_token()
                    token = auth_xl or auth
                    products = None
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
                    _op_summary("Browse catalog (US)", detail=f"{gt} — {len(products):,} products" if products else f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Browse catalog (US)", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "Z":
            gt = _pick_account(gamertags, "Multi-region browse using which account?", allow_all=False)
            if gt:
                _t0 = time.time()
                try:
                    set_account_paths(gt)
                    if _is_token_expired(gt):
                        _auto_refresh_token(gt)
                    auth = read_auth_token(optional=True)
                    auth_xl = _read_xl_token()
                    token = auth_xl or auth
                    products = None
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
                    _op_summary("Browse catalog (all regions)", detail=f"{gt} — {len(products):,} products" if products else f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Browse catalog (all regions)", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "Y":
            gt = _pick_account(gamertags, "Full discovery using which account?", allow_all=False)
            if gt:
                _t0 = time.time()
                try:
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
                    _op_summary("Full discovery", detail=f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("Full discovery", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "H":
            gt = _pick_account(gamertags, "TitleHub scan using which account?", allow_all=False)
            if gt:
                _t0 = time.time()
                try:
                    set_account_paths(gt)
                    xl_token = _read_xl_token()
                    if not xl_token:
                        print(f"[!] No xl token for {gt}. Refresh token first.")
                    else:
                        scan_titlehub_all_regions(xl_token)
                    _op_summary("TitleHub ID scan", detail=f"{gt}", elapsed=time.time() - _t0)
                except Exception as _e:
                    _op_summary("TitleHub ID scan", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "K":
            _t0 = time.time()
            try:
                process_xbox_usb_tool()
                _op_summary("USB Hard Drive Tool", detail="Done", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("USB Hard Drive Tool", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "I":
            print("\n[Xbox One / Series X|S CDN Installer]")
            print("  Coming soon.")
            continue
        elif pu == "U":
            print("\n[Xbox One / Series X|S Hard Delist Installer]")
            print("  Coming soon.")
            continue
        elif pu == "J":
            _t0 = time.time()
            try:
                process_gfwl_download()
                _op_summary("GFWL CDN Installer", detail="Done", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("GFWL CDN Installer", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        elif pu == "O":
            _t0 = time.time()
            try:
                process_store_packages()
                _op_summary("MS Store Installer", detail="Done", elapsed=time.time() - _t0)
            except Exception as _e:
                _op_summary("MS Store Installer", success=False, detail=str(_e), elapsed=time.time() - _t0)
            continue
        else:
            try:
                idx = int(pick) - 1
                if 0 <= idx < len(gamertags):
                    gt = gamertags[idx]
                    _t0 = time.time()
                    try:
                        # Refresh token (clears API cache) so we always get fresh data
                        print(f"\n[*] Refreshing token for {gt}...")
                        refresh_account_token(gt)
                        html_file, _lib = process_account(gt, method="both")
                        file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                        print(f"[*] Opening in browser: {file_url}")
                        webbrowser.open(file_url)
                        _op_summary("Process gamertag", detail=f"{gt} — {len(_lib):,} items", elapsed=time.time() - _t0)
                    except Exception as _e:
                        _op_summary("Process gamertag", success=False, detail=str(_e), elapsed=time.time() - _t0)
                    continue
                else:
                    print("  Invalid selection.")
            except ValueError:
                print("  Invalid selection.")


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    args = sys.argv[1:]
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
        elif args[0] == "preview":
            os.makedirs(ACCOUNTS_DIR, exist_ok=True)
            html_file = os.path.join(ACCOUNTS_DIR, "XCT.html")
            html = build_html_template()
            with open(html_file, "w", encoding="utf-8") as f:
                f.write(html)
            write_data_js([], [], [], os.path.join(ACCOUNTS_DIR, "data.js"))
            print(f"[+] Preview HTML written (no gamertag data)")
            if html_file:
                file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                print(f"[*] Opening in browser: {file_url}")
                webbrowser.open(file_url)
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
                print(f"ERROR: Gamertag '{gamertag}' not found in accounts.json")
                print(f"  Known gamertags: {', '.join(accounts.keys()) or '(none)'}")
                print("  Run `python XCT.py add` to set up a gamertag.")
            else:
                # Refresh token
                print(f"[*] Refreshing token for {gamertag}...")
                refresh_account_token(gamertag)

                html_file, _lib = process_account(gamertag)
                if html_file:
                    file_url = "file:///" + html_file.replace("\\", "/").replace(" ", "%20")
                    print(f"[*] Opening in browser: {file_url}")
                    webbrowser.open(file_url)

    # Always enter interactive menu
    interactive_menu()


if __name__ == "__main__":
    if "--no-update" not in sys.argv:
        check_for_updates()
    else:
        sys.argv.remove("--no-update")
    main()
