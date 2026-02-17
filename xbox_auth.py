#!/usr/bin/env python3
"""
Xbox Auth Helper — Multi-Account Device Auth
==============================================
Authenticates with Xbox Live using the device auth flow (ProofOfPossession)
to produce XBL3.0 tokens with full device claims, suitable for the Collections API.

Supports multiple accounts stored under accounts/{gamertag}/.

Usage:
  python xbox_auth.py                    # Interactive: list accounts, pick to refresh or add new
  python xbox_auth.py add                # Add new account (device code flow)
  python xbox_auth.py refresh <gamertag> # Refresh specific account token
  python xbox_auth.py refresh --all      # Refresh all account tokens
  python xbox_auth.py extract [file]     # HAR extraction (prompts for label)

Requires: pip install ecdsa  (for SISU auth; HAR extraction works without it)
"""

import base64
import glob
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DIR = os.path.join(SCRIPT_DIR, "accounts")
ACCOUNTS_FILE = os.path.join(SCRIPT_DIR, "accounts.json")

CLIENT_ID = "000000004c12ae6f"
SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"

CACHE_FILES = [
    "entitlements.json",
    "catalog_gb.json",
    "catalog_us.json",
    "gamepass.json",
    "gamepass_details.json",
    "_gp_catalog_gb_tmp.json",
    "_gp_catalog_us_tmp.json",
]

# Windows FILETIME epoch offset (seconds between 1601-01-01 and 1970-01-01)
FILETIME_EPOCH_OFFSET = 11644473600

ecdsa = None  # lazy import


def _require_ecdsa():
    """Import ecdsa on demand so HAR extraction works without it."""
    global ecdsa
    if ecdsa is not None:
        return
    try:
        import ecdsa as _ecdsa
        ecdsa = _ecdsa
    except ImportError:
        print("ERROR: 'ecdsa' package is required for SISU auth.")
        print("  Install it with: pip install ecdsa")
        print()
        print("  Or use HAR extraction instead: python xbox_auth.py extract")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Account Registry
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# EC P-256 Key Management
# ---------------------------------------------------------------------------

def b64url(data):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_ec_key():
    """Generate a new EC P-256 key pair."""
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    return sk


def ec_key_to_jwk(sk):
    """Convert an ecdsa SigningKey to a JWK dict (public key only)."""
    vk = sk.get_verifying_key()
    # Public key is 64 bytes: 32 bytes x + 32 bytes y
    pub = vk.to_string()
    x = pub[:32]
    y = pub[32:]
    return {
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "x": b64url(x),
        "y": b64url(y),
    }


def save_state(sk, refresh_token=None, gamertag=None):
    """Persist EC key pair and refresh token."""
    state = {
        "private_key_hex": sk.to_string().hex(),
        "refresh_token": refresh_token,
    }
    if gamertag:
        ensure_account_dir(gamertag)
        state_file = account_path(gamertag, "xbox_auth_state.json")
    else:
        state_file = os.path.join(SCRIPT_DIR, "xbox_auth_state.json")
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def load_state(gamertag=None):
    """Load persisted EC key pair and refresh token. Returns (sk, refresh_token) or (None, None)."""
    if gamertag:
        state_file = account_path(gamertag, "xbox_auth_state.json")
    else:
        state_file = os.path.join(SCRIPT_DIR, "xbox_auth_state.json")
    if not os.path.isfile(state_file):
        return None, None
    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(state["private_key_hex"]),
            curve=ecdsa.NIST256p,
        )
        return sk, state.get("refresh_token")
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"[!] Warning: Could not load state file: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Request Signing
# ---------------------------------------------------------------------------

def filetime_now():
    """Return current time as Windows FILETIME (100-nanosecond intervals since 1601-01-01)."""
    return int((time.time() + FILETIME_EPOCH_OFFSET) * 10_000_000)


def sign_request(sk, method, url, auth_header="", body=b""):
    """
    Sign an Xbox Live request using the EC P-256 key.

    Returns the Signature header value.
    """
    ts = filetime_now()

    # Parse URL to get path+query
    parsed = urllib.parse.urlparse(url)
    path_and_query = parsed.path
    if parsed.query:
        path_and_query += "?" + parsed.query

    # Build signature payload
    # version(1, 4 bytes BE) + null + timestamp(8 bytes BE) + null +
    # method + null + url_path_and_query + null + auth_header + null + body + null
    payload = struct.pack(">I", 1)  # version = 1, 4 bytes big-endian
    payload += b"\x00"
    payload += struct.pack(">Q", ts)  # timestamp, 8 bytes big-endian
    payload += b"\x00"
    payload += method.upper().encode("ascii") + b"\x00"
    payload += path_and_query.encode("ascii") + b"\x00"
    payload += auth_header.encode("ascii") + b"\x00"
    if isinstance(body, str):
        body = body.encode("utf-8")
    payload += body + b"\x00"

    # SHA-256 hash
    digest = hashlib.sha256(payload).digest()

    # ECDSA sign (deterministic, 64-byte r||s)
    sig_bytes = sk.sign_digest(digest, sigencode=ecdsa.util.sigencode_string)

    # Encode: version(4 bytes) + timestamp(8 bytes) + signature(64 bytes)
    header_bytes = struct.pack(">I", 1) + struct.pack(">Q", ts) + sig_bytes

    return base64.b64encode(header_bytes).decode("ascii")


# ---------------------------------------------------------------------------
# HTTP Helpers
# ---------------------------------------------------------------------------

def xbox_request(url, body_dict, sk, extra_headers=None):
    """
    Make a signed POST request to an Xbox Live endpoint.
    Returns parsed JSON response.
    """
    body = json.dumps(body_dict).encode("utf-8")
    signature = sign_request(sk, "POST", url, body=body)

    headers = {
        "Content-Type": "application/json",
        "Signature": signature,
        "x-xbl-contract-version": "1",
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"[!] HTTP {e.code} from {url}")
        print(f"    {error_body[:500]}")
        raise


def msa_request(url, params):
    """Make a form-encoded POST to login.live.com. Returns parsed JSON."""
    body = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"[!] HTTP {e.code} from {url}")
        print(f"    {error_body[:500]}")
        raise


# ---------------------------------------------------------------------------
# Auth Flow Steps
# ---------------------------------------------------------------------------

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


def get_device_token(sk):
    """Step B: Get Device Token."""
    print("[*] Getting device token...")

    jwk = ec_key_to_jwk(sk)
    device_id = "{" + str(uuid.uuid4()).upper() + "}"

    resp = xbox_request(
        "https://device.auth.xboxlive.com/device/authenticate",
        {
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "AuthMethod": "ProofOfPossession",
                "Id": device_id,
                "DeviceType": "Win32",
                "Version": "10.0.19041",
                "ProofKey": jwk,
            },
        },
        sk,
    )

    token = resp["Token"]
    print(f"[+] Device token acquired (expires: {resp.get('NotAfter', 'unknown')})")
    return token


def xbl_user_authenticate(sk, msa_token, device_token):
    """Step C: XBL User Authenticate — get a PoP-bound user token."""
    print("[*] Authenticating user with Xbox Live...")

    jwk = ec_key_to_jwk(sk)

    resp = xbox_request(
        "https://user.auth.xboxlive.com/user/authenticate",
        {
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "AuthMethod": "RPS",
                "DeviceToken": device_token,
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"t={msa_token}",
                "ProofKey": jwk,
            },
        },
        sk,
    )

    token = resp["Token"]
    print(f"[+] User token acquired (expires: {resp.get('NotAfter', 'unknown')})")
    return token


def get_gamertag(sk, user_token, device_token):
    """Resolve the gamertag by requesting an XSTS token for xboxlive.com (which includes gtg in claims)."""
    print("[*] Resolving gamertag...")
    try:
        resp = xbox_request(
            "https://xsts.auth.xboxlive.com/xsts/authorize",
            {
                "RelyingParty": "http://xboxlive.com",
                "TokenType": "JWT",
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [user_token],
                    "DeviceToken": device_token,
                },
            },
            sk,
            extra_headers={"x-xbl-contract-version": "2"},
        )
        xui = resp["DisplayClaims"]["xui"][0]
        gamertag = xui.get("gtg", "")
        if gamertag:
            print(f"[+] Gamertag: {gamertag}")
        return gamertag
    except Exception as e:
        print(f"[!] Could not resolve gamertag: {e}")
        return ""


def get_xsts_token(sk, user_token, device_token):
    """Step D: Get XSTS token for the Collections/Licensing relying party."""
    print("[*] Getting XSTS token for licensing...")

    resp = xbox_request(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        {
            "RelyingParty": "http://licensing.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [user_token],
                "DeviceToken": device_token,
            },
        },
        sk,
    )

    token = resp["Token"]
    user_hash = resp["DisplayClaims"]["xui"][0]["uhs"]
    print(f"[+] XSTS token acquired (uhs={user_hash})")
    return token, user_hash


def build_xbl3_token(xsts_token, user_hash):
    """Step E: Build the XBL3.0 token string."""
    return f"XBL3.0 x={user_hash};{xsts_token}"


# ---------------------------------------------------------------------------
# Cache Management
# ---------------------------------------------------------------------------

def clear_api_cache(gamertag=None):
    """Delete cached API responses so xbox_library.py fetches fresh data."""
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


# ---------------------------------------------------------------------------
# Auth Flows
# ---------------------------------------------------------------------------

def sisu_auth_for_account(existing_gamertag=None):
    """Full device authentication flow: MSA -> Device Token -> User Token -> XSTS.
    If existing_gamertag is provided, loads state from that account's directory.
    Returns the gamertag."""
    _require_ecdsa()

    # Load existing state for refresh, or generate fresh key for new accounts
    if existing_gamertag:
        sk, refresh_token = load_state(gamertag=existing_gamertag)
        if sk is None:
            print("[*] Generating new EC P-256 key pair...")
            sk = generate_ec_key()
        else:
            print("[*] Loaded existing EC key pair from state file.")
    else:
        print("[*] Generating new EC P-256 key pair...")
        sk = generate_ec_key()
        refresh_token = None

    # Get MSA token (refresh or device code)
    msa_token = None
    if refresh_token:
        try:
            msa_token, refresh_token = refresh_msa_token(refresh_token)
        except Exception as e:
            print(f"[!] Refresh failed: {e}")
            print("[*] Falling back to device code flow...")
            refresh_token = None

    if msa_token is None:
        msa_token, refresh_token = device_code_auth()

    print()

    # Device Token (PoP-bound to our EC key)
    device_token = get_device_token(sk)

    # User Token (PoP-bound, linked to device token)
    user_token = xbl_user_authenticate(sk, msa_token, device_token)

    # Resolve gamertag (separate XSTS call to xboxlive.com RP)
    gamertag = existing_gamertag or get_gamertag(sk, user_token, device_token)

    # XSTS Token for licensing (with device claims)
    xsts_token, user_hash = get_xsts_token(sk, user_token, device_token)

    if not gamertag:
        # Fallback: prompt for gamertag if lookup failed
        gamertag = input("  Enter gamertag label for this account: ").strip()
        if not gamertag:
            gamertag = f"Account_{user_hash[:8]}"

    # Save state and token to account directory
    ensure_account_dir(gamertag)
    save_state(sk, refresh_token, gamertag=gamertag)

    # Build and save XBL3.0 token
    xbl3_token = build_xbl3_token(xsts_token, user_hash)
    token_file = account_path(gamertag, "auth_token.txt")
    with open(token_file, "w") as f:
        f.write(xbl3_token)

    # Register in accounts.json
    register_account(gamertag, user_hash)

    # Clear cache for this account
    clear_api_cache(gamertag=gamertag)

    print()
    print(f"[+] Account: {gamertag}")
    print(f"[+] XBL3.0 token saved to {token_file}")
    print(f"    Length: {len(xbl3_token)} chars")

    return gamertag


def cmd_add():
    """Add a new account via device code flow. Loops until user declines."""
    while True:
        print("=" * 56)
        print("  Xbox Auth — Add New Account")
        print("=" * 56)
        print()
        gamertag = sisu_auth_for_account()
        print()
        print(f"You can now run: python xbox_library.py {gamertag}")
        print()
        again = input("Add another account? [y/N]: ").strip().lower()
        if again not in ("y", "yes"):
            break
        print()


def cmd_refresh(gamertag):
    """Refresh a specific account's token."""
    accounts = load_accounts()
    if gamertag not in accounts:
        print(f"ERROR: Account '{gamertag}' not found in accounts.json")
        print(f"  Known accounts: {', '.join(accounts.keys()) or '(none)'}")
        sys.exit(1)

    print("=" * 56)
    print(f"  Xbox Auth — Refresh: {gamertag}")
    print("=" * 56)
    print()
    sisu_auth_for_account(existing_gamertag=gamertag)
    print()
    print(f"You can now run: python xbox_library.py {gamertag}")


def cmd_refresh_all():
    """Refresh all accounts' tokens."""
    accounts = load_accounts()
    if not accounts:
        print("No accounts found. Run: python xbox_auth.py add")
        sys.exit(1)

    print("=" * 56)
    print(f"  Xbox Auth — Refresh All ({len(accounts)} accounts)")
    print("=" * 56)
    print()

    results = []
    for gamertag in accounts:
        print(f"\n--- Refreshing: {gamertag} ---")
        try:
            sisu_auth_for_account(existing_gamertag=gamertag)
            results.append((gamertag, True))
        except Exception as e:
            print(f"[!] Failed to refresh {gamertag}: {e}")
            results.append((gamertag, False))

    print()
    print("=" * 56)
    print("  Refresh Summary")
    print("=" * 56)
    for gt, ok in results:
        status = "OK" if ok else "FAILED"
        print(f"  {gt}: {status}")


def cmd_interactive():
    """Interactive mode: list accounts, pick one to refresh or add new."""
    accounts = load_accounts()

    # Check for legacy flat files
    legacy_token = os.path.join(SCRIPT_DIR, "auth_token.txt")
    if not accounts and os.path.isfile(legacy_token):
        print("Legacy auth files found in script directory.")
        print("Run `python xbox_auth.py add` to set up your account.")
        print()

    if not accounts:
        print("No accounts found. Starting new account setup...")
        print()
        cmd_add()
        return

    print("=" * 56)
    print("  Xbox Auth — Account Manager")
    print("=" * 56)
    print()
    print("  Accounts:")

    gamertags = list(accounts.keys())
    for i, gt in enumerate(gamertags, 1):
        token_file = account_path(gt, "auth_token.txt")
        if os.path.isfile(token_file):
            age_s = time.time() - os.path.getmtime(token_file)
            age_h = age_s / 3600
            if age_h < 1:
                age_str = f"{int(age_s / 60)}m old"
            else:
                age_str = f"{age_h:.1f}h old"
        else:
            age_str = "no token"
        print(f"    [{i}] {gt} (token: {age_str})")

    print(f"    [A] Refresh all accounts")
    print(f"    [N] Add new account")
    print()

    pick = input(f"  Pick [1-{len(gamertags)}, A, N]: ").strip()

    if pick.upper() == "A":
        cmd_refresh_all()
    elif pick.upper() == "N":
        cmd_add()
    else:
        try:
            idx = int(pick) - 1
            if 0 <= idx < len(gamertags):
                cmd_refresh(gamertags[idx])
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid selection.")


# ---------------------------------------------------------------------------
# HAR Extraction (fallback)
# ---------------------------------------------------------------------------

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


def har_extract(arg=None):
    """HAR extraction subcommand."""
    print("=" * 56)
    print("  Xbox Auth Helper — HAR Token Extractor")
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

    # Prompt for gamertag label
    uhs = selected.split(";")[0].replace("XBL3.0 x=", "")
    print()
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
    print()
    print(f"You can now run: python xbox_library.py {label}")


# ---------------------------------------------------------------------------
# Token refresh helper (importable by xbox_library.py)
# ---------------------------------------------------------------------------

def refresh_account_token(gamertag):
    """Refresh an account's XBL3.0 token. Returns True on success."""
    _require_ecdsa()
    try:
        sisu_auth_for_account(existing_gamertag=gamertag)
        return True
    except Exception as e:
        print(f"[!] Token refresh failed for {gamertag}: {e}")
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if not args:
        # Interactive mode
        cmd_interactive()
    elif args[0] == "add":
        cmd_add()
    elif args[0] == "refresh":
        if len(args) >= 2:
            if args[1] == "--all":
                cmd_refresh_all()
            else:
                cmd_refresh(args[1])
        else:
            print("Usage: python xbox_auth.py refresh <gamertag>")
            print("       python xbox_auth.py refresh --all")
            sys.exit(1)
    elif args[0] == "extract":
        arg = args[1] if len(args) >= 2 else None
        har_extract(arg)
    else:
        print(f"Unknown command: {args[0]}")
        print()
        print("Usage:")
        print("  python xbox_auth.py                    # Interactive mode")
        print("  python xbox_auth.py add                # Add new account")
        print("  python xbox_auth.py refresh <gamertag> # Refresh specific account")
        print("  python xbox_auth.py refresh --all      # Refresh all accounts")
        print("  python xbox_auth.py extract [file]     # HAR extraction")
        sys.exit(1)


if __name__ == "__main__":
    main()
