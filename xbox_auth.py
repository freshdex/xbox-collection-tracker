#!/usr/bin/env python3
"""
Xbox Auth Helper
================
Authenticates with your Microsoft account via OAuth2 and writes the
XBL3.0 token needed by xbox_library.py to auth_token.txt.

Uses only Python stdlib. No Azure app registration needed — uses the
same public Xbox Live client ID that the official Xbox app uses.

Usage:
  python xbox_auth.py
"""

import http.server
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
import threading

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_TOKEN_FILE = os.path.join(SCRIPT_DIR, "auth_token.txt")

# Public Xbox Live client ID (used by the Xbox app / community tools)
CLIENT_ID = "000000004C12AE6F"
REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
SCOPES = "Xboxlive.signin Xboxlive.offline_access"

# Relying party for collections.mp.microsoft.com
RELYING_PARTY = "http://mp.microsoft.com/"

SSL_CTX = ssl.create_default_context()


def api_post(url, body, headers=None):
    """POST JSON, return parsed response."""
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
        return json.loads(resp.read())


def get_oauth_token_via_browser():
    """Open browser for Microsoft login, capture the auth code via redirect."""
    auth_url = (
        "https://login.live.com/oauth20_authorize.srf"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&approval_prompt=auto"
        f"&scope={urllib.parse.quote(SCOPES)}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    )

    print("[*] Opening browser for Microsoft login...")
    print(f"    If the browser doesn't open, visit this URL:\n")
    print(f"    {auth_url}\n")
    webbrowser.open(auth_url)

    print("[*] After signing in, you'll be redirected to a blank page.")
    print("    Copy the ENTIRE URL from your browser's address bar and paste it here.\n")
    redirect_url = input("Paste redirect URL: ").strip()

    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)

    if "code" not in params:
        # Try parsing as fragment
        params = urllib.parse.parse_qs(parsed.fragment)

    if "code" not in params:
        print("ERROR: No authorization code found in the URL.")
        print(f"  URL: {redirect_url}")
        if "error" in params:
            print(f"  Error: {params.get('error', ['?'])[0]}")
            print(f"  Description: {params.get('error_description', ['?'])[0]}")
        sys.exit(1)

    code = params["code"][0]
    print(f"[+] Got authorization code ({len(code)} chars)")

    # Exchange code for access token
    print("[*] Exchanging code for access token...")
    token_data = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://login.live.com/oauth20_token.srf",
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
        token_resp = json.loads(resp.read())

    access_token = token_resp.get("access_token")
    if not access_token:
        print("ERROR: No access token in response.")
        print(f"  Response: {json.dumps(token_resp, indent=2)[:500]}")
        sys.exit(1)

    print(f"[+] Got OAuth access token ({len(access_token)} chars)")
    return access_token


def get_xbox_token(access_token):
    """Exchange OAuth access token for Xbox User Token."""
    print("[*] Requesting Xbox User Token...")
    resp = api_post(
        "https://user.auth.xboxlive.com/user/authenticate",
        body={
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": f"d={access_token}",
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        },
        headers={"x-xbl-contract-version": "1"},
    )
    token = resp.get("Token")
    print(f"[+] Got Xbox User Token ({len(token)} chars)")
    return token


def get_xsts_token(user_token):
    """Exchange Xbox User Token for XSTS token with the right relying party."""
    print(f"[*] Requesting XSTS token (relying party: {RELYING_PARTY})...")
    resp = api_post(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        body={
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [user_token],
            },
            "RelyingParty": RELYING_PARTY,
            "TokenType": "JWT",
        },
        headers={"x-xbl-contract-version": "1"},
    )

    token = resp.get("Token")
    uhs = resp.get("DisplayClaims", {}).get("xui", [{}])[0].get("uhs", "0")

    xbl3_token = f"XBL3.0 x={uhs};{token}"
    print(f"[+] Got XSTS token (user hash: {uhs})")
    return xbl3_token


def main():
    print("=" * 50)
    print("  Xbox Auth Helper")
    print("=" * 50)
    print()

    try:
        access_token = get_oauth_token_via_browser()
        user_token = get_xbox_token(access_token)
        xbl3_token = get_xsts_token(user_token)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        print(f"\nERROR: HTTP {e.code}")
        print(f"  {body}")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    with open(AUTH_TOKEN_FILE, "w") as f:
        f.write(xbl3_token)

    print()
    print(f"[+] Token saved to {AUTH_TOKEN_FILE}")
    print(f"    Token length: {len(xbl3_token)} chars")
    print()
    print("You can now run: python xbox_library.py")


if __name__ == "__main__":
    main()
