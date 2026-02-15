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
REDIRECT_PORT = 8921
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/auth/callback"
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
    """Open browser for Microsoft login, capture the auth code via local server."""
    auth_url = (
        "https://login.live.com/oauth20_authorize.srf"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&approval_prompt=auto"
        f"&scope={urllib.parse.quote(SCOPES)}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
    )

    result = {"code": None, "error": None}

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                result["code"] = params["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h2>Success!</h2>"
                    b"<p>Got authorization code. You can close this tab.</p>"
                    b"</body></html>"
                )
            else:
                result["error"] = params.get("error_description",
                    params.get("error", ["Unknown error"]))[0]
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    f"<html><body><h2>Error</h2><p>{result['error']}</p>"
                    f"</body></html>".encode()
                )

        def log_message(self, format, *args):
            pass  # suppress request logs

    server = http.server.HTTPServer(("127.0.0.1", REDIRECT_PORT), CallbackHandler)

    print("[*] Opening browser for Microsoft login...")
    print(f"    If the browser doesn't open, visit this URL:\n")
    print(f"    {auth_url}\n")
    webbrowser.open(auth_url)
    print("[*] Waiting for login callback...")

    server.handle_request()
    server.server_close()

    if result["error"]:
        print(f"ERROR: {result['error']}")
        sys.exit(1)

    if not result["code"]:
        print("ERROR: No authorization code received.")
        sys.exit(1)

    code = result["code"]
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
