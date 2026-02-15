#!/usr/bin/env python3
"""
Xbox Auth Helper
================
Helps you get the XBL3.0 token needed by xbox_library.py.

The Collections API requires a token with full device authentication
claims (including your Xbox User ID). The simplest way to get this
is by extracting it from xbox.com's authenticated requests.

Usage:
  python xbox_auth.py
"""

import os
import sys
import webbrowser

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_TOKEN_FILE = os.path.join(SCRIPT_DIR, "auth_token.txt")

JS_SNIPPET = r"""(function(){var o=XMLHttpRequest.prototype.setRequestHeader,f=window.fetch,d=false;XMLHttpRequest.prototype.setRequestHeader=function(n,v){if(!d&&n.toLowerCase()==='authorization'&&v.startsWith('XBL3.0')){d=true;copy(v);console.log('%c[OK] Token copied! ('+v.length+' chars)','color:#4caf50;font-size:14px;font-weight:bold');XMLHttpRequest.prototype.setRequestHeader=o;window.fetch=f}return o.apply(this,arguments)};window.fetch=function(i,init){if(!d&&init&&init.headers){var h=init.headers instanceof Headers?init.headers:new Headers(init.headers);var a=h.get('authorization')||'';if(a.startsWith('XBL3.0')){d=true;copy(a);console.log('%c[OK] Token copied! ('+a.length+' chars)','color:#4caf50;font-size:14px;font-weight:bold');window.fetch=f;XMLHttpRequest.prototype.setRequestHeader=o}}return f.apply(this,arguments)};console.log('%c[*] Waiting... click on a game or navigate around.','color:#ff9800;font-size:13px')})();"""


def main():
    print("=" * 56)
    print("  Xbox Auth Helper")
    print("=" * 56)
    print()
    print("  This will help you get your XBL3.0 auth token")
    print("  from xbox.com using your browser.")
    print()
    print("=" * 56)
    print()

    print("Step 1: Opening xbox.com — sign in if needed.")
    webbrowser.open("https://www.xbox.com/en-GB/games/all-games")
    print()

    print("Step 2: Open DevTools (F12) > Console tab.")
    print('        Type "allow pasting" if prompted.')
    print()

    print("Step 3: Paste this snippet and press Enter:")
    print()
    print(f"  {JS_SNIPPET}")
    print()

    print("Step 4: Click on any game tile on the page.")
    print('        You should see "[OK] Token copied!" in the console.')
    print()

    token = input("Step 5: Paste the token here: ").strip()

    if not token.startswith("XBL3.0"):
        print()
        print("ERROR: Token should start with 'XBL3.0'.")
        print(f"  Got: {token[:50]}...")
        sys.exit(1)

    with open(AUTH_TOKEN_FILE, "w") as f:
        f.write(token)

    print()
    print(f"[+] Token saved to {AUTH_TOKEN_FILE}")
    print(f"    Token length: {len(token)} chars")
    print()
    print("You can now run: python xbox_library.py")


if __name__ == "__main__":
    main()
