#!/usr/bin/env python3
"""
Xbox Auth Helper
================
Extracts the XBL3.0 token from a mitmproxy HAR capture of the Xbox app.

Usage:
  1. Capture Xbox app traffic with mitmproxy (Android/iOS)
  2. Export as HAR file to this directory
  3. Run: python xbox_auth.py [harfile]

If no file is specified, looks for any .har file in the current directory.
"""

import glob
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_TOKEN_FILE = os.path.join(SCRIPT_DIR, "auth_token.txt")


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

    tokens = {}  # token_value -> {len, urls, relying_party_guess}

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


def main():
    print("=" * 56)
    print("  Xbox Auth Helper — HAR Token Extractor")
    print("=" * 56)
    print()

    arg = sys.argv[1] if len(sys.argv) > 1 else None
    har_path = find_har_file(arg)
    print(f"[*] Reading: {os.path.basename(har_path)}")

    tokens = extract_token(har_path)

    # Group by token length (proxy for relying party)
    by_len = {}
    for token, info in tokens.items():
        by_len.setdefault(info["len"], []).append((token, info))

    print(f"[+] Found {len(tokens)} unique tokens ({len(by_len)} different types)\n")

    # Show summary and let user pick if multiple
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
        print(f"[+] Using the only token found.")
    else:
        # Default to the token used for collections/licensing, or the longest
        # Try to find the one used for collections.mp.microsoft.com
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
            print(f"[+] Auto-selected: token used for collections.mp.microsoft.com")
        else:
            try:
                pick = input(f"Pick token [1-{len(choices)}, default=1]: ").strip()
                idx = int(pick) - 1 if pick else 0
                selected = choices[idx]
            except (ValueError, IndexError):
                selected = choices[0]

    with open(AUTH_TOKEN_FILE, "w") as f:
        f.write(selected)

    print()
    print(f"[+] Token saved to {AUTH_TOKEN_FILE}")
    print(f"    Length: {len(selected)} chars")
    print()
    print("You can now run: python xbox_library.py")


if __name__ == "__main__":
    main()
