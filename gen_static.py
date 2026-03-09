"""Generate static HTML for Nginx direct serving.

Run inside the Docker container:
    docker exec freshdex-xct-live python3 /app/gen_static.py
"""
import gzip
import os
import sys

sys.path.insert(0, "/app")
os.makedirs("/app/static", exist_ok=True)

AUTH_JS = open("/app/auth_hosted.js").read()

from XCT import build_html_template

HEADER_HTML = (
    '<div id="xct-auth" style="margin-left:auto;display:flex;align-items:center;gap:8px;padding:0 12px">'
    '<span id="xct-auth-user" style="color:#888;font-size:12px"></span>'
    '<img id="xct-avatar" src="" style="width:24px;height:24px;border-radius:50%;object-fit:cover;display:none;cursor:pointer" onclick="_openProfile()">'
    '<span id="xct-xbox-gt" style="color:#107c10;font-size:12px;display:none;cursor:pointer" onclick="_openProfile()"></span>'
    "<button id=\"xct-upload-btn\" onclick=\"document.getElementById('xct-upload-input').click()\" "
    'style="display:none;padding:4px 12px;background:#333;color:#ccc;border:1px solid #555;border-radius:4px;font-size:12px;cursor:pointer">Upload</button>'
    '<input type="file" id="xct-upload-input" accept=".json" style="display:none" onchange="_xctUploadFile(this)">'
    '<button id="xct-xbox-btn" onclick="_xctXboxAuth()" style="padding:4px 12px;background:#107c10;color:#fff;border:none;border-radius:4px;font-size:12px;cursor:pointer;display:none">\u2b22 Sign in with Xbox</button>'
    '<button id="xct-auth-btn" onclick="_xctShowAuth()" style="padding:4px 12px;background:#107c10;color:#fff;border:none;border-radius:4px;font-size:12px;cursor:pointer">Log In</button>'
    '</div>\n'
)

html = build_html_template(
    header_html=HEADER_HTML,
    default_tab="marketplace",
    extra_js=AUTH_JS,
)

with open("/app/static/index.html", "w", encoding="utf-8") as f:
    f.write(html)
with open("/app/static/index.html.gz", "wb") as f:
    f.write(gzip.compress(html.encode("utf-8"), compresslevel=6))

print(f"[+] Static HTML: {len(html):,} bytes, gzipped: {os.path.getsize('/app/static/index.html.gz'):,} bytes")
