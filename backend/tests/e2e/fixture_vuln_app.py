"""Deliberately vulnerable local fixture web application (E2E only).

This server exists purely for controlled end-to-end testing of the VibeShield
scanner against a local, fully-owned target. It Never serves real traffic to
third parties and binds only to 127.0.0.1.

Routes:
- /            — vulnerable HTML page (meta tags, form, inline+external script)
- /app.js      — JS with a secret candidate, eval(), fetch() API ref, http:// ref
- /plain.js    — innocuous JS (control)
- /chain1..12  — redirect chain longer than the scanner's 5-hop limit
- /loop_a,/loop_b — infinite redirect loop
- /redir_ftp   — 302 redirect to ftp:// (always-invalid scheme)
- /redir_loopback — 302 redirect to another loopback port (prohibited
                    when private targets are disallowed)
- /health      — {ok: true}
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A clearly fake secret so evidence-redaction checks never leak a real value.
FAKE_SECRET = "sk-vibeshield-E2E-FAKE-secret-000"

INDEX_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="description" content="Deliberately vulnerable fixture for VibeShield E2E">
<meta name="generator" content="fixture_vuln_app">
<title>VibeShield Vulnerable Fixture</title>
<link rel="stylesheet" href="https://cdn.example.com/nonexistent.css">
<script src="/app.js"></script>
<script>const inlineApiKey = "{FAKE_SECRET}"; eval("1+1");</script>
</head>
<body>
<h1>Vulnerable fixture</h1>
<form action="/login" method="post">
<input name="user" type="text">
<input name="pass" type="password">
<button type="submit">go</button>
</form>
<a href="http://insecure-rn.example.com/path">insecure link</a>
<a href="/page2">safe link</a>
<img src="http://insecure-rn.example.com/img.png" alt="x">
</body>
</html>
"""

APP_JS = f"""// fixture app.js: deliberately unsafe patterns
const apiKey = "{FAKE_SECRET}";
const awsKey = "AKIAIOSFODNN7EXAMPLE";
// insecure transport reference used by the page itself:
fetch("http://insecure-rn.example.com/api/users")
  .then(r => r.json())
  .then(data => {{
    eval(data.code);
    document.write(data.html);
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.SIG";
    console.log(jwt);
  }});
debugger;
"""


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "VibeShieldVulnFixture/1.0"

    # Deliberately weak header set (no CSP, no HSTS, etc.).

    def _cookie_header(self) -> str:
        # Session cookie WITHOUT Secure/HttpOnly/SameSite - cookie_analysis
        # must observe all three weaknesses.
        return "fixture_session=deadbeef; fixture_prefs=dark"

    def send_response_and(self, code: int, content_type: str, body: bytes, extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "vibeshield-fixture/1.0 (unsafe)")
        self.send_header("Set-Cookie", self._cookie_header())
        self.send_header("Access-Control-Allow-Origin", "*")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self.send_response_and(200, "application/json", json.dumps({"ok": True}).encode())
        elif path in ("/", "/index.html"):
            self.send_response_and(200, "text/html; charset=utf-8", INDEX_HTML.encode())
        elif path == "/app.js":
            self.send_response_and(200, "application/javascript", APP_JS.encode())
        elif path == "/plain.js":
            self.send_response_and(200, "application/javascript", b"const ok = 1;\n")
        elif path in ("/page2", "/login", "/data"):
            self.send_response_and(200, "text/html", b"<html><body>fixture page</body></html>")
        elif path.startswith("/chain"):
            # /chain1 -> /chain2 -> ... -> /chain12 (12 > scanner limit of 5)
            try:
                n = int(path[len("/chain"):])
            except ValueError:
                n = 1
            if n >= 12:
                self.send_response_and(200, "text/plain", b"end of chain")
                return
            self.send_response_and(302, "text/plain", b"",
                                   {"Location": f"/chain{n + 1}"})
        elif path in ("/loop_a", "/loop_b"):
            nxt = "/loop_b" if path == "/loop_a" else "/loop_a"
            self.send_response_and(302, "text/plain", b"", {"Location": nxt})
        elif path == "/redir_ftp":
            self.send_response_and(302, "text/plain", b"", {"Location": "ftp://127.0.0.1/root"})
        elif path == "/redir_loopback":
            # Prohibited for scanners that forbid private destinations.
            self.send_response_and(302, "text/plain", b"", {"Location": "http://127.0.0.1:59876/x"})
        else:
            self.send_response_and(404, "text/plain", b"fixture: not found")

    def log_message(self, fmt: str, *args: object) -> None:  # keep console quiet
        pass


def start_fixture_server(port: int = 0) -> tuple[ThreadingHTTPServer, int]:
    """Start the fixture app on 127.0.0.1; returns (server, bound_port)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8901)
    args = parser.parse_args()
    srv, real_port = start_fixture_server(args.port)
    print(f"fixture listening on http://127.0.0.1:{real_port}", flush=True)
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
