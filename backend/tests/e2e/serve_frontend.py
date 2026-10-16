"""Serve the production frontend build with /api reverse-proxied to the backend.

Used only by the Phase 8 E2E runner so headless Chrome can exercise the real
built frontend (real JS bundle, real backend responses).
"""

from __future__ import annotations

import argparse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
    ".woff2": "font/woff2",
}


def build_handler(dist: Path, api_base: str, backend_host: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VibeShieldE2EStatic/1.0"

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path.startswith("/api"):
                self._proxy()
                return
            if path in ("/", ""):
                path = "/index.html"
            candidate = (dist / path.lstrip("/")).resolve()
            if dist.resolve() not in candidate.parents and candidate != (dist / "index.html").resolve():
                self.send_error(403)
                return
            if not candidate.exists():
                # SPA fallback
                candidate = dist / "index.html"
            if not candidate.exists():
                self.send_error(404)
                return
            body = candidate.read_bytes()
            mime = MIME.get(candidate.suffix, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _proxy(self) -> None:
            url = api_base + self.path
            try:
                req = urllib.request.Request(url, method="GET")
                for k in ("Accept",):
                    if k in self.headers:
                        req.add_header(k, self.headers[k])
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = resp.read()
                    self.send_response(resp.status)
                    self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            except urllib.error.HTTPError as e:
                body = e.read()
                self.send_response(e.code)
                self.send_header("Content-Type", e.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                self.send_error(502)

        def log_message(self, fmt: str, *args: object) -> None:
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", required=True)
    parser.add_argument("--port", type=int, default=4174)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    dist = Path(args.dist).resolve()
    handler = build_handler(dist, args.api, None)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"frontend static server on http://127.0.0.1:{args.port} (api -> {args.api})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
