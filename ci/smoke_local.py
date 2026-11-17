#!/usr/bin/env python3
"""Platform smoke test: installed wheel must serve a local HTTP request."""

from __future__ import annotations

import http.server
import os
import socketserver
import threading

import ruyihttp


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ruyihttp-smoke"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main() -> int:
    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with ruyihttp.Session(firefox="159") as session:
            response = session.get(f"http://127.0.0.1:{port}/", timeout=10)
        server.shutdown()
    assert response.status_code == 200, response.status_code
    assert response.content == b"ruyihttp-smoke", response.content
    print("local smoke OK", ruyihttp.__version__, response.tls or "http")

    if os.environ.get("RUYIHTTP_LIVE") == "1":
        with ruyihttp.Session(firefox="159") as session:
            live = session.get("https://example.com/", timeout=20)
        assert live.status_code == 200, live.status_code
        print("live smoke OK", live.status_code, live.tls)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
