#!/usr/bin/env python3
"""Deterministic HTTP origin for harness tests.

Endpoints:
  /            -> plain 200, for reachability checks
  /bytes/<n>   -> exactly n bytes, for throughput measurement. FR-004 requires
                  that a profile counts as working only if it carries usable
                  traffic, not merely if a handshake completes -- this is how
                  that gets measured.
  /blocked     -> stands in for a destination the simulated UTM blocks
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOAD = b"x" * 65536
MAX_BYTES = 512 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path == "/":
            self._send(b"dnet-harness-origin\n", "text/plain")
        elif self.path.startswith("/bytes/"):
            self._send_bytes()
        elif self.path == "/blocked":
            self._send(b"reached-blocked-destination\n", "text/plain")
        else:
            self.send_error(404)

    def _send_bytes(self):
        try:
            n = min(int(self.path.rsplit("/", 1)[1]), MAX_BYTES)
        except ValueError:
            self.send_error(400, "bad byte count")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.end_headers()
        sent = 0
        while sent < n:
            chunk = PAYLOAD[: min(len(PAYLOAD), n - sent)]
            self.wfile.write(chunk)
            sent += len(chunk)

    def _send(self, body: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # keep harness output readable


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
