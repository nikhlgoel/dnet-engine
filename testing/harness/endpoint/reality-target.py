#!/usr/bin/env python3
"""The TLS 1.3 "target" a VLESS+REALITY server forwards unauthenticated handshakes to.

REALITY makes a connection look like a TLS session with a real third-party site: a client that
cannot prove it holds the key is handed to that site. The harness endpoint has no route to the
internet (HN-06), so it hosts its own stand-in. It only has to complete a TLS 1.3 handshake and
answer a request; REALITY authenticates real clients by key, not by this certificate.

Bound to loopback only: nothing outside the endpoint container should ever reach it.
"""

import socket
import ssl
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9443
CERT = sys.argv[2] if len(sys.argv) > 2 else "/opt/state/reality/target.crt"
KEY = sys.argv[3] if len(sys.argv) > 3 else "/opt/state/reality/target.key"
BODY = b"dnet-harness-reality-target\n"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
    + f"Content-Length: {len(BODY)}\r\n\r\n".encode()
    + BODY
)


def serve(context: ssl.SSLContext, raw: socket.socket) -> None:
    try:
        # A connection that never finishes its handshake must not hold a thread forever: REALITY
        # forwards every unauthenticated handshake here.
        raw.settimeout(10)
        with context.wrap_socket(raw, server_side=True) as tls:
            tls.recv(4096)
            tls.sendall(RESPONSE)
    except (ssl.SSLError, OSError):
        pass  # a probe that hung up mid-handshake is not an error here


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.load_cert_chain(CERT, KEY)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", PORT))
        server.listen(64)
        while True:
            raw, _ = server.accept()
            threading.Thread(target=serve, args=(context, raw), daemon=True).start()


if __name__ == "__main__":
    main()
