#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""T200 - serves the two server-side cores over HTTPS from inside the lab server.

The product's setup script downloads each core from a pinned https address and checks its SHA-256; it refuses plain
http and does not skip certificate checks. In the lab the cores are the ones the project built itself
(`target/server-cores`), so they are served from the server itself, on a name (`cores.lab`) that the lab points at
127.0.0.1 and a certificate the lab makes and trusts in this one container. Nothing here is reachable from outside:
it listens on the loopback address only.
"""
import functools
import http.server
import ssl
import sys

directory, certificate, key = sys.argv[1], sys.argv[2], sys.argv[3]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
