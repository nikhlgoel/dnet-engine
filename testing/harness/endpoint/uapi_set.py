"""Send one UAPI `set` operation to an AmneziaWG core over its unix socket.

Usage: uapi_set.py <socket-path> < lines

Reads `key=value` lines from stdin, frames them exactly as the client does on Windows
(`set=1`, the lines, a blank line), and exits non-zero unless the core answers errno=0.
Never echoes the request (it carries the private key).
"""

import socket
import sys


def main() -> int:
    path = sys.argv[1]
    body = "".join(line if line.endswith("\n") else line + "\n" for line in sys.stdin if line.strip())
    op = f"set=1\n{body}\n".encode()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        s.sendall(op)
        reply = b""
        while not reply.endswith(b"\n\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk

    text = reply.decode(errors="replace")
    if "errno=0" not in text:
        print(f"[uapi] rejected: {text.strip()}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
