"""Write a plain placeholder icon (PNG, and an ICO that embeds it) for the UI spikes.

Run from testing/spike-ui:  python make_icons.py
The spikes only need *an* icon so the build and the tray work; it is not the product's icon.
"""
import os
import struct
import zlib

SIZE = 64


def png(size: int) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            inside = (x - size / 2) ** 2 + (y - size / 2) ** 2 < (size * 0.42) ** 2
            row += bytes((20, 184, 166, 255) if inside else (0, 0, 0, 0))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico(image: bytes, size: int) -> bytes:
    entry = struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(image), 22)
    return struct.pack("<HHH", 0, 1, 1) + entry + image


data = png(SIZE)
for folder in ("tauri-tray/icons",):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "icon.png"), "wb") as f:
        f.write(data)
    with open(os.path.join(folder, "icon.ico"), "wb") as f:
        f.write(ico(data, SIZE))
print("icons written")
