import pathlib, struct, subprocess, sys
K = pathlib.Path(__file__).parent
REPO = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else K.parents[2]
ICONS = REPO / "apps/dnet-tray/src-tauri/icons"
TRAY = ICONS / "tray"
TRAY.mkdir(exist_ok=True)

def render(svg, size, out):
    subprocess.run(["node", str(K / "render.mjs"), str(K / "svg" / svg), str(size), str(out)], check=True, cwd=K)

# the application icon: the full mark from 48 px up, the small one below
sizes = [16, 24, 32, 48, 64, 128, 256]
pngs = {}
for s in sizes:
    out = K / "png" / f"app-{s}.png"
    render("master.svg" if s >= 48 else "small.svg", s, out)
    pngs[s] = out.read_bytes()
render("master.svg", 512, ICONS / "icon.png")
(ICONS / "32x32.png").write_bytes(pngs[32])
(ICONS / "128x128.png").write_bytes(pngs[128])
(ICONS / "128x128@2x.png").write_bytes(pngs[256])
# a .ico that embeds PNGs (Windows Vista and later)
entries = []
offset = 6 + 16 * len(sizes)
head = struct.pack("<HHH", 0, 1, len(sizes))
data = b""
for s in sizes:
    b = pngs[s]
    entries.append(struct.pack("<BBBBHHII", 0 if s >= 256 else s, 0 if s >= 256 else s, 0, 0, 1, 32, len(b), offset + len(data)))
    data += b
(ICONS / "icon.ico").write_bytes(head + b"".join(entries) + data)
# the tray's frames, 64 px
for name in ("off", "down", "ok", "warn", "fail"):
    render(f"tray-{name}.svg", 64, TRAY / f"{name}.png")
for k in range(12):
    render(f"tray-probe-{k:02d}.svg", 64, TRAY / f"probe-{k:02d}.png")
# the website's icon: the small mark, as vector
(REPO / "site" / "favicon.svg").write_text((K / "svg" / "small.svg").read_text(encoding="utf-8"), encoding="utf-8")
print("assets written:", sorted(p.name for p in TRAY.glob("*.png")))
