"""The polished Tunnel mark: master art, small-size art, and the tray's state frames, as SVG.

Colours are the app's own tokens (docs/design/tokens.css, dark): base #1b2523, paper #f1ebdd, ok #4fdcb0,
probe #ecc95e, warn #f5a55c, fail #ff8478. The art is flat (no gradient, no glow: design-system section 2).

Run:  python make_tunnel.py   -> writes svg/*.svg next to this file.
"""
import pathlib

HERE = pathlib.Path(__file__).parent
OUT = HERE / "svg"
OUT.mkdir(exist_ok=True)

INK = "#1b2523"
EDGE = "#2f403b"      # the tile's inner edge: a hairline that gives the shape its edge on any wallpaper
PAPER = "#f1ebdd"
MID = "#8ea299"       # the middle arch: the tunnel receding
FAR = "#4d625a"       # the floor
LAMP = {"ok": "#4fdcb0", "probe": "#ecc95e", "warn": "#f5a55c", "fail": "#ff8478", "off": "#7a8d85"}

BASE = 404            # where the arches meet the floor


def arch_path(w: float, apex: float, base: float = BASE) -> str:
    x1, x2, r = 256 - w / 2, 256 + w / 2, w / 2
    return f"M{x1:g} {base:g} V{apex + r:g} A{r:g} {r:g} 0 0 1 {x2:g} {apex + r:g} V{base:g}"


def door_path(w: float, apex: float, base: float = BASE) -> str:
    return arch_path(w, apex, base) + " Z"


def tile(body: str, rx: int, edge: bool = True) -> str:
    hair = (
        f'<rect x="3" y="3" width="506" height="506" rx="{rx - 3}" fill="none" stroke="{EDGE}" stroke-width="4"/>'
        if edge
        else ""
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">'
        f'<rect width="512" height="512" rx="{rx}" fill="{INK}"/>{hair}{body}</svg>\n'
    )


def master() -> str:
    """The full mark, for 48 px and up: three receding arches, a lit door, a packet of light, the floor."""
    door = 136
    body = (
        # the floor: the tunnel has ground to stand on
        f'<rect x="66" y="{BASE + 4}" width="380" height="18" rx="9" fill="{FAR}"/>'
        f'<path d="{arch_path(328, 84)}" fill="none" stroke="{PAPER}" stroke-width="30" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="{arch_path(232, 158)}" fill="none" stroke="{MID}" stroke-width="26" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="{door_path(door, 232)}" fill="{LAMP["ok"]}"/>'
        # one packet of light inside the door
        f'<circle cx="256" cy="{BASE - 62}" r="17" fill="{PAPER}"/>'
    )
    return tile(body, 112)


def small() -> str:
    """For 16 to 32 px: two arches and the lit door, thicker, with no floor and no packet."""
    body = (
        f'<path d="{arch_path(336, 92, 420)}" fill="none" stroke="{PAPER}" stroke-width="46" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="{door_path(168, 216, 420)}" fill="{LAMP["ok"]}"/>'
    )
    return tile(body, 112, edge=False)


def tray(state: str, fill: float = 1.0) -> str:
    """A tray frame: the small mark, with the door showing the state by SHAPE as well as colour.

    off / down  the door is an outline only                 (nothing is lit)
    probe       the door fills from the bottom, `fill` 0..1 (something is being tried; animated by the caller)
    ok          the door is filled                          (carrying)
    warn        the door is filled in its lower half only   (carrying, poorly)
    fail        the door is filled with a gap down the middle (broken)
    """
    base, apex, w = 420, 216, 168
    color = LAMP[state if state in LAMP else "off"]
    door = door_path(w, apex, base)
    outer = f'<path d="{arch_path(336, 92, 420)}" fill="none" stroke="{PAPER}" stroke-width="46" stroke-linecap="round" stroke-linejoin="round"/>'
    x1 = 256 - w / 2
    height = base - apex
    clip = f'<clipPath id="d"><path d="{door}"/></clipPath>'
    if state in ("off", "down"):
        inner = f'<path d="{door}" fill="none" stroke="{color}" stroke-width="22" stroke-linejoin="round"/>'
        if state == "down":
            inner += f'<path d="M{x1 + 10:g} {base - 8:g} L{x1 + w - 10:g} {apex + 30:g}" stroke="{color}" stroke-width="22" stroke-linecap="round"/>'
    elif state == "probe":
        top = base - height * fill
        inner = (
            f'<path d="{door}" fill="none" stroke="{color}" stroke-width="22" stroke-linejoin="round"/>'
            f'<g clip-path="url(#d)"><rect x="{x1:g}" y="{top:g}" width="{w}" height="{height * fill + 2:g}" fill="{color}"/></g>'
        )
    elif state == "ok":
        inner = f'<path d="{door}" fill="{color}"/>'
    elif state == "warn":
        mid = apex + height * 0.45
        inner = (
            f'<path d="{door}" fill="none" stroke="{color}" stroke-width="22" stroke-linejoin="round"/>'
            f'<g clip-path="url(#d)"><rect x="{x1:g}" y="{mid:g}" width="{w}" height="{base - mid + 2:g}" fill="{color}"/></g>'
        )
    else:  # fail
        inner = (
            f'<path d="{door}" fill="{color}"/>'
            f'<rect x="{256 - 12}" y="{apex - 10}" width="24" height="{height + 20}" fill="{INK}"/>'
        )
    return tile(clip + outer + inner, 112, edge=False)


def write(name: str, text: str) -> None:
    (OUT / name).write_text(text, encoding="utf-8")


write("master.svg", master())
write("small.svg", small())
for state in ("off", "down", "ok", "warn", "fail"):
    write(f"tray-{state}.svg", tray(state))
FRAMES = 12
for k in range(FRAMES):
    # Fills from empty to full over the first eight frames, holds, then drains: a breath, not a spinner.
    ramp = [0.0, 0.12, 0.3, 0.5, 0.7, 0.88, 1.0, 1.0, 0.88, 0.7, 0.5, 0.3][k]
    write(f"tray-probe-{k:02d}.svg", tray("probe", ramp))
print("wrote", len(list(OUT.glob("*.svg"))), "svg files")
