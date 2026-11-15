# The tunnel mark

The product's icon and the pictures of the tray: **arches receding to a doorway**. Chosen by the owner from ten concepts
(2026-11-15) and polished here. The doorway is the state, shown by *shape* as well as colour, so the logo is not a picture
beside the program but a live part of it.

| File | What |
|---|---|
| `master.svg` | The full mark, 48 px and up: three receding arches, a lit doorway, a packet of light, the floor. |
| `small.svg` | For 16 to 32 px (and the website's favicon): two arches and the doorway, thicker, nothing finer. |
| `make_tunnel.py` | Writes every SVG, including the tray's state frames, into `svg/` (not committed). |
| `build_assets.py` | Renders them (with `render.mjs`, which uses `@resvg/resvg-js`) into `apps/dnet-tray/src-tauri/icons/` and `site/favicon.svg`. |

Rebuild: `npm i @resvg/resvg-js` somewhere, then `python make_tunnel.py && python build_assets.py`.

**The tray's pictures** (`icons/tray/*.png`, 64 px): *off* an empty doorway; *probe* the doorway filling and draining (12
frames, the one thing that moves, because it is the only state in which something is being tried); *ok* a lit doorway;
*warn* a half-lit one; *fail* a lit one with a gap through it; *down* (the service did not answer) a crossed one.
`dnet_view::tray::Lamp` chooses, `src-tauri/src/tray_icon.rs` carries them. The window's `Mark.svelte` draws the same
shapes from the design tokens, so the logo in the window and the one in the tray always say the same thing.

Colours are the app's own tokens (`docs/design/tokens.css`, dark): base `#1b2523`, paper `#f1ebdd`, ok `#4fdcb0`,
probe `#ecc95e`, warn `#f5a55c`, fail `#ff8478`. The art is flat: no gradient and no glow (design-system §2).
The name of the product is **not** decided; nothing here depends on it.
