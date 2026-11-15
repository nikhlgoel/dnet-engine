// Render SVG files to PNG with resvg. Usage: node render.mjs <svg> <size> <out.png> [<svg> <size> <out.png> ...]
import { Resvg } from '@resvg/resvg-js';
import { readFileSync, writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i += 3) {
  const [svg, size, out] = [args[i], Number(args[i + 1]), args[i + 2]];
  const png = new Resvg(readFileSync(svg), { fitTo: { mode: 'width', value: size } }).render().asPng();
  writeFileSync(out, png);
}
