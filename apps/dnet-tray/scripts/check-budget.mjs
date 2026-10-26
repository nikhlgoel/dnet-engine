// Size budget for the built window (ADR-0007 R6, design-system §17): JavaScript ≤ 150 KB gzipped, fonts ≤ 60 KB.
// Runs after `vite build`; a build over budget fails, so growth is a decision and not an accident.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';
import { gzipSync } from 'node:zlib';

const BUDGET_JS_GZ = 150 * 1024;
const BUDGET_FONTS = 60 * 1024;

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}

let js = 0;
let fonts = 0;
for (const path of files('dist')) {
  const ext = extname(path);
  if (ext === '.js') js += gzipSync(readFileSync(path)).length;
  else if (['.woff', '.woff2', '.ttf', '.otf'].includes(ext)) fonts += statSync(path).size;
}

const kb = (n) => `${(n / 1024).toFixed(1)} KB`;
console.log(`javascript ${kb(js)} gzipped (budget ${kb(BUDGET_JS_GZ)}); fonts ${kb(fonts)} (budget ${kb(BUDGET_FONTS)})`);
if (js > BUDGET_JS_GZ || fonts > BUDGET_FONTS) {
  console.error('over budget');
  process.exit(1);
}
