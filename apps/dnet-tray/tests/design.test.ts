/**
 * The design rules that must not drift (design-system §4, §10, §17; ADR-0007 R4, R7), checked against the files
 * themselves: the contrast of every pair in both themes, no colour defined outside tokens.css, and none of the
 * constructs that would let a hostile string become markup or let the page reach the network.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '..');
const TOKENS = readFileSync(join(ROOT, '..', '..', 'docs', 'design', 'tokens.css'), 'utf8');

function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

const SOURCES = [...walk(join(ROOT, 'src'))].filter((p) => /\.(svelte|ts|css|html)$/.test(p));
const rel = (p: string): string => relative(ROOT, p).replaceAll('\\', '/');

/** A source file without its comments, so a rule is checked against what runs and not against prose about it. */
function code(path: string): string {
  return readFileSync(path, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

// ------------------------------------------------------------------ contrast

type Rgb = [number, number, number];

/** The declarations inside the first block whose selector text starts with `selector`. */
function block(css: string, selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`no block for ${selector}`);
  const open = css.indexOf('{', start);
  const close = css.indexOf('}', open);
  const out: Record<string, string> = {};
  for (const m of css.slice(open + 1, close).matchAll(/--c-([\w-]+):\s*(#[0-9a-fA-F]{6})\b/g)) {
    out[m[1] as string] = m[2] as string;
  }
  return out;
}

const THEMES: Record<'dark' | 'light', Record<string, string>> = {
  dark: block(TOKENS, ':root,\n:root[data-theme="dark"]'),
  light: block(TOKENS, ':root[data-theme="light"]'),
};

const rgb = (hex: string): Rgb => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as Rgb;
const lin = (v: number): number => {
  const c = v / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};
const lum = ([r, g, b]: Rgb): number => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
const ratio = (a: Rgb, b: Rgb): number => {
  const x = lum(a);
  const y = lum(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
};
const mix = (a: Rgb, b: Rgb, p: number): Rgb => a.map((v, i) => Math.round(v * (1 - p) + (b[i] as number) * p)) as Rgb;

/** The same 22 pairs as `docs/design/preview.html`, plus words on the ambient wash of each lamp (8): 30. */
const CHECKS: Array<[string, string, number]> = [
  ['text', 'base', 4.5], ['text', 'card', 4.5], ['text', 'raised', 4.5],
  ['text-2', 'base', 4.5], ['text-2', 'card', 4.5], ['text-2', 'raised', 4.5],
  ['text-3', 'card', 4.5], ['on-paper', 'paper', 4.5],
  ['ok', 'card', 4.5], ['probe', 'card', 4.5], ['warn', 'card', 4.5], ['fail', 'card', 4.5],
  ['ok', 'base', 3], ['probe', 'base', 3], ['warn', 'base', 3], ['fail', 'base', 3],
  ['line-strong', 'card', 3], ['line-strong', 'base', 3], ['line-strong', 'raised', 3],
  ['focus', 'base', 3], ['focus', 'card', 3], ['focus', 'raised', 3],
];

describe('tokens.css', () => {
  it('reads both themes completely', () => {
    for (const theme of ['dark', 'light'] as const) {
      for (const name of ['base', 'card', 'raised', 'line', 'line-strong', 'text', 'text-2', 'text-3', 'paper', 'on-paper', 'focus', 'ok', 'probe', 'warn', 'fail']) {
        expect(THEMES[theme][name], `${theme} ${name}`).toMatch(/^#[0-9a-f]{6}$/i);
      }
    }
  });

  it('gives the system-light media query the same values as data-theme="light" (no drift)', () => {
    const media = block(TOKENS, ':root:not([data-theme="dark"])');
    for (const [name, value] of Object.entries(THEMES.light)) expect(media[name], name).toBe(value);
  });

  for (const theme of ['dark', 'light'] as const) {
    describe(`${theme} theme: WCAG 2.2 AA`, () => {
      for (const [fg, bg, need] of CHECKS) {
        it(`${fg} on ${bg} is at least ${need} : 1`, () => {
          const t = THEMES[theme];
          expect(ratio(rgb(t[fg] as string), rgb(t[bg] as string))).toBeGreaterThanOrEqual(need);
        });
      }

      for (const lamp of ['ok', 'probe', 'warn', 'fail']) {
        for (const text of ['text-2', 'text-3']) {
          it(`${text} on the stage washed with ${lamp} is at least 4.5 : 1`, () => {
            const t = THEMES[theme];
            const strength = Number(/--ambient-strength:\s*(\d+)%/.exec(TOKENS)?.[1]) / 100;
            const wash = mix(rgb(t.base as string), rgb(t[lamp] as string), strength);
            expect(ratio(rgb(t[text] as string), wash)).toBeGreaterThanOrEqual(4.5);
          });
        }
      }
    });
  }

  it('checks thirty pairs per theme', () => {
    expect(CHECKS.length + 4 * 2).toBe(30);
  });
});

// ------------------------------------------------------------------ source rules

describe('the window’s source', () => {
  it('has sources to check', () => {
    expect(SOURCES.length).toBeGreaterThan(25);
  });

  it('defines no colour, size or duration of its own (ADR-0007 R7): tokens only', () => {
    for (const path of SOURCES) {
      const text = readFileSync(path, 'utf8');
      // `#` followed by hex digits at a word boundary, and the colour functions. Comments and `href="#…"` fragments
      // do not match because no source uses a hex-looking fragment.
      expect(text.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [], rel(path)).toEqual([]);
      expect(text.match(/\b(rgba?|hsla?|hwb|oklch|oklab|lab|lch)\(/g) ?? [], rel(path)).toEqual([]);
    }
  });

  it('never builds markup from a string: no {@html}, innerHTML, document.write, eval or new Function', () => {
    for (const path of SOURCES) {
      const text = code(path);
      expect(text, rel(path)).not.toMatch(/\{@html\b|\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write|\beval\(|new Function\(/);
    }
  });

  it('has no inline style attribute, which the page’s CSP would refuse', () => {
    for (const path of SOURCES.filter((p) => p.endsWith('.svelte'))) {
      // `style:prop={…}` directives are set through the CSSOM and are fine; a `style="…"` attribute is not.
      expect(readFileSync(path, 'utf8'), rel(path)).not.toMatch(/\sstyle\s*=/);
    }
  });

  it('never reaches the network or the filesystem itself: that is the Rust side’s job (R4)', () => {
    for (const path of SOURCES) {
      const text = readFileSync(path, 'utf8');
      expect(text, rel(path)).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon|https?:\/\//);
    }
  });

  it('keeps the control pipe out of the web view entirely', () => {
    for (const path of SOURCES) {
      expect(readFileSync(path, 'utf8'), rel(path)).not.toMatch(/\\\\\.\\pipe|dnet-control|@tauri-apps\/plugin-(fs|shell|http)/);
    }
  });

  // Which source may name the third-party components is enforced for the whole repository, this directory
  // included, by `cargo xtask lint-branding` (CI job `licence-compliance`); a second copy here would only drift.
});

describe('the page’s Content-Security-Policy', () => {
  const config = readFileSync(join(ROOT, 'vite.config.ts'), 'utf8');

  // The policy as written in the plugin, without the comment above it that explains why it has no unsafe source.
  const policy = /const policy = \[([\s\S]*?)\]/.exec(config)?.[1] ?? '';

  it('starts from default-src self and allows no unsafe source', () => {
    expect(policy).toContain(`"default-src 'self'"`);
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
  });

  it('allows no object, no base, no form posting', () => {
    expect(config).toContain(`"object-src 'none'"`);
    expect(config).toContain(`"base-uri 'none'"`);
    expect(config).toContain(`"form-action 'none'"`);
  });

  it('lets the page talk only to itself and to the Tauri bridge', () => {
    const connect = /"connect-src ([^"]*)"/.exec(config)?.[1] ?? '';
    expect(connect.split(' ').sort()).toEqual(["'self'", 'http://ipc.localhost', 'ipc:'].sort());
  });
});
