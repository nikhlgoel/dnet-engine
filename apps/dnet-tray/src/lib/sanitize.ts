/**
 * Design-system §17 rules 1 and 2: every string from the service is text, and is stripped before it is
 * shown. A Wi-Fi name is chosen by whoever runs the access point, so it is hostile input like the rest.
 *
 * Control characters would drive a terminal if a string were ever printed; bidirectional controls would
 * reorder or hide neighbouring text; zero-width characters would hide text altogether. All become `?`,
 * the same rule `dnetctl` applies (`render::plain`), so the two clients show the same thing.
 */

const MAX_SHOWN = 200;

function unsafe(codePoint: number): boolean {
  return (
    codePoint < 0x20 ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    // line and paragraph separators, which some renderers break on
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    // zero-width space, non-joiner, joiner, word joiner, and the byte-order mark
    (codePoint >= 0x200b && codePoint <= 0x200d) ||
    codePoint === 0x2060 ||
    codePoint === 0xfeff ||
    // bidirectional marks, embeddings, overrides and isolates
    codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  );
}

/** `text` with every character that could drive a display or disguise other text replaced by `?`, cut to `max`. */
export function plain(text: unknown, max: number = MAX_SHOWN): string {
  if (typeof text !== 'string') return '';
  const shown: string[] = [];
  let count = 0;
  for (const ch of text) {
    if (count === max) {
      shown.push('…');
      break;
    }
    shown.push(unsafe(ch.codePointAt(0) ?? 0) ? '?' : ch);
    count += 1;
  }
  return shown.join('');
}
