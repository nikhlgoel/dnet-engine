import { describe, expect, it } from 'vitest';
import { disclosure, en, fill, plural } from '../src/lib/messages';

/** Every string in a nested object, with the path it was found at. */
function strings(value: unknown, path = 'en'): Array<[string, string]> {
  if (typeof value === 'string') return [[path, value]];
  if (Array.isArray(value)) return value.flatMap((v, i) => strings(v, `${path}[${i}]`));
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).flatMap(([k, v]) => strings(v, `${path}.${k}`));
  }
  return [];
}

const ALL = [...strings(en), ...strings(disclosure, 'disclosure')];

describe('voice (design-system §14, ADR-0006 §3)', () => {
  it('has strings to check', () => {
    expect(ALL.length).toBeGreaterThan(150);
  });

  it('never claims more than it can show: no secure, private, anonymous or protected', () => {
    for (const [path, text] of ALL) {
      expect(text, path).not.toMatch(/\b(secure[ds]?|security|private|privacy|anonymous|anonymity|protect(ed|s|ion)?)\b/i);
    }
  });

  it('never shouts or apologises with a mascot voice', () => {
    for (const [path, text] of ALL) {
      expect(text, path).not.toContain('!');
      expect(text, path).not.toMatch(/\b(oops|whoops|uh-oh|sorry about that)\b/i);
    }
  });

  it('never promises what a method has not been shown to do', () => {
    for (const [path, text] of ALL) {
      expect(text, path).not.toMatch(/\b(guarantee[ds]?|unblockable|undetectable|invisible|unbreakable)\b/i);
    }
  });

  it('uses typographic apostrophes and ellipses, not ASCII stand-ins', () => {
    // The window's own strings only: the disclosure is the service's wording, kept byte for byte.
    for (const [path, text] of strings(en)) {
      expect(text, path).not.toMatch(/\w'\w/);
      expect(text, path).not.toContain('...');
    }
  });

  it('keeps placeholders as plain {names}', () => {
    for (const [path, text] of ALL) {
      for (const m of text.matchAll(/\{([^}]*)\}/g)) expect(m[1], path).toMatch(/^\w+$/);
    }
  });
});

describe('fill and plural', () => {
  it('fills named placeholders and leaves a missing one visible', () => {
    expect(fill('{a} and {b}', { a: 1 })).toBe('1 and {b}');
  });

  it('picks the right form of a count', () => {
    const forms = { zero: 'none', one: 'one thing', other: '{count} things' };
    expect(plural(forms, 0)).toBe('none');
    expect(plural(forms, 1)).toBe('one thing');
    expect(plural(forms, 4)).toBe('4 things');
  });
});

describe('the encrypted-name disclosure', () => {
  it('is the service’s own words: all five parts present and non-empty', () => {
    for (const key of ['headline', 'what', 'why', 'howToOptOut', 'consequenceOfOptingOut'] as const) {
      expect(disclosure[key].length, key).toBeGreaterThan(20);
    }
    expect(disclosure.version).toBe(1);
  });

  it('states the consequence of opting out in the same breath as the choice', () => {
    expect(disclosure.consequenceOfOptingOut).toMatch(/will not apply/);
    expect(disclosure.howToOptOut).toMatch(/one step/);
  });
});
