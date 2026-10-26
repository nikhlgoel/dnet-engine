import { describe, expect, it } from 'vitest';
import { plain } from '../src/lib/sanitize';
import { FAILURE_CAUSES, ModelError, parseSnapshot, type FailureCause } from '../src/lib/model';
import { rawSnapshot, type MockNetworks, type MockState } from '../src/lib/mock';

const STATES: MockState[] = ['off', 'probe', 'ok', 'warn', 'fail'];
const NETWORKS: MockNetworks[] = ['one', 'two', 'three'];

function raw(state: MockState, networks: MockNetworks = 'two', cause: FailureCause = FAILURE_CAUSES[0]): Record<string, unknown> {
  return rawSnapshot({ state, networks, cause }, 1_000) as Record<string, unknown>;
}

describe('plain (design-system §17: every string from the service is hostile)', () => {
  it('turns control, bidi and zero-width characters into ?', () => {
    expect(plain('a\u0007b')).toBe('a?b');
    expect(plain('a\u202eb')).toBe('a?b');
    expect(plain('a\u200bb')).toBe('a?b');
    expect(plain('a\u2028b')).toBe('a?b');
    expect(plain('a\u0085b')).toBe('a?b');
    expect(plain('a\ufeffb')).toBe('a?b');
    expect(plain('a\u2066b\u2069')).toBe('a?b?');
  });

  it('keeps ordinary text, including non-Latin scripts and emoji', () => {
    expect(plain('Café 日本語 🙂')).toBe('Café 日本語 🙂');
  });

  it('cuts to the limit by characters, not UTF-16 units, and says it did', () => {
    expect(plain('abcdef', 3)).toBe('abc…');
    expect(plain('🙂🙂🙂🙂', 2)).toBe('🙂🙂…');
  });

  it('shows nothing for a value that is not text', () => {
    expect(plain(42)).toBe('');
    expect(plain(null)).toBe('');
    expect(plain({})).toBe('');
  });
});

describe('parseSnapshot', () => {
  it('accepts every state the window can draw, with one, two and three networks', () => {
    for (const state of STATES) {
      for (const networks of NETWORKS) {
        expect(() => parseSnapshot(raw(state, networks), 5)).not.toThrow();
      }
    }
  });

  it('accepts every failure cause, and only those', () => {
    expect(FAILURE_CAUSES).toHaveLength(7);
    for (const cause of FAILURE_CAUSES) {
      expect(parseSnapshot(raw('fail', 'two', cause), 5).failure?.cause).toBe(cause);
    }
    const unknown = raw('fail');
    unknown.failure = { ...(unknown.failure as object), cause: 'Unknown' };
    expect(() => parseSnapshot(unknown, 5)).toThrow(ModelError);
  });

  it('rejects what is not an object or has an unknown status', () => {
    for (const bad of [null, 7, 'x', [], undefined]) expect(() => parseSnapshot(bad, 0)).toThrow(ModelError);
    expect(() => parseSnapshot({ ...raw('ok'), status: 'Maybe' }, 0)).toThrow(ModelError);
  });

  it('rejects a snapshot that contradicts itself (IPC-11 applied again at this boundary)', () => {
    // Connected with nothing carrying.
    expect(() => parseSnapshot({ ...raw('ok'), activeProfile: null }, 0)).toThrow(ModelError);
    expect(() => parseSnapshot({ ...raw('ok'), activeEndpoint: null }, 0)).toThrow(ModelError);
    // Something carrying while not connected.
    expect(() => parseSnapshot({ ...raw('off'), activeProfile: raw('ok').activeProfile }, 0)).toThrow(ModelError);
    // Failed with no cause; a cause while not failed.
    expect(() => parseSnapshot({ ...raw('fail'), failure: null }, 0)).toThrow(ModelError);
    expect(() => parseSnapshot({ ...raw('ok'), failure: raw('fail').failure }, 0)).toThrow(ModelError);
    // The fail-closed posture while connected, and a tunnel while not.
    expect(() => parseSnapshot({ ...raw('ok'), posture: { kind: 'FailClosed' } }, 0)).toThrow(ModelError);
    expect(() => parseSnapshot({ ...raw('off'), posture: { kind: 'Tunnelled', tier: 'Tier2' } }, 0)).toThrow(ModelError);
    // The posture and the profile disagree about the tier.
    expect(() => parseSnapshot({ ...raw('ok'), posture: { kind: 'Tunnelled', tier: 'Tier1' } }, 0)).toThrow(ModelError);
  });

  it('cleans every string it keeps', () => {
    const value = raw('ok');
    value.activeEndpoint = { id: 'e1', label: 'evil\u202e\u0007name' };
    value.lastBecause = 'because\u200b!';
    const s = parseSnapshot(value, 0);
    expect(s.activeEndpoint?.label).toBe('evil??name');
    expect(s.lastBecause).toBe('because?!');
  });

  it('refuses numbers that are not finite', () => {
    const value = raw('ok');
    (value.stats as Record<string, unknown>).connectedForS = Number.NaN;
    expect(() => parseSnapshot(value, 0)).toThrow(ModelError);
    const paths = raw('ok').paths as { paths: Array<Record<string, unknown>> };
    paths.paths[0] = { ...paths.paths[0], rttMs: Number.POSITIVE_INFINITY };
    expect(() => parseSnapshot({ ...raw('ok'), paths }, 0)).toThrow(ModelError);
  });

  it('keeps the window clock it was given, to age the snapshot', () => {
    expect(parseSnapshot(raw('ok'), 12345).receivedAtMs).toBe(12345);
  });
});
