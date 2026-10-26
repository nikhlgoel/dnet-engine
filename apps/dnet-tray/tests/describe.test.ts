import { describe, expect, it } from 'vitest';
import {
  ACTION_FOR_CAUSE,
  chips,
  formatDuration,
  freshness,
  look,
  strip,
} from '../src/lib/describe';
import { FAILURE_CAUSES, parseSnapshot, type FailureCause, type Snapshot } from '../src/lib/model';
import { rawSnapshot, type MockNetworks, type MockState } from '../src/lib/mock';

function snap(state: MockState, networks: MockNetworks = 'two', cause: FailureCause = FAILURE_CAUSES[0], at = 1_000): Snapshot {
  return parseSnapshot(rawSnapshot({ state, networks, cause }, at), at);
}

describe('look: every state says what it is and why (principle 3)', () => {
  const expected: Record<MockState, { lamp: string; shape: string }> = {
    off: { lamp: 'off', shape: 'ring' },
    probe: { lamp: 'probe', shape: 'ring' },
    ok: { lamp: 'ok', shape: 'sphere' },
    warn: { lamp: 'warn', shape: 'sphere' },
    fail: { lamp: 'fail', shape: 'cube' },
  };

  for (const state of Object.keys(expected) as MockState[]) {
    it(`${state}: lamp, shape, words and an announcement`, () => {
      const l = look(snap(state));
      expect(l.lamp).toBe(expected[state].lamp);
      expect(l.shape).toBe(expected[state].shape);
      expect(l.headline.length).toBeGreaterThan(0);
      expect(l.because.length).toBeGreaterThan(0);
      expect(l.announcement).toContain(l.headline);
    });
  }

  it('state is never carried by colour alone: each lamp has its own shape or its own words', () => {
    const seen = new Set(
      (['off', 'probe', 'ok', 'warn', 'fail'] as MockState[]).map((s) => {
        const l = look(snap(s));
        return `${l.shape}|${l.headline}`;
      }),
    );
    expect(seen.size).toBe(5);
  });

  it('the switch reflects the state', () => {
    expect(look(snap('off')).switch).toMatchObject({ on: false, busy: false, word: 'Stabilize' });
    expect(look(snap('probe')).switch).toMatchObject({ on: true, busy: true });
    expect(look(snap('ok')).switch).toMatchObject({ on: true, busy: false, word: 'Stabilized' });
    expect(look(snap('fail')).switch.on).toBe(false);
  });

  it('only a failure interrupts a screen reader, and only a failure offers an action', () => {
    for (const state of ['off', 'probe', 'ok', 'warn'] as MockState[]) {
      const l = look(snap(state));
      expect(l.assertive).toBe(false);
      expect(l.action).toBeNull();
    }
    const failed = look(snap('fail'));
    expect(failed.assertive).toBe(true);
    expect(failed.action).not.toBeNull();
  });

  it('each of the seven failure causes offers its own one action', () => {
    expect(Object.keys(ACTION_FOR_CAUSE).sort()).toEqual([...FAILURE_CAUSES].sort());
    for (const cause of FAILURE_CAUSES) {
      expect(look(snap('fail', 'two', cause)).action?.id).toBe(ACTION_FOR_CAUSE[cause]);
    }
  });

  it('a degraded connection says why it is staying put', () => {
    expect(look(snap('warn', 'one')).because).toMatch(/only network available/);
    expect(look(snap('warn', 'two')).because).toMatch(/no other network is better/);
  });

  it("uses the service's own words for the latest reason when it has them", () => {
    const base = snap('ok');
    expect(look({ ...base, lastBecause: 'It moved because of this.' }).because).toBe('It moved because of this.');
  });

  it('names the method, the tier and the carrying network', () => {
    expect(look(snap('ok')).facts).toBe('Hysteria 2 · Tier 2 · via Hostel-5G');
  });
});

describe('chips', () => {
  it('lists the networks with their roles', () => {
    const rows = chips(snap('ok', 'three'));
    expect(rows.map((r) => r.role)).toEqual(['carry', 'standby', 'lost']);
  });

  it('with nothing connected, a usable network is available and not standing by', () => {
    for (const row of chips(snap('off', 'two'))) expect(row.role).not.toBe('standby');
  });

  it('an unmeasured network says so and never shows a number', () => {
    for (const row of chips(snap('off', 'two'))) expect(row.metrics).not.toMatch(/\d/);
  });
});

describe('strip', () => {
  it('has four cells and shows no number it did not measure', () => {
    const cells = strip(snap('off'));
    expect(cells).toHaveLength(4);
    for (const c of cells) {
      expect(c.none).toBe(true);
      expect(c.value).toBe('—');
    }
  });

  it('shows rounded figures once connected', () => {
    const [latency, jitter, loss, stability] = strip(snap('ok'));
    expect(latency).toMatchObject({ value: '43', unit: 'ms', none: false });
    expect(jitter).toMatchObject({ value: '4', unit: 'ms' });
    expect(loss).toMatchObject({ value: '2', unit: '%' });
    expect(stability?.value).toBe('0 poor spells');
  });

  it('every cell has an accessible name that says what it measured', () => {
    for (const c of strip(snap('warn'))) expect(c.name.length).toBeGreaterThan(c.label.length);
  });
});

describe('formatDuration', () => {
  it('uses seconds, minutes and hours without ambiguity', () => {
    expect(formatDuration(0)).toBe('0 s');
    expect(formatDuration(59)).toBe('59 s');
    expect(formatDuration(60)).toBe('1 m 00 s');
    expect(formatDuration(3600 + 5 * 60)).toBe('1 h 05 m');
  });
});

describe('freshness: a figure is never shown as current without its age', () => {
  const s = snap('ok', 'two', FAILURE_CAUSES[0], 10_000);

  it('is live shortly after an update, and says how long ago', () => {
    expect(freshness(s, 13_000)).toEqual({ live: true, text: 'Live · updated 3 s ago' });
  });

  it('goes stale and says so instead of pretending', () => {
    const f = freshness(s, 10_000 + 60_000);
    expect(f.live).toBe(false);
    expect(f.text).toBe('Last update 60 s ago');
  });

  it('waits for the service when it has heard nothing', () => {
    expect(freshness(null, 0)).toEqual({ live: false, text: 'Waiting for the service' });
  });
});
