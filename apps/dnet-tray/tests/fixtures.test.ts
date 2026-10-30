/**
 * The other half of the contract with the Rust side. `crates/dnet-view/tests/fixtures` holds what the window is
 * sent for each situation, pinned by a Rust test; this reads the same files with the window's own parser, so a
 * field renamed, retyped or dropped on either side fails a test on one of them (ADR-0007 R4).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ACTION_FOR_CAUSE, ACTION_LABEL, chips, look, strip } from '../src/lib/describe';
import { FAILURE_CAUSES, parseEndpoints, parseRulesReply, parseSnapshot } from '../src/lib/model';

const DIR = join(__dirname, '..', '..', '..', 'crates', 'dnet-view', 'tests', 'fixtures');
const read = (name: string): unknown => JSON.parse(readFileSync(join(DIR, `${name}.json`), 'utf8'));
const NAMES = readdirSync(DIR).map((f) => f.replace(/\.json$/, ''));
const SNAPSHOTS = NAMES.filter((n) => n.startsWith('snapshot-'));

describe('what the Rust side sends', () => {
  it('has the fixtures it is meant to', () => {
    expect(SNAPSHOTS.length).toBe(4 + FAILURE_CAUSES.length);
    expect(NAMES).toContain('endpoints');
    expect(NAMES).toContain('rules');
  });

  for (const name of SNAPSHOTS) {
    it(`${name}: parses, and every part of it can be drawn`, () => {
      const snapshot = parseSnapshot(read(name), 0);
      const l = look(snapshot);
      expect(l.headline.length).toBeGreaterThan(0);
      expect(l.announcement.length).toBeGreaterThan(0);
      expect(strip(snapshot)).toHaveLength(4);
      expect(() => chips(snapshot)).not.toThrow();
    });
  }

  it('a connected snapshot says what carries the connection, from the service’s own numbers', () => {
    const s = parseSnapshot(read('snapshot-connected'), 0);
    expect(s.status).toBe('Connected');
    expect(s.activeProfile).toEqual({ id: 'hy2-default', kind: 'Hysteria2', tier: 'Tier2' });
    expect(s.paths.paths.map((p) => p.role)).toEqual(['Carrying', 'Standby', 'Unusable']);
    expect(s.paths.paths[0]).toMatchObject({ name: 'Hostel-5G', rttMs: 43.3, loss: 0.023, measured: true });
    expect(s.paths.paths[2]).toMatchObject({ measured: false, rttMs: null });
    expect(s.lastBecause).toMatch(/Hysteria 2 carried/);
    expect(look(s).because).toBe(s.lastBecause);
  });

  it('a slow connection is drawn as such, with the reason it is staying put', () => {
    const l = look(parseSnapshot(read('snapshot-degraded'), 0));
    expect(l.lamp).toBe('warn');
    expect(l.because).toMatch(/no other network is better/);
  });

  it('an older service’s answer is shown as not measured, never as fine', () => {
    const s = parseSnapshot(read('snapshot-older-service'), 0);
    for (const cell of strip(s)) expect(cell.none).toBe(true);
    expect(look(s).lamp).toBe('ok');
  });

  for (const cause of FAILURE_CAUSES) {
    it(`failure ${cause}: its own words, whole, and its one action`, () => {
      const s = parseSnapshot(read(`snapshot-failed-${cause.toLowerCase()}`), 0);
      expect(s.failure?.cause).toBe(cause);
      const l = look(s);
      expect(l.lamp).toBe('fail');
      expect(l.assertive).toBe(true);
      expect(l.headline).toBe(s.failure?.title);
      expect(l.because).toBe(s.failure?.detail);
      // The advice is the service's sentence, uncut; the button is the window's short label.
      expect(l.advice).toBe(s.failure?.action);
      expect(l.advice.endsWith('…')).toBe(false);
      expect(l.advice.length).toBeGreaterThan(20);
      expect(l.action).toEqual({ id: ACTION_FOR_CAUSE[cause], label: ACTION_LABEL[ACTION_FOR_CAUSE[cause]] });
      expect(l.action?.label.length).toBeLessThan(30);
      expect(l.announcement).toContain(l.advice);
    });
  }

  it('the seven failures do not share a headline', () => {
    const titles = FAILURE_CAUSES.map((c) => parseSnapshot(read(`snapshot-failed-${c.toLowerCase()}`), 0).failure?.title);
    expect(new Set(titles).size).toBe(7);
  });

  it('the endpoint list parses, and only the fields the window shows are in it', () => {
    const raw = read('endpoints') as { endpoints: Array<Record<string, unknown>> };
    const list = parseEndpoints(raw);
    expect(list.map((e) => e.label)).toEqual(['oracle-mumbai', 'spare']);
    expect(list[0]).toEqual({
      id: '5b1f0c1e-8a43-4c51-9a79-0f6d1a9c2f10',
      label: 'oracle-mumbai',
      address: '203.0.113.9:44443',
      enabled: true,
      health: 'Healthy',
    });
    for (const item of raw.endpoints) expect(Object.keys(item).sort()).toEqual(['address', 'enabled', 'health', 'id', 'label']);
  });

  it('the rules parse, with the encrypted-name setting in the window’s own names', () => {
    const view = parseRulesReply(read('rules'));
    expect(view.rules.map((r) => [r.precedence, r.reliability, r.builtin, r.kind, r.value])).toEqual([
      [1, 'Deterministic', true, 'ip_cidr', '10.0.0.0/8'],
      [200, 'BestEffort', false, 'application', 'C:\\Apps\\app.exe?'],
    ]);
    expect(view.rules[1]?.id).toBe('21111111-2222-4333-8444-555555555555');
    expect(view.encryptedDns).toEqual({ block: true, needsDisclosure: false });
  });
});
