import { describe, expect, it } from 'vitest';
import {
  POINTS_FULL,
  POINTS_REDUCED,
  easeHover,
  hash,
  pointFor,
  radiusFor,
  slotsFor,
} from '../src/lib/scene';

const SHAPES = ['ring', 'sphere', 'cube'] as const;

describe('pointFor: the three forms the figure takes', () => {
  for (const shape of SHAPES) {
    for (const n of [POINTS_REDUCED, POINTS_FULL]) {
      it(`${shape} with ${n} points: every coordinate is finite`, () => {
        for (let i = 0; i < n; i += 1) {
          for (const c of pointFor(shape, i, n)) expect(Number.isFinite(c)).toBe(true);
        }
      });
    }
  }

  it('a ring is flat, a sphere is round, a cube is boxy', () => {
    const n = POINTS_FULL;
    for (let i = 0; i < n; i += 1) {
      expect(pointFor('ring', i, n)[2]).toBe(0);
      const [x, y, z] = pointFor('sphere', i, n);
      expect(Math.hypot(x, y, z)).toBeCloseTo(1, 5);
      const [a, b, c] = pointFor('cube', i, n);
      expect(Math.max(Math.abs(a), Math.abs(b), Math.abs(c))).toBeCloseTo(0.82, 5);
    }
  });

  it('is deterministic, so a state draws the same figure every time', () => {
    for (const shape of SHAPES) expect(pointFor(shape, 17, POINTS_FULL)).toEqual(pointFor(shape, 17, POINTS_FULL));
  });
});

describe('layout helpers', () => {
  it('hash stays in [0, 1)', () => {
    for (let i = 0; i < 1000; i += 1) {
      const h = hash(i);
      expect(h).toBeGreaterThanOrEqual(0);
      expect(h).toBeLessThan(1);
    }
  });

  it('keeps the four network slots inside the scene at the window sizes it supports', () => {
    for (const [w, h] of [
      [560, 300],
      [960, 420],
      [1400, 600],
    ] as const) {
      const slots = slotsFor(w, h);
      expect(slots).toHaveLength(4);
      for (const s of slots) {
        expect(Number.isFinite(s.x) && Number.isFinite(s.y)).toBe(true);
        expect(s.x).toBeGreaterThan(0);
        expect(s.x).toBeLessThan(w);
        expect(s.y).toBeGreaterThan(0);
        expect(s.y).toBeLessThan(h);
      }
    }
  });

  it('bounds the core’s radius', () => {
    expect(radiusFor(0)).toBe(56);
    expect(radiusFor(10_000)).toBe(120);
    expect(radiusFor(200)).toBeCloseTo(80, 5);
  });

  it('leaves room for the figure between the network chips and inside the scene', () => {
    for (const [w, h] of [
      [560, 300],
      [960, 420],
      [1400, 600],
    ] as const) {
      const r = radiusFor(h);
      const [left, right] = slotsFor(w, h);
      // The figure never reaches the chips, and fits the scene with a margin.
      expect((right?.x ?? 0) - w / 2 - r).toBeGreaterThanOrEqual(48);
      expect(w / 2 - (left?.x ?? 0) - r).toBeGreaterThanOrEqual(48);
      expect(2 * r).toBeLessThanOrEqual(h * 0.85);
    }
  });
});

describe('easeHover: the hover is a soft lift of the figure itself, not an outline', () => {
  it('moves toward the target without overshooting, in both directions', () => {
    let v = 0;
    for (let i = 0; i < 60; i += 1) {
      const next = easeHover(v, true, 1 / 60, false);
      expect(next).toBeGreaterThanOrEqual(v);
      expect(next).toBeLessThanOrEqual(1);
      v = next;
    }
    expect(v).toBeGreaterThan(0.95);
    for (let i = 0; i < 90; i += 1) {
      const next = easeHover(v, false, 1 / 60, false);
      expect(next).toBeLessThanOrEqual(v);
      expect(next).toBeGreaterThanOrEqual(0);
      v = next;
    }
    expect(v).toBeLessThan(0.02);
  });

  it('does not move when no time has passed, and jumps when motion is reduced', () => {
    expect(easeHover(0.3, true, 0, false)).toBe(0.3);
    expect(easeHover(0.3, true, 0.016, true)).toBe(1);
    expect(easeHover(0.7, false, 0.016, true)).toBe(0);
  });

  it('stays finite and inside 0 to 1 for any input', () => {
    for (const dt of [0, 0.001, 0.1, 5, Number.POSITIVE_INFINITY, Number.NaN]) {
      for (const from of [0, 0.5, 1]) {
        for (const on of [true, false]) {
          const v = easeHover(from, on, dt, false);
          expect(Number.isFinite(v)).toBe(true);
          expect(v).toBeGreaterThanOrEqual(0);
          expect(v).toBeLessThanOrEqual(1);
        }
      }
    }
  });
});
