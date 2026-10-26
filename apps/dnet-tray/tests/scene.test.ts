import { describe, expect, it } from 'vitest';
import { POINTS_FULL, POINTS_REDUCED, hash, pointFor, radiusFor, slotsFor } from '../src/lib/scene';

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
    expect(radiusFor(0)).toBe(48);
    expect(radiusFor(10_000)).toBe(96);
    expect(radiusFor(200)).toBeCloseTo(68, 5);
  });
});
