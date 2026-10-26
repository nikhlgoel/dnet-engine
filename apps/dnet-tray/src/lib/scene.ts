/**
 * The scene: a figure of dots whose form is the state, orbiting networks, and dotted beams between them
 * (design-system §5 and §6). Ported from `docs/design/preview.html`, which the owner reviewed.
 *
 * It is a canvas, drawn in 2D with perspective projection. No 3D or animation library (ADR-0007 R8). It is
 * decoration: every meaning in it is also text in the DOM, and the canvas is `aria-hidden`.
 *
 * Honesty (principle 11): dots flow along a beam only for the network that is carrying traffic; the beam of a
 * lossy network is drawn ragged; a lost network is a sparse dashed line; nothing moves while nothing happens.
 *
 * Budget (R8): at most 30 frames a second; paused while hidden (the component stops the loop); a still frame
 * under reduced motion; and if the average frame costs more than `SLOW_MS` the figure drops to half the frame
 * rate and half the points, rather than costing the person's battery.
 */
import type { ChipRole, Shape } from './describe';
import type { Lamp } from './model';

export const POINTS_FULL = 520;
export const POINTS_REDUCED = 260;
/** If the average frame costs more than this, the scene gets cheaper (R8). */
export const SLOW_MS = 4;
export const FRAME_MS_FULL = 33;
export const FRAME_MS_SLOW = 66;

export interface SceneColors {
  text2: string;
  text3: string;
  ok: string;
  probe: string;
  warn: string;
  fail: string;
}

export type Point3 = readonly [number, number, number];

/** Where point `i` of `n` sits for a form. Unit-ish coordinates: the figure is scaled by the radius. */
export function pointFor(kind: Shape, i: number, n: number): Point3 {
  if (kind === 'ring') {
    const track = i % 4;
    const perTrack = n / 4;
    const angle = (Math.floor(i / 4) / perTrack) * Math.PI * 2;
    const r = [0.8, 0.93, 1.06, 1.19][track] ?? 1;
    return [Math.cos(angle) * r, Math.sin(angle) * r, 0];
  }
  if (kind === 'cube') {
    const face = i % 6;
    const k = Math.floor(i / 6);
    const side = Math.ceil(Math.sqrt(n / 6));
    const u = (((k % side) + 0.5) / side) * 2 - 1;
    const v = ((Math.floor(k / side) + 0.5) / side) * 2 - 1;
    const s = 0.82;
    switch (face) {
      case 0:
        return [s, u * s, v * s];
      case 1:
        return [-s, u * s, v * s];
      case 2:
        return [u * s, s, v * s];
      case 3:
        return [u * s, -s, v * s];
      case 4:
        return [u * s, v * s, s];
      default:
        return [u * s, v * s, -s];
    }
  }
  // A Fibonacci lattice: an even scatter over a sphere.
  const y = 1 - (2 * (i + 0.5)) / n;
  const r = Math.sqrt(Math.max(0, 1 - y * y));
  const theta = i * 2.399963;
  return [Math.cos(theta) * r, y, Math.sin(theta) * r];
}

/** A cheap deterministic noise in [0, 1), for jitter that must not change between identical frames. */
export function hash(i: number): number {
  const x = Math.sin(i * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

export interface Slot {
  x: number;
  y: number;
  /** Which side of the core the chip sits on. */
  left: boolean;
}

/** Four places for network chips round the core, for a scene `width` by `height`. */
export function slotsFor(width: number, height: number): Slot[] {
  const cx = width / 2;
  const cy = height / 2;
  const dx = Math.min(width * 0.33, 290);
  const up = height * 0.12;
  const low = height * 0.3;
  return [
    { x: cx - dx, y: cy - up, left: true },
    { x: cx + dx, y: cy - up, left: false },
    { x: cx - dx * 0.82, y: cy + low, left: true },
    { x: cx + dx * 0.82, y: cy + low, left: false },
  ];
}

/** The core's radius for a scene of this height. */
export function radiusFor(height: number): number {
  return Math.max(48, Math.min(height * 0.34, 96));
}

const SPEED: Record<Lamp, number> = { off: 0.03, probe: 0.5, ok: 0.34, warn: 0.2, fail: 0.12 };
const TAU = Math.PI * 2;

export class Scene {
  private readonly ctx: CanvasRenderingContext2D;
  private n = POINTS_FULL;
  private base = new Float32Array(POINTS_FULL * 3);
  private target = new Float32Array(POINTS_FULL * 3);
  private lamp: Lamp = 'off';
  private shape: Shape = 'ring';
  private roles: ChipRole[] = [];
  private angle = 0;
  private roll = 0;
  private width = 0;
  private height = 0;
  private dpr = 1;
  private colors: SceneColors;
  private readonly dust = Array.from({ length: 70 }, (_, i) => ({
    x: ((i * 97) % 100) / 100,
    y: ((i * 53) % 100) / 100,
    s: 0.4 + ((i * 31) % 10) / 14,
    v: 0.004 + ((i * 17) % 10) / 3000,
  }));
  /** Recent frame costs in milliseconds, for the slow-device rule. */
  private readonly costs: number[] = [];
  private slow = false;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    colors: SceneColors,
  ) {
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('a 2D canvas is not available');
    this.ctx = ctx;
    this.colors = colors;
    this.retarget(true);
  }

  /** The colours changed (the theme did). */
  setColors(colors: SceneColors): void {
    this.colors = colors;
  }

  setState(lamp: Lamp, shape: Shape, still: boolean): void {
    this.lamp = lamp;
    if (shape !== this.shape) {
      this.shape = shape;
      this.retarget(still);
    }
  }

  setNetworks(roles: ChipRole[]): void {
    this.roles = roles;
  }

  /** Match the canvas to its box. Returns the slots the chips go in. */
  resize(width: number, height: number, devicePixelRatio: number): Slot[] {
    this.width = width;
    this.height = height;
    this.dpr = Math.min(devicePixelRatio || 1, 1.5);
    this.canvas.width = Math.round(width * this.dpr);
    this.canvas.height = Math.round(height * this.dpr);
    return slotsFor(width, height);
  }

  /** Whether the scene has had to get cheaper: the component then runs it at half the frame rate. */
  get isSlow(): boolean {
    return this.slow;
  }

  get frameIntervalMs(): number {
    return this.slow ? FRAME_MS_SLOW : FRAME_MS_FULL;
  }

  get pointCount(): number {
    return this.n;
  }

  private retarget(snap: boolean): void {
    for (let i = 0; i < this.n; i += 1) {
      const [x, y, z] = pointFor(this.shape, i, this.n);
      this.target[i * 3] = x;
      this.target[i * 3 + 1] = y;
      this.target[i * 3 + 2] = z;
      if (snap) {
        this.base[i * 3] = x;
        this.base[i * 3 + 1] = y;
        this.base[i * 3 + 2] = z;
      }
    }
  }

  private recordCost(ms: number): void {
    this.costs.push(ms);
    if (this.costs.length > 60) this.costs.shift();
    if (!this.slow && this.costs.length >= 30) {
      const mean = this.costs.reduce((a, b) => a + b, 0) / this.costs.length;
      if (mean > SLOW_MS) {
        this.slow = true;
        this.n = POINTS_REDUCED;
        this.base = new Float32Array(this.n * 3);
        this.target = new Float32Array(this.n * 3);
        this.retarget(true);
      }
    }
  }

  /** Draw one frame. `t` is seconds since the start, `dt` the seconds since the last frame; `still` draws a static frame. */
  draw(t: number, dt: number, still: boolean): void {
    const started = performance.now();
    const { ctx, width: W, height: H, n } = this;
    const c = this.colors;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const lamp = { off: c.text3, probe: c.probe, ok: c.ok, warn: c.warn, fail: c.fail }[this.lamp];
    const cx = W / 2;
    const cy = H / 2;
    const R = radiusFor(H);

    // Drifting dust, for depth. Still under reduced motion.
    ctx.fillStyle = c.text3;
    for (const d of this.dust) {
      if (!still) {
        d.y -= d.v * dt * 30;
        if (d.y < 0) d.y = 1;
      }
      ctx.globalAlpha = 0.18;
      ctx.beginPath();
      ctx.arc(d.x * W, d.y * H, d.s, 0, TAU);
      ctx.fill();
    }

    this.drawBeams(t, still, lamp, cx, cy, R);

    // The core.
    const speed = SPEED[this.lamp];
    if (!still) {
      this.angle += speed * dt;
      if (this.lamp === 'fail') this.roll += 0.1 * dt;
    }
    const ca = Math.cos(this.angle);
    const sa = Math.sin(this.angle);
    const pitch = this.shape === 'ring' ? 0 : 0.38;
    const cp = Math.cos(pitch);
    const sp = Math.sin(pitch);
    const cr = Math.cos(this.roll);
    const sr = Math.sin(this.roll);
    const k = still ? 1 : 0.09;

    interface Projected {
      x: number;
      y: number;
      z: number;
      i: number;
      bx: number;
      by: number;
    }
    const projected: Projected[] = [];
    for (let i = 0; i < n; i += 1) {
      const o = i * 3;
      // Glide toward the target form, so a change of state is seen, not cut.
      for (let a = 0; a < 3; a += 1) {
        const from = this.base[o + a] ?? 0;
        const to = this.target[o + a] ?? 0;
        this.base[o + a] = from + (to - from) * k;
      }
      const bx = this.base[o] ?? 0;
      const by = this.base[o + 1] ?? 0;
      const bz = this.base[o + 2] ?? 0;
      let x = bx;
      let y = by;
      let z = bz;
      if (this.shape === 'ring') {
        const tilt = 0.9;
        const yy = y * Math.cos(tilt) - z * Math.sin(tilt);
        const zz = y * Math.sin(tilt) + z * Math.cos(tilt);
        y = yy;
        z = zz;
      }
      const x1 = x * ca + z * sa;
      const z1 = -x * sa + z * ca;
      let y1 = y;
      if (this.lamp === 'fail') {
        const x2 = x1 * cr - y1 * sr;
        y1 = x1 * sr + y1 * cr;
        x = x2;
      } else {
        x = x1;
      }
      projected.push({ x, y: y1 * cp - z1 * sp, z: y1 * sp + z1 * cp, i, bx, by });
    }
    projected.sort((p, q) => p.z - q.z);

    const scanHead = t * 3.2;
    for (const p of projected) {
      const depth = (p.z + 1.2) / 2.4;
      const f = 3.4 / (3.4 - p.z * 0.9);
      const px = cx + p.x * R * f;
      const py = cy + p.y * R * f;
      let alpha = 0.2 + 0.62 * depth;
      let size = 0.75 + 1.15 * depth;
      switch (this.lamp) {
        case 'off':
          alpha *= 0.55;
          break;
        case 'probe': {
          // A bright arc sweeping the ring; under reduced motion one still frame, with the arc at rest.
          const theta = Math.atan2(p.by, p.bx);
          const d = (((scanHead - theta) % TAU) + TAU) % TAU;
          alpha *= d < 1.3 ? 1 - (d / 1.3) * 0.7 : 0.32;
          size += d < 1.3 ? 0.7 : 0;
          break;
        }
        case 'ok':
          alpha *= still ? 1 : 0.8 + 0.2 * Math.sin(t * 2 + p.i);
          break;
        case 'warn':
          // One hemisphere lit; its edge flickers.
          alpha *= p.x < 0 ? 1 : 0.2;
          if (p.x < 0 && !still && (p.i + Math.floor(t * 6)) % 13 === 0) alpha *= 0.25;
          break;
        case 'fail':
          // A cube with dropouts.
          if (p.i % 9 === 0) alpha *= still ? 0.3 : 0.15 + 0.5 * hash(p.i + Math.floor(t * 5));
          break;
      }
      ctx.globalAlpha = Math.max(0, Math.min(1, alpha));
      ctx.fillStyle = lamp;
      ctx.beginPath();
      ctx.arc(px, py, size, 0, TAU);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    this.recordCost(performance.now() - started);
  }

  private drawBeams(t: number, still: boolean, lamp: string, cx: number, cy: number, R: number): void {
    const { ctx } = this;
    const c = this.colors;
    const slots = slotsFor(this.width, this.height);
    this.roles.forEach((role, i) => {
      const s = slots[i];
      if (!s) return;
      const dxs = cx - s.x;
      const dys = cy - s.y;
      const dist = Math.hypot(dxs, dys) || 1;
      const ux = dxs / dist;
      const uy = dys / dist;
      const x0 = s.x + (s.x < cx ? 4 : -4);
      const y0 = s.y;
      const x1 = cx - ux * R * 1.28;
      const y1 = cy - uy * R * 1.28;
      const len = Math.hypot(x1 - x0, y1 - y0);
      const count = Math.max(6, Math.floor(len / 7));
      const probing = this.lamp === 'probe';
      const carry = role === 'carry';
      const poor = carry && this.lamp === 'warn';
      ctx.fillStyle = carry ? lamp : probing && role === 'avail' ? c.probe : c.text3;
      for (let k = 0; k < count; k += 1) {
        let u = k / count;
        // Dots travel toward the core only on the network that is carrying traffic.
        if (carry && !still) u = (u + t * (poor ? 0.12 : 0.28)) % 1;
        if (probing && !still) u = (u + t * 0.35 + i * 0.3) % 1;
        if (role === 'lost' && k % 3) continue;
        if (role === 'avail' && !probing && k % 2) continue;
        if (role === 'standby' && k % 2) continue;
        // A ragged beam: loss, drawn.
        if (poor && hash(k + Math.floor(t * 4)) < 0.35) continue;
        const px = x0 + (x1 - x0) * u;
        const py = y0 + (y1 - y0) * u + (poor && !still ? (hash(k * 7 + Math.floor(t * 8)) - 0.5) * 6 : 0);
        ctx.globalAlpha = carry ? 0.35 + 0.65 * Math.sin(Math.PI * u) : role === 'lost' ? 0.25 : 0.4;
        ctx.beginPath();
        ctx.arc(px, py, carry ? 2.1 : 1.5, 0, TAU);
        ctx.fill();
      }
    });
    ctx.globalAlpha = 1;
  }
}
