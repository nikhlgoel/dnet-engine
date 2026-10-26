/**
 * What the window says and draws for a snapshot. Pure functions, no DOM: the state is decided by the service
 * (principle 7: the app shows, it does not compute), and this only turns it into words and a form.
 *
 * Nothing here invents a figure. A word, a number or a role on screen comes from the snapshot or from the
 * service's own `because` (principle: no claim without a source, design-system §17 rule 5).
 */
import { en, fill, plural } from './messages';
import type { FailureCause, Lamp, PathView, Snapshot } from './model';

/** The figure at the centre: its form is the state (design-system §5). */
export type Shape = 'ring' | 'sphere' | 'cube';

export type ActionId =
  | 'open-login'
  | 'open-endpoints'
  | 'retry'
  | 'open-activity'
  | 'show-networks'
  | 'grant-rights';

export interface Look {
  lamp: Lamp;
  shape: Shape;
  headline: string;
  because: string;
  /** What the service says to do about a failure, in its words: a sentence of advice, not a button label. */
  advice: string;
  /** A short line of facts: method, tier, network. Empty when nothing is carrying. */
  facts: string;
  switch: { on: boolean; busy: boolean; word: string };
  action: { id: ActionId; label: string } | null;
  /** What a screen reader hears when the state changes. */
  announcement: string;
  /** A failure interrupts; everything else waits its turn (design-system §15, 4.1.3). */
  assertive: boolean;
}

/** The button's label for each action: the window's own words, short, with a verb (design-system §14). */
export const ACTION_LABEL: Record<ActionId, string> = {
  'open-login': en.actions.openLogin,
  'open-endpoints': en.actions.checkEndpoints,
  retry: en.actions.retry,
  'open-activity': en.actions.viewDiagnostics,
  'show-networks': en.actions.showAdapters,
  'grant-rights': en.actions.grantRights,
};

/** What each failure cause offers as its one action (design-system §14). */
export const ACTION_FOR_CAUSE: Record<FailureCause, ActionId> = {
  NoEndpointReachable: 'open-endpoints',
  AllProfilesBlocked: 'retry',
  CaptivePortalUnsatisfied: 'open-login',
  InsufficientPrivilege: 'grant-rights',
  CoreFailedPersistently: 'open-activity',
  NoUsablePath: 'show-networks',
  ConfigurationInvalid: 'open-endpoints',
};

export function networkTitle(path: PathView): string {
  return path.name ?? en.network[path.kind];
}

function carryingPath(s: Snapshot): PathView | undefined {
  return s.paths.paths.find((p) => p.role === 'Carrying');
}

function tierWord(tier: 'Tier1' | 'Tier2'): string {
  return tier === 'Tier1' ? en.facts.tier1 : en.facts.tier2;
}

function degradedBecause(s: Snapshot, network: string): string {
  switch (s.paths.degraded?.staying) {
    case 'OnlyPath':
      return fill(en.because.warnOnlyPath, { network });
    case 'NoBetterPath':
      return fill(en.because.warnNoBetter, { network });
    case 'Proving':
      return en.because.warnProving;
    case 'Dwell':
      return en.because.warnDwell;
    case 'Budget':
      return en.because.warnBudget;
    default:
      return fill(en.because.warn, { network });
  }
}

export function look(s: Snapshot): Look {
  switch (s.status) {
    case 'Disconnected':
      return {
        lamp: 'off',
        shape: 'ring',
        headline: en.state.off,
        because: s.lastBecause ?? en.because.off,
        advice: '',
        facts: '',
        switch: { on: false, busy: false, word: en.switch.off },
        action: null,
        announcement: `${en.state.off}. ${en.because.off}`,
        assertive: false,
      };
    case 'Probing':
      return {
        lamp: 'probe',
        shape: 'ring',
        headline: en.state.probe,
        because: s.lastBecause ?? en.because.probe,
        advice: '',
        facts: '',
        switch: { on: true, busy: true, word: en.switch.busy },
        action: null,
        announcement: `${en.state.probe}. ${s.lastBecause ?? en.because.probe}`,
        assertive: false,
      };
    case 'Connected': {
      const path = carryingPath(s);
      const method = en.method[s.activeProfile?.kind ?? 'Hysteria2'];
      const tier = s.activeProfile ? tierWord(s.activeProfile.tier) : '';
      const network = path ? networkTitle(path) : null;
      const degraded = s.paths.degraded !== null;
      const headline = degraded ? en.state.warn : en.state.ok;
      const fallback = degraded
        ? degradedBecause(s, network ?? en.network.Other)
        : network
          ? fill(en.because.ok, { network, endpoint: s.activeEndpoint?.label ?? '', method })
          : fill(en.because.okNoNetwork, { endpoint: s.activeEndpoint?.label ?? '', method });
      const because = s.lastBecause ?? fallback;
      return {
        lamp: degraded ? 'warn' : 'ok',
        shape: 'sphere',
        headline,
        because,
        advice: '',
        facts: network
          ? fill(en.facts.via, { method, tier, network })
          : fill(en.facts.line, { method, tier }),
        switch: { on: true, busy: false, word: en.switch.on },
        action: null,
        announcement: `${headline}. ${because}`,
        assertive: false,
      };
    }
    case 'Failed': {
      const failure = s.failure;
      // `parseSnapshot` refuses a failed state with no cause; this is for a caller that did not parse.
      const cause: FailureCause = failure?.cause ?? 'ConfigurationInvalid';
      const headline = failure?.title ?? en.state.off;
      const because = failure?.detail ?? '';
      const advice = failure?.action ?? '';
      return {
        lamp: 'fail',
        shape: 'cube',
        headline,
        because,
        advice,
        facts: '',
        switch: { on: false, busy: false, word: en.switch.off },
        action: failure ? { id: ACTION_FOR_CAUSE[cause], label: ACTION_LABEL[ACTION_FOR_CAUSE[cause]] } : null,
        announcement: [headline, because, advice].filter((part) => part !== '').join('. '),
        assertive: true,
      };
    }
  }
}

// ------------------------------------------------------------------ the networks

export type ChipRole = 'carry' | 'standby' | 'avail' | 'lost';

export interface Chip {
  id: string;
  title: string;
  kind: PathView['kind'];
  role: ChipRole;
  roleText: string;
  metrics: string;
}

/** Which role to draw: with nothing connected, a usable network is merely available (it is not standing by). */
export function chipRole(path: PathView, status: Snapshot['status']): ChipRole {
  if (path.role === 'Unusable') return 'lost';
  if (status !== 'Connected') return 'avail';
  return path.role === 'Carrying' ? 'carry' : 'standby';
}

export function formatMs(value: number | null): string {
  return value === null ? '—' : String(Math.round(value));
}

export function formatLoss(loss: number | null): string {
  return loss === null ? '—' : String(Math.round(loss * 100));
}

export function chips(s: Snapshot): Chip[] {
  // Up to four chips fit; the rest are in the drawer (design-system §6).
  return s.paths.paths.slice(0, 4).map((p): Chip => {
    const role = chipRole(p, s.status);
    const roleText =
      role === 'carry' ? en.role.Carrying : role === 'standby' ? en.role.Standby : role === 'lost' ? en.role.Unusable : en.role.Available;
    const metrics =
      role === 'lost'
        ? en.metrics.unavailable
        : p.measured
          ? fill(en.metrics.measured, { rtt: formatMs(p.rttMs), loss: formatLoss(p.loss) })
          : en.metrics.notMeasured;
    return { id: p.id, title: networkTitle(p), kind: p.kind, role, roleText, metrics };
  });
}

// ------------------------------------------------------------------ the heartbeat

/** After this long without a reading the window says "last update", and the figure freezes (§12). */
export const STALE_AFTER_S = 15;

export interface Freshness {
  live: boolean;
  text: string;
}

export function freshness(s: Snapshot | null, nowMs: number): Freshness {
  if (s === null) return { live: false, text: en.heartbeat.none };
  const seconds = Math.max(0, Math.round((nowMs - s.receivedAtMs) / 1000));
  return seconds > STALE_AFTER_S
    ? { live: false, text: fill(en.heartbeat.stale, { seconds }) }
    : { live: true, text: fill(en.heartbeat.live, { seconds }) };
}

// ------------------------------------------------------------------ the strip

export interface Cell {
  key: 'latency' | 'jitter' | 'loss' | 'stability';
  label: string;
  value: string;
  unit: string;
  context: string;
  trace: (number | null)[];
  /** True when there is no measurement, so the value must not read as fine. */
  none: boolean;
  /** The accessible name: states the meaning, not the decoration. */
  name: string;
}

function typicalLine(path: PathView): string {
  return path.typicalMs
    ? fill(en.instruments.typical, { low: Math.round(path.typicalMs[0]), high: Math.round(path.typicalMs[1]) })
    : '';
}

export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h} h ${String(m).padStart(2, '0')} m`;
  if (m > 0) return `${m} m ${String(s % 60).padStart(2, '0')} s`;
  return `${s} s`;
}

export function strip(s: Snapshot): Cell[] {
  const path = s.status === 'Connected' ? carryingPath(s) : undefined;
  const measured = path !== undefined && path.measured;
  const none = en.instruments.none;

  const numeric = (
    key: Cell['key'],
    label: string,
    unit: string,
    value: number | null,
    show: (n: number) => string,
    context: string,
  ): Cell => {
    const has = measured && value !== null;
    const shown = has ? show(value) : '—';
    return {
      key,
      label,
      value: shown,
      unit: has ? unit : '',
      context: has ? context : none,
      trace: has && path ? path.traceMs : [],
      none: !has,
      name: has ? `${label} ${shown} ${unit === 'ms' ? 'milliseconds' : 'percent'}${context ? `, ${context}` : ''}` : `${label}: ${none}`,
    };
  };

  const stats = s.stats;
  const poor = stats.connected ? stats.degradedPeriods : 0;
  const stability: Cell = stats.connected
    ? {
        key: 'stability',
        label: en.instruments.stability,
        value: plural(en.instruments.poorSpells, poor),
        unit: '',
        context: fill(en.instruments.session, {
          duration: formatDuration(stats.connectedForS),
          changes: plural(en.instruments.changes, stats.networkChanges),
        }),
        trace: [],
        none: false,
        name: `${en.instruments.stability}: ${plural(en.instruments.poorSpells, poor)}`,
      }
    : {
        key: 'stability',
        label: en.instruments.stability,
        value: '—',
        unit: '',
        context: none,
        trace: [],
        none: true,
        name: `${en.instruments.stability}: ${none}`,
      };

  return [
    numeric('latency', en.instruments.latency, 'ms', path?.rttMs ?? null, (n) => String(Math.round(n)), path ? typicalLine(path) : ''),
    numeric('jitter', en.instruments.jitter, 'ms', path?.jitterMs ?? null, (n) => String(Math.round(n)), ''),
    numeric('loss', en.instruments.loss, '%', path?.loss ?? null, (n) => String(Math.round(n * 100)), ''),
    stability,
  ];
}
