/**
 * The view-models the Rust side sends the window (ADR-0007 R4). The web view never sees the control pipe or
 * a protocol frame: it sees these, already decoded and checked by the typed protocol, in camelCase.
 *
 * They are still parsed here (`parseSnapshot`): the boundary between two processes is a place for a check,
 * and a snapshot that contradicts itself must not be drawn as though it were true. Every string is passed
 * through `plain` on the way in, so no component has to remember to.
 */
import { plain } from './sanitize';

export type Status = 'Disconnected' | 'Probing' | 'Connected' | 'Failed';
export type Tier = 'Tier1' | 'Tier2';
export type Lamp = 'off' | 'probe' | 'ok' | 'warn' | 'fail';

/** The seven distinguishable causes (FR-039, SC-020). There is no `Unknown`, and there must not be. */
export const FAILURE_CAUSES = [
  'NoEndpointReachable',
  'AllProfilesBlocked',
  'CaptivePortalUnsatisfied',
  'InsufficientPrivilege',
  'CoreFailedPersistently',
  'NoUsablePath',
  'ConfigurationInvalid',
] as const;
export type FailureCause = (typeof FAILURE_CAUSES)[number];

export const WARNINGS = ['Tier2ProfileActive', 'BrutalEnabled', 'EncryptedDnsOverridden'] as const;
export type Warning = (typeof WARNINGS)[number];

export type PathKind = 'Wifi' | 'Cellular' | 'Ethernet' | 'Other';
export type PathRole = 'Carrying' | 'Standby' | 'Unusable';

export interface PathView {
  id: string;
  kind: PathKind;
  /** Cleaned. `null` when Windows would not say (location access) or the kind has no name. */
  name: string | null;
  role: PathRole;
  /** False means nothing below may be read as fine. */
  measured: boolean;
  rttMs: number | null;
  jitterMs: number | null;
  /** A fraction from 0 to 1. */
  loss: number | null;
  traceMs: (number | null)[];
  typicalMs: [number, number] | null;
}

export interface Degraded {
  path: string;
  quality: 'Poor' | 'Unusable';
  staying: 'OnlyPath' | 'NoBetterPath' | 'Proving' | 'Dwell' | 'Budget';
}

export interface PathsView {
  /** When this was true, by the service's clock. Never shown as current without this. */
  asOfMs: number;
  /** False: nothing is connected, so nothing is being looked at. An empty list then means "not looking". */
  watching: boolean;
  paths: PathView[];
  degraded: Degraded | null;
}

export type StatsView =
  | { connected: false }
  | {
      connected: true;
      connectedForS: number;
      networkChanges: number;
      changesThatDropConnections: number;
      methodSwitches: number;
      endpointSwitches: number;
      degradedPeriods: number;
      longestDegradedS: number;
    };

export interface ProfileRef {
  id: string;
  kind: 'AmneziaWg' | 'Hysteria2' | 'VlessReality';
  tier: Tier;
}

export interface Snapshot {
  status: Status;
  activeProfile: ProfileRef | null;
  activeEndpoint: { id: string; label: string } | null;
  failure: { cause: FailureCause; title: string; detail: string; action: string } | null;
  warnings: Warning[];
  posture: { kind: 'Tunnelled'; tier: Tier } | { kind: 'FailClosed' };
  paths: PathsView;
  stats: StatsView;
  /** The `because` of the latest thing the service did, in its words. */
  lastBecause: string | null;
  /** The window's own clock when the snapshot arrived, to age it. */
  receivedAtMs: number;
}

export class ModelError extends Error {}

// ------------------------------------------------------------------ small readers

type Json = Record<string, unknown>;

function obj(value: unknown, what: string): Json {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ModelError(`${what} must be an object`);
  }
  return value as Json;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], what: string): T {
  if (typeof value === 'string' && (allowed as readonly string[]).includes(value)) return value as T;
  throw new ModelError(`${what} is not one of the values this window knows`);
}

function text(value: unknown, what: string, max = 200): string {
  if (typeof value !== 'string') throw new ModelError(`${what} must be text`);
  return plain(value, max);
}

function optionalText(value: unknown, what: string, max = 200): string | null {
  return value === null || value === undefined ? null : text(value, what, max);
}

function num(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new ModelError(`${what} must be a number`);
  return value;
}

function optionalNum(value: unknown, what: string): number | null {
  return value === null || value === undefined ? null : num(value, what);
}

function list(value: unknown, what: string, max: number): unknown[] {
  if (!Array.isArray(value)) throw new ModelError(`${what} must be a list`);
  if (value.length > max) throw new ModelError(`${what} is longer than any real one`);
  return value;
}

// ------------------------------------------------------------------ parsing

function parsePath(value: unknown): PathView {
  const o = obj(value, 'a network');
  const measured = o.measured === true;
  const view: PathView = {
    id: text(o.id, 'a network id', 24),
    kind: oneOf(o.kind, ['Wifi', 'Cellular', 'Ethernet', 'Other'] as const, 'a network kind'),
    name: optionalText(o.name, 'a network name', 64),
    role: oneOf(o.role, ['Carrying', 'Standby', 'Unusable'] as const, 'a network role'),
    measured,
    rttMs: optionalNum(o.rttMs, 'latency'),
    jitterMs: optionalNum(o.jitterMs, 'jitter'),
    loss: optionalNum(o.loss, 'loss'),
    traceMs: list(o.traceMs ?? [], 'a trace', 64).map((p) => optionalNum(p, 'a trace point')),
    typicalMs: null,
  };
  const typical = o.typicalMs;
  if (typical !== null && typical !== undefined) {
    const pair = list(typical, 'a typical range', 2);
    if (pair.length === 2) view.typicalMs = [num(pair[0], 'typical'), num(pair[1], 'typical')];
  }
  // A network that was not measured claims no figure: a snapshot that says otherwise is refused, as the
  // service's own decoder refuses it, so an unmeasured network can never be drawn as healthy.
  if (!measured && (view.rttMs !== null || view.jitterMs !== null || view.loss !== null)) {
    throw new ModelError('a network that was not measured carries a figure');
  }
  if (view.loss !== null && (view.loss < 0 || view.loss > 1)) throw new ModelError('loss is outside 0 to 1');
  return view;
}

function parsePaths(value: unknown): PathsView {
  const o = obj(value, 'the networks');
  const paths = list(o.paths, 'the networks', 32).map(parsePath);
  if (paths.filter((p) => p.role === 'Carrying').length > 1) {
    throw new ModelError('more than one network is carrying (aggregation is not in v1)');
  }
  let degraded: Degraded | null = null;
  if (o.degraded !== null && o.degraded !== undefined) {
    const d = obj(o.degraded, 'the degradation');
    degraded = {
      path: text(d.path, 'a network id', 24),
      quality: oneOf(d.quality, ['Poor', 'Unusable'] as const, 'a quality'),
      staying: oneOf(d.staying, ['OnlyPath', 'NoBetterPath', 'Proving', 'Dwell', 'Budget'] as const, 'a reason'),
    };
  }
  return { asOfMs: num(o.asOfMs, 'the time of the reading'), watching: o.watching === true, paths, degraded };
}

function parseStats(value: unknown): StatsView {
  const o = obj(value, 'the counts');
  if (o.connected !== true) return { connected: false };
  return {
    connected: true,
    connectedForS: num(o.connectedForS, 'time connected'),
    networkChanges: num(o.networkChanges, 'network changes'),
    changesThatDropConnections: num(o.changesThatDropConnections, 'changes that drop connections'),
    methodSwitches: num(o.methodSwitches, 'method switches'),
    endpointSwitches: num(o.endpointSwitches, 'endpoint switches'),
    degradedPeriods: num(o.degradedPeriods, 'poor spells'),
    longestDegradedS: num(o.longestDegradedS, 'the longest poor spell'),
  };
}

/** Parse and check a snapshot. Throws `ModelError` for one that is malformed or contradicts itself. */
export function parseSnapshot(value: unknown, receivedAtMs: number): Snapshot {
  const o = obj(value, 'the state');
  const status = oneOf(o.status, ['Disconnected', 'Probing', 'Connected', 'Failed'] as const, 'the status');

  let activeProfile: ProfileRef | null = null;
  if (o.activeProfile !== null && o.activeProfile !== undefined) {
    const p = obj(o.activeProfile, 'the profile');
    activeProfile = {
      id: text(p.id, 'a profile id', 64),
      kind: oneOf(p.kind, ['AmneziaWg', 'Hysteria2', 'VlessReality'] as const, 'a profile kind'),
      tier: oneOf(p.tier, ['Tier1', 'Tier2'] as const, 'a tier'),
    };
  }
  let activeEndpoint: Snapshot['activeEndpoint'] = null;
  if (o.activeEndpoint !== null && o.activeEndpoint !== undefined) {
    const e = obj(o.activeEndpoint, 'the endpoint');
    activeEndpoint = { id: text(e.id, 'an endpoint id', 64), label: text(e.label, 'an endpoint label', 64) };
  }
  let failure: Snapshot['failure'] = null;
  if (o.failure !== null && o.failure !== undefined) {
    const f = obj(o.failure, 'the failure');
    failure = {
      cause: oneOf(f.cause, FAILURE_CAUSES, 'a failure cause'),
      title: text(f.title, 'a failure title', 200),
      detail: text(f.detail, 'a failure detail', 600),
      action: text(f.action, 'a failure action', 400),
    };
  }
  const posture = obj(o.posture, 'the posture');
  const parsedPosture: Snapshot['posture'] =
    posture.kind === 'Tunnelled'
      ? { kind: 'Tunnelled', tier: oneOf(posture.tier, ['Tier1', 'Tier2'] as const, 'a tier') }
      : { kind: 'FailClosed' };

  // The service's own consistency rules, applied again at this boundary (IPC-11): a snapshot that
  // contradicts itself must not be drawn as though it were true.
  if (status === 'Connected' && (activeProfile === null || activeEndpoint === null)) {
    throw new ModelError('connected, with nothing carrying');
  }
  if (status !== 'Connected' && (activeProfile !== null || activeEndpoint !== null)) {
    throw new ModelError('something is carrying while not connected');
  }
  if (status === 'Failed' && failure === null) throw new ModelError('failed, with no cause');
  if (status !== 'Failed' && failure !== null) throw new ModelError('a cause, but not failed');
  if (status === 'Connected' && parsedPosture.kind !== 'Tunnelled') throw new ModelError('connected, but fail-closed');
  if (status !== 'Connected' && parsedPosture.kind === 'Tunnelled') throw new ModelError('tunnelled, but not connected');
  if (activeProfile && parsedPosture.kind === 'Tunnelled' && parsedPosture.tier !== activeProfile.tier) {
    throw new ModelError('the posture and the profile disagree about the tier');
  }

  return {
    status,
    activeProfile,
    activeEndpoint,
    failure,
    warnings: list(o.warnings ?? [], 'the warnings', 8).map((w) => oneOf(w, WARNINGS, 'a warning')),
    posture: parsedPosture,
    paths: parsePaths(o.paths),
    stats: parseStats(o.stats),
    lastBecause: optionalText(o.lastBecause, 'the latest reason', 400),
    receivedAtMs,
  };
}

// ------------------------------------------------------------------ the other lists

export interface EndpointView {
  id: string;
  label: string;
  address: string;
  enabled: boolean;
  health: 'Unknown' | 'Healthy' | 'Degraded' | 'Unreachable';
}

export function parseEndpoints(value: unknown): EndpointView[] {
  const o = obj(value, 'the endpoints');
  return list(o.endpoints, 'the endpoints', 64).map((item) => {
    const e = obj(item, 'an endpoint');
    return {
      id: text(e.id, 'an endpoint id', 64),
      label: text(e.label, 'an endpoint label', 64),
      address: text(e.address, 'an address', 260),
      enabled: e.enabled === true,
      health: oneOf(e.health, ['Unknown', 'Healthy', 'Degraded', 'Unreachable'] as const, 'a health'),
    };
  });
}

export const RULE_KINDS = ['domain', 'domain_suffix', 'ip_cidr', 'application', 'dns_port', 'encrypted_dns_port'] as const;
export type RuleKind = (typeof RULE_KINDS)[number];

export interface RuleView {
  id: string;
  /** What the rule matches, and the name, range, program or port it matches. */
  kind: RuleKind;
  value: string;
  /** Position in the precedence order; lower is stronger. */
  precedence: number;
  action: string;
  /** Domain and address rules are reliable; application rules are best-effort (Principle VI). */
  reliability: 'Deterministic' | 'BestEffort';
  /** A built-in rule cannot be removed; it is shown so the person can see why local things keep working. */
  builtin: boolean;
}

export interface EncryptedDnsSetting {
  /** True: programs' own encrypted name lookups are blocked (the default). */
  block: boolean;
  /** True until the first-run disclosure has been shown and answered. */
  needsDisclosure: boolean;
}

/** One connection method: its kind, its tier (measured, never intended) and whether Brutal is on. */
export interface ProfileView {
  id: string;
  kind: 'AmneziaWg' | 'Hysteria2' | 'VlessReality';
  tier: 'Tier1' | 'Tier2';
  brutal: boolean;
}

export function parseProfiles(value: unknown): ProfileView[] {
  const o = obj(value, 'the connection methods');
  return list(o.profiles, 'the connection methods', 16).map((item) => {
    const p = obj(item, 'a connection method');
    return {
      id: text(p.id, 'a connection method id', 64),
      kind: oneOf(p.kind, ['AmneziaWg', 'Hysteria2', 'VlessReality'] as const, 'a connection method kind'),
      tier: oneOf(p.tier, ['Tier1', 'Tier2'] as const, 'a tier'),
      brutal: p.brutal === true,
    };
  });
}

export interface RulesView {
  rules: RuleView[];
  encryptedDns: EncryptedDnsSetting;
}

/** The rules reply: the rule list, and the encrypted-DNS choice that rides with it. */
export function parseRulesReply(value: unknown): RulesView {
  const o = obj(value, 'the rules');
  const dns = obj(o.encrypted_dns ?? o.encryptedDns, 'the encrypted-name setting');
  return {
    rules: parseRules(value),
    encryptedDns: {
      block: dns.block === true,
      needsDisclosure: (dns.needs_disclosure ?? dns.needsDisclosure) === true,
    },
  };
}

export function parseRules(value: unknown): RuleView[] {
  const o = obj(value, 'the rules');
  return list(o.rules, 'the rules', 512).map((item) => {
    const r = obj(item, 'a rule');
    return {
      id: text(r.id, 'a rule id', 64),
      kind: oneOf(r.kind, RULE_KINDS, 'what a rule matches'),
      value: text(r.value, 'what a rule matches', 260),
      precedence: num(r.precedence, 'a precedence'),
      action: text(r.action, 'an action', 32),
      reliability: oneOf(r.reliability, ['Deterministic', 'BestEffort'] as const, 'a reliability'),
      builtin: r.builtin === true,
    };
  });
}

// ------------------------------------------------------------------ the map of parts (T170)

export const COMPONENT_KINDS = [
  'NetworkPath', 'CarrierLeaf', 'Session', 'Endpoint', 'CoreProcess', 'Adapter', 'Routes', 'DnsHandling', 'Guard', 'CaptivePortal',
] as const;
export type ComponentKind = (typeof COMPONENT_KINDS)[number];

export const COMPONENT_STATES = ['Unknown', 'Off', 'Starting', 'Ok', 'Degraded', 'Blocked', 'Failed'] as const;
export type ComponentState = (typeof COMPONENT_STATES)[number];

/** One part of the system: its state, why, how long it has been so, and what was measured (if anything was). */
export interface ComponentView {
  kind: ComponentKind;
  id: string;
  state: ComponentState;
  /** The part's own account, whole. */
  reason: string;
  ageSeconds: number;
  /** A measurement that was not taken is null, never zero. */
  latencyMs: number | null;
  lossPermille: number | null;
  restarts: number | null;
}

export interface ComponentsView {
  /** False for a service too old to know the request: the window says so and does not imply "no parts" or "fine". */
  supported: boolean;
  overall: ComponentState;
  parts: ComponentView[];
}

export function parseComponents(value: unknown): ComponentsView {
  const o = obj(value, 'the parts');
  const supported = o.supported === true;
  const overall = oneOf(o.overall, COMPONENT_STATES, 'the overall state');
  const parts = list(o.parts, 'the parts', 128).map((item) => {
    const p = obj(item, 'a part');
    const age = num(p.ageSeconds, 'an age');
    if (age < 0) throw new ModelError('an age is negative');
    const loss = optionalNum(p.lossPermille, 'a loss');
    if (loss !== null && (loss < 0 || loss > 1000)) throw new ModelError('a loss is out of range');
    return {
      kind: oneOf(p.kind, COMPONENT_KINDS, 'a part kind'),
      id: text(p.id, 'a part id', 64),
      state: oneOf(p.state, COMPONENT_STATES, 'a part state'),
      reason: text(p.reason, 'a reason', 512),
      ageSeconds: age,
      latencyMs: optionalNum(p.latencyMs, 'a latency'),
      lossPermille: loss,
      restarts: optionalNum(p.restarts, 'a restart count'),
    };
  });
  if (!supported && parts.length > 0) throw new ModelError('a service that cannot list parts listed some');
  return { supported, overall, parts };
}

/** Whether the kill switch is on and whether a guard is in the firewall now (T161). */
export interface GuardView {
  /** False for a service too old to know the question; then nothing else here is claimed. */
  supported: boolean;
  killSwitch: boolean;
  /** `null` is "the firewall could not be asked", which is not the same as "no guard is in". */
  guardIn: boolean | null;
}

export function parseGuard(value: unknown): GuardView {
  const o = obj(value, 'the kill switch');
  if (typeof o.supported !== 'boolean') throw new ModelError('the kill switch did not say whether it is supported');
  if (typeof o.killSwitch !== 'boolean') throw new ModelError('the kill switch did not say whether it is on');
  if (o.guardIn !== null && typeof o.guardIn !== 'boolean') throw new ModelError('the kill switch did not say whether a guard is in');
  if (!o.supported && (o.killSwitch || o.guardIn !== null)) throw new ModelError('a service that cannot say claimed something');
  return { supported: o.supported, killSwitch: o.killSwitch, guardIn: o.guardIn };
}

/** One line of the Activity view: something the service did, and why (principle 3). */
export interface ActivityItem {
  seq: number | null;
  event: string;
  because: string;
  /** Milliseconds, by the window's clock when it arrived. */
  atMs: number;
}

export function parseActivity(value: unknown, atMs: number): ActivityItem {
  const o = obj(value, 'an event');
  const seq = o.seq === undefined || o.seq === null ? null : num(o.seq, 'a sequence number');
  return { seq, event: text(o.event, 'an event name', 48), because: text(o.because, 'a reason', 400), atMs };
}

/** A change that redirects traffic and waits for the person to approve it (T160): what it would do, and until when. */
export interface PendingView {
  /** Names the change; it is not a secret, because approving needs the Windows prompt and not the name. */
  id: string;
  /** In the service's own words: for example the server's name and address. */
  what: string;
  /** When it is dropped if nobody approves it, in milliseconds since 1970. */
  expiresUnixMs: number;
}

export function parsePending(value: unknown): PendingView[] {
  const o = obj(value, 'the waiting changes');
  return list(o.pending, 'the waiting changes', 16).map((item) => {
    const p = obj(item, 'a waiting change');
    return {
      id: text(p.id, 'a change id', 32),
      what: text(p.what, 'what a change does', 400),
      expiresUnixMs: num(p.expiresUnixMs, 'a deadline'),
    };
  });
}
