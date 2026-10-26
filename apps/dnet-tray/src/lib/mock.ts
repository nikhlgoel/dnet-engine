/**
 * A stand-in for the service, with every state the real one can be in. It is how the window is developed
 * (no service, no elevation), how it is tested, and how the design is reviewed in a plain browser tab. Its
 * snapshots are built to the same shape and the same consistency rules the real ones obey, and they go through
 * `parseSnapshot` like the real ones, so a mock that drew something the real service cannot say would fail.
 */
import type { Bridge, Capabilities, NewEndpointInput, Outcome } from './bridge';
import type {
  ActivityItem,
  EncryptedDnsSetting,
  EndpointView,
  FailureCause,
  PathView,
  RuleView,
  RulesView,
  Snapshot,
} from './model';
import { parseSnapshot } from './model';

export type MockState = 'off' | 'probe' | 'ok' | 'warn' | 'fail';
export type MockNetworks = 'one' | 'two' | 'three';

/** What each failure says, in the words the service would send (title, detail, action). */
export const MOCK_FAILURES: Record<FailureCause, { title: string; detail: string; action: string }> = {
  NoEndpointReachable: {
    title: 'None of your endpoints are reachable.',
    detail: 'DNet Engine tried every endpoint you have added and none answered.',
    action: 'Check that the endpoint server is running and that this network allows connections to it, or add another endpoint.',
  },
  AllProfilesBlocked: {
    title: 'This network is blocking every connection method.',
    detail: 'All three methods were tried and none got through.',
    action: 'Try a different network, such as mobile data, or check for an update that adds a method this network does not recognise.',
  },
  CaptivePortalUnsatisfied: {
    title: 'This network needs you to log in first.',
    detail: 'It is asking for a sign-in page before it lets anything out.',
    action: 'Open a browser, complete the network’s sign-in page, then connect again.',
  },
  InsufficientPrivilege: {
    title: 'DNet Engine needs administrator rights.',
    detail: 'Its background service is not running with the permission it needs.',
    action: 'Start the DNet Engine service as the system or as an administrator, then try again.',
  },
  CoreFailedPersistently: {
    title: 'A component keeps failing to start.',
    detail: 'It stopped 5 times in a row, so DNet Engine has given up on it for now.',
    action: 'Open the activity list to read what it last said, then restart the service.',
  },
  NoUsablePath: {
    title: 'No usable network connection.',
    detail: 'This computer has no network that can reach the internet.',
    action: 'Connect to a network, then try again.',
  },
  ConfigurationInvalid: {
    title: 'Configuration is invalid: the endpoint address is empty.',
    detail: 'Nothing was changed on this computer.',
    action: 'Check the endpoint’s address and connection details, or add the endpoint again.',
  },
};

const WIFI = { id: '7', kind: 'Wifi', name: 'Hostel-5G' } as const;
const PHONE = { id: '9', kind: 'Cellular', name: 'Pixel 8 · USB' } as const;
const CABLE = { id: '4', kind: 'Ethernet', name: null } as const;

function trace(seed: number, bad: boolean): (number | null)[] {
  let x = seed;
  return Array.from({ length: 40 }, (_, i) => {
    x = (x * 1664525 + 1013904223) % 4294967296;
    const n = x / 4294967296;
    if (bad && n < 0.15) return null;
    return bad ? 120 + n * 200 : 38 + n * 10 + Math.sin(i / 4) * 4;
  });
}

function measured(base: Pick<PathView, 'id' | 'kind' | 'name'>, role: PathView['role'], rtt: number, jitter: number, loss: number, bad: boolean): PathView {
  return {
    ...base,
    role,
    measured: true,
    rttMs: rtt,
    jitterMs: jitter,
    loss,
    traceMs: trace(Number(base.id) * 31 + (bad ? 1 : 0), bad),
    typicalMs: bad ? [40, 48] : [38, 52],
  };
}

function unmeasured(base: Pick<PathView, 'id' | 'kind' | 'name'>, role: PathView['role']): PathView {
  return { ...base, role, measured: false, rttMs: null, jitterMs: null, loss: null, traceMs: [], typicalMs: null };
}

export interface Scenario {
  state: MockState;
  networks: MockNetworks;
  cause: FailureCause;
}

/** A raw snapshot, as the Rust side would send it, for `scenario`. */
export function rawSnapshot(sc: Scenario, nowMs: number): unknown {
  const live = sc.state === 'ok' || sc.state === 'warn';
  const bad = sc.state === 'warn';
  const paths: PathView[] = [];
  const add = (base: Pick<PathView, 'id' | 'kind' | 'name'>, carrying: boolean, standby: boolean, lost: boolean): void => {
    if (lost) paths.push(unmeasured(base, 'Unusable'));
    else if (!live) paths.push(unmeasured(base, 'Standby'));
    else if (carrying) paths.push(measured(base, 'Carrying', bad ? 212 : 43, bad ? 38 : 4, bad ? 0.18 : 0.02, bad));
    else if (standby) paths.push(measured(base, 'Standby', 88, 6, 0, false));
  };
  if (sc.state === 'fail' && sc.cause === 'NoUsablePath') add(WIFI, false, false, true);
  else {
    add(WIFI, true, false, false);
    if (sc.networks !== 'one') add(PHONE, false, true, false);
    if (sc.networks === 'three') add(CABLE, false, false, true);
  }
  const f = MOCK_FAILURES[sc.cause];
  const status = { off: 'Disconnected', probe: 'Probing', ok: 'Connected', warn: 'Connected', fail: 'Failed' }[sc.state];
  return {
    status,
    activeProfile: live ? { id: 'hy2-default', kind: 'Hysteria2', tier: 'Tier2' } : null,
    activeEndpoint: live ? { id: 'e1', label: 'endpoint-1' } : null,
    failure: sc.state === 'fail' ? { cause: sc.cause, ...f } : null,
    warnings: live ? ['Tier2ProfileActive', 'EncryptedDnsOverridden'] : [],
    posture: live ? { kind: 'Tunnelled', tier: 'Tier2' } : { kind: 'FailClosed' },
    paths: {
      asOfMs: nowMs,
      watching: live,
      paths: live || sc.state === 'fail' || sc.state === 'off' || sc.state === 'probe' ? paths : [],
      degraded: bad ? { path: WIFI.id, quality: 'Poor', staying: sc.networks === 'one' ? 'OnlyPath' : 'NoBetterPath' } : null,
    },
    stats: live
      ? {
          connected: true,
          connectedForS: 11520,
          networkChanges: 2,
          changesThatDropConnections: 1,
          methodSwitches: 1,
          endpointSwitches: 0,
          degradedPeriods: bad ? 1 : 0,
          longestDegradedS: bad ? 40 : 0,
        }
      : { connected: false },
    lastBecause: null,
  };
}

export interface MockOptions {
  now?: () => number;
  /** How long "probing" lasts before the mock reports connected. */
  probeMs?: number;
  /** Whether turning the control on first needs the Tier 2 consent (a Tier 1 method is viable). */
  requireTier2Consent?: boolean;
  capabilities?: Partial<Capabilities>;
  initial?: Partial<Scenario>;
  endpoints?: EndpointView[];
  /** Pretend the person has already been through first run. */
  disclosed?: boolean;
}

export interface MockController extends Bridge {
  /** Jump to a state, as the design preview's toolbar does. */
  set(scenario: Partial<Scenario>): void;
  readonly scenario: Scenario;
  /** Push an event into the Activity view. */
  emit(event: string, because: string): void;
  /** Make the next `stabilize(true)` fail with this reason. */
  failNext(reason: string): void;
}

const BUILTIN_RULES: RuleView[] = [
  { precedence: 1, action: 'Bypass', reliability: 'Deterministic', builtin: true },
  { precedence: 2, action: 'Bypass', reliability: 'Deterministic', builtin: true },
  { precedence: 3, action: 'Capture', reliability: 'Deterministic', builtin: true },
  { precedence: 100, action: 'Reject', reliability: 'Deterministic', builtin: true },
];

export function createMockBridge(options: MockOptions = {}): MockController {
  const now = options.now ?? (() => Date.now());
  const scenario: Scenario = { state: 'off', networks: 'two', cause: 'NoEndpointReachable', ...options.initial };
  const capabilities: Capabilities = { provisioning: false, updates: true, ...options.capabilities };
  let endpoints: EndpointView[] = options.endpoints ?? [
    { id: 'e1', label: 'endpoint-1', address: '203.0.113.9:44443', enabled: true, health: 'Healthy' },
  ];
  let dns: EncryptedDnsSetting = { block: true, needsDisclosure: options.disclosed !== true };
  const snapshotListeners = new Set<(s: Snapshot) => void>();
  const activityListeners = new Set<(a: ActivityItem) => void>();
  let seq = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let failure: string | null = null;

  const build = (): Snapshot => parseSnapshot(rawSnapshot(scenario, now()), now());
  const push = (): void => {
    const s = build();
    for (const l of snapshotListeners) l(s);
  };
  const emit = (event: string, because: string): void => {
    const item: ActivityItem = { seq: (seq += 1), event, because, atMs: now() };
    for (const l of activityListeners) l(item);
  };
  const connected = (): boolean => scenario.state === 'ok' || scenario.state === 'warn' || scenario.state === 'probe';
  const refuse = (reason: string, code: 'ServiceBusy' | 'Refused' = 'Refused'): Outcome => ({ ok: false, reason, code });
  const idleOnly = (): Outcome | null =>
    connected() ? refuse('disconnect before changing endpoints or encrypted-name settings', 'Refused') : null;

  return {
    capabilities,
    scenario,

    set(next) {
      Object.assign(scenario, next);
      push();
    },
    emit,
    failNext(reason) {
      failure = reason;
    },

    subscribe(onSnapshot, onActivity) {
      snapshotListeners.add(onSnapshot);
      activityListeners.add(onActivity);
      queueMicrotask(() => onSnapshot(build()));
      return (): void => {
        snapshotListeners.delete(onSnapshot);
        activityListeners.delete(onActivity);
      };
    },

    async stabilize(on, opts) {
      clearTimeout(timer);
      if (!on) {
        scenario.state = 'off';
        emit('Disconnected', 'You turned it off, so the tunnel was taken down and your traffic leaves directly.');
        push();
        return { ok: true };
      }
      if (options.requireTier2Consent && opts?.acknowledgeTier2 !== true) {
        return { ok: false, reason: 'a method that drops connections on a network change needs your consent', code: 'TierConsentRequired' };
      }
      if (failure !== null) {
        const reason = failure;
        failure = null;
        scenario.state = 'fail';
        push();
        return { ok: false, reason };
      }
      scenario.state = 'probe';
      emit('ProbeStarted', 'A connection was requested, so each configured method is being tested for usable throughput.');
      push();
      timer = setTimeout(() => {
        scenario.state = 'ok';
        emit('ProfileSelected', 'Hysteria 2 carried 1.2 Mbit/s and AmneziaWG timed out, so Hysteria 2 was chosen.');
        push();
      }, options.probeMs ?? 1500);
      return { ok: true };
    },

    async endpoints() {
      return endpoints.map((e) => ({ ...e }));
    },
    async addEndpoint(input: NewEndpointInput) {
      const blocked = idleOnly();
      if (blocked) return blocked;
      if (endpoints.some((e) => e.label === input.label)) return refuse('an endpoint with that label already exists');
      if (input.credentials.trim() === '') return refuse('`credentials` holds no connection method');
      const id = `e${endpoints.length + 2}`;
      endpoints = [...endpoints, { id, label: input.label, address: `${input.host}:44443`, enabled: true, health: 'Unknown' }];
      return { ok: true, id };
    },
    async removeEndpoint(id) {
      const blocked = idleOnly();
      if (blocked) return blocked;
      if (!endpoints.some((e) => e.id === id)) return refuse('there is no endpoint with that id');
      endpoints = endpoints.filter((e) => e.id !== id);
      return { ok: true };
    },
    async setEndpointEnabled(id, enabled) {
      const blocked = idleOnly();
      if (blocked) return blocked;
      if (!endpoints.some((e) => e.id === id)) return refuse('there is no endpoint with that id');
      endpoints = endpoints.map((e) => (e.id === id ? { ...e, enabled } : e));
      return { ok: true };
    },

    async rules(): Promise<RulesView> {
      return { rules: BUILTIN_RULES.map((r) => ({ ...r })), encryptedDns: { ...dns } };
    },
    async setEncryptedDns(block) {
      const blocked = idleOnly();
      if (blocked) return blocked;
      dns = { block, needsDisclosure: false };
      return block
        ? { ok: true }
        : {
            ok: true,
            consequence:
              'Rules for sites and domains will not apply to traffic from programs that use their own encrypted lookups. Those programs will be routed by address only.',
          };
    },

    async checkUpdates() {
      if (!capabilities.updates) return refuse('checking for updated definitions is not available in this build yet');
      emit('DefinitionsChanged', 'The place connection method updates are published could not be reached, so the definitions in use are unchanged.');
      return { ok: true, route: connected() ? 'tunnel' : 'physical' };
    },

    async openLoginPage() {
      return { ok: true };
    },
  } satisfies MockController;
}
