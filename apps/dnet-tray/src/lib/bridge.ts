/**
 * The one door between the window and everything else (ADR-0007 R4).
 *
 * The window never touches the control pipe. The Rust side owns the `dnet-ipc` client, decodes replies with the
 * typed protocol, and hands this side small view-models; this side asks for things through the commands below.
 * Two implementations exist: `tauriBridge` (the real one) and `mockBridge` (development, tests, and the
 * design preview), and the components cannot tell them apart.
 */
import type {
  ActivityItem,
  ComponentsView,
  EncryptedDnsSetting,
  EndpointView,
  PendingView,
  ProfileView,
  RulesView,
  Snapshot,
} from './model';

export type { ComponentsView, EncryptedDnsSetting, PendingView, ProfileView, RulesView };

export type Unsubscribe = () => void;

/** What the service has in this build. A feature it lacks is shown as unavailable, never faked. */
export interface Capabilities {
  /**
   * Creating a server through the provider's own programming interface (not built; no cloud credential is
   * ever asked for). The guided setup, where the person works in the provider's pages, does not depend on it.
   */
  provisioning: boolean;
  /** Checking for updated connection methods (T066b). False when the build has no trust anchor. */
  updates: boolean;
}

/** The outcome of something the person asked for. A refusal carries the service's own reason. */
export type Outcome =
  | { ok: true }
  | { ok: false; reason: string; code?: 'TierConsentRequired' | 'ServiceBusy' | 'NotConnected' | 'Refused' };

export interface NewEndpointInput {
  label: string;
  host: string;
  /** The connection file's text. It holds keys; it goes straight to the Rust side and is not kept here. */
  credentials: string;
}

/** The kind of processor a server has. */
export type ServerKind = 'amd64' | 'arm64';

/** What the service made for a new setup: the script to run on the server and the ports to open. */
export interface PreparedServer {
  arch: ServerKind;
  script: string;
  ports: { protocol: string; port: number }[];
  /** How long the service keeps the keys waiting for the result. */
  validForMinutes: number;
}

export interface FinishServerInput {
  label: string;
  host: string;
  /** What the server printed, pasted. It holds keys; it goes straight to the Rust side and is not kept here. */
  report: string;
}

/** A rule a person can add: by site, by a site and its subdomains, or by address range. */
export interface NewRuleInput {
  kind: 'domain' | 'domain_suffix' | 'ip_cidr';
  value: string;
  action: 'tunnel' | 'bypass';
}

export interface Bridge {
  readonly capabilities: Capabilities;

  /** The latest state, then every change. The first call returns what the service says right now. */
  subscribe(onSnapshot: (s: Snapshot) => void, onActivity: (a: ActivityItem) => void): Unsubscribe;

  /** Turn the one control on or off. Turning it on may need the Tier 2 consent first. */
  stabilize(on: boolean, options?: { acknowledgeTier2?: boolean }): Promise<Outcome>;

  endpoints(): Promise<EndpointView[]>;
  addEndpoint(input: NewEndpointInput): Promise<Outcome & { id?: string }>;
  removeEndpoint(id: string): Promise<Outcome>;
  setEndpointEnabled(id: string, enabled: boolean): Promise<Outcome>;

  /** Begin setting up the person's own server. The same script comes back until it is used or expires. */
  prepareServer(arch: ServerKind): Promise<Outcome & { prepared?: PreparedServer }>;
  /** Finish it with what the server printed. The service checks it belongs to this setup. */
  finishServer(input: FinishServerInput): Promise<Outcome & { id?: string }>;

  /** The live map of parts. A service too old to know the request answers `supported: false`. */
  components(): Promise<ComponentsView>;

  profiles(): Promise<ProfileView[]>;
  /**
   * Turn aggressive speed mode (Brutal) on for a Hysteria 2 method with both speeds in Mbit/s, or off with
   * `null`. Call it to turn it on only after the person accepted `brutalWarning`; its revision is sent with it.
   */
  setBrutal(profile: string, bandwidth: { up: number; down: number } | null): Promise<Outcome>;

  rules(): Promise<RulesView>;
  /** Add one of the person's own rules. The service puts it after every built-in rule. */
  addRule(rule: NewRuleInput): Promise<Outcome & { id?: string }>;
  removeRule(id: string): Promise<Outcome>;
  /** `block: false` is the one-action opt-out; the reply carries the consequence to show. */
  setEncryptedDns(block: boolean): Promise<Outcome & { consequence?: string }>;

  /** The changes that redirect traffic and wait for approval (T160). Empty when none do, or the service predates them. */
  pending(): Promise<PendingView[]>;
  /**
   * Approve one. The window is not an elevated client, so this opens the approver, which asks Windows and applies the
   * change only when the person types yes in its own window; it comes back when that window is closed.
   */
  approveChange(id: string): Promise<Outcome>;
  /** Drop a waiting change without applying it. */
  rejectChange(id: string): Promise<Outcome>;

  /** Ask the service to check for updated connection methods now. */
  checkUpdates(): Promise<Outcome & { route?: 'tunnel' | 'physical' }>;

  /** Open the sign-in page of a captive portal in the person's own browser. The Rust side checks the address. */
  openLoginPage(): Promise<Outcome>;
}

/** The real bridge when running inside Tauri, otherwise the mock (a browser tab, a test). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
