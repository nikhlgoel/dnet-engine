/**
 * The one door between the window and everything else (ADR-0007 R4).
 *
 * The window never touches the control pipe. The Rust side owns the `dnet-ipc` client, decodes replies with the
 * typed protocol, and hands this side small view-models; this side asks for things through the commands below.
 * Two implementations exist: `tauriBridge` (the real one) and `mockBridge` (development, tests, and the
 * design preview), and the components cannot tell them apart.
 */
import type { ActivityItem, EncryptedDnsSetting, EndpointView, RulesView, Snapshot } from './model';

export type { EncryptedDnsSetting, RulesView };

export type Unsubscribe = () => void;

/** What the service has in this build. A feature it lacks is shown as unavailable, never faked. */
export interface Capabilities {
  /** Setting up a server in the person's cloud account (T093 and the provider; not built). */
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

  rules(): Promise<RulesView>;
  /** `block: false` is the one-action opt-out; the reply carries the consequence to show. */
  setEncryptedDns(block: boolean): Promise<Outcome & { consequence?: string }>;

  /** Ask the service to check for updated connection methods now. */
  checkUpdates(): Promise<Outcome & { route?: 'tunnel' | 'physical' }>;

  /** Open the sign-in page of a captive portal in the person's own browser. The Rust side checks the address. */
  openLoginPage(): Promise<Outcome>;
}

/** The real bridge when running inside Tauri, otherwise the mock (a browser tab, a test). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
