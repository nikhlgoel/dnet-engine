/**
 * The real bridge: the window's door to the Rust side inside Tauri (ADR-0007 R4).
 *
 * Everything that crosses is plain JSON. The Rust side owns the `dnet-ipc` client and decodes the service's
 * replies with the typed protocol; what arrives here is checked again by `parseSnapshot` and friends, because the
 * web view is the side that must not trust what it is handed. Nothing in this file touches the control pipe, a
 * file, or the network.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Bridge, Capabilities, NewEndpointInput, Outcome, PreparedServer } from './bridge';
import { brutalWarning } from './messages';
import {
  parseActivity,
  parseEndpoints,
  parseProfiles,
  parseRulesReply,
  parseSnapshot,
  type ActivityItem,
  type Snapshot,
} from './model';

const CODES = new Set(['TierConsentRequired', 'ServiceBusy', 'NotConnected', 'Refused']);

/** A command's reply as an `Outcome`. Anything that is not clearly a success is a refusal with a reason. */
function outcome(value: unknown): Outcome & Record<string, unknown> {
  if (typeof value === 'object' && value !== null) {
    const v = value as Record<string, unknown>;
    if (v.ok === true) return v as Outcome & Record<string, unknown>;
    if (v.ok === false && typeof v.reason === 'string') {
      const code = typeof v.code === 'string' && CODES.has(v.code) ? v.code : undefined;
      return { ok: false, reason: v.reason, ...(code ? { code: code as 'Refused' } : {}) };
    }
  }
  return { ok: false, reason: 'The service gave an answer this window does not understand.', code: 'Refused' };
}

/** A command that failed outright (the Rust side is gone, or refused to run it). */
function failed(error: unknown): Outcome {
  return { ok: false, reason: typeof error === 'string' ? error : 'The background service did not answer.', code: 'ServiceBusy' };
}

async function call(command: string, args?: Record<string, unknown>): Promise<Outcome & Record<string, unknown>> {
  try {
    return outcome(await invoke(command, args));
  } catch (error) {
    return failed(error) as Outcome & Record<string, unknown>;
  }
}

/** The service's script reply, read as untrusted: anything that is not exactly the promised shape is refused. */
function parsePrepared(value: Record<string, unknown>): PreparedServer | null {
  const { arch, script, ports, validForMinutes } = value;
  if (arch !== 'amd64' && arch !== 'arm64') return null;
  if (typeof script !== 'string' || script.length === 0 || script.length > 65536) return null;
  if (!Array.isArray(ports) || ports.length === 0 || ports.length > 8) return null;
  const checked: { protocol: string; port: number }[] = [];
  for (const p of ports) {
    const q = p as { protocol?: unknown; port?: unknown };
    if (q.protocol !== 'udp' && q.protocol !== 'tcp') return null;
    if (typeof q.port !== 'number' || !Number.isInteger(q.port) || q.port < 1 || q.port > 65535) return null;
    checked.push({ protocol: q.protocol, port: q.port });
  }
  if (typeof validForMinutes !== 'number' || !Number.isFinite(validForMinutes) || validForMinutes < 1) return null;
  return { arch, script, ports: checked, validForMinutes: Math.floor(validForMinutes) };
}

function capabilitiesFrom(value: unknown): Capabilities {
  const v = (typeof value === 'object' && value !== null ? value : {}) as Record<string, unknown>;
  return { provisioning: v.provisioning === true, updates: v.updates === true };
}

/** Build the bridge. The capabilities are asked once, up front, because the window lays itself out with them. */
export async function createTauriBridge(): Promise<Bridge> {
  let capabilities: Capabilities = { provisioning: false, updates: false };
  try {
    capabilities = capabilitiesFrom(await invoke('capabilities'));
  } catch {
    // The Rust side did not answer: show only what needs nothing from it.
  }

  return {
    capabilities,

    subscribe(onSnapshot, onActivity) {
      let live = true;
      const stops: Array<() => void> = [];
      const take = (stop: () => void): void => {
        if (live) stops.push(stop);
        else stop();
      };

      // What happened while the window was closed comes first, oldest first, and then what happens now. An
      // event that arrives while the backlog is still on its way is held and shown unless the backlog had it:
      // the Rust side keeps the events, so the window shows the session and not only its own lifetime.
      let held: ActivityItem[] | null = [];
      const seen = new Set<number>();
      const show = (item: ActivityItem): void => {
        if (item.seq !== null) seen.add(item.seq);
        onActivity(item);
      };

      void listen<unknown>('dnet:snapshot', (event) => {
        try {
          onSnapshot(parseSnapshot(event.payload, Date.now()));
        } catch {
          // A malformed snapshot is dropped; the heartbeat then shows that updates stopped.
        }
      }).then(take);
      void listen<unknown>('dnet:activity', (event) => {
        try {
          const item = parseActivity(event.payload, Date.now());
          if (held !== null) held.push(item);
          else show(item);
        } catch {
          // Likewise.
        }
      }).then(take);

      invoke<unknown>('activity_backlog')
        .then((value) => {
          if (!live) return;
          if (Array.isArray(value)) {
            for (const raw of value) {
              try {
                show(parseActivity(raw, Date.now()));
              } catch {
                // An item the window cannot read is skipped, not drawn.
              }
            }
          }
        })
        .catch(() => undefined)
        .finally(() => {
          const waiting = held ?? [];
          held = null;
          if (!live) return;
          for (const item of waiting) if (item.seq === null || !seen.has(item.seq)) show(item);
        });

      // The state right now, so a window that opens after the service started is not blank.
      invoke<unknown>('snapshot')
        .then((value) => {
          if (live) onSnapshot(parseSnapshot(value, Date.now()));
        })
        .catch(() => undefined);

      return (): void => {
        live = false;
        for (const stop of stops.splice(0)) stop();
      };
    },

    stabilize: (on, options) => call('stabilize', { on, acknowledgeTier2: options?.acknowledgeTier2 === true }),

    async endpoints() {
      return parseEndpoints(await invoke('list_endpoints'));
    },
    async addEndpoint(input: NewEndpointInput) {
      const reply = await call('add_endpoint', { ...input });
      return reply.ok && typeof reply.id === 'string' ? { ok: true as const, id: reply.id } : reply;
    },
    async prepareServer(arch) {
      const reply = await call('prepare_server', { arch });
      if (!reply.ok) return reply;
      const prepared = parsePrepared(reply);
      return prepared
        ? { ok: true as const, prepared }
        : { ok: false as const, reason: 'The background service’s answer was not what was expected.' };
    },
    async finishServer(input) {
      const reply = await call('finish_server', { ...input });
      return reply.ok && typeof reply.id === 'string' ? { ok: true as const, id: reply.id } : reply;
    },
    removeEndpoint: (id) => call('remove_endpoint', { id }),
    setEndpointEnabled: (id, enabled) => call('set_endpoint_enabled', { id, enabled }),

    async profiles() {
      return parseProfiles(await invoke('list_profiles'));
    },
    setBrutal: (profile, bandwidth) =>
      call('set_brutal', {
        profile,
        up: bandwidth?.up ?? null,
        down: bandwidth?.down ?? null,
        warningRevision: brutalWarning.revision,
      }),

    async addRule(rule) {
      const reply = await call('add_rule', { ...rule });
      return reply.ok && typeof reply.id === 'string' ? { ok: true as const, id: reply.id } : reply;
    },
    removeRule: (id) => call('remove_rule', { id }),

    async rules() {
      return parseRulesReply(await invoke('list_rules'));
    },
    async setEncryptedDns(block) {
      const reply = await call('set_encrypted_dns', { block });
      return reply.ok && typeof reply.consequence === 'string' ? { ok: true as const, consequence: reply.consequence } : reply;
    },

    async checkUpdates() {
      const reply = await call('check_updates');
      if (reply.ok) return { ok: true as const, route: reply.route === 'physical' ? ('physical' as const) : ('tunnel' as const) };
      return reply;
    },

    openLoginPage: () => call('open_login_page'),
  };
}

export type { ActivityItem, Snapshot };
