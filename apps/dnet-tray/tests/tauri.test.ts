/**
 * The real bridge, against a stand-in for the Rust side (`mockIPC`): which command each call makes with which
 * arguments, how an answer that is not what the contract says is treated, and how the window catches up on what
 * it missed while it was closed.
 */
import { emit } from '@tauri-apps/api/event';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Bridge } from '../src/lib/bridge';
import { createTauriBridge } from '../src/lib/tauri';
import type { ActivityItem, Snapshot } from '../src/lib/model';
import { rawSnapshot } from '../src/lib/mock';
import { brutalWarning } from '../src/lib/messages';

type Handler = (command: string, args: Record<string, unknown>) => unknown;

interface Calls {
  list: Array<[string, Record<string, unknown>]>;
}

/** Install a Rust side that answers from `handler`, and remember what it was asked. */
function rust(handler: Handler): Calls {
  const calls: Calls = { list: [] };
  mockIPC(
    (command, payload) => {
      if (command.startsWith('plugin:event|')) return undefined;
      const args = (payload ?? {}) as Record<string, unknown>;
      calls.list.push([command, args]);
      return handler(command, args);
    },
    { shouldMockEvents: true },
  );
  return calls;
}

const answers: Record<string, unknown> = {
  capabilities: { provisioning: false, updates: true },
  snapshot: rawSnapshot({ state: 'ok', networks: 'two', cause: 'NoEndpointReachable' }, 1),
  activity_backlog: [],
};

async function bridge(handler: Handler = (c) => answers[c]): Promise<{ b: Bridge; calls: Calls }> {
  const calls = rust(handler);
  return { b: await createTauriBridge(), calls };
}

afterEach(() => {
  clearMocks();
});

describe('capabilities', () => {
  it('are asked once, up front', async () => {
    const { b, calls } = await bridge();
    expect(b.capabilities).toEqual({ provisioning: false, updates: true });
    expect(calls.list.filter(([c]) => c === 'capabilities')).toHaveLength(1);
  });

  it('are the least when the Rust side does not answer', async () => {
    const { b } = await bridge(() => {
      throw new Error('gone');
    });
    expect(b.capabilities).toEqual({ provisioning: false, updates: false });
  });

  it('read only what is plainly true', async () => {
    const { b } = await bridge(() => ({ provisioning: 'yes', updates: 1 }));
    expect(b.capabilities).toEqual({ provisioning: false, updates: false });
  });
});

describe('commands', () => {
  it('stabilize sends the switch and the consent, and never a consent that was not given', async () => {
    const { b, calls } = await bridge(() => ({ ok: true }));
    await b.stabilize(true);
    await b.stabilize(true, { acknowledgeTier2: true });
    await b.stabilize(false);
    expect(calls.list.filter(([c]) => c === 'stabilize').map(([, a]) => a)).toEqual([
      { on: true, acknowledgeTier2: false },
      { on: true, acknowledgeTier2: true },
      { on: false, acknowledgeTier2: false },
    ]);
  });

  it('a refusal keeps the service’s reason and its code', async () => {
    const { b } = await bridge(() => ({ ok: false, reason: 'a method that drops connections needs your consent', code: 'TierConsentRequired' }));
    expect(await b.stabilize(true)).toEqual({ ok: false, reason: 'a method that drops connections needs your consent', code: 'TierConsentRequired' });
  });

  it('a code it does not know is dropped, and the reason stays', async () => {
    const { b } = await bridge(() => ({ ok: false, reason: 'because', code: 'Mystery' }));
    expect(await b.stabilize(true)).toEqual({ ok: false, reason: 'because' });
  });

  it('an answer that is not an outcome is a refusal, never a success', async () => {
    for (const odd of [null, 'ok', 7, {}, { ok: 'true' }, { ok: false }, { ok: false, reason: 5 }]) {
      const { b } = await bridge(() => odd);
      const out = await b.stabilize(true);
      expect(out.ok, JSON.stringify(odd)).toBe(false);
    }
  });

  it('a command that fails outright is the service being unavailable, in its own words when it gave some', async () => {
    const { b } = await bridge((c) => {
      if (c === 'capabilities') return answers.capabilities;
      throw 'the control pipe could not be opened';
    });
    expect(await b.stabilize(true)).toEqual({ ok: false, reason: 'the control pipe could not be opened', code: 'ServiceBusy' });
    const { b: b2 } = await bridge((c) => {
      if (c === 'capabilities') return answers.capabilities;
      throw new Error('not a string');
    });
    expect(await b2.stabilize(true)).toEqual({ ok: false, reason: 'The background service did not answer.', code: 'ServiceBusy' });
  });

  it('adding an endpoint sends the file’s text once and gets back only an id', async () => {
    const { b, calls } = await bridge((c) => (c === 'add_endpoint' ? { ok: true, id: 'abc' } : answers[c]));
    const out = await b.addEndpoint({ label: 'home', host: '203.0.113.9', credentials: '{"secret":"x"}' });
    expect(out).toEqual({ ok: true, id: 'abc' });
    expect(calls.list.find(([c]) => c === 'add_endpoint')?.[1]).toEqual({ label: 'home', host: '203.0.113.9', credentials: '{"secret":"x"}' });
    expect(JSON.stringify(out)).not.toContain('secret');
  });

  it('removing and switching name the endpoint by id', async () => {
    const { b, calls } = await bridge((c) => (c === 'remove_endpoint' || c === 'set_endpoint_enabled' ? { ok: true } : answers[c]));
    await b.removeEndpoint('e1');
    await b.setEndpointEnabled('e1', false);
    expect(calls.list.filter(([c]) => c.endsWith('endpoint') || c === 'set_endpoint_enabled').map(([c, a]) => [c, a])).toEqual([
      ['remove_endpoint', { id: 'e1' }],
      ['set_endpoint_enabled', { id: 'e1', enabled: false }],
    ]);
  });

  it('opting out of the encrypted-name block carries the consequence, and only the service’s', async () => {
    const { b } = await bridge((c) => (c === 'set_encrypted_dns' ? { ok: true, consequence: 'Rules for sites will not apply.' } : answers[c]));
    expect(await b.setEncryptedDns(false)).toEqual({ ok: true, consequence: 'Rules for sites will not apply.' });
  });

  it('a check for updates says which network it uses, and defaults to the safer reading', async () => {
    const { b } = await bridge((c) => (c === 'check_updates' ? { ok: true, route: 'physical' } : answers[c]));
    expect(await b.checkUpdates()).toEqual({ ok: true, route: 'physical' });
    const { b: b2 } = await bridge((c) => (c === 'check_updates' ? { ok: true, route: 'elsewhere' } : answers[c]));
    expect(await b2.checkUpdates()).toEqual({ ok: true, route: 'tunnel' });
  });

  it('the lists are parsed by the window’s own parsers, which refuse what is not a list', async () => {
    const { b } = await bridge((c) => {
      if (c === 'list_endpoints') return { endpoints: [{ id: 'e1', label: 'a', address: 'x:1', enabled: true, health: 'Healthy' }] };
      if (c === 'list_rules') return { rules: [], encryptedDns: { block: true, needsDisclosure: false } };
      return answers[c];
    });
    expect((await b.endpoints()).map((e) => e.label)).toEqual(['a']);
    expect((await b.rules()).encryptedDns.block).toBe(true);

    const { b: bad } = await bridge((c) => (c === 'list_endpoints' ? { endpoints: 'many' } : answers[c]));
    await expect(bad.endpoints()).rejects.toThrow();
  });
});

describe('subscribe', () => {
  const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 10));

  it('shows the state right now, then each change', async () => {
    const { b } = await bridge();
    const seen: Snapshot[] = [];
    const stop = b.subscribe((s) => seen.push(s), () => undefined);
    await vi.waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.status).toBe('Connected');

    await emit('dnet:snapshot', rawSnapshot({ state: 'off', networks: 'one', cause: 'NoEndpointReachable' }, 1));
    await vi.waitFor(() => expect(seen).toHaveLength(2));
    expect(seen[1]?.status).toBe('Disconnected');
    stop();
  });

  it('drops a snapshot it cannot believe and keeps going', async () => {
    const { b } = await bridge();
    const seen: Snapshot[] = [];
    const stop = b.subscribe((s) => seen.push(s), () => undefined);
    await vi.waitFor(() => expect(seen).toHaveLength(1));
    await emit('dnet:snapshot', { status: 'Connected' });
    await tick();
    expect(seen).toHaveLength(1);
    await emit('dnet:snapshot', rawSnapshot({ state: 'warn', networks: 'two', cause: 'NoEndpointReachable' }, 1));
    await vi.waitFor(() => expect(seen).toHaveLength(2));
    stop();
  });

  it('catches up on what happened while the window was closed, oldest first', async () => {
    const { b } = await bridge((c) =>
      c === 'activity_backlog'
        ? [
            { seq: 1, event: 'ProbeStarted', because: 'first' },
            { seq: 2, event: 'ProfileSelected', because: 'second' },
          ]
        : answers[c],
    );
    const seen: ActivityItem[] = [];
    const stop = b.subscribe(() => undefined, (a) => seen.push(a));
    await vi.waitFor(() => expect(seen).toHaveLength(2));
    expect(seen.map((a) => a.because)).toEqual(['first', 'second']);
    stop();
  });

  it('does not show an event twice when it arrives while the backlog is on its way', async () => {
    let release: (value: unknown) => void = () => undefined;
    const backlog = new Promise((resolve) => {
      release = resolve;
    });
    const { b } = await bridge((c) => (c === 'activity_backlog' ? backlog : answers[c]));
    const seen: ActivityItem[] = [];
    const stop = b.subscribe(() => undefined, (a) => seen.push(a));

    await tick();
    // Seen live (seq 2 is also in the backlog; seq 3 is not).
    await emit('dnet:activity', { seq: 2, event: 'ProfileSelected', because: 'second' });
    await emit('dnet:activity', { seq: 3, event: 'Degraded', because: 'third' });
    await tick();
    expect(seen).toHaveLength(0);

    release([
      { seq: 1, event: 'ProbeStarted', because: 'first' },
      { seq: 2, event: 'ProfileSelected', because: 'second' },
    ]);
    await vi.waitFor(() => expect(seen).toHaveLength(3));
    expect(seen.map((a) => a.seq)).toEqual([1, 2, 3]);

    // After that, events pass straight through.
    await emit('dnet:activity', { seq: 4, event: 'Recovered', because: 'fourth' });
    await vi.waitFor(() => expect(seen).toHaveLength(4));
    stop();
  });

  it('skips an activity item it cannot read, in the backlog and live', async () => {
    const { b } = await bridge((c) => (c === 'activity_backlog' ? [{ seq: 1, event: 'Fine', because: 'ok' }, { nonsense: true }, 7] : answers[c]));
    const seen: ActivityItem[] = [];
    const stop = b.subscribe(() => undefined, (a) => seen.push(a));
    await vi.waitFor(() => expect(seen).toHaveLength(1));
    await emit('dnet:activity', { event: '' });
    await tick();
    expect(seen).toHaveLength(1);
    stop();
  });

  it('delivers nothing that was still on its way when the window stopped asking', async () => {
    let release: (value: unknown) => void = () => undefined;
    const backlog = new Promise((resolve) => {
      release = resolve;
    });
    const { b } = await bridge((c) => (c === 'activity_backlog' ? backlog : answers[c]));
    const seen: ActivityItem[] = [];
    const stop = b.subscribe(() => undefined, (a) => seen.push(a));
    stop();
    release([{ seq: 1, event: 'Late', because: 'arrived after the window closed' }]);
    await tick();
    expect(seen).toEqual([]);
  });

  it('stops listening when the window stops asking', async () => {
    const { b } = await bridge();
    const seen: Snapshot[] = [];
    const stop = b.subscribe((s) => seen.push(s), () => undefined);
    await vi.waitFor(() => expect(seen).toHaveLength(1));
    stop();
    await emit('dnet:snapshot', rawSnapshot({ state: 'off', networks: 'one', cause: 'NoEndpointReachable' }, 1));
    await tick();
    expect(seen).toHaveLength(1);
  });
});

describe('aggressive speed mode (Brutal, T105)', () => {
  it('reads the methods, and turns the mode on with both figures and the revision of the warning shown', async () => {
    const { b, calls } = await bridge((c) =>
      c === 'list_profiles'
        ? { profiles: [{ id: 'hy2-default', kind: 'Hysteria2', tier: 'Tier2', brutal: false }] }
        : c === 'set_brutal'
          ? { ok: true }
          : answers[c],
    );
    expect(await b.profiles()).toEqual([{ id: 'hy2-default', kind: 'Hysteria2', tier: 'Tier2', brutal: false }]);
    expect(await b.setBrutal('hy2-default', { up: 50, down: 200 })).toEqual({ ok: true });
    expect(await b.setBrutal('hy2-default', null)).toEqual({ ok: true });
    expect(calls.list.filter(([c]) => c === 'set_brutal').map(([, a]) => a)).toEqual([
      { profile: 'hy2-default', up: 50, down: 200, warningRevision: brutalWarning.revision },
      { profile: 'hy2-default', up: null, down: null, warningRevision: brutalWarning.revision },
    ]);
  });

  it('a method list it cannot read is an error, not an empty list', async () => {
    const { b } = await bridge((c) => (c === 'list_profiles' ? { profiles: [{ id: 'x', kind: 'Telepathy', tier: 'Tier2' }] } : answers[c]));
    await expect(b.profiles()).rejects.toBeTruthy();
  });
});

describe('rules (T108)', () => {
  it('adds a rule by what it matches and removes one by id', async () => {
    const { b, calls } = await bridge((c) =>
      c === 'add_rule' ? { ok: true, id: 'r1' } : c === 'remove_rule' ? { ok: true } : answers[c],
    );
    expect(await b.addRule({ kind: 'domain_suffix', value: 'example.com', action: 'bypass' })).toEqual({ ok: true, id: 'r1' });
    expect(await b.removeRule('r1')).toEqual({ ok: true });
    expect(calls.list.filter(([c]) => c.endsWith('_rule')).map(([c, a]) => [c, a])).toEqual([
      ['add_rule', { kind: 'domain_suffix', value: 'example.com', action: 'bypass' }],
      ['remove_rule', { id: 'r1' }],
    ]);
  });
});

