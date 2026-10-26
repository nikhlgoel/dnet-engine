/**
 * The window's state and behaviour against the mock bridge: the one control, the Tier 2 consent, refusals shown in
 * the service's words, and nothing running while the window is hidden (ADR-0007 R2).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppState } from '../src/lib/app.svelte';
import { en } from '../src/lib/messages';
import { createMockBridge, type MockController, type MockOptions } from '../src/lib/mock';

const ACK = 'dnet.acceptable-use.v1';
const PREFS = 'dnet.prefs.v1';

function make(options: MockOptions = {}, acknowledged = true): { app: AppState; mock: MockController } {
  if (acknowledged) window.localStorage.setItem(ACK, '{}');
  const mock = createMockBridge({ probeMs: 5, disclosed: true, ...options });
  return { app: new AppState(mock), mock };
}

const settled = async (check: () => boolean): Promise<void> => vi.waitFor(() => expect(check()).toBe(true), { timeout: 2000 });

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('the one control', () => {
  it('turns on: probing, then connected, with the words to match', async () => {
    const { app } = make();
    app.start();
    await settled(() => app.snapshot !== null);
    expect(app.look?.headline).toBe('Not connected');

    await app.toggle();
    await settled(() => app.look?.lamp === 'probe');
    await settled(() => app.look?.lamp === 'ok');
    expect(app.look?.headline).toBe('Connected');
    app.stop();
  });

  it('turns off at once, and the reason lands in Activity', async () => {
    const { app } = make({ initial: { state: 'ok' } });
    app.start();
    await settled(() => app.snapshot !== null);
    await app.toggle();
    await settled(() => app.look?.lamp === 'off');
    expect(app.activity[0]?.event).toBe('Disconnected');
    expect(app.activity[0]?.because).toMatch(/turned it off/);
    app.stop();
  });

  it('does nothing until the acceptable-use acknowledgement is given, and takes the person to it', async () => {
    const { app, mock } = make({}, false);
    const stabilize = vi.spyOn(mock, 'stabilize');
    app.start();
    await settled(() => app.snapshot !== null);

    await app.toggle();
    expect(stabilize).not.toHaveBeenCalled();
    expect(app.view).toBe('firstrun');
    app.stop();
  });

  it('records the acknowledgement with its time and the exact text shown', () => {
    const { app } = make({}, false);
    expect(app.acknowledged).toBe(false);
    app.acknowledgeAcceptableUse('the words');
    expect(app.acknowledged).toBe(true);
    const stored = JSON.parse(window.localStorage.getItem(ACK) ?? '{}') as { at: string; text: string };
    expect(stored.text).toBe('the words');
    expect(Number.isNaN(Date.parse(stored.at))).toBe(false);
    expect(new AppState(createMockBridge()).acknowledged).toBe(true);
  });
});

describe('the Tier 2 consent (a method that drops connections on a network change)', () => {
  it('asks first, and declining changes nothing', async () => {
    const { app, mock } = make({ requireTier2Consent: true });
    const stabilize = vi.spyOn(mock, 'stabilize');
    app.start();
    await settled(() => app.snapshot !== null);

    await app.toggle();
    expect(app.tier2Prompt).toBe(true);
    await app.answerTier2(false);
    expect(app.tier2Prompt).toBe(false);
    // One call, the first, which the service refused for want of consent. Declining sent nothing more.
    expect(stabilize).toHaveBeenCalledTimes(1);
    expect(app.look?.lamp).toBe('off');
    app.stop();
  });

  it('accepting sends the acknowledgement and connects', async () => {
    const { app, mock } = make({ requireTier2Consent: true });
    const stabilize = vi.spyOn(mock, 'stabilize');
    app.start();
    await settled(() => app.snapshot !== null);

    await app.toggle();
    await app.answerTier2(true);
    expect(stabilize).toHaveBeenLastCalledWith(true, { acknowledgeTier2: true });
    await settled(() => app.look?.lamp === 'ok');
    app.stop();
  });
});

describe('refusals are shown in the service’s own words', () => {
  it('keeps the reason as the notice and the lamp where the service put it', async () => {
    const { app, mock } = make();
    app.start();
    await settled(() => app.snapshot !== null);
    mock.failNext('no endpoint answered on this network');

    await app.toggle();
    expect(app.notice).toBe('no endpoint answered on this network');
    // The next action clears the old notice.
    app.go('rules');
    expect(app.notice).toBeNull();
    app.stop();
  });
});

describe('the one action a failure offers', () => {
  it('opens the view that fixes it', async () => {
    const { app } = make();
    await app.act('open-endpoints');
    expect(app.view).toBe('endpoints');
    await app.act('open-activity');
    expect(app.view).toBe('activity');
  });

  it('opens the networks drawer, and explains how to get rights without pretending to grant them', async () => {
    const { app } = make();
    await app.act('show-networks');
    expect(app.drawerOpen).toBe(true);
    await app.act('grant-rights');
    expect(app.notice).toBe(en.help.grantRights);
  });

  it('retry is the same control, not a second path to connecting', async () => {
    const { app, mock } = make();
    const stabilize = vi.spyOn(mock, 'stabilize');
    app.start();
    await settled(() => app.snapshot !== null);
    await app.act('retry');
    expect(stabilize).toHaveBeenCalledTimes(1);
    app.stop();
  });

  it('opens the login page through the bridge, which checks the address', async () => {
    const { app, mock } = make();
    const open = vi.spyOn(mock, 'openLoginPage');
    await app.act('open-login');
    expect(open).toHaveBeenCalledTimes(1);
  });
});

describe('nothing runs while the window is hidden (R2)', () => {
  it('drops the subscription and the clock, and comes back with the latest state', async () => {
    const { app, mock } = make({ initial: { state: 'ok' } });
    app.start();
    await settled(() => app.snapshot !== null);

    app.setVisible(false);
    mock.set({ state: 'warn' });
    await new Promise((r) => setTimeout(r, 20));
    // Not told while hidden.
    expect(app.snapshot?.paths.degraded).toBeNull();

    app.setVisible(true);
    await settled(() => app.snapshot?.paths.degraded !== null);
    app.stop();
  });

  it('starts only once and stops cleanly', async () => {
    const { app, mock } = make({ initial: { state: 'ok' } });
    const subscribe = vi.spyOn(mock, 'subscribe');
    app.start();
    app.start();
    expect(subscribe).toHaveBeenCalledTimes(1);
    app.stop();
    app.stop();
  });

  it('ages the heartbeat once a second while visible', async () => {
    vi.useFakeTimers();
    try {
      const { app } = make();
      app.start();
      const before = app.now;
      vi.advanceTimersByTime(3000);
      expect(app.now).toBeGreaterThanOrEqual(before + 3000);
      app.stop();
      const frozen = app.now;
      vi.advanceTimersByTime(3000);
      expect(app.now).toBe(frozen);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Activity', () => {
  it('lists the newest first and keeps at most 200 lines', async () => {
    const { app, mock } = make();
    app.start();
    for (let i = 0; i < 250; i += 1) mock.emit(`Event${i}`, 'because');
    expect(app.activity).toHaveLength(200);
    expect(app.activity[0]?.event).toBe('Event249');
    app.stop();
  });
});

describe('preferences', () => {
  it('remember the theme and reduced motion', () => {
    const { app } = make();
    app.setTheme('light');
    app.setReduceMotion(true);
    const again = new AppState(createMockBridge());
    expect(again.theme).toBe('light');
    expect(again.reduceMotion).toBe(true);
  });

  it('fall back to the system theme on anything they cannot read', () => {
    for (const bad of ['not json', '[]', 'null', '{"theme":"neon","reduceMotion":"yes"}']) {
      window.localStorage.setItem(PREFS, bad);
      const app = new AppState(createMockBridge());
      expect(app.theme).toBe('system');
      expect(app.reduceMotion).toBe(false);
    }
  });

  it('work without storage at all (a private window, cleared data)', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    const app = new AppState(createMockBridge());
    expect(() => app.setTheme('dark')).not.toThrow();
    expect(app.theme).toBe('dark');
    expect(app.acknowledged).toBe(false);
  });
});

describe('endpoints and the encrypted-name setting are changed only while disconnected', () => {
  it('the bridge refuses while connected, and the refusal is a reason, not a crash', async () => {
    const { mock } = make({ initial: { state: 'ok' } });
    const added = await mock.addEndpoint({ label: 'x', host: '198.51.100.1', credentials: '{}' });
    expect(added.ok).toBe(false);
    const dns = await mock.setEncryptedDns(false);
    expect(dns.ok).toBe(false);
  });

  it('opting out of the block returns the consequence in the service’s words', async () => {
    const { mock } = make({ initial: { state: 'off' } });
    const reply = await mock.setEncryptedDns(false);
    expect(reply).toMatchObject({ ok: true });
    expect(reply.consequence).toMatch(/will not apply/);
    expect((await mock.rules()).encryptedDns.block).toBe(false);
  });
});
