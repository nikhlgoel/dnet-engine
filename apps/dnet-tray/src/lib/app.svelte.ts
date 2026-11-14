/**
 * The window's state, in one place. Components read it and call its methods; they do not talk to the bridge
 * themselves, so there is one path for every action and one place that decides what a consent needs.
 *
 * Nothing runs while the window is hidden (ADR-0007 R2, design-system §18): the subscription is dropped and
 * the heartbeat timer cleared, and both come back on the first visible moment. A hidden window that kept a
 * timer would defeat the reason the web view is destroyed after a grace period at all.
 */
import type { ActionId, Look } from './describe';
import { look as describe } from './describe';
import { en } from './messages';
import type { Bridge, Outcome } from './bridge';
import { plain } from './sanitize';
import type { ActivityItem, Snapshot } from './model';

export type ViewId =
  | 'status'
  | 'endpoints'
  | 'rules'
  | 'activity'
  | 'settings'
  | 'about'
  | 'firstrun'
  | 'wizard'
  | 'join'
  | 'invite';
export type ThemePref = 'system' | 'dark' | 'light';

/** The most Activity lines kept: the service holds the session; this is only what is on screen. */
const ACTIVITY_LIMIT = 200;

const PREFS_KEY = 'dnet.prefs.v1';
const ACKNOWLEDGED_KEY = 'dnet.acceptable-use.v1';

interface Prefs {
  theme: ThemePref;
  reduceMotion: boolean;
}

/** Storage can be missing or refuse (a private window, cleared data); the window works without it. */
function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Nothing to do: the preference lasts until the window closes.
  }
}

function loadPrefs(): Prefs {
  const fallback: Prefs = { theme: 'system', reduceMotion: false };
  const raw = read(PREFS_KEY);
  if (raw === null) return fallback;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return fallback;
    const p = parsed as Record<string, unknown>;
    return {
      theme: p.theme === 'dark' || p.theme === 'light' ? p.theme : 'system',
      reduceMotion: p.reduceMotion === true,
    };
  } catch {
    return fallback;
  }
}

export class AppState {
  snapshot = $state<Snapshot | null>(null);
  activity = $state<ActivityItem[]>([]);
  view = $state<ViewId>('status');
  /** The server an owner is adding a friend's device to, while the invite page is open (T188). */
  inviteFor = $state<string | null>(null);
  drawerOpen = $state(false);
  switcherOpen = $state(false);
  /** The Tier 2 consent is showing. */
  tier2Prompt = $state(false);
  /** Something the person asked for was refused; the service's reason, to show. */
  notice = $state<string | null>(null);
  /** The window's clock, ticking once a second while it is visible, to age the heartbeat. */
  now = $state(Date.now());
  visible = $state(true);
  theme = $state<ThemePref>('system');
  reduceMotion = $state(false);
  /** The acceptable-use acknowledgement has been given (FR-032). */
  acknowledged = $state(false);

  readonly look: Look | null = $derived(this.snapshot ? describe(this.snapshot) : null);

  private unsubscribe: (() => void) | null = null;
  private ticker: ReturnType<typeof setInterval> | null = null;

  constructor(readonly bridge: Bridge) {
    const prefs = loadPrefs();
    this.theme = prefs.theme;
    this.reduceMotion = prefs.reduceMotion;
    this.acknowledged = read(ACKNOWLEDGED_KEY) !== null;
  }

  // ------------------------------------------------------------------ lifecycle

  /** Begin listening. Safe to call again; it does nothing while already listening. */
  start(): void {
    if (this.unsubscribe !== null) return;
    this.unsubscribe = this.bridge.subscribe(
      (s) => {
        this.snapshot = s;
      },
      (a) => {
        this.activity = [a, ...this.activity].slice(0, ACTIVITY_LIMIT);
      },
    );
    this.ticker = setInterval(() => {
      this.now = Date.now();
    }, 1000);
    this.now = Date.now();
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
    if (this.ticker !== null) clearInterval(this.ticker);
    this.ticker = null;
  }

  /** The window became visible or hidden. Hidden: nothing runs. */
  setVisible(visible: boolean): void {
    this.visible = visible;
    if (visible) this.start();
    else this.stop();
  }

  // ------------------------------------------------------------------ preferences

  setTheme(theme: ThemePref): void {
    this.theme = theme;
    this.savePrefs();
  }

  setReduceMotion(on: boolean): void {
    this.reduceMotion = on;
    this.savePrefs();
  }

  private savePrefs(): void {
    write(PREFS_KEY, JSON.stringify({ theme: this.theme, reduceMotion: this.reduceMotion }));
  }

  /** Record the acknowledgement with the time and the exact text the person saw (design-system §13). */
  acknowledgeAcceptableUse(shown: string): void {
    this.acknowledged = true;
    write(ACKNOWLEDGED_KEY, JSON.stringify({ at: new Date().toISOString(), text: shown }));
  }

  // ------------------------------------------------------------------ actions

  go(view: ViewId): void {
    this.view = view;
    this.drawerOpen = false;
    this.notice = null;
  }

  /** Show what the service refused with, in its words. */
  private refused(outcome: Outcome): boolean {
    if (outcome.ok) return false;
    this.notice = outcome.reason;
    return true;
  }

  /**
   * Why a read from the service failed, in words for a person: the reason the service or the bridge gave, cleaned,
   * or the plain fact that it did not answer. A view shows this where the list would have been, so a failed
   * read is never an empty list.
   */
  reason(error: unknown): string {
    const given = typeof error === 'string' ? error : error instanceof Error ? error.message : '';
    const text = plain(given, 400).trim();
    return text === '' ? en.errors.service : text;
  }

  /** The one control. Turning it off is immediate; turning it on may need the Tier 2 consent first. */
  async toggle(): Promise<void> {
    const on = this.look?.switch.on ?? false;
    this.notice = null;
    if (on) {
      this.refused(await this.bridge.stabilize(false));
      return;
    }
    // Nothing is switched on before the acceptable-use acknowledgement (FR-032).
    if (!this.acknowledged) {
      this.go('firstrun');
      return;
    }
    const outcome = await this.bridge.stabilize(true);
    if (!outcome.ok && outcome.code === 'TierConsentRequired') {
      this.tier2Prompt = true;
      return;
    }
    this.refused(outcome);
  }

  /** The person answered the Tier 2 consent. Declining changes nothing. */
  async answerTier2(accept: boolean): Promise<void> {
    this.tier2Prompt = false;
    if (!accept) return;
    this.refused(await this.bridge.stabilize(true, { acknowledgeTier2: true }));
  }

  /** The one action a failure offers. */
  async act(id: ActionId): Promise<void> {
    switch (id) {
      case 'open-login':
        this.refused(await this.bridge.openLoginPage());
        break;
      case 'open-endpoints':
        this.go('endpoints');
        break;
      case 'open-activity':
        this.go('activity');
        break;
      case 'show-networks':
        this.drawerOpen = true;
        break;
      case 'retry':
        await this.toggle();
        break;
      case 'grant-rights':
        this.notice = en.help.grantRights;
        break;
    }
  }
}
