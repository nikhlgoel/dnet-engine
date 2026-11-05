/**
 * The window's own frame (the title bar and its buttons): what each control asks the Rust side for, that the
 * page is given four named commands and nothing wider (ADR-0007 R4), and that the frame is simply absent where
 * there is no Rust side (a browser tab).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import axe from 'axe-core';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import { emit } from '@tauri-apps/api/event';
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import App from '../src/App.svelte';
import { createTauriChrome, type WindowChrome } from '../src/lib/chrome';
import { createMockBridge } from '../src/lib/mock';

const ACK = 'dnet.firstrun.acknowledged';

type Ask = () => Promise<void>;

interface Fake extends WindowChrome {
  minimize: Mock<Ask>;
  toggleMaximize: Mock<Ask>;
  close: Mock<Ask>;
  startDrag: Mock<Ask>;
  ready: Mock<Ask>;
  /** Tell the page the window became maximised (or not), as the Rust side does. */
  say(maximized: boolean): void;
}

function fakeChrome(): Fake {
  let listener: ((maximized: boolean) => void) | null = null;
  return {
    minimize: vi.fn<Ask>(async () => {}),
    toggleMaximize: vi.fn<Ask>(async () => {}),
    close: vi.fn<Ask>(async () => {}),
    startDrag: vi.fn<Ask>(async () => {}),
    ready: vi.fn<Ask>(async () => {}),
    onMaximized: async (l) => {
      listener = l;
      return () => {
        listener = null;
      };
    },
    say: (maximized) => listener?.(maximized),
  };
}

function mount(chrome: WindowChrome | null): void {
  window.localStorage.setItem(ACK, '{}');
  const bridge = createMockBridge({ probeMs: 5, disclosed: true });
  render(App, { props: { bridge, chrome } });
}

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
  clearMocks();
});

describe('the title bar', () => {
  it('names the window and has the three buttons a window has', async () => {
    mount(fakeChrome());
    const bar = await screen.findByRole('region', { name: 'Window' });
    expect(bar.textContent).toContain('DNet Engine');
    expect(screen.getByRole('button', { name: 'Minimize' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Maximize' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Close' })).toBeTruthy();
  });

  it('each button asks the Rust side for exactly its own thing', async () => {
    const chrome = fakeChrome();
    mount(chrome);
    await fireEvent.click(await screen.findByRole('button', { name: 'Minimize' }));
    expect(chrome.minimize).toHaveBeenCalledTimes(1);
    await fireEvent.click(screen.getByRole('button', { name: 'Maximize' }));
    expect(chrome.toggleMaximize).toHaveBeenCalledTimes(1);
    await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(chrome.close).toHaveBeenCalledTimes(1);
    expect(chrome.startDrag).not.toHaveBeenCalled();
  });

  it('says Restore, not Maximize, once the window is maximised, and back again', async () => {
    const chrome = fakeChrome();
    mount(chrome);
    await screen.findByRole('button', { name: 'Maximize' });
    chrome.say(true);
    expect(await screen.findByRole('button', { name: 'Restore' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Maximize' })).toBeNull();
    chrome.say(false);
    expect(await screen.findByRole('button', { name: 'Maximize' })).toBeTruthy();
  });

  it('is dragged by pressing the left button on the bar, and only there', async () => {
    const chrome = fakeChrome();
    mount(chrome);
    const bar = await screen.findByRole('region', { name: 'Window' });
    const drag = bar.querySelector('[data-drag]') as HTMLElement;
    expect(drag).toBeTruthy();

    await fireEvent.mouseDown(drag, { button: 2 });
    expect(chrome.startDrag).not.toHaveBeenCalled();
    await fireEvent.mouseDown(drag, { button: 0 });
    expect(chrome.startDrag).toHaveBeenCalledTimes(1);

    // Pressing a button is a click, never the start of a drag.
    await fireEvent.mouseDown(screen.getByRole('button', { name: 'Close' }), { button: 0 });
    expect(chrome.startDrag).toHaveBeenCalledTimes(1);
  });

  it('maximises or restores on the second press of a double-click, without starting a drag', async () => {
    const chrome = fakeChrome();
    mount(chrome);
    const bar = await screen.findByRole('region', { name: 'Window' });
    const drag = bar.querySelector('[data-drag]') as HTMLElement;
    // The system's move loop can swallow the release, so the double-click is read from the second press itself.
    await fireEvent.mouseDown(drag, { button: 0, detail: 1 });
    expect(chrome.startDrag).toHaveBeenCalledTimes(1);
    await fireEvent.mouseDown(drag, { button: 0, detail: 2 });
    expect(chrome.toggleMaximize).toHaveBeenCalledTimes(1);
    expect(chrome.startDrag).toHaveBeenCalledTimes(1);
  });

  it('tells the Rust side the page is up once the title bar is drawn, so the system frame is not brought back', async () => {
    const chrome = fakeChrome();
    mount(chrome);
    await screen.findByRole('region', { name: 'Window' });
    await waitFor(() => expect(chrome.ready).toHaveBeenCalledTimes(1));
  });

  it('is not drawn where there is no Rust side, so a browser tab has one frame, not two', async () => {
    mount(null);
    await screen.findByRole('navigation');
    expect(screen.queryByRole('region', { name: 'Window' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Close' })).toBeNull();
  });

  it('has nothing an accessibility check objects to', async () => {
    mount(fakeChrome());
    await screen.findByRole('region', { name: 'Window' });
    const result = await axe.run(document.body, { rules: { 'color-contrast': { enabled: false } } });
    expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
  });
});

describe('the real chrome', () => {
  function rust(handler: (command: string) => unknown): string[] {
    const asked: string[] = [];
    mockIPC(
      (command) => {
        if (command.startsWith('plugin:event|')) return undefined;
        asked.push(command);
        return handler(command);
      },
      { shouldMockEvents: true },
    );
    return asked;
  }

  it('asks for five named commands, one for each thing, and nothing else', async () => {
    const asked = rust(() => undefined);
    const chrome = createTauriChrome();
    await chrome.minimize();
    await chrome.toggleMaximize();
    await chrome.startDrag();
    await chrome.close();
    await chrome.ready();
    expect(asked).toEqual(['window_minimize', 'window_toggle_maximize', 'window_start_drag', 'window_close', 'window_ready']);
  });

  it('is told, by an event from the Rust side, when the window is maximised or not', async () => {
    rust(() => undefined);
    const chrome = createTauriChrome();
    const seen: boolean[] = [];
    const stop = await chrome.onMaximized((m) => seen.push(m));
    await emit('dnet:window', true);
    await emit('dnet:window', false);
    await waitFor(() => expect(seen).toEqual([true, false]));
    // Anything that is not a plain true or false is not a state, and is not believed.
    await emit('dnet:window', 'yes');
    await emit('dnet:window', { maximized: true });
    stop();
    await emit('dnet:window', true);
    await new Promise((r) => setTimeout(r, 20));
    expect(seen).toEqual([true, false]);
  });

  it('does not throw when the Rust side refuses a command: the window just does not move', async () => {
    rust(() => {
      throw new Error('refused');
    });
    const chrome = createTauriChrome();
    await expect(chrome.minimize()).resolves.toBeUndefined();
    await expect(chrome.close()).resolves.toBeUndefined();
  });
});

describe('what the page is allowed to ask of the window (ADR-0007 R4)', () => {
  const root = join(__dirname, '..', 'src-tauri');
  const read = (p: string): string => readFileSync(join(root, p), 'utf8');

  const declared = [...(read('build.rs').match(/COMMANDS: &\[&str\] = &\[([\s\S]*?)\];/)?.[1] ?? '').matchAll(/"([a-z_]+)"/g)].map((m) => m[1] as string);
  const granted = (JSON.parse(read('capabilities/default.json')) as { permissions: string[] }).permissions
    .filter((p) => p.startsWith('allow-'))
    .map((p) => p.slice('allow-'.length).replaceAll('-', '_'));
  const handled = [...(read('src/shell.rs').match(/generate_handler!\[([\s\S]*?)\]/)?.[1] ?? '').matchAll(/([a-z_]+),/g)].map((m) => m[1] as string);

  it('every command is declared, granted and handled, and none of them is only one of those', () => {
    expect(declared.length).toBeGreaterThan(20);
    expect([...granted].sort()).toEqual([...declared].sort());
    expect([...handled].sort()).toEqual([...declared].sort());
  });

  it('the five window commands are among them', () => {
    for (const name of ['window_minimize', 'window_toggle_maximize', 'window_start_drag', 'window_close', 'window_ready']) {
      expect(declared).toContain(name);
    }
  });

  it('no general window permission is granted: only the named commands and listening for events', () => {
    const all = (JSON.parse(read('capabilities/default.json')) as { permissions: string[] }).permissions;
    expect(all.filter((p) => p.startsWith('core:') && !p.startsWith('core:event:'))).toEqual([]);
  });

  it('the window is created without the system frame, so the page draws it', () => {
    expect(read('src/shell.rs')).toMatch(/\.decorations\(false\)/);
  });
});
