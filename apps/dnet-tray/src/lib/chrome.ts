/**
 * The window's own frame: what the title bar may ask of the Rust side (ADR-0007 R4).
 *
 * Four named commands and one event, and nothing wider: the page is not given the framework's general window
 * permissions, so it cannot move, resize, hide or reach anything of the window except through these. Each command
 * acts on this program's own window and takes no argument, so there is nothing for a hostile string to steer.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

export interface WindowChrome {
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  /** Close asks the program to hide the window, as the system's own close button did; the tray keeps running. */
  close(): Promise<void>;
  /** Begin moving the window with the pointer, which the system then follows. */
  startDrag(): Promise<void>;
  /** Say the title bar is drawn. Without it the Rust side gives the window its system frame back, so a page that
   * failed to start never leaves a window with no way to move or close it. */
  ready(): Promise<void>;
  /** Told whenever the window becomes maximised or stops being; returns the way to stop being told. */
  onMaximized(listener: (maximized: boolean) => void): Promise<() => void>;
}

/** A command that the Rust side refused or could not run leaves the window as it was: there is nothing to tell. */
async function ask(command: string): Promise<void> {
  try {
    await invoke(command);
  } catch {
    /* the window did not move; the person can press again */
  }
}

export function createTauriChrome(): WindowChrome {
  return {
    minimize: () => ask('window_minimize'),
    toggleMaximize: () => ask('window_toggle_maximize'),
    close: () => ask('window_close'),
    startDrag: () => ask('window_start_drag'),
    ready: () => ask('window_ready'),
    async onMaximized(listener) {
      // Only a plain true or false is a state; anything else is not believed.
      return listen<unknown>('dnet:window', (event) => {
        if (typeof event.payload === 'boolean') listener(event.payload);
      });
    },
  };
}
