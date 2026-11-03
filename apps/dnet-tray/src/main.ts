// The one stylesheet that defines a colour, a size or a duration lives with the design (ADR-0007 R7).
import '../../../docs/design/tokens.css';
import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { isTauri } from './lib/bridge';
import { createMockBridge } from './lib/mock';

async function bridge() {
  if (isTauri()) {
    const { createTauriBridge } = await import('./lib/tauri');
    return createTauriBridge();
  }
  // A browser tab with no service behind it: the design's own scenarios, so the window can be developed and
  // looked at. Never reached inside the real app, which has `__TAURI_INTERNALS__`. New servers and rules that send
  // traffic around the tunnel wait for approval, as the installed service makes them (T160).
  const mock = createMockBridge({ initial: { state: 'ok', networks: 'two' }, disclosed: true, holdChanges: true });
  // In development only (the condition is false in a production build, so this is removed from it): the mock
  // can be driven from the console, e.g. `__dnetMock.set({ state: 'fail', cause: 'NoUsablePath' })`.
  if (import.meta.env.DEV) (window as unknown as { __dnetMock: unknown }).__dnetMock = mock;
  return mock;
}

const target = document.getElementById('app');
if (target === null) throw new Error('the page has no #app element');
mount(App, { target, props: { bridge: await bridge() } });
