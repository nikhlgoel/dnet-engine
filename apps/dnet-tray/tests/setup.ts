// jsdom has no canvas, no <dialog> modality, no matchMedia and no ResizeObserver. These stand-ins give the
// components somewhere to run; they draw nothing, and the tests that matter assert on the DOM and the logic.
import { afterEach, vi } from 'vitest';

const context = new Proxy({} as Record<string | symbol, unknown>, {
  get: (target, property) =>
    property in target ? target[property] : () => ({ addColorStop: () => undefined, width: 0 }),
  set: (target, property, value) => {
    target[property] = value;
    return true;
  },
});

HTMLCanvasElement.prototype.getContext = (() => context) as unknown as HTMLCanvasElement['getContext'];

HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement): void {
  this.setAttribute('open', '');
};
HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement): void {
  this.removeAttribute('open');
};

class StubResizeObserver {
  constructor(private readonly callback: ResizeObserverCallback) {}
  observe(): void {
    // Report one size so the scene lays itself out once.
    queueMicrotask(() => this.callback([], this as unknown as ResizeObserver));
  }
  unobserve(): void {}
  disconnect(): void {}
}
vi.stubGlobal('ResizeObserver', StubResizeObserver);

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }) as MediaQueryList,
});

afterEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.removeAttribute('data-motion');
  document.body.replaceChildren();
});
