/**
 * The window's life (T206): the logo that shows the state, the opening, and the rule that behind all of it holds —
 * nothing moves unless something is really happening (design-system principle 11), and everything rests when the
 * person asks for no motion.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App.svelte';
import Intro from '../src/components/Intro.svelte';
import Mark from '../src/components/Mark.svelte';
import { createMockBridge, type MockOptions } from '../src/lib/mock';

const ACK = 'dnet.acceptable-use.v1';

function mount(options: MockOptions = {}) {
  window.localStorage.setItem(ACK, '{}');
  const bridge = createMockBridge({ probeMs: 5, disclosed: true, ...options });
  render(App, { props: { bridge } });
  return bridge;
}

const mark = (): SVGElement => document.querySelector('.plate svg.mark') as unknown as SVGElement;

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('the mark is the state, by shape', () => {
  const cases: [string, string[]][] = [
    ['off', []],
    ['probe', ['rise']],
    ['ok', ['lit']],
    ['warn', ['lit']],
    ['fail', ['lit', 'gap']],
  ];

  it.each(cases)('draws the %s doorway with its own pieces', (lamp, pieces) => {
    const { container } = render(Mark, { props: { lamp: lamp as 'off' } });
    const fill = [...container.querySelectorAll('.fill .lit, .fill .rise, .fill .gap')].map(
      (el) => ['lit', 'rise', 'gap'].find((name) => el.classList.contains(name)),
    );
    expect(fill).toEqual(pieces);
    expect(container.querySelector('svg')?.getAttribute('class')).toContain(`lamp-${lamp}`);
  });

  it('is decoration unless it is given a name, so a screen reader is not read a picture twice', () => {
    const plain = render(Mark, { props: {} });
    expect(plain.container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    cleanup();
    const named = render(Mark, { props: { label: 'DNet Engine' } });
    expect(named.container.querySelector('svg')?.getAttribute('role')).toBe('img');
    expect(named.container.querySelector('svg')?.getAttribute('aria-hidden')).toBeNull();
  });

  it('gives each mark its own clip, so two on one page do not share a doorway', () => {
    const a = render(Mark, { props: { lamp: 'probe' } });
    const first = a.container.querySelector('clipPath')?.id;
    const b = render(Mark, { props: { lamp: 'probe' } });
    const second = b.container.querySelectorAll('clipPath')[0]?.id;
    expect(first).toBeTruthy();
    expect(first).not.toBe(second);
  });

  it('in the window follows the connection: it is lit when connected and empty when not', async () => {
    const bridge = mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    expect(mark().getAttribute('class')).toContain('lamp-ok');
    bridge.set({ state: 'off' });
    await screen.findByRole('heading', { level: 1, name: 'Not connected' });
    await waitFor(() => expect(mark().getAttribute('class')).toContain('lamp-off'));
  });
});

describe('the opening', () => {
  it('waits for the window to be shown, then runs, and goes when it is over', async () => {
    const done = vi.fn();
    const { container, rerender } = render(Intro, { props: { running: false, ondone: done } });
    const intro = container.querySelector('.intro') as HTMLElement;
    expect(intro.classList.contains('go')).toBe(false);
    await rerender({ running: true, ondone: done });
    expect(intro.classList.contains('go')).toBe(true);
    // The veil is the last thing to finish; its end ends the opening, and only its own end (not a child's).
    await fireEvent.animationEnd(container.querySelector('.tunnel') as HTMLElement);
    expect(done).not.toHaveBeenCalled();
    await fireEvent.animationEnd(intro);
    expect(done).toHaveBeenCalledTimes(1);
  });

  it('ends at once on a key or a click, so nobody waits for a logo', async () => {
    const done = vi.fn();
    render(Intro, { props: { running: true, ondone: done } });
    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(done).toHaveBeenCalledTimes(1);
  });

  it('is not made at all for a person who asked for no motion', () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({ matches: true, media: query, addEventListener: () => undefined, removeEventListener: () => undefined }) as unknown as MediaQueryList,
    );
    mount({ initial: { state: 'ok' } });
    expect(document.querySelector('.intro')).toBeNull();
    // And the page is told, so every stylesheet rule that moves has a rule that rests.
    expect(document.documentElement.getAttribute('data-motion')).toBe('reduce');
  });

  it('plays for everyone else, and is not an element a screen reader meets', () => {
    mount({ initial: { state: 'ok' } });
    const intro = document.querySelector('.intro');
    expect(intro).not.toBeNull();
    expect(intro?.getAttribute('aria-hidden')).toBe('true');
  });
});

describe('nothing moves that is not happening', () => {
  it('the breath exists only while probing', () => {
    for (const lamp of ['off', 'ok', 'warn', 'fail'] as const) {
      const { container } = render(Mark, { props: { lamp } });
      expect(container.querySelector('.rise'), lamp).toBeNull();
      cleanup();
    }
    const { container } = render(Mark, { props: { lamp: 'probe' } });
    expect(container.querySelector('.rise')).not.toBeNull();
  });

  it('a state change sends one ring from the core, and a repeat of the same state sends none', async () => {
    const bridge = mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    const first = document.querySelector('.ping');
    expect(first).not.toBeNull();
    bridge.set({ state: 'ok' });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(document.querySelector('.ping')).toBe(first);
    bridge.set({ state: 'off' });
    await screen.findByRole('heading', { level: 1, name: 'Not connected' });
    await waitFor(() => expect(document.querySelector('.ping')).not.toBe(first));
  });
});
