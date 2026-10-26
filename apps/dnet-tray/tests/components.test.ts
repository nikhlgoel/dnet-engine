/**
 * The window as a person meets it: mounted with the mock bridge, driven through its controls, and checked with
 * axe (WCAG 2.2 AA) in every view. Colour contrast is asserted separately, from the tokens, because jsdom does
 * not load the stylesheet.
 */
import axe from 'axe-core';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App.svelte';
import { FAILURE_CAUSES } from '../src/lib/model';
import { createMockBridge, type MockController, type MockOptions } from '../src/lib/mock';

const ACK = 'dnet.acceptable-use.v1';

function mount(options: MockOptions = {}, acknowledged = true): MockController {
  if (acknowledged) window.localStorage.setItem(ACK, '{}');
  const bridge = createMockBridge({ probeMs: 5, disclosed: true, ...options });
  render(App, { props: { bridge } });
  return bridge;
}

async function violations(): Promise<string[]> {
  const result = await axe.run(document.body, {
    // jsdom has no layout and does not load the stylesheet: contrast is asserted from the tokens instead, and
    // "region" wants landmarks around the live regions that are deliberately outside the page body.
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  return result.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(' | ')})`);
}

/** The dialog that is open now. Closed consents stay in the page, so a role query would find them all. */
const openDialog = async (): Promise<HTMLElement> => {
  await waitFor(() => expect(document.querySelector('dialog[open]')).not.toBeNull());
  return document.querySelector('dialog[open]') as HTMLElement;
};

const go = async (name: string): Promise<void> => {
  await fireEvent.click(within(screen.getByRole('navigation')).getByRole('link', { name }));
};

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
});

describe('Status', () => {
  it('says the state, the reason and the control, with no accessibility violations', async () => {
    mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    expect(screen.getByRole('switch', { name: 'Stabilize this connection' })).toHaveProperty('ariaChecked', 'true');
    expect(await violations()).toEqual([]);
  });

  it('shows a failure in words, offers the one action, and announces it assertively', async () => {
    mount({ initial: { state: 'fail', cause: 'NoEndpointReachable' } });
    await screen.findByRole('heading', { level: 1 });
    const action = await screen.findByRole('button', { name: /check endpoints/i });
    expect(action).toBeTruthy();
    await waitFor(() => expect(document.querySelector('[role="alert"][aria-live="assertive"]')?.textContent).not.toBe(''));
    expect(await violations()).toEqual([]);
  });

  for (const cause of FAILURE_CAUSES) {
    it(`failure ${cause}: no violations, and an action`, async () => {
      mount({ initial: { state: 'fail', cause } });
      await screen.findByRole('heading', { level: 1 });
      expect(document.querySelectorAll('.row-actions .btn.primary')).toHaveLength(1);
      expect(await violations()).toEqual([]);
    });
  }

  it('the switch connects and disconnects', async () => {
    mount();
    const toggle = await screen.findByRole('switch');
    expect(toggle.getAttribute('aria-checked')).toBe('false');
    await fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByRole('switch').getAttribute('aria-checked')).toBe('true'));
    await waitFor(() => expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Connected'));
    await fireEvent.click(screen.getByRole('switch'));
    await waitFor(() => expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Not connected'));
  });

  it('the details control opens the drawer, and Escape closes it', async () => {
    mount({ initial: { state: 'ok' } });
    const more = await screen.findByRole('button', { name: 'Details' });
    expect(more.getAttribute('aria-expanded')).toBe('false');
    await fireEvent.click(more);
    expect(more.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('region', { name: 'Your networks' })).toBeTruthy();
    expect(await violations()).toEqual([]);
    await fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Your networks' })).toBeNull());
    expect(document.activeElement).toBe(more);
  });

  it('a hostile network name is shown as plain text, with its controls replaced', async () => {
    const mock = mount({ initial: { state: 'ok', networks: 'two' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    expect(mock.scenario.state).toBe('ok');
    expect(document.body.textContent).not.toMatch(/[\u202e\u200b\u0007]/);
  });
});

describe('every view', () => {
  const views: Array<[string, RegExp]> = [
    ['Endpoints', /endpoints/i],
    ['Rules', /rules/i],
    ['Activity', /activity/i],
    ['Settings', /settings/i],
  ];

  for (const [name, heading] of views) {
    it(`${name}: has its heading, marks itself as the current page, and has no violations`, async () => {
      mount();
      await screen.findByRole('switch');
      await go(name);
      await screen.findByRole('heading', { level: 1, name: heading });
      expect(within(screen.getByRole('navigation')).getByRole('link', { name }).getAttribute('aria-current')).toBe('page');
      expect(await violations()).toEqual([]);
    });
  }

  it('About lists the components it uses, with their licences', async () => {
    mount();
    await screen.findByRole('switch');
    await fireEvent.click(screen.getByRole('button', { name: 'About DNet Engine' }));
    await screen.findByRole('heading', { level: 1, name: 'About DNet Engine' });
    // Three components, each with its licence: the attribution the licences ask for (the names themselves are
    // checked for confinement by `cargo xtask lint-branding`, not here).
    expect(document.querySelectorAll('.parts > li')).toHaveLength(3);
    expect(document.body.textContent).toMatch(/GNU General Public License/);
    expect(document.body.textContent).toMatch(/MIT licence/);
    expect(document.body.textContent).toMatch(/not a free-software licence/);
    expect(await violations()).toEqual([]);
    await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await screen.findByRole('switch');
  });

  it('Endpoints lists them, and is locked while connected', async () => {
    mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    await go('Endpoints');
    await screen.findByText('endpoint-1');
    expect(screen.getByRole('button', { name: 'Add a server you already have' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByText(/Disconnect before changing/)).toBeTruthy();
  });

  it('Endpoints says plainly that setting a server up is not available in this build', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Endpoints');
    expect(await screen.findByText(/not available in this build/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Set one up for me' }).hasAttribute('disabled')).toBe(true);
  });

  it('Rules says which rules are best effort in the row, not in a tooltip', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Rules');
    await screen.findByRole('table');
    expect(screen.getByText(/Rules by program are best effort/)).toBeTruthy();
  });

  it('Settings: turning the encrypted-name block off asks first and states the consequence', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Settings');
    const block = await screen.findByRole('switch', { name: /encrypted name lookups/i });
    await waitFor(() => expect((block as HTMLInputElement).disabled).toBe(false));
    expect((block as HTMLInputElement).checked).toBe(true);

    await fireEvent.click(block);
    const dialog = await openDialog();
    expect(within(dialog).getByText(/will not apply/)).toBeTruthy();
    // Two buttons of equal weight; focus starts on the safe one.
    const buttons = within(dialog).getAllByRole('button', { hidden: true });
    expect(buttons.map((b) => b.textContent)).toEqual(['Keep blocking', 'Turn it off']);
    expect(buttons.some((b) => b.classList.contains('primary'))).toBe(false);
    expect(document.activeElement).toBe(buttons[0]);

    await fireEvent.click(buttons[1] as HTMLElement);
    await waitFor(() => expect((screen.getByRole('switch', { name: /encrypted name lookups/i }) as HTMLInputElement).checked).toBe(false));
  });

  it('Settings: declining the opt-out leaves the block on', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Settings');
    const block = (await screen.findByRole('switch', { name: /encrypted name lookups/i })) as HTMLInputElement;
    await waitFor(() => expect(block.disabled).toBe(false));
    await fireEvent.click(block);
    const dialog = await openDialog();
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Keep blocking', hidden: true }));
    expect(block.checked).toBe(true);
  });
});

describe('a read that fails is said, never drawn as an empty list', () => {
  it('Endpoints shows the reason and not "no endpoints yet"', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    vi.spyOn(mock, 'endpoints').mockRejectedValue('the control pipe could not be opened');
    await go('Endpoints');
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toBe('the control pipe could not be opened');
    expect(screen.queryByText(/No endpoints yet/)).toBeNull();
    expect(await violations()).toEqual([]);
  });

  it('Rules shows the reason and no table', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    vi.spyOn(mock, 'rules').mockRejectedValue(new Error('the service did not report the encrypted-name setting'));
    await go('Rules');
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toBe('the service did not report the encrypted-name setting');
    expect(screen.queryByRole('table')).toBeNull();
    expect(await violations()).toEqual([]);
  });

  it('Settings does not offer to change a setting it could not read', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    vi.spyOn(mock, 'rules').mockRejectedValue('');
    await go('Settings');
    const block = (await screen.findByRole('switch', { name: /encrypted name lookups/i })) as HTMLInputElement;
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toBe('The background service did not answer.');
    expect(block.disabled).toBe(true);
    expect(screen.queryByText(/Disconnect before changing/)).toBeNull();
  });
});

describe('first run', () => {
  it('asks for the acceptable-use acknowledgement before anything else, and records it', async () => {
    mount({}, false);
    const dialog = await openDialog();
    expect(within(dialog).getByText(/Before you connect on a managed network/)).toBeTruthy();
    await fireEvent.click(within(dialog).getByRole('button', { name: 'I understand', hidden: true }));
    await screen.findByText(/Some programs hide the sites they look up/);
    expect(window.localStorage.getItem(ACK)).toContain('Before you connect on a managed network');
    expect(await violations()).toEqual([]);
  });

  it('declining takes the person to Status without recording anything', async () => {
    mount({}, false);
    const dialog = await openDialog();
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Not now', hidden: true }));
    await screen.findByRole('switch');
    expect(window.localStorage.getItem(ACK)).toBeNull();
  });
});

describe('the keyboard', () => {
  it('Ctrl+K opens the switcher, filters it, and goes where it says', async () => {
    mount();
    await screen.findByRole('switch');
    await fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    const box = await screen.findByRole('textbox', { name: 'Go to…', hidden: true });
    await fireEvent.input(box, { target: { value: 'rul' } });
    const choices = within(box.closest('dialog') as HTMLElement).getAllByRole('button', { hidden: true });
    expect(choices.map((c) => c.textContent)).toEqual(['Rules']);
    await fireEvent.click(choices[0] as HTMLElement);
    await screen.findByRole('heading', { level: 1, name: /rules/i });
  });
});

describe('theme and motion', () => {
  it('apply as attributes of the root, where the tokens look for them', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Settings');
    await fireEvent.click(await screen.findByRole('radio', { name: 'Light' }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    await fireEvent.click(screen.getByRole('radio', { name: 'Follow the system' }));
    expect(document.documentElement.getAttribute('data-theme')).toBeNull();
    await fireEvent.click(screen.getByRole('checkbox', { name: 'Reduce motion' }));
    expect(document.documentElement.getAttribute('data-motion')).toBe('reduce');
  });
});
