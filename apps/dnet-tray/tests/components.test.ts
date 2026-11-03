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
    ['Servers', /servers/i],
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

  /** FR-033, Principle VI: what the obfuscation hides, and what it does not, said where a person looks for it. */
  it('About says the tunnel is not hidden, nor how much is sent or where it goes', async () => {
    mount();
    await screen.findByRole('switch');
    await fireEvent.click(screen.getByRole('button', { name: 'About DNet Engine' }));
    await screen.findByRole('heading', { level: 1, name: 'About DNet Engine' });
    const text = document.body.textContent ?? '';
    expect(text).toMatch(/content/);
    expect(text).toMatch(/does not hide that you are using a tunnel/);
    expect(text).toMatch(/how much you send and receive/);
    expect(text).toMatch(/where the tunnel’s packets go/);
  });

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

  it('Servers lists them, and is locked while connected', async () => {
    mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    await go('Servers');
    await screen.findByText('endpoint-1');
    expect(screen.getByRole('button', { name: 'Add a server you already have' }).hasAttribute('disabled')).toBe(true);
    expect(screen.getByText(/Disconnect before changing/)).toBeTruthy();
  });

  it('Servers offers to set one up, which opens the guide, and says what a server is', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Servers');
    expect(await screen.findByText(/small computer of yours/)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Set up a server for me' }));
    await screen.findByRole('heading', { level: 1, name: 'Set up your server' });
  });

  it('Activity lists the parts with their state in words, how long, and why, and no violations', async () => {
    mount({ initial: { state: 'ok' } });
    await screen.findByRole('heading', { level: 1, name: 'Connected' });
    await go('Activity');
    const parts = await screen.findByRole('list', { name: 'Parts of the system' });
    const items = within(parts).getAllByRole('listitem');
    expect(items.length).toBeGreaterThan(2);
    const text = items.map((i) => i.textContent ?? '').join('\n');
    expect(text).toMatch(/Working/);
    expect(text).toMatch(/for \d+ (s|min|h)/);
    expect(await violations()).toEqual([]);
  });

  it('Activity says plainly when the service is too old to list its parts, and shows no part as fine', async () => {
    mount({ noComponents: true });
    await screen.findByRole('switch');
    await go('Activity');
    expect(await screen.findByText(/too old to list its parts/)).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Parts of the system' })).toBeNull();
    expect(screen.queryByText(/Working/)).toBeNull();
  });

  it('Activity shows a failed part with its reason whole', async () => {
    mount({ initial: { state: 'fail', cause: 'NoUsablePath' } });
    await screen.findByRole('switch');
    await go('Activity');
    const parts = await screen.findByRole('list', { name: 'Parts of the system' });
    expect(within(parts).getByText('Failed')).toBeTruthy();
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

describe('Rules: a person adds and removes their own (T108)', () => {
  it('adds a rule for a site, shows it with what it matches, and removes it', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    await go('Rules');
    await screen.findByRole('table');
    await fireEvent.change(screen.getByLabelText(/^match$/i), { target: { value: 'domain_suffix' } });
    await fireEvent.input(screen.getByLabelText(/site or address/i), { target: { value: 'example.com' } });
    await fireEvent.change(screen.getByLabelText(/^send it$/i), { target: { value: 'bypass' } });
    await fireEvent.click(screen.getByRole('button', { name: /add rule/i }));
    const row = await screen.findByText('example.com and its subdomains');
    expect(row).toBeTruthy();
    expect((await mock.rules()).rules.filter((r) => !r.builtin)).toHaveLength(1);
    expect(await violations()).toEqual([]);

    await fireEvent.click(screen.getByRole('button', { name: /remove the rule for example.com/i }));
    await waitFor(() => expect(screen.queryByText('example.com and its subdomains')).toBeNull());
  });

  it('a refused rule shows the service’s reason and adds nothing', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    await go('Rules');
    await screen.findByRole('table');
    await fireEvent.change(screen.getByLabelText(/^match$/i), { target: { value: 'ip_cidr' } });
    await fireEvent.input(screen.getByLabelText(/site or address/i), { target: { value: 'not a range' } });
    await fireEvent.click(screen.getByRole('button', { name: /add rule/i }));
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toMatch(/address range/);
    expect((await mock.rules()).rules.filter((r) => !r.builtin)).toHaveLength(0);
  });

  it('built-in rules have no remove button', async () => {
    mount();
    await screen.findByRole('switch');
    await go('Rules');
    await screen.findByRole('table');
    expect(screen.queryAllByRole('button', { name: /remove the rule/i })).toHaveLength(0);
  });
});

describe('Settings: aggressive speed mode (Brutal, T105)', () => {
  const figures = async (up: string, down: string): Promise<void> => {
    await fireEvent.input(await screen.findByLabelText(/upload speed/i), { target: { value: up } });
    await fireEvent.input(screen.getByLabelText(/download speed/i), { target: { value: down } });
  };
  const modeSwitch = async (): Promise<HTMLInputElement> => {
    const s = (await screen.findByRole('switch', { name: /aggressive speed mode/i })) as HTMLInputElement;
    await waitFor(() => expect(s.disabled).toBe(false));
    return s;
  };

  it('turning it on shows the warning first, with equal choices and focus on the safe one, then sends both figures', async () => {
    const mock = mount();
    const set = vi.spyOn(mock, 'setBrutal');
    await screen.findByRole('switch');
    await go('Settings');
    const mode = await modeSwitch();
    expect(mode.checked).toBe(false);
    await figures('50', '200');

    await fireEvent.click(mode);
    const dialog = await openDialog();
    expect(within(dialog).getByText(/worse for everyone around you/)).toBeTruthy();
    const buttons = within(dialog).getAllByRole('button', { hidden: true });
    expect(buttons.map((b) => b.textContent)).toEqual(['Keep it off', 'Turn it on']);
    expect(document.activeElement).toBe(buttons[0]);
    expect(set).not.toHaveBeenCalled();

    await fireEvent.click(buttons[1] as HTMLElement);
    await waitFor(() => expect(set).toHaveBeenCalledWith('hy2-default', { up: 50, down: 200 }));
    await waitFor(() => expect(mode.checked).toBe(true));
    expect(await violations()).toEqual([]);
  });

  it('declining leaves it off and sends nothing', async () => {
    const mock = mount();
    const set = vi.spyOn(mock, 'setBrutal');
    await screen.findByRole('switch');
    await go('Settings');
    const mode = await modeSwitch();
    await figures('50', '200');
    await fireEvent.click(mode);
    const dialog = await openDialog();
    await fireEvent.click(within(dialog).getByRole('button', { name: 'Keep it off', hidden: true }));
    expect(mode.checked).toBe(false);
    expect(set).not.toHaveBeenCalled();
  });

  it('without both figures it says what is missing and does not ask', async () => {
    const mock = mount();
    const set = vi.spyOn(mock, 'setBrutal');
    await screen.findByRole('switch');
    await go('Settings');
    const mode = await modeSwitch();
    await figures('50', '');
    await fireEvent.click(mode);
    expect(document.querySelector('dialog[open]')).toBeNull();
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toMatch(/both speeds/i);
    expect(mode.checked).toBe(false);
    expect(set).not.toHaveBeenCalled();
  });

  it('turning it off needs no consent', async () => {
    const mock = mount({ brutalOn: true });
    const set = vi.spyOn(mock, 'setBrutal');
    await screen.findByRole('switch');
    await go('Settings');
    const mode = await modeSwitch();
    expect(mode.checked).toBe(true);
    await fireEvent.click(mode);
    expect(document.querySelector('dialog[open]')).toBeNull();
    await waitFor(() => expect(set).toHaveBeenCalledWith('hy2-default', null));
    await waitFor(() => expect(mode.checked).toBe(false));
  });
});

describe('a read that fails is said, never drawn as an empty list', () => {
  it('Servers shows the reason and not "no servers yet"', async () => {
    const mock = mount();
    await screen.findByRole('switch');
    vi.spyOn(mock, 'endpoints').mockRejectedValue('the control pipe could not be opened');
    await go('Servers');
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toBe('the control pipe could not be opened');
    expect(screen.queryByText(/You have no servers yet/)).toBeNull();
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

describe('Changes waiting for approval (T160)', () => {
  it('lists a waiting change in the Servers view with what it does, and approving it removes it', async () => {
    const bridge = mount();
    const id = bridge.hold('Adding the server "home" at 203.0.113.9');
    const approving = vi.spyOn(bridge, 'approveChange');
    const dropping = vi.spyOn(bridge, 'rejectChange');
    await go('Servers');
    const approve = await screen.findByRole('button', { name: /Approve: Adding the server "home" at 203\.0\.113\.9/ });
    expect(screen.getByRole('heading', { level: 2, name: 'Waiting for your approval' })).toBeTruthy();
    expect(await violations()).toEqual([]);

    await fireEvent.click(approve);
    await waitFor(() => expect(screen.queryByRole('button', { name: /^Approve:/ })).toBeNull());
    expect(await screen.findByText('Approved and applied.')).toBeTruthy();
    expect(approving).toHaveBeenCalledWith(id);
    expect(dropping).not.toHaveBeenCalled();
    expect(await bridge.pending()).toEqual([]);
  });

  it('drops a waiting change without applying it', async () => {
    const bridge = mount();
    const id = bridge.hold('Sending example.com around the tunnel');
    const approving = vi.spyOn(bridge, 'approveChange');
    const dropping = vi.spyOn(bridge, 'rejectChange');
    await go('Rules');
    await fireEvent.click(await screen.findByRole('button', { name: /^Drop: Sending example\.com/ }));
    expect(await screen.findByText('Dropped. The change was not applied.')).toBeTruthy();
    expect(dropping).toHaveBeenCalledWith(id);
    expect(approving).not.toHaveBeenCalled();
    expect(await bridge.pending()).toEqual([]);
  });

  it('shows nothing at all when nothing waits', async () => {
    mount();
    await go('Servers');
    await screen.findByRole('heading', { level: 1, name: 'Servers' });
    expect(screen.queryByText('Waiting for your approval')).toBeNull();
  });

  it('says why when the approval did not go through, in the words it was given', async () => {
    const bridge = mount();
    bridge.hold('Adding the server "home"');
    await go('Servers');
    const approve = await screen.findByRole('button', { name: /^Approve:/ });
    // The change goes away behind the window's back (dropped by dnetctl, or it expired).
    await bridge.rejectChange((await bridge.pending())[0]!.id);
    await fireEvent.click(approve);
    expect(await screen.findByText(/no change is waiting under that name/)).toBeTruthy();
  });
});
