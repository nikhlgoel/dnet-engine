/**
 * The guided server setup as a person meets it: mounted with the mock bridge and driven by its buttons. The
 * mock stands in for the background service; what the service itself does is tested in Rust.
 */
import axe from 'axe-core';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App.svelte';
import { createMockBridge, type MockController, type MockOptions } from '../src/lib/mock';

const ACK = 'dnet.acceptable-use.v1';

function mount(options: MockOptions = {}): MockController {
  window.localStorage.setItem(ACK, '{}');
  const bridge = createMockBridge({ probeMs: 5, disclosed: true, ...options });
  render(App, { props: { bridge } });
  return bridge;
}

async function violations(): Promise<string[]> {
  const result = await axe.run(document.body, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  return result.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(' | ')})`);
}

const click = (name: string | RegExp) => fireEvent.click(screen.getByRole('button', { name }));
const next = () => click('Next');
/** The alerts of the wizard itself; the window has a live region of its own that is always present. */
const alerts = (): HTMLElement[] => within(document.querySelector('section.view') as HTMLElement).queryAllByRole('alert');

async function openWizard(options: MockOptions = {}): Promise<MockController> {
  const mock = mount(options);
  await screen.findByRole('switch');
  await fireEvent.click(within(screen.getByRole('navigation')).getByRole('link', { name: 'Servers' }));
  await click('Set up a server for me');
  await screen.findByRole('heading', { level: 1, name: 'Set up your server' });
  return mock;
}

/** From the first screen to the step called `title`, choosing Oracle and Arm on the way. */
async function reach(title: string): Promise<void> {
  await click(/Use my own server/);
  await click(/Oracle Cloud, free/);
  await click('Continue');
  for (let i = 0; i < 12; i++) {
    const heading = screen.getAllByRole('heading', { level: 2 }).at(0)?.textContent ?? '';
    if (heading === title) return;
    if (heading === 'Choose the kind of server') {
      await fireEvent.click(screen.getByRole('radio', { name: /Arm/ }));
      await waitFor(() => expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(false));
    }
    await next();
  }
  throw new Error(`never reached "${title}"`);
}

const REPORT = 'root@vm:~# sh dnet-setup.sh\nDNET-BOOTSTRAP-REPORT {"version":1}\nroot@vm:~# ';

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('the first screen', () => {
  it('offers two ways, the server one recommended, each with its good and not-so-good sides', async () => {
    await openWizard();
    const groups = screen.getAllByRole('group');
    const server = groups.find((g) => within(g).queryByText('Your own server'))!;
    const local = groups.find((g) => within(g).queryByText('Without a server'))!;
    expect(within(server).getByText('Recommended')).toBeTruthy();
    expect(within(local).queryByText('Recommended')).toBeNull();
    // What each gives and lacks, as words and not only as marks.
    expect(within(local).getAllByText('Not included').length).toBe(2);
    expect(within(local).getByText(/cannot get past a network that blocks/i)).toBeTruthy();
    expect(within(server).getAllByText(/Included/).length).toBeGreaterThan(2);
    expect(await violations()).toEqual([]);
  });

  it('says the second way is not available yet and does not let it be chosen', async () => {
    await openWizard();
    const button = screen.getByRole('button', { name: /Use without a server/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(screen.getAllByText(/Not available in this version yet/).length).toBeGreaterThan(0);
  });
});

describe('the steps', () => {
  it('Oracle: states what the free server costs and when it was checked, before any step asks for anything', async () => {
    await openWizard();
    await click(/Use my own server/);
    await click(/Oracle Cloud, free/);
    expect(screen.getByText(/credit card/i)).toBeTruthy();
    expect(screen.getByText(/50 Mbps/)).toBeTruthy();
    expect(screen.getByText(/Checked on 2026-10-30/)).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('shows where it is, and goes back', async () => {
    await openWizard();
    await reach('Create your Oracle Cloud account');
    expect(screen.getByText(/Step 2 of 8/)).toBeTruthy();
    await click('Back');
    expect(screen.getByText(/Step 1 of 8/)).toBeTruthy();
    expect(screen.getByRole('heading', { level: 2, name: 'What you need' })).toBeTruthy();
  });

  it('every step reads as where to go, what to do, and what you should see', async () => {
    await openWizard();
    await reach('Create the server');
    expect(screen.getByText(/What you should see/)).toBeTruthy();
    expect(screen.getByText(/different from what you see/i)).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('choosing the kind of server asks the service for the script, and cannot go on without it', async () => {
    const mock = await openWizard();
    const prepare = vi.spyOn(mock, 'prepareServer');
    await reach('Choose the kind of server');
    expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true);
    await fireEvent.click(screen.getByRole('radio', { name: /Arm/ }));
    await waitFor(() => expect(prepare).toHaveBeenCalledWith('arm64'));
    await waitFor(() => expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(false));
  });

  it('a build that cannot set servers up says so here, before the person does any work at the provider', async () => {
    await openWizard({ noServerDownloads: true });
    await reach('Choose the kind of server');
    await fireEvent.click(screen.getByRole('radio', { name: /AMD/ }));
    await waitFor(() => expect(alerts().length).toBe(1));
    expect(alerts()[0]!.textContent).toMatch(/not available in this build/);
    expect((screen.getByRole('button', { name: 'Next' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('lists the three ports the service named, to copy', async () => {
    await openWizard();
    await reach('Open three ports');
    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('cell').map((c) => c.textContent));
    expect(rows).toEqual([
      ['UDP', '51820', '0.0.0.0/0'],
      ['UDP', '44443', '0.0.0.0/0'],
      ['TCP', '8443', '0.0.0.0/0'],
    ]);
    expect(await violations()).toEqual([]);
  });

  it('builds the connection command only from a plausible address, and shows the block to paste', async () => {
    await openWizard();
    await reach('Run the setup on your server');
    const address = screen.getByLabelText(/Server address/);
    await fireEvent.input(address, { target: { value: 'x;rm -rf /' } });
    expect(screen.getByTestId('ssh-command').textContent).toContain('<server address>');
    expect(screen.getByTestId('ssh-command').textContent).not.toContain('rm -rf');
    await fireEvent.input(address, { target: { value: '203.0.113.10' } });
    expect(screen.getByTestId('ssh-command').textContent).toContain('ubuntu@203.0.113.10');
    const block = (screen.getByLabelText('Paste this block in the terminal') as HTMLTextAreaElement).value;
    expect(block.startsWith("cat > dnet-setup.sh <<'DNET_SETUP_EOF'\n#!/bin/sh")).toBe(true);
    expect(block.endsWith('sudo sh dnet-setup.sh')).toBe(true);
  });

  it('copies on request and says so; where copying is refused it says to select and copy by hand', async () => {
    await openWizard();
    await reach('Run the setup on your server');
    const write = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText: write } });
    await fireEvent.click(screen.getAllByRole('button', { name: /^Copy/ })[0]!);
    await waitFor(() => expect(write).toHaveBeenCalled());
    expect(await screen.findByText('Copied')).toBeTruthy();

    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('no')) } });
    await fireEvent.click(screen.getAllByRole('button', { name: /^Copy/ })[0]!);
    expect(await screen.findByText(/select the text and press Ctrl\+C/i)).toBeTruthy();
  });
});

describe('bringing the result back', () => {
  async function toPaste(): Promise<void> {
    await reach('Bring the result back');
  }

  it('a result the service refuses is shown with its reason, and nothing is lost', async () => {
    await openWizard();
    await toPaste();
    await fireEvent.input(screen.getByLabelText(/What the server printed/), { target: { value: 'just a prompt' } });
    await fireEvent.input(screen.getByLabelText(/Server address/), { target: { value: '203.0.113.10' } });
    await click('Check and add the server');
    await waitFor(() => expect(alerts().length).toBe(1));
    expect(alerts()[0]!.textContent).toMatch(/printed no bootstrap report/);
    expect((screen.getByLabelText(/What the server printed/) as HTMLTextAreaElement).value).toBe('just a prompt');
  });

  it('a good result adds the server, clears the pasted text, and offers to turn it on', async () => {
    const mock = await openWizard();
    await toPaste();
    await fireEvent.input(screen.getByLabelText(/Name/), { target: { value: 'Frankfurt' } });
    await fireEvent.input(screen.getByLabelText(/Server address/), { target: { value: '203.0.113.10' } });
    await fireEvent.input(screen.getByLabelText(/What the server printed/), { target: { value: REPORT } });
    await click('Check and add the server');
    await screen.findByRole('heading', { level: 2, name: 'Turn it on' });
    expect((await mock.endpoints()).map((e) => e.label)).toContain('Frankfurt');
    await click('Go to Status');
    await screen.findByRole('switch');
  });

  it('is not offered while the connection is on, because servers change only while it is off', async () => {
    await openWizard({ initial: { state: 'ok' } });
    await toPaste();
    expect(screen.getByText(/Turn the connection off first/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Check and add the server' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
