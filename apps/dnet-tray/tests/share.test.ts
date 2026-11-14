/**
 * Sharing a server as a person meets it (T188): a friend asks to join, the owner adds the friend's device and sends an
 * invite back, and the friend pastes it. Mounted with the mock bridge and driven by its buttons; what the service
 * does is tested in Rust.
 */
import axe from 'axe-core';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../src/App.svelte';
import { createMockBridge, type MockController, type MockOptions } from '../src/lib/mock';

const ACK = 'dnet.acceptable-use.v1';
const REQUEST =
  'DNET-DEVICE-REQUEST {"version":1,"name":"Ravi laptop","public_key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="}';
const REPORT = 'root@vm:~# sh dnet-device.sh\nDNET-DEVICE-REPORT {"version":1}\nroot@vm:~# ';
const INVITE = 'DNET-INVITE-1:bW9jay1pbnZpdGU';

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

async function onServers(options: MockOptions = {}): Promise<MockController> {
  const mock = mount(options);
  await screen.findByRole('switch');
  await fireEvent.click(within(screen.getByRole('navigation')).getByRole('link', { name: 'Servers' }));
  await screen.findByRole('heading', { level: 1, name: 'Servers' });
  return mock;
}

/** The alert of the page itself; the window has a live region of its own that is always present. */
const pageAlert = (): Promise<HTMLElement> =>
  within(document.querySelector('section.view') as HTMLElement).findByRole('alert');

async function paste(label: string | RegExp, text: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText(label), { target: { value: text } });
}

beforeEach(() => {
  window.localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('joining a friend’s server', () => {
  async function openJoin(options: MockOptions = {}): Promise<void> {
    await onServers(options);
    await click('Join a friend’s server');
    await screen.findByRole('heading', { level: 1, name: 'Join a friend’s server' });
  }

  it('asks for the name first and shows what to send, which holds no secret', async () => {
    await openJoin();
    expect(screen.queryByTestId('join-request')).toBeNull();
    expect(screen.getByText(/Make your request first/)).toBeTruthy();
    await paste('A name for this computer', 'Ravi laptop');
    await click('Make my request');
    const sent = await screen.findByTestId('join-request');
    expect(sent.textContent).toMatch(/^DNET-DEVICE-REQUEST /);
    expect(sent.textContent).not.toMatch(/private/i);
    // The invite step is there once the request is.
    expect(screen.getByLabelText('The invite')).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('refuses a name the service would refuse, in its words, and shows no request', async () => {
    await openJoin();
    await paste('A name for this computer', "Rav'i");
    await click('Make my request');
    expect(await pageAlert()).toBeTruthy();
    expect(screen.queryByTestId('join-request')).toBeNull();
  });

  it('adds the server when the invite is pasted, and says where it is', async () => {
    await openJoin();
    await click('Make my request');
    await screen.findByTestId('join-request');
    await paste('The invite', `Hi, here you go: ${INVITE}`);
    await paste(/A name for this server/, 'Ravi server');
    await click('Add the server');
    await screen.findByRole('heading', { name: 'The server is added' });
    await click('Go to Servers');
    expect(await screen.findByText('Ravi server')).toBeTruthy();
  });

  it('says why an invite cannot be used, and keeps the request', async () => {
    await openJoin();
    await click('Make my request');
    await screen.findByTestId('join-request');
    await paste('The invite', 'this is not an invite');
    await click('Add the server');
    const alert = await pageAlert();
    expect(alert.textContent).toContain('not an invite');
    expect(screen.getByTestId('join-request')).toBeTruthy();
  });

  it('waits for the approval when changes are held, and the server arrives once approved', async () => {
    await openJoin({ holdChanges: true });
    await click('Make my request');
    await screen.findByTestId('join-request');
    await paste('The invite', INVITE);
    await click('Add the server');
    expect(await screen.findByText(/waits for your approval above/)).toBeTruthy();
    // The pasted invite is not kept in the page.
    expect(document.body.textContent).not.toContain(INVITE);
    await fireEvent.click(await screen.findByRole('button', { name: /^Approve: Adding the server/ }));
    await screen.findByRole('heading', { name: 'The server is added' });
  });

  it('says so when the approval was dropped, and the server is not there', async () => {
    await openJoin({ holdChanges: true });
    await click('Make my request');
    await screen.findByTestId('join-request');
    await paste('The invite', INVITE);
    await click('Add the server');
    await fireEvent.click(await screen.findByRole('button', { name: /^Drop: Adding the server/ }));
    expect(await screen.findByText(/The server was not added/)).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'The server is added' })).toBeNull();
  });
});

describe('adding a friend’s device', () => {
  async function openInvite(options: MockOptions = {}): Promise<void> {
    await onServers(options);
    await click('Add a friend’s device to endpoint-1');
    await screen.findByRole('heading', { level: 1, name: 'Add a friend’s device' });
  }

  async function toTheScript(): Promise<void> {
    await paste('Your friend’s request', REQUEST);
    await click('Make the script');
    await screen.findByRole('heading', { name: /Step 2/ });
  }

  it('is offered for each server and names the server it is for', async () => {
    await openInvite();
    expect(screen.getByText('endpoint-1')).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('turns the friend’s request into a script to paste, and says what to expect', async () => {
    await openInvite();
    await toTheScript();
    const block = screen.getByLabelText('Commands to paste') as HTMLTextAreaElement;
    expect(block.value).toContain('cat > dnet-device.sh');
    expect(block.value).toContain('sudo sh dnet-device.sh');
    expect(screen.getByText(/prints one line that starts with DNET-DEVICE-REPORT/)).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('refuses text that is not a request, with the service’s reason', async () => {
    await openInvite();
    await paste('Your friend’s request', 'hello');
    await click('Make the script');
    const alert = await pageAlert();
    expect(alert.textContent).toContain('not a device request');
    expect(screen.queryByLabelText('Commands to paste')).toBeNull();
  });

  it('makes the invite from what the server printed and says whom it is for', async () => {
    await openInvite();
    await toTheScript();
    await paste('What the server printed', REPORT);
    await click('Make the invite');
    const invite = await screen.findByTestId('invite-text');
    expect(invite.textContent).toBe(INVITE);
    expect(screen.getByText(/Ravi laptop has the address 10\.9\.0\.3/)).toBeTruthy();
    // It says plainly what is not here yet.
    expect(screen.getByText(/Taking a device off the server again is not in this window yet/)).toBeTruthy();
    expect(await violations()).toEqual([]);
  });

  it('refuses a result that is not one, and keeps the script', async () => {
    await openInvite();
    await toTheScript();
    await paste('What the server printed', 'nothing useful');
    await click('Make the invite');
    expect((await pageAlert()).textContent).toContain('printed no device report');
    expect(screen.getByLabelText('Commands to paste')).toBeTruthy();
  });

  it('waits for the approval, because an invite holds the server’s details, and then shows it', async () => {
    await openInvite({ holdChanges: true });
    await toTheScript();
    await paste('What the server printed', REPORT);
    await click('Make the invite');
    expect(await screen.findByText(/waits for your approval above/)).toBeTruthy();
    // Nothing is shown before the approval.
    expect(screen.queryByTestId('invite-text')).toBeNull();
    await fireEvent.click(await screen.findByRole('button', { name: /^Approve: Making an invite for the device "Ravi laptop"/ }));
    expect((await screen.findByTestId('invite-text')).textContent).toBe(INVITE);
  });

  it('says so when the approval was dropped, and the invite is not shown', async () => {
    await openInvite({ holdChanges: true });
    await toTheScript();
    await paste('What the server printed', REPORT);
    await click('Make the invite');
    await fireEvent.click(await screen.findByRole('button', { name: /^Drop: Making an invite/ }));
    expect(await screen.findByText(/The invite was not made/)).toBeTruthy();
    expect(screen.queryByTestId('invite-text')).toBeNull();
  });

  it('starts over for another device', async () => {
    await openInvite();
    await toTheScript();
    await paste('What the server printed', REPORT);
    await click('Make the invite');
    await screen.findByTestId('invite-text');
    await click('Add another device');
    await waitFor(() => expect(screen.getByLabelText('Your friend’s request')).toBeTruthy());
    expect((screen.getByLabelText('Your friend’s request') as HTMLTextAreaElement).value).toBe('');
  });

  it('can be left for Servers at any step', async () => {
    await openInvite();
    await click('Back to Servers');
    await screen.findByRole('heading', { level: 1, name: 'Servers' });
  });
});
