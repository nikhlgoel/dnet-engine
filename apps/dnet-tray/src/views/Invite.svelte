<script lang="ts">
  import { onMount } from 'svelte';
  import PendingChanges from '../components/PendingChanges.svelte';
  import type { AppState } from '../lib/app.svelte';
  import type { InvitedDevice, PreparedDevice } from '../lib/bridge';
  import { copyText } from '../lib/clipboard';
  import { wrapForPaste } from '../lib/guide';
  import { en, fill } from '../lib/messages';
  import type { EndpointView } from '../lib/model';

  let { app }: { app: AppState } = $props();

  const t = en.views.invite;

  let servers = $state<EndpointView[]>([]);
  let loaded = $state(false);
  let serverId = $state('');
  let requestText = $state('');
  let prepared = $state<PreparedDevice | null>(null);
  let report = $state('');
  let invited = $state<InvitedDevice | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  /** Making the invite waits for the person's approval (T160), because it holds the server's access details. */
  let held = $state(false);
  let dropped = $state(false);
  let asked = $state(0);
  let copied = $state<'script' | 'invite' | null>(null);
  let copyFailed = $state(false);

  /** What to paste into the server's terminal. The script comes from the service; it is shown and copied whole. */
  const block = $derived.by(() => {
    if (prepared === null) return '';
    try {
      return wrapForPaste(prepared.script, 'dnet-device.sh');
    } catch {
      return '';
    }
  });
  const serverName = $derived(servers.find((s) => s.id === serverId)?.label ?? '');

  onMount(() => {
    void (async () => {
      try {
        servers = await app.bridge.endpoints();
      } catch (e) {
        error = app.reason(e);
      }
      const wanted = app.inviteFor;
      serverId = servers.find((s) => s.id === wanted)?.id ?? servers[0]?.id ?? '';
      loaded = true;
    })();
  });

  async function makeScript(event: Event): Promise<void> {
    event.preventDefault();
    busy = true;
    error = null;
    const outcome = await app.bridge.prepareDevice(serverId, requestText.trim());
    busy = false;
    if (outcome.ok && outcome.prepared) prepared = outcome.prepared;
    else error = outcome.ok ? null : outcome.reason;
  }

  async function copy(what: 'script' | 'invite', text: string): Promise<void> {
    const ok = await copyText(text);
    copied = ok ? what : null;
    copyFailed = !ok;
  }

  /** Ask for the invite. The first time it waits for approval; once approved, asking again returns it. */
  async function makeInvite(event?: Event): Promise<void> {
    event?.preventDefault();
    busy = true;
    error = null;
    dropped = false;
    const outcome = await app.bridge.finishDevice(serverId, requestText.trim(), report);
    busy = false;
    if (outcome.ok && outcome.invited) {
      invited = outcome.invited;
      held = false;
      // What was pasted is not kept: the invite is all that is left of it.
      report = '';
    } else if (!outcome.ok && outcome.code === 'ApprovalRequired') {
      held = true;
      asked += 1;
    } else {
      held = false;
      error = outcome.ok ? null : outcome.reason;
    }
  }

  /** A waiting change was approved or dropped in the list. Approved: ask again, and the invite is handed over. */
  async function settled(applied: boolean): Promise<void> {
    if (!held) return;
    if (applied) {
      await makeInvite();
    } else {
      held = false;
      dropped = true;
    }
  }

  /** The person approved it somewhere else (the command line): ask now. A request still waiting is not asked twice. */
  async function checkAgain(): Promise<void> {
    const waiting = await app.bridge.pending().catch(() => []);
    if (waiting.some((c) => c.what.includes('Making an invite'))) {
      error = null;
      return;
    }
    await makeInvite();
  }

  function another(): void {
    requestText = '';
    prepared = null;
    report = '';
    invited = null;
    error = null;
    held = false;
    dropped = false;
    copied = null;
  }
</script>

<section class="view" aria-labelledby="invite-title">
  <h1 id="invite-title">{t.title}</h1>
  <p class="lede">{t.lede}</p>

  {#if loaded && servers.length === 0}
    <p class="notice" role="status">{t.noServers}</p>
  {:else if invited}
    <h2>{t.stepSend}</h2>
    <div class="card">
      <p>{fill(t.sendBody, { name: invited.name, address: invited.address })}</p>
      <pre class="code" data-testid="invite-text">{invited.invite}</pre>
      <div class="actions">
        <button type="button" class="btn primary" aria-label={`${t.copy}: ${t.stepSend}`} onclick={() => copy('invite', invited?.invite ?? '')}>{t.copy}</button>
        <button type="button" class="btn" onclick={another}>{t.another}</button>
      </div>
      {#if copied === 'invite'}<span class="help" role="status">{t.copied}</span>{/if}
      {#if copyFailed}<p class="notice" role="status">{t.copyFailed}</p>{/if}
      <p class="help">{t.removeNote}</p>
    </div>
  {:else if loaded}
    {#if servers.length > 1}
      <div class="field narrow">
        <label for="inv-server">{t.serverLabel}</label>
        <select id="inv-server" bind:value={serverId} disabled={prepared !== null}>
          {#each servers as s (s.id)}<option value={s.id}>{s.label}</option>{/each}
        </select>
      </div>
    {:else}
      <p class="help">{t.serverLabel}: <strong>{serverName}</strong></p>
    {/if}

    {#if prepared === null}
      <h2>{t.stepRequest}</h2>
      <form class="form" onsubmit={makeScript}>
        <div class="field">
          <label for="inv-request">{t.requestLabel}</label>
          <textarea id="inv-request" bind:value={requestText} rows="4" spellcheck="false" required></textarea>
          <span class="help">{t.requestHelp}</span>
        </div>
        {#if error}<p class="notice" role="alert">{error}</p>{/if}
        <div class="actions">
          <button type="submit" class="btn primary" disabled={busy || requestText.trim() === ''}>{t.makeScript}</button>
        </div>
      </form>
    {:else}
      <h2>{t.stepRun}</h2>
      <p>{fill(t.runBody, { name: prepared.name })}</p>
      <div class="field">
        <label for="inv-block">{t.commands}</label>
        <textarea id="inv-block" readonly rows="8" value={block}></textarea>
      </div>
      <div class="actions">
        <button type="button" class="btn primary" aria-label={`${t.copy}: ${t.commands}`} onclick={() => copy('script', block)}>{t.copy}</button>
      </div>
      {#if copied === 'script'}<span class="help" role="status">{t.copied}</span>{/if}
      {#if copyFailed}<p class="notice" role="status">{t.copyFailed}</p>{/if}

      <h2>{t.stepReport}</h2>
      {#if held}
        <p class="notice" role="status">{t.held}</p>
        <PendingChanges {app} {asked} onsettled={(applied) => void settled(applied)} />
        <div class="actions">
          <button type="button" class="btn" onclick={() => void checkAgain()}>{t.checkAgain}</button>
        </div>
        {#if error}<p class="notice" role="alert">{error}</p>{/if}
      {:else}
        {#if dropped}<p class="notice" role="status">{t.dropped}</p>{/if}
        <form class="form" onsubmit={makeInvite}>
          <div class="field">
            <label for="inv-report">{t.reportLabel}</label>
            <textarea id="inv-report" bind:value={report} rows="6" spellcheck="false" required></textarea>
            <span class="help">{t.reportHelp}</span>
          </div>
          {#if error}<p class="notice" role="alert">{error}</p>{/if}
          <div class="actions">
            <button type="submit" class="btn primary" disabled={busy || report.trim() === ''}>{t.makeInvite}</button>
          </div>
        </form>
      {/if}
    {/if}
  {/if}

  <div class="actions leave">
    <button type="button" class="btn" onclick={() => app.go('endpoints')}>{t.back}</button>
  </div>
</section>

<style>
  h2 {
    font-weight: 600;
  }

  .help {
    color: var(--c-text-2);
  }

  .narrow {
    max-width: 360px;
  }

  .code {
    font-family: var(--font-num);
    white-space: pre-wrap;
    word-break: break-all;
    border: 1px solid var(--c-text-3);
    border-radius: var(--r-ctl);
    padding: var(--s-2) var(--s-3);
    margin: var(--s-2) 0;
  }

  .form {
    display: grid;
    gap: var(--s-4);
    max-width: 560px;
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
  }

  .leave {
    margin-top: var(--s-4);
    padding-top: var(--s-4);
    border-top: 1px solid var(--c-line);
  }
</style>
