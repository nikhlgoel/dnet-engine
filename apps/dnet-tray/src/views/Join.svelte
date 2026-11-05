<script lang="ts">
  import PendingChanges from '../components/PendingChanges.svelte';
  import type { AppState } from '../lib/app.svelte';
  import type { JoinRequest } from '../lib/bridge';
  import { copyText } from '../lib/clipboard';
  import { en, fill } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.views.join;

  let name = $state<string>(t.defaultName);
  let request = $state<JoinRequest | null>(null);
  let invite = $state('');
  let serverName = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let copied = $state(false);
  let copyFailed = $state(false);
  /** The invite was sent and the server waits for the person's approval (T160). How many servers there were then. */
  let held = $state(false);
  let before = $state(0);
  let dropped = $state(false);
  let done = $state(false);
  let asked = $state(0);

  const connected = $derived((app.look?.switch.on ?? false) === true);

  async function make(event: Event): Promise<void> {
    event.preventDefault();
    busy = true;
    error = null;
    const outcome = await app.bridge.requestJoin(name.trim());
    busy = false;
    if (outcome.ok && outcome.request) request = outcome.request;
    else error = outcome.ok ? null : outcome.reason;
  }

  async function copy(): Promise<void> {
    if (request === null) return;
    const ok = await copyText(request.text);
    copied = ok;
    copyFailed = !ok;
  }

  async function add(event: Event): Promise<void> {
    event.preventDefault();
    busy = true;
    error = null;
    dropped = false;
    try {
      before = (await app.bridge.endpoints()).length;
    } catch {
      before = 0;
    }
    const outcome = await app.bridge.acceptInvite(invite, serverName.trim() === '' ? undefined : serverName.trim());
    busy = false;
    if (outcome.ok) {
      // The invite is dropped as soon as the service has it.
      invite = '';
      done = true;
    } else if (outcome.code === 'ApprovalRequired') {
      // Not refused: the service holds the server, and the invite with it, until the person approves it.
      invite = '';
      held = true;
      asked += 1;
    } else {
      error = outcome.reason;
    }
  }

  /** A waiting change was approved or dropped in the list: has the server arrived? */
  async function settled(): Promise<void> {
    if (!held) return;
    try {
      const servers = await app.bridge.endpoints();
      held = false;
      if (servers.length > before) done = true;
      else dropped = true;
    } catch {
      // No answer now: the list above is still on screen and can be used again.
    }
  }
</script>

<section class="view" aria-labelledby="join-title">
  <h1 id="join-title">{t.title}</h1>
  <p class="lede">{t.lede}</p>

  {#if done}
    <div class="card">
      <h2>{t.doneTitle}</h2>
      <p>{t.doneBody}</p>
      <div class="actions">
        <button type="button" class="btn primary" onclick={() => app.go('endpoints')}>{t.toServers}</button>
      </div>
    </div>
  {:else}
    <h2>{t.stepRequest}</h2>
    <form class="form" onsubmit={make}>
      <div class="field">
        <label for="join-name">{t.nameLabel}</label>
        <input id="join-name" bind:value={name} required maxlength="32" autocomplete="off" spellcheck="false" />
        <span class="help">{t.nameHelp}</span>
      </div>
      {#if error && request === null}<p class="notice" role="alert">{error}</p>{/if}
      <div class="actions">
        <button type="submit" class="btn" class:primary={request === null} disabled={busy || name.trim() === ''}>{t.make}</button>
      </div>
    </form>

    {#if request}
      <div class="card">
        <h3>{t.sendTitle}</h3>
        <p>{t.sendBody}</p>
        <pre class="code" data-testid="join-request">{request.text}</pre>
        <div class="actions">
          <button type="button" class="btn primary" aria-label={`${t.copy}: ${t.sendTitle}`} onclick={copy}>{t.copy}</button>
        </div>
        {#if copied}<span class="help" role="status">{t.copied}</span>{/if}
        {#if copyFailed}<p class="notice" role="status">{t.copyFailed}</p>{/if}
        <p class="help">{fill(t.keepKey, { minutes: request.validForMinutes })}</p>
      </div>

      <h2>{t.stepInvite}</h2>
      {#if held}
        <p class="notice" role="status">{t.held}</p>
        <PendingChanges {app} {asked} onsettled={() => void settled()} />
      {:else}
        {#if dropped}<p class="notice" role="status">{t.dropped}</p>{/if}
        <form class="form" onsubmit={add}>
          <div class="field">
            <label for="join-invite">{t.inviteLabel}</label>
            <textarea id="join-invite" bind:value={invite} rows="5" spellcheck="false" required></textarea>
            <span class="help">{t.inviteHelp}</span>
          </div>
          <div class="field">
            <label for="join-server">{t.serverLabel}</label>
            <input id="join-server" bind:value={serverName} maxlength="64" autocomplete="off" />
            <span class="help">{t.serverHelp}</span>
          </div>
          {#if error}<p class="notice" role="alert">{error}</p>{/if}
          <div class="actions">
            <button type="submit" class="btn primary" disabled={busy || connected || invite.trim() === ''}>{t.add}</button>
          </div>
        </form>
      {/if}
    {:else}
      <p class="help">{t.needRequest}</p>
    {/if}

    <div class="actions leave">
      <button type="button" class="btn" onclick={() => app.go('endpoints')}>{t.back}</button>
    </div>
  {/if}
</section>

<style>
  h2,
  h3 {
    font-weight: 600;
  }

  .help {
    color: var(--c-text-2);
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
