<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import Consent from '../components/Consent.svelte';
  import PendingChanges from '../components/PendingChanges.svelte';
  import { en } from '../lib/messages';
  import type { EndpointView } from '../lib/model';

  let { app }: { app: AppState } = $props();

  const t = en.views.endpoints;
  let list = $state<EndpointView[]>([]);
  let adding = $state(false);
  let removing = $state<EndpointView | null>(null);
  let error = $state<string | null>(null);
  let label = $state('');
  let host = $state('');
  let credentials = $state('');
  let busy = $state(false);
  let failedToLoad = $state(false);
  /** What this view asked for waits for the person's approval (T160), in words: which, if any. How many times it has asked. */
  let held = $state<string | null>(null);
  let asked = $state(0);

  // Endpoints change only while disconnected: the engine and what it drives were built from the endpoints of
  // the moment. The buttons say so instead of being refused after the fact.
  const locked = $derived((app.look?.switch.on ?? false) === true);

  async function load(): Promise<void> {
    try {
      list = await app.bridge.endpoints();
      if (error !== null && failedToLoad) error = null;
      failedToLoad = false;
    } catch (e) {
      // A list that could not be read is said so, and is not drawn as "no endpoints".
      list = [];
      error = app.reason(e);
      failedToLoad = true;
    }
  }

  onMount(() => {
    void load();
  });

  async function readFile(event: Event): Promise<void> {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    // The file's text is held only until the form is submitted or closed.
    credentials = file ? await file.text() : '';
  }

  function close(): void {
    adding = false;
    label = '';
    host = '';
    credentials = '';
    error = null;
  }

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    busy = true;
    const outcome = await app.bridge.addEndpoint({ label, host, credentials });
    busy = false;
    if (outcome.ok) {
      close();
      await load();
    } else if (outcome.code === 'ApprovalRequired') {
      // Not refused: the service holds the server, with the details from the file, until the person approves it
      // in the list above. The form's copy of the file is dropped now, as on success.
      close();
      held = t.held;
      asked += 1;
    } else {
      error = outcome.reason;
    }
  }

  /** A waiting change was approved or dropped in the list: the servers are read again. */
  async function settled(): Promise<void> {
    held = null;
    await load();
  }

  async function toggle(e: EndpointView): Promise<void> {
    const outcome = await app.bridge.setEndpointEnabled(e.id, !e.enabled);
    // Turning a server on that is held for approval was not refused: it waits in the list above (T160).
    const waits = !outcome.ok && outcome.code === 'ApprovalRequired';
    error = outcome.ok || waits ? null : outcome.reason;
    held = waits ? t.heldOn : null;
    if (waits) asked += 1;
    await load();
  }

  async function confirmRemove(): Promise<void> {
    const target = removing;
    removing = null;
    if (!target) return;
    const outcome = await app.bridge.removeEndpoint(target.id);
    error = outcome.ok ? null : outcome.reason;
    await load();
  }
</script>

<section class="view" aria-labelledby="endpoints-title">
  <h1 id="endpoints-title">{t.title}</h1>

  <p class="lede">{t.lede}</p>

  <PendingChanges {app} {asked} onsettled={settled} />

  {#if held}
    <p class="notice" role="status">{held}</p>
  {/if}
  {#if locked}
    <p class="notice">{en.errors.disconnectFirst}</p>
  {/if}
  {#if error}
    <p class="notice" role="alert">{error}</p>
  {/if}

  {#if list.length === 0 && !failedToLoad}
    <p class="empty">{t.empty}</p>
  {:else if failedToLoad}
    <!-- The reason is above; there is no list to show. -->
  {:else}
    <ul class="list">
      {#each list as e (e.id)}
        <li class="card">
          <div class="head">
            <strong class="disp">{e.label}</strong>
            <span class="state">{e.enabled ? t.enabled : t.disabled}</span>
          </div>
          <p class="num addr">{e.address}</p>
          <p class="health">{t.health[e.health]}</p>
          <div class="actions">
            <button type="button" class="btn" disabled={locked} onclick={() => toggle(e)}>
              {e.enabled ? t.disable : t.enable}
            </button>
            <button type="button" class="btn" disabled={locked} onclick={() => (removing = e)}>{t.remove}</button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  {#if adding}
    <form class="card form" onsubmit={submit}>
      <div class="field">
        <label for="ep-label">{t.form.label}</label>
        <input id="ep-label" bind:value={label} required maxlength="64" autocomplete="off" />
        <span class="help">{t.form.labelHelp}</span>
      </div>
      <div class="field">
        <label for="ep-host">{t.form.host}</label>
        <input id="ep-host" bind:value={host} required autocomplete="off" spellcheck="false" />
        <span class="help">{t.form.hostHelp}</span>
      </div>
      <div class="field">
        <label for="ep-file">{t.form.credentials}</label>
        <input id="ep-file" type="file" accept=".json,application/json" onchange={readFile} required />
        <span class="help">{t.form.credentialsHelp}</span>
      </div>
      <div class="actions">
        <button type="submit" class="btn primary" disabled={busy || credentials === ''}>{t.form.submit}</button>
        <button type="button" class="btn" onclick={close}>{t.form.cancel}</button>
      </div>
    </form>
  {:else}
    <div class="actions">
      <button
        type="button"
        class="btn primary"
        disabled={locked}
        onclick={() => {
          adding = true;
          held = null;
        }}>{t.add}</button
      >
      <button type="button" class="btn" disabled={locked} onclick={() => app.go('wizard')}>{t.setup}</button>
    </div>
  {/if}
</section>

<Consent
  open={removing !== null}
  title={t.removeTitle}
  paragraphs={[t.removeBody]}
  consequence={removing ? `“${removing.label}” will no longer be used.` : ''}
  decline={t.removeDecline}
  accept={t.removeAccept}
  ondecline={() => (removing = null)}
  onaccept={confirmRemove}
/>

<style>
  .list {
    display: grid;
    gap: var(--s-3);
  }

  .head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--s-3);
  }

  .state,
  .health {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }

  .addr {
    font-size: var(--fs-sm);
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
  }

  .form {
    gap: var(--s-4);
    max-width: 520px;
  }
</style>
