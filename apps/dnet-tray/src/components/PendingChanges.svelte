<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import { en, fill } from '../lib/messages';
  import type { PendingView } from '../lib/model';

  let {
    app,
    asked = 0,
    onsettled,
  }: {
    app: AppState;
    /** Raised by the view each time something it asked for was held, so the list is read again at once. */
    asked?: number;
    /** Told after a change is approved or dropped here, so the view can read what that changed. */
    onsettled?: () => void;
  } = $props();

  const t = en.views.pending;
  /** How often the list is read again: a change can be asked for by another program, such as `dnetctl`. */
  const REFRESH_MS = 4000;

  let items = $state<PendingView[]>([]);
  let message = $state<string | null>(null);
  /** The change being approved or dropped now; the others wait their turn. */
  let busy = $state<string | null>(null);
  let approving = $state(false);

  async function load(): Promise<void> {
    try {
      items = await app.bridge.pending();
    } catch {
      // A service that does not know the list (an older one), or does not answer, has nothing to show here;
      // the other views say when the service cannot be reached.
      items = [];
    }
  }

  // Read when shown, and again each time the view says it asked for something that was held.
  $effect(() => {
    void asked;
    void load();
  });

  onMount(() => {
    const timer = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(timer);
  });

  function minutesLeft(item: PendingView): number {
    return Math.max(1, Math.ceil((item.expiresUnixMs - Date.now()) / 60000));
  }

  async function approve(item: PendingView): Promise<void> {
    busy = item.id;
    approving = true;
    message = t.waiting;
    const outcome = await app.bridge.approveChange(item.id);
    approving = false;
    busy = null;
    message = outcome.ok ? t.approved : outcome.reason;
    await load();
    onsettled?.();
  }

  async function drop(item: PendingView): Promise<void> {
    busy = item.id;
    const outcome = await app.bridge.rejectChange(item.id);
    busy = null;
    message = outcome.ok ? t.dropped : outcome.reason;
    await load();
    onsettled?.();
  }
</script>

{#if items.length > 0 || message}
  <section class="card pending" aria-labelledby="pending-title">
    <h2 id="pending-title">{t.title}</h2>
    {#if items.length > 0}
      <p class="help-line">{t.explainer}</p>
      <ul>
        {#each items as item (item.id)}
          <li>
            <span class="what">{item.what}</span>
            <span class="help-line">{fill(t.left, { minutes: minutesLeft(item) })}</span>
            <span class="actions">
              <button
                type="button"
                class="btn"
                disabled={busy !== null}
                aria-label={fill(t.approveLabel, { what: item.what })}
                onclick={() => approve(item)}>{t.approve}</button
              >
              <button
                type="button"
                class="btn"
                disabled={busy !== null}
                aria-label={fill(t.dropLabel, { what: item.what })}
                onclick={() => drop(item)}>{t.drop}</button
              >
            </span>
          </li>
        {/each}
      </ul>
    {/if}
    {#if message}
      <p class="notice" role={approving ? 'status' : 'alert'}>{message}</p>
    {/if}
  </section>
{/if}

<style>
  .pending {
    display: grid;
    gap: var(--s-2);
    max-width: 720px;
    margin-bottom: var(--s-4);
  }

  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
  }

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s-3);
  }

  li {
    display: grid;
    gap: var(--s-1);
    padding-top: var(--s-2);
    border-top: 1px solid var(--c-line);
  }

  .what {
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    gap: var(--s-2);
  }

  .help-line {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }
</style>
