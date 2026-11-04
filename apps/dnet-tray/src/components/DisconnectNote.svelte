<script lang="ts">
  import type { AppState } from '../lib/app.svelte';
  import { en } from '../lib/messages';

  /** Says a page needs the connection off, and lets it be turned off here instead of sending the person back to Status. */
  let { app, text = en.errors.disconnectFirst }: { app: AppState; text?: string } = $props();

  let busy = $state(false);

  async function off(): Promise<void> {
    busy = true;
    await app.toggle();
    busy = false;
  }
</script>

<p class="note">
  <span>{text}</span>
  <button type="button" class="btn" disabled={busy} onclick={off}>{en.errors.disconnectNow}</button>
</p>

<style>
  .note {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--s-2) var(--s-3);
    padding: var(--s-2) var(--s-3);
    border-left: 3px solid var(--c-warn);
    background: var(--c-warn-bg);
    border-radius: 0 var(--r-ctl) var(--r-ctl) 0;
    font-size: var(--fs-sm);
  }

  .note span {
    flex: 1 1 16rem;
  }
</style>
