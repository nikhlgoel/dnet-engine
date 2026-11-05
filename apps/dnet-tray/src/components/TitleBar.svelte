<script lang="ts">
  import { onMount } from 'svelte';
  import type { WindowChrome } from '../lib/chrome';
  import { en } from '../lib/messages';

  let { chrome }: { chrome: WindowChrome } = $props();

  const t = en.window;
  let maximized = $state(false);

  onMount(() => {
    // Drawn: the system frame is not needed.
    void chrome.ready();
    let stop: (() => void) | null = null;
    let gone = false;
    void chrome.onMaximized((state) => (maximized = state)).then((off) => {
      if (gone) off();
      else stop = off;
    });
    return () => {
      gone = true;
      stop?.();
    };
  });

  /** Pressing the primary button on the bar starts a drag; a button on the bar is a click, never a drag. The second
   * press of a double-click maximises or restores: the system's move loop can swallow the release, so the click
   * event itself is not relied on. */
  function press(event: MouseEvent): void {
    if (event.button !== 0) return;
    if (event.detail === 2) void chrome.toggleMaximize();
    else void chrome.startDrag();
  }
</script>

<section class="titlebar" aria-label={t.label}>
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="drag" data-drag onmousedown={press}>
    <span class="mark" aria-hidden="true"></span>
    <span class="name">{t.title}</span>
  </div>
  <div class="controls">
    <button type="button" class="ctl" aria-label={t.minimize} onclick={() => void chrome.minimize()}>
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.2">
        <path d="M1 5.5h8" />
      </svg>
    </button>
    <button type="button" class="ctl" aria-label={maximized ? t.restore : t.maximize} onclick={() => void chrome.toggleMaximize()}>
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.2">
        {#if maximized}
          <path d="M2.5 3.5h5.5v5.5H2.5zM4 3.5V1h5v5H8" />
        {:else}
          <rect x="1.5" y="1.5" width="7" height="7" />
        {/if}
      </svg>
    </button>
    <button type="button" class="ctl close" aria-label={t.close} onclick={() => void chrome.close()}>
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.2">
        <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" />
      </svg>
    </button>
  </div>
</section>

<style>
  .titlebar {
    display: flex;
    align-items: stretch;
    justify-content: space-between;
    height: var(--hit);
    flex: none;
    background: var(--c-base);
    border-bottom: 1px solid var(--c-line);
    user-select: none;
  }

  .drag {
    flex: 1;
    display: flex;
    align-items: center;
    gap: var(--s-2);
    min-width: 0;
    padding: 0 var(--s-3);
    cursor: default;
  }

  .mark {
    width: var(--s-2);
    height: var(--s-2);
    border-radius: var(--r-pill);
    background: var(--c-ok);
  }

  .name {
    font: var(--fs-xs) / var(--lh-tight) var(--font-display);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--c-text-2);
  }

  .controls {
    display: flex;
  }

  .ctl {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: calc(var(--hit) * 1.3);
    height: 100%;
    padding: 0;
    border: 0;
    border-radius: 0;
    background: transparent;
    color: var(--c-text-2);
    cursor: default;
    transition: background var(--dur-1) var(--ease);
  }

  .ctl:hover {
    background: var(--c-raised);
    color: var(--c-text);
  }

  .close:hover {
    background: var(--c-fail);
    color: var(--c-base);
  }

  .ctl:focus-visible {
    outline: 2px solid var(--c-focus);
    outline-offset: -2px;
  }
</style>
