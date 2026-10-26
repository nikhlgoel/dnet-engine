<script lang="ts">
  import type { AppState } from '../lib/app.svelte';
  import { en } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.views.activity;

  function clock(ms: number): string {
    return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
</script>

<section class="view" aria-labelledby="activity-title">
  <h1 id="activity-title">{t.title}</h1>
  <p class="lede">{t.note}</p>

  {#if app.activity.length === 0}
    <p class="empty">{t.empty}</p>
  {:else}
    <!-- Newest first. Each line says what happened and why (principle 3); a bare "Reconnecting…" is not acceptable. -->
    <ol class="log">
      {#each app.activity as item (item.seq ?? item.atMs)}
        <li>
          <time class="num" datetime={new Date(item.atMs).toISOString()}>{clock(item.atMs)}</time>
          <span class="what">
            <strong>{item.event}</strong>
            <span>{item.because}</span>
          </span>
        </li>
      {/each}
    </ol>
  {/if}
</section>

<style>
  .log {
    display: grid;
    max-width: 760px;
  }

  li {
    display: grid;
    grid-template-columns: 6.5em 1fr;
    gap: var(--s-3);
    padding: var(--s-2) 0;
    border-top: 1px solid var(--c-line);
  }

  time {
    color: var(--c-text-3);
    font-size: var(--fs-sm);
  }

  .what {
    display: grid;
    gap: 2px;
  }

  .what span {
    color: var(--c-text-2);
  }
</style>
