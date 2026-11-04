<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import { en, fill } from '../lib/messages';
  import type { ComponentsView } from '../lib/model';

  let { app }: { app: AppState } = $props();

  const t = en.views.activity;
  const p = t.parts;

  let map = $state<ComponentsView | null>(null);
  let mapError = $state<string | null>(null);

  async function loadMap(): Promise<void> {
    try {
      map = await app.bridge.components();
      mapError = null;
    } catch (e) {
      // A map that could not be read is said so; it is not drawn as "no parts" and not as "fine".
      map = null;
      mapError = app.reason(e);
    }
  }

  // Read while this view is open and no longer: nothing runs while the window is hidden (ADR-0007 R2).
  onMount(() => {
    void loadMap();
    const timer = setInterval(() => void loadMap(), 5000);
    return () => clearInterval(timer);
  });

  function age(seconds: number): string {
    if (seconds < 60) return `${seconds} s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
    return `${Math.floor(seconds / 3600)} h`;
  }

  function clock(ms: number): string {
    return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
</script>

<section class="view" aria-labelledby="activity-title">
  <h1 id="activity-title">{t.title}</h1>
  <p class="lede">{t.note}</p>

  <h2>{p.title}</h2>
  {#if mapError}
    <p class="notice" role="alert">{mapError}</p>
  {:else if map && !map.supported}
    <p class="notice" role="status">{p.unsupported}</p>
  {:else if map}
    <p class="hint">{p.note}</p>
    <ul class="parts" aria-label={p.title}>
      {#each map.parts as part (part.kind + part.id)}
        <li class={`part ${part.state.toLowerCase()}`}>
          <span class="state">{p.states[part.state]}</span>
          <span class="what">
            <strong>{p.kinds[part.kind]}{' '}<span class="id">{part.id}</span></strong>
            <span>{part.reason}</span>
            <span class="meta num">
              {fill(p.for, { age: age(part.ageSeconds) })}
              {#if part.latencyMs !== null} · {fill(p.latency, { ms: part.latencyMs })}{/if}
              {#if part.lossPermille !== null} · {fill(p.loss, { percent: part.lossPermille / 10 })}{/if}
              {#if part.restarts !== null && part.restarts > 0} · {fill(p.restarts, { count: part.restarts })}{/if}
            </span>
          </span>
        </li>
      {/each}
    </ul>
  {/if}

  <h2>{p.log}</h2>
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
  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
    margin-top: var(--s-5);
  }

  .parts {
    display: grid;
    max-width: 760px;
  }

  .part {
    display: grid;
    grid-template-columns: 6.5em 1fr;
    gap: var(--s-3);
    padding: var(--s-2) 0;
    border-top: 1px solid var(--c-line);
  }

  .part .state {
    font-weight: 600;
  }

  .part.ok .state {
    color: var(--c-ok);
  }

  .part.degraded .state,
  .part.blocked .state {
    color: var(--c-warn);
  }

  .part.failed .state {
    color: var(--c-fail);
  }

  .part .id,
  .part .meta {
    color: var(--c-text-3);
    font-size: var(--fs-sm);
  }

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
