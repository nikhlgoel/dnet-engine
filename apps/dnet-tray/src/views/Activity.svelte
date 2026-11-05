<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import { en, fill } from '../lib/messages';
  import type { ComponentsView } from '../lib/model';

  let { app }: { app: AppState } = $props();

  const t = en.views.activity;
  const p = t.parts;
  /** The lamp for a part's state: what the service said, drawn, never decoration. */
  const lampOf: Record<ComponentsView['parts'][number]['state'], string> = {
    Unknown: '',
    Off: '',
    Starting: 'probe',
    Ok: 'ok',
    Degraded: 'warn',
    Blocked: 'warn',
    Failed: 'fail',
  };

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

  <h2 class="cat">{p.title}</h2>
  {#if mapError}
    <p class="notice" role="alert">{mapError}</p>
  {:else if map && !map.supported}
    <p class="notice" role="status">{p.unsupported}</p>
  {:else if map}
    <p class="hint">{p.note}</p>
    <ul class="panel parts" aria-label={p.title}>
      {#each map.parts as part (part.kind + part.id)}
        <li class="row part">
          <span class={`dot ${lampOf[part.state]}`} aria-hidden="true"></span>
          <span class="text">
            <strong class="title">{p.kinds[part.kind]}{' '}<span class="id">{part.id}</span></strong>
            <span class="desc">{part.reason}</span>
            <span class="meta num">
              {fill(p.for, { age: age(part.ageSeconds) })}
              {#if part.latencyMs !== null} · {fill(p.latency, { ms: part.latencyMs })}{/if}
              {#if part.lossPermille !== null} · {fill(p.loss, { percent: part.lossPermille / 10 })}{/if}
              {#if part.restarts !== null && part.restarts > 0} · {fill(p.restarts, { count: part.restarts })}{/if}
            </span>
          </span>
          <span class={`state ${part.state.toLowerCase()}`}>{p.states[part.state]}</span>
        </li>
      {/each}
    </ul>
  {/if}

  <h2 class="cat">{p.log}</h2>
  {#if app.activity.length === 0}
    <div class="panel"><p class="empty row">{t.empty}</p></div>
  {:else}
    <!-- Newest first. Each line says what happened and why (principle 3); a bare "Reconnecting…" is not acceptable. -->
    <ol class="panel log">
      {#each app.activity as item (item.seq ?? item.atMs)}
        <li class="row entry">
          <time class="num" datetime={new Date(item.atMs).toISOString()}>{clock(item.atMs)}</time>
          <span class="text">
            <strong class="title">{item.event}</strong>
            <span class="desc">{item.because}</span>
          </span>
        </li>
      {/each}
    </ol>
  {/if}
</section>

<style>
  .hint {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }

  .part {
    align-items: flex-start;
  }

  .part .dot {
    margin-top: var(--s-2);
  }

  .part .id,
  .part .meta {
    color: var(--c-text-3);
    font-size: var(--fs-sm);
  }

  .part .meta {
    display: block;
  }

  /* The state in words, in its lamp colour; the dot beside it repeats it, and neither is the only sign. */
  .state {
    flex: none;
    font-weight: 600;
    font-size: var(--fs-sm);
  }

  .state.ok {
    color: var(--c-ok);
  }

  .state.degraded,
  .state.blocked {
    color: var(--c-warn);
  }

  .state.failed {
    color: var(--c-fail);
  }

  .entry {
    align-items: flex-start;
    justify-content: flex-start;
    gap: var(--s-4);
  }

  .entry time {
    flex: none;
    min-width: 6.5em;
    color: var(--c-text-3);
    font-size: var(--fs-sm);
    padding-top: 2px;
  }
</style>
