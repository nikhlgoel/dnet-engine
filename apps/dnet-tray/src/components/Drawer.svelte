<script lang="ts">
  import { chips, formatDuration, formatLoss, formatMs } from '../lib/describe';
  import { en } from '../lib/messages';
  import type { Snapshot } from '../lib/model';

  let { snapshot, onclose }: { snapshot: Snapshot; onclose: () => void } = $props();

  const rows = $derived(chips(snapshot));
  const measuredById = $derived(new Map(snapshot.paths.paths.map((p) => [p.id, p])));
  const stats = $derived(snapshot.stats);

  /** Esc closes it, unless a dialog is open: that Esc belongs to the dialog. */
  function onkeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && document.querySelector('dialog[open]') === null) {
      event.stopPropagation();
      onclose();
    }
  }
</script>

<!-- An overlay, so opening it moves nothing. Esc closes it; the caller returns focus to the chevron. -->
<svelte:window {onkeydown} />

<div class="drawer" id="drawer" role="region" aria-label={en.drawer.networks}>
  <div>
    <h2>{en.drawer.networks}</h2>
    {#if rows.length === 0}
      <p class="fine">{en.drawer.notWatching}</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th>{en.drawer.columns.network}</th>
            <th>{en.drawer.columns.role}</th>
            <th>{en.drawer.columns.latency}</th>
            <th>{en.drawer.columns.jitter}</th>
            <th>{en.drawer.columns.loss}</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as row (row.id)}
            {@const p = measuredById.get(row.id)}
            {@const has = p?.measured === true && row.role !== 'lost'}
            <tr>
              <td>{row.title}</td>
              <td>{row.roleText}</td>
              <td class="num">{has ? `${formatMs(p?.rttMs ?? null)} ms` : '—'}</td>
              <td class="num">{has ? `${formatMs(p?.jitterMs ?? null)} ms` : '—'}</td>
              <td class="num">{has ? `${formatLoss(p?.loss ?? null)} %` : '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
  <div>
    <h2>{en.drawer.since}</h2>
    <dl>
      <dt>{en.drawer.connectedFor}</dt>
      <dd class="num">{stats.connected ? formatDuration(stats.connectedForS) : '—'}</dd>
      <dt>{en.drawer.networkChanges}</dt>
      <dd class="num">{stats.connected ? stats.networkChanges : '—'}</dd>
      <dt>{en.drawer.dropping}</dt>
      <dd class="num">{stats.connected ? stats.changesThatDropConnections : '—'}</dd>
      <dt>{en.drawer.methodSwitches}</dt>
      <dd class="num">{stats.connected ? stats.methodSwitches : '—'}</dd>
      <dt>{en.drawer.endpointSwitches}</dt>
      <dd class="num">{stats.connected ? stats.endpointSwitches : '—'}</dd>
      <dt>{en.drawer.poorSpells}</dt>
      <dd class="num">{stats.connected ? stats.degradedPeriods : '—'}</dd>
      <dt>{en.drawer.longestPoor}</dt>
      <dd class="num">{stats.connected ? formatDuration(stats.longestDegradedS) : '—'}</dd>
    </dl>
  </div>
  <p class="fine">{en.drawer.fine}</p>
</div>

<style>
  .drawer {
    position: absolute;
    z-index: 6;
    left: var(--s-5);
    right: var(--s-5);
    bottom: 78px;
    padding: var(--s-4) var(--s-5);
    border: 1px solid var(--c-line-strong);
    border-radius: var(--r-card);
    background: var(--c-raised);
    box-shadow: var(--shadow-dialog);
    display: grid;
    gap: var(--s-4);
    grid-template-columns: 1.5fr 1fr;
  }

  @container (max-width: 720px) {
    .drawer {
      grid-template-columns: 1fr;
      max-height: 60%;
      overflow: auto;
    }
  }

  h2 {
    font: 600 11px / 1 var(--font-display);
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--c-text-3);
    margin-bottom: var(--s-2);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--fs-sm);
  }

  th,
  td {
    text-align: left;
    padding: 5px var(--s-2) 5px 0;
    border-top: 1px solid var(--c-line);
    white-space: nowrap;
  }

  th {
    color: var(--c-text-3);
    font-weight: 500;
    font-size: var(--fs-xs);
    border-top: 0;
  }

  dl {
    margin: 0;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 0 var(--s-4);
    font-size: var(--fs-sm);
  }

  dt {
    color: var(--c-text-2);
    padding: 5px 0;
    border-top: 1px solid var(--c-line);
  }

  dd {
    margin: 0;
    padding: 5px 0;
    border-top: 1px solid var(--c-line);
    text-align: right;
  }

  dt:first-of-type,
  dd:first-of-type {
    border-top: 0;
  }

  .fine {
    grid-column: 1 / -1;
    font-size: var(--fs-xs);
    color: var(--c-text-3);
  }
</style>
