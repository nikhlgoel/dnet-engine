<script lang="ts">
  import type { Cell } from '../lib/describe';
  import { en } from '../lib/messages';
  import Icon from './Icon.svelte';

  let {
    cells,
    expanded,
    ontoggle,
    chevron = $bindable(null),
  }: {
    cells: Cell[];
    expanded: boolean;
    ontoggle: () => void;
    /** The details button, so the caller can return focus to it when the drawer closes. */
    chevron?: HTMLButtonElement | null;
  } = $props();

  /** A 40-sample trace as polyline points in a 100 × 22 box; a lost probe is a gap, not a zero. */
  function path(trace: (number | null)[]): string {
    const values = trace.filter((v): v is number => v !== null);
    if (values.length < 2) return '';
    const lo = Math.min(...values);
    const hi = Math.max(...values);
    const span = hi - lo || 1;
    const n = trace.length;
    return trace
      .map((v, i) => (v === null ? null : `${((i / (n - 1)) * 100).toFixed(1)},${(20 - ((v - lo) / span) * 18).toFixed(1)}`))
      .filter((p): p is string => p !== null)
      .join(' ');
  }
</script>

<section class="strip" aria-label="Connection quality">
  {#each cells as cell (cell.key)}
    <div class="cell" role="group" aria-label={cell.name}>
      <div class="k" aria-hidden="true">{cell.label}</div>
      <div class="v num" class:na={cell.none} aria-hidden="true">
        {cell.value}{#if cell.unit}<small>{cell.unit}</small>{/if}
      </div>
      {#if cell.trace.length > 1 && !cell.none}
        <svg class="t" viewBox="0 0 100 22" preserveAspectRatio="none" aria-hidden="true">
          <polyline points={path(cell.trace)} fill="none" stroke="currentColor" stroke-width="1.4" vector-effect="non-scaling-stroke" />
        </svg>
      {:else}
        <span></span>
      {/if}
      <div class="d" aria-hidden="true">{cell.context}</div>
    </div>
  {/each}
  <button type="button" class="more" bind:this={chevron} aria-expanded={expanded} aria-controls="drawer" aria-label={en.instruments.details} onclick={ontoggle}>
    <Icon name="chevron" />
  </button>
</section>

<style>
  .strip {
    position: relative;
    margin: 0 var(--s-5) var(--s-3);
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr)) auto;
    border-radius: var(--r-card);
    background: color-mix(in srgb, var(--c-card) 78%, transparent);
  }

  .cell {
    display: grid;
    grid-template-columns: 1fr auto;
    grid-template-rows: auto auto;
    column-gap: var(--s-3);
    padding: 10px var(--s-4);
    border-left: 1px solid var(--c-line);
    min-width: 0;
    align-items: end;
  }

  .cell:first-child {
    border-left: 0;
  }

  .k {
    grid-column: 1 / -1;
    font: 500 10px / 1.4 var(--font-display);
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--c-text-3);
  }

  .v {
    font: 400 24px / 1.1 var(--font-num);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .v small {
    font: 12px var(--font-display);
    letter-spacing: 0.04em;
    color: var(--c-text-2);
    margin-left: 3px;
  }

  .v.na {
    color: var(--c-text-3);
  }

  .t {
    width: 64px;
    height: 22px;
    color: var(--c-text-3);
    align-self: center;
  }

  .d {
    grid-column: 1 / -1;
    font-size: var(--fs-xs);
    color: var(--c-text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .more {
    display: grid;
    place-items: center;
    width: 44px;
    border: 0;
    border-left: 1px solid var(--c-line);
    background: none;
    cursor: pointer;
    color: var(--c-text-2);
    border-radius: 0 var(--r-card) var(--r-card) 0;
  }

  .more:hover {
    background: var(--c-raised);
    color: var(--c-text);
  }

  .more :global(svg) {
    transition: transform var(--dur-2) var(--ease);
  }

  .more[aria-expanded='true'] :global(svg) {
    transform: rotate(180deg);
  }

  @container (max-width: 720px) {
    .strip {
      grid-template-columns: repeat(2, minmax(0, 1fr)) auto;
    }

    .cell:nth-child(3) {
      border-left: 0;
      border-top: 1px solid var(--c-line);
    }

    .cell:nth-child(4) {
      border-top: 1px solid var(--c-line);
    }

    .more {
      grid-row: 1 / 3;
      grid-column: 3;
    }
  }
</style>
