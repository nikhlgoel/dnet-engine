<script lang="ts">
  import { en } from '../lib/messages';
  import type { ViewId } from '../lib/app.svelte';
  import Icon, { type IconName } from './Icon.svelte';

  let { current, onnavigate }: { current: ViewId; onnavigate: (view: ViewId) => void } = $props();

  const stations: { view: ViewId; label: string; icon: IconName }[] = [
    { view: 'status', label: en.nav.status, icon: 'status' },
    { view: 'endpoints', label: en.nav.endpoints, icon: 'endpoints' },
    { view: 'rules', label: en.nav.rules, icon: 'rules' },
    { view: 'activity', label: en.nav.activity, icon: 'activity' },
    { view: 'settings', label: en.nav.settings, icon: 'settings' },
  ];
</script>

<!-- A real <nav> of links: tab order is left to right, the current page is aria-current, Ctrl+K duplicates it. -->
<div class="dock">
  <nav aria-label={en.nav.sections}>
    {#each stations as station, i (station.view)}
      {#if i > 0}<i class="sep"></i>{/if}
      <a
        href={`#${station.view}`}
        aria-current={current === station.view ? 'page' : undefined}
        onclick={(event) => {
          event.preventDefault();
          onnavigate(station.view);
        }}
      >
        <Icon name={station.icon} />
        <span class="label">{station.label}</span>
      </a>
    {/each}
  </nav>
</div>

<style>
  .dock {
    display: flex;
    justify-content: center;
    padding: 0 var(--s-5) var(--s-4);
  }

  nav {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 5px;
    box-shadow: var(--shadow-dock);
    border-radius: var(--r-pill);
    background: color-mix(in srgb, var(--c-raised) 82%, transparent);
    backdrop-filter: blur(10px);
  }

  a {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 40px;
    padding: 0 16px;
    border-radius: var(--r-pill);
    color: var(--c-text-2);
    text-decoration: none;
    font: 500 var(--fs-sm) / 1 var(--font-display);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    transition:
      background var(--dur-1) var(--ease),
      color var(--dur-1) var(--ease);
  }

  a:hover {
    background: var(--c-card);
    color: var(--c-text);
  }

  a[aria-current='page'] {
    color: var(--c-text);
    background: var(--c-card);
  }

  /* The current station has a dot above it: shape, not only colour. */
  a[aria-current='page']::before {
    content: '';
    position: absolute;
    top: 3px;
    left: 50%;
    width: 4px;
    height: 4px;
    margin-left: -2px;
    border-radius: 50%;
    background: var(--c-text);
  }

  .sep {
    width: 3px;
    height: 3px;
    border-radius: 50%;
    background: var(--c-line-strong);
  }

  @container (max-width: 760px) {
    a:not([aria-current='page']) .label {
      display: none;
    }

    a {
      padding: 0 12px;
    }

    .sep {
      display: none;
    }
  }
</style>
