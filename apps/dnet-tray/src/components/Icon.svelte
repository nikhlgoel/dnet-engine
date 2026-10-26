<script lang="ts" module>
  /** The few icons the window uses, as SVG elements (never as markup built from a string: no `{@html}`). */
  export type IconName = 'wifi' | 'cell' | 'eth' | 'chevron' | 'status' | 'endpoints' | 'rules' | 'activity' | 'settings';
</script>

<script lang="ts">
  let { name, size = 18 }: { name: IconName; size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  {#if name === 'wifi'}
    <path d="M2.5 9a14 14 0 0 1 19 0M5.5 12.5a9.5 9.5 0 0 1 13 0M8.6 16a5 5 0 0 1 6.8 0" />
    <circle cx="12" cy="19.2" r="1.4" fill="currentColor" stroke="none" />
  {:else if name === 'cell'}
    <rect x="7" y="2.5" width="10" height="19" rx="2.5" />
    <path d="M10.5 18.5h3" />
  {:else if name === 'eth'}
    <rect x="4" y="5" width="16" height="9" rx="2" />
    <path d="M8 14v4M12 14v4M16 14v4M7 18h10" />
  {:else if name === 'chevron'}
    <path d="M6 15l6-6 6 6" stroke-width="2.2" />
  {:else if name === 'status'}
    <circle cx="12" cy="12" r="8" />
    <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />
  {:else if name === 'endpoints'}
    <rect x="4" y="4" width="16" height="6" rx="2" />
    <rect x="4" y="14" width="16" height="6" rx="2" />
  {:else if name === 'rules'}
    <path d="M5 7h14M5 12h14M5 17h9" />
  {:else if name === 'activity'}
    <path d="M3 12h4l3-7 4 14 3-7h4" />
  {:else if name === 'settings'}
    <circle cx="12" cy="12" r="3" />
    <path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1" />
  {/if}
</svg>
