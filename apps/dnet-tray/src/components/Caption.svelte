<script lang="ts">
  import type { Look } from '../lib/describe';
  import { en } from '../lib/messages';
  import type { Warning } from '../lib/model';

  let {
    look,
    warnings,
    notice,
    ontoggle,
    onaction,
  }: {
    look: Look;
    warnings: Warning[];
    /** Something the person asked for was refused: the service's reason. */
    notice: string | null;
    ontoggle: () => void;
    onaction: () => void;
  } = $props();
</script>

<div class="caption" data-fail={look.lamp === 'fail' ? '' : undefined}>
  <h1 id="headline">{look.headline}</h1>
  {#if look.facts}
    <p class="facts num">{look.facts}</p>
  {/if}
  <p class="because">{look.because}</p>
  {#if look.advice}
    <p class="because advice">{look.advice}</p>
  {/if}
  <div class="row-actions">
    <button
      type="button"
      class="pill"
      role="switch"
      aria-checked={look.switch.on}
      aria-busy={look.switch.busy}
      aria-label={en.switch.label}
      onclick={ontoggle}
    >
      <span class="track" aria-hidden="true"></span>
      <span class="w">{look.switch.word}</span>
    </button>
    {#if look.action}
      <button type="button" class="btn primary" onclick={onaction}>{look.action.label}</button>
    {/if}
  </div>
  {#if notice}
    <p class="notice" role="alert">{notice}</p>
  {/if}
  {#each warnings as w (w)}
    <p class="notice">{en.notices[w]}</p>
  {/each}
</div>

<style>
  .caption {
    display: grid;
    justify-items: center;
    gap: var(--s-2);
    padding: 0 var(--s-5) var(--s-3);
    text-align: center;
  }

  h1 {
    font: 500 30px / 1.1 var(--font-display);
    letter-spacing: -0.005em;
    font-variation-settings: 'wdth' 92;
  }

  .caption[data-fail] h1 {
    font-size: var(--fs-xl);
  }

  .facts {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }

  .because {
    color: var(--c-text-2);
    max-width: 54ch;
    min-height: 3em;
  }

  .row-actions {
    display: flex;
    gap: var(--s-3);
    align-items: center;
    justify-content: center;
    flex-wrap: wrap;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    gap: var(--s-3);
    height: 44px;
    padding: 0 var(--s-4) 0 var(--s-2);
    border: 1px solid var(--c-line);
    border-radius: var(--r-pill);
    background: color-mix(in srgb, var(--c-card) 70%, transparent);
    cursor: pointer;
    transition: background var(--dur-1) var(--ease);
  }

  .pill:hover {
    background: var(--c-raised);
  }

  .track {
    width: 44px;
    height: 28px;
    border-radius: var(--r-pill);
    border: 1px solid var(--c-line-strong);
    background: var(--c-base);
    position: relative;
    transition: background var(--dur-2) var(--ease);
  }

  .track::after {
    content: '';
    position: absolute;
    top: 3px;
    left: 3px;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: var(--c-text-2);
    transition:
      transform var(--dur-2) var(--ease),
      background var(--dur-2) var(--ease);
  }

  .pill[aria-checked='true'] .track {
    background: var(--c-paper);
    border-color: var(--c-paper);
  }

  .pill[aria-checked='true'] .track::after {
    transform: translateX(16px);
    background: var(--c-on-paper);
  }

  /* Busy is shape, not colour: a hatched track. */
  .pill[aria-busy='true'] .track {
    background: repeating-linear-gradient(135deg, var(--c-base) 0 6px, var(--c-raised) 6px 12px);
  }

  .w {
    font: 500 var(--fs-lg) / 1 var(--font-display);
    letter-spacing: 0.02em;
    min-width: 6.4em;
    text-align: left;
  }

  @media (forced-colors: active) {
    .pill .track::after {
      forced-color-adjust: none;
      background: ButtonText;
    }

    .pill[aria-checked='true'] .track {
      background: Highlight;
    }
  }
</style>
