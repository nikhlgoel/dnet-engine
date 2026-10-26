<script lang="ts">
  import { onMount } from 'svelte';
  import type { Chip, Look } from '../lib/describe';
  import { Scene, radiusFor, type SceneColors, type Slot } from '../lib/scene';
  import Icon from './Icon.svelte';

  let {
    look,
    chips,
    still,
    visible,
    themeKey,
    ontoggle,
  }: {
    look: Look;
    chips: Chip[];
    /** Reduced motion: one static frame per state. */
    still: boolean;
    /** False while the window is hidden or minimised: the loop stops. */
    visible: boolean;
    /** Changes when the theme does, so the canvas re-reads its colours. */
    themeKey: string;
    /** The core is clickable with a pointer; the accessible control is the labelled switch (§5). */
    ontoggle: () => void;
  } = $props();

  let box: HTMLDivElement;
  let canvas: HTMLCanvasElement;
  let scene: Scene | undefined;
  let slots = $state<Slot[]>([]);
  let width = $state(0);
  let height = $state(0);
  let widths = $state<number[]>([]);
  let raf = 0;
  let last = 0;

  function colors(): SceneColors {
    const css = getComputedStyle(document.documentElement);
    const read = (name: string): string => css.getPropertyValue(name).trim();
    return {
      text2: read('--c-text-2'),
      text3: read('--c-text-3'),
      ok: read('--c-ok'),
      probe: read('--c-probe'),
      warn: read('--c-warn'),
      fail: read('--c-fail'),
    };
  }

  function frame(ts: number): void {
    raf = requestAnimationFrame(frame);
    if (!scene) return;
    if (ts - last < scene.frameIntervalMs) return;
    const dt = Math.min(0.1, (ts - last) / 1000);
    last = ts;
    scene.draw(ts / 1000, dt, false);
  }

  /** (Re)start the loop, or stop it and draw one still frame. Nothing runs while hidden. */
  function kick(): void {
    cancelAnimationFrame(raf);
    raf = 0;
    if (!scene) return;
    if (still || !visible) {
      if (visible) scene.draw(0, 0, true);
      return;
    }
    last = 0;
    raf = requestAnimationFrame(frame);
  }

  onMount(() => {
    scene = new Scene(canvas, colors());
    const observer = new ResizeObserver(() => {
      const r = box.getBoundingClientRect();
      width = r.width;
      height = r.height;
      slots = scene?.resize(r.width, r.height, window.devicePixelRatio) ?? [];
      kick();
    });
    observer.observe(box);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(raf);
    };
  });

  $effect(() => {
    // Re-read the colours when the theme changes (after the attribute has been applied).
    void themeKey;
    queueMicrotask(() => {
      scene?.setColors(colors());
      kick();
    });
  });

  $effect(() => {
    scene?.setState(look.lamp, look.shape, still);
    scene?.setNetworks(chips.map((c) => c.role));
    kick();
  });

  $effect(() => {
    void visible;
    void still;
    kick();
  });

  // Each chip is kept inside the scene whatever its text: measured, then clamped.
  function left(i: number, slot: Slot): number {
    const w = widths[i] ?? 0;
    return slot.left ? Math.max(slot.x, w + 14) : Math.min(slot.x, width - w - 14);
  }

  const hit = $derived(radiusFor(height) * 1.25);
</script>

<div class="scene" bind:this={box} role="group" aria-label="Your networks">
  <canvas bind:this={canvas} aria-hidden="true"></canvas>
  <!-- A pointer convenience only. The labelled switch below is the accessible control. -->
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="core-hit"
    aria-hidden="true"
    style:left="{width / 2 - hit}px"
    style:top="{height / 2 - hit}px"
    style:width="{hit * 2}px"
    style:height="{hit * 2}px"
    onclick={ontoggle}
  ></div>
  <ul class="sats">
    {#each chips as chip, i (chip.id)}
      {@const slot = slots[i]}
      {#if slot}
        <li
          class="sat {slot.left ? 'l' : 'r'}"
          data-role={chip.role}
          bind:clientWidth={widths[i]}
          style:left="{left(i, slot)}px"
          style:top="{slot.y}px"
        >
          <Icon name={chip.kind === 'Wifi' ? 'wifi' : chip.kind === 'Cellular' ? 'cell' : 'eth'} size={22} />
          <span class="name">{chip.title}</span>
          <span class="role">
            <svg class="mk" viewBox="0 0 10 10" aria-hidden="true">
              {#if chip.role === 'carry'}
                <circle cx="5" cy="5" r="4.2" fill="currentColor" />
              {:else if chip.role === 'lost'}
                <path d="M1.5 1.5l7 7M8.5 1.5l-7 7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              {:else}
                <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" stroke-width="1.5" />
              {/if}
            </svg>
            {chip.roleText}
          </span>
          <span class="m num">{chip.metrics}</span>
        </li>
      {/if}
    {/each}
  </ul>
</div>

<style>
  .scene {
    position: relative;
    flex: 1;
    min-height: 200px;
  }

  canvas {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
  }

  .core-hit {
    position: absolute;
    border-radius: 50%;
    cursor: pointer;
    transition: box-shadow var(--dur-2) var(--ease);
  }

  .core-hit:hover {
    box-shadow: 0 0 0 1px var(--c-line-strong);
  }

  .sats {
    position: absolute;
    inset: 0;
    pointer-events: none;
  }

  .sat {
    position: absolute;
    pointer-events: auto;
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 1px 10px;
    align-items: center;
    min-width: 148px;
    padding: 8px 12px;
    border: 1px solid transparent;
    border-radius: 12px;
    background: color-mix(in srgb, var(--c-card) 72%, transparent);
    backdrop-filter: blur(6px);
  }

  .sat.l {
    transform: translate(-100%, -50%);
  }

  .sat.r {
    transform: translate(0, -50%);
  }

  .sat :global(svg:first-child) {
    grid-row: 1 / 3;
    color: var(--c-text-2);
  }

  .name {
    font: 500 14px/1.2 var(--font-display);
    letter-spacing: 0.01em;
  }

  .role {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--fs-xs);
    color: var(--c-text-2);
  }

  .mk {
    width: 9px;
    height: 9px;
    flex: none;
  }

  .m {
    grid-column: 1 / -1;
    font-size: var(--fs-xs);
    color: var(--c-text-2);
    padding-top: 2px;
    white-space: nowrap;
  }

  .sat[data-role='carry'] {
    border-color: color-mix(in srgb, var(--ambient) 40%, transparent);
    background: color-mix(in srgb, var(--c-card) 88%, transparent);
  }

  .sat[data-role='carry'] .mk {
    color: var(--ambient);
  }

  .sat[data-role='lost'] {
    border-style: dashed;
    color: var(--c-text-3);
  }
</style>
