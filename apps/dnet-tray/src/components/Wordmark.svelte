<script lang="ts">
  /**
   * "DNET" in a 5×7 dot matrix (design-system §9). On first open the dots light in sequence, once; none of that
   * under reduced motion (the stylesheet turns the animation off).
   */
  const GLYPH: Record<string, readonly string[]> = {
    D: ['11110', '10001', '10001', '10001', '10001', '10001', '11110'],
    N: ['10001', '11001', '10101', '10011', '10001', '10001', '10001'],
    E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
    T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  };

  interface Dot {
    cx: number;
    cy: number;
    delay: number;
  }

  const dots: Dot[] = (() => {
    const out: Dot[] = [];
    let x = 2;
    let n = 0;
    for (const ch of 'DNET') {
      const rows = GLYPH[ch] ?? [];
      rows.forEach((row, y) => {
        [...row].forEach((on, i) => {
          if (on === '1') {
            out.push({ cx: x + i * 4, cy: 2 + y * 4, delay: n * 9 });
            n += 1;
          }
        });
      });
      x += 27;
    }
    return out;
  })();
</script>

<svg class="wm" width="108" height="28" viewBox="0 0 108 28" aria-hidden="true">
  {#each dots as dot}
    <circle cx={dot.cx} cy={dot.cy} r="1.35" fill="currentColor" style:animation-delay="{dot.delay}ms" />
  {/each}
</svg>

<style>
  .wm circle {
    transform-box: fill-box;
    transform-origin: center;
    animation: boot var(--dur-3) var(--ease) backwards;
  }

  @keyframes boot {
    from {
      opacity: 0;
      transform: scale(0.2);
    }
  }

  :global([data-motion='reduce']) .wm circle {
    animation: none;
  }
</style>
