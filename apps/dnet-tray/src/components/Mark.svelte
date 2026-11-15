<script lang="ts" module>
  /** The lamps the mark can show: the same five states the core and the tray show (design-system §5). */
  export type MarkLamp = 'off' | 'probe' | 'ok' | 'warn' | 'fail';

  let counter = 0;
</script>

<script lang="ts">
  /**
   * The tunnel mark (docs/design/icon): arches receding to a doorway. The doorway is the state, shown by SHAPE as
   * well as colour, the same as the tray icon: empty (off), filling and draining (probing, the only motion), lit
   * (connected), half lit (slow), lit with a gap through it (failed). So the logo in the window is a live part of it,
   * not a picture beside it.
   *
   * `draw` plays the arches in one after another (the opening animation); it is nothing under reduced motion.
   */
  let {
    lamp = 'ok',
    size = 28,
    draw = false,
    label = '',
  }: { lamp?: MarkLamp; size?: number; draw?: boolean; label?: string } = $props();

  const id = `door-${(counter += 1)}`;

  const BASE = 420;
  const arch = (w: number, apex: number): string => {
    const r = w / 2;
    return `M${256 - r} ${BASE} V${apex + r} A${r} ${r} 0 0 1 ${256 + r} ${apex + r} V${BASE}`;
  };
  const DOOR_W = 168;
  const DOOR_APEX = 216;
  const DOOR_H = BASE - DOOR_APEX;
  const door = `${arch(DOOR_W, DOOR_APEX)} Z`;
  const x0 = 256 - DOOR_W / 2;
  const half = DOOR_APEX + DOOR_H * 0.45;
</script>

<svg
  class="mark lamp-{lamp}"
  class:draw
  width={size}
  height={size}
  viewBox="0 0 512 512"
  role={label ? 'img' : undefined}
  aria-label={label || undefined}
  aria-hidden={label ? undefined : 'true'}
>
  <defs>
    <clipPath {id}><path d={door} /></clipPath>
  </defs>
  <path class="outer" d={arch(336, 92)} pathLength="1" />
  <path class="doorway" d={door} pathLength="1" />
  <g class="fill">
  {#if lamp === 'ok'}
    <path class="lit" d={door} />
  {:else if lamp === 'probe'}
    <g clip-path="url(#{id})">
      <rect class="rise" x={x0} y={DOOR_APEX} width={DOOR_W} height={DOOR_H + 2} />
    </g>
  {:else if lamp === 'warn'}
    <g clip-path="url(#{id})">
      <rect class="lit" x={x0} y={half} width={DOOR_W} height={BASE - half + 2} />
    </g>
  {:else if lamp === 'fail'}
    <path class="lit" d={door} />
    <rect class="gap" x={256 - 12} y={DOOR_APEX - 10} width="24" height={DOOR_H + 20} />
  {/if}
  </g>
</svg>

<style>
  .mark {
    flex: none;
    overflow: visible;
    --lamp: var(--c-text-3);
  }

  .lamp-ok {
    --lamp: var(--c-ok);
  }

  .lamp-probe {
    --lamp: var(--c-probe);
  }

  .lamp-warn {
    --lamp: var(--c-warn);
  }

  .lamp-fail {
    --lamp: var(--c-fail);
  }

  .outer {
    fill: none;
    stroke: var(--c-paper);
    stroke-width: 46;
    stroke-linecap: round;
    stroke-linejoin: round;
  }

  .doorway {
    fill: none;
    stroke: var(--lamp);
    stroke-width: 22;
    stroke-linejoin: round;
    transition: stroke var(--dur-3) var(--ease);
  }

  /* A lit doorway has no separate outline: the fill is the doorway. */
  .lamp-ok .doorway,
  .lamp-fail .doorway {
    stroke: none;
  }

  .lit,
  .rise {
    fill: var(--lamp);
    transition: fill var(--dur-3) var(--ease);
  }

  .gap {
    fill: var(--c-base);
  }

  /* The one motion: the doorway fills and drains while the service is finding a way through. */
  .rise {
    transform-box: fill-box;
    transform-origin: 50% 100%;
    animation: breathe var(--probe-period) ease-in-out infinite;
  }

  @keyframes breathe {
    0% {
      transform: scaleY(0);
    }
    42%,
    58% {
      transform: scaleY(1);
    }
    100% {
      transform: scaleY(0);
    }
  }

  /* The opening: the arches draw themselves in, outer first, then the doorway lights. */
  .draw .outer,
  .draw .doorway {
    stroke-dasharray: 1;
    stroke-dashoffset: 1;
    animation: stroke var(--dur-4) var(--ease) forwards;
  }

  .draw .doorway {
    animation-delay: var(--dur-3);
  }

  .draw .fill {
    opacity: 0;
    animation: appear var(--dur-3) var(--ease) calc(var(--dur-4) + var(--dur-2)) forwards;
  }

  @keyframes stroke {
    to {
      stroke-dashoffset: 0;
    }
  }

  @keyframes appear {
    to {
      opacity: 1;
    }
  }

  /* Reduced motion: every state is one still picture; the breath rests half full, so "trying" is still a shape. */
  :global([data-motion='reduce']) .rise {
    animation: none;
    transform: scaleY(0.5);
  }

  :global([data-motion='reduce']) .draw .outer,
  :global([data-motion='reduce']) .draw .doorway,
  :global([data-motion='reduce']) .draw .fill {
    animation: none;
    stroke-dashoffset: 0;
    opacity: 1;
  }
</style>
