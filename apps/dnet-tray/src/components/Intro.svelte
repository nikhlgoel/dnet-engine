<script lang="ts">
  import { onMount } from 'svelte';
  import Mark from './Mark.svelte';

  /**
   * The opening (about a second and a half): the tunnel draws itself in, its doorway lights, and the picture opens
   * outward, as if the window were the far end of it. It is the logo, not a status: it makes no claim about the
   * connection, and it ends before the state is shown.
   *
   * It waits until the window is actually on screen (`running`), because the window is built hidden and shown when
   * the page has loaded; an opening that played while hidden would be over before anyone saw it. Any key or click
   * ends it at once. Under reduced motion it is not made at all (the caller does not render it).
   */
  let { running, ondone }: { running: boolean; ondone: () => void } = $props();

  onMount(() => {
    const skip = (): void => ondone();
    window.addEventListener('keydown', skip, { once: true });
    window.addEventListener('pointerdown', skip, { once: true });
    return () => {
      window.removeEventListener('keydown', skip);
      window.removeEventListener('pointerdown', skip);
    };
  });
</script>

<div class="intro" class:go={running} aria-hidden="true" onanimationend={(event) => event.target === event.currentTarget && ondone()}>
  <div class="tunnel">
    <Mark lamp="ok" size={176} draw={running} />
  </div>
</div>

<style>
  .intro {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: grid;
    place-items: center;
    background: var(--c-base);
  }

  /* Until the window is shown there is nothing to see: the page waits behind a plain ground. */
  .tunnel {
    opacity: 0;
  }

  .go .tunnel {
    opacity: 1;
    /* Held while the tunnel draws and lights, then opened outward through the last of the time. */
    animation: through var(--dur-4) var(--ease) calc(var(--dur-intro) - var(--dur-4)) forwards;
  }

  .go {
    animation: veil var(--dur-3) linear calc(var(--dur-intro) - var(--dur-3)) forwards;
  }

  @keyframes through {
    to {
      opacity: 0;
      transform: scale(7);
    }
  }

  @keyframes veil {
    to {
      opacity: 0;
    }
  }
</style>
