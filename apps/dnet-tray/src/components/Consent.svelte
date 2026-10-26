<script lang="ts">
  /**
   * A consent (design-system §13): a modal <dialog> that states the consequence. The rules, all of them
   * enforced here so no caller can forget one:
   *
   * - the two buttons have equal weight (neither is the filled primary);
   * - initial focus is on the safe choice, the first button;
   * - Esc declines;
   * - the consequence is a callout before the buttons;
   * - the buttons are verbs that say what happens.
   */
  let {
    open,
    title,
    paragraphs = [],
    consequence,
    note = '',
    decline,
    accept,
    ondecline,
    onaccept,
  }: {
    open: boolean;
    title: string;
    paragraphs?: string[];
    consequence: string;
    note?: string;
    decline: string;
    accept: string;
    ondecline: () => void;
    onaccept: () => void;
  } = $props();

  // Several consents live in the page at once (closed); each needs its own id for its label.
  const uid = $props.id();
  let dialog: HTMLDialogElement;
  let safe: HTMLButtonElement;

  $effect(() => {
    if (open && !dialog.open) {
      dialog.showModal();
      safe.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  });
</script>

<dialog
  bind:this={dialog}
  aria-labelledby="{uid}-title"
  oncancel={(event) => {
    // Esc declines. The dialog is closed by the `open` prop, not by the browser, so state stays in one place.
    event.preventDefault();
    ondecline();
  }}
>
  <div class="body">
    <h2 id="{uid}-title">{title}</h2>
    {#each paragraphs as paragraph}
      <p>{paragraph}</p>
    {/each}
    <p class="consequence">{consequence}</p>
    {#if note}
      <p class="note">{note}</p>
    {/if}
  </div>
  <div class="foot">
    <button type="button" class="btn" bind:this={safe} onclick={ondecline}>{decline}</button>
    <button type="button" class="btn" onclick={onaccept}>{accept}</button>
  </div>
</dialog>

<style>
  dialog {
    border: 1px solid var(--c-line-strong);
    border-radius: var(--r-card);
    padding: 0;
    background: var(--c-raised);
    color: var(--c-text);
    width: min(460px, calc(100% - 32px));
    box-shadow: var(--shadow-dialog);
  }

  dialog::backdrop {
    background: var(--c-scrim);
  }

  .body {
    padding: var(--s-5);
    display: grid;
    gap: var(--s-3);
  }

  h2 {
    font: 600 var(--fs-xl) / var(--lh-tight) var(--font-display);
  }

  .consequence {
    padding: var(--s-3) var(--s-4);
    border-left: 3px solid var(--c-warn);
    background: var(--c-warn-bg);
  }

  .note {
    color: var(--c-text-2);
  }

  .foot {
    display: flex;
    justify-content: flex-end;
    gap: var(--s-3);
    padding: var(--s-4) var(--s-5);
    border-top: 1px solid var(--c-line);
  }
</style>
