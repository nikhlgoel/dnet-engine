<script lang="ts">
  /**
   * Ctrl+K: go to a view or do the one thing the window does (design-system §6). It duplicates the dock and the
   * switch; nothing is reachable only from here.
   */
  import type { ViewId } from '../lib/app.svelte';
  import { en } from '../lib/messages';

  interface Command {
    id: string;
    label: string;
    run: () => void;
  }

  let { open, commands, onclose }: { open: boolean; commands: Command[]; onclose: () => void } = $props();

  let dialog: HTMLDialogElement;
  let input: HTMLInputElement;
  let query = $state('');
  let list: HTMLUListElement;

  const matches = $derived(
    commands.filter((c) => c.label.toLowerCase().includes(query.trim().toLowerCase())),
  );

  $effect(() => {
    if (open && !dialog.open) {
      query = '';
      dialog.showModal();
      input.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  });

  function choose(command: Command): void {
    onclose();
    command.run();
  }

  function buttons(): HTMLButtonElement[] {
    return [...list.querySelectorAll('button')];
  }

  function onkeydown(event: KeyboardEvent): void {
    const all = buttons();
    const at = all.indexOf(document.activeElement as HTMLButtonElement);
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      all[Math.min(all.length - 1, at + 1)]?.focus();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      if (at <= 0) input.focus();
      else all[at - 1]?.focus();
    } else if (event.key === 'Enter' && document.activeElement === input && matches[0]) {
      event.preventDefault();
      choose(matches[0]);
    }
  }
</script>

<dialog
  bind:this={dialog}
  aria-label={en.switcher.label}
  {onkeydown}
  oncancel={(event) => {
    event.preventDefault();
    onclose();
  }}
>
  <label class="sr-only" for="switcher-input">{en.switcher.label}</label>
  <input id="switcher-input" bind:this={input} bind:value={query} placeholder={en.switcher.placeholder} autocomplete="off" />
  <ul bind:this={list}>
    {#each matches as command (command.id)}
      <li><button type="button" onclick={() => choose(command)}>{command.label}</button></li>
    {:else}
      <li class="none">{en.switcher.none}</li>
    {/each}
  </ul>
</dialog>

<style>
  dialog {
    border: 1px solid var(--c-line-strong);
    border-radius: var(--r-card);
    padding: var(--s-3);
    background: var(--c-raised);
    color: var(--c-text);
    width: min(420px, calc(100% - 32px));
    margin-top: 12vh;
    box-shadow: var(--shadow-dialog);
  }

  dialog::backdrop {
    background: var(--c-scrim);
  }

  input {
    width: 100%;
    min-height: var(--hit);
    padding: 0 var(--s-3);
    border: 1px solid var(--c-line-strong);
    border-radius: var(--r-ctl);
    background: var(--c-card);
  }

  ul {
    margin-top: var(--s-2);
    display: grid;
  }

  li button {
    width: 100%;
    min-height: var(--hit);
    text-align: left;
    background: none;
    border: 0;
    border-radius: var(--r-ctl);
    padding: 0 var(--s-3);
    cursor: pointer;
  }

  li button:hover,
  li button:focus-visible {
    background: var(--c-card);
  }

  .none {
    color: var(--c-text-2);
    padding: var(--s-2) var(--s-3);
  }
</style>
