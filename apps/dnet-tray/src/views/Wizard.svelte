<script lang="ts">
  import type { AppState } from '../lib/app.svelte';
  import { en, fill } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.wizard;
  const steps = t.steps;
  const available = $derived(app.bridge.capabilities.provisioning);
</script>

<section class="view" aria-labelledby="wizard-title">
  <h1 id="wizard-title">{t.title}</h1>
  <p class="lede">{t.body}</p>

  {#if !available}
    <p class="notice" role="status">{t.unavailable}</p>
  {/if}

  <ol class="steps">
    {#each steps as name, i (name)}
      <li class="card">
        <span class="num n">{i + 1}</span>
        <span>{fill(t.stepOf, { n: i + 1, total: steps.length, name })}</span>
      </li>
    {/each}
  </ol>

  <div class="actions">
    <button type="button" class="btn" onclick={() => app.go('endpoints')}>{t.close}</button>
  </div>
</section>

<style>
  .steps {
    display: grid;
    gap: var(--s-2);
    max-width: 560px;
  }

  .steps li {
    grid-template-columns: 2em 1fr;
    align-items: center;
  }

  .n {
    color: var(--c-text-3);
  }

  .actions {
    display: flex;
    gap: var(--s-3);
  }
</style>
