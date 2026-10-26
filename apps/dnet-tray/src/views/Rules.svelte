<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import { en } from '../lib/messages';
  import type { RuleView } from '../lib/model';

  let { app }: { app: AppState } = $props();

  const t = en.views.rules;
  let rules = $state<RuleView[]>([]);
  let error = $state<string | null>(null);

  onMount(async () => {
    try {
      rules = (await app.bridge.rules()).rules;
    } catch (e) {
      error = app.reason(e);
    }
  });

  const own = $derived(rules.filter((r) => !r.builtin));
  const builtin = $derived(rules.filter((r) => r.builtin));
</script>

<section class="view" aria-labelledby="rules-title">
  <h1 id="rules-title">{t.title}</h1>
  <p class="lede">{t.explainer}</p>

  {#if error}
    <p class="notice" role="alert">{error}</p>
  {:else}
    {#if own.length === 0}
      <p class="empty">{t.empty}</p>
    {/if}

  <table>
    <thead>
      <tr>
        <th>{t.precedence}</th>
        <th>{t.action}</th>
        <th>{t.kind}</th>
        <th><span class="sr-only">{t.origin}</span></th>
      </tr>
    </thead>
    <tbody>
      {#each [...own, ...builtin] as rule (`${rule.precedence}-${rule.action}`)}
        <tr>
          <td class="num">{rule.precedence}</td>
          <td>{rule.action}</td>
          <!-- Best-effort is said in the row itself, not in a tooltip (Principle VI). -->
          <td class:best={rule.reliability === 'BestEffort'}>
            {rule.reliability === 'BestEffort' ? t.bestEffort : t.reliable}
          </td>
          <td class="dim">{rule.builtin ? t.builtin : ''}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="help-line">{t.bestEffortNote}</p>
  {/if}
</section>

<style>
  table {
    width: 100%;
    max-width: 720px;
    border-collapse: collapse;
    font-size: var(--fs-sm);
  }

  th,
  td {
    text-align: left;
    padding: 6px var(--s-3) 6px 0;
    border-top: 1px solid var(--c-line);
  }

  th {
    color: var(--c-text-3);
    font-weight: 500;
    font-size: var(--fs-xs);
    border-top: 0;
  }

  .best {
    font-weight: 600;
  }

  .dim,
  .help-line {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }
</style>
