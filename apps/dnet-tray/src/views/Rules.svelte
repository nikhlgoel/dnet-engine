<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import PendingChanges from '../components/PendingChanges.svelte';
  import { en } from '../lib/messages';
  import type { RuleView } from '../lib/model';
  import type { NewRuleInput } from '../lib/bridge';

  let { app }: { app: AppState } = $props();

  const t = en.views.rules;
  let rules = $state<RuleView[]>([]);
  let error = $state<string | null>(null);
  let changeError = $state<string | null>(null);
  let kind = $state<NewRuleInput['kind']>('domain_suffix');
  let value = $state('');
  let action = $state<NewRuleInput['action']>('tunnel');
  let busy = $state(false);

  const connected = $derived((app.look?.switch.on ?? false) === true);

  async function load(): Promise<void> {
    try {
      rules = (await app.bridge.rules()).rules;
      error = null;
    } catch (e) {
      error = app.reason(e);
    }
  }

  onMount(load);

  function describe(rule: RuleView): string {
    return t.describe[rule.kind].replace('{value}', rule.value);
  }

  async function add(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    const outcome = await app.bridge.addRule({ kind, value: value.trim(), action });
    busy = false;
    changeError = outcome.ok ? null : outcome.reason;
    if (outcome.ok) {
      value = '';
      await load();
    }
  }

  async function remove(rule: RuleView): Promise<void> {
    const outcome = await app.bridge.removeRule(rule.id);
    changeError = outcome.ok ? null : outcome.reason;
    if (outcome.ok) await load();
  }

  const own = $derived(rules.filter((r) => !r.builtin));
  const builtin = $derived(rules.filter((r) => r.builtin));
</script>

<section class="view" aria-labelledby="rules-title">
  <h1 id="rules-title">{t.title}</h1>
  <p class="lede">{t.explainer}</p>

  <PendingChanges {app} />

  {#if error}
    <p class="notice" role="alert">{error}</p>
  {:else}
    <form class="card add" onsubmit={add}>
      <h2>{t.add}</h2>
      <label>
        {t.match}
        <select bind:value={kind} disabled={connected || busy}>
          <option value="domain_suffix">{t.matchSuffix}</option>
          <option value="domain">{t.matchDomain}</option>
          <option value="ip_cidr">{t.matchCidr}</option>
        </select>
      </label>
      <label>
        {t.value}
        <input type="text" autocomplete="off" spellcheck="false" bind:value disabled={connected || busy} />
      </label>
      <p class="help-line">{t.valueHelp}</p>
      <label>
        {t.sendIt}
        <select bind:value={action} disabled={connected || busy}>
          <option value="tunnel">{t.tunnel}</option>
          <option value="bypass">{t.bypass}</option>
        </select>
      </label>
      <div>
        <button type="submit" class="btn" disabled={connected || busy || value.trim() === ''}>{t.addButton}</button>
      </div>
      {#if connected}
        <p class="help-line">{en.errors.disconnectFirst}</p>
      {:else}
        <p class="help-line">{t.appliesNext}</p>
      {/if}
      {#if changeError}
        <p class="notice" role="alert">{changeError}</p>
      {/if}
    </form>

    {#if own.length === 0}
      <p class="empty">{t.empty}</p>
    {/if}

  <table>
    <thead>
      <tr>
        <th>{t.precedence}</th>
        <th>{t.matches}</th>
        <th>{t.action}</th>
        <th>{t.kind}</th>
        <th><span class="sr-only">{t.origin}</span></th>
      </tr>
    </thead>
    <tbody>
      {#each [...own, ...builtin] as rule (rule.id)}
        <tr>
          <td class="num">{rule.precedence}</td>
          <td class="match">{describe(rule)}</td>
          <td>{rule.action}</td>
          <!-- Best-effort is said in the row itself, not in a tooltip (Principle VI). -->
          <td class:best={rule.reliability === 'BestEffort'}>
            {rule.reliability === 'BestEffort' ? t.bestEffort : t.reliable}
          </td>
          <td class="dim">
            {#if rule.builtin}
              {t.builtin}
            {:else}
              <button
                type="button"
                class="btn"
                disabled={connected}
                aria-label={t.removeLabel.replace('{value}', rule.value)}
                onclick={() => remove(rule)}>{t.remove}</button
              >
            {/if}
          </td>
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

  .add {
    display: grid;
    gap: var(--s-2);
    max-width: 720px;
    margin-bottom: var(--s-4);
  }

  .add label {
    display: grid;
    gap: var(--s-1);
  }

  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
  }

  .match {
    overflow-wrap: anywhere;
  }

  .dim,
  .help-line {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }
</style>
