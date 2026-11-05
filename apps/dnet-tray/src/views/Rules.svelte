<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import DisconnectNote from '../components/DisconnectNote.svelte';
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
  /** A rule this view asked for waits for the person's approval (T160); how many times it has asked. */
  let held = $state(false);
  let asked = $state(0);

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
    // A rule held for approval was not refused: it waits in the list above (T160).
    const waits = !outcome.ok && outcome.code === 'ApprovalRequired';
    changeError = outcome.ok || waits ? null : outcome.reason;
    held = waits;
    if (waits) asked += 1;
    if (outcome.ok || waits) value = '';
    if (outcome.ok) await load();
  }

  /** A waiting change was approved or dropped in the list: the rules are read again. */
  async function settled(): Promise<void> {
    held = false;
    await load();
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

  <PendingChanges {app} {asked} onsettled={settled} />

  {#if held}
    <p class="notice" role="status">{t.held}</p>
  {/if}
  {#if error}
    <p class="notice" role="alert">{error}</p>
  {:else}
    <h2 class="cat">{t.add}</h2>
    <form class="card add" onsubmit={add}>
      <div class="fields">
        <label>
          {t.match}
          <select class="input" bind:value={kind} disabled={connected || busy}>
            <option value="domain_suffix">{t.matchSuffix}</option>
            <option value="domain">{t.matchDomain}</option>
            <option value="ip_cidr">{t.matchCidr}</option>
          </select>
        </label>
        <label>
          {t.value}
          <input class="input" type="text" autocomplete="off" spellcheck="false" bind:value disabled={connected || busy} />
        </label>
        <label>
          {t.sendIt}
          <select class="input" bind:value={action} disabled={connected || busy}>
            <option value="tunnel">{t.tunnel}</option>
            <option value="bypass">{t.bypass}</option>
          </select>
        </label>
        <button type="submit" class="btn primary" disabled={connected || busy || value.trim() === ''}>{t.addButton}</button>
      </div>
      <p class="help-line">{t.valueHelp}</p>
      {#if connected}
        <DisconnectNote {app} />
      {:else}
        <p class="help-line">{t.appliesNext}</p>
      {/if}
      {#if changeError}
        <p class="notice" role="alert">{changeError}</p>
      {/if}
    </form>

    <h2 class="cat">{t.listTitle}</h2>
    {#if own.length === 0}
      <p class="empty">{t.empty}</p>
    {/if}

    <div class="panel">
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
              <td class="num order">{rule.precedence}</td>
              <td class="match">{describe(rule)}</td>
              <td>{rule.action}</td>
              <!-- Best-effort is said in the row itself, not in a tooltip (Principle VI). -->
              <td class:best={rule.reliability === 'BestEffort'}>
                {rule.reliability === 'BestEffort' ? t.bestEffort : t.reliable}
              </td>
              <td class="dim end">
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
    </div>
    <p class="help-line">{t.bestEffortNote}</p>
  {/if}
</section>

<style>
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--fs-sm);
  }

  th,
  td {
    text-align: left;
    padding: var(--s-3) var(--s-4);
    border-top: 1px solid var(--c-line);
    vertical-align: middle;
  }

  thead th {
    color: var(--c-text-3);
    font-weight: 500;
    font-size: var(--fs-xs);
    border-top: 0;
  }

  .order {
    width: 1%;
    white-space: nowrap;
  }

  .end {
    text-align: right;
  }

  .best {
    font-weight: 600;
  }

  /* Name, value, where it goes, and the button, on one line; two by two in a narrow window. */
  .fields {
    display: grid;
    grid-template-columns: 1fr 1.4fr 1fr auto;
    gap: var(--s-3);
    align-items: end;
  }

  .fields label {
    display: grid;
    gap: var(--s-1);
    font-size: var(--fs-sm);
    font-weight: 500;
  }

  @media (max-width: 720px) {
    .fields {
      grid-template-columns: 1fr 1fr;
    }
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
