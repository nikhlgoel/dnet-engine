<script lang="ts">
  import DisconnectNote from '../components/DisconnectNote.svelte';
  import type { AppState } from '../lib/app.svelte';
  import type { PreparedServer, ServerKind } from '../lib/bridge';
  import PendingChanges from '../components/PendingChanges.svelte';
  import { copyText } from '../lib/clipboard';
  import {
    GUIDES,
    OPTIONS,
    checkedOn,
    isPlausibleAddress,
    keyPermissionFix,
    portRows,
    sshCommand,
    wrapForPaste,
    type GuideId,
    type Step,
  } from '../lib/guide';
  import { en, fill } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.wizard;

  type Phase = 'choose' | 'provider' | 'steps';
  let phase = $state<Phase>('choose');
  let guideId = $state<GuideId | null>(null);
  let index = $state(0);

  // What the service made for this setup, and the choices the person made for it.
  let kind = $state<ServerKind | null>(null);
  let prepared = $state<PreparedServer | null>(null);
  let preparing = $state(false);
  let prepareError = $state<string | null>(null);

  let address = $state('');
  let user = $state(t.defaultUser);
  let keyFile = $state('');
  let label = $state(t.defaultName);
  let report = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let copied = $state<string | null>(null);
  let copyFailed = $state(false);

  /** How often a held server is looked for while the guide waits: it can be approved elsewhere too (`dnetctl`). */
  const HELD_CHECK_MS = 2000;
  /** The name of the server that waits for the person's approval (T160), while it does. */
  let held = $state<string | null>(null);
  /** The held server was dropped, or expired, without being added. */
  let heldDropped = $state(false);

  const guide = $derived(guideId ? GUIDES[guideId] : null);
  const step = $derived<Step | null>(guide ? (guide.steps[index] ?? null) : null);
  const connected = $derived((app.look?.switch.on ?? false) === true);
  const block = $derived(prepared ? wrapForPaste(prepared.script) : '');
  const connectCommand = $derived(sshCommand(address.trim(), user.trim(), keyFile.trim()));
  const permissionFix = $derived(keyPermissionFix(keyFile.trim()));
  const addressOk = $derived(isPlausibleAddress(address.trim()));

  /** The two kinds of processor, worded for the provider the person chose. */
  const kindChoices = $derived<{ value: ServerKind; name: string }[]>(
    guideId === 'oracle'
      ? [
          { value: 'arm64', name: t.kindArm },
          { value: 'amd64', name: t.kindAmd },
        ]
      : [
          { value: 'arm64', name: t.kindArmOther },
          { value: 'amd64', name: t.kindIntelOther },
        ],
  );

  /** Next is allowed once the thing the step needs exists. */
  const canGoOn = $derived(step?.action === 'kind' ? prepared !== null : true);

  function choose(id: GuideId): void {
    guideId = id;
  }

  function start(): void {
    index = 0;
    phase = 'steps';
  }

  function back(): void {
    if (index === 0) phase = 'provider';
    else index -= 1;
  }

  function forward(): void {
    if (guide && index < guide.steps.length - 1) index += 1;
  }

  async function pickKind(chosen: ServerKind): Promise<void> {
    kind = chosen;
    prepared = null;
    prepareError = null;
    preparing = true;
    const outcome = await app.bridge.prepareServer(chosen);
    preparing = false;
    if (outcome.ok && outcome.prepared) prepared = outcome.prepared;
    else prepareError = outcome.ok ? t.preparing : outcome.reason;
  }

  async function copy(what: string, text: string): Promise<void> {
    const ok = await copyText(text);
    copyFailed = !ok;
    copied = ok ? what : null;
  }

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    busy = true;
    error = null;
    heldDropped = false;
    const name = label.trim();
    const outcome = await app.bridge.finishServer({ label: name, host: address.trim(), report });
    busy = false;
    if (outcome.ok) {
      // The pasted text holds keys: it is dropped as soon as the service has it.
      report = '';
      forward();
    } else if (outcome.code === 'ApprovalRequired') {
      // Not refused: the service holds the server, and the text with it, until the person approves it. The
      // window's copy is dropped all the same. The service's own words name a command; the guide says it plainly.
      report = '';
      held = name;
    } else {
      error = outcome.reason;
    }
  }

  /** How a held change names this server: in quotes, as the service writes it (`shown` in `dnetd`). */
  function named(name: string): string {
    return `"${name.replace(/\p{Cc}/gu, '')}"`;
  }

  /** To the step after the one that adds the server, wherever the person is in the guide now. */
  function afterAdding(): void {
    const at = guide ? guide.steps.findIndex((s) => s.action === 'paste') : -1;
    if (guide && at >= 0 && at < guide.steps.length - 1) {
      phase = 'steps';
      index = at + 1;
    }
  }

  /**
   * Where the held server is now. The waiting list is read first: the service adds an approved server before it
   * takes the change off the list, so a server found in neither place was not added.
   */
  async function settle(): Promise<void> {
    const name = held;
    if (name === null) return;
    try {
      const waiting = await app.bridge.pending();
      if (held !== name || waiting.some((c) => c.what.includes(named(name)))) return;
      const servers = await app.bridge.endpoints();
      if (held !== name) return;
      held = null;
      if (servers.some((e) => e.label === name)) afterAdding();
      else heldDropped = true;
    } catch {
      // No answer now: asked again at the next check.
    }
  }

  // While a server waits, look for it now and then; nothing is sent while the window is hidden (ADR-0007 R2).
  $effect(() => {
    if (held === null) return;
    const timer = setInterval(() => {
      if (app.visible) void settle();
    }, HELD_CHECK_MS);
    return () => clearInterval(timer);
  });
</script>

<section class="view" aria-labelledby="wizard-title">
  <h1 id="wizard-title">{t.title}</h1>

  {#if phase === 'choose'}
    <p class="lede">{t.lede}</p>
    <h2>{t.chooseTitle}</h2>
    <div class="options">
      {#each OPTIONS as option (option.id)}
        <section class="card option" role="group" aria-labelledby={`opt-${option.id}`}>
          <div class="head">
            <h3 id={`opt-${option.id}`}>{option.title}</h3>
            {#if option.recommended}<span class="badge">{t.recommended}</span>{/if}
          </div>
          <p>{option.summary}</p>
          <!-- The way to start comes before the long comparison, so nobody has to scroll to find it. -->
          {#if option.available}
            <button type="button" class="btn primary" onclick={() => (phase = 'provider')}>{t.useServer}</button>
          {:else}
            <button type="button" class="btn" disabled>{t.useWithout}</button>
            <p class="help">{t.notYet}</p>
          {/if}
          <h4>{t.whatYouGet}</h4>
          <ul class="features">
            {#each option.features as feature (feature.text)}
              <li>
                <span class={feature.included ? 'yes' : 'no'}>{feature.included ? t.included : t.notIncluded}</span>
                {feature.text}
              </li>
            {/each}
          </ul>
          <h4>{t.goodSides}</h4>
          <ul>{#each option.pros as line (line)}<li>{line}</li>{/each}</ul>
          <h4>{t.otherSides}</h4>
          <ul>{#each option.cons as line (line)}<li>{line}</li>{/each}</ul>
        </section>
      {/each}
    </div>
  {:else if phase === 'provider'}
    <h2>{t.providerTitle}</h2>
    <p class="lede">{t.providerLede}</p>
    <div class="options">
      {#each Object.values(GUIDES) as g (g.id)}
        <button
          type="button"
          class="card pick"
          aria-pressed={guideId === g.id}
          onclick={() => choose(g.id)}
        >
          <span class="head">
            <strong class="disp">{g.name}</strong>
            {#if guideId === g.id}<span class="badge">{t.chosen}</span>{/if}
          </span>
          <span>{g.summary}</span>
        </button>
      {/each}
    </div>
    {#if guide && guide.facts.length > 0}
      <div class="card">
        <ul>{#each guide.facts as fact (fact.text)}<li>{fact.text}</li>{/each}</ul>
        <p class="help">{fill(t.checkedOn, { date: checkedOn(guide) ?? '' })}</p>
      </div>
    {/if}
    <div class="actions">
      <button type="button" class="btn" onclick={() => (phase = 'choose')}>{t.back}</button>
      <button type="button" class="btn primary" disabled={guide === null} onclick={start}>{t.continue}</button>
    </div>
  {:else if guide && step}
    <p class="steps-of num">{fill(t.stepOf, { n: index + 1, total: guide.steps.length })}</p>
    <h2>{step.title}</h2>

    {#if step.action !== 'done'}
      <h3>{t.whatToDo}</h3>
      <ol class="todo">{#each step.do as line (line)}<li>{line}</li>{/each}</ol>
    {:else}
      <p>{t.doneBody}</p>
    {/if}

    {#if step.action === 'kind'}
      <fieldset class="kinds">
        <legend>{t.kindLabel}</legend>
        {#each kindChoices as choice (choice.value)}
          <label class="radio">
            <input type="radio" name="kind" value={choice.value} checked={kind === choice.value} onchange={() => pickKind(choice.value)} />
            {choice.name}
          </label>
        {/each}
      </fieldset>
      {#if preparing}<p class="help" role="status">{t.preparing}</p>{/if}
      {#if prepareError}<p class="notice" role="alert">{prepareError}</p>{/if}
      {#if prepared}<p class="help" role="status">{fill(t.ready, { minutes: prepared.validForMinutes })}</p>{/if}
    {:else if step.action === 'ports' && prepared}
      <p>{t.portsLede}</p>
      <table class="ports">
        <thead><tr>{#each t.portsHead as head (head)}<th scope="col">{head}</th>{/each}</tr></thead>
        <tbody>
          {#each portRows(prepared.ports) as row (row.protocol + row.port)}
            <tr><td>{row.protocol}</td><td class="num">{row.port}</td><td class="num">{row.source}</td></tr>
          {/each}
        </tbody>
      </table>
    {:else if step.action === 'run'}
      <div class="field">
        <label for="w-address">{t.addressLabel}</label>
        <input id="w-address" bind:value={address} autocomplete="off" spellcheck="false" />
        <span class="help">{t.addressHelp}</span>
      </div>
      <div class="field">
        <label for="w-user">{t.userLabel}</label>
        <input id="w-user" bind:value={user} autocomplete="off" spellcheck="false" />
        <span class="help">{t.userHelp}</span>
      </div>
      <div class="field">
        <label for="w-key">{t.keyLabel}</label>
        <input id="w-key" bind:value={keyFile} autocomplete="off" spellcheck="false" />
        <span class="help">{t.keyHelp}</span>
      </div>
      <p class="label">{t.connectLabel}</p>
      <pre class="code" data-testid="ssh-command">{connectCommand}</pre>
      <button type="button" class="btn" aria-label={`${t.copy}: ${t.connectLabel}`} onclick={() => copy('ssh', connectCommand)}>{t.copy}</button>
      <details>
        <summary>{t.permissionFix}</summary>
        <pre class="code">{permissionFix}</pre>
        <button type="button" class="btn" aria-label={`${t.copy}: ${t.permissionFix}`} onclick={() => copy('fix', permissionFix)}>{t.copy}</button>
      </details>
      <div class="field">
        <label for="w-block">{t.pasteBlock}</label>
        <textarea id="w-block" readonly rows="8" value={block}></textarea>
      </div>
      <button type="button" class="btn primary" aria-label={`${t.copy}: ${t.pasteBlock}`} onclick={() => copy('block', block)}>{t.copy}</button>
      {#if copied}<span class="help" role="status">{t.copied}</span>{/if}
      {#if copyFailed}<p class="notice" role="status">{t.copyFailed}</p>{/if}
    {:else if step.action === 'paste' && held !== null}
      <p class="notice" role="status">{t.held}</p>
      <PendingChanges {app} onsettled={() => void settle()} />
    {:else if step.action === 'paste'}
      {#if connected}<DisconnectNote {app} text={t.disconnectFirst} />{/if}
      {#if heldDropped}<p class="notice" role="status">{t.heldDropped}</p>{/if}
      <form class="form" onsubmit={submit}>
        <div class="field">
          <label for="w-label">{t.nameLabel}</label>
          <input id="w-label" bind:value={label} required maxlength="64" autocomplete="off" />
          <span class="help">{t.nameHelp}</span>
        </div>
        <div class="field">
          <label for="w-host">{t.addressLabel}</label>
          <input id="w-host" bind:value={address} required autocomplete="off" spellcheck="false" />
          <span class="help">{t.addressHelp}</span>
        </div>
        <div class="field">
          <label for="w-report">{t.reportLabel}</label>
          <textarea id="w-report" bind:value={report} rows="6" spellcheck="false" required></textarea>
          <span class="help">{t.reportHelp}</span>
        </div>
        {#if error}<p class="notice" role="alert">{error}</p>{/if}
        <button type="submit" class="btn primary" disabled={busy || connected || report.trim() === '' || !addressOk}>
          {busy ? t.adding : t.submit}
        </button>
      </form>
    {:else if step.action === 'done'}
      <div class="actions">
        <button type="button" class="btn primary" onclick={() => app.go('status')}>{t.goStatus}</button>
        <button type="button" class="btn" onclick={() => app.go('endpoints')}>{t.goServers}</button>
      </div>
    {/if}

    {#if step.see}
      <h3>{t.youShouldSee}</h3>
      <p>{step.see}</p>
    {/if}
    {#if step.stuck && step.stuck.length > 0}
      <details>
        <summary>{t.ifDifferent}</summary>
        <ul>{#each step.stuck as line (line)}<li>{line}</li>{/each}</ul>
      </details>
    {/if}

    {#if step.action !== 'done'}
      <div class="actions">
        <button type="button" class="btn" onclick={back}>{t.back}</button>
        {#if step.action !== 'paste'}
          <button type="button" class="btn primary" disabled={!canGoOn} onclick={forward}>{t.next}</button>
        {/if}
      </div>
    {/if}
  {/if}

  <div class="actions">
    <button type="button" class="btn" onclick={() => app.go('endpoints')}>{t.close}</button>
  </div>
</section>

<style>
  .options {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: var(--s-3);
  }

  .option,
  .pick {
    display: grid;
    gap: var(--s-2);
    align-content: start;
    text-align: left;
  }

  .pick {
    cursor: pointer;
    font: inherit;
    color: inherit;
    /* A button brings the browser's own white border; the card's edge is the design's. */
    border: 1px solid var(--c-line-strong);
  }

  .pick[aria-pressed='true'] {
    border-color: var(--c-paper);
    outline: 2px solid var(--c-focus);
  }

  .head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--s-3);
  }

  .badge {
    font-size: var(--fs-sm);
    border: 1px solid var(--c-text-2);
    border-radius: var(--r-ctl);
    padding: 0 var(--s-2);
  }

  h2,
  h3 {
    font-weight: 600;
  }

  h4 {
    font-size: var(--fs-sm);
    color: var(--c-text-2);
  }

  .features .yes,
  .features .no {
    font-size: var(--fs-sm);
    margin-right: var(--s-2);
  }

  .features .no,
  .help,
  .steps-of {
    color: var(--c-text-2);
  }

  .todo {
    list-style: decimal;
    padding-left: 1.6em;
    display: grid;
    gap: var(--s-2);
  }

  .option ul,
  details ul {
    list-style: disc;
    padding-left: 1.2em;
    display: grid;
    gap: var(--s-1, 4px);
  }

  .option .features {
    list-style: none;
    padding-left: 0;
  }

  .kinds {
    display: grid;
    gap: var(--s-2);
    border: 0;
    padding: 0;
  }

  .radio {
    display: flex;
    gap: var(--s-2);
    align-items: center;
  }

  .code {
    font-family: var(--font-num);
    white-space: pre-wrap;
    word-break: break-all;
    background: var(--c-surface-2, transparent);
    border: 1px solid var(--c-text-3);
    border-radius: var(--r-ctl);
    padding: var(--s-2) var(--s-3);
    margin: var(--s-2) 0;
  }

  .ports {
    border-collapse: collapse;
  }

  .ports th,
  .ports td {
    text-align: left;
    padding: var(--s-1, 4px) var(--s-4);
    border-bottom: 1px solid var(--c-text-3);
  }

  .form {
    display: grid;
    gap: var(--s-4);
    max-width: 560px;
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
  }
</style>
