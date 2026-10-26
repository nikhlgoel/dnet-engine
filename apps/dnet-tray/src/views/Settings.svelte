<script lang="ts">
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import Consent from '../components/Consent.svelte';
  import { disclosure, en } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.views.settings;
  const dns = en.consent.dns;
  let block = $state(true);
  let known = $state(false);
  let askOptOut = $state(false);
  let consequence = $state<string | null>(null);
  let error = $state<string | null>(null);
  let checking = $state(false);
  let result = $state<string | null>(null);

  const connected = $derived((app.look?.switch.on ?? false) === true);
  const locked = $derived(connected || !known);

  onMount(async () => {
    try {
      block = (await app.bridge.rules()).encryptedDns.block;
      known = true;
    } catch (e) {
      // Not knowing the setting is not the same as it being on: say so, and do not offer to change it.
      error = app.reason(e);
    }
  });

  /** Turning the block off asks first and states the consequence; turning it on needs no consent (§13). */
  async function onchange(event: Event): Promise<void> {
    const wants = (event.currentTarget as HTMLInputElement).checked;
    if (!wants) {
      askOptOut = true;
      // Keep the switch where it was until the person answers.
      (event.currentTarget as HTMLInputElement).checked = true;
      return;
    }
    const outcome = await app.bridge.setEncryptedDns(true);
    error = outcome.ok ? null : outcome.reason;
    if (outcome.ok) {
      block = true;
      consequence = null;
    }
  }

  async function optOut(): Promise<void> {
    askOptOut = false;
    const outcome = await app.bridge.setEncryptedDns(false);
    error = outcome.ok ? null : outcome.reason;
    if (outcome.ok) {
      block = false;
      // The service's own words, shown after the fact as well as before it.
      consequence = outcome.consequence ?? disclosure.consequenceOfOptingOut;
    }
  }

  async function checkNow(): Promise<void> {
    checking = true;
    result = null;
    const outcome = await app.bridge.checkUpdates();
    checking = false;
    result = outcome.ok ? (outcome.route === 'physical' ? 'physical' : 'tunnel') : outcome.reason;
  }
</script>

<section class="view" aria-labelledby="settings-title">
  <h1 id="settings-title">{t.title}</h1>

  <fieldset class="card">
    <legend>{t.theme}</legend>
    <label><input type="radio" name="theme" checked={app.theme === 'system'} onchange={() => app.setTheme('system')} /> {t.themeSystem}</label>
    <label><input type="radio" name="theme" checked={app.theme === 'dark'} onchange={() => app.setTheme('dark')} /> {t.themeDark}</label>
    <label><input type="radio" name="theme" checked={app.theme === 'light'} onchange={() => app.setTheme('light')} /> {t.themeLight}</label>
  </fieldset>

  <div class="card">
    <label>
      <input type="checkbox" checked={app.reduceMotion} onchange={(e) => app.setReduceMotion(e.currentTarget.checked)} />
      {t.motion}
    </label>
    <p class="help">{t.motionHelp}</p>
  </div>

  <div class="card">
    <label>
      <input type="checkbox" role="switch" checked={block} disabled={locked} {onchange} />
      {dns.on}
    </label>
    <p class="help">{block ? dns.onHelp : dns.offHelp}</p>
    {#if connected}
      <p class="help">{en.errors.disconnectFirst}</p>
    {/if}
    {#if consequence}
      <p class="notice">{consequence}</p>
    {/if}
    {#if error}
      <p class="notice" role="alert">{error}</p>
    {/if}
  </div>

  {#if app.bridge.capabilities.updates}
    <div class="card">
      <h2>{t.updates}</h2>
      <p class="help">{t.updatesHelp}</p>
      <div>
        <button type="button" class="btn" disabled={checking} onclick={checkNow}>{checking ? t.checking : t.checkNow}</button>
      </div>
      {#if result === 'tunnel' || result === 'physical'}
        <p class="help" role="status">
          {result === 'physical' ? t.checkedPhysical : t.checkedTunnel}
        </p>
      {:else if result}
        <p class="notice" role="alert">{result}</p>
      {/if}
    </div>
  {/if}

  <div>
    <button type="button" class="btn" onclick={() => app.go('about')}>{t.about}</button>
  </div>
</section>

<Consent
  open={askOptOut}
  title={dns.title}
  paragraphs={[disclosure.what, disclosure.why]}
  consequence={disclosure.consequenceOfOptingOut}
  decline={dns.decline}
  accept={dns.accept}
  ondecline={() => (askOptOut = false)}
  onaccept={optOut}
/>

<style>
  fieldset {
    border: 0;
    margin: 0;
  }

  legend {
    font-weight: 600;
    margin-bottom: var(--s-2);
  }

  label {
    display: flex;
    gap: var(--s-3);
    align-items: center;
    min-height: var(--hit);
  }

  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
  }

  .help {
    color: var(--c-text-2);
    font-size: var(--fs-sm);
  }
</style>
