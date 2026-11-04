<script lang="ts">
  import DisconnectNote from '../components/DisconnectNote.svelte';
  import { onMount } from 'svelte';
  import type { AppState } from '../lib/app.svelte';
  import Consent from '../components/Consent.svelte';
  import { brutalWarning, disclosure, en } from '../lib/messages';
  import type { ProfileView } from '../lib/model';

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

  const brutal = en.consent.brutal;
  let hy2 = $state<ProfileView | null>(null);
  let up = $state('');
  let down = $state('');
  let askBrutal = $state(false);
  let brutalError = $state<string | null>(null);

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
    try {
      hy2 = (await app.bridge.profiles()).find((p) => p.kind === 'Hysteria2') ?? null;
    } catch (e) {
      brutalError = app.reason(e);
    }
  });

  /** A whole number of Mbit/s the service accepts, or null. */
  function speed(text: string): number | null {
    const n = Number(text.trim());
    return /^\d+$/.test(text.trim()) && n >= 1 && n <= 1_000_000 ? n : null;
  }

  /** Turning the mode on asks first, with the service's warning; turning it off needs no consent (§13). */
  async function onBrutalChange(event: Event): Promise<void> {
    const box = event.currentTarget as HTMLInputElement;
    const wants = box.checked;
    // Stay where it was until the change is made.
    box.checked = !wants;
    if (!hy2) return;
    if (wants) {
      if (speed(up) === null || speed(down) === null) {
        brutalError = t.speedsNeeded;
        return;
      }
      brutalError = null;
      askBrutal = true;
      return;
    }
    await setBrutal(null);
  }

  async function setBrutal(bandwidth: { up: number; down: number } | null): Promise<void> {
    if (!hy2) return;
    const outcome = await app.bridge.setBrutal(hy2.id, bandwidth);
    brutalError = outcome.ok ? null : outcome.reason;
    if (outcome.ok) hy2 = { ...hy2, brutal: bandwidth !== null };
  }

  async function acceptBrutal(): Promise<void> {
    askBrutal = false;
    const u = speed(up);
    const d = speed(down);
    if (u === null || d === null) return;
    await setBrutal({ up: u, down: d });
  }

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

  <h2 class="cat">{t.catLook}</h2>
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

  <h2 class="cat">{t.catPrivacy}</h2>
  <div class="card">
    <label>
      <input type="checkbox" role="switch" checked={block} disabled={locked} {onchange} />
      {dns.on}
    </label>
    <p class="help">{block ? dns.onHelp : dns.offHelp}</p>
    {#if connected}
      <DisconnectNote {app} />
    {/if}
    {#if consequence}
      <p class="notice">{consequence}</p>
    {/if}
    {#if error}
      <p class="notice" role="alert">{error}</p>
    {/if}
  </div>

  {#if hy2 || brutalError}
    <h2 class="cat">{t.speedMode}</h2>
    <div class="card">
      {#if hy2}
        <label>
          <input type="checkbox" role="switch" checked={hy2.brutal} disabled={connected} onchange={onBrutalChange} />
          {t.speedMode}
        </label>
        <p class="help">{hy2.brutal ? t.speedModeOnHelp : t.speedModeHelp}</p>
        {#if !hy2.brutal}
          <label>
            {t.up}
            <input type="text" inputmode="numeric" autocomplete="off" bind:value={up} disabled={connected} />
          </label>
          <label>
            {t.down}
            <input type="text" inputmode="numeric" autocomplete="off" bind:value={down} disabled={connected} />
          </label>
        {/if}
        {#if connected}
          <DisconnectNote {app} />
        {/if}
      {/if}
      {#if brutalError}
        <p class="notice" role="alert">{brutalError}</p>
      {/if}
    </div>
  {/if}

  {#if app.bridge.capabilities.updates}
    <h2 class="cat">{t.updates}</h2>
    <div class="card">
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

<Consent
  open={askBrutal}
  title={brutalWarning.title}
  paragraphs={[brutalWarning.body, brutalWarning.note]}
  consequence={brutalWarning.consequence}
  decline={brutal.decline}
  accept={brutal.accept}
  ondecline={() => (askBrutal = false)}
  onaccept={acceptBrutal}
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
