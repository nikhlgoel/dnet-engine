<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { AppState } from './lib/app.svelte';
  import type { Bridge } from './lib/bridge';
  import type { WindowChrome } from './lib/chrome';
  import { chips as chipsOf, freshness, strip as cellsOf } from './lib/describe';
  import { en } from './lib/messages';
  import About from './lib/About.svelte';
  import Caption from './components/Caption.svelte';
  import Consent from './components/Consent.svelte';
  import Dock from './components/Dock.svelte';
  import Drawer from './components/Drawer.svelte';
  import Scene from './components/Scene.svelte';
  import Strip from './components/Strip.svelte';
  import Switcher from './components/Switcher.svelte';
  import TitleBar from './components/TitleBar.svelte';
  import Wordmark from './components/Wordmark.svelte';
  import Activity from './views/Activity.svelte';
  import Endpoints from './views/Endpoints.svelte';
  import FirstRun from './views/FirstRun.svelte';
  import Rules from './views/Rules.svelte';
  import Settings from './views/Settings.svelte';
  import Wizard from './views/Wizard.svelte';

  /** The window's own frame, when there is a window to draw it for; null in a browser tab. */
  let { bridge, chrome = null }: { bridge: Bridge; chrome?: WindowChrome | null } = $props();

  // The bridge is chosen once, before the window exists; it does not change for the life of the page.
  // svelte-ignore state_referenced_locally
  const app = new AppState(bridge);

  const t = en;
  let osReducesMotion = $state(false);
  let chevron = $state<HTMLButtonElement | null>(null);
  let polite = $state('');
  let assertive = $state('');

  const still = $derived(app.reduceMotion || osReducesMotion);
  const dark = $derived(app.theme === 'system' ? undefined : app.theme);
  const beat = $derived(freshness(app.snapshot, app.now));
  const lampKey = $derived(app.look?.lamp ?? 'off');
  const chipRows = $derived(app.snapshot ? chipsOf(app.snapshot) : []);
  const cellRows = $derived(app.snapshot ? cellsOf(app.snapshot) : []);
  const onStatus = $derived(app.view === 'status');

  // Theme and motion are attributes of the root, where the design tokens look for them.
  $effect(() => {
    const root = document.documentElement;
    if (dark) root.setAttribute('data-theme', dark);
    else root.removeAttribute('data-theme');
    if (still) root.setAttribute('data-motion', 'reduce');
    else root.removeAttribute('data-motion');
  });

  // A state change is announced once: a failure interrupts, everything else waits its turn.
  let lastAnnounced = '';
  $effect(() => {
    const look = app.look;
    if (!look || look.announcement === lastAnnounced) return;
    lastAnnounced = look.announcement;
    if (look.assertive) {
      assertive = look.announcement;
      polite = '';
    } else {
      polite = look.announcement;
      assertive = '';
    }
  });

  onMount(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    osReducesMotion = query.matches;
    const onMotion = (event: MediaQueryListEvent): void => {
      osReducesMotion = event.matches;
    };
    query.addEventListener('change', onMotion);

    const onVisibility = (): void => app.setVisible(!document.hidden);
    document.addEventListener('visibilitychange', onVisibility);
    app.setVisible(!document.hidden);

    if (!app.acknowledged) app.go('firstrun');

    return () => {
      query.removeEventListener('change', onMotion);
      document.removeEventListener('visibilitychange', onVisibility);
      app.stop();
    };
  });

  function onWindowKey(event: KeyboardEvent): void {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      app.switcherOpen = true;
    }
  }

  async function toggleDrawer(): Promise<void> {
    const wasOpen = app.drawerOpen;
    app.drawerOpen = !wasOpen;
    if (wasOpen) {
      await tick();
      chevron?.focus();
    }
  }

  const commands = $derived([
    { id: 'status', label: t.nav.status, run: () => app.go('status') },
    { id: 'endpoints', label: t.nav.endpoints, run: () => app.go('endpoints') },
    { id: 'rules', label: t.nav.rules, run: () => app.go('rules') },
    { id: 'activity', label: t.nav.activity, run: () => app.go('activity') },
    { id: 'settings', label: t.nav.settings, run: () => app.go('settings') },
    { id: 'about', label: t.nav.about, run: () => app.go('about') },
    { id: 'toggle', label: app.look?.switch.on ? t.switch.turnOff : t.switch.off, run: () => void app.toggle() },
  ]);
</script>

<svelte:window onkeydown={onWindowKey} />

<div class="frame" class:framed={chrome !== null}>
  {#if chrome}
    <TitleBar {chrome} />
  {/if}
  <div class="app" data-lamp={lampKey}>
    <header class="top">
      <button type="button" class="plate" aria-label={t.nav.about} onclick={() => app.go('about')}>
        <Wordmark />
        <span class="engine">engine</span>
      </button>
      <div class="heartbeat" aria-live="off">
        <i class:stale={!beat.live}></i>
        <span class="num">{beat.text}</span>
      </div>
    </header>

    <main class="stage">
      {#if onStatus && app.look && app.snapshot}
        <Scene
          look={app.look}
          chips={chipRows}
          {still}
          visible={app.visible}
          themeKey={`${dark ?? 'system'}`}
          ontoggle={() => void app.toggle()}
        />
        <Caption
          look={app.look}
          warnings={app.snapshot.warnings}
          notice={app.notice}
          ontoggle={() => void app.toggle()}
          onaction={() => app.look?.action && void app.act(app.look.action.id)}
        />
      {:else if onStatus}
        <p class="waiting">{t.heartbeat.none}</p>
      {:else if app.view === 'endpoints'}
        <Endpoints {app} />
      {:else if app.view === 'rules'}
        <Rules {app} />
      {:else if app.view === 'activity'}
        <Activity {app} />
      {:else if app.view === 'settings'}
        <Settings {app} />
      {:else if app.view === 'about'}
        <About onclose={() => app.go('status')} />
      {:else if app.view === 'firstrun'}
        <FirstRun {app} />
      {:else if app.view === 'wizard'}
        <Wizard {app} />
      {/if}
    </main>

    {#if onStatus && app.snapshot}
      <Strip cells={cellRows} expanded={app.drawerOpen} ontoggle={toggleDrawer} bind:chevron />
      {#if app.drawerOpen}
        <Drawer snapshot={app.snapshot} onclose={toggleDrawer} />
      {/if}
    {:else}
      <div></div>
    {/if}

    <Dock current={app.view} onnavigate={(view) => app.go(view)} />
  </div>
</div>

<Consent
  open={app.tier2Prompt}
  title={t.consent.tier2.title}
  paragraphs={[t.consent.tier2.body]}
  consequence={t.consent.tier2.consequence}
  note={t.consent.tier2.note}
  decline={t.consent.tier2.decline}
  accept={t.consent.tier2.accept}
  ondecline={() => void app.answerTier2(false)}
  onaccept={() => void app.answerTier2(true)}
/>

<Switcher open={app.switcherOpen} {commands} onclose={() => (app.switcherOpen = false)} />

<!-- Two live regions so a failure can interrupt without everything else doing so (4.1.3). -->
<div class="sr-only" role="status" aria-live="polite">{polite}</div>
<div class="sr-only" role="alert" aria-live="assertive">{assertive}</div>

<style>
  .frame {
    container-type: inline-size;
    display: flex;
    flex-direction: column;
    height: 100vh;
    min-width: 560px;
  }

  /* With no system frame, the page draws the window's edge: one line, like the system's own. */
  .frame.framed {
    border: 1px solid var(--c-line);
  }

  .app {
    position: relative;
    isolation: isolate;
    display: grid;
    grid-template-rows: auto 1fr auto auto;
    flex: 1;
    min-height: 0;
    overflow: hidden;
    --ambient: var(--c-text-3);
  }

  .app[data-lamp='ok'] {
    --ambient: var(--c-ok);
  }

  .app[data-lamp='probe'] {
    --ambient: var(--c-probe);
  }

  .app[data-lamp='warn'] {
    --ambient: var(--c-warn);
  }

  .app[data-lamp='fail'] {
    --ambient: var(--c-fail);
  }

  /* The ambient wash and the dot grid: one soft colour from the state, fading out toward the edges. */
  .app::before {
    content: '';
    position: absolute;
    inset: 0;
    z-index: -1;
    transition: background var(--dur-3) var(--ease);
    background:
      radial-gradient(60% 52% at 50% 36%, color-mix(in srgb, var(--ambient) var(--ambient-strength), transparent), transparent 72%),
      radial-gradient(circle at center, var(--dot-grid) 1px, transparent 1.4px) 0 0 / var(--dot-grid-step) var(--dot-grid-step);
    mask-image: radial-gradient(75% 70% at 50% 42%, var(--c-text) 25%, transparent 100%);
  }

  .app::after {
    content: '';
    position: absolute;
    inset: 0;
    z-index: -2;
    background: var(--c-base);
  }

  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--s-4) var(--s-5) 0;
  }

  .plate {
    display: inline-flex;
    align-items: flex-end;
    gap: var(--s-3);
    background: none;
    border: 0;
    padding: 4px;
    cursor: pointer;
    border-radius: var(--r-ctl);
    color: var(--c-text);
  }

  .engine {
    font: 500 10px / 1 var(--font-display);
    letter-spacing: 0.42em;
    color: var(--c-text-3);
    padding-bottom: 3px;
    text-transform: uppercase;
  }

  .heartbeat {
    display: inline-flex;
    align-items: center;
    gap: var(--s-2);
    color: var(--c-text-3);
    font: 400 var(--fs-xs) / 1 var(--font-display);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  .heartbeat i {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--c-text-2);
    animation: beat 2s ease-in-out infinite;
  }

  .heartbeat i.stale {
    animation: none;
    background: none;
    border: 1px solid var(--c-text-3);
  }

  :global([data-motion='reduce']) .heartbeat i {
    animation: none;
  }

  @keyframes beat {
    50% {
      opacity: 0.25;
    }
  }

  .stage {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  .stage > :global(.view) {
    flex: 1;
  }

  .waiting {
    margin: auto;
    color: var(--c-text-2);
  }
</style>
