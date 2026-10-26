<script lang="ts">
  import type { AppState } from '../lib/app.svelte';
  import Consent from '../components/Consent.svelte';
  import { disclosure, en } from '../lib/messages';

  let { app }: { app: AppState } = $props();

  const t = en.firstRun;
  const use = en.consent.acceptableUse;
  let step = $state<0 | 1 | 2>(0);

  /** The exact text the person saw is what is recorded with the time (design-system §13). */
  function accept(): void {
    app.acknowledgeAcceptableUse([use.title, use.body, use.consequence, use.note].join('\n'));
    step = 1;
  }

  function haveServer(has: boolean): void {
    app.go(has ? 'endpoints' : 'wizard');
  }
</script>

<section class="view" aria-labelledby="first-title">
  <h1 id="first-title">{t.welcome}</h1>
  <p class="lede">{t.intro}</p>

  {#if step === 1}
    <!-- Said once, in the service's own words; the switch for it lives in Settings. -->
    <div class="card">
      <h2>{t.dnsTitle}</h2>
      <p class="strong">{disclosure.headline}</p>
      <p>{disclosure.what}</p>
      <p>{disclosure.why}</p>
      <p>{disclosure.howToOptOut}</p>
    </div>
    <div>
      <button type="button" class="btn" onclick={() => (step = 2)}>{t.next}</button>
    </div>
  {:else if step === 2}
    <div class="card">
      <h2>{t.haveServer}</h2>
      <p>{t.endpointNote}</p>
    </div>
    <div class="actions">
      <button type="button" class="btn" onclick={() => haveServer(true)}>{t.yes}</button>
      <button type="button" class="btn" onclick={() => haveServer(false)}>{t.no}</button>
    </div>
  {/if}
</section>

<Consent
  open={step === 0}
  title={use.title}
  paragraphs={[use.body]}
  consequence={use.consequence}
  note={use.note}
  decline={use.decline}
  accept={use.accept}
  ondecline={() => app.go('status')}
  onaccept={accept}
/>

<style>
  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
  }

  .strong {
    font-weight: 600;
  }

  .card p {
    color: var(--c-text-2);
  }

  .card .strong {
    color: var(--c-text);
  }

  .actions {
    display: flex;
    gap: var(--s-3);
    flex-wrap: wrap;
  }
</style>
