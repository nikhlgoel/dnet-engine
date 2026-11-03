<script lang="ts">
  /**
   * About: the one UI surface permitted to name the third-party components it runs (Constitution, licence
   * obligation 1; `cargo xtask lint-branding` allows exactly this path). The wording follows
   * THIRD-PARTY-NOTICES.md, which is the authority; nothing here endorses or promotes by the vendors' names.
   */
  import { en } from './messages';

  let { onclose }: { onclose: () => void } = $props();

  const t = en.views.about;
</script>

<section class="view" aria-labelledby="about-title">
  <h1 id="about-title">{t.title}</h1>
  <p class="lede">{t.body}</p>
  <h2>{t.limitsTitle}</h2>
  <p class="lede">{t.limits}</p>
  <p class="lede">{t.attribution}</p>

  <ul class="parts">
    <li class="card">
      <h2 class="disp">sing-box</h2>
      <p>
        The primary transport core. Licensed under the GNU General Public License, version 3 or later, with an
        additional term permitted by section 7(e): no derivative work may use the name or imply association with
        this application without prior consent. DNet Engine does not use that project’s name in its branding and
        does not imply association with or endorsement by it.
      </p>
      <p>
        The bundled executable is built from the pinned upstream source with one modification, made by the DNet
        Engine project: the Windows adapter loader of its TUN library was changed to load the separately shipped,
        signed adapter library from beside the executable, instead of an embedded copy. The patch is part of the
        corresponding source.
      </p>
    </li>
    <li class="card">
      <h2 class="disp">amneziawg-go</h2>
      <p>Licensed under the MIT licence. Its copyright notice is kept with the installed files.</p>
    </li>
    <li class="card">
      <h2 class="disp">Wintun</h2>
      <p>
        The prebuilt, vendor-signed adapter library, shipped as a separate file and used only through its documented
        interface by the two supervised programs above. It is distributed under its own “Prebuilt Binaries
        License”, which is not a free-software licence; the text is installed beside it. This notice is
        attribution, not endorsement.
      </p>
    </li>
  </ul>

  <p class="lede">The full licence texts are installed with the program, in THIRD-PARTY-NOTICES.md.</p>
  <div>
    <button type="button" class="btn" onclick={onclose}>{t.close}</button>
  </div>
</section>

<style>
  .parts {
    display: grid;
    gap: var(--s-3);
    max-width: 720px;
  }

  h2 {
    font-size: var(--fs-lg);
    font-weight: 600;
  }

  p {
    color: var(--c-text-2);
  }
</style>
