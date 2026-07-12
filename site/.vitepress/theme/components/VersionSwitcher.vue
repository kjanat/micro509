<!--
	VersionSwitcher — navbar dropdown between docs channels.

	The label ('v0.9.0', 'next', …) comes from themeConfig at build time, so it
	renders during SSG without any fetch. The dropdown entries come from
	/versions.json, fetched ORIGIN-ABSOLUTE on purpose: the manifest is written
	by scripts/assemble-site.bun.ts at the deployed site root, so frozen
	archived builds always list the live set of versions without rebuilds.
	When the manifest is unreachable (dev server, offline), only the label
	renders.
-->
<script setup lang="ts">
import { useData } from 'vitepress';
import { computed, onMounted, ref } from 'vue';

interface VersionEntry {
  /** Dropdown text, e.g. 'v0.9' or 'next'. */
  readonly label: string;
  /** URL prefix the version is served under: '/', '/next/', '/v0.9/'. */
  readonly base: string;
}

interface VersionsManifest {
  readonly schemaVersion: number;
  /** Pre-ordered dropdown entries — the manifest owns the order. */
  readonly entries?: readonly VersionEntry[];
  /** The root site — a release build, or the HEAD bootstrap. Always present. */
  readonly latest: VersionEntry;
  readonly next: VersionEntry;
  readonly archived: readonly VersionEntry[];
}

const { theme, page, site } = useData();
const manifest = ref<VersionsManifest>();
const open = ref(false);

const label = computed(() => {
  // Prefer the live manifest's label for this build's own base — the baked
  // themeConfig label is frozen inside old tarballs and can go stale.
  const fromManifest = entries.value.find(
    (entry) => entry.base === site.value.base,
  );
  if (fromManifest !== undefined) return fromManifest.label;
  const configured: unknown = theme.value.docsVersion;
  return typeof configured === 'string'
    ? configured
    : 'dev';
});

const entries = computed<readonly VersionEntry[]>(() => {
  if (manifest.value === undefined) return [];
  // Render the manifest's pre-ordered entries verbatim — ordering is a
  // deploy-time decision, never baked into frozen builds. The composition
  // fallback covers pre-schema-2 manifests only.
  return (
    manifest.value.entries ?? [
      manifest.value.next,
      manifest.value.latest,
      ...manifest.value.archived,
    ]
  );
});

onMounted(async () => {
  try {
    const response = await fetch('/versions.json');
    if (response.ok) {
      manifest.value = await response.json();
    }
  } catch {
    // No manifest reachable: render the label without a dropdown.
  }
});

/**
 * Same page in another channel; a page that does not exist there falls
 * through to that channel's own 404 (assets 404.html lookup walks up
 * directories, so each version serves its version-scoped 404 page).
 */
function hrefFor(base: string): string {
  const path = page.value.relativePath
    .replace(/index\.md$/, '')
    .replace(/\.md$/, '');
  return base + path;
}
</script>

<template>
  <div
    class="version-switcher"
    @mouseenter="open = true"
    @mouseleave="open = false"
  >
    <button
      type="button"
      class="vs-button"
      aria-haspopup="true"
      :aria-expanded="open"
      @click="open = !open"
    >
      {{ label }}
      <span
        v-if="entries.length"
        class="vs-caret"
        aria-hidden="true"
        >▾</span
      >
    </button>
    <ul v-if="open && entries.length" class="vs-menu">
      <li v-for="entry in entries" :key="entry.base">
        <!--
          target="_self" is VitePress's documented opt-out from SPA routing
          (docs/en/guide/routing.md, "linking to non-VitePress pages"): other
          channels are separate apps under a different base, so the click must
          be a full document navigation, not a router push.
        -->
        <a
          class="vs-link"
          :class="{
            'vs-active': entry.base === site.base,
          }"
          :href="hrefFor(entry.base)"
          target="_self"
          >{{ entry.label }}</a
        >
      </li>
    </ul>
  </div>
</template>

<style scoped>
.version-switcher {
  position: relative;
  display: flex;
  align-items: center;
  height: var(--vp-nav-height);
}

.vs-button {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 0 12px;
  font-size: 13px;
  font-weight: 500;
  color: var(--vp-c-text-1);
  background: transparent;
  border: none;
  cursor: pointer;
  transition: color 0.25s;
}

.vs-button:hover {
  color: var(--vp-c-brand-1);
}

.vs-caret {
  font-size: 10px;
  color: var(--vp-c-text-3);
}

.vs-menu {
  position: absolute;
  top: calc(var(--vp-nav-height) - 8px);
  right: 0;
  min-width: 128px;
  margin: 0;
  padding: 8px 0;
  list-style: none;
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  box-shadow: var(--vp-shadow-3);
  z-index: 30;
}

.vs-link {
  display: block;
  padding: 4px 16px;
  font-size: 13px;
  color: var(--vp-c-text-1);
  white-space: nowrap;
  transition:
    color 0.25s,
    background-color 0.25s;
}

.vs-link:hover {
  color: var(--vp-c-brand-1);
  background: var(--vp-c-default-soft);
}

.vs-active {
  color: var(--vp-c-brand-1);
  font-weight: 600;
}
</style>
