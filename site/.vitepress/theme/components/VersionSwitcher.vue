<!--
	VersionSwitcher — links between independently built version snapshots.

	The embedded theme config keeps the preview usable immediately. At runtime,
	/versions.json supplies the published version catalog and page inventories.
	Version links use full document navigation because each version has its own
	VitePress app under a distinct base path.
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed, onMounted, ref } from 'vue';
import {
  hrefFor as hrefForVersion,
  mergeVersions,
  parseCatalog,
  type VersionEntry,
} from './version-catalog';

const { theme } = useData();
const route = useRoute();
const open = ref(false);
const embeddedVersions = computed<readonly VersionEntry[]>(
  () => theme.value.versions ?? [],
);
const catalogVersions = ref<readonly VersionEntry[] | undefined>();

const versions = computed<readonly VersionEntry[]>(
  () => {
    const catalog = catalogVersions.value;
    if (catalog === undefined) return embeddedVersions.value;
    return mergeVersions(catalog, embeddedVersions.value);
  },
);

onMounted(async () => {
  try {
    const response = await fetch('/versions.json', { headers: { accept: 'application/json' } });
    if (!response.ok) return;
    const parsed = parseCatalog(await response.json());
    if (parsed !== undefined) catalogVersions.value = parsed;
  } catch {
    // The build-time theme config remains a usable offline and preview fallback.
  }
});

/** Path within the current version, e.g. 'guide/keys' on /v0.8.0/guide/keys. */
const current = computed(() => {
  const path = route.path.replace(/^\//, '');
  // Longest prefix wins: '' matches everything and must lose to 'v0.8.0/'.
  const version = [...versions.value]
    .sort((a, b) => b.prefix.length - a.prefix.length)
    .find((entry) => path.startsWith(entry.prefix));
  return {
    version,
    page:
      version === undefined
        ? path
        : path.slice(version.prefix.length),
  };
});

const label = computed(
  () => current.value.version?.label ?? 'dev',
);

const labelUrl = computed(() =>
  versions.value.length === 1
    ? current.value.version?.labelUrl
    : undefined,
);

/**
 * The matching page in another version, including its query and symbol hash.
 * If its page inventory lacks that page, use that section's landing page.
 */
function hrefFor(entry: VersionEntry): string {
  return hrefForVersion(entry, current.value.page, `${route.query}${route.hash}`);
}
</script>

<template>
  <div
    class="version-switcher"
    @mouseenter="open = true"
    @mouseleave="open = false"
  >
    <a
      v-if="labelUrl !== undefined"
      class="vs-button"
      :href="labelUrl"
      target="_blank"
      rel="noreferrer"
      :aria-label="`Open details for ${label}`"
    >
      {{ label }}
    </a>
    <button
      v-else
      type="button"
      class="vs-button"
      aria-haspopup="true"
      :aria-expanded="open"
      @click="open = true"
    >
      {{ label }}
      <span
        v-if="versions.length > 1"
        class="vs-caret"
        aria-hidden="true"
        >▾</span
      >
    </button>
    <ul v-if="open && versions.length > 1" class="vs-menu">
      <li v-for="entry in versions" :key="entry.prefix">
        <!-- `target` skips VitePress SPA routing across separately deployed snapshots. -->
        <a
          class="vs-link"
          target="_self"
          :class="{
            'vs-active':
              entry.prefix === current.version?.prefix,
          }"
          :href="hrefFor(entry)"
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
  text-decoration: none;
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
