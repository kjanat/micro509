<!--
	VersionSwitcher — navbar dropdown between the versions this site serves.

	Every version is part of one app, so the entries come from themeConfig at
	build time (no fetch, no manifest, nothing frozen into an old artifact) and
	switching versions is ordinary SPA routing: the reader stays on the same
	page, in a different version, without a document reload.

	Order is the timeline, newest first: next (the unreleased tree), then the
	release the root serves, then superseded releases. The plugin hands them over
	in that order — this renders them as given.
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed, ref } from 'vue';

interface VersionEntry {
  /** Dropdown text: 'next', 'v0.9.0', … */
  readonly label: string;
  /** URL prefix without the leading slash: '', 'next/', 'v0.8.0/'. */
  readonly prefix: string;
}

const { theme } = useData();
const route = useRoute();
const open = ref(false);

const versions = computed<readonly VersionEntry[]>(
  () => theme.value.versions ?? [],
);

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

/**
 * The same page in another version. Every version serves the same guide and
 * reference tree, so the reader lands where they were; a page that a version
 * doesn't have (an API module added later) falls through to the 404, which is
 * the honest answer — that page did not exist in that version.
 */
function hrefFor(entry: VersionEntry): string {
  return `/${entry.prefix}${current.value.page}`;
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
        v-if="versions.length > 1"
        class="vs-caret"
        aria-hidden="true"
        >▾</span
      >
    </button>
    <ul v-if="open && versions.length > 1" class="vs-menu">
      <li v-for="entry in versions" :key="entry.prefix">
        <!-- In-app routing: versions are pages of one site, not separate apps. -->
        <a
          class="vs-link"
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
