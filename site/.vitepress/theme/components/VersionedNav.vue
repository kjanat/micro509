<!--
	VersionedNav — the navbar's Guide/API/Reference links, bound to the version
	being read.

	The site serves every version from one app, so these links cannot be static
	themeConfig entries: on /v0.8.0/guide/keys they must point at /v0.8.0/api/,
	not at the root's. The prefix comes from the current route, so a reader
	never falls out of the version they are in by clicking the navbar.

	Rendered in the navbar, in the mobile screen menu (`screen-menu`), and in
	the navbar's `⋯` overflow panel (`menu`). Each context sizes its rows
	differently, so the links follow VitePress's own nav links in each.
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed } from 'vue';
import type { VersionEntry } from './version-catalog';
import { versionForPath } from './version-catalog';

const props = defineProps<{
  readonly screenMenu?: boolean;
  readonly menu?: boolean;
}>();

const SECTIONS = [
  {
    text: 'Guide',
    path: 'guide/getting-started',
    match: 'guide/',
  },
  { text: 'API', path: 'api/', match: 'api/' },
  {
    text: 'Reference',
    path: 'reference/standards',
    match: 'reference/',
  },
] as const;

const { theme } = useData();
const route = useRoute();

/** URL prefix of the version being read: '', 'next/', 'v0.8.0/'. */
const prefix = computed(() => {
  const versions: readonly VersionEntry[] =
    theme.value.versions ?? [];
  return versionForPath(versions, route.path)?.prefix ?? '';
});

const links = computed(() =>
  SECTIONS.map((section) => ({
    text: section.text,
    link: `/${prefix.value}${section.path}`,
    active: route.path.startsWith(
      `/${prefix.value}${section.match}`,
    ),
  })),
);
</script>

<template>
  <div
    class="versioned-nav"
    :class="{ 'screen-menu': props.screenMenu, 'menu-panel': props.menu }"
  >
    <a
      v-for="link in links"
      :key="link.text"
      class="VPLink link vp-external-link-icon-none versioned-nav-link"
      :class="{
        active: link.active,
        VPNavBarMenuLink: !props.screenMenu && !props.menu,
        VPNavScreenMenuLink: props.screenMenu,
        'menu-panel-link': props.menu,
      }"
      :href="link.link"
    >
      {{ link.text }}
    </a>
  </div>
</template>

<style scoped>
.versioned-nav {
  display: flex;
}

.screen-menu,
.menu-panel {
  display: block;
}

.versioned-nav-link {
  font-size: 14px;
  font-weight: 500;
  color: var(--vp-c-text-1);
  transition: color 0.25s;
}

.VPNavBarMenuLink {
  display: flex;
  align-items: center;
  padding: 0 12px;
  line-height: var(--vp-nav-height);
}

.VPNavScreenMenuLink {
  display: block;
  border-bottom: 1px solid var(--vp-c-divider);
  padding: 12px 0 11px;
  line-height: 24px;
}

.menu-panel-link {
  display: block;
  border-radius: 6px;
  padding: 0 12px;
  line-height: 32px;
  white-space: nowrap;
}

.menu-panel-link:hover {
  background: var(--vp-c-default-soft);
}

.versioned-nav-link.active {
  color: var(--vp-c-brand-1);
}

.versioned-nav-link:hover {
  color: var(--vp-c-brand-1);
}
</style>
