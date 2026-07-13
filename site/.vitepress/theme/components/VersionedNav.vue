<!--
	VersionedNav — the navbar's Guide/API/Reference links, bound to the version
	being read.

	The site serves every version from one app, so these links cannot be static
	themeConfig entries: on /v0.8.0/guide/keys they must point at /v0.8.0/api/,
	not at the root's. The prefix comes from the current route, so a reader
	never falls out of the version they are in by clicking the navbar.

	Rendered by both VPNavBarMenu (desktop) and VPNavScreenMenu (mobile).
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed } from 'vue';

interface VersionEntry {
  readonly prefix: string;
}

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
  const path = route.path.replace(/^\//, '');
  return (
    [...versions]
      .sort((a, b) => b.prefix.length - a.prefix.length)
      .find((version) => path.startsWith(version.prefix))
      ?.prefix ?? ''
  );
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
  <a
    v-for="link in links"
    :key="link.text"
    class="VPLink link vp-external-link-icon-none VPNavBarMenuLink"
    :class="{ active: link.active }"
    :href="link.link"
  >
    {{ link.text }}
  </a>
</template>

<style scoped>
.VPNavBarMenuLink {
  display: flex;
  align-items: center;
  padding: 0 12px;
  line-height: var(--vp-nav-height);
  font-size: 14px;
  font-weight: 500;
  color: var(--vp-c-text-1);
  transition: color 0.25s;
}

.VPNavBarMenuLink.active {
  color: var(--vp-c-brand-1);
}

.VPNavBarMenuLink:hover {
  color: var(--vp-c-brand-1);
}
</style>
