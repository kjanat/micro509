<!--
	VersionSwitcher — links between independently built version snapshots.

	The embedded theme config keeps the preview usable immediately. At runtime,
	/versions.json supplies the published version catalog and page inventories.
	Version links use full document navigation because each version has its own
	VitePress app under a distinct base path.
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import {
  hrefFor as hrefForVersion,
  mergeVersions,
  parseCatalog,
  type VersionEntry,
  versionForPath,
  versionKey,
} from './version-catalog';

const { theme } = useData();
const props = defineProps<{ readonly screenMenu?: boolean }>();
const route = useRoute();
const open = ref(false);
const switcher = ref<HTMLElement>();
const trigger = ref<HTMLButtonElement>();
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

function setHoverOpen(event: PointerEvent, value: boolean): void {
  if (event.pointerType === 'mouse' && !props.screenMenu) open.value = value;
}

function closeOutside(event: PointerEvent): void {
  if (event.target instanceof Node && !switcher.value?.contains(event.target)) open.value = false;
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key !== 'Escape' || !open.value) return;
  event.stopPropagation();
  event.preventDefault();
  open.value = false;
  trigger.value?.focus();
}

onMounted(async () => {
  document.addEventListener('pointerdown', closeOutside);
  if (theme.value.versionCatalogUrl === false) return;
  try {
    const response = await fetch(theme.value.versionCatalogUrl ?? '/versions.json', {
      headers: { accept: 'application/json' },
    });
    if (!response.ok) return;
    const parsed = parseCatalog(await response.json());
    if (parsed !== undefined) catalogVersions.value = parsed;
  } catch {
    // The build-time theme config remains a usable offline and preview fallback.
  }
});

onUnmounted(() => document.removeEventListener('pointerdown', closeOutside));

/** Path within the current version, e.g. 'guide/keys' on /v0.8.0/guide/keys. */
const current = computed(() => {
  const path = route.path.replace(/^\//, '');
  const version = versionForPath(versions.value, route.path);
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
    ref="switcher"
    class="version-switcher"
    :class="{ 'screen-menu': props.screenMenu }"
    @pointerenter="setHoverOpen($event, true)"
    @pointerleave="setHoverOpen($event, false)"
    @keydown="onKeydown"
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
      ref="trigger"
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
      <li v-for="entry in versions" :key="versionKey(entry)">
        <!-- `target` skips VitePress SPA routing across separately deployed snapshots. -->
        <a
          class="vs-link"
          target="_self"
          :class="{
            'vs-active':
              current.version !== undefined && versionKey(entry) === versionKey(current.version),
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
  max-height: min(480px, calc(100dvh - var(--vp-nav-height) - 16px));
  overflow-y: auto;
  overscroll-behavior: contain;
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

.screen-menu {
  display: block;
  height: auto;
  border-bottom: 1px solid var(--vp-c-divider);
}

.screen-menu .vs-button {
  width: 100%;
  justify-content: space-between;
  padding: 12px 0 11px;
  font-size: 14px;
  line-height: 24px;
}

.screen-menu .vs-menu {
  position: static;
  max-height: min(50dvh, 384px);
  margin-bottom: 12px;
  box-shadow: none;
}

.screen-menu .vs-link {
  padding: 8px 16px;
  line-height: 24px;
}
</style>
