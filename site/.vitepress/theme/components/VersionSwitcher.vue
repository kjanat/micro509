<!--
	VersionSwitcher — links between independently built version snapshots.

	The embedded theme config keeps the preview usable immediately. At runtime,
	/versions.json supplies the published version catalog and page inventories.
	Version links use full document navigation because each version has its own
	VitePress app under a distinct base path.

	That catalog is an inventory of published bases, not a menu: a release is
	deployed at both `/` and `/vX.Y.Z/`. `displayVersions` turns it into one row
	per release, ordered this preview, next, latest, archives. `next` and a
	preview carry no version number, so each row says which channel it is.

	VitePress renders a nav component in three contexts and flags each one:
	the navbar (no flag), the mobile screen menu (`screen-menu`), and the
	navbar's `⋯` overflow panel (`menu`). Only the navbar has room to float a
	flyout; the other two are vertical list panels, so the version list renders
	in flow there — as an accordion on the screen menu and as a flat group in
	the overflow panel, matching VitePress's own nav items in each.
-->
<script setup lang="ts">
import { useData, useRoute } from 'vitepress';
import { computed, onMounted, onUnmounted, ref, useId } from 'vue';
import {
  displayVersions,
  hrefFor as hrefForVersion,
  mergeVersions,
  parseCatalog,
  type VersionEntry,
  versionForPath,
  versionKey,
} from './version-catalog';

const { theme } = useData();
const props = defineProps<{
  readonly screenMenu?: boolean;
  readonly menu?: boolean;
}>();
const route = useRoute();
const open = ref(false);
const switcher = ref<HTMLElement>();
const trigger = ref<HTMLButtonElement>();
const listId = useId();
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

/** One row per release, in reading order, rather than per published base. */
const listed = computed(() => displayVersions(versions.value, current.value.version));

/** A list panel holds the versions in flow; only the navbar floats them. */
const inPanel = computed(() => props.screenMenu === true || props.menu === true);

/** The overflow panel is already a disclosure, so it lists versions directly. */
const expanded = computed(
  () => listed.value.length > 1 && (props.menu === true || open.value),
);

function setHoverOpen(event: PointerEvent, value: boolean): void {
  if (event.pointerType === 'mouse' && !inPanel.value) open.value = value;
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

const label = computed(
  () => current.value.version?.label ?? 'dev',
);

const labelUrl = computed(() =>
  listed.value.length === 1
    ? current.value.version?.labelUrl
    : undefined,
);

/** Only a release names itself; say what the other channels are. */
function noteFor(entry: VersionEntry): string | undefined {
  switch (entry.channel) {
    case 'preview':
      return 'this preview';
    case 'next':
      return 'unreleased';
    case 'latest':
      return 'latest';
    default:
      return undefined;
  }
}

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
    :class="{
      'screen-menu': props.screenMenu,
      'menu-panel': props.menu,
      open: expanded,
    }"
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
    <!-- The overflow panel lists versions unconditionally; its label is a heading. -->
    <p v-else-if="props.menu" class="vs-title">{{ label }}</p>
    <button
      v-else
      ref="trigger"
      type="button"
      class="vs-button"
      :aria-haspopup="props.screenMenu ? undefined : true"
      :aria-expanded="open"
      :aria-controls="expanded ? listId : undefined"
      @click="open = !open"
    >
      {{ label }}
      <!-- The screen menu uses VitePress's accordion plus, the navbar a caret. -->
      <span
        v-if="listed.length > 1 && props.screenMenu"
        class="vs-plus vpi-plus"
        aria-hidden="true"
      />
      <span
        v-else-if="listed.length > 1"
        class="vs-caret"
        aria-hidden="true"
        >▾</span
      >
    </button>
    <ul v-if="expanded" :id="listId" class="vs-menu">
      <li v-for="entry in listed" :key="versionKey(entry)">
        <!-- `target` skips VitePress SPA routing across separately deployed snapshots. -->
        <a
          class="vs-link"
          target="_self"
          :class="{
            'vs-active':
              current.version !== undefined && versionKey(entry) === versionKey(current.version),
          }"
          :href="hrefFor(entry)"
        >
          <span>{{ entry.label }}</span>
          <span v-if="noteFor(entry) !== undefined" class="vs-note">{{ noteFor(entry) }}</span>
        </a>
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
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  padding: 4px 16px;
  font-size: 13px;
  color: var(--vp-c-text-1);
  white-space: nowrap;
  transition:
    color 0.25s,
    background-color 0.25s;
}

/* Names the channels that carry no version number. */
.vs-note {
  font-size: 11px;
  color: var(--vp-c-text-3);
}

.vs-link:hover {
  color: var(--vp-c-brand-1);
  background: var(--vp-c-default-soft);
}

.vs-active {
  color: var(--vp-c-brand-1);
  font-weight: 600;
}

/* A list panel owns the scrolling, so the version list drops the floating shell. */
.screen-menu .vs-menu,
.menu-panel .vs-menu {
  position: static;
  min-width: 0;
  max-height: none;
  overflow: visible;
  padding: 0;
  background: transparent;
  border: none;
  border-radius: 0;
  box-shadow: none;
}

.screen-menu {
  display: block;
  height: auto;
  border-bottom: 1px solid var(--vp-c-divider);
  transition: border-color 0.5s;
}

.screen-menu.open {
  padding-bottom: 10px;
}

.screen-menu .vs-button {
  width: 100%;
  justify-content: space-between;
  padding: 12px 4px 11px 0;
  font-size: 14px;
  line-height: 24px;
}

.screen-menu.open .vs-button {
  padding-bottom: 6px;
  color: var(--vp-c-brand-1);
}

.vs-plus {
  transition: transform 0.25s;
}

.screen-menu.open .vs-plus {
  transform: rotate(45deg);
}

.screen-menu .vs-link {
  margin-left: 12px;
  padding: 0;
  font-size: 14px;
  line-height: 32px;
  white-space: normal;
}

.screen-menu .vs-link:hover {
  background: transparent;
}

.menu-panel {
  display: block;
  height: auto;
}

.menu-panel .vs-title {
  padding: 0 12px;
  font-size: 14px;
  font-weight: 600;
  line-height: 32px;
  color: var(--vp-c-text-2);
  white-space: nowrap;
}

.menu-panel .vs-button {
  padding: 0 12px;
  font-size: 14px;
  line-height: 32px;
}

.menu-panel .vs-link {
  border-radius: 6px;
  padding: 0 12px;
  font-size: 14px;
  line-height: 32px;
}
</style>
