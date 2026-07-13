/**
 * VitePress plugin: every released version of the docs, served from one build.
 *
 * One `vitepress build` renders, side by side:
 *   - `/`           the newest release (its pages, its API, its library)
 *   - `/next/`      the checked-out tree
 *   - `/vX.Y.Z/`    every superseded release, one route tree each
 *
 * A version's pages are *materialized*, not frozen: each release's markdown is
 * read straight out of its git tag, and its API reference is regenerated from
 * that tag's sources. VitePress renders them like any other page, so archived
 * versions get today's theme, today's version switcher, and in-app routing
 * between versions. Nothing about the presentation is baked into an artifact,
 * so nothing needs re-baking when the presentation changes.
 *
 * The *compiled library* a version's runnable examples import is not built or
 * hosted here: each version's pages get an import map binding the library's bare
 * specifiers to an ESM CDN, at the version that page documents. The caller says
 * where a version's modules live (`library.moduleBase`); a released version
 * points at what it published, and the checked-out tree points at a build of the
 * commit being deployed.
 *
 * Serving the library ourselves is what this replaced. A package's own file
 * layout then became URLs under our origin, and a single unlucky filename could
 * be refused by the reader's browser — content blockers match on URL paths, and
 * `x509/fingerprint.js` is on their lists. Binding to package *subpaths* and
 * letting the CDN resolve each version's `exports` keeps the library's internal
 * layout out of our URL space entirely.
 *
 * Nothing here knows the host project: every path, manifest and name arrives
 * through `VersionedDocsOptions`. The caller owns the layout; this owns the
 * routing.
 *
 * @module
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import * as tar from 'tar';
import type {
	DefaultTheme,
	HeadConfig,
	MarkdownRenderer,
	PageData,
	Plugin,
	SiteConfig,
} from 'vitepress';

/** Where the versions come from, and where their pieces are put. */
export interface VersionedDocsOptions {
	/** Working tree of the project being documented — the `/next/` channel. */
	readonly repoRoot: string;
	/** Directory VitePress globs for pages, relative to its `srcDir`. */
	readonly siteRoot: string;
	/** Where materialized per-version pages are written (gitignore this). */
	readonly versionsDir: string;
	/** Where downloaded tag trees are kept between builds. */
	readonly cacheDir: string;
	/** Version label for the checked-out tree, e.g. `v1.4.0-dev`. */
	readonly devLabel: string;

	/** Page paths taken verbatim from a tag, relative to the repository root. */
	readonly pages: readonly string[];
	/**
	 * Everything else a tag needs for `generateApi` to run against it — sources,
	 * manifests. Together with `pages`, this is all that is taken from a tag: the
	 * rest of the repository (tool configs above all) stays out of the cache.
	 */
	readonly sources: readonly string[];

	/** The published releases that become versions. */
	readonly releases: {
		/**
		 * Registry document listing every published version, e.g.
		 * `https://registry.npmjs.org/micro509`.
		 */
		readonly index: string;
		/** The tag a published version was cut from. */
		readonly tag: (version: string) => string;
		/** Source archive of that tag, e.g. a codeload tarball. */
		readonly source: (tag: string) => string;
		/** Where a human reads about the release. */
		readonly url: (tag: string) => string;
		/** Resolve no versions; build the checked-out tree alone. */
		readonly offline?: boolean;
	};

	/** The library each version's examples import, and where it is served from. */
	readonly library: {
		/** Bare specifier root, e.g. `micro509` — becomes `<name>/keys`. */
		readonly name: string;
		/**
		 * The public subpaths, as package.json `exports` keys: `.`, `./x509`.
		 *
		 * Only the keys: the files behind them are the CDN's business, and each
		 * version's are its own.
		 */
		readonly exports: readonly string[];
		/**
		 * Where a version's examples import one subpath from, keyed as `exports` keys
		 * it: `.`, `./x509`. A whole URL rather than a base to append to — a CDN's
		 * URL for a subpath is its own business, and not every one is a prefix
		 * (jsDelivr wants `.../micro509@0.8.0/x509/+esm`).
		 */
		readonly moduleUrl: (version: DocsVersion, subpath: string) => string;
	};

	/** Regenerate one version's API reference. Called per tag, and for the tree. */
	readonly generateApi: (target: { readonly root: string; readonly outDir: string }) => void;

	/** Fail the build above this many output files. */
	readonly fileGuardrail: number;
}

export type DocsChannel = 'latest' | 'next' | 'archive';

/** A page a version ships, as it titles itself. */
export interface DocsPage {
	/** File stem: `keys` for `guide/keys.md`, `index` for a section landing. */
	readonly slug: string;
	/** The page's own title — frontmatter `title`, else its first heading. */
	readonly title: string;
}

/** The pages a version ships, per section. Sidebars are built from these. */
export type DocsSections = Readonly<Record<string, readonly DocsPage[]>>;

/** One version of the docs, as served. */
export interface DocsVersion {
	/** Release tag, or the dev label for the checked-out tree. */
	readonly tag: string;
	/** Dropdown text. */
	readonly label: string;
	readonly channel: DocsChannel;
	/** URL prefix without the leading slash: `''`, `'next/'`, `'v0.8.0/'`. */
	readonly prefix: string;
	/** srcDir-relative directory holding this version's markdown. */
	readonly srcRoot: string;
	/** The pages this version ships — not the pages the tree ships. */
	readonly sections: DocsSections;
	/** The release this version was cut from; absent for the checked-out tree. */
	readonly release?: {
		readonly url: string;
		readonly published: string | null;
	};
}

interface Packument {
	readonly versions: Readonly<Record<string, unknown>>;
	readonly time?: Readonly<Record<string, string>>;
}

/** A published release: its tag, and its sources. */
interface DocsRelease {
	readonly tag: string;
	readonly version: readonly [number, number, number];
	readonly sourceUrl: string;
	readonly url: string;
	readonly published: string | null;
}

function parseStableVersion(version: string): readonly [number, number, number] | undefined {
	const match = version.match(/^(\d+)\.(\d+)\.(\d+)$/);
	if (!match) return undefined;
	return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/**
 * Published stable releases, newest first.
 *
 * The registry is the source of truth for what shipped — no repository API, no
 * token, no rate limit that a shared CI address can exhaust. A failure here
 * fails the build: a docs site missing every version is worse than a docs site
 * that does not deploy.
 */
async function fetchReleases(options: VersionedDocsOptions): Promise<readonly DocsRelease[]> {
	const response = await fetch(options.releases.index, {
		headers: { accept: 'application/json', 'user-agent': 'vitepress-versioned-docs' },
	});
	if (!response.ok) {
		throw new Error(
			`[versions] ${options.releases.index} -> ${response.status} ${response.statusText}. Set DOCS_OFFLINE=1 to build the checked-out tree alone.`,
		);
	}

	const packument: Packument = await response.json();
	return Object.keys(packument.versions)
		.flatMap((published): DocsRelease[] => {
			const version = parseStableVersion(published);
			if (version === undefined) return [];
			const tag = options.releases.tag(published);
			return [
				{
					tag,
					version,
					sourceUrl: options.releases.source(tag),
					url: options.releases.url(tag),
					published: packument.time?.[published] ?? null,
				},
			];
		})
		.sort(
			(a, b) =>
				b.version[0] - a.version[0] || b.version[1] - a.version[1] || b.version[2] - a.version[2],
		);
}

/**
 * Download a gzipped tarball and unpack it into `into`.
 *
 * Extraction goes through the `tar` dependency rather than a `tar` binary: the
 * binary is whatever the build machine happens to have (and Windows has none),
 * while the dependency is pinned by the lockfile and identical everywhere.
 */
async function unpack(
	url: string,
	into: string,
	options: {
		/** Leading path components to drop when writing files out. */
		readonly strip: number;
		/**
		 * Which archive entries to take, by their path *inside the archive*.
		 *
		 * Never "all of them" for a repository archive: it carries the project's
		 * tool configs (biome.json, tsconfig.json), and anything later scanning the
		 * cache directory would find them and honor them.
		 */
		readonly wanted: (entry: string) => boolean;
	},
): Promise<void> {
	const response = await fetch(url, {
		headers: { 'user-agent': 'vitepress-versioned-docs' },
	});
	if (!response.ok) {
		throw new Error(`[versions] ${url} -> ${response.status} ${response.statusText}`);
	}

	const blob = `${into}.tar.gz`;
	await fsp.mkdir(path.dirname(blob), { recursive: true });
	await fsp.writeFile(blob, Buffer.from(await response.arrayBuffer()));

	await fsp.rm(into, { recursive: true, force: true });
	await fsp.mkdir(into, { recursive: true });
	await tar.x({ file: blob, cwd: into, strip: options.strip, filter: options.wanted });
	await fsp.rm(blob, { force: true });
}

/** `src` matches `src` and `src/x509/parse.ts`, but not `srcery`. */
function under(paths: readonly string[], entry: string): boolean {
	return paths.some((wanted) => entry === wanted || entry.startsWith(`${wanted}/`));
}

/**
 * A release's source tree, downloaded once into the build cache.
 *
 * Fetched rather than read out of the local clone: CI clones shallow, so the tag
 * object is not there, and `git` is not a dependency of this package.
 */
async function ensureTagTree(release: DocsRelease, options: VersionedDocsOptions): Promise<string> {
	const tree = path.join(options.cacheDir, release.tag, 'tree');
	const marker = path.join(tree, '.complete');
	if (fs.existsSync(marker)) return tree;

	const paths = [...options.sources, ...options.pages];
	await unpack(release.sourceUrl, tree, {
		strip: 1,
		wanted: (entry) => under(paths, entry.split('/').slice(1).join('/')),
	});
	await fsp.writeFile(marker, '');
	return tree;
}

/** Copy a tag's authored pages into the version's page directory. */
async function materializePages(
	tree: string,
	target: string,
	options: VersionedDocsOptions,
): Promise<void> {
	await fsp.rm(target, { recursive: true, force: true });
	await fsp.mkdir(target, { recursive: true });
	for (const page of options.pages) {
		const source = path.join(tree, page);
		if (!fs.existsSync(source)) continue;
		await fsp.cp(source, path.join(target, path.basename(page)), { recursive: true });
	}
}

/** What a page calls itself: frontmatter `title`, else its first heading, else its slug. */
function titleOf(file: string, slug: string): string {
	const source = fs.readFileSync(file, 'utf8');
	const frontmatter = source.match(/^---\n([\s\S]*?)\n---/);
	const declared = frontmatter?.[1]?.match(/^title:\s*(.+)$/m)?.[1]?.trim();
	if (declared !== undefined && declared !== '') return declared.replace(/^['"]|['"]$/g, '');
	return source.match(/^#\s+(.+)$/m)?.[1]?.trim() ?? slug;
}

/**
 * The pages a directory holds, titled by the pages themselves.
 *
 * Read off disk rather than declared by the caller: each version ships the pages
 * that existed at its tag, and a hardcoded list would link an old version at
 * pages it never had, and hide the ones it did.
 */
function sectionPages(dir: string): readonly DocsPage[] {
	if (!fs.existsSync(dir)) return [];
	return fs
		.readdirSync(dir)
		.filter((entry) => entry.endsWith('.md'))
		.map((entry) => {
			const slug = entry.replace(/\.md$/, '');
			return { slug, title: titleOf(path.join(dir, entry), slug) };
		})
		.sort((a, b) => a.slug.localeCompare(b.slug));
}

/** Every section directly under a version's page root. */
function sectionsOf(pageRoot: string): DocsSections {
	if (!fs.existsSync(pageRoot)) return {};
	const sections: Record<string, readonly DocsPage[]> = {};
	for (const entry of fs.readdirSync(pageRoot, { withFileTypes: true })) {
		if (entry.isDirectory()) sections[entry.name] = sectionPages(path.join(pageRoot, entry.name));
	}
	return sections;
}

/**
 * Resolve every version the site serves, in timeline order:
 * next (the tree), latest (the newest release), then archives newest-first.
 *
 * Materializes as it goes, so by the time VitePress globs for pages they are
 * files on disk like any other.
 */
async function resolveVersions(options: VersionedDocsOptions): Promise<readonly DocsVersion[]> {
	const releases = options.releases.offline === true ? [] : await fetchReleases(options);

	const treeRoot = path.join(options.repoRoot, options.siteRoot);
	options.generateApi({ root: options.repoRoot, outDir: path.join(treeRoot, 'api') });
	const treeSections = sectionsOf(treeRoot);

	if (releases.length === 0) {
		console.log('[versions] no releases resolved; serving the checked-out tree');
		await fsp.rm(options.versionsDir, { recursive: true, force: true });
		return [
			{
				tag: options.devLabel,
				label: options.devLabel,
				channel: 'latest',
				prefix: '',
				srcRoot: options.siteRoot,
				sections: treeSections,
			},
		];
	}

	const versions: DocsVersion[] = [
		{
			tag: options.devLabel,
			label: 'next',
			channel: 'next',
			prefix: 'next/',
			srcRoot: options.siteRoot,
			sections: treeSections,
		},
	];

	await fsp.rm(options.versionsDir, { recursive: true, force: true });
	const versionsRoot = path.relative(options.repoRoot, options.versionsDir);

	for (const [index, release] of releases.entries()) {
		const isLatest = index === 0;
		const key = isLatest ? 'latest' : release.tag;
		const pageRoot = path.join(options.versionsDir, key);

		const tree = await ensureTagTree(release, options);
		await materializePages(tree, pageRoot, options);
		options.generateApi({ root: tree, outDir: path.join(pageRoot, 'api') });

		versions.push({
			tag: release.tag,
			label: release.tag,
			channel: isLatest ? 'latest' : 'archive',
			prefix: isLatest ? '' : `${release.tag}/`,
			srcRoot: path.posix.join(versionsRoot, key),
			sections: sectionsOf(pageRoot),
			release: { url: release.url, published: release.published },
		});
	}

	console.log(
		`[versions] root=${versions[1]?.label}, next, archives=[${versions
			.slice(2)
			.map((version) => version.label)
			.join(', ')}]`,
	);
	return versions;
}

/** The version a page belongs to, by its (post-rewrite) route path. */
function versionOfPage(page: string, versions: readonly DocsVersion[]): DocsVersion | undefined {
	return [...versions]
		.sort((a, b) => b.prefix.length - a.prefix.length)
		.find((version) => page.startsWith(version.prefix));
}

/**
 * The import map resolving a page's bare specifiers to the library the version
 * it belongs to documents, and the origin serving it.
 *
 * Specifiers are bound to package *subpaths* (`micro509/x509`), never to files.
 * Which file a subpath resolves to is the released version's own `exports` map,
 * and the CDN is the thing that reads it — so a page keeps working against a
 * release whose internal file layout no longer resembles today's, and no part of
 * the library's layout becomes a URL under this origin.
 */
function importMapFor(
	version: DocsVersion,
	options: VersionedDocsOptions,
): { readonly importMap: string; readonly origin: string | undefined } {
	const imports = Object.fromEntries(
		options.library.exports
			.filter((subpath) => subpath === '.' || subpath.startsWith('./'))
			// A manifest exports its own manifest; nothing imports it.
			.filter((subpath) => subpath !== './package.json')
			.map((subpath): [string, string] => [
				subpath === '.'
					? options.library.name
					: `${options.library.name}/${subpath.slice('./'.length)}`,
				options.library.moduleUrl(version, subpath),
			]),
	);
	const root = imports[options.library.name];
	return {
		importMap: JSON.stringify({ imports }),
		origin: root !== undefined && URL.canParse(root) ? new URL(root).origin : undefined,
	};
}

/**
 * What a version's pages carry in their head: its import map, and a connection
 * to the origin serving it, opened before an example needs it.
 *
 * No `modulepreload`: an example's modules are fetched when a reader runs one,
 * and most readers never do. Preconnect pays the handshake up front and nothing
 * else.
 */
function headFor(version: DocsVersion, options: VersionedDocsOptions): string {
	const { importMap, origin } = importMapFor(version, options);
	const preconnect =
		origin === undefined ? '' : `<link rel="preconnect" href="${origin}" crossorigin>\n`;
	return `${preconnect}<script type="importmap">${importMap}</script>`;
}

/** Put the import map first in the head, ahead of anything that resolves against it. */
function withImportMap(html: string, version: DocsVersion, options: VersionedDocsOptions): string {
	return html.replace('<head>', `<head>\n${headFor(version, options)}`);
}

/**
 * Dev-server half: the same import map, on every page.
 *
 * `transformHtml` is a build-only hook, so the dev server needs its own
 * injection or its pages have nothing to resolve a bare `micro509` against. The
 * tree's map serves all of them — dev renders the tree's pages, and only the
 * build materializes a page per version to give each its own.
 */
function importMapPlugin(versions: readonly DocsVersion[], options: VersionedDocsOptions): Plugin {
	return {
		name: 'vitepress-versioned-docs',
		apply: 'serve',
		transformIndexHtml: (html) => {
			const tree = versions.find((version) => version.srcRoot === options.siteRoot);
			return tree === undefined ? html : withImportMap(html, tree, options);
		},
	};
}

async function countFiles(dir: string): Promise<number> {
	let count = 0;
	for (const entry of await fsp.readdir(dir, { withFileTypes: true, recursive: true })) {
		if (entry.isFile()) count += 1;
	}
	return count;
}

/** Publish the version index, hold the file budget. */
async function emitVersionIndex(
	versions: readonly DocsVersion[],
	options: VersionedDocsOptions,
	siteConfig: SiteConfig,
): Promise<void> {
	const outDir = siteConfig.outDir;

	const index = {
		schemaVersion: 3,
		versions: versions.map((version) => ({
			label: version.label,
			tag: version.tag,
			channel: version.channel,
			base: `/${version.prefix}`,
			releasedAt: version.release?.published ?? null,
			releaseUrl: version.release?.url ?? null,
		})),
	};
	await fsp.writeFile(path.join(outDir, 'versions.json'), `${JSON.stringify(index, null, '\t')}\n`);

	const files = await countFiles(outDir);
	console.log(`[versions] ${files} files across ${versions.length} versions`);
	if (files > options.fileGuardrail) {
		throw new Error(
			`[versions] ${files} files exceeds the ${options.fileGuardrail}-file budget. Serve fewer versions, or ship less per version.`,
		);
	}
}

/** A named group of pages, in reading order, by slug. */
export interface SidebarGroup {
	readonly text: string;
	readonly slugs: readonly string[];
}

/** Reading order per section. Pages a version lacks are skipped; extras append. */
export type SidebarOrder = Readonly<Record<string, readonly SidebarGroup[]>>;

/** `index` is a section's landing page: `/guide/`, never `/guide/index`. */
function linkTo(section: string, page: DocsPage): string {
	return page.slug === 'index' ? `/${section}/` : `/${section}/${page.slug}`;
}

/**
 * One section's sidebar for one version: the declared reading order, filled with
 * the pages that version ships, titled as those pages title themselves.
 */
function sectionSidebar(
	section: string,
	groups: readonly SidebarGroup[],
	pages: readonly DocsPage[],
): DefaultTheme.SidebarItem[] {
	const bySlug = new Map(pages.map((page) => [page.slug, page]));
	const ordered = new Set(groups.flatMap((group) => group.slugs));

	const items: DefaultTheme.SidebarItem[] = groups.map((group) => ({
		text: group.text,
		items: group.slugs
			.map((slug) => bySlug.get(slug))
			.filter((page) => page !== undefined)
			.map((page) => ({ text: page.title, link: linkTo(section, page) })),
	}));

	const rest = pages.filter((page) => !ordered.has(page.slug));
	const last = items.at(-1);
	if (rest.length > 0 && last?.items !== undefined) {
		last.items = [
			...last.items,
			...rest.map((page) => ({ text: page.title, link: linkTo(section, page) })),
		];
	}
	return items.filter((group) => (group.items?.length ?? 0) > 0);
}

/** A frontmatter entry carrying a link — a hero action, as authored. */
function isLinked(value: unknown): value is { readonly link: string } {
	return (
		typeof value === 'object' && value !== null && 'link' in value && typeof value.link === 'string'
	);
}

/** A link to a page rather than to a file. */
function isPageLink(href: string): boolean {
	return href.endsWith('.md') || /\.html(?:#|$)/.test(href);
}

/**
 * A relative page link, resolved against the routes its version serves.
 *
 * Pages of an old version reach files that sit outside any version (a repository
 * doc, a directory up). Under a version prefix such a link resolves to
 * `/v0.3.0/docs/…`, which nothing serves — and those files are not versioned, so
 * the link belongs to the one copy at the root. Links within the version's own
 * sections already resolve correctly and are left alone.
 */
function outOfVersionLink(href: string, page: string, version: DocsVersion): string {
	const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(page), href));
	if (!resolved.startsWith(version.prefix)) return href;

	const target = resolved.slice(version.prefix.length);
	const section = target.split('/')[0] ?? '';
	if (section in version.sections || target === 'index.md') return href;
	return `/${target}`;
}

/** Where a link on a page actually points, once its version is accounted for. */
function routeOf(
	href: string,
	page: string,
	version: DocsVersion | undefined,
	versionedLink: (href: string, page: string) => string,
): string {
	if (href.startsWith('/')) return versionedLink(href, page);
	if (version === undefined || version.prefix === '' || !isPageLink(href)) return href;
	return outOfVersionLink(href, page, version);
}

/** Everything a VitePress config needs to serve all versions from one app. */
export interface VersionedDocs {
	/** Every version, in timeline order: next, the root release, then archives. */
	readonly versions: readonly DocsVersion[];
	/** Dev-server support: the import map, which the build-only hook cannot give it. */
	readonly plugin: Plugin;
	/** Source path -> route path. */
	readonly rewrites: (id: string) => string;
	/** Keeps a page's links inside the version it belongs to. */
	readonly markdown: (md: MarkdownRenderer) => void;
	/** Versions the hero actions, which are frontmatter rather than links. */
	readonly transformPageData: (pageData: PageData) => void;
	/** Only the root version is indexable; the rest are copies of it. */
	readonly head: (page: string) => HeadConfig[];
	/** Points a page's bare imports at its own version's library. */
	readonly html: (html: string, page: string) => string;
	/** Writes the version index, enforces the budget. */
	readonly buildEnd: (siteConfig: SiteConfig) => Promise<void>;
	/** Every version's sidebar, keyed by the paths it serves. */
	readonly sidebar: (order: SidebarOrder) => DefaultTheme.SidebarMulti;
	/** True for pages the root version serves — the sitemap's only entries. */
	readonly isIndexable: (page: string) => boolean;
}

export async function versionedDocs(options: VersionedDocsOptions): Promise<VersionedDocs> {
	const versions = await resolveVersions(options);
	const at = (page: string): DocsVersion | undefined => versionOfPage(page, versions);
	const tree = versions.find((version) => version.srcRoot === options.siteRoot);

	const sectionLink = new RegExp(`^/(${Object.keys(tree?.sections ?? {}).join('|')})(/|#|$)`);
	const versionedLink = (href: string, page: string): string => {
		if (!sectionLink.test(href)) return href;
		const version = at(page);
		return version === undefined || version.prefix === ''
			? href
			: `/${version.prefix}${href.slice(1)}`;
	};

	return {
		versions,
		plugin: importMapPlugin(versions, options),

		rewrites: (id) => {
			for (const version of versions) {
				if (version.srcRoot === options.siteRoot) continue;
				const prefix = `${version.srcRoot}/`;
				if (id.startsWith(prefix)) return `${version.prefix}${id.slice(prefix.length)}`;
			}
			const treePrefix = `${options.siteRoot}/`;
			if (id.startsWith(treePrefix)) {
				return `${tree?.prefix ?? ''}${id.slice(treePrefix.length)}`;
			}
			return id;
		},

		markdown: (md) => {
			const previous =
				md.renderer.rules.link_open ??
				((tokens, idx, opts, _env, self) => self.renderToken(tokens, idx, opts));

			md.renderer.rules.link_open = (tokens, idx, opts, env, self) => {
				const token = tokens[idx];
				const href = token?.attrGet('href');
				const page: string = env.relativePath ?? '';
				if (token !== undefined && href !== null && href !== undefined) {
					token.attrSet('href', routeOf(href, page, at(page), versionedLink));
				}
				return previous(tokens, idx, opts, env, self);
			};
		},

		transformPageData: (pageData) => {
			const hero: { readonly actions?: unknown } | undefined = pageData.frontmatter.hero;
			const actions: unknown = hero?.actions;
			if (hero === undefined || !Array.isArray(actions)) return;
			pageData.frontmatter = {
				...pageData.frontmatter,
				hero: {
					...hero,
					actions: actions.map((action: unknown) =>
						isLinked(action)
							? { ...action, link: versionedLink(action.link, pageData.relativePath) }
							: action,
					),
				},
			};
		},

		head: (page) =>
			at(page)?.channel === 'latest' ? [] : [['meta', { name: 'robots', content: 'noindex' }]],

		html: (html, page) => {
			const version = at(page);
			return version === undefined ? html : withImportMap(html, version, options);
		},

		buildEnd: (siteConfig) => emitVersionIndex(versions, options, siteConfig),

		sidebar: (order) =>
			Object.fromEntries(
				versions.flatMap((version) =>
					Object.entries(order).map(([section, groups]) => [
						`/${version.prefix}${section}/`,
						{
							base: version.prefix === '' ? '' : `/${version.prefix.slice(0, -1)}`,
							items: sectionSidebar(section, groups, version.sections[section] ?? []),
						},
					]),
				),
			),

		isIndexable: (page) => at(page)?.channel === 'latest',
	};
}
