/**
 * VitePress plugin. One `vitepress build` renders every version of the docs:
 *
 *   - `/`           the newest release
 *   - `/next/`      the checked-out tree
 *   - `/vX.Y.Z/`    every superseded release
 *
 * It reads each release's markdown from its git tag and regenerates its API
 * reference from that tag's sources.
 *
 * Every page gets the same import map: top-level imports for the root version and
 * a scope per version prefix. `library.moduleUrl` gives the URLs.
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
	/** Render only the checked-out tree for an incremental publish. */
	readonly target?: {
		readonly channel: 'next' | 'latest' | 'archive' | 'preview';
		readonly version?: string;
		/** Extracted source tree for an immutable historical target. */
		readonly sourceRoot?: string;
	};
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
	/** External destination for the checked-out tree label, e.g. its pull request. */
	readonly devLabelUrl?: string;
	/** Serve no `/next/` channel: the checked-out tree is exactly the latest release. */
	readonly omitNext?: boolean;

	/** Page paths taken verbatim from a tag, relative to the repository root. */
	readonly pages: readonly string[];
	/** Source and manifest paths `generateApi` needs from a tag. */
	readonly sources: readonly string[];
	/** Rewrite each materialized markdown page before it is served. */
	readonly transformPage?: (markdown: string) => string;

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
		 * The whole URL a version imports one subpath from. `subpath` is an `exports`
		 * key such as `.` or `./x509`.
		 */
		readonly moduleUrl: (version: DocsVersion, subpath: string) => string;
	};

	/** Regenerate one version's API reference. Called per tag, and for the tree. */
	readonly generateApi: (target: { readonly root: string; readonly outDir: string }) => void;

	/** Fail the build above this many output files. */
	readonly fileGuardrail: number;
}

export type DocsChannel = 'latest' | 'next' | 'archive' | 'preview';

/** A page a version ships, as it titles itself. */
export interface DocsPage {
	/** File stem: `keys` for `guide/keys.md`, `index` for a section landing. */
	readonly slug: string;
	/** The page's own title — frontmatter `title`, else its first heading. */
	readonly title: string;
	/** Optional shorter label used only in navigation. */
	readonly sidebarTitle?: string;
}

/** The pages a version ships, per section. Sidebars are built from these. */
export type DocsSections = Readonly<Record<string, readonly DocsPage[]>>;

/** One version of the docs, as served. */
export interface DocsVersion {
	/** Release tag, or the dev label for the checked-out tree. */
	readonly tag: string;
	/** Version from this documentation tree's package manifest. */
	readonly packageVersion: string;
	/** Dropdown text. */
	readonly label: string;
	/** Optional external destination for the label when no version switching is available. */
	readonly labelUrl?: string;
	readonly channel: DocsChannel;
	/** URL prefix without the leading slash: `''`, `'next/'`, `'v0.8.0/'`. */
	readonly prefix: string;
	/** srcDir-relative directory holding this version's markdown. */
	readonly srcRoot: string;
	/** This version's `exports` keys, such as `.` or `./x509`. */
	readonly exports: readonly string[];
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

/** Published stable releases, newest first. Throws on a failed fetch. */
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

/** Download a gzipped tarball and unpack it into `into`. */
async function unpack(
	url: string,
	into: string,
	options: {
		/** Leading path components to drop when writing files out. */
		readonly strip: number;
		/** Which archive entries to take, by their path inside the archive. */
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
	const transform = options.transformPage;
	if (transform === undefined) return;
	for (const file of await fsp.readdir(target, { recursive: true })) {
		if (!file.endsWith('.md')) continue;
		const full = path.join(target, file);
		const markdown = await fsp.readFile(full, 'utf8');
		const rewritten = transform(markdown);
		if (rewritten !== markdown) await fsp.writeFile(full, rewritten);
	}
}

/** Read the optional single-line labels from a page's frontmatter. */
function frontmatterLabel(source: string, key: 'title' | 'sidebarTitle'): string | undefined {
	const frontmatter = source.match(/^---\r?\n([\s\S]*?)\r?\n---/);
	const declared = frontmatter?.[1]?.match(new RegExp(`^${key}:[ \t]*(.*)$`, 'm'))?.[1]?.trim();
	if (declared === undefined || declared === '') return undefined;
	const quoted = declared.match(/^(['"])(.*)\1$/);
	const value = quoted?.[2] ?? declared;
	return value === '' ? undefined : value;
}

/** The pages a directory holds, titled by the pages themselves. */
function markdownFiles(root: string, directory = root): readonly string[] {
	return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		if (entry.name.startsWith('.')) return [];
		const file = path.join(directory, entry.name);
		if (entry.isDirectory()) return markdownFiles(root, file);
		return entry.isFile() && entry.name.endsWith('.md') ? [path.relative(root, file)] : [];
	});
}

function sectionPages(dir: string): readonly DocsPage[] {
	if (!fs.existsSync(dir)) return [];
	return markdownFiles(dir)
		.map((entry) => {
			const slug = entry.replace(/\.md$/, '').split(path.sep).join('/');
			const file = path.join(dir, entry);
			const source = fs.readFileSync(file, 'utf8');
			const sidebarTitle = frontmatterLabel(source, 'sidebarTitle');
			return {
				slug,
				title:
					frontmatterLabel(source, 'title') ?? source.match(/^#\s+(.+)$/m)?.[1]?.trim() ?? slug,
				...(sidebarTitle === undefined ? {} : { sidebarTitle }),
			};
		})
		.sort((a, b) => a.slug.localeCompare(b.slug));
}

/** Every section directly under a version's page root. */
function sectionsOf(pageRoot: string, versionsDir: string): DocsSections {
	if (!fs.existsSync(pageRoot)) return {};
	const sections: Record<string, readonly DocsPage[]> = {};
	for (const entry of fs.readdirSync(pageRoot, { withFileTypes: true })) {
		const directory = path.join(pageRoot, entry.name);
		if (!entry.isDirectory() || entry.name.startsWith('.') || directory === versionsDir) continue;
		const pages = sectionPages(directory);
		if (pages.length > 0) sections[entry.name] = pages;
	}
	return sections;
}

/**
 * Every version the site serves, in timeline order: next, latest, archives
 * newest-first. Writes each version's pages to disk before VitePress globs them.
 */
async function resolveVersions(options: VersionedDocsOptions): Promise<readonly DocsVersion[]> {
	if (options.target !== undefined) return resolveTargetVersion(options, options.target);
	return resolveAllVersions(options);
}

function targetTagOf(
	target: NonNullable<VersionedDocsOptions['target']>,
	packageVersion: string,
): string {
	const releaseTarget = target.channel === 'latest' || target.channel === 'archive';
	if (target.sourceRoot !== undefined && !releaseTarget)
		throw new Error('[versions] sourceRoot is only valid for release targets');
	const expected = `v${packageVersion}`;
	const tag = target.version ?? (releaseTarget ? expected : undefined);
	if (!releaseTarget && tag !== undefined)
		throw new Error(`[versions] target ${target.channel} does not accept a version`);
	if (
		tag !== undefined &&
		!/^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(tag)
	)
		throw new Error(`[versions] invalid target version: ${tag}`);
	if (releaseTarget && tag !== expected)
		throw new Error(
			`[versions] target version ${tag} does not match package version ${packageVersion}`,
		);
	return tag ?? '';
}

async function resolveTargetVersion(
	options: VersionedDocsOptions,
	target: NonNullable<VersionedDocsOptions['target']>,
): Promise<readonly DocsVersion[]> {
	const sourceRoot = target.sourceRoot ?? options.repoRoot;
	const packageVersion = packageVersionOf(sourceRoot);
	const releaseTarget = target.channel === 'latest' || target.channel === 'archive';
	const tag = targetTagOf(target, packageVersion) || options.devLabel;
	const channel = target.channel;
	const { pageRoot, srcRoot } = await targetPageRoot(options, target, sourceRoot, channel, tag);
	const release = releaseTarget ? { url: options.releases.url(tag), published: null } : undefined;
	return [
		{
			tag,
			packageVersion,
			label:
				target.channel === 'next' ? 'next' : target.channel === 'preview' ? options.devLabel : tag,
			...(target.channel === 'preview' && options.devLabelUrl !== undefined
				? { labelUrl: options.devLabelUrl }
				: {}),
			channel,
			prefix: target.channel === 'next' ? 'next/' : target.channel === 'archive' ? `${tag}/` : '',
			srcRoot,
			exports: exportsOf(sourceRoot),
			sections: sectionsOf(pageRoot, options.versionsDir),
			...(release === undefined ? {} : { release }),
		},
	];
}

async function targetPageRoot(
	options: VersionedDocsOptions,
	target: NonNullable<VersionedDocsOptions['target']>,
	sourceRoot: string,
	channel: DocsChannel,
	tag: string,
): Promise<{ readonly pageRoot: string; readonly srcRoot: string }> {
	const sourceSiteRoot = path.join(sourceRoot, options.siteRoot);
	if (target.sourceRoot === undefined) {
		options.generateApi({ root: sourceRoot, outDir: path.join(sourceSiteRoot, 'api') });
		return { pageRoot: sourceSiteRoot, srcRoot: options.siteRoot };
	}
	const key = channel === 'latest' ? 'latest' : tag;
	const pageRoot = path.join(options.versionsDir, key);
	await materializePages(sourceRoot, pageRoot, options);
	options.generateApi({ root: sourceRoot, outDir: path.join(pageRoot, 'api') });
	return {
		pageRoot,
		srcRoot: path.relative(options.repoRoot, pageRoot).split(path.sep).join('/'),
	};
}

async function resolveAllVersions(options: VersionedDocsOptions): Promise<readonly DocsVersion[]> {
	const releases = options.releases.offline === true ? [] : await fetchReleases(options);

	const treeRoot = path.join(options.repoRoot, options.siteRoot);
	const treePackageVersion = packageVersionOf(options.repoRoot);
	options.generateApi({ root: options.repoRoot, outDir: path.join(treeRoot, 'api') });
	const treeSections = sectionsOf(treeRoot, options.versionsDir);

	if (releases.length === 0) {
		console.log('[versions] no releases resolved; serving the checked-out tree');
		await fsp.rm(options.versionsDir, { recursive: true, force: true });
		return [
			{
				tag: options.devLabel,
				packageVersion: treePackageVersion,
				label: options.devLabel,
				...(options.devLabelUrl === undefined ? {} : { labelUrl: options.devLabelUrl }),
				channel: 'latest',
				prefix: '',
				srcRoot: options.siteRoot,
				exports: exportsOf(options.repoRoot),
				sections: treeSections,
			},
		];
	}

	const versions: DocsVersion[] =
		options.omitNext === true
			? []
			: [
					{
						tag: options.devLabel,
						packageVersion: treePackageVersion,
						label: 'next',
						channel: 'next',
						prefix: 'next/',
						srcRoot: options.siteRoot,
						exports: exportsOf(options.repoRoot),
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
			packageVersion: packageVersionOf(tree),
			label: release.tag,
			channel: isLatest ? 'latest' : 'archive',
			prefix: isLatest ? '' : `${release.tag}/`,
			srcRoot: path.posix.join(versionsRoot, key),
			exports: exportsOf(tree),
			sections: sectionsOf(pageRoot, options.versionsDir),
			release: { url: release.url, published: release.published },
		});
	}

	const root = versions.find((version) => version.channel === 'latest');
	const hasNext = versions.some((version) => version.channel === 'next');
	console.log(
		`[versions] root=${root?.label}${hasNext ? ', next' : ' (tree is the release, no next)'}, archives=[${versions
			.filter((version) => version.channel === 'archive')
			.map((version) => version.label)
			.join(', ')}]`,
	);
	return versions;
}

function exportsOf(root: string): readonly string[] {
	const manifest: { readonly exports?: Readonly<Record<string, unknown>> } = JSON.parse(
		fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
	);
	return Object.keys(manifest.exports ?? {});
}

function packageVersionOf(root: string): string {
	const manifest: { readonly version: string } = JSON.parse(
		fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
	);
	return manifest.version;
}

/** The version a page belongs to, by its (post-rewrite) route path. */
function versionOfPage(page: string, versions: readonly DocsVersion[]): DocsVersion | undefined {
	return [...versions]
		.sort((a, b) => b.prefix.length - a.prefix.length)
		.find((version) => page.startsWith(version.prefix));
}

function entriesFor(version: DocsVersion, options: VersionedDocsOptions): Record<string, string> {
	return Object.fromEntries(
		version.exports
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
}

/**
 * One import map for the whole site: top-level imports for the root version, a scope
 * per prefixed version. Scopes match on the referring module's URL, so an example run
 * after client-side navigation still resolves the version of the page it runs on.
 */
function siteImportMap(
	versions: readonly DocsVersion[],
	options: VersionedDocsOptions,
): { readonly importMap: string; readonly origins: readonly string[] } {
	const root =
		versions.find((version) => version.prefix === '') ??
		(options.target === undefined ? undefined : versions[0]);
	const imports = root === undefined ? {} : entriesFor(root, options);
	const scopes = Object.fromEntries(
		versions
			.filter((version) => version.prefix !== '' || options.target !== undefined)
			.map((version) => [`/${version.prefix}`, entriesFor(version, options)]),
	);
	const targets = [
		...Object.values(imports),
		...Object.values(scopes).flatMap((scope) => Object.values(scope)),
	];
	const origins = [
		...new Set(targets.filter((url) => URL.canParse(url)).map((url) => new URL(url).origin)),
	];
	const map =
		Object.keys(scopes).length === 0
			? JSON.stringify({ imports })
			: JSON.stringify({ imports, scopes });
	return { importMap: map, origins };
}

function headFor(versions: readonly DocsVersion[], options: VersionedDocsOptions): string {
	const { importMap, origins } = siteImportMap(versions, options);
	const preconnect = origins
		.map((origin) => `<link rel="preconnect" href="${origin}" crossorigin>\n`)
		.join('');
	return `${preconnect}<script type="importmap">${importMap}</script>`;
}

/** Put the import map first in the head, ahead of anything that resolves against it. */
function withImportMap(
	html: string,
	versions: readonly DocsVersion[],
	options: VersionedDocsOptions,
): string {
	return html.replace('<head>', `<head>\n${headFor(versions, options)}`);
}

/** `transformHtml` is build-only. The dev server gets the import map from here. */
function importMapPlugin(versions: readonly DocsVersion[], options: VersionedDocsOptions): Plugin {
	return {
		name: 'vitepress-versioned-docs',
		apply: 'serve',
		transformIndexHtml: (html) => withImportMap(html, versions, options),
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
			base: version.prefix === '' ? '/' : `/${version.prefix}`,
			releasedAt: version.release?.published ?? null,
			releaseUrl: version.release?.url ?? null,
			sections: version.sections,
		})),
	};
	await fsp.writeFile(path.join(outDir, 'versions.json'), `${JSON.stringify(index, null, '\t')}\n`);

	const latest = versions.find(
		(version) => version.channel === 'latest' && version.release !== undefined,
	);
	if (latest !== undefined && options.target === undefined) {
		await fsp.appendFile(
			path.join(outDir, '_redirects'),
			`/${latest.tag} / 302\n/${latest.tag}/* /:splat 302\n`,
		);
	}

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

/** One section's sidebar for one version, in the reading order `order` declares. */
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
			.map((page) => ({ text: page.sidebarTitle ?? page.title, link: linkTo(section, page) })),
	}));

	const rest = pages.filter((page) => !page.slug.includes('/') && !ordered.has(page.slug));
	const last = items.at(-1);
	if (rest.length > 0 && last?.items !== undefined) {
		last.items = [
			...last.items,
			...rest.map((page) => ({
				text: page.sidebarTitle ?? page.title,
				link: linkTo(section, page),
			})),
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

/** Rewrites a relative link out of a version's own sections to the root copy. */
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
	/** VitePress base for a single-target deployment. */
	readonly base: string;
	/** Every version, in timeline order: next, the root release, then archives. */
	readonly versions: readonly DocsVersion[];
	/** Dev-server support: the import map, which the build-only hook cannot give it. */
	readonly plugin: Plugin;
	/** Source path -> route path. */
	readonly rewrites: (id: string) => string;
	/** Tree pages the build must skip when no version serves the tree. */
	readonly srcExclude: readonly string[];
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
	const routeVersions =
		options.target === undefined
			? versions
			: versions.map((version) => ({ ...version, prefix: '' }));
	const at = (page: string): DocsVersion | undefined => versionOfPage(page, routeVersions);
	const tree = routeVersions.find((version) => version.srcRoot === options.siteRoot);
	const inactiveVersionDirs = inactiveVersionSourceExcludes(options, versions);

	const sections = new Set(routeVersions.flatMap((version) => Object.keys(version.sections)));
	const sectionLink = new RegExp(`^/(${[...sections].join('|')})(/|#|$)`);
	const versionedLink = (href: string, page: string): string => {
		if (!sectionLink.test(href)) return href;
		const version = at(page);
		return version === undefined || version.prefix === ''
			? href
			: `/${version.prefix}${href.slice(1)}`;
	};

	return {
		versions,
		base:
			options.target === undefined || versions[0]?.prefix === '' ? '/' : `/${versions[0]?.prefix}`,
		plugin: importMapPlugin(versions, options),

		srcExclude: [
			...(tree === undefined
				? [
						...options.pages.map((page) => (page.endsWith('.md') ? page : `${page}/**`)),
						`${options.siteRoot}/api/**`,
					]
				: []),
			...inactiveVersionDirs,
		],

		rewrites: (id) => {
			for (const version of routeVersions) {
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
			const version = at(pageData.relativePath);
			pageData.frontmatter = {
				...pageData.frontmatter,
				...(version === undefined ? {} : { packageVersion: version.packageVersion }),
			};

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
			at(page)?.channel === 'latest' && options.target?.channel !== 'preview'
				? []
				: [['meta', { name: 'robots', content: 'noindex' }]],

		html: (html) => withImportMap(html, versions, options),

		buildEnd: (siteConfig) => emitVersionIndex(versions, options, siteConfig),

		sidebar: (order) =>
			Object.fromEntries(
				routeVersions.flatMap((version) =>
					Object.entries(order).map(([section, groups]) => [
						`/${version.prefix}${section}/`,
						{
							base: version.prefix === '' ? '' : `/${version.prefix.slice(0, -1)}`,
							items: sectionSidebar(section, groups, version.sections[section] ?? []),
						},
					]),
				),
			),

		isIndexable: (page) => at(page)?.channel === 'latest' && options.target?.channel !== 'preview',
	};
}

/** Exclude materialized versions from prior single-target runs. A historical
 * sourceRoot keeps only the one version directory this build just generated. */
function inactiveVersionSourceExcludes(
	options: VersionedDocsOptions,
	versions: readonly DocsVersion[],
): string[] {
	if (options.target === undefined) return [];
	const relativeDir = path
		.relative(options.repoRoot, options.versionsDir)
		.split(path.sep)
		.join('/');
	if (
		relativeDir === '' ||
		relativeDir === '..' ||
		relativeDir.startsWith('../') ||
		path.isAbsolute(relativeDir)
	)
		return [];
	if (options.target.sourceRoot === undefined) return [`${relativeDir}/**`];

	const activeRoot = versions[0]?.srcRoot;
	const activePath = activeRoot === undefined ? '' : path.resolve(options.repoRoot, activeRoot);
	const relativeActive = activePath === '' ? '' : path.relative(options.versionsDir, activePath);
	const activeName =
		relativeActive !== '' &&
		!relativeActive.startsWith(`..${path.sep}`) &&
		!path.isAbsolute(relativeActive)
			? relativeActive.split(path.sep)[0]
			: undefined;
	if (activeName === undefined) return [`${relativeDir}/**`];
	if (!fs.existsSync(options.versionsDir)) return [];
	return fs
		.readdirSync(options.versionsDir, { withFileTypes: true })
		.filter((entry) => entry.name !== activeName)
		.map((entry) => `${relativeDir}/${entry.name}/**`)
		.sort();
}
