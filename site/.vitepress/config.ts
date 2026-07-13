import { writeDenoImportMap } from '@micro509/doc-render/import-map';
import { apiDocsPlugin, generateApiDocs } from '@micro509/vitepress-api-docs';
import type { DocExamplesOptions } from '@micro509/vitepress-doc-examples';
import { docExamplesPlugin } from '@micro509/vitepress-doc-examples';
import { githubLinks } from '@micro509/vitepress-github-links';
import type { DocsVersion, SidebarOrder } from '@micro509/vitepress-versioned-docs';
import { versionedDocs } from '@micro509/vitepress-versioned-docs';
import markdownItTaskLists from 'markdown-it-task-lists';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import robotsTxt from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import type { DefaultTheme } from 'vitepress';
import { defineConfig } from 'vitepress';

/** DefaultTheme config plus the versions the navbar components render. */
interface DocsThemeConfig extends DefaultTheme.Config {
	/** Timeline order: next, the release the root serves, then archives. */
	readonly versions: readonly DocsVersion[];
}

const repoRoot = path.resolve(import.meta.dirname, '../..');
/** Where the authored pages live, relative to VitePress's srcDir (the repo). */
const siteRoot = 'site';

/** What a tree declares about itself. */
interface Manifests {
	readonly name: string;
	readonly version: string;
	readonly description: string;
	readonly homepage: string;
	readonly license: string;
	readonly author: { readonly name: string };
	readonly repository: { readonly url: string };
	/** Subpath -> built file, for the library the docs co-host. */
	readonly exports: Readonly<Record<string, string | { readonly default: string }>>;
	/** jsr.json: the registry name, and the public entrypoints in source form. */
	readonly registry: {
		readonly name: string;
		readonly exports: Readonly<Record<string, string>>;
	};
}

/**
 * Read a tree's manifests.
 *
 * Off disk, for every tree — including this one. Importing this repository's
 * manifests would be typed and free, but the same questions get asked of each
 * released tag ("what were you called, what did you export"), and a tag's
 * answers are its own. One reader, one answer per tree.
 */
function manifestsOf(root: string): Manifests {
	const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
	const jsr = JSON.parse(fs.readFileSync(path.join(root, 'jsr.json'), 'utf8'));
	return { ...pkg, registry: jsr };
}

const repo = manifestsOf(repoRoot);
const repoUrl = new URL(repo.repository.url.replace('git+', '').replace(/\.git$/, ''));

/** The ref source links point at: CI states it, a local build asks git. */
const gitRef = ((): string => {
	for (const name of ['MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME']) {
		const value = process.env[name]?.trim();
		if (value !== undefined && value !== '') return value;
	}
	try {
		const branch = execFileSync('git', ['branch', '--show-current'], {
			cwd: repoRoot,
			encoding: 'utf8',
		}).trim();
		if (branch !== '') return branch;
	} catch {}
	return 'master';
})();

/** One tree's API reference, generated the way this project is laid out. */
function generateApi(target: { readonly root: string; readonly outDir: string }): void {
	const tree = manifestsOf(target.root);
	const importMap = 'deno.import_map.json';
	writeDenoImportMap({ root: target.root, manifest: 'package.json', out: importMap });

	generateApiDocs({
		root: target.root,
		outDir: target.outDir,
		name: tree.name,
		importMap,
		// The `.` barrel re-exports every subpath and would document each symbol twice.
		entrypoints: Object.entries(tree.registry.exports)
			.filter(([subpath]) => subpath !== '.')
			.map(([, source]) => source.replace(/^\.\//, ''))
			.sort(),
	});
}

/**
 * The library `/next/` serves, compiled from the sources being documented.
 *
 * A fresh checkout has no `dist/`, so this is what a build machine is missing
 * when it has never run the library's own build.
 */
const distDir = path.join(repoRoot, 'dist');
execFileSync('bun', ['run', 'bd'], { cwd: repoRoot, stdio: 'inherit' });

/** Markdown files directly under `dir`. */
function pagesIn(dir: string): readonly string[] {
	if (!fs.existsSync(dir)) return [];
	return fs
		.readdirSync(dir)
		.filter((entry) => entry.endsWith('.md'))
		.map((entry) => path.join(dir, entry));
}

/**
 * The runnable examples, and what they may import.
 *
 * Only the tree's own pages: an archived version's examples were written against
 * that release's API and were checked by the build that shipped it, and the API
 * pages are generated from the very sources the examples are checked against.
 */
const examples: DocExamplesOptions = {
	root: repoRoot,
	pages: [
		path.join(repoRoot, siteRoot, 'index.md'),
		...pagesIn(path.join(repoRoot, siteRoot, 'guide')),
		...pagesIn(path.join(repoRoot, siteRoot, 'reference')),
	],
	outDir: path.join(import.meta.dirname, 'cache/examples'),
	/** A `<LiveCode>` tag wrapping a ts fence; the fence's source is the example. */
	block: /<LiveCode[^>]*>\s*\n\n```ts\n([\s\S]*?)```/g,
	paths: {
		[repo.name]: [path.join(repoRoot, 'src/index.ts')],
		[`${repo.name}/*`]: [path.join(repoRoot, 'src/*/index.ts')],
	},
};

/**
 * Every version this site serves, and the hooks that route them: the checked-out
 * tree at `/next/`, the newest release at `/`, one tree per superseded release at
 * `/vX.Y.Z/`. Resolved before VitePress globs for pages.
 */
const docs = await versionedDocs({
	repoRoot,
	siteRoot,
	versionsDir: path.join(repoRoot, siteRoot, 'versions'),
	cacheDir: path.join(import.meta.dirname, 'cache/versions'),
	distDir,
	devLabel: `v${repo.version}-dev`,
	pages: ['site/guide', 'site/reference', 'site/index.md'],
	sources: ['src', 'package.json', 'jsr.json'],
	releases: {
		index: `https://registry.npmjs.org/${repo.name}`,
		libraryPath: 'package/dist',
		tag: (version) => `v${version}`,
		source: (tag) => `https://codeload.github.com${repoUrl.pathname}/tar.gz/refs/tags/${tag}`,
		url: (tag) => `${repoUrl.href}/releases/tag/${tag}`,
		offline: process.env.DOCS_OFFLINE === '1',
	},
	library: { name: repo.name, exports: repo.exports, exportsPrefix: './dist/' },
	generateApi,
	fileGuardrail: 19_500,
});

/**
 * Reading order within each section — the only thing about a version's pages
 * this file decides. Which pages exist, and what each is called, comes from the
 * version being rendered: an archived release lists the pages it shipped, under
 * the titles it gave them. Unlisted pages append to their section's last group.
 */
const ORDER: SidebarOrder = {
	guide: [
		{ text: 'Introduction', slugs: ['getting-started', 'why'] },
		{ text: 'Workflows', slugs: ['certificates', 'verification', 'keys', 'revocation', 'pkcs'] },
	],
	reference: [{ text: 'Reference', slugs: ['index', 'standards', 'algorithms', 'runtimes'] }],
	api: [{ text: 'API Reference', slugs: ['index'] }],
};

export default defineConfig<DocsThemeConfig>({
	vite: {
		build: { chunkSizeWarningLimit: 1500 },
		plugins: [
			apiDocsPlugin({
				watchDir: path.join(repoRoot, 'src'),
				regenerate: () =>
					generateApi({ root: repoRoot, outDir: path.join(repoRoot, siteRoot, 'api') }),
			}),
			docExamplesPlugin(examples),
			docs.plugin,
			robotsTxt({ preset: 'allowAll' }),
			svgToIco({
				input: `${import.meta.dirname}/../assets/favicon.svg`,
				emit: [{ format: 'ico' }],
			}),
		],
		publicDir: `${import.meta.dirname}/../assets/`,
	},

	title: repo.name,
	description: repo.description,
	cleanUrls: true,
	lastUpdated: true,
	srcDir: '../',
	srcExclude: [
		'**/AGENTS.md',
		'**/README.md',
		'.opencode/**',
		'.claude/**',
		'comparisons/**',
		'packages/**',
		'src/**',
		'test/**',
		'docs/rfc/**',
		'CONTRIBUTING.md',
		'**/_*.md',
	],
	ignoreDeadLinks: [/test\/fixtures\//],

	rewrites: docs.rewrites,
	sitemap: {
		hostname: repo.homepage,
		transformItems: (items) => items.filter((item) => docs.isIndexable(item.url)),
	},

	markdown: {
		config(md) {
			md.use(markdownItTaskLists);
			docs.markdown(md);
			githubLinks({ repoUrl: repoUrl.href, ref: gitRef })(md);
		},
	},

	transformPageData: docs.transformPageData,
	transformHead: (context) => docs.head(context.page),
	transformHtml: (html, _id, context) => docs.html(html, context.page),
	buildEnd: docs.buildEnd,

	head: /* biome-ignore format: X */ [
		['meta', { name: 'theme-color', content: '#3c8772' }],
		['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
		['meta', { property: 'og:type', content: 'website' }],
		['meta', { property: 'og:title', content: repo.name }],
		['meta', { property: 'og:description', content: repo.description }],
		['meta', { property: 'og:url', content: repo.homepage }],
		['meta', { property: 'og:image', content: `${repo.homepage}/icon.svg` }],
		['meta', { name: 'twitter:card', content: 'summary' }],
		['meta', { name: 'twitter:title', content: repo.name }],
		['meta', { name: 'twitter:description', content: repo.description }],
	],

	themeConfig: {
		logo: { light: '/icon.svg', dark: '/icon-light.svg', alt: repo.name },
		versions: docs.versions,
		nav: [{ component: 'VersionedNav' }, { component: 'VersionSwitcher' }],
		sidebar: docs.sidebar(ORDER),

		socialLinks: [
			{ icon: 'github', link: repoUrl.href, ariaLabel: 'GitHub' },
			{ icon: 'npm', link: `https://npm.im/${repo.name}`, ariaLabel: 'NPM' },
			{
				icon: {
					svg: '<svg role="img" viewBox="0 0 24 12.924" xmlns="http://www.w3.org/2000/svg"><title>JSR</title><path fill="#f7df1e" d="M3.692 0v3.693H0v7.384h7.385v1.847h12.923v-3.693H24V1.847h-7.385V0Z"/><path fill="#083344" d="M3.692 0v3.693H0v7.384h7.385v1.847h12.923v-3.693H24V1.847h-7.385V0Zm1.846 1.847h1.847v7.384H1.846v-3.692h1.846v1.846h1.846zm3.693 0h5.538V3.692h-3.692v1.846h3.692v5.538H9.231V9.232h3.692v-1.846H9.231Zm7.384 1.846h5.539v3.692h-1.846v-1.846h-1.846v5.538h-1.847z"/></svg>',
				},
				link: `https://jsr.io/${repo.registry.name}`,
				ariaLabel: 'JSR',
			},
		],

		footer: {
			message: `Released under the ${repo.license} License.`,
			copyright: `Copyright © ${new Date().getFullYear()}-present ${repo.author.name}`,
		},

		search: { provider: 'local' },
	},
});
