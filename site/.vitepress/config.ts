import { writeImportMap } from 'importmapify';
import { entrypointsOf } from '@micro509/doc-render';
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
import ts from 'typescript';
import robotsTxt from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import type { DefaultTheme } from 'vitepress';
import { defineConfig } from 'vitepress';

interface DocsThemeConfig extends DefaultTheme.Config {
	readonly versions: readonly DocsVersion[];
}

const repoRoot = path.resolve(import.meta.dirname, '../..');
const siteRoot = 'site';

interface Manifests {
	readonly name: string;
	readonly version: string;
	readonly description: string;
	readonly homepage: string;
	readonly license: string;
	readonly author: { readonly name: string };
	readonly repository: { readonly url: string };
	readonly exports: Readonly<Record<string, unknown>>;
	/** From jsr.json. Its exports point at source files. */
	readonly registry: {
		readonly name: string;
		readonly exports: Readonly<Record<string, string>>;
	};
}

function manifestsOf(root: string): Manifests {
	const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
	const jsr = JSON.parse(fs.readFileSync(path.join(root, 'jsr.json'), 'utf8'));
	return { ...pkg, registry: jsr };
}

const repo = manifestsOf(repoRoot);
const repoUrl = new URL(repo.repository.url.replace('git+', '').replace(/\.git$/, ''));

function git(...args: readonly string[]): string | undefined {
	try {
		const out = execFileSync('git', args, { cwd: repoRoot, encoding: 'utf8' }).trim();
		return out === '' ? undefined : out;
	} catch (error) {
		console.warn(`[versions] git ${args.join(' ')}: ${String(error)}`);
		return undefined;
	}
}

function envOf(...names: readonly string[]): string | undefined {
	for (const name of names) {
		const value = process.env[name]?.trim();
		if (value !== undefined && value !== '') return value;
	}
	return undefined;
}

/** The ref source links point at.
 *
 * Supported environments for the docs site build:
 * - Workers CI (WORKERS_CI_BRANCH / WORKERS_CI_COMMIT_SHA)
 * - GitHub Actions (GITHUB_REF_NAME / GITHUB_SHA)
 * - Local / manual (git branch or MICRO509_GIT_BRANCH override)
 */
const gitRef =
	envOf('MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME') ??
	git('branch', '--show-current') ??
	'master';

function generateApi(target: { readonly root: string; readonly outDir: string }): void {
	const tree = manifestsOf(target.root);
	const importMap = 'deno.import_map.json';
	writeImportMap({ root: target.root, out: importMap });

	generateApiDocs({
		root: target.root,
		outDir: target.outDir,
		name: tree.name,
		importMap,
		entrypoints: entrypointsOf(tree.registry),
	});
}

function commitSha(): string | undefined {
	return envOf('WORKERS_CI_COMMIT_SHA') ?? git('rev-parse', 'HEAD');
}

const treeSha = commitSha();

const GITHUB_TIMEOUT_MS = 10_000;

async function pullRequestOf(sha: string): Promise<string | undefined> {
	const url = `https://api.github.com/repos${repoUrl.pathname}/commits/${sha}/pulls`;
	const token = envOf('GITHUB_TOKEN');

	try {
		const response = await fetch(url, {
			headers: {
				accept: 'application/vnd.github+json',
				'user-agent': repo.name,
				...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
			},
			signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
		});
		if (!response.ok) {
			console.warn(`[versions] ${url}: ${response.status} ${response.statusText}`);
			return undefined;
		}

		const pulls: ReadonlyArray<{ readonly number: number }> = await response.json();
		const first = pulls[0];
		return first === undefined ? undefined : String(first.number);
	} catch (error) {
		console.warn(`[versions] ${url}: ${String(error)}`);
		return undefined;
	}
}

const pull = await (async (): Promise<string | undefined> => {
	if (process.env.DOCS_OFFLINE === '1' || gitRef === 'master') return undefined;

	// Some CI environments pass PR refs in the form "NN/merge" or "NN/head".
	// Extract the PR number so pkg.pr.new gets a clean ref like "54" instead of "54/merge".
	const prMatch = gitRef.match(/^(\d+)\/(merge|head)$/);
	if (prMatch) return prMatch[1];

	return treeSha === undefined ? undefined : await pullRequestOf(treeSha);
})();

/** An immutable ref for the library that the current-tree docs execute. */
const nextRef = treeSha ?? (pull ?? gitRef).replace(/\/(?:merge|head)$/, '');

const devLabel = pull === undefined ? `v${repo.version}-dev` : `#${pull}`;
const devLabelUrl =
	pull === undefined ? undefined : `${repoUrl.origin}${repoUrl.pathname}/pull/${pull}`;

console.log(`[versions] tree -> GitHub @${nextRef}, labelled ${devLabel}`);

/** Markdown files directly under `dir`. */
function pagesIn(dir: string): readonly string[] {
	if (!fs.existsSync(dir)) return [];
	return fs
		.readdirSync(dir)
		.filter((entry) => entry.endsWith('.md'))
		.map((entry) => path.join(dir, entry));
}

const examples: DocExamplesOptions = {
	root: repoRoot,
	pages: [
		path.join(repoRoot, siteRoot, 'index.md'),
		...pagesIn(path.join(repoRoot, siteRoot, 'guide')),
		...pagesIn(path.join(repoRoot, siteRoot, 'reference')),
	],
	outDir: path.join(import.meta.dirname, 'cache/examples'),
	/** Matches a `<LiveCode>` tag wrapping a ts fence. The capture is the example. */
	block: /<LiveCode[^>]*>\s*\n\n```ts\n([\s\S]*?)```/g,
	paths: {
		[repo.name]: [path.join(repoRoot, 'src/index.ts')],
		[`${repo.name}/*`]: [path.join(repoRoot, 'src/*/index.ts')],
	},
};

const LIVE_CODE_BLOCK = /(<LiveCode[^>]*>\s*\n\n```ts\n)([\s\S]*?)(```)/g;

/** The example's syntax errors. A bare transpile does no type checking. */
function syntaxErrors(source: string): readonly ts.Diagnostic[] {
	return (
		ts.transpileModule(source, {
			reportDiagnostics: true,
			compilerOptions: { target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext },
		}).diagnostics ?? []
	);
}

/**
 * Repair an example that lost a closing brace before its tag by inserting each
 * brace where the parser expects it, then confirming the result parses. An
 * example that does not resolve to valid syntax is left untouched.
 */
function repairExample(source: string): string {
	let repaired = source;
	for (let attempt = 0; attempt < 20; attempt += 1) {
		const errors = syntaxErrors(repaired);
		if (errors.length === 0) return repaired;
		const missingBrace = errors.find((error) => error.code === 1005 || error.code === 1513);
		if (missingBrace === undefined || missingBrace.start === undefined) return source;
		repaired = `${repaired.slice(0, missingBrace.start)}}\n${repaired.slice(missingBrace.start)}`;
	}
	return source;
}

/** Repair runnable examples an archived tag shipped with a syntax error. */
function repairExamples(markdown: string): string {
	return markdown.replace(LIVE_CODE_BLOCK, (whole, open, body, close) =>
		syntaxErrors(body).length === 0 ? whole : `${open}${repairExample(body)}${close}`,
	);
}

const docs = await versionedDocs({
	repoRoot,
	siteRoot,
	versionsDir: path.join(repoRoot, siteRoot, 'versions'),
	cacheDir: path.join(import.meta.dirname, 'cache/versions'),
	devLabel,
	...(devLabelUrl === undefined ? {} : { devLabelUrl }),
	pages: ['site/guide', 'site/reference', 'site/index.md'],
	sources: ['src', 'package.json', 'jsr.json'],
	transformPage: repairExamples,
	releases: {
		index: `https://registry.npmjs.org/${repo.name}`,
		tag: (version) => `v${version}`,
		source: (tag) => `https://codeload.github.com${repoUrl.pathname}/tar.gz/refs/tags/${tag}`,
		url: (tag) => `${repoUrl.href}/releases/tag/${tag}`,
		/** A preview serves only its pull request. */
		offline: process.env.DOCS_OFFLINE === '1' || pull !== undefined,
	},
	/** jsDelivr serves releases. esm.sh builds the current GitHub tree by commit. */
	library: {
		name: repo.name,
		moduleUrl: (version, subpath) => {
			const tail = subpath === '.' ? '' : `/${subpath.slice('./'.length)}`;
			return version.tag === devLabel
				? `https://esm.sh/gh${repoUrl.pathname}@${nextRef}${tail}?standalone`
				: `https://cdn.jsdelivr.net/npm/${repo.name}@${version.tag.replace(/^v/, '')}${tail}/+esm`;
		},
	},
	generateApi,
	fileGuardrail: 19_500,
});

const versionPrefixes = docs.versions
	.map((version) => version.prefix)
	.sort((left, right) => right.length - left.length);

function versionPrefixOfPath(pathname: string): string {
	const path = pathname.replace(/^\//, '');
	return (
		versionPrefixes.find(
			(prefix) => prefix === '' || path === prefix.slice(0, -1) || path.startsWith(prefix),
		) ?? ''
	);
}

/** Reading order within each section. Unlisted pages append to the last group. */
const ORDER: SidebarOrder = {
	guide: [
		{ text: 'Introduction', slugs: ['getting-started', 'why'] },
		{ text: 'Workflows', slugs: ['certificates', 'verification', 'keys', 'revocation', 'pkcs'] },
	],
	reference: [
		{
			text: 'Reference',
			slugs: ['index', 'standards', 'algorithms', 'runtimes', 'execution-model'],
		},
	],
	api: [{ text: 'API Reference', slugs: ['index', 'root'] }],
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

		search: {
			provider: 'local',
			options: {
				miniSearch: {
					/** @type {Pick<import('minisearch').Options, 'extractField' | 'tokenize' | 'processTerm'>} */
					options: {},
					/**
					 * @type {import('minisearch').SearchOptions}
					 * @default
					 * { fuzzy: 0.2, prefix: true, boost: {title: 4, text: 2, titles: 1}}
					 */
					searchOptions: {
						filter: (result) => {
							const pathname = globalThis.location?.pathname;
							return (
								pathname === undefined ||
								versionPrefixOfPath(String(result.id)) === versionPrefixOfPath(pathname)
							);
						},
					},
				},
			},
		},
	},
});
