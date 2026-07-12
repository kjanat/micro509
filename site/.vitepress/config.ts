import markdownItTaskLists from 'markdown-it-task-lists';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { cp } from 'node:fs/promises';
import { dirname, extname, join, normalize, resolve, sep } from 'node:path';
import robotsTxt from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import { type DefaultTheme, defineConfigWithTheme, type HeadConfig, type Plugin } from 'vitepress';

/** DefaultTheme config plus the channel fields read by VersionSwitcher.vue. */
interface DocsThemeConfig extends DefaultTheme.Config {
	readonly docsChannel: string;
	readonly docsVersion: string;
}

import jsr from '../../jsr.json' with { type: 'json' };
import pkg from '../../package.json' with { type: 'json' };
import { apiDocsPlugin, generateApiDocs } from './api-gen.ts';

/** Trimmed stdout of a local git command, or '' if git is unavailable/fails. */
const gitOut = (args: readonly string[]): string => {
	try {
		return execFileSync('git', args, { encoding: 'utf8' }).trim();
	} catch {
		return '';
	}
};

/**
 * First non-empty override env (CI provides these), else a local-git fallback.
 * Precedence: explicit `MICRO509_*` > Cloudflare CI > GitHub Actions > local git.
 */
const resolveGit = (names: readonly string[], fallback: () => string): string => {
	for (const name of names) {
		const v = process.env[name]?.trim();
		if (v) return v;
	}
	const local = fallback().trim();
	if (local) return local;
	throw new Error(`Cannot resolve git info: no env (${names.join(', ')}) and local git failed.`);
};

// ── Docs channel ──────────────────────────────────────────────────────────
//
// One site build = one channel flavor. The assembly script
// (scripts/assemble-site.bun.ts) composes flavors into the deployed tree:
// root '/' = latest stable npm release, '/next/' = master canary,
// '/vX.Y/' = archived minors.

/** URL prefix this build is served under: '/', '/next/', or '/vX.Y/'. */
const docsBase = process.env.DOCS_BASE ?? '/';
/** Which channel this build represents; non-latest builds get noindex. */
const docsChannel = process.env.DOCS_CHANNEL ?? 'latest';
/**
 * Display label for the navbar version switcher. Only release tooling passes
 * an explicit DOCS_VERSION; every other build (local dev, bootstrap root) is
 * an unreleased tree and says so.
 */
const docsVersion = process.env.DOCS_VERSION ?? `v${pkg.version}-dev`;
if (!/^\/(?:[\w.-]+\/)?$/.test(docsBase)) {
	throw new Error(`DOCS_BASE must be '/' or '/<segment>/', got: ${docsBase}`);
}
if (docsChannel !== 'latest' && docsChannel !== 'next' && docsChannel !== 'archive') {
	throw new Error(`DOCS_CHANNEL must be latest|next|archive, got: ${docsChannel}`);
}

/** Git info for edit links. */
const gitEnv = {
	/** Branch name for edit links. */
	get branch(): string {
		return resolveGit(['MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME'], () =>
			gitOut(['branch', '--show-current']),
		);
	},

	/** Cleaned GitHub url */
	get githubUrl(): string {
		return pkg.repository.url.replace('git+', '').replace(/\.git$/, '');
	},
};

// ── Co-hosted library ─────────────────────────────────────────────────────
//
// LiveCode snippets import the library built from THIS git tree, served by
// the site itself under /vendor/micro509 — not a per-commit pkg-pr-new blob
// via esm.sh. Docs and library can never drift apart at build time, and the
// site build no longer depends on every commit having a successful package
// publish.

const repoRoot = resolve(import.meta.dirname, '../..');
const distDir = join(repoRoot, 'dist');
// docsBase ends in '/'; raw head URLs and the import map are NOT base-rewritten
// by VitePress, so the channel prefix must be baked in here.
const vendorBase = `${docsBase}vendor/${pkg.name}`;

/** Build the library so dist/ matches the checked-out sources. */
function buildLibrary(): void {
	execFileSync('bun', ['run', 'bd'], { cwd: repoRoot, stdio: 'inherit' });
}

/** Import map entries derived from package.json exports, served from /vendor. */
const importEntries = (Object.entries(pkg.exports) as [string, string | { default: string }][])
	.filter((e): e is [string, { default: string }] => typeof e[1] === 'object')
	.map(([key, value]): [string, string] => [
		key === '.' ? pkg.name : `${pkg.name}/${key.slice(2)}`,
		`${vendorBase}/${value.default.replace('./dist/', '')}`,
	]);

/** Entry-point URLs for module preloading. */
const entryUrls = importEntries.map(([, url]) => url);

/** Import map JSON for browser module resolution. */
const importMapJson = JSON.stringify({ imports: Object.fromEntries(importEntries) });

const VENDOR_CONTENT_TYPES: Record<string, string> = {
	'.js': 'text/javascript; charset=utf-8',
	'.mjs': 'text/javascript; charset=utf-8',
	'.map': 'application/json; charset=utf-8',
	'.ts': 'text/plain; charset=utf-8',
	'.txt': 'text/plain; charset=utf-8',
};

/**
 * Vite plugin — serves the built library from dist/ under /vendor in dev
 * mode, and injects the import map via `transformIndexHtml` (fires in dev
 * but NOT during VitePress SSG; the SSG path is covered by `transformHtml`
 * below). The production build gets its /vendor files copied into outDir by
 * the `buildEnd` hook.
 */
function cohostedLibraryPlugin(): Plugin {
	return {
		name: `${pkg.name}-cohosted-library`,
		configureServer(server) {
			server.middlewares.use((req, res, next) => {
				const url = (req.url ?? '').split('?')[0] ?? '';
				if (!url.startsWith(`${vendorBase}/`)) return next();
				const file = resolve(distDir, url.slice(vendorBase.length + 1));
				// Containment check: never serve outside dist/ (e.g. /vendor/micro509/../..).
				if (!file.startsWith(distDir + sep) || !existsSync(file)) return next();
				res.setHeader(
					'Content-Type',
					VENDOR_CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
				);
				res.end(readFileSync(file));
			});
		},
		transformIndexHtml: {
			order: 'pre',
			handler: () => [
				...entryUrls.map((url) => ({
					tag: 'link' as const,
					attrs: { rel: 'modulepreload', href: url },
					injectTo: 'head' as const,
				})),
				{
					tag: 'script',
					attrs: { type: 'importmap' },
					children: importMapJson,
					injectTo: 'head-prepend' as const,
				},
			],
		},
	};
}

// Generate the API reference pages (module + per-symbol) at config-load time,
// before VitePress resolves its page list — so every generated `/api/...` page
// exists when dead-link checking runs. The plugin below only handles dev HMR.
generateApiDocs();

// Build the co-hosted library at config-load time so /vendor always serves
// dist/ compiled from the checked-out sources (fast: ~300ms incremental).
buildLibrary();

/** Only the latest-release channel is indexable; /next/ and /vX.Y/ are not. */
const noindexHead: HeadConfig[] =
	docsChannel === 'latest' ? [] : [['meta', { name: 'robots', content: 'noindex' }]];

export default defineConfigWithTheme<DocsThemeConfig>({
	vite: {
		build: { chunkSizeWarningLimit: 1500 },
		plugins: [
			apiDocsPlugin(),
			cohostedLibraryPlugin(),
			robotsTxt({ preset: 'allowAll' }),
			svgToIco({
				input: `${import.meta.dirname}/../assets/favicon.svg`,
				// v4 emit array: generate favicon.ico only. The source favicon.svg is
				// already shipped via publicDir and the favicon link is declared in
				// `head` below, so no SVG re-emit and no auto-injection.
				emit: [{ format: 'ico' }],
			}),
		],
		publicDir: `${import.meta.dirname}/../assets/`,
	},
	title: pkg.name,
	description: pkg.description,
	base: docsBase,
	cleanUrls: true,
	lastUpdated: true,
	sitemap: { hostname: pkg.homepage + docsBase },

	srcDir: '../',
	rewrites: { 'site/:path*': ':path*' },
	srcExclude: [
		'**/AGENTS.md',
		'**/README.md',
		'.opencode/**',
		'.claude/**',
		'comparisons/**',
		'src/**',
		'test/**',
		'docs/rfc/**',
		'CONTRIBUTING.md',
		'**/_*.md',
	],
	ignoreDeadLinks: [/test\/fixtures\//],

	markdown: {
		config(md) {
			md.use(markdownItTaskLists);

			/** Rewrite relative links to non-page files (`.ts`, `.txt`, etc.) as GitHub blob URLs. */
			const defaultLinkOpen =
				md.renderer.rules.link_open ??
				((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options));

			md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
				const token = tokens[idx];
				if (!token) return defaultLinkOpen(tokens, idx, options, env, self);
				const href = token.attrGet('href');
				if (
					href &&
					!href.startsWith('http') &&
					!href.startsWith('//') &&
					!href.startsWith('#') &&
					!href.startsWith('/') &&
					!href.endsWith('.md') &&
					!/\.html(?:#|$)/.test(href)
				) {
					const rel: string = env.relativePath ?? '';
					const resolved = normalize(join(dirname(rel), href));
					const segment = resolved.endsWith('/') ? 'tree' : 'blob';
					token.attrSet('href', `${gitEnv.githubUrl}/${segment}/${gitEnv.branch}/${resolved}`);
				}
				return defaultLinkOpen(tokens, idx, options, env, self);
			};
		},
	},

	head: /* biome-ignore format: X */ [
		['meta', { name: 'theme-color', content: '#3c8772' }],
		['link', { rel: 'icon', href: `${docsBase}favicon.svg`, type: 'image/svg+xml' }],
		['meta', { property: 'og:type', content: 'website' }],
		['meta', { property: 'og:title', content: pkg.name }],
		['meta', { property: 'og:description', content: pkg.description }],
		['meta', { property: 'og:url', content: pkg.homepage + docsBase }],
		['meta', { property: 'og:image', content: `${pkg.homepage}/icon.svg` }],
		['meta', { name: 'twitter:card', content: 'summary' }],
		['meta', { name: 'twitter:title', content: pkg.name }],
		['meta', { name: 'twitter:description', content: pkg.description }],
		// Only the latest-release channel is indexable; /next/ and /vX.Y/ are not.
		...noindexHead,
	],

	/** Inject import map before any module scripts (SSG build path). */
	transformHtml(html) {
		const preloadTags = entryUrls
			.map((url) => `<link rel="modulepreload" href="${url}">`)
			.join('\n');
		return html.replace(
			'<head>',
			`<head>\n${preloadTags}\n<script type="importmap">${importMapJson}</script>`,
		);
	},

	/** Ship the co-hosted library: copy the built dist/ into the site output. */
	async buildEnd(siteConfig) {
		await cp(distDir, join(siteConfig.outDir, 'vendor', pkg.name), { recursive: true });
	},

	themeConfig: {
		logo: { light: '/icon.svg', dark: '/icon-light.svg', alt: pkg.name },
		// Read by VersionSwitcher.vue for the SSR-safe navbar label.
		docsChannel,
		docsVersion,
		nav: [
			{ text: 'Guide', link: '/guide/getting-started' },
			{ text: 'API', link: '/api/' },
			{ text: 'Reference', link: '/reference/standards' },
			{ component: 'VersionSwitcher' },
		],

		sidebar: {
			'/guide/': [
				{
					text: 'Introduction',
					items: [
						{ text: 'Getting Started', link: '/guide/getting-started' },
						{ text: `Why ${pkg.name}?`, link: '/guide/why' },
					],
				},
				{
					text: 'Workflows',
					items: [
						{ text: 'Certificates', link: '/guide/certificates' },
						{ text: 'Verification', link: '/guide/verification' },
						{ text: 'Keys', link: '/guide/keys' },
						{ text: 'Revocation', link: '/guide/revocation' },
						{ text: 'PKCS', link: '/guide/pkcs' },
					],
				},
			],
			'/api/': [
				{
					text: 'API Reference',
					items: [
						{ text: 'Overview', link: '/api/' },
						...Object.keys(jsr.exports)
							.filter((key) => key !== '.')
							.map((key) => key.slice('./'.length))
							.sort()
							.map((mod) => ({ text: `${pkg.name}/${mod}`, link: `/api/${mod}` })),
					],
				},
			],
			'/reference/': [
				{
					text: 'Reference',
					items: [
						{ text: 'Standards Scope', link: '/reference/standards' },
						{ text: 'Algorithms', link: '/reference/algorithms' },
						{ text: 'Runtime Support', link: '/reference/runtimes' },
					],
				},
			],
		},

		socialLinks: [
			{ icon: 'github', link: gitEnv.githubUrl, ariaLabel: 'GitHub' },
			{ icon: 'npm', link: `https://npm.im/${pkg.name}`, ariaLabel: 'NPM' },
			{
				icon: {
					svg: '<svg role="img" viewBox="0 0 24 12.924" xmlns="http://www.w3.org/2000/svg"><title>JSR</title><path fill="#f7df1e" d="M3.692 0v3.693H0v7.384h7.385v1.847h12.923v-3.693H24V1.847h-7.385V0Z"/><path fill="#083344" d="M3.692 0v3.693H0v7.384h7.385v1.847h12.923v-3.693H24V1.847h-7.385V0Zm1.846 1.847h1.847v7.384H1.846v-3.692h1.846v1.846h1.846zm3.693 0h5.538V3.692h-3.692v1.846h3.692v5.538H9.231V9.232h3.692v-1.846H9.231Zm7.384 1.846h5.539v3.692h-1.846v-1.846h-1.846v5.538h-1.847z"/></svg>',
				},
				link: `https://jsr.io/${jsr.name}`,
				ariaLabel: 'JSR',
			},
		],

		// editLink: {
		// 	pattern: `${gitEnv.githubUrl}/edit/${gitEnv.branch}/site/:path`,
		// 	text: 'Edit this page on GitHub',
		// },

		footer: {
			message: `Released under the ${pkg.license} License.`,
			copyright: `Copyright © ${new Date().getFullYear()}-present ${pkg.author.name}`,
		},

		search: {
			provider: 'local',
		},
	},
});
