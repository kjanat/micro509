import { dirname, join, normalize } from 'node:path';
import robotsTxt from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import { defineConfig, type Plugin } from 'vitepress';
import { cloudflare } from '@cloudflare/vite-plugin';
import markdownItTaskLists from 'markdown-it-task-lists';

import jsr from '../../jsr.json' with { type: 'json' };
import pkg from '../../package.json' with { type: 'json' };
import typedocSidebar from '../api/typedoc-sidebar.json' with { type: 'json' };

const getRequiredEnv = (names: readonly string[]): string => {
	for (const name of names) {
		const v = process.env[name]?.trim();
		if (v) return v;
	}

	throw new Error(`Missing required env: ${names.join(' or ')}. Run via package scripts.`);
};

/** Git info for edit links and cache-busting import map URLs. */
const gitEnv = {
	/** Branch name for edit links; also included in the import map URL to ensure cache invalidation on new commits. */
	get branch(): string {
		return getRequiredEnv(['MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME']);
	},
	/** Short 7-char hash for display; full hash is available via `GITHUB_SHA` in the import map URL. */
	get commitHash(): string {
		return getRequiredEnv(['MICRO509_GIT_COMMIT', 'WORKERS_CI_COMMIT_SHA', 'GITHUB_SHA']).slice(
			0,
			7,
		);
	},

	/** Cleaned GitHub url */
	get githubUrl(): string {
		return pkg.repository.url.replace('git+', '').replace(/\.git$/, '');
	},

	/** GitHub repo owner/name */
	get githubRepo(): string {
		const repo = this.githubUrl.match(/github\.com[:/](.+\/.+?)(?:\.git)?$/)?.[1];
		if (repo === undefined) throw new Error(`Invalid GitHub URL: ${this.githubUrl}`);
		return repo;
	},
};

/**
 * CDN base for the micro509 package in browser import maps.
 * Uses pkg-pr-new via esm.sh while pre-release; switch to
 * `https://esm.sh/micro509@${pkg.version}` once published on npm.
 */
const cdnBase = `https://esm.sh/pr/${gitEnv.githubRepo}/${pkg.name}@${gitEnv.commitHash}`;

/** Import map entries derived from package.json exports via the CDN. */
const importEntries = (Object.entries(pkg.exports) as [string, string | { default: string }][])
	.filter((e): e is [string, { default: string }] => typeof e[1] === 'object')
	.map(([key]): [string, string] => [
		key === '.' ? pkg.name : `${pkg.name}/${key.slice(2)}`,
		key === '.' ? cdnBase : `${cdnBase}/${key.slice(2)}`,
	]);

/** CDN URLs for prefetching. */
const cdnUrls = importEntries.map(([, url]) => url);

/** Import map JSON for browser module resolution. */
const importMapJson = JSON.stringify({ imports: Object.fromEntries(importEntries) });

/**
 * Vite plugin — injects import map in dev mode via `transformIndexHtml`.
 * This hook fires in dev but NOT during VitePress SSG; the SSG path is
 * covered by `transformHtml` below.
 */
function importMapPlugin(): Plugin {
	return {
		name: `${pkg.name}-importmap`,
		transformIndexHtml: {
			order: 'pre',
			handler: () => [
				...cdnUrls.map((url) => ({
					tag: 'link' as const,
					attrs: { rel: 'prefetch', as: 'script', href: url },
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

export default defineConfig({
	vite: {
		build: { chunkSizeWarningLimit: 1500 },
		plugins: [
			cloudflare(),
			importMapPlugin(),
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
	base: '/',
	cleanUrls: true,
	lastUpdated: true,
	sitemap: { hostname: pkg.homepage },

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
		'anal.md',
		'_gemini_*.md',
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
		['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
		['meta', { property: 'og:type', content: 'website' }],
		['meta', { property: 'og:title', content: pkg.name }],
		['meta', { property: 'og:description', content: pkg.description }],
		['meta', { property: 'og:url', content: pkg.homepage }],
		['meta', { property: 'og:image', content: `${pkg.homepage}/icon.svg` }],
		['meta', { name: 'twitter:card', content: 'summary' }],
		['meta', { name: 'twitter:title', content: pkg.name }],
		['meta', { name: 'twitter:description', content: pkg.description }],
	],

	/** Inject import map before any module scripts (SSG build path). */
	transformHtml(html) {
		const prefetchTags = cdnUrls
			.map((url) => `<link rel="prefetch" as="script" href="${url}">`)
			.join('\n');
		return html.replace(
			'<head>',
			`<head>\n${prefetchTags}\n<script type="importmap">${importMapJson}</script>`,
		);
	},

	themeConfig: {
		logo: { light: '/icon.svg', dark: '/icon-light.svg', alt: pkg.name },
		nav: [
			{ text: 'Guide', link: '/guide/getting-started' },
			{ text: 'API', link: '/api/' },
			{ text: 'Reference', link: '/reference/standards' },
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
						{ text: 'Root Import', link: `/api/${pkg.name}` },
						...(Array.isArray(typedocSidebar)
							? typedocSidebar.flatMap((item: { text: string; link: string }) =>
									item.text === pkg.name
										? []
										: [
												{
													text: `${pkg.name}/${item.text}`,
													link: item.link.replace('/site/', '/').replace('.md', ''),
												},
											],
								)
							: []),
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
