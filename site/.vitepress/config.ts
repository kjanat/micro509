import type { Plugin } from 'vite';
import robotsTxt from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import { defineConfig } from 'vitepress';

import jsr from '../../jsr.json' with { type: 'json' };
import pkg from '../../package.json' with { type: 'json' };
import typedocSidebar from '../api/typedoc-sidebar.json' with { type: 'json' };

const getRequiredEnv = (names: readonly string[]): string => {
	for (const name of names) {
		if (process.env[name]?.trim()) return process.env[name]?.trim();
	}

	throw new Error(`Missing required env: ${names.join(' or ')}. Run via package scripts.`);
};

/** Git info for edit links and cache-busting import map URLs. */
const gitEnv = {
	/** Branch name for edit links; also included in the import map URL to ensure cache invalidation on new commits. */
	get branch(): string {
		return getRequiredEnv(['MICRO509_GIT_BRANCH', 'GITHUB_REF_NAME']);
	},
	/** Short 7-char hash for display; full hash is available via `GITHUB_SHA` in the import map URL. */
	get commitHash(): string {
		return getRequiredEnv(['MICRO509_GIT_COMMIT', 'GITHUB_SHA']).slice(0, 7);
	},

	/** Cleaned GitHub url */
	get githubUrl(): string {
		return pkg.repository.url.replace('git+', '').replace(/\.git$/, '');
	},

	/** GitHub repo owner/name */
	get githubRepo(): string {
		const match = this.githubUrl.match(/github\.com[:/](.+\/.+?)(?:\.git)?$/);
		if (!match) throw new Error(`Invalid GitHub URL: ${this.githubUrl}`);
		return match[1];
	},
};

/**
 * CDN base for the micro509 package in browser import maps.
 * Uses pkg-pr-new via esm.sh while pre-release; switch to
 * `https://esm.sh/micro509@${pkg.version}` once published on npm.
 */
const cdnBase = `https://esm.sh/pr/${gitEnv.githubRepo}/${pkg.name}@${gitEnv.commitHash}`;

/** Import map JSON derived from package.json exports via the CDN. */
const importMapJson = JSON.stringify({
	imports: Object.fromEntries(
		(Object.entries(pkg.exports) as [string, string | { default: string }][])
			.filter((e): e is [string, { default: string }] => typeof e[1] === 'object')
			.map(([key]) => [
				key === '.' ? pkg.name : `${pkg.name}/${key.slice(2)}`,
				key === '.' ? cdnBase : `${cdnBase}/${key.slice(2)}`,
			]),
	),
});

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
				{
					tag: 'script',
					attrs: { type: 'importmap' },
					children: importMapJson,
					injectTo: 'head-prepend',
				},
			],
		},
	};
}

export default defineConfig({
	vite: {
		build: { chunkSizeWarningLimit: 1500 },
		plugins: [
			importMapPlugin(),
			robotsTxt({ preset: 'disallowAll' }),
			svgToIco({
				input: `${import.meta.dirname}/../assets/favicon.svg`,
				emit: { source: true, inject: false },
			}),
		],
		publicDir: `${import.meta.dirname}/../assets/`,
	},
	title: pkg.name,
	description: pkg.description,
	base: '/',
	cleanUrls: true,
	lastUpdated: true,

	head: /* biome-ignore format: X */ [
		['meta', { name: 'theme-color', content: '#3c8772' }],
		['link', { rel: 'icon', href: '/favicon.ico', type: 'image/x-icon', sizes: '16x16 32x32 48x48' }],
		['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
	],

	/** Inject import map before any module scripts (SSG build path). */
	transformHtml(html) {
		return html.replace('<head>', `<head>\n<script type="importmap">${importMapJson}</script>`);
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
						{ text: 'Root Import', link: `/api/${pkg.name}` },
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
			{ icon: 'jsr', link: `https://jsr.io/${jsr.name}`, ariaLabel: 'JSR' },
		],

		// editLink: {
		// 	pattern: `${gitEnv.githubUrl}/edit/${gitEnv.branch}/site/:path`,
		// 	text: 'Edit this page on GitHub',
		// },

		footer: {
			message: `Released under the ${pkg.license} License.`,
			copyright: `Copyright © 2026-present ${pkg.author}`,
		},

		search: {
			provider: 'local',
		},
	},
});
