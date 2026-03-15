import { robotsTxt } from 'vite-robots-txt';
import svgToIco from 'vite-svg-to-ico';
import { defineConfig } from 'vitepress';

import pkg from '../../package.json' with { type: 'json' };
import typedocSidebar from '../api/typedoc-sidebar.json' with { type: 'json' };

export default defineConfig({
	vite: {
		build: { chunkSizeWarningLimit: 1500 },
		plugins: [
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

	themeConfig: {
		logo: { light: '/icon.svg', dark: '/icon-light.svg', alt: 'micro509' },
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
									item.text === 'micro509'
										? []
										: [
												{
													text: `micro509/${item.text}`,
													link: item.link.replace('/site/', '/').replace('.md', ''),
												},
											],
								)
							: []),
						{ text: 'Full Reference', link: '/api/micro509' },
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
			{ icon: 'github', link: 'https://github.com/kjanat/ts-x509', ariaLabel: 'GitHub' },
			{ icon: 'npm', link: 'https://npm.im/micro509', ariaLabel: 'NPM' },
			{ icon: 'jsr', link: 'https://jsr.io/@kjanat/micro509', ariaLabel: 'JSR' },
		],

		footer: {
			message: `Released under the ${pkg.license} License.`,
		},

		search: {
			provider: 'local',
		},
	},
});
