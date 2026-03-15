import { defineConfig } from 'vitepress';
import typedocSidebar from '../reference/api/typedoc-sidebar.json';

const apiSidebar = Array.isArray(typedocSidebar)
	? typedocSidebar.map((item: { text: string; link: string }) => ({
			text: item.text === 'index' ? 'micro509' : `micro509/${item.text}`,
			link: item.link.replace('/site/', '/').replace('.md', ''),
		}))
	: [];

export default defineConfig({
	vite: { build: { chunkSizeWarningLimit: 1500 } },
	title: 'micro509',
	description:
		'The TypeScript PKI library that tells you why verification failed, not just that it did.',
	base: '/',
	cleanUrls: true,
	lastUpdated: true,

	head: [['meta', { name: 'theme-color', content: '#3c8772' }]],

	themeConfig: {
		nav: [
			{ text: 'Guide', link: '/guide/getting-started' },
			{ text: 'API', link: '/reference/api/' },
			{ text: 'Standards', link: '/reference/standards' },
		],

		sidebar: {
			'/guide/': [
				{
					text: 'Introduction',
					items: [
						{ text: 'Getting Started', link: '/guide/getting-started' },
						{ text: 'Why micro509', link: '/guide/why' },
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
			'/reference/api/': [
				{
					text: 'API Reference',
					items: apiSidebar,
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

		socialLinks: [{ icon: 'github', link: 'https://github.com/kjanat/ts-x509' }],

		footer: {
			message: 'Released under the MIT License.',
		},

		search: {
			provider: 'local',
		},
	},
});
