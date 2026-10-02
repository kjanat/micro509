import { defineConfig } from 'importmapify';

export default defineConfig({
	out: 'deno.import_map.json',
	additionalImports: {
		'bun:test': './node_modules/bun-types/test.d.ts',
		vue: './node_modules/vue/dist/vue.d.ts',
	},
});
