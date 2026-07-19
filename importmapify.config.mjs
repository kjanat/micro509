import { defineConfig } from 'importmapify';

export default defineConfig({
	root: '.',
	out: 'deno.import_map.json',
	additionalImports: {
		'bun:test': './node_modules/bun-types/test.d.ts',
		'@deno/doc': 'jsr:@deno/doc@0.199.0',
	},
});
