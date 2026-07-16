#!/usr/bin/env bun
/**
 * Writes `deno.import_map.json` for the checked-out tree (`deno doc`/`docs:*`).
 *
 * CLI over `writeImportMap`; the site's API-doc plugin calls the same
 * function for each released tag's source tree.
 *
 * @module
 */
import path from 'node:path';
import { writeImportMap } from 'importmapify';

const target = writeImportMap({
	root: path.resolve(import.meta.dir, '..'),
	manifest: 'package.json',
	out: 'deno.import_map.json',
	additionalImports: {
		'bun:test': './node_modules/bun-types/test.d.ts', //'https://cdn.jsdelivr.net/npm/bun-types@1.3/test.d.ts',
		'@deno/doc': 'jsr:@deno/doc@0.199.0',
	},
});
Bun.stderr.write(`Wrote ${target}\n`);
