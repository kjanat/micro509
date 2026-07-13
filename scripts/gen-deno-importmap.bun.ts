#!/usr/bin/env bun
/**
 * Writes `deno.import_map.json` for the checked-out tree (`deno doc`/`docs:*`).
 *
 * CLI over `writeDenoImportMap`; the site's API-doc plugin calls the same
 * function for each released tag's sources, with that tag's manifest.
 *
 * @module
 */
import path from 'node:path';
import { writeDenoImportMap } from '@micro509/doc-render/import-map';

const target = writeDenoImportMap({
	root: path.resolve(import.meta.dir, '..'),
	manifest: 'package.json',
	out: 'deno.import_map.json',
});
Bun.stderr.write(`Wrote ${target}\n`);
