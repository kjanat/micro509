#!/usr/bin/env bun
/**
 * Generates `deno.import_map.json` for `deno doc`.
 *
 * `deno check` and `deno lint` honor the package.json `imports` subpath
 * patterns (`#micro509/*` -> `./src/*.ts`) natively, but `deno doc` does not —
 * it reports every `#micro509/*` import as "not a dependency". A Deno import
 * map can bridge that, except import maps cannot append an extension (a `/`
 * prefix key must map to a `/` prefix value, and globs are unsupported). So the
 * `#micro509/*` pattern is expanded here into one explicit entry per source
 * file, alongside the non-wildcard entries copied straight from package.json.
 *
 * @module
 */

import { Glob } from 'bun';
import { readFileSync, writeFileSync } from 'node:fs';

const pkg: { readonly imports: Record<string, string> } = JSON.parse(
	readFileSync('package.json', 'utf8'),
);

const imports: Record<string, string> = {};

// Copy the non-wildcard entries verbatim (barrels, #pkg, #jsr, #typedoc-sidebar).
for (const [key, value] of Object.entries(pkg.imports)) {
	if (!key.includes('*')) {
		imports[key] = value;
	}
}

// Expand `#micro509/*` -> `./src/*.ts` into an explicit entry per source file.
const files = [...new Glob('src/**/*.ts').scanSync('.')].sort();
for (const file of files) {
	const specifier = `#micro509/${file.slice('src/'.length).replace(/\.ts$/, '')}`;
	imports[specifier] = `./${file}`;
}

writeFileSync('deno.import_map.json', `${JSON.stringify({ imports }, null, 2)}\n`);
