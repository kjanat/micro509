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

import pkg from '#pkg' with { type: 'json' };

const imports: Record<string, string> = {};
const root = new URL('..', import.meta.url).pathname;
const glob = new Bun.Glob('src/**/*.ts');

const denoMap = Bun.file(`${root}deno.import_map.json`);

// Copy the non-wildcard entries verbatim (barrels, #pkg, #jsr, #typedoc-sidebar).
for (const [key, value] of Object.entries(pkg.imports)) {
	if (!key.includes('*')) {
		imports[key] = value;
	}
}

// Expand `#micro509/*` -> `./src/*.ts` into an explicit entry per source file.
for (const file of await Array.fromAsync(glob.scan({ cwd: root }))) {
	imports[`#micro509/${file.slice('src/'.length).replace(/\.ts$/, '')}`] = `./${file}`;
}
const importMap = /* dprint-ignore */ `${JSON.stringify({ imports: Object.fromEntries(Object.entries(imports).sort(([a], [b]) => a.localeCompare(b))) }, null, '\t')}\n`;

try {
	await Bun.write(denoMap, importMap);
	console.error(`Wrote ${importMap.length} bytes to ${denoMap.name}`);
} catch (err) {
	process.exitCode = 1;
	console.error(`Failed to write ${denoMap.name}:`, err);
}
