#!/usr/bin/env -S deno run --allow-read --allow-net --allow-env --allow-sys --allow-run
/// <reference lib="deno.ns" />
/**
 * Renders the micro509 public API to cross-linked markdown (Deno entry).
 *
 * Sources doc nodes straight from `@deno/doc`'s `doc()` — the same wasm-compiled
 * deno_doc that backs the `deno doc` CLI, but in-process. No subprocess, and no
 * import map: `doc()` resolves `#micro509/*` via package.json imports natively.
 * Output is piped through dprint so it needs no downstream formatting.
 *
 *     deno run -A scripts/render-deno-doc-with-deno.ts [symbol...]
 *
 * Caveats vs the bun/CLI companion `render-deno-doc.ts` (the authoritative one):
 *   - Coverage: `doc()` surfaces 406 of the CLI's 413 symbols. The 7 it drops
 *     are `export type` re-exports (e.g. `IssuingDistributionPoint*`) it doesn't
 *     follow the way the CLI does with an explicit import map. The 406 it emits
 *     render identically.
 *   - Reliability: @deno/doc's wasm intermittently fails to instantiate
 *     (`__wbindgen_placeholder__`) in this environment. The value import stays on
 *     the `jsr:` specifier (the `npm:@jsr/deno__doc` alias runs its `export *`
 *     over a `.d.ts` at runtime and throws); the type comes from the npm alias
 *     via the shared module, so it resolves under tsgo/bun too.
 *
 * @module
 */

import { doc } from 'jsr:@deno/doc@0.199.0';

import { publicEntrypoints, renderDocuments } from './render-deno-doc.shared.ts';

const urls = publicEntrypoints.map((src) => new URL(`../${src}`, import.meta.url).href);
const nodes = await doc(urls);
const md = renderDocuments(nodes, new Set(Deno.args));

// Format through dprint so downstream doesn't have to.
const dprint = new Deno.Command('dprint', {
	args: ['fmt', '--stdin', 'md'],
	stdin: 'piped',
	stdout: 'piped',
});
const child = dprint.spawn();
const writer = child.stdin.getWriter();
await writer.write(new TextEncoder().encode(md));
await writer.close();
const { stdout } = await child.output();
await Deno.stdout.write(stdout);
