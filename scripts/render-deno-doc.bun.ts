#!/usr/bin/env bun
/**
 * Renders the micro509 public API to cross-linked markdown (bun entry).
 *
 * Sources doc nodes from the `deno doc --json` CLI: regenerates the Deno import
 * map (the CLI needs it to resolve `#micro509/*`), runs `deno doc` over the
 * public entrypoints, and hands the JSON to the shared renderer. The Deno-native
 * companion `render-deno-doc.deno.ts` produces identical output without the
 * subprocess or import map.
 *
 *     bun scripts/render-deno-doc.bun.ts [symbol...]
 *
 * No `symbol` args renders every exported symbol; otherwise only the named ones.
 * Output is piped through dprint so it needs no downstream formatting.
 *
 * @module
 */

import { $, argv, stdout } from 'bun';

import pkg from '#pkg' with { type: 'json' };

import { resolve } from 'node:path';
import type { ApiModule } from './render-deno-doc.shared.ts';
import { publicEntrypoints, renderDocuments } from './render-deno-doc.shared.ts';

const root = resolve(import.meta.dirname, '..');

await $`bun scripts/gen-deno-importmap.bun.ts`.cwd(root).quiet();
const raw =
	await $`deno doc --no-npm --import-map deno.import_map.json --json --name=${pkg.name} ${[...publicEntrypoints]}`
		.cwd(root)
		.text();

const parsed: { nodes: Record<string, ApiModule> } = JSON.parse(raw);
const md = renderDocuments(parsed.nodes, new Set(argv.slice(2)));
stdout.write(await $`dprint fmt --stdin md < ${new Blob([md])}`.text());
