#!/usr/bin/env node
/**
 * Runtime smoke test against the built dist output.
 *
 * Runs under Node:
 * ```sh
 * node scripts/smoke.mjs # smoke OK (v26.5.0)
 * ```
 *
 * and Deno:
 * ```sh
 * deno run --allow-read scripts/smoke.mjs # smoke OK (2.9.1)
 * ```
 *
 * and Bun:
 * ```sh
 * bun --bun scripts/smoke.mjs # smoke OK (1.3.14)
 * ```
 *
 * to back the multi-runtime support claim with executable evidence.
 * @module
 */

import pkg from '#pkg' with { type: 'json' };
import { runSmoke } from '#smoke';

const resolvedDefaultRootExport = new URL(
	pkg['exports']['.']['default'],
	import.meta.resolve('#pkg'),
);
/** @type {typeof import('#micro509')} */
const micro509 = await import(resolvedDefaultRootExport.href);

const whichVersion =
	typeof Deno !== 'undefined'
		? Deno.version.deno
		: typeof Bun !== 'undefined'
			? Bun.version
			: process.version;

console.log(`${await runSmoke(micro509)} (${whichVersion})`);
