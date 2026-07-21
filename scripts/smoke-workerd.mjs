#!/usr/bin/env node
/**
 * Cloudflare Workers smoke test: runs scripts/smoke-worker.mjs in a local workerd via wrangler's test harness.
 * ```sh
 * node scripts/smoke-workerd.mjs
 * ```
 */
import { createTestHarness } from 'wrangler';

const server = createTestHarness({
	workers: [
		{
			config: {
				name: 'micro509-smoke',
				main: `${import.meta.dirname}/smoke-worker.mjs`,
				compatibility_date: '2026-06-29',
			},
		},
	],
});

try {
	await server.listen();
	const response = await server.fetch('/');
	const body = await response.text();
	if (response.status !== 200) {
		throw new Error(`workerd smoke failed (${response.status}): ${body}`);
	}
	console.log(`${body} (workerd)`);
} finally {
	await server.close();
}
