// Cloudflare Workers smoke test: runs scripts/smoke-worker.mjs in a local
// workerd via wrangler's test harness (`node scripts/smoke-workerd.mjs`).

import { createTestHarness } from 'wrangler';

const server = createTestHarness({
	workers: [{ configPath: new URL('./wrangler.smoke.toml', import.meta.url) }],
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
