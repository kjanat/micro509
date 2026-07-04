// Browser smoke test: serves the built dist output to a headless Chromium
// via Playwright and runs the shared smoke assertions against real browser
// WebCrypto (`node scripts/smoke-browser.mjs`, needs `bun run build` first).

import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const root = new URL('..', import.meta.url);

const pageHtml = `\
<!DOCTYPE html>
  <script type="module">
  	import * as m from '/dist/index.js';
  	import { runSmoke } from '/scripts/smoke-core.mjs';
  	try {
  		globalThis.__smoke = await runSmoke(m);
  	} catch (err) {
  		globalThis.__smoke = 'FAIL: ' + err;
  	}
  </script>
`;

const server = createServer((request, response) => {
	if (request.url === '/') {
		response.setHeader('content-type', 'text/html');
		response.end(pageHtml);
		return;
	}
	const target = new URL(`.${request.url}`, root);
	if (!target.pathname.startsWith(root.pathname)) {
		response.statusCode = 403;
		response.end();
		return;
	}
	readFile(target)
		.then((body) => {
			response.setHeader('content-type', 'text/javascript');
			response.end(body);
		})
		.catch(() => {
			response.statusCode = 404;
			response.end();
		});
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
const address = server.address();
if (address === null || typeof address === 'string') {
	throw new Error('browser smoke: no server port');
}

const browser = await chromium.launch();
try {
	const page = await browser.newPage();
	await page.goto(`http://127.0.0.1:${address.port}/`);
	const handle = await page.waitForFunction(() => Reflect.get(globalThis, '__smoke'), undefined, {
		timeout: 30_000,
	});
	const result = await handle.jsonValue();
	if (result !== 'smoke OK') {
		throw new Error(`browser smoke: ${result}`);
	}
	console.log(`${result} (chromium ${browser.version()})`);
} finally {
	await browser.close();
	server.close();
}
