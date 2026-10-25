#!/usr/bin/env node
/**
 * Browser smoke test: serves the built dist output to a headless Chromium via Playwright and runs
 * the shared smoke assertions against real browser WebCrypto (`node scripts/smoke-browser.mjs`,
 * needs `bun run build` first). @module
 */
// deno-lint-ignore-file
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const root = new URL('.', import.meta.resolve('#pkg'));

const pageHtml = `\
<!DOCTYPE html>
  <script type="module">
    import * as m from '/dist/index.js';
    import * as cryptoApi from '/dist/crypto.js';
    import * as kdfApi from '/dist/kdf.js';
    import * as sshApi from '/dist/ssh.js';
    import * as joseApi from '/dist/jose.js';
    import { runSmoke } from '/scripts/smoke-core.mjs';
    import { runJwksRotationSmoke } from '/scripts/smoke-jwks-browser.mjs';
    try {
      const result = await runSmoke(m, cryptoApi, kdfApi, sshApi, joseApi);
      await runJwksRotationSmoke(joseApi, globalThis.__publishJwks);
      globalThis.__smoke = result;
    } catch (err) {
      globalThis.__smoke = 'FAIL: ' + err;
    }
  </script>
`;

let jwksBody = JSON.stringify({ keys: [] });
let jwksRequests = 0;
const server = createServer((request, response) => {
	if (request.url === '/rotation-jwks.json') {
		jwksRequests += 1;
		response.setHeader('content-type', 'application/json');
		response.setHeader('cache-control', 'public, max-age=3600');
		response.end(jwksBody);
		return;
	}
	if (request.url === '/') {
		response.setHeader('content-type', 'text/html');
		response.end(pageHtml);
		return;
	}
	const target = new URL(`${request.url}`.replace(/^\//, ''), root);
	if (!target.pathname.startsWith(root.pathname)) {
		response.statusCode = 403;
		response.end();
		return;
	}
	readFile(target.pathname)
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
	await page.exposeFunction(
		'__publishJwks',
		/** @param {{ keys: JsonWebKey[] }} jwks */ (jwks) => {
			jwksBody = JSON.stringify(jwks);
		},
	);
	await page.goto(`http://127.0.0.1:${address.port}/`);
	const handle = await page.waitForFunction(() => Reflect.get(globalThis, '__smoke'), undefined, {
		timeout: 30_000,
	});
	const result = await handle.jsonValue();
	if (result !== 'smoke OK') {
		throw new Error(`browser smoke: ${result}`);
	}
	if (jwksRequests !== 2) {
		throw new Error(`browser JWKS rotation: expected two endpoint requests, got ${jwksRequests}`);
	}
	console.log(`${result} (chromium ${browser.version()}, JWKS rotation: ${jwksRequests} requests)`);
} finally {
	await browser.close();
	server.close();
}
