#!/usr/bin/env node
/**
 * The docs site's examples run in the reader's browser, against a library it imports
 * from a CDN. `site-import-maps.deno.ts` proves those URLs resolve and that the code
 * runs; it cannot prove the page does — the LiveCode component, the blob module it
 * builds, the secure context WebCrypto needs, or the reader's content blocker.
 *
 * Against the built site (`run site:build` first), for one page per channel: click Run,
 * and require a certificate to come out.
 *
 * A content blocker is simulated, because a headless browser has none — and without one
 * this test would have passed happily while the bug that motivated it was live. The site
 * used to serve the library from its own origin, where `x509/fingerprint.js` matched an
 * EasyPrivacy rule blocking that path on every domain but github.com. That file is a
 * static import of the root entry, so one refused request killed every example on the
 * site, for every reader running uBlock — while the server returned 200 throughout.
 *
 * So: abort what a blocker aborts, and require the examples to run anyway. This guards
 * the class, not the filename — any module whose URL a filter list happens to match.
 *
 * @module
 */
// deno-lint-ignore-file
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { chromium } from 'playwright';

const DIST = path.resolve('site/.vitepress/dist');

/**
 * Generic path rules from EasyPrivacy — the ones that apply to every domain, not to a
 * named tracker. A URL containing any of these is one a large share of readers' browsers
 * will refuse. The first is the rule this site actually tripped.
 */
const BLOCKER_RULES = [
	'/fingerprint.js',
	'/fingerprint.min.js',
	'/fingerprint2.js',
	'/analytics.js',
	'/tracking.js',
	'/telemetry.js',
];

/**
 * One page per channel: each carries the examples written for the version it documents.
 *
 * @type {ReadonlyArray<{ readonly label: string, readonly route: string }>}
 */
const PAGES = [
	{ label: '/ (latest release)', route: '/guide/getting-started' },
	{ label: '/next/ (the tree)', route: '/next/guide/getting-started' },
	{ label: '/v0.8.0/ (archive)', route: '/v0.8.0/guide/getting-started' },
	{ label: '/v0.1.0/ (oldest)', route: '/v0.1.0/guide/getting-started' },
];

/** @type {Readonly<Record<string, string>>} */
const TYPES = {
	'.html': 'text/html',
	'.js': 'text/javascript',
	'.css': 'text/css',
	'.svg': 'image/svg+xml',
	'.json': 'application/json',
	'.ico': 'image/x-icon',
	'.woff2': 'font/woff2',
};

if (!existsSync(DIST)) {
	console.error(`[live-examples] no built site at ${DIST} — run \`run site:build\` first`);
	process.exit(1);
}

/** 127.0.0.1 is a secure context, so the page gets crypto.subtle. file:// does not. */
const server = createServer((request, response) => {
	const url = `${request.url ?? '/'}`.split('?')[0] ?? '/';
	let file = path.join(DIST, decodeURIComponent(url));
	if (!file.startsWith(DIST)) {
		response.writeHead(403).end();
		return;
	}
	if (existsSync(file) && statSync(file).isDirectory()) file = path.join(file, 'index.html');
	if (!existsSync(file) && existsSync(`${file}.html`)) file = `${file}.html`;
	if (!existsSync(file)) {
		response.writeHead(404).end('not found');
		return;
	}
	response.writeHead(200, {
		'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream',
	});
	response.end(readFileSync(file));
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
const address = server.address();
if (address === null || typeof address === 'string') {
	throw new Error('[live-examples] no server port');
}
const base = `http://127.0.0.1:${address.port}`;

const browser = await chromium.launch();
/** @type {string[]} */
const failures = [];

for (const { label, route } of PAGES) {
	const context = await browser.newContext();
	const page = await context.newPage();

	/** @type {string[]} */
	const refused = [];
	/** @type {string[]} */
	const problems = [];

	// The reader's content blocker, which a headless browser does not have.
	await page.route('**/*', (route_) => {
		const url = route_.request().url();
		const rule = BLOCKER_RULES.find((pattern) => url.includes(pattern));
		if (rule === undefined) {
			route_.continue();
			return;
		}
		refused.push(`${url} (matches ${rule})`);
		route_.abort('blockedbyclient');
	});

	page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));

	try {
		await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
		await page.locator('.live-code-btn').first().click();
		await page.locator('.live-code-pre').first().waitFor({ state: 'visible', timeout: 90_000 });
		await page.waitForFunction(
			() => !document.querySelector('.live-code-btn')?.textContent?.includes('Running'),
			{ timeout: 90_000 },
		);

		const output = (await page.locator('.live-code-pre').first().innerText()).trim();
		const errored = (await page.locator('.live-code-err').count()) > 0;

		if (errored || output === '') {
			failures.push(`${label}: example failed — ${output.split('\n')[0] || '(no output)'}`);
		} else if (refused.length > 0) {
			// The example ran, but a blocker refused something: the next one may not.
			failures.push(`${label}: a content blocker would refuse ${refused.join(', ')}`);
		} else {
			console.log(`[live-examples] ${label.padEnd(22)} ran, nothing a blocker would refuse`);
		}
		if (problems.length > 0) failures.push(`${label}: ${problems.join('; ')}`);
	} catch (error) {
		failures.push(`${label}: ${String(error).split('\n')[0]}`);
	}

	await context.close();
}

await browser.close();
server.close();

if (failures.length > 0) {
	console.error(`\n[live-examples] ${failures.length} failed:\n  ${failures.join('\n  ')}`);
	process.exit(1);
}
console.log(`\n[live-examples] ${PAGES.length} channels run a real example in a browser`);
