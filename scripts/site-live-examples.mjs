#!/usr/bin/env node
/**
 * The docs site's examples run in the reader's browser, against a library it imports
 * from a CDN. `site-import-maps.deno.ts` proves those URLs resolve and that the code
 * runs; it cannot prove the page does — the LiveCode component, the blob module it
 * builds, the secure context WebCrypto needs, or the reader's content blocker.
 *
 * Against the built site (`run site:build` first): for every version the site serves,
 * click Run on its getting-started example and require a certificate out of it. Each
 * version's page carries the example written against the API that release shipped, and
 * imports the library that release published — so this runs fifteen different libraries
 * against the fifteen examples written for them.
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
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

/**
 * Every file the build produced, under each route that serves it: its own path, that path
 * without the `.html`, and — for an index — the directory it indexes. A request picks an
 * entry out of this map; it never names a path of its own, so the only files the server
 * can read are the ones the build wrote.
 *
 * @returns {Map<string, string>}
 */
function routes() {
	/** @type {Map<string, string>} */
	const files = new Map();

	/** @param {string} dir */
	const walk = (dir) => {
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const file = path.join(dir, entry.name);
			if (entry.isDirectory()) walk(file);
			else files.set(`/${path.relative(DIST, file).split(path.sep).join('/')}`, file);
		}
	};
	walk(DIST);

	const served = new Map(files);
	for (const [route, file] of files) {
		if (!route.endsWith('/index.html')) continue;
		served.set(route.slice(0, -'index.html'.length), file);
		served.set(route.slice(0, -'/index.html'.length) || '/', file);
	}
	for (const [route, file] of files) {
		if (!route.endsWith('.html')) continue;
		const bare = route.slice(0, -'.html'.length);
		if (!served.has(bare)) served.set(bare, file);
	}
	return served;
}

const SERVED = routes();

/**
 * Every version the site serves, in the order the switcher lists them: the root release,
 * the tree, then the archives newest first.
 *
 * @returns {Array<{ version: string, route: string }>}
 */
function versions() {
	const archives = readdirSync(DIST, { withFileTypes: true })
		.filter((entry) => entry.isDirectory() && /^v\d+\.\d+\.\d+$/.test(entry.name))
		.map((entry) => entry.name)
		.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));

	return [
		{ version: '(latest)', route: '/guide/getting-started' },
		{ version: 'next', route: '/next/guide/getting-started' },
		...archives.map((version) => ({ version, route: `/${version}/guide/getting-started` })),
	].filter(({ route }) => SERVED.has(route));
}

/**
 * Long output, shown as its head and its tail — a certificate is mostly base64.
 *
 * @param {string} text
 * @param {number} head
 * @param {number} tail
 * @returns {string}
 */
function elide(text, head, tail) {
	const lines = text.split('\n');
	const kept =
		lines.length <= head + tail + 1
			? lines
			: [...lines.slice(0, head), `… ${lines.length - head - tail} more`, ...lines.slice(-tail)];
	return kept.map((line) => `    ${line}`).join('\n');
}

/** 127.0.0.1 is a secure context, so the page gets crypto.subtle. file:// does not. */
const server = createServer((request, response) => {
	const url = `${request.url ?? '/'}`.split('?')[0] ?? '/';
	const file = SERVED.get(decodeURIComponent(url));
	if (file === undefined) {
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

/** Close everything, whatever happened. An open server handle keeps node alive forever. */
let closed = false;
async function teardown() {
	if (closed) return;
	closed = true;
	await browser.close().catch(() => {});
	server.close();
}
for (const signal of ['SIGINT', 'SIGTERM']) {
	process.once(signal, () => {
		console.log(`\n[live-examples] ${signal} — closing browser`);
		teardown().then(() => process.exit(130));
	});
}

/**
 * @typedef {{ version: string, source: string, output: string, failed: boolean,
 *             why: string, ms: number, imported: string[] }} Result
 */

/**
 * Click Run on one version's getting-started example, and keep what it printed.
 *
 * @param {string} version
 * @param {string} route
 * @returns {Promise<Result>}
 */
async function runVersion(version, route) {
	const page = await browser.newPage();

	/** @type {string[]} */
	const refused = [];
	/** @type {string[]} */
	const imported = [];

	page.on('request', (request) => {
		const url = request.url();
		if (!url.startsWith(base) && /^https?:/.test(url)) imported.push(url);
	});

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

	try {
		await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });

		const block = page.locator('.live-code').first();
		const source = (await block.locator('pre code').first().innerText()).trim();

		const started = Date.now();
		await page.locator('.live-code-btn').first().click();
		await block.locator('.live-code-pre').first().waitFor({ state: 'visible', timeout: 60_000 });
		await page.waitForFunction(
			() => !document.querySelector('.live-code-btn')?.textContent?.includes('Running'),
			{ timeout: 60_000 },
		);
		const ms = Date.now() - started;

		const output = (await block.locator('.live-code-pre').first().innerText()).trim();
		const errored = (await block.locator('.live-code-err').count()) > 0;

		const why =
			refused.length > 0
				? `a content blocker would refuse ${refused.join(', ')}`
				: errored
					? 'the example errored'
					: output === ''
						? 'the example printed nothing'
						: '';

		return { version, source, output, failed: why !== '', why, ms, imported };
	} catch (error) {
		return {
			version,
			source: '',
			output: '',
			failed: true,
			why: String(error).split('\n')[0] ?? 'threw',
			ms: 0,
			imported,
		};
	} finally {
		await page.close().catch(() => {});
	}
}

/** @type {Result[]} */
const results = [];

try {
	const all = versions();
	console.log(`[live-examples] ${all.length} versions, one example each\n`);

	for (const { version, route } of all) {
		const result = await runVersion(version, route);
		results.push(result);
		console.log(
			`  ${result.failed ? 'FAIL' : ' ok '} ${version.padEnd(10)} ${String(result.ms).padStart(5)}ms  ` +
				`${result.imported.length} request${result.imported.length === 1 ? ' ' : 's'} to ` +
				`${[...new Set(result.imported.map((url) => new URL(url).host))].join(', ') || '(none)'}`,
		);
	}
} finally {
	await teardown();
}

// The example is the same source across versions that share it, so print each once.
/** @type {Map<string, string[]>} */
const bySource = new Map();
for (const result of results.filter((candidate) => !candidate.failed)) {
	bySource.set(result.source, [...(bySource.get(result.source) ?? []), result.version]);
}

for (const [source, sharing] of bySource) {
	console.log(`\n${'─'.repeat(78)}`);
	console.log(
		`the example, as ${sharing.join(', ')} publish${sharing.length === 1 ? 'es' : ''} it:\n`,
	);
	console.log(source.replace(/^/gm, '    '));
	console.log(`\n  what each of them printed, in the browser:\n`);
	for (const version of sharing) {
		const result = results.find((candidate) => candidate.version === version);
		if (result === undefined) continue;
		console.log(`  ${version} — from ${new URL(result.imported[0] ?? base).host}, ${result.ms} ms`);
		console.log(elide(result.output, 3, 2));
		console.log('');
	}
}
console.log('─'.repeat(78));

const failures = results.filter((result) => result.failed);
if (failures.length > 0) {
	console.error(`\n[live-examples] ${failures.length} of ${results.length} failed:`);
	for (const result of failures) {
		console.error(`\n  ${result.version} — ${result.why}`);
		console.error((result.output || '(no output)').replace(/^/gm, '    '));
	}
	process.exit(1);
}

console.log(`\n[live-examples] ${results.length} versions each ran their own example`);
