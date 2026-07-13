#!/usr/bin/env node
/**
 * Runs the getting-started example from every built documentation version,
 * requiring non-empty output while simulating a content blocker.
 *
 * Run `site:build` first.
 *
 * @module
 */
import { once } from 'node:events';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { chromium } from 'playwright';

/**
 * @typedef {{ version: string, route: string }} Version
 *
 * @typedef {{
 *   version: string,
 *   source: string,
 *   output: string,
 *   failed: boolean,
 *   why: string,
 *   ms: number,
 *   imported: string[]
 * }} Result
 */

const DIST = path.resolve(import.meta.dirname, '..', 'site/.vitepress/dist');
const HOST = '127.0.0.1';
const EXAMPLE_TIMEOUT_MS = 60_000;

/** EasyPrivacy path rules. */
const BLOCKER_RULES = [
	'/fingerprint.js',
	'/fingerprint.min.js',
	'/fingerprint2.js',
	'/analytics.js',
	'/tracking.js',
	'/telemetry.js',
];

/** @type {Record<string, string>} */
const MIME_TYPES = {
	'.css': 'text/css; charset=utf-8',
	'.html': 'text/html; charset=utf-8',
	'.ico': 'image/x-icon',
	'.jpeg': 'image/jpeg',
	'.jpg': 'image/jpeg',
	'.js': 'text/javascript; charset=utf-8',
	'.json': 'application/json; charset=utf-8',
	'.map': 'application/json; charset=utf-8',
	'.mjs': 'text/javascript; charset=utf-8',
	'.png': 'image/png',
	'.svg': 'image/svg+xml',
	'.txt': 'text/plain; charset=utf-8',
	'.wasm': 'application/wasm',
	'.webmanifest': 'application/manifest+json',
	'.webp': 'image/webp',
	'.woff2': 'font/woff2',
};

/**
 * @returns {Map<string, string>}
 */
function buildRoutes() {
	/** @type {Map<string, string>} */
	const files = new Map();

	/** @param {string} directory */
	function walk(directory) {
		for (const entry of readdirSync(directory, { withFileTypes: true })) {
			const file = path.join(directory, entry.name);

			if (entry.isDirectory()) {
				walk(file);
				continue;
			}

			const relative = path.relative(DIST, file).split(path.sep).join('/');
			files.set(`/${relative}`, file);
		}
	}

	walk(DIST);

	const routes = new Map(files);

	for (const [route, file] of files) {
		if (route.endsWith('/index.html')) {
			routes.set(route.slice(0, -'index.html'.length), file);
			routes.set(route.slice(0, -'/index.html'.length) || '/', file);
		}

		if (route.endsWith('.html')) {
			const extensionless = route.slice(0, -'.html'.length);
			if (!routes.has(extensionless)) routes.set(extensionless, file);
		}
	}

	return routes;
}

/**
 * @param {Map<string, string>} routes
 * @returns {Version[]}
 */
function findVersions(routes) {
	const archived = readdirSync(DIST, { withFileTypes: true })
		.filter((entry) => entry.isDirectory() && /^v\d+\.\d+\.\d+$/.test(entry.name))
		.map((entry) => entry.name)
		.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));

	return [
		{ version: '(latest)', route: '/guide/getting-started' },
		{ version: 'next', route: '/next/guide/getting-started' },
		...archived.map((version) => ({
			version,
			route: `/${version}/guide/getting-started`,
		})),
	].filter(({ route }) => routes.has(route));
}

/**
 * @param {string} text
 * @param {number} [head]
 * @param {number} [tail]
 */
function elide(text, head = 3, tail = 2) {
	const lines = text.split('\n');

	const visible =
		lines.length <= head + tail + 1
			? lines
			: [...lines.slice(0, head), `… ${lines.length - head - tail} more`, ...lines.slice(-tail)];

	return visible.map((line) => `    ${line}`).join('\n');
}

/**
 * @param {string[]} urls
 */
function hostsOf(urls) {
	return [...new Set(urls.map((url) => new URL(url).host))].join(', ');
}

/**
 * crypto.subtle requires a secure context; loopback addresses qualify.
 *
 * @param {Map<string, string>} routes
 */
async function startServer(routes) {
	const server = createServer((request, response) => {
		let route;

		try {
			route = decodeURIComponent(new URL(request.url ?? '/', `http://${HOST}`).pathname);
		} catch {
			response.writeHead(400).end('bad request');
			return;
		}

		const file = routes.get(route);

		if (file === undefined) {
			response.writeHead(404).end('not found');
			return;
		}

		response.writeHead(200, {
			'content-type': MIME_TYPES[path.extname(file)] ?? 'application/octet-stream',
		});
		response.end(readFileSync(file));
	});

	server.listen(0, HOST);
	await once(server, 'listening');

	const address = server.address();

	if (address === null || typeof address === 'string') {
		throw new Error('[live-examples] server started without a TCP port');
	}

	return {
		server,
		baseUrl: `http://${HOST}:${address.port}`,
	};
}

/**
 * @param {import('node:http').Server} server
 */
async function closeServer(server) {
	if (!server.listening) return;

	await new Promise((resolve, reject) => {
		server.close((error) => {
			if (error) reject(error);
			else resolve(undefined);
		});
	});
}

/**
 * @param {import('playwright').Browser} browser
 * @param {string} baseUrl
 * @param {Version} target
 * @returns {Promise<Result>}
 */
async function runVersion(browser, baseUrl, { version, route }) {
	const context = await browser.newContext({
		baseURL: baseUrl,
		serviceWorkers: 'block',
	});
	const page = await context.newPage();

	page.setDefaultTimeout(EXAMPLE_TIMEOUT_MS);
	page.setDefaultNavigationTimeout(EXAMPLE_TIMEOUT_MS);

	/** @type {string[]} */
	const refused = [];
	/** @type {string[]} */
	const imported = [];

	let source = '';
	let output = '';
	let started;

	page.on('request', (request) => {
		const url = request.url();
		const parsed = new URL(url);

		if (/^https?:$/.test(parsed.protocol) && parsed.origin !== baseUrl) {
			imported.push(url);
		}
	});

	await page.route('**/*', async (intercepted) => {
		const url = intercepted.request().url();
		const rule = BLOCKER_RULES.find((candidate) => url.includes(candidate));

		if (rule === undefined) {
			await intercepted.continue();
			return;
		}

		refused.push(`${url} (matches ${rule})`);
		await intercepted.abort('blockedbyclient');
	});

	try {
		await page.goto(route, { waitUntil: 'domcontentloaded' });

		const block = page.locator('.live-code').first();
		const button = block.locator('.live-code-btn').first();
		const outputBlock = block.locator('.live-code-pre').first();

		source = (await block.locator('pre code').first().innerText()).trim();

		started = performance.now();
		await button.click();
		await outputBlock.waitFor({ state: 'visible' });
		await page.waitForFunction(
			(selector) => !document.querySelector(selector)?.textContent?.includes('Running'),
			'.live-code .live-code-btn',
		);

		const ms = Math.round(performance.now() - started);
		output = (await outputBlock.innerText()).trim();

		let why = '';

		if (refused.length > 0) {
			why = `a content blocker would refuse ${refused.join(', ')}`;
		} else if ((await block.locator('.live-code-err').count()) > 0) {
			why = 'the example errored';
		} else if (output === '') {
			why = 'the example printed nothing';
		}

		return {
			version,
			source,
			output,
			failed: why !== '',
			why,
			ms,
			imported,
		};
	} catch (error) {
		return {
			version,
			source,
			output,
			failed: true,
			why: String(error).split('\n')[0] || 'threw',
			ms: started === undefined ? 0 : Math.round(performance.now() - started),
			imported,
		};
	} finally {
		await context.close().catch((error) => {
			console.warn(`[live-examples] ${version}: failed to close context: ${error}`);
		});
	}
}

/**
 * @param {import('playwright').Browser} browser
 * @param {import('node:http').Server} server
 */
function createTeardown(browser, server) {
	/** @type {Promise<void> | undefined} */
	let pending;

	return () =>
		(pending ??= (async () => {
			await browser.close().catch((error) => {
				console.warn(`[live-examples] failed to close browser: ${error}`);
			});

			await closeServer(server).catch((error) => {
				console.warn(`[live-examples] failed to close server: ${error}`);
			});
		})());
}

/**
 * @param {Result[]} results
 * @param {string} baseUrl
 */
function printSuccessfulOutputs(results, baseUrl) {
	/** @type {Map<string, Result[]>} */
	const bySource = new Map();

	for (const result of results) {
		if (result.failed) continue;

		const group = bySource.get(result.source) ?? [];
		group.push(result);
		bySource.set(result.source, group);
	}

	for (const [source, group] of bySource) {
		console.log(`\n${'─'.repeat(78)}`);
		console.log(`\nthe example published by ${group.map(({ version }) => version).join(', ')}:\n`);
		console.log(source.replace(/^/gm, '    '));
		console.log(`\n  what each version printed in the browser:\n`);

		for (const result of group) {
			const hosts = hostsOf(result.imported) || new URL(baseUrl).host;

			console.log(`  ${result.version} — ${hosts}, ${result.ms} ms`);
			console.log(elide(result.output));
			console.log('');
		}
	}

	console.log('─'.repeat(78));
}

async function main() {
	if (!existsSync(DIST)) {
		throw new Error(`[live-examples] no built site at ${DIST} — run \`run site:build\` first`);
	}

	const routes = buildRoutes();
	const versions = findVersions(routes);
	const { server, baseUrl } = await startServer(routes);

	let browser;

	try {
		browser = await chromium.launch();
	} catch (error) {
		await closeServer(server);
		throw error;
	}

	const teardown = createTeardown(browser, server);
	const signalHandlers = new Map();

	/** @type {Array<[NodeJS.Signals, number]>} */
	const signals = [
		['SIGINT', 130],
		['SIGTERM', 143],
	];

	for (const [signal, exitCode] of signals) {
		const handler = () => {
			console.log(`\n[live-examples] ${signal} — shutting down`);
			void teardown().finally(() => process.exit(exitCode));
		};

		signalHandlers.set(signal, handler);
		process.once(signal, handler);
	}

	/** @type {Result[]} */
	const results = [];

	try {
		for (const version of versions) {
			const result = await runVersion(browser, baseUrl, version);
			results.push(result);

			const requests = result.imported.length;
			const hosts = hostsOf(result.imported) || '(none)';

			console.log(
				`  ${result.failed ? 'FAIL' : ' ok '} ${result.version.padEnd(10)} ` +
					`${String(result.ms).padStart(5)}ms  ` +
					`${requests} external request${requests === 1 ? '' : 's'} to ${hosts}`,
			);
		}

		const count = versions.length;
		const label = count === 1 ? 'version' : 'versions';
		console.log(`\n[live-examples] ${count} ${label}:\n`);
	} finally {
		for (const [signal, handler] of signalHandlers) {
			process.off(signal, handler);
		}

		await teardown();
	}

	printSuccessfulOutputs(results, baseUrl);

	const failures = results.filter(({ failed }) => failed);

	if (failures.length > 0) {
		console.error(`\n[live-examples] ${failures.length} of ${results.length} failed:`);

		for (const result of failures) {
			console.error(`\n  ${result.version} — ${result.why}`);
			console.error((result.output || '(no output)').replace(/^/gm, '    '));
		}

		process.exitCode = 1;
		return;
	}

	const count = results.length;
	const label = count === 1 ? 'version' : 'versions';
	const pronoun = count === 1 ? 'its' : 'their';
	console.log(`\n[live-examples] ${count} ${label} each ran ${pronoun} own example`);
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : error);
	process.exitCode = 1;
});
