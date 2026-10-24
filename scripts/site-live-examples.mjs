#!/usr/bin/env node
/**
 * Runs every SSR-rendered example from every built documentation version,
 * requiring non-empty output while simulating a content blocker.
 *
 * Run `site:build` first.
 *
 * @module
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { chromium } from 'playwright';
import { matchBlockedRequest } from './site-content-blocker.mjs';
import { findExamplePages } from './site-live-examples-helpers.mjs';

/** @typedef {{version: string, route: string}} Version */

/**
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

const DIST =
	process.env.SITE_DIST === undefined
		? path.resolve(import.meta.dirname, '..', 'site/.vitepress/dist')
		: path.resolve(process.env.SITE_DIST);
const HOST = '127.0.0.1';
const EXAMPLE_TIMEOUT_MS = 60_000;

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
 * Capture requests that violate browser expectations for every page mode.
 * Matching blocker requests are aborted so the actual example exercises that
 * condition; all requested URLs are checked before execution and on completion.
 *
 * @param {import('playwright').Page} page
 * @param {string} baseUrl
 */
async function installNetworkGuard(page, baseUrl) {
	/** @type {string[]} */
	const failures = [];
	/** @type {string[]} */
	const imported = [];
	page.on('request', (request) => {
		const url = request.url();
		const parsed = new URL(url);
		if (/^https?:$/.test(parsed.protocol) && parsed.origin !== baseUrl) imported.push(url);
		const documentUrl = requestDocumentUrl(request, page, baseUrl);
		const rule = matchBlockedRequest(url, documentUrl, request.resourceType());
		if (rule !== undefined) failures.push(`${url} (matches ${rule})`);
	});
	page.on('requestfailed', (request) => {
		failures.push(
			`${request.url()} (request failed: ${request.failure()?.errorText ?? 'unknown'})`,
		);
	});
	page.on('response', (response) => {
		if (response.status() >= 400) failures.push(`${response.url()} (HTTP ${response.status()})`);
	});
	await page.route('**/*', async (intercepted) => {
		const url = intercepted.request().url();
		const request = intercepted.request();
		const documentUrl = requestDocumentUrl(request, page, baseUrl);
		if (matchBlockedRequest(url, documentUrl, request.resourceType()) !== undefined) {
			await intercepted.abort('blockedbyclient');
		} else {
			await intercepted.continue();
		}
	});

	return { failures, imported };
}

/**
 * @param {import('playwright').Request} request
 * @param {import('playwright').Page} page
 * @param {string} fallback
 */
function requestDocumentUrl(request, page, fallback) {
	if (request.isNavigationRequest()) return request.url();
	try {
		return request.frame().url() || page.url() || fallback;
	} catch {
		return page.url() || fallback;
	}
}

/** @param {string[]} failures @param {number} errorCount @param {string} output */
function resultFailure(failures, errorCount, output) {
	if (failures.length > 0) return failures.join(', ');
	if (errorCount > 0) return 'the example errored';
	if (output === '') return 'the example printed nothing';
	return '';
}

/**
 * Run every LiveCode block on one page; a block that errors, prints nothing,
 * or never settles fails.
 *
 * @param {import('playwright').Browser} browser
 * @param {string} baseUrl
 * @param {{route: string, expectedBlocks: number}} pageInfo
 * @returns {Promise<Result[]>}
 */
async function runAllBlocks(browser, baseUrl, { route, expectedBlocks }) {
	const context = await browser.newContext({
		baseURL: baseUrl,
		serviceWorkers: 'block',
	});
	const page = await context.newPage();

	page.setDefaultTimeout(EXAMPLE_TIMEOUT_MS);
	page.setDefaultNavigationTimeout(EXAMPLE_TIMEOUT_MS);

	const { failures, imported } = await installNetworkGuard(page, baseUrl);
	/** @type {Result[]} */
	const results = [];

	try {
		await page.goto(route, { waitUntil: 'domcontentloaded' });
		await page.waitForFunction(() => {
			const app = document.querySelector('#app');
			return app !== null && '__vue_app__' in app;
		});

		const blocks = page.locator('.live-code');
		const count = await blocks.count();
		if (count === 0) {
			return [
				{
					version: route,
					source: '',
					output: '',
					failed: true,
					why: 'SSR page contains LiveCode markup but no hydrated examples appeared',
					ms: 0,
					imported,
				},
			];
		}
		if (count !== expectedBlocks) {
			return [
				{
					version: route,
					source: '',
					output: '',
					failed: true,
					why: `SSR rendered ${expectedBlocks} examples but the browser found ${count}; hydration did not preserve every block`,
					ms: 0,
					imported,
				},
			];
		}
		for (let index = 0; index < count; index += 1) {
			const buttons = await blocks.nth(index).locator('.live-code-btn').count();
			if (buttons !== 1) {
				return [
					{
						version: route,
						source: '',
						output: '',
						failed: true,
						why: `example ${index + 1} did not hydrate exactly one Run button`,
						ms: 0,
						imported,
					},
				];
			}
		}

		for (let index = 0; index < count; index += 1) {
			const label = `${route}#${index}`;
			const block = blocks.nth(index);
			const button = block.locator('.live-code-btn').first();
			const outputBlock = block.locator('.live-code-pre').first();

			let source = '';
			let output = '';
			let started;

			try {
				for (const details of await block.locator('xpath=ancestor::details').all()) {
					if ((await details.getAttribute('open')) === null) {
						await details.locator(':scope > summary').click();
					}
				}
				await block.scrollIntoViewIfNeeded();
				source = (await block.locator('pre code').first().innerText()).trim();

				started = performance.now();
				await button.click();
				await outputBlock.waitFor({ state: 'visible' });
				await page.waitForFunction(
					({ index: nth }) =>
						!document
							.querySelectorAll('.live-code')
							[nth]?.querySelector('.live-code-btn')
							?.textContent?.includes('Running'),
					{ index },
				);

				const ms = Math.round(performance.now() - started);
				output = (await outputBlock.innerText()).trim();

				const why = resultFailure(failures, await block.locator('.live-code-err').count(), output);

				results.push({ version: label, source, output, failed: why !== '', why, ms, imported });
			} catch (error) {
				results.push({
					version: label,
					source,
					output,
					failed: true,
					why: String(error).split('\n')[0] || 'threw',
					ms: started === undefined ? 0 : Math.round(performance.now() - started),
					imported,
				});
			}
		}

		await page.waitForLoadState('networkidle');
		if (failures.length > 0) {
			for (const result of results) {
				result.failed = true;
				result.why = failures.join(', ');
			}
		}

		return results;
	} finally {
		await context.close().catch((error) => {
			console.warn(`[live-examples] ${route}: failed to close context: ${error}`);
		});
	}
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
 * Switching to an immutable snapshot loads its own document and import map.
 * Exercise the real switcher and check that its example imports that release.
 *
 * @param {import('playwright').Browser} browser
 * @param {string} baseUrl
 * @param {Version} target
 * @returns {Promise<Result>}
 */
async function runAfterVersionSwitch(browser, baseUrl, { version, route }) {
	const label = `switch:${version}`;
	const context = await browser.newContext({
		baseURL: baseUrl,
		serviceWorkers: 'block',
	});
	const page = await context.newPage();

	page.setDefaultTimeout(EXAMPLE_TIMEOUT_MS);
	page.setDefaultNavigationTimeout(EXAMPLE_TIMEOUT_MS);

	const { failures, imported } = await installNetworkGuard(page, baseUrl);
	let source = '';
	let output = '';
	let started;

	try {
		await page.goto('/guide/getting-started', { waitUntil: 'networkidle' });
		await page.waitForFunction(() => {
			const app = document.querySelector('#app');
			return app !== null && '__vue_app__' in app;
		});

		await page.evaluate(() => {
			/** @type {Window & { __liveExamplesSpa?: boolean }} */ (window).__liveExamplesSpa = true;
		});
		await page.locator('.version-switcher').hover();
		await page.locator(`.vs-link[href="${route}"]`).click();
		await page.waitForURL(`**${route}`);
		await page.locator('.live-code').first().waitFor({ state: 'visible' });

		const survived = await page.evaluate(
			() =>
				/** @type {Window & { __liveExamplesSpa?: boolean }} */ (window).__liveExamplesSpa === true,
		);
		if (survived) {
			throw new Error('version switch did not load the snapshot document and its import map');
		}

		const block = page.locator('.live-code').first();
		const button = block.locator('.live-code-btn').first();
		const outputBlock = block.locator('.live-code-pre').first();

		await block.waitFor({ state: 'visible' });
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

		const marker = `@${version.slice(1)}`;
		const misdirected = imported.filter((url) => !url.includes(marker));

		let why = '';
		if (misdirected.length > 0)
			why = `after switching to ${route}, the example imported ${misdirected.join(', ')}`;
		else if (imported.length === 0) why = 'the example imported nothing external';
		else why = resultFailure(failures, await block.locator('.live-code-err').count(), output);

		return {
			version: label,
			source,
			output,
			failed: why !== '',
			why,
			ms,
			imported,
		};
	} catch (error) {
		return {
			version: label,
			source,
			output,
			failed: true,
			why: String(error).split('\n')[0] || 'threw',
			ms: started === undefined ? 0 : Math.round(performance.now() - started),
			imported,
		};
	} finally {
		await context.close().catch((error) => {
			console.warn(`[live-examples] ${label}: failed to close context: ${error}`);
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

/** Prove the browser route actually aborts and reports a matching module request.
 * @param {import('playwright').Browser} browser
 * @param {string} baseUrl
 */
async function verifyBlockerInterception(browser, baseUrl) {
	const context = await browser.newContext({ serviceWorkers: 'block' });
	try {
		const page = await context.newPage();
		const { failures } = await installNetworkGuard(page, baseUrl);
		await page.goto(baseUrl, { waitUntil: 'networkidle' });
		const blockedUrl = `${baseUrl}/fingerprint.js`;
		const failed = page.waitForEvent('requestfailed', {
			predicate: (request) => request.url() === blockedUrl,
			timeout: 10_000,
		});
		await assert.rejects(page.addScriptTag({ url: blockedUrl, type: 'module' }));
		const request = await failed;
		assert.match(request.failure()?.errorText ?? '', /ERR_BLOCKED_BY_CLIENT/);
		assert.ok(
			failures.some((failure) => failure.includes(`${blockedUrl} (matches /fingerprint.js^`)),
		);
		console.log('[live-examples] content-blocker interception verified');
	} finally {
		await context.close();
	}
}

/** Exercise generated symbol links and the serialized client-side search callback.
 * @param {import('playwright').Browser} browser
 * @param {string} baseUrl
 * @param {string} prefix
 */
async function verifyApiNavigation(browser, baseUrl, prefix) {
	const context = await browser.newContext({ baseURL: baseUrl });
	try {
		const page = await context.newPage();
		/** @type {string[]} */
		const errors = [];
		page.on('pageerror', (error) => errors.push(error.message));
		await page.goto(`${prefix}api/x509`, { waitUntil: 'networkidle' });
		await page.locator(`.vp-doc a[href="${prefix}api/type/SubjectAltName"]`).first().click();
		await page.waitForURL(`**${prefix}api/type/SubjectAltName`);
		await page.locator('.vp-doc h1').filter({ hasText: 'SubjectAltName' }).waitFor();
		await page.locator('.VPNavBarSearch button').click();
		await page.locator('.VPLocalSearchBox input').fill('createCertificate');
		const result = page.locator('.VPLocalSearchBox .result').first();
		await result.waitFor({ state: 'visible' });
		const href = await result.getAttribute('href');
		assert.ok(href?.startsWith(prefix), `search result escaped ${prefix}: ${href}`);
		assert.deepEqual(errors, []);
		console.log(`[live-examples] symbol navigation and search verified at ${prefix}`);
	} finally {
		await context.close();
	}
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
	const pages = findExamplePages(routes, (file) => readFileSync(file, 'utf8'));
	if (pages.length === 0)
		throw new Error('[live-examples] the built site contains no SSR LiveCode examples');
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

	/** @param {Result} result */
	function report(result) {
		results.push(result);

		const requests = result.imported.length;
		const hosts = hostsOf(result.imported) || '(none)';

		console.log(
			`  ${result.failed ? 'FAIL' : ' ok '} ${result.version.padEnd(10)} ` +
				`${String(result.ms).padStart(5)}ms  ` +
				`${requests} external request${requests === 1 ? '' : 's'} to ${hosts}`,
		);
	}

	try {
		await verifyBlockerInterception(browser, baseUrl);
		if (routes.has('/next/api/x509')) await verifyApiNavigation(browser, baseUrl, '/next/');
		else if (routes.has('/api/x509')) await verifyApiNavigation(browser, baseUrl, '/');
		for (const pageInfo of pages) {
			for (const result of await runAllBlocks(browser, baseUrl, pageInfo)) report(result);
		}

		const navigable = pages.find(
			({ version, route }) => /^v\d/.test(version) && route.endsWith('/guide/getting-started'),
		);
		if (navigable !== undefined && routes.has('/guide/getting-started')) {
			report(await runAfterVersionSwitch(browser, baseUrl, navigable));
		}

		const count = results.length;
		const label = count === 1 ? 'example run' : 'example runs';
		console.log(`\n[live-examples] ${count} ${label}:\n`);
	} finally {
		for (const [signal, handler] of signalHandlers) {
			process.off(signal, handler);
		}

		await teardown();
	}

	printSuccessfulOutputs(
		results.filter(
			({ version }) =>
				version.startsWith('switch:') || version.endsWith('/guide/getting-started#0'),
		),
		baseUrl,
	);

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
	const label = count === 1 ? 'example' : 'examples';
	console.log(`\n[live-examples] ${count} ${label} passed across all built pages`);
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : error);
	process.exitCode = 1;
});
