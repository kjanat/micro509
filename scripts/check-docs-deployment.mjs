import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** @param {unknown} catalog @returns {string[]} */
export function publishedBases(catalog) {
	if (
		typeof catalog !== 'object' ||
		catalog === null ||
		!('schemaVersion' in catalog) ||
		catalog.schemaVersion !== 3 ||
		!('versions' in catalog) ||
		!Array.isArray(catalog.versions)
	) {
		throw new Error('Production docs require a versioned publication catalog');
	}
	const bases = [];
	let latestTag;
	for (const entry of catalog.versions) {
		if (typeof entry !== 'object' || entry === null || typeof entry.base !== 'string')
			throw new Error('Invalid docs catalog entry');
		if (entry.channel === 'latest' && entry.base === '/' && /^v\d+\.\d+\.\d+$/.test(entry.tag))
			latestTag = entry.tag;
		if (!/^\/(?:next\/|v\d+\.\d+\.\d+\/)?$/.test(entry.base))
			throw new Error('Invalid docs catalog base');
		bases.push(entry.base);
	}
	if (latestTag === undefined || !bases.includes('/next/') || !bases.includes(`/${latestTag}/`)) {
		throw new Error('Production docs require latest, next, and the latest release archive');
	}
	return bases;
}

/** @param {string} directory */
export async function checkPublishedTree(directory) {
	const catalog = JSON.parse(await readFile(path.join(directory, 'versions.json'), 'utf8'));
	for (const base of publishedBases(catalog)) {
		await readFile(path.join(directory, base.slice(1), 'index.html'));
	}
	const publicationId = (await readFile(path.join(directory, 'publication-id.txt'), 'utf8')).trim();
	if (!/^\d+:\d+$/.test(publicationId)) throw new Error('Invalid docs publication identifier');
	return { catalog, publicationId };
}

/** @param {unknown} expected @param {string} baseUrl @param {string} publicationId */
export async function checkLiveDocs(expected, baseUrl, publicationId) {
	publishedBases(expected);
	const response = await fetch(new URL('versions.json', baseUrl), {
		cache: 'no-store',
		signal: AbortSignal.timeout(20_000),
	});
	if (!response.ok) throw new Error(`Live docs catalog returned ${response.status}`);
	const actual = await response.json();
	publishedBases(actual);
	if (JSON.stringify(actual) !== JSON.stringify(expected))
		throw new Error('Live docs catalog differs from the published tree');
	const publication = await fetch(new URL('publication-id.txt', baseUrl), {
		cache: 'no-store',
		signal: AbortSignal.timeout(20_000),
	});
	if (!publication.ok) throw new Error(`Live docs publication returned ${publication.status}`);
	if ((await publication.text()).trim() !== publicationId)
		throw new Error('Live docs publication differs from the published tree');
	for (const route of ['', 'next/', 'guide/getting-started', 'next/guide/getting-started']) {
		const page = await fetch(new URL(route, baseUrl), {
			cache: 'no-store',
			signal: AbortSignal.timeout(20_000),
		});
		if (!page.ok) throw new Error(`Live docs ${route || '/'} returned ${page.status}`);
		await page.body?.cancel();
	}
}

if (
	process.argv[1] !== undefined &&
	import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
	const directory = path.resolve(process.argv[2] ?? path.join(root, 'site/.vitepress/dist'));
	const { catalog, publicationId } = await checkPublishedTree(directory);
	if (process.argv.includes('--live')) {
		const deadline = Date.now() + 10 * 60_000;
		for (;;) {
			try {
				await checkLiveDocs(catalog, 'https://micro509.kjanat.dev/', publicationId);
				break;
			} catch (error) {
				if (Date.now() >= deadline) throw error;
				console.log(
					`Waiting for production docs: ${error instanceof Error ? error.message : String(error)}`,
				);
				await new Promise((resolve) => setTimeout(resolve, 15_000));
			}
		}
	}
	console.log('Production documentation checks passed');
}
