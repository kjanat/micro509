import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { checkLiveDocs, checkPublishedTree, publishedBases } from './check-docs-deployment.mjs';

const catalog = {
	schemaVersion: 3,
	versions: [
		{ channel: 'latest', tag: 'v0.15.0', base: '/' },
		{ channel: 'next', tag: 'v0.15.0-dev', base: '/next/' },
		{ channel: 'archive', tag: 'v0.15.0', base: '/v0.15.0/' },
	],
};
const preview = {
	schemaVersion: 3,
	versions: [{ channel: 'latest', tag: 'v0.15.0-dev', base: '/' }],
};

test('refuses preview catalogs and missing archive files before deployment', async () => {
	assert.throws(() => publishedBases(preview), /require latest/);
	assert.throws(() => publishedBases({}), /versioned publication/);
	assert.throws(
		() => publishedBases({ ...catalog, versions: [...catalog.versions, { base: '/../escape/' }] }),
		/Invalid/,
	);
	const directory = await mkdtemp(path.join(os.tmpdir(), 'docs-deploy-test-'));
	try {
		await writeFile(path.join(directory, 'versions.json'), JSON.stringify(catalog));
		for (const base of ['/', '/next/']) {
			await mkdir(path.join(directory, base), { recursive: true });
			await writeFile(path.join(directory, base, 'index.html'), 'page');
		}
		await assert.rejects(checkPublishedTree(directory), /ENOENT/);
		await mkdir(path.join(directory, 'v0.15.0'));
		await writeFile(path.join(directory, 'v0.15.0/index.html'), 'archive');
		await assert.rejects(checkPublishedTree(directory), /ENOENT/);
		await writeFile(path.join(directory, 'publication-id.txt'), '\n');
		await assert.rejects(checkPublishedTree(directory), /Invalid docs publication/);
		await writeFile(path.join(directory, 'publication-id.txt'), '101:1\n');
		assert.deepEqual(await checkPublishedTree(directory), { catalog, publicationId: '101:1' });
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('live check catches preview deployment, stale catalogs, and missing next pages', async () => {
	let mode = 'preview';
	const server = createServer((req, res) => {
		if (req.url === '/versions.json') {
			res.setHeader('content-type', 'application/json');
			res.end(
				new Map([
					['preview', JSON.stringify(preview)],
					['stale', JSON.stringify({ ...catalog, stale: true })],
				]).get(mode) ?? JSON.stringify(catalog),
			);
		} else if (req.url === '/publication-id.txt') {
			res.statusCode = mode === 'missing-publication' ? 404 : 200;
			res.end(
				new Map([
					['old-publication', '100:1\n'],
					['old-attempt', '101:1\n'],
				]).get(mode) ?? '101:2\n',
			);
		} else {
			res.statusCode = mode === 'missing' && req.url === '/next/guide/getting-started' ? 404 : 200;
			res.end('page');
		}
	});
	await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
	try {
		const address = server.address();
		if (address === null || typeof address === 'string') throw new Error('No server port');
		const url = `http://127.0.0.1:${address.port}/`;
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /require latest/);
		mode = 'stale';
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /differs/);
		mode = 'missing';
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /404/);
		mode = 'ready';
		await checkLiveDocs(catalog, url, '101:2');
		mode = 'old-publication';
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /publication differs/);
		mode = 'old-attempt';
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /publication differs/);
		mode = 'missing-publication';
		await assert.rejects(checkLiveDocs(catalog, url, '101:2'), /publication returned 404/);
	} finally {
		await new Promise((resolve) => server.close(resolve));
	}
});
