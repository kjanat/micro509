import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { copyPublishedDocsTree, usePublishedDocsTree } from './site-build.mjs';

test('selects the published tree only for the unqualified master deploy', () => {
	assert.equal(usePublishedDocsTree({ WORKERS_CI_BRANCH: 'master' }), true);
	assert.equal(usePublishedDocsTree({ WORKERS_CI_BRANCH: 'master', DOCS_CHANNEL: 'next' }), false);
	assert.equal(usePublishedDocsTree({ WORKERS_CI_BRANCH: 'feature/docs' }), false);
	assert.equal(usePublishedDocsTree({}), false);
});

test('copies the published tree without its git metadata', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'site-build-test-'));
	try {
		const source = path.join(root, 'source');
		const destination = path.join(root, 'dist');
		await mkdir(path.join(source, '.git'), { recursive: true });
		await mkdir(path.join(source, 'next'), { recursive: true });
		await writeFile(path.join(source, '.git', 'config'), 'private git metadata');
		await writeFile(path.join(source, 'index.html'), 'published index');
		await writeFile(path.join(source, 'next', 'index.html'), 'published next');
		await mkdir(destination, { recursive: true });
		await writeFile(path.join(destination, 'stale.html'), 'stale');

		await copyPublishedDocsTree(source, destination);

		assert.equal(await readFile(path.join(destination, 'index.html'), 'utf8'), 'published index');
		assert.equal(
			await readFile(path.join(destination, 'next', 'index.html'), 'utf8'),
			'published next',
		);
		await assert.rejects(readFile(path.join(destination, '.git', 'config')));
		await assert.rejects(readFile(path.join(destination, 'stale.html')));
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
