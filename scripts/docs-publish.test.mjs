import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assembleDocs } from './docs-publish.mjs';

/** @typedef {'next' | 'archive' | 'latest'} Channel */
/** @typedef {{label: string, tag: string, channel: Channel, base: string, releasedAt: string | null, releaseUrl: string | null, sections?: Record<string, unknown>}} Entry */

/** @param {unknown} value @returns {value is Entry} */
const isEntry = (value) =>
	typeof value === 'object' &&
	value !== null &&
	'label' in value &&
	typeof value.label === 'string' &&
	'tag' in value &&
	typeof value.tag === 'string' &&
	'channel' in value &&
	(value.channel === 'next' || value.channel === 'archive' || value.channel === 'latest') &&
	'base' in value &&
	typeof value.base === 'string' &&
	'releasedAt' in value &&
	(typeof value.releasedAt === 'string' || value.releasedAt === null) &&
	'releaseUrl' in value &&
	(typeof value.releaseUrl === 'string' || value.releaseUrl === null);

/** @param {string} file @returns {Promise<Entry[]>} */
const entriesOf = async (file) => {
	const catalog = JSON.parse(await readFile(file, 'utf8'));
	if (
		typeof catalog !== 'object' ||
		catalog === null ||
		!('versions' in catalog) ||
		!Array.isArray(catalog.versions) ||
		!catalog.versions.every(isEntry)
	) {
		throw new Error('invalid test catalog');
	}
	return catalog.versions;
};

/** @param {string} root @param {string} name @param {Record<string, string>} files @param {Entry[]} versions */
const fixture = async (root, name, files, versions) => {
	const directory = path.join(root, name);
	await mkdir(directory, { recursive: true });
	for (const [file, contents] of Object.entries(files)) {
		const target = path.join(directory, file);
		await mkdir(path.dirname(target), { recursive: true });
		await writeFile(target, contents);
	}
	await writeFile(
		path.join(directory, 'versions.json'),
		`${JSON.stringify({ schemaVersion: 3, versions }, null, '\t')}\n`,
	);
	return directory;
};

/** @param {string} base @param {Channel} channel @param {string} tag @param {string} [label] @returns {Entry} */
const version = (base, channel, tag, label = tag ?? channel) => ({
	label,
	tag,
	channel,
	base,
	releasedAt: tag ? '2026-10-01T00:00:00Z' : null,
	releaseUrl: null,
});

test('next replaces only next, retaining root and archive bytes and merging catalog', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'docs-publish-test-'));
	try {
		const tree = path.join(root, 'tree');
		const old = await fixture(
			root,
			'old',
			{
				'index.html': 'latest',
				'v0.1.0/index.html': 'snapshot',
				'v0.1.0-alpha.2/index.html': 'alpha two',
				'v0.1.0-alpha.10/index.html': 'alpha ten',
				'next/index.html': 'old next',
			},
			[
				version('/', 'latest', 'v0.2.0'),
				version('/v0.1.0/', 'archive', 'v0.1.0'),
				version('/v0.1.0-alpha.2/', 'archive', 'v0.1.0-alpha.2'),
				version('/v0.1.0-alpha.10/', 'archive', 'v0.1.0-alpha.10'),
			],
		);
		await cp(old, tree, { recursive: true });
		const archiveBefore = await readFile(path.join(tree, 'v0.1.0/index.html'));
		const rootBefore = await readFile(path.join(tree, 'index.html'));
		const input = await fixture(root, 'next', { 'index.html': 'new next' }, [
			version('/next/', 'next', 'master'),
		]);
		await assembleDocs({ channel: 'next', input, output: tree });
		assert.equal(await readFile(path.join(tree, 'next/index.html'), 'utf8'), 'new next');
		assert.deepEqual(await readFile(path.join(tree, 'v0.1.0/index.html')), archiveBefore);
		assert.deepEqual(await readFile(path.join(tree, 'index.html')), rootBefore);
		const catalogEntries = await entriesOf(path.join(tree, 'versions.json'));
		assert.deepEqual(
			catalogEntries.map((item) => item.base),
			['/', '/next/', '/v0.1.0/', '/v0.1.0-alpha.10/', '/v0.1.0-alpha.2/'],
		);
		assert.equal(catalogEntries[1]?.tag, 'master');
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test('archive refuses overwrite; latest replaces root while preserving prior snapshots byte-for-byte', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'docs-publish-test-'));
	try {
		const tree = path.join(root, 'tree');
		const prior = await fixture(
			root,
			'prior',
			{
				'index.html': 'root old',
				'next/index.html': 'next stable',
				'v0.1.0/index.html': 'first snapshot',
			},
			[
				version('/', 'latest', 'v0.1.0'),
				version('/next/', 'next', 'master'),
				version('/v0.1.0/', 'archive', 'v0.1.0'),
			],
		);
		await cp(prior, tree, { recursive: true });
		const firstSnapshot = await readFile(path.join(tree, 'v0.1.0/index.html'));
		const archive = await fixture(root, 'archive', { 'index.html': 'second snapshot' }, [
			version('/v0.2.0/', 'archive', 'v0.2.0'),
		]);
		await assembleDocs({ channel: 'archive', version: 'v0.2.0', input: archive, output: tree });
		const secondSnapshot = await readFile(path.join(tree, 'v0.2.0/index.html'));
		const latest = await fixture(
			root,
			'latest',
			{ 'index.html': 'root current', 'guide/index.html': 'updated guide' },
			[
				{
					...version('/', 'latest', 'v0.2.0'),
					sections: { guide: [{ slug: 'new', title: 'Latest guide' }] },
				},
			],
		);
		await assembleDocs({ channel: 'latest', version: 'v0.2.0', input: latest, output: tree });
		assert.equal(await readFile(path.join(tree, 'index.html'), 'utf8'), 'root current');
		assert.equal(await readFile(path.join(tree, 'guide/index.html'), 'utf8'), 'updated guide');
		assert.equal(await readFile(path.join(tree, 'next/index.html'), 'utf8'), 'next stable');
		assert.deepEqual(await readFile(path.join(tree, 'v0.1.0/index.html')), firstSnapshot);
		assert.deepEqual(await readFile(path.join(tree, 'v0.2.0/index.html')), secondSnapshot);
		const catalogEntries = await entriesOf(path.join(tree, 'versions.json'));
		assert.deepEqual(
			catalogEntries.map((item) => item.base),
			['/', '/next/', '/v0.2.0/', '/v0.1.0/'],
		);
		assert.equal(catalogEntries[0]?.tag, 'v0.2.0');
		assert.deepEqual(catalogEntries[0]?.sections?.guide, [{ slug: 'new', title: 'Latest guide' }]);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test('archive overwrite requires explicit repair and source symlinks are rejected', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'docs-publish-test-'));
	try {
		const tree = path.join(root, 'tree');
		const input = await fixture(root, 'input', { 'index.html': 'x' }, [
			version('/v1.2.3/', 'archive', 'v1.2.3'),
		]);
		await assembleDocs({ channel: 'archive', version: 'v1.2.3', input, output: tree });
		const before = await readFile(path.join(tree, 'v1.2.3/index.html'));
		await assert.rejects(
			assembleDocs({ channel: 'archive', version: 'v1.2.3', input, output: tree }),
			/already exists/,
		);
		assert.deepEqual(await readFile(path.join(tree, 'v1.2.3/index.html')), before);
		await assembleDocs({
			channel: 'archive',
			version: 'v1.2.3',
			input,
			output: tree,
			repair: true,
		});
		await symlink(path.join(input, 'index.html'), path.join(input, 'bad-link'));
		await assert.rejects(
			assembleDocs({ channel: 'archive', version: 'v1.2.3', input, output: tree }),
			/symbolic links/,
		);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test('rejects unsafe versions and symlinks in the existing publish tree without changing it', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'docs-publish-test-'));
	try {
		const tree = path.join(root, 'tree');
		const input = await fixture(root, 'input', { 'index.html': 'next' }, [
			version('/next/', 'next', 'master'),
		]);
		await assert.rejects(
			assembleDocs({ channel: 'archive', version: 'v1.2.3/../../escape', input, output: tree }),
			/invalid release version/,
		);
		const old = await fixture(root, 'old', { 'index.html': 'old' }, [
			version('/', 'latest', 'v1.0.0'),
		]);
		await cp(old, tree, { recursive: true });
		await symlink(path.join(input, 'index.html'), path.join(tree, 'linked-file'));
		await assert.rejects(assembleDocs({ channel: 'next', input, output: tree }), /symbolic links/);
		assert.equal(await readFile(path.join(tree, 'index.html'), 'utf8'), 'old');
		assert.equal(await readFile(path.join(tree, 'linked-file'), 'utf8'), 'next');
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test('rejects a malformed existing catalog and rolls back a staged tree over budget', async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), 'docs-publish-test-'));
	try {
		const tree = path.join(root, 'tree');
		const input = await fixture(root, 'input', { 'index.html': 'new' }, [
			version('/next/', 'next', 'master'),
		]);
		const old = await fixture(root, 'old', { 'index.html': 'old' }, [
			version('/', 'latest', 'v1.0.0'),
		]);
		await cp(old, tree, { recursive: true });
		const malformed = '{"schemaVersion":3,"versions":[{"base":"/../../escape"}]}\n';
		await writeFile(path.join(tree, 'versions.json'), malformed);
		await assert.rejects(
			assembleDocs({ channel: 'next', input, output: tree }),
			/invalid entry|unsafe version/,
		);
		assert.equal(await readFile(path.join(tree, 'index.html'), 'utf8'), 'old');
		await writeFile(
			path.join(tree, 'versions.json'),
			`${JSON.stringify({ schemaVersion: 3, versions: [version('/', 'latest', 'v1.0.0')] })}\n`,
		);
		await assert.rejects(
			assembleDocs({ channel: 'next', input, output: tree, maxFiles: 1 }),
			/file budget/,
		);
		assert.equal(await readFile(path.join(tree, 'index.html'), 'utf8'), 'old');
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
