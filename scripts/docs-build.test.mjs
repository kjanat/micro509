import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { extractSourceTag, parseArgs, stableVersions } from './docs-build.mjs';

test('parses explicit single-target build modes', () => {
	assert.deepEqual(parseArgs(['--channel', 'next', '--output', '.publish']), {
		channel: 'next',
		output: '.publish',
	});
	assert.deepEqual(
		parseArgs(['--channel', 'release', '--version', 'v1.2.3', '--output', '.publish']),
		{
			channel: 'release',
			version: 'v1.2.3',
			output: '.publish',
		},
	);
	assert.deepEqual(
		parseArgs(['--channel', 'repair', '--version', 'v1.2.3', '--output', '.publish']),
		{
			channel: 'repair',
			version: 'v1.2.3',
			output: '.publish',
			repair: true,
		},
	);
	assert.throws(() =>
		parseArgs(['--channel', 'next', '--version', 'v1.2.3', '--output', '.publish']),
	);
	assert.throws(() => parseArgs(['--channel', 'repair', '--output', '.publish']));
});

test('bootstrap release selection filters prereleases and sorts stable versions newest first', () => {
	assert.deepEqual(
		stableVersions({
			versions: {
				'0.10.0': {},
				'0.9.9': {},
				'1.0.0-beta.1': {},
				'1.0.0': {},
				'2.0.0-rc.1': {},
			},
		}),
		['1.0.0', '0.10.0', '0.9.9'],
	);
	assert.throws(() => stableVersions({}));
});

/** @param {string} directory @param {string[]} args */
function fixtureGit(directory, args) {
	return execFileSync('git', ['-C', directory, ...args], { encoding: 'utf8', stdio: 'pipe' });
}

/** @param {string} directory */
async function sourceRepository(directory) {
	await mkdir(directory);
	fixtureGit(directory, ['init', '--quiet']);
	for (const [name, contents] of Object.entries({
		'package.json': JSON.stringify({ name: 'micro509', version: '1.2.3' }),
		'jsr.json': '{}',
		'src/index.ts': 'export const revision = 1;',
		'site/index.md': '# Home',
		'site/guide/getting-started.md': '# Getting started',
		'site/reference/algorithms.md': '# Algorithms',
		'not-for-docs.txt': 'excluded',
	})) {
		await mkdir(path.dirname(path.join(directory, name)), { recursive: true });
		await writeFile(path.join(directory, name), contents);
	}
	fixtureGit(directory, ['add', '.']);
	fixtureGit(directory, [
		'-c',
		'user.name=Fixture',
		'-c',
		'user.email=fixture@example.test',
		'-c',
		'commit.gpgsign=false',
		'commit',
		'--quiet',
		'-m',
		'fixture',
	]);
	fixtureGit(directory, ['-c', 'tag.gpgsign=false', 'tag', 'v1.2.3']);
}

test('extracts the selected Git tag and only its documentation source paths', async () => {
	const temporary = await mkdtemp(path.join(os.tmpdir(), 'docs-source-test-'));
	try {
		const repository = path.join(temporary, 'repository');
		await sourceRepository(repository);
		await writeFile(path.join(repository, 'src/index.ts'), 'export const revision = 2;');
		const target = path.join(temporary, 'extracted');
		await extractSourceTag(path.join(repository, '.git'), 'v1.2.3', target);
		assert.equal(
			await readFile(path.join(target, 'src/index.ts'), 'utf8'),
			'export const revision = 1;',
		);
		assert.equal(await readFile(path.join(target, '.complete'), 'utf8'), '');
		assert.equal(existsSync(path.join(target, 'not-for-docs.txt')), false);
		assert.equal(existsSync(path.join(target, '.git')), false);
		await assert.rejects(
			extractSourceTag(path.join(repository, '.git'), '../bad', target),
			/invalid source version/,
		);
		fixtureGit(repository, ['-c', 'tag.gpgsign=false', 'tag', 'v9.9.9']);
		await assert.rejects(
			extractSourceTag(path.join(repository, '.git'), 'v9.9.9', target),
			/unexpected package identity or version/,
		);
		assert.equal(
			await readFile(path.join(target, 'src/index.ts'), 'utf8'),
			'export const revision = 1;',
		);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});

test('rejects links in a Git source tag before publishing the extracted tree', async () => {
	const temporary = await mkdtemp(path.join(os.tmpdir(), 'docs-source-links-'));
	try {
		const repository = path.join(temporary, 'repository');
		await sourceRepository(repository);
		await symlink('../package.json', path.join(repository, 'src/link.ts'));
		fixtureGit(repository, ['add', '.']);
		fixtureGit(repository, [
			'-c',
			'user.name=Fixture',
			'-c',
			'user.email=fixture@example.test',
			'-c',
			'commit.gpgsign=false',
			'commit',
			'--quiet',
			'-m',
			'link',
		]);
		fixtureGit(repository, ['-c', 'tag.gpgsign=false', 'tag', '--force', 'v1.2.3']);
		const target = path.join(temporary, 'extracted');
		await assert.rejects(
			extractSourceTag(path.join(repository, '.git'), 'v1.2.3', target),
			/contains a link/,
		);
		assert.equal(existsSync(target), false);
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
});
