#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPOSITORY = 'https://github.com/kjanat/micro509.git';
const PUBLISHED_BRANCH = 'docs-site';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** @param {NodeJS.ProcessEnv} [env] @returns {boolean} */
export function usePublishedDocsTree(env = process.env) {
	return env.WORKERS_CI_BRANCH === 'master' && env.DOCS_CHANNEL === undefined;
}

/** Copy the generated branch tree, leaving Git metadata out of the deploy root. */
/** @param {string} source @param {string} destination @returns {Promise<void>} */
export async function copyPublishedDocsTree(source, destination) {
	await rm(destination, { recursive: true, force: true });
	await cp(source, destination, {
		recursive: true,
		filter: (entry) => path.basename(entry) !== '.git',
	});
}

async function deployPublishedTree() {
	const temporary = await mkdtemp(path.join(os.tmpdir(), 'micro509-docs-site-'));
	const checkout = path.join(temporary, 'checkout');
	try {
		const clone = spawnSync(
			'git',
			['clone', '--depth=1', '--single-branch', '--branch', PUBLISHED_BRANCH, REPOSITORY, checkout],
			{ cwd: root, stdio: 'inherit' },
		);
		if (clone.error) throw clone.error;
		if (clone.status !== 0) throw new Error(`git clone exited with status ${clone.status}`);
		await copyPublishedDocsTree(checkout, path.join(root, 'site/.vitepress/dist'));
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

function runLocalSiteBuild() {
	const result = spawnSync('run', ['-s', 'build', 'micro509-site:build'], {
		cwd: root,
		stdio: 'inherit',
		env: process.env,
	});
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error(`site build exited with status ${result.status}`);
}

if (
	process.argv[1] !== undefined &&
	import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
	try {
		if (usePublishedDocsTree()) await deployPublishedTree();
		else runLocalSiteBuild();
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
