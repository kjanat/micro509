#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
	cp,
	lstat,
	mkdir,
	mkdtemp,
	readdir,
	readFile,
	rm,
	stat,
	writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as tar from 'tar';
import { assembleDocs } from './docs-publish.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageManifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const sourceCache = path.join(root, 'node_modules/.cache/docs-sources');
const registry = `https://registry.npmjs.org/${packageManifest.name}`;
const REPO = 'kjanat/micro509';
const VERSION = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const SOURCE_PATHS = [
	'src',
	'package.json',
	'jsr.json',
	'site/guide',
	'site/reference',
	'site/index.md',
];

/** @typedef {{ channel: 'next' | 'bootstrap', output: string } | { channel: 'release' | 'repair', output: string, version: string, repair?: true }} BuildOptions */
/** @typedef {{ channel: 'next' | 'archive' | 'latest', version?: string, sourceRoot?: string, output: string, publishTree: string, repair?: boolean }} TargetOptions */
/** @typedef {{ channel?: string, output?: string, version?: string, repair?: boolean }} RawOptions */

/** @param {string} version @returns {number[] | undefined} */
function versionParts(version) {
	const match = version.match(/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
	return match === null ? undefined : match.slice(1).map(Number);
}

/** @param {unknown} packument @returns {string[]} */
export function stableVersions(packument) {
	if (
		typeof packument !== 'object' ||
		packument === null ||
		!('versions' in packument) ||
		typeof packument.versions !== 'object' ||
		packument.versions === null ||
		Array.isArray(packument.versions)
	)
		throw new Error('npm packument has no versions map');
	return Object.keys(packument.versions)
		.filter((version) => versionParts(version) !== undefined)
		.sort((left, right) => {
			const a = versionParts(left) ?? [];
			const b = versionParts(right) ?? [];
			return (b[0] ?? 0) - (a[0] ?? 0) || (b[1] ?? 0) - (a[1] ?? 0) || (b[2] ?? 0) - (a[2] ?? 0);
		});
}

/** @param {string[]} args @returns {BuildOptions} */
export function parseArgs(args) {
	return validateArgs(collectArgs(args));
}

/** @param {string[]} args @returns {RawOptions} */
function collectArgs(args) {
	/** @type {RawOptions} */
	const options = {};
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === undefined) throw new Error('missing argument');
		if (['--channel', '--output', '--version'].includes(arg)) {
			const value = args[++index];
			if (value === undefined || value.startsWith('--'))
				throw new Error(`missing value for ${arg}`);
			if (arg === '--channel') options.channel = value;
			else if (arg === '--output') options.output = value;
			else options.version = value;
		} else if (arg === '--repair') options.repair = true;
		else throw new Error(`unknown argument: ${arg}`);
	}
	return options;
}

/** @param {RawOptions} options @returns {BuildOptions} */
function validateArgs(options) {
	const channel = options.channel;
	if (
		channel !== 'next' &&
		channel !== 'release' &&
		channel !== 'bootstrap' &&
		channel !== 'repair'
	)
		throw new Error('channel must be next, release, bootstrap, or repair');
	const output = options.output;
	if (output === undefined) throw new Error('--output is required');
	if (channel === 'next' || channel === 'bootstrap') {
		if (options.version !== undefined) throw new Error(`--version is not valid for ${channel}`);
		if (options.repair) throw new Error('--repair is only valid with --channel repair');
		return { channel, output };
	}
	const version = options.version;
	if (version === undefined || !VERSION.test(version))
		throw new Error(`a stable --version is required for ${channel}`);
	if (channel === 'release' && options.repair)
		throw new Error('--repair is only valid with --channel repair');
	return channel === 'repair'
		? { channel, output, version, repair: true }
		: { channel, output, version };
}

/** @param {string} url @returns {Promise<unknown>} */
async function responseJson(url) {
	const response = await fetch(url, {
		headers: { accept: 'application/json', 'user-agent': 'micro509-docs-build' },
		signal: AbortSignal.timeout(30_000),
	});
	if (!response.ok) throw new Error(`${url} -> ${response.status} ${response.statusText}`);
	return response.json();
}

/** @param {unknown} packument @returns {string | undefined} */
function latestVersion(packument) {
	if (
		typeof packument !== 'object' ||
		packument === null ||
		!('dist-tags' in packument) ||
		typeof packument['dist-tags'] !== 'object' ||
		packument['dist-tags'] === null ||
		!('latest' in packument['dist-tags'])
	)
		return undefined;
	const latest = packument['dist-tags'].latest;
	return typeof latest === 'string' ? latest : undefined;
}

/** @param {string} version @returns {Promise<string>} */
async function fetchSource(version) {
	const target = path.join(sourceCache, version);
	const requiredPaths = ['src', 'package.json', 'jsr.json', 'site/guide', 'site/reference'];
	const hasMarker = await exists(path.join(target, '.complete'));
	const cached = await Promise.all(requiredPaths.map((entry) => exists(path.join(target, entry))));
	if (hasMarker && cached.every(Boolean)) {
		const manifest = JSON.parse(await readFile(path.join(target, 'package.json'), 'utf8'));
		if (manifest.name === packageManifest.name && manifest.version === version.slice(1))
			return target;
	}
	await mkdir(sourceCache, { recursive: true });
	const url = `https://codeload.github.com/${REPO}/tar.gz/refs/tags/${version}`;
	const response = await fetch(url, {
		headers: { 'user-agent': 'micro509-docs-build' },
		signal: AbortSignal.timeout(60_000),
	});
	if (!response.ok) throw new Error(`${url} -> ${response.status} ${response.statusText}`);
	const archive = `${target}.tar.gz`;
	const staging = `${target}.partial`;
	await writeFile(archive, Buffer.from(await response.arrayBuffer()));
	try {
		await rm(staging, { recursive: true, force: true });
		await mkdir(staging, { recursive: true });
		await tar.x({
			file: archive,
			cwd: staging,
			strip: 1,
			preservePaths: false,
			filter: (entry) => {
				const relative = entry.split('/').slice(1).join('/');
				return SOURCE_PATHS.some(
					(wanted) => relative === wanted || relative.startsWith(`${wanted}/`),
				);
			},
		});
		for (const required of requiredPaths) {
			if (
				!(await stat(path.join(staging, required)).then(
					() => true,
					() => false,
				))
			)
				throw new Error(`archive ${version} is missing ${required}`);
		}
		const manifest = JSON.parse(await readFile(path.join(staging, 'package.json'), 'utf8'));
		if (manifest.name !== packageManifest.name || manifest.version !== version.slice(1))
			throw new Error(`source archive ${version} has unexpected package identity or version`);
		await rejectSymlinks(staging);
		await writeFile(path.join(staging, '.complete'), '');
		await rm(target, { recursive: true, force: true });
		await cp(staging, target, { recursive: true });
	} finally {
		await rm(archive, { force: true });
		await rm(staging, { recursive: true, force: true });
	}
	return target;
}

/** @param {string} filename @returns {Promise<boolean>} */
async function exists(filename) {
	return stat(filename).then(
		() => true,
		() => false,
	);
}

/** @param {string} directory @returns {Promise<void>} */
async function rejectSymlinks(directory) {
	for (const entry of await readdir(directory, { withFileTypes: true })) {
		const target = path.join(directory, entry.name);
		const info = await lstat(target);
		if (info.isSymbolicLink())
			throw new Error(`source archive contains a symbolic link: ${target}`);
		if (entry.isDirectory()) await rejectSymlinks(target);
	}
}

/** @param {TargetOptions} options @returns {Promise<void>} */
async function buildTarget({ channel, version, sourceRoot, output, publishTree, repair = false }) {
	console.log(`[docs-build] ${channel}${version === undefined ? '' : ` ${version}`}`);
	/** @type {NodeJS.ProcessEnv} */
	const env = { ...process.env, DOCS_CHANNEL: channel };
	delete env.DOCS_VERSION;
	delete env.DOCS_SOURCE_ROOT;
	if (version !== undefined) env.DOCS_VERSION = version;
	if (sourceRoot !== undefined) env.DOCS_SOURCE_ROOT = sourceRoot;
	const build = spawnSync('bun', ['run', 'site:build'], { cwd: root, stdio: 'inherit', env });
	if (build.error) throw build.error;
	if (build.status !== 0)
		throw new Error(`site build for ${channel} exited with status ${build.status}`);
	const dist = path.join(root, 'site/.vitepress/dist');
	await rm(output, { recursive: true, force: true });
	await cp(dist, output, { recursive: true });
	await assembleDocs({ channel, version, input: output, output: publishTree, repair });
}

/** @param {BuildOptions} options @returns {Promise<void>} */
async function run(options) {
	const publishTree = path.resolve(root, options.output);
	await mkdir(path.dirname(publishTree), { recursive: true });
	const temporary = await mkdtemp(path.join(os.tmpdir(), 'micro509-docs-build-'));
	/** @param {string} name @param {Omit<TargetOptions, 'output' | 'publishTree'>} target */
	const buildAt = async (name, target) =>
		buildTarget({ ...target, output: path.join(temporary, name), publishTree });
	try {
		if (options.channel === 'next') {
			await buildAt('next', { channel: 'next' });
			return;
		}
		if (options.channel === 'release') {
			await buildAt('archive', { channel: 'archive', version: options.version });
			await buildAt('latest', { channel: 'latest', version: options.version });
			return;
		}
		if (options.channel === 'repair') {
			const sourceRoot = await fetchSource(options.version);
			await buildAt('repair', {
				channel: 'archive',
				version: options.version,
				sourceRoot,
				repair: true,
			});
			return;
		}

		const packument = await responseJson(registry);
		const releases = stableVersions(packument);
		const latest = latestVersion(packument);
		if (latest === undefined || !releases.includes(latest))
			throw new Error('npm latest dist-tag is not a stable published version');
		await buildAt('next', { channel: 'next' });
		for (const version of releases) {
			if (version === latest) continue;
			const sourceRoot = await fetchSource(`v${version}`);
			await buildAt(`archive-${version}`, {
				channel: 'archive',
				version: `v${version}`,
				sourceRoot,
			});
		}
		const latestSource = await fetchSource(`v${latest}`);
		await buildAt('latest-archive', {
			channel: 'archive',
			version: `v${latest}`,
			sourceRoot: latestSource,
		});
		await buildAt('latest', {
			channel: 'latest',
			version: `v${latest}`,
			sourceRoot: latestSource,
		});
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

if (
	process.argv[1] !== undefined &&
	import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
	try {
		await run(parseArgs(process.argv.slice(2)));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
