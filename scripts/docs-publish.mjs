#!/usr/bin/env node
import { cp, lstat, mkdtemp, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const VERSION = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

/** @typedef {'next' | 'archive' | 'latest'} Channel */
/**
 * @typedef {{
 *   label: string,
 *   tag: string,
 *   channel: Channel,
 *   base: string,
 *   releasedAt: string | null,
 *   releaseUrl: string | null,
 *   sections?: Record<string, unknown>
 * }} VersionEntry
 */
/** @typedef {{schemaVersion: 3, versions: VersionEntry[], [key: string]: unknown}} VersionCatalog */
/**
 * @typedef {{
 *   channel: Channel,
 *   input: string,
 *   output: string,
 *   version?: string,
 *   repair?: boolean,
 *   maxFiles?: number
 * }} AssembleOptions
 */

/** Reject a symlink in every parent component. */
/** @param {string} directory */
async function rejectSymlinkParents(directory) {
	const resolved = path.resolve(directory);
	const parent = path.dirname(resolved);
	if (parent !== resolved) await rejectSymlinkParents(parent);
	const info = await lstat(resolved);
	if (info.isSymbolicLink()) throw new Error(`symbolic links are not allowed: ${resolved}`);
	if (!info.isDirectory()) throw new Error(`expected a directory: ${resolved}`);
}

/** @param {string} root */
async function rejectSymlinks(root) {
	await rejectSymlinkParents(root);
	const info = await lstat(root);
	if (info.isSymbolicLink()) throw new Error(`symbolic links are not allowed: ${root}`);
	if (!info.isDirectory()) throw new Error(`expected a directory: ${root}`);
	for (const entry of await readdir(root, { withFileTypes: true })) {
		const child = path.join(root, entry.name);
		if (entry.isSymbolicLink()) throw new Error(`symbolic links are not allowed: ${child}`);
		if (entry.isDirectory()) await rejectSymlinks(child);
	}
}

/** @param {string} root @param {string} name */
function safeChild(root, name) {
	const target = path.resolve(root, name);
	if (target === path.resolve(root) || !target.startsWith(`${path.resolve(root)}${path.sep}`)) {
		throw new Error(`path escapes publish tree: ${name}`);
	}
	return target;
}

/** @param {string} target */
async function removeIfExists(target) {
	await rm(target, { recursive: true, force: true });
}

/** @param {string} target */
async function exists(target) {
	return lstat(target).then(
		() => true,
		(error) => {
			if (error.code === 'ENOENT') return false;
			throw error;
		},
	);
}

/** @param {unknown} value @param {string} description @returns {VersionCatalog} */
function validateCatalog(value, description) {
	if (!isRecord(value) || value.schemaVersion !== 3 || !Array.isArray(value.versions)) {
		throw new Error(`${description} versions.json must use schemaVersion 3`);
	}
	/** @type {VersionEntry[]} */
	const versions = [];
	const seen = new Set();
	for (const candidate of value.versions) {
		const entry = versionEntryOf(candidate, description);
		if (seen.has(entry.base))
			throw new Error(`${description} versions.json repeats base ${entry.base}`);
		seen.add(entry.base);
		versions.push(entry);
	}
	return { ...value, schemaVersion: 3, versions };
}

/** @param {unknown} value @param {string} description @returns {VersionEntry} */
function versionEntryOf(value, description) {
	if (!isVersionEntry(value)) throw new Error(`${description} versions.json has an invalid entry`);
	if (!hasSafeVersionPath(value)) {
		throw new Error(`${description} versions.json has an unsafe version entry: ${value.base}`);
	}
	return {
		label: value.label,
		tag: value.tag,
		channel: value.channel,
		base: value.base,
		releasedAt: value.releasedAt,
		releaseUrl: value.releaseUrl,
		...(value.sections === undefined ? {} : { sections: value.sections }),
	};
}

/** @param {unknown} value @returns {value is VersionEntry} */
function isVersionEntry(value) {
	return (
		isRecord(value) &&
		typeof value.label === 'string' &&
		typeof value.tag === 'string' &&
		isChannel(value.channel) &&
		typeof value.base === 'string' &&
		(typeof value.releasedAt === 'string' || value.releasedAt === null) &&
		(typeof value.releaseUrl === 'string' || value.releaseUrl === null) &&
		(value.sections === undefined || isRecord(value.sections))
	);
}

/** @param {VersionEntry} entry */
function hasSafeVersionPath(entry) {
	if (entry.channel === 'latest') return entry.base === '/' && VERSION.test(entry.tag);
	if (entry.channel === 'next') {
		return entry.base === '/next/' && /^[A-Za-z0-9][A-Za-z0-9._#-]*$/.test(entry.tag);
	}
	return entry.base === `/${entry.tag}/` && VERSION.test(entry.tag);
}

/** @param {unknown} value @returns {value is Channel} */
function isChannel(value) {
	return value === 'next' || value === 'archive' || value === 'latest';
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** @param {VersionEntry[]} versions */
function sortVersions(versions) {
	const channelRank = { latest: 0, next: 1, archive: 2 };
	return versions.sort((left, right) => {
		const rank = channelRank[left.channel] - channelRank[right.channel];
		if (rank !== 0) return rank;
		return left.channel === 'archive' && right.channel === 'archive'
			? compareVersionTags(right.tag, left.tag)
			: 0;
	});
}

/** @typedef {{major: number, minor: number, patch: number, prerelease: readonly string[]}} ParsedVersion */

/** @param {string} tag @returns {ParsedVersion | undefined} */
function parseVersionTag(tag) {
	const match = tag.match(/^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
	if (match === null) return undefined;
	return {
		major: Number(match[1]),
		minor: Number(match[2]),
		patch: Number(match[3]),
		prerelease: match[4]?.split('.') ?? [],
	};
}

/** @param {string} left @param {string} right */
function compareVersionTags(left, right) {
	const leftVersion = parseVersionTag(left);
	const rightVersion = parseVersionTag(right);
	if (leftVersion === undefined || rightVersion === undefined) return left.localeCompare(right);
	if (leftVersion.major !== rightVersion.major) return leftVersion.major - rightVersion.major;
	if (leftVersion.minor !== rightVersion.minor) return leftVersion.minor - rightVersion.minor;
	if (leftVersion.patch !== rightVersion.patch) return leftVersion.patch - rightVersion.patch;
	return comparePrerelease(leftVersion.prerelease, rightVersion.prerelease);
}

/** @param {readonly string[]} left @param {readonly string[]} right */
function comparePrerelease(left, right) {
	if (left.length === 0 || right.length === 0)
		return Number(right.length > 0) - Number(left.length > 0);
	for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
		const leftPart = left[index];
		const rightPart = right[index];
		if (leftPart === undefined || rightPart === undefined)
			return Number(leftPart !== undefined) - Number(rightPart !== undefined);
		const result = compareIdentifiers(leftPart, rightPart);
		if (result !== 0) return result;
	}
	return 0;
}

/** @param {string} left @param {string} right */
function compareIdentifiers(left, right) {
	if (left === right) return 0;
	const leftNumber = /^\d+$/.test(left) ? Number(left) : undefined;
	const rightNumber = /^\d+$/.test(right) ? Number(right) : undefined;
	if (leftNumber !== undefined && rightNumber !== undefined) return leftNumber - rightNumber;
	if (leftNumber !== undefined) return -1;
	if (rightNumber !== undefined) return 1;
	return left.localeCompare(right);
}

/** @param {string} directory */
async function countFiles(directory) {
	let count = 0;
	for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
		if (entry.isFile()) count += 1;
	}
	return count;
}

/** @param {AssembleOptions} options */
function validateOptions(options) {
	if (!isChannel(options.channel)) throw new Error(`invalid channel: ${options.channel}`);
	if (options.channel === 'archive' || options.channel === 'latest') {
		if (typeof options.version !== 'string' || !VERSION.test(options.version))
			throw new Error(`invalid release version: ${options.version}`);
	} else if (options.version !== undefined) {
		throw new Error('version is only valid for archive or latest');
	}
	if (
		options.maxFiles !== undefined &&
		(!Number.isInteger(options.maxFiles) || options.maxFiles < 1)
	)
		throw new Error(`invalid file budget: ${options.maxFiles}`);
}

/** @param {string} input @param {string} output */
function pathsOf(input, output) {
	const source = path.resolve(input);
	const destination = path.resolve(output);
	if (
		source === destination ||
		source.startsWith(`${destination}${path.sep}`) ||
		destination.startsWith(`${source}${path.sep}`)
	) {
		throw new Error('input and output must be separate directories');
	}
	return { source, destination };
}

/** @param {string} source @param {AssembleOptions} options @returns {Promise<VersionCatalog>} */
async function targetCatalogOf(source, options) {
	await rejectSymlinks(source);
	const incoming = validateCatalog(
		JSON.parse(await readFile(path.join(source, 'versions.json'), 'utf8')),
		'input',
	);
	if (incoming.versions.length !== 1) {
		throw new Error('input versions.json must describe exactly one target version');
	}
	const expectedBase =
		options.channel === 'next'
			? '/next/'
			: options.channel === 'archive'
				? `/${options.version}/`
				: '/';
	const entry = incoming.versions[0];
	if (
		entry === undefined ||
		entry.base !== expectedBase ||
		entry.channel !== options.channel ||
		(options.version !== undefined && entry.tag !== options.version)
	) {
		throw new Error(
			`input versions.json does not describe ${options.channel} ${options.version ?? ''}`.trim(),
		);
	}
	return incoming;
}

/** @param {string} stage @param {VersionCatalog} incoming */
async function mergeCatalog(stage, incoming) {
	const catalogPath = path.join(stage, 'versions.json');
	if (!(await exists(catalogPath)))
		return { ...incoming, versions: sortVersions([...incoming.versions]) };
	const current = validateCatalog(JSON.parse(await readFile(catalogPath, 'utf8')), 'publish tree');
	const merged = new Map(current.versions.map((item) => [item.base, item]));
	for (const item of incoming.versions) merged.set(item.base, item);
	return { ...current, ...incoming, versions: sortVersions([...merged.values()]) };
}

/** @param {string} stage @param {string} source @param {string} version @param {boolean} repair */
async function replaceArchive(stage, source, version, repair) {
	const archive = safeChild(stage, version);
	if ((await exists(archive)) && !repair)
		throw new Error(`archive already exists (use --repair to replace): ${version}`);
	await removeIfExists(archive);
	await cp(source, archive, {
		recursive: true,
		filter: (from) => path.basename(from) !== 'versions.json',
	});
}

/** @param {string} stage @param {string} source */
async function replaceNext(stage, source) {
	const next = safeChild(stage, 'next');
	await removeIfExists(next);
	await cp(source, next, {
		recursive: true,
		filter: (from) => path.basename(from) !== 'versions.json',
	});
}

/** @param {string} name @param {string} stage */
async function preserveRootDirectory(name, stage) {
	if (name === 'next') return true;
	const item = path.join(stage, name);
	return VERSION.test(name) && (await lstat(item)).isDirectory();
}

/** @param {string} stage @param {string} source */
async function replaceLatest(stage, source) {
	for (const name of await readdir(stage)) {
		if (name === 'versions.json' || (await preserveRootDirectory(name, stage))) continue;
		await removeIfExists(path.join(stage, name));
	}
	for (const name of await readdir(source)) {
		if (name !== 'versions.json' && name !== 'next' && !VERSION.test(name)) {
			await cp(path.join(source, name), path.join(stage, name), { recursive: true });
		}
	}
}

/** @param {Channel} channel @param {string} stage @param {string} source @param {string | undefined} version @param {boolean} repair */
async function applyTarget(channel, stage, source, version, repair) {
	if (channel === 'archive') {
		if (version === undefined) throw new Error('archive requires a version');
		await replaceArchive(stage, source, version, repair);
	} else if (channel === 'next') {
		await replaceNext(stage, source);
	} else {
		await replaceLatest(stage, source);
	}
}

/** @typedef {AssembleOptions & {source: string, destination: string, incoming: VersionCatalog}} StageOptions */
/** @param {StageOptions} options */
async function buildStage(options) {
	const { source, destination, incoming } = options;
	const parent = path.dirname(destination);
	await rejectSymlinkParents(parent);
	if (await exists(destination)) await rejectSymlinks(destination);
	const stage = await mkdtemp(path.join(parent, '.docs-publish-'));
	try {
		if (await exists(destination))
			await cp(destination, stage, { recursive: true, errorOnExist: true });
		const catalog = await mergeCatalog(stage, incoming);
		await applyTarget(options.channel, stage, source, options.version, options.repair ?? false);
		await writeFile(path.join(stage, 'versions.json'), `${JSON.stringify(catalog, null, '\t')}\n`);
		if (options.maxFiles !== undefined) {
			const fileCount = await countFiles(stage);
			if (fileCount > options.maxFiles) {
				throw new Error(
					`publish tree has ${fileCount} files, exceeding the ${options.maxFiles}-file budget`,
				);
			}
		}
		return stage;
	} catch (error) {
		await removeIfExists(stage);
		throw error;
	}
}

/** @param {string} stage @param {string} destination */
async function commitStage(stage, destination) {
	const backup = `${stage}-old`;
	let originalMoved = false;
	try {
		if (await exists(destination)) {
			await rename(destination, backup);
			originalMoved = true;
		}
		await rename(stage, destination);
	} catch (error) {
		await removeIfExists(stage);
		if (originalMoved) {
			if (await exists(destination)) {
				throw new Error(
					'publish tree changed during assembly; original tree remains in staging backup',
				);
			}
			await rename(backup, destination);
		}
		throw error;
	}
	if (originalMoved) {
		await removeIfExists(backup).catch((error) => {
			console.warn(
				`published tree is updated, but staging backup cleanup failed: ${String(error)}`,
			);
		});
	}
}

/** Merge one single-target VitePress output into the persistent publish tree. */
/** @param {AssembleOptions} options */
export async function assembleDocs(options) {
	validateOptions(options);
	const { source, destination } = pathsOf(options.input, options.output);
	const incoming = await targetCatalogOf(source, options);
	const stage = await buildStage({ ...options, source, destination, incoming });
	await commitStage(stage, destination);
}

/** @param {string[]} args @returns {Partial<AssembleOptions>} */
function parseArgs(args) {
	/** @type {Partial<AssembleOptions>} */
	const options = {};
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === '--repair') options.repair = true;
		else if (arg === '--channel') {
			const value = args[++index];
			if (value !== 'next' && value !== 'archive' && value !== 'latest')
				throw new Error(`invalid channel: ${value}`);
			options.channel = value;
		} else if (arg === '--input') options.input = args[++index];
		else if (arg === '--output') options.output = args[++index];
		else if (arg === '--version') options.version = args[++index];
		else throw new Error(`unknown argument: ${arg}`);
	}
	return options;
}

/** @param {Partial<AssembleOptions>} options @returns {AssembleOptions} */
function requiredOptions(options) {
	if (
		options.channel === undefined ||
		options.input === undefined ||
		options.output === undefined
	) {
		throw new Error(
			'usage: docs-publish.mjs --channel CHANNEL --input DIR --output DIR [--version TAG] [--repair]',
		);
	}
	return {
		channel: options.channel,
		input: options.input,
		output: options.output,
		...(options.version === undefined ? {} : { version: options.version }),
		...(options.repair === undefined ? {} : { repair: options.repair }),
	};
}

if (
	process.argv[1] !== undefined &&
	import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
	try {
		await assembleDocs(requiredOptions(parseArgs(process.argv.slice(2))));
	} catch (error) {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	}
}
