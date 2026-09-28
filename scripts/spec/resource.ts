import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

/** A cache is evidence of an observation, not a claim that a document is current. */
export interface ResourceProvenance {
	readonly url: string;
	readonly fetchedAt: string;
	readonly source: 'network' | 'cache';
	readonly fresh: boolean;
}

export interface Resource<T> {
	readonly value: T;
	readonly provenance: ResourceProvenance;
	readonly cacheWarning: string | undefined;
}

export interface ResourceOptions {
	readonly directory: string;
	readonly offline: boolean;
	readonly refresh: boolean;
	readonly maxAgeSeconds: number;
}

export function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function resourceCachePath(directory: string, url: string): string {
	return path.join(directory, `${createHash('sha256').update(url).digest('hex')}.json`);
}

function cachedResource<T>(
	input: unknown,
	url: string,
	decode: (value: unknown) => T | undefined,
	maxAgeSeconds: number,
): Resource<T> | undefined {
	if (!isRecord(input) || input['version'] !== 1 || input['url'] !== url) return undefined;
	const fetchedAt = input['fetchedAt'];
	if (typeof fetchedAt !== 'string') return undefined;
	const age = Date.now() - Date.parse(fetchedAt);
	if (!Number.isFinite(age) || age < 0) return undefined;
	const value = decode(input['payload']);
	return value === undefined
		? undefined
		: {
				value,
				provenance: { url, fetchedAt, source: 'cache', fresh: age < maxAgeSeconds * 1000 },
				cacheWarning: undefined,
			};
}

async function readCached<T>(
	file: string,
	url: string,
	decode: (value: unknown) => T | undefined,
	maxAgeSeconds: number,
): Promise<Resource<T> | undefined> {
	try {
		const input: unknown = JSON.parse(await readFile(file, 'utf8'));
		return cachedResource(input, url, decode, maxAgeSeconds);
	} catch {
		return undefined;
	}
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

async function writeCached(file: string, body: string): Promise<string | undefined> {
	const temporary = `${file}.${randomUUID()}.tmp`;
	try {
		await mkdir(path.dirname(file), { recursive: true });
		await writeFile(temporary, body, { flag: 'wx' });
		await rename(temporary, file);
		return undefined;
	} catch (error) {
		return `could not cache ${file}: ${errorText(error)}`;
	} finally {
		await rm(temporary, { force: true }).catch(() => undefined);
	}
}

/** Validate both cached and live payloads; never silently fall back to stale data. */
export async function loadJsonResource<T>(
	url: string,
	decode: (value: unknown) => T | undefined,
	options: ResourceOptions,
): Promise<Resource<T>> {
	if (options.offline && options.refresh) throw new Error('--offline and --refresh conflict');
	if (!Number.isSafeInteger(options.maxAgeSeconds) || options.maxAgeSeconds < 0) {
		throw new Error('maxAgeSeconds must be a non-negative safe integer');
	}
	const file = resourceCachePath(options.directory, url);
	const cached = await readCached(file, url, decode, options.maxAgeSeconds);
	if (options.offline) {
		if (cached === undefined) throw new Error(`no usable offline cache for ${url}`);
		return cached;
	}
	if (!options.refresh && cached?.provenance.fresh === true) return cached;
	const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
	if (!response.ok) throw new Error(`${url}: HTTP ${response.status} ${response.statusText}`);
	const payload: unknown = await response.json();
	const value = decode(payload);
	if (value === undefined) throw new Error(`${url}: unrecognized or incomplete response`);
	const fetchedAt = new Date().toISOString();
	const cacheWarning = await writeCached(
		file,
		`${JSON.stringify({ version: 1, url, fetchedAt, payload })}\n`,
	);
	return {
		value,
		provenance: { url, fetchedAt, source: 'network', fresh: true },
		cacheWarning,
	};
}
