#!/usr/bin/env -S deno run --allow-read --allow-net --allow-write --allow-run
/**
 * Checks the import map the built site ships. Every page must carry the same map:
 * top-level imports bound to the root version, and a scope per version prefix bound
 * to the version that prefix documents. Every URL in it must resolve to a JavaScript
 * module. Versions that speak today's API also run an example under their own scope.
 *
 * Run `site:build` first. Deno resolves import maps natively.
 *
 * @module
 */
/// <reference types="deno" />
const DIST = new URL('../site/.vitepress/dist/', import.meta.url).pathname;

const LIBRARY: string = JSON.parse(
	await Deno.readTextFile(new URL('../package.json', import.meta.url).pathname),
).name;

function isVersionDir(name: string): boolean {
	return name === 'next' || /^v\d+\.\d+\.\d+$/.test(name);
}

interface SiteMap {
	readonly imports: Readonly<Record<string, string>>;
	readonly scopes: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

/** Written against today's API. Archives shipped a different one. */
const EXAMPLE = `
import { createSelfSignedCertificate } from 'micro509';
import { parseCertificatePem } from 'micro509/x509';

const { certificate } = await createSelfSignedCertificate({
	subject: { commonName: 'import-maps.example' },
	validity: { days: 1 },
});
if (!certificate.pem.startsWith('-----BEGIN CERTIFICATE-----')) throw new Error('no certificate');

const parsed = await parseCertificatePem(certificate.pem);
if (!parsed.ok) throw new Error('parse failed');
const cn = parsed.value.subject.values.commonName;
if (cn !== 'import-maps.example') throw new Error(\`wrong subject: \${cn}\`);
`;

async function rawMapOf(prefix: string): Promise<string> {
	const html = await Deno.readTextFile(`${DIST}${prefix}index.html`);
	const found = html.match(/<script type="importmap">(.*?)<\/script>/s);
	if (found?.[1] === undefined) throw new Error(`/${prefix} ships no import map`);
	return found[1];
}

/** URL prefixes of every version the site serves, such as `''` or `'v0.8.0/'`. */
async function servedPrefixes(): Promise<readonly string[]> {
	const prefixes = [''];
	for await (const entry of Deno.readDir(DIST)) {
		if (entry.isDirectory && isVersionDir(entry.name)) prefixes.push(`${entry.name}/`);
	}
	return prefixes.sort();
}

function parseMap(raw: string): SiteMap {
	const parsed = JSON.parse(raw);
	return { imports: parsed.imports ?? {}, scopes: parsed.scopes ?? {} };
}

/** What a module under `prefix` resolves: its scope over the top-level imports. */
function effectiveImports(map: SiteMap, prefix: string): Readonly<Record<string, string>> {
	return prefix === '' ? map.imports : { ...map.imports, ...map.scopes[`/${prefix}`] };
}

/** The library ref a mapping points at, such as `0.8.0` or `master`. */
function boundTo(imports: Readonly<Record<string, string>>): string {
	const root = imports[LIBRARY] ?? '';
	return root.match(/@([^/@?]+)/)?.[1] ?? '';
}

/** A prefix must resolve the version it documents. */
function bindsToItsOwnVersion(map: SiteMap, prefix: string): boolean {
	const version = prefix.replace(/^v/, '').replace(/\/$/, '');
	if (version === '' || version === 'next') return true;
	return boundTo(effectiveImports(map, prefix)) === version;
}

async function runs(imports: Readonly<Record<string, string>>): Promise<string | undefined> {
	const dir = await Deno.makeTempDir();
	try {
		await Deno.writeTextFile(`${dir}/import_map.json`, JSON.stringify({ imports }));
		await Deno.writeTextFile(`${dir}/example.ts`, EXAMPLE);

		const { success, stderr } = await new Deno.Command(Deno.execPath(), {
			args: [
				'run',
				'--quiet',
				'--allow-net',
				'--no-lock',
				`--import-map=${dir}/import_map.json`,
				`${dir}/example.ts`,
			],
			stderr: 'piped',
			stdout: 'null',
		}).output();

		return success ? undefined : new TextDecoder().decode(stderr).trim().split('\n')[0];
	} finally {
		await Deno.remove(dir, { recursive: true });
	}
}

const ATTEMPTS = 4;
const CONCURRENCY = 8;

async function fetchRetrying(url: string, init?: RequestInit): Promise<Response | string> {
	let problem = '';
	for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
		if (attempt > 1) {
			await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** (attempt - 2)));
		}
		const response = await fetch(url, init).catch((error: unknown) => String(error));
		if (typeof response === 'string') {
			problem = response;
			continue;
		}
		if (response.status !== 429 && response.status < 500) return response;
		await response.body?.cancel();
		problem = `${response.status} ${response.statusText}`;
	}
	return `${problem} after ${ATTEMPTS} attempts`;
}

async function pooled<T, R>(
	items: readonly T[],
	run: (item: T) => Promise<R>,
): Promise<readonly R[]> {
	const queue = items.entries();
	const results: R[] = [];
	const worker = async (): Promise<void> => {
		for (const [index, item] of queue) results[index] = await run(item);
	};
	await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, worker));
	return results;
}

/** Every release jsDelivr carries. */
async function published(): Promise<readonly string[]> {
	const response = await fetchRetrying(`https://data.jsdelivr.com/v1/packages/npm/${LIBRARY}`, {
		headers: { accept: 'application/json' },
	});
	if (typeof response === 'string') {
		throw new Error(`[import-maps] jsDelivr metadata -> ${response}`);
	}
	if (!response.ok) {
		throw new Error(`[import-maps] jsDelivr metadata -> ${response.status} ${response.statusText}`);
	}
	const metadata: { readonly versions: ReadonlyArray<{ readonly version: string }> } =
		await response.json();
	return metadata.versions.map((entry) => entry.version);
}

async function resolvesAsModule([specifier, url]: readonly [string, string]): Promise<
	string | undefined
> {
	const response = await fetchRetrying(url);
	if (typeof response === 'string') return `${specifier} -> ${url} (${response})`;
	const body = await response.text();
	if (!response.ok) return `${specifier} -> ${url} (${response.status})`;

	const javascript = response.headers.get('content-type')?.includes('javascript');
	return javascript === true && /\bexport\b/.test(body)
		? undefined
		: `${specifier} -> ${url} (not a module)`;
}

const prefixes = await servedPrefixes().catch(() => []);
if (prefixes.length === 0) {
	console.error('[import-maps] no built site at site/.vitepress/dist — run `run site:build` first');
	Deno.exit(1);
}

const failures: string[] = [];

const rawRoot = await rawMapOf('');
const map = parseMap(rawRoot);

for (const prefix of prefixes.slice(1)) {
	const raw = await rawMapOf(prefix);
	if (raw !== rawRoot) failures.push(`/${prefix} ships a different map than /`);
}

const servedSemvers = new Set(
	prefixes
		.map((prefix) => boundTo(effectiveImports(map, prefix)))
		.filter((version) => /^\d+\.\d+\.\d+$/.test(version)),
);

if (servedSemvers.size > 0) {
	const releases = new Set(await published());
	for (const version of releases) {
		if (!servedSemvers.has(version))
			failures.push(`jsDelivr carries ${version}, but the site serves no page for it`);
	}
	for (const version of servedSemvers) {
		if (!releases.has(version))
			failures.push(`the site serves ${version}, which jsDelivr does not carry`);
	}
	console.log(
		`[import-maps] jsDelivr carries ${releases.size} releases; the site serves ${servedSemvers.size}`,
	);
} else {
	console.log(
		'[import-maps] preview build (only current tree served); skipping published releases check',
	);
}

const entries = new Map<string, readonly [string, string]>();
for (const prefix of prefixes) {
	for (const entry of Object.entries(effectiveImports(map, prefix))) {
		entries.set(entry[1], [entry[0], entry[1]]);
	}
}
const unresolved = (await pooled([...entries.values()], resolvesAsModule)).filter(
	(problem) => problem !== undefined,
);
if (unresolved.length > 0) {
	failures.push(`dead imports:\n    ${unresolved.join('\n    ')}`);
}

for (const prefix of prefixes) {
	const route = `/${prefix}`;
	const imports = effectiveImports(map, prefix);

	if (!bindsToItsOwnVersion(map, prefix)) {
		failures.push(`${route} resolves ${boundTo(imports)}, not the version it documents`);
		continue;
	}

	// Archives answer to their own API; running today's example against them proves nothing.
	const ran = (prefix === '' || prefix === 'next/') && unresolved.length === 0;
	const broke = ran ? await runs(imports) : undefined;
	if (broke !== undefined) {
		failures.push(`${route} (${boundTo(imports)}) cannot run an example: ${broke}`);
	}

	console.log(
		`[import-maps] ${route.padEnd(10)} -> ${boundTo(imports).padEnd(8)} ${Object.keys(imports).length} imports${ran && broke === undefined ? ', example runs' : ''}`,
	);
}

if (failures.length > 0) {
	console.error(`\n[import-maps] ${failures.length} failed:\n  ${failures.join('\n  ')}`);
	Deno.exit(1);
}
console.log(`\n[import-maps] ${prefixes.length} versions bound to their own library`);
