#!/usr/bin/env -S deno run --allow-read --allow-net --allow-write --allow-run
/**
 * Checks the import map each version of the built site ships. Every version's map must
 * name the library version that page documents, and every URL in it must resolve to a
 * JavaScript module. Versions that speak today's API also run an example under their
 * own map.
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

interface Shipped {
	/** URL prefix the page is served under, such as `''` or `'v0.8.0/'`. */
	readonly prefix: string;
	readonly imports: Readonly<Record<string, string>>;
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

async function mapOf(prefix: string): Promise<Shipped> {
	const html = await Deno.readTextFile(`${DIST}${prefix}index.html`);
	const found = html.match(/<script type="importmap">(.*?)<\/script>/s);
	if (found?.[1] === undefined) throw new Error(`/${prefix} ships no import map`);
	return { prefix, imports: JSON.parse(found[1]).imports };
}

/** Every version's map, read out of each version's landing page. */
async function shipped(): Promise<readonly Shipped[]> {
	const prefixes = [''];
	for await (const entry of Deno.readDir(DIST)) {
		if (entry.isDirectory && isVersionDir(entry.name)) prefixes.push(`${entry.name}/`);
	}
	const pages = await Promise.all(prefixes.sort().map(mapOf));
	return pages;
}

/** The library ref a version's map points at, such as `0.8.0` or `master`. */
function boundTo(page: Shipped): string {
	const root = Object.values(page.imports)[0] ?? '';
	return root.match(/@([^/@?]+)/)?.[1] ?? '';
}

/** A page must import the version it documents. */
function bindsToItsOwnVersion(page: Shipped): boolean {
	const version = page.prefix.replace(/^v/, '').replace(/\/$/, '');
	return version === '' || version === 'next' || boundTo(page) === version;
}

async function runs(page: Shipped): Promise<string | undefined> {
	const dir = await Deno.makeTempDir();
	try {
		await Deno.writeTextFile(`${dir}/import_map.json`, JSON.stringify({ imports: page.imports }));
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

/** Every release jsDelivr carries. */
async function published(): Promise<readonly string[]> {
	const response = await fetch(`https://data.jsdelivr.com/v1/packages/npm/${LIBRARY}`, {
		headers: { accept: 'application/json' },
	});
	if (!response.ok) {
		throw new Error(`[import-maps] jsDelivr metadata -> ${response.status} ${response.statusText}`);
	}
	const metadata: { readonly versions: ReadonlyArray<{ readonly version: string }> } =
		await response.json();
	return metadata.versions.map((entry) => entry.version);
}

const pages = await shipped();
if (pages.length === 0) {
	console.error('[import-maps] no built site at site/.vitepress/dist — run `run site:build` first');
	Deno.exit(1);
}

const failures: string[] = [];

const servedSemvers = new Set(
	pages.map((page) => boundTo(page)).filter((version) => /^\d+\.\d+\.\d+$/.test(version)),
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

for (const page of pages) {
	const route = `/${page.prefix}`;

	if (!bindsToItsOwnVersion(page)) {
		failures.push(`${route} imports ${boundTo(page)}, not the version it documents`);
		continue;
	}

	const unresolved = (
		await Promise.all(
			Object.entries(page.imports).map(async ([specifier, url]) => {
				const response = await fetch(url).catch((error: unknown) => String(error));
				if (typeof response === 'string') return `${specifier} -> ${url} (${response})`;
				const body = await response.text();
				if (!response.ok) return `${specifier} -> ${url} (${response.status})`;

				const javascript = response.headers.get('content-type')?.includes('javascript');
				return javascript === true && /\bexport\b/.test(body)
					? undefined
					: `${specifier} -> ${url} (not a module)`;
			}),
		)
	).filter((problem) => problem !== undefined);

	if (unresolved.length > 0) {
		failures.push(`${route} has dead imports:\n    ${unresolved.join('\n    ')}`);
		continue;
	}

	// Archives answer to their own API; running today's example against them proves nothing.
	const executable = page.prefix === '' || page.prefix === 'next/';
	const broke = executable ? await runs(page) : undefined;
	if (broke !== undefined)
		failures.push(`${route} (${boundTo(page)}) cannot run an example: ${broke}`);

	const count = Object.keys(page.imports).length;
	console.log(
		`[import-maps] ${route.padEnd(10)} -> ${boundTo(page).padEnd(8)} ${count} imports resolve${executable ? ', example runs' : ''}`,
	);
}

if (failures.length > 0) {
	console.error(`\n[import-maps] ${failures.length} failed:\n  ${failures.join('\n  ')}`);
	Deno.exit(1);
}
console.log(`\n[import-maps] ${pages.length} versions bound to their own library`);
