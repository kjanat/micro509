#!/usr/bin/env -S deno run --allow-read --allow-net --allow-write --allow-run
/**
 * The docs site does not host the library: each version's pages carry an import map
 * binding `micro509` to the library that version documents, on esm.sh. Nothing in the
 * build proves those URLs exist, or that a page ended up bound to its own version —
 * a wrong map ships a site whose every example is dead, and looks fine doing it.
 *
 * Against the built site (`run site:build` first), for every version:
 *   - the map names the version the page serves, not another one
 *   - every URL in it resolves, and resolves to a module
 * and against the versions that speak today's API, that an example actually runs.
 *
 * Deno resolves import maps natively, so an example runs here exactly as a browser
 * runs it: same map, same URLs, same module graph.
 *
 * @module
 */
const DIST = new URL('../site/.vitepress/dist/', import.meta.url).pathname;

/** The directories a version is served from: the root, the tree, one per release. */
function isVersionDir(name: string): boolean {
	return name === 'next' || /^v\d+\.\d+\.\d+$/.test(name);
}

/** A version's page, and the import map it shipped. */
interface Shipped {
	/** URL prefix the page is served under: `''`, `'next/'`, `'v0.8.0/'`. */
	readonly prefix: string;
	readonly imports: Readonly<Record<string, string>>;
}

/**
 * An example written against today's API, to run against the versions that have it.
 *
 * Not run against archives: an old release's examples were written against the API it
 * shipped (v0.1.0's `parseCertificatePem` returns the certificate, where today's returns
 * a `Result`), and those pages carry their own. What is checked for every version is that
 * its map resolves — which library it resolves to is the point.
 */
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

/** One version's map, read back out of the landing page that ships it. */
async function mapOf(prefix: string): Promise<Shipped> {
	const html = await Deno.readTextFile(`${DIST}${prefix}index.html`);
	const found = html.match(/<script type="importmap">(.*?)<\/script>/s);
	if (found?.[1] === undefined) throw new Error(`/${prefix} ships no import map`);
	return { prefix, imports: JSON.parse(found[1]).imports };
}

/** Every version's map. Each version has a landing page; one page per version is enough. */
async function shipped(): Promise<readonly Shipped[]> {
	const prefixes = [''];
	for await (const entry of Deno.readDir(DIST)) {
		if (entry.isDirectory && isVersionDir(entry.name)) prefixes.push(`${entry.name}/`);
	}
	const pages = await Promise.all(prefixes.sort().map(mapOf));
	return pages;
}

/**
 * The library a version's map points at: `0.8.0`, or `master`/a commit for the tree.
 *
 * Read out of the URL rather than off the end of it: a CDN puts its own things after
 * the version (`.../micro509@0.8.0/x509/+esm`), and only the `@ref` is ours.
 */
function boundTo(page: Shipped): string {
	const root = Object.values(page.imports)[0] ?? '';
	return root.match(/@([^/@?]+)/)?.[1] ?? '';
}

/** A page must import the version it documents — `/v0.8.0/` must not serve v0.11.0's library. */
function bindsToItsOwnVersion(page: Shipped): boolean {
	const version = page.prefix.replace(/^v/, '').replace(/\/$/, '');
	// The tree and the root release document what they build from, not a tag in their path.
	return version === '' || version === 'next' || boundTo(page) === version;
}

/** Run the example under a map, the way the browser will. */
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

const pages = await shipped();
if (pages.length === 0) {
	console.error('[import-maps] no built site at site/.vitepress/dist — run `run site:build` first');
	Deno.exit(1);
}

const failures: string[] = [];

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

				// A CDN that 404s into an HTML page is still a dead import. What every CDN's
				// output has in common is that it is JavaScript and it exports something —
				// not a shape: esm.sh leads with an import, jsDelivr with a build banner.
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
