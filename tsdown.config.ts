import { readFile, writeFile } from 'node:fs/promises';

import { defineConfig } from 'tsdown';

type ExportMap = Readonly<Record<string, string>>;

type JsrManifest = {
	readonly name: string;
	readonly exports: ExportMap;
	readonly license: string;
	readonly publish: {
		readonly include: readonly string[];
		readonly exclude: readonly string[];
	};
	readonly version: string;
};

const jsrManifestPath = new URL('./jsr.json', import.meta.url);
const packageManifestPath = new URL('./package.json', import.meta.url);

export const publicEntrypoints = {
	index: 'src/index.ts',
	certificate: 'src/certificate.ts',
	crl: 'src/crl.ts',
	csr: 'src/csr.ts',
	extensions: 'src/extensions.ts',
	identity: 'src/identity.ts',
	keys: 'src/keys/index.ts',
	name: 'src/name.ts',
	'name-constraints': 'src/name-constraints.ts',
	ocsp: 'src/ocsp.ts',
	parse: 'src/parse.ts',
	pem: 'src/pem/index.ts',
	pfx: 'src/pfx.ts',
	pkcs7: 'src/pkcs7.ts',
	'pkcs12-mac': 'src/pkcs12-mac.ts',
	policy: 'src/policy.ts',
	result: 'src/result/index.ts',
	revocation: 'src/revocation/index.ts',
	verify: 'src/verify/index.ts',
	x509: 'src/x509/index.ts',
} as const satisfies Record<string, string>;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is readonly string[] {
	return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isStringRecord(value: unknown): value is Record<string, string> {
	return isRecord(value) && Object.values(value).every((item) => typeof item === 'string');
}

function toPublicSubpath(entryName: string): string {
	return entryName === 'index' ? '.' : `./${entryName}`;
}

function parsePackageExports(source: string): ExportMap {
	const parsed: unknown = JSON.parse(source);
	if (!isRecord(parsed) || !isStringRecord(parsed.exports)) {
		throw new TypeError('package.json must contain a string export map');
	}

	return parsed.exports;
}

function parseJsrManifest(source: string): JsrManifest {
	const parsed: unknown = JSON.parse(source);
	if (!isRecord(parsed)) {
		throw new TypeError('Expected jsr.json to contain an object');
	}

	const publish = parsed.publish;
	if (
		typeof parsed.name !== 'string' ||
		!isStringRecord(parsed.exports) ||
		typeof parsed.license !== 'string' ||
		!isRecord(publish) ||
		!isStringArray(publish.include) ||
		!isStringArray(publish.exclude) ||
		typeof parsed.version !== 'string'
	) {
		throw new TypeError('jsr.json does not match the expected manifest shape');
	}

	return {
		name: parsed.name,
		exports: parsed.exports,
		license: parsed.license,
		publish: {
			include: publish.include,
			exclude: publish.exclude,
		},
		version: parsed.version,
	};
}

function sorted(values: readonly string[]): readonly string[] {
	return [...values].sort();
}

/**
 * Public subpaths exposed by the package surface.
 */
export function createPublicSubpaths(
	entrypoints: Readonly<Record<string, string>> = publicEntrypoints,
): readonly string[] {
	return Object.keys(entrypoints).map((entryName) => toPublicSubpath(entryName));
}

/**
 * JSR uses source entrypoints instead of dist output.
 */
export function createJsrExports(
	entrypoints: Readonly<Record<string, string>> = publicEntrypoints,
): ExportMap {
	return Object.fromEntries(
		Object.entries(entrypoints).map(([entryName, sourcePath]) => [
			toPublicSubpath(entryName),
			`./${sourcePath}`,
		]),
	);
}

export async function syncJsrManifest(): Promise<void> {
	const currentSource = await readFile(jsrManifestPath, 'utf8');
	const currentManifest = parseJsrManifest(currentSource);
	const nextManifest: JsrManifest = {
		...currentManifest,
		exports: createJsrExports(),
	};
	const nextSource = `${JSON.stringify(nextManifest, null, '\t')}\n`;
	if (nextSource !== currentSource) {
		await writeFile(jsrManifestPath, nextSource);
	}
}

export async function checkExportMapParity(): Promise<void> {
	const [packageSource, jsrSource] = await Promise.all([
		readFile(packageManifestPath, 'utf8'),
		readFile(jsrManifestPath, 'utf8'),
	]);
	const packageExports = parsePackageExports(packageSource);
	const jsrManifest = parseJsrManifest(jsrSource);
	const expectedSubpaths = sorted(createPublicSubpaths());
	const packageSubpaths = sorted(
		Object.keys(packageExports).filter((subpath) => subpath !== './package.json'),
	);
	const jsrSubpaths = sorted(Object.keys(jsrManifest.exports));

	if (JSON.stringify(packageSubpaths) !== JSON.stringify(expectedSubpaths)) {
		throw new TypeError('package.json export subpaths drifted from publicEntrypoints');
	}
	if (packageExports['./package.json'] !== './package.json') {
		throw new TypeError('package.json must keep npm-only ./package.json export');
	}
	if (JSON.stringify(jsrSubpaths) !== JSON.stringify(expectedSubpaths)) {
		throw new TypeError('jsr.json export subpaths drifted from publicEntrypoints');
	}
	if (JSON.stringify(jsrManifest.exports) !== JSON.stringify(createJsrExports())) {
		throw new TypeError('jsr.json exports are not synchronized with publicEntrypoints');
	}
}

export default defineConfig({
	entry: publicEntrypoints,
	name: 'micro509',
	format: ['esm'],
	dts: true,
	clean: true,
	platform: 'neutral',
	target: 'es2024',
	tsconfig: 'tsconfig.src.json',
	sourcemap: true,
	unbundle: true,
	hash: false,
	minify: true,
	inputOptions: {
		resolve: {
			mainFields: ['browser', 'module', 'main'],
		},
	},
	hooks: {
		'build:prepare': async () => {
			await syncJsrManifest();
		},
	},
	exports: true,
	onSuccess: 'bunx sort-package-json --quiet package.json',
	attw: { profile: 'esm-only', ignoreRules: ['no-resolution'] },
	unused: true,
	publint: true,
});
