/**
 * Validates the npm tarball against the exports map that will actually be
 * published.
 *
 * `npm publish` does NOT rewrite `exports` from `publishConfig.exports`
 * (that is a pnpm/bun feature), so the publish workflow applies the rewrite
 * explicitly before publishing. This script simulates that rewrite and then
 * asserts every export target resolves to a file inside the packed tarball —
 * catching dev-only conditions (e.g. `bun` → `./src/*.ts`) that would ship
 * pointing at files excluded by the `files` allowlist.
 *
 * Run: `bun scripts/check-npm-pack.ts` (requires `dist/` to be built).
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

interface PackedEntry {
	readonly path: string;
}

interface PackReport {
	readonly files: readonly PackedEntry[];
}

type ExportsValue = string | { readonly [condition: string]: ExportsValue };

function collectTargets(value: ExportsValue, into: Set<string>): void {
	if (typeof value === 'string') {
		into.add(value.replace(/^\.\//, ''));
		return;
	}
	for (const nested of Object.values(value)) {
		collectTargets(nested, into);
	}
}

const pkg: {
	readonly exports: Record<string, ExportsValue>;
	readonly publishConfig?: { readonly exports?: Record<string, ExportsValue> };
	readonly types?: string;
} = JSON.parse(readFileSync('package.json', 'utf8'));

const publishedExports = pkg.publishConfig?.exports ?? pkg.exports;

const targets = new Set<string>();
for (const value of Object.values(publishedExports)) {
	collectTargets(value, targets);
}
if (pkg.types !== undefined) {
	targets.add(pkg.types.replace(/^\.\//, ''));
}
targets.delete('package.json');

const pack = spawnSync('npm', ['pack', '--dry-run', '--json'], { encoding: 'utf8' });
if (pack.status !== 0) {
	console.error(pack.stderr);
	process.exit(1);
}
const reports: readonly PackReport[] = JSON.parse(pack.stdout);
const report = reports[0];
if (report === undefined) {
	console.error('npm pack --json produced no report');
	process.exit(1);
}
const packedFiles = new Set(report.files.map((entry) => entry.path));

const missing = [...targets].filter((target) => !packedFiles.has(target));
if (missing.length > 0) {
	console.error('Published exports point at files missing from the npm tarball:');
	for (const target of missing) {
		console.error(`  - ${target}`);
	}
	process.exit(1);
}

if (pkg.publishConfig?.exports === undefined) {
	// Without a publishConfig rewrite, the raw exports map ships as-is —
	// every condition target (including dev-only ones) must be in the tarball.
	const rawTargets = new Set<string>();
	for (const value of Object.values(pkg.exports)) {
		collectTargets(value, rawTargets);
	}
	rawTargets.delete('package.json');
	const rawMissing = [...rawTargets].filter((target) => !packedFiles.has(target));
	if (rawMissing.length > 0) {
		console.error(
			'exports contains targets missing from the tarball and no publishConfig.exports rewrite exists:',
		);
		for (const target of rawMissing) {
			console.error(`  - ${target}`);
		}
		process.exit(1);
	}
}

console.log(`npm pack OK — ${targets.size} export targets present in tarball`);
