#!/usr/bin/env bun
/**
 * Validates that every package export target resolves to a file inside the npm
 * tarball.
 *
 * Run: `bun scripts/check-npm-pack.ts` (requires `dist/` to be built).
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { log, error } from 'node:console';
import { exit } from 'node:process';

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
	readonly types?: string;
} = JSON.parse(readFileSync('package.json', 'utf8'));

const targets = new Set<string>();
for (const value of Object.values(pkg.exports)) {
	collectTargets(value, targets);
}
if (pkg.types !== undefined) {
	targets.add(pkg.types.replace(/^\.\//, ''));
}
targets.delete('package.json');

const pack = spawnSync('npm', ['pack', '--dry-run', '--json'], { encoding: 'utf8' });
if (pack.status !== 0) {
	error(pack.stderr);
	exit(1);
}
const reports: readonly PackReport[] = JSON.parse(pack.stdout);
const report = reports[0];
if (report === undefined) {
	error('npm pack --json produced no report');
	exit(1);
}
const packedFiles = new Set(report.files.map((entry) => entry.path));

const missing = [...targets].filter((target) => !packedFiles.has(target));
if (missing.length > 0) {
	error('Published exports point at files missing from the npm tarball:');
	for (const target of missing) {
		error(`  - ${target}`);
	}
	exit(1);
}

log(`npm pack OK: ${targets.size} export targets present in tarball`);
