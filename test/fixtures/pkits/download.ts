#!/usr/bin/env bun
import { copyFile, mkdir, mkdtemp, readdir, rm, unlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { $, which } from 'bun';

// Vendors the full PKITS fixture corpus from the BoringSSL mirror of the NIST
// PKITS inputs via a shallow blobless sparse checkout (~3 MB) instead of ~580
// individual HTTP requests.

const UPSTREAM_REPO_URL = 'https://github.com/google/boringssl.git';
const UPSTREAM_SPARSE_PATH = 'pki/testdata/nist-pkits';
const UPSTREAM_FILES = ['README.md', 'generate_tests.py', 'pkits_testcases-inl.h'] as const;

function requireCommand(name: string): void {
	if (which(name) === null) {
		throw new Error(`Missing required command: ${name}`);
	}
}

async function syncDirectory(sourceDir: string, destDir: string, extension: string): Promise<void> {
	const label = path.basename(sourceDir);
	console.log(`syncing ${label}/ …`);
	await mkdir(destDir, { recursive: true });

	const [sourceFiles, destFiles] = await Promise.all([readdir(sourceDir), readdir(destDir)]);

	const suffix = `.${extension}`;
	const sourceSet = new Set(sourceFiles.filter((f) => f.endsWith(suffix)));
	const destSet = destFiles.filter((f) => f.endsWith(suffix));

	// Remove orphaned files no longer present upstream
	const orphans = destSet.filter((f) => !sourceSet.has(f));
	if (orphans.length > 0) {
		await Promise.all(orphans.map((f) => unlink(path.join(destDir, f))));
		console.log(`  removed ${orphans.length} orphaned .${extension} files`);
	}

	// Copy all upstream files in parallel (overwrites existing)
	await Promise.all(
		[...sourceSet].map((f) => copyFile(path.join(sourceDir, f), path.join(destDir, f))),
	);
	console.log(`  synced ${sourceSet.size} .${extension} files`);
}

async function main(): Promise<void> {
	const certDir = `${import.meta.dir}/certs`;
	const crlDir = `${import.meta.dir}/crls`;
	const upstreamDir = `${import.meta.dir}/upstream`;

	requireCommand('git');

	const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'pkits-sync-'));
	try {
		console.log('cloning boringssl (shallow sparse) …');
		await $`git clone --depth 1 --filter=blob:none --sparse --quiet ${UPSTREAM_REPO_URL} ${tmpDir}`;
		await $`git -C ${tmpDir} sparse-checkout set ${UPSTREAM_SPARSE_PATH}`.quiet();

		const cloneBase = path.join(tmpDir, UPSTREAM_SPARSE_PATH);

		await syncDirectory(path.join(cloneBase, 'certs'), certDir, 'crt');
		await syncDirectory(path.join(cloneBase, 'crls'), crlDir, 'crl');

		await mkdir(upstreamDir, { recursive: true });
		await Promise.all(
			UPSTREAM_FILES.map((f) => copyFile(path.join(cloneBase, f), path.join(upstreamDir, f))),
		);
		console.log(`synced ${UPSTREAM_FILES.length} upstream metadata files`);
	} finally {
		await rm(tmpDir, { recursive: true, force: true });
	}

	await $`bun ${import.meta.dir}/generate-manifest.ts`;

	await $`bunx dprint fmt --log-level error ${import.meta.dir}/**/*.{ts,md,py,h}`;
}

if (import.meta.main) await main();
