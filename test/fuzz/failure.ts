/**
 * Persist a failing fuzz iteration as a self-contained repro fixture.
 *
 * OpenSSL key generation is random, so a seed alone cannot reproduce a failure;
 * the offending key + certificate + resolved spec are written to disk instead.
 * Promote a directory out of the (gitignored) failures folder to turn it into a
 * permanent regression fixture.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type { Mismatch } from './compare.ts';
import type { CertSpec } from './spec.ts';

const FAILURE_ROOT = join(import.meta.dirname, '../fixtures/differential-failures');

export interface FailureArtifact {
	readonly seed: number;
	readonly index: number;
	readonly spec: CertSpec;
	readonly certPem: string;
	readonly keyPem: string;
	readonly opensslVersion: string;
	readonly mismatches: readonly Mismatch[];
}

/** Write a failing iteration to `test/fixtures/differential-failures/<seed>-<index>/`. */
export async function dumpFailure(artifact: FailureArtifact): Promise<string> {
	const dir = join(FAILURE_ROOT, `${artifact.seed}-${artifact.index}`);
	await mkdir(dir, { recursive: true });
	await Promise.all([
		writeFile(join(dir, 'cert.pem'), artifact.certPem, 'utf8'),
		writeFile(join(dir, 'key.pem'), artifact.keyPem, 'utf8'),
		writeFile(
			join(dir, 'repro.json'),
			`${JSON.stringify(
				{
					seed: artifact.seed,
					index: artifact.index,
					opensslVersion: artifact.opensslVersion,
					spec: artifact.spec,
					mismatches: artifact.mismatches,
				},
				null,
				2,
			)}\n`,
			'utf8',
		),
	]);
	return dir;
}
