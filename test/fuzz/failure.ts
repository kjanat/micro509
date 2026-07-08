/**
 * Persist a failing fuzz iteration as a self-contained repro fixture.
 *
 * OpenSSL key generation is random, so a seed alone cannot reproduce a failure;
 * the offending key + certificate + resolved spec are written to disk instead.
 * Promote a directory out of the (gitignored) failures folder to turn it into a
 * permanent regression fixture.
 */

import { join } from 'node:path';

import type { Mismatch } from '#test/fuzz/compare';
import type { CertSpec } from '#test/fuzz/spec';

const FAILURE_ROOT = join(import.meta.dir, '../fixtures/differential-failures');

export interface FailureArtifact {
	readonly seed: number;
	readonly index: number;
	readonly spec: CertSpec;
	readonly certPem: string;
	readonly keyPem: string;
	readonly opensslVersion: string;
	readonly mismatches: readonly Mismatch[];
	/** Thrown-error message for failures with no field mismatches (parse/codec throws, expect misses). */
	readonly error?: string;
}

/** Write a failing iteration to `test/fixtures/differential-failures/<seed>-<index>/`. */
export async function dumpFailure(artifact: FailureArtifact): Promise<string> {
	const dir = join(FAILURE_ROOT, `${artifact.seed}-${artifact.index}`);
	const repro = {
		seed: artifact.seed,
		index: artifact.index,
		opensslVersion: artifact.opensslVersion,
		spec: artifact.spec,
		mismatches: artifact.mismatches,
		...(artifact.error === undefined ? {} : { error: artifact.error }),
	};
	await Promise.all([
		Bun.write(`${dir}/cert.pem`, artifact.certPem, { createPath: true }),
		Bun.write(`${dir}/key.pem`, artifact.keyPem, { createPath: true }),
		Bun.write(`${dir}/repro.json`, `${JSON.stringify(repro, null, '\t')}\n`, { createPath: true }),
	]);
	return dir;
}
