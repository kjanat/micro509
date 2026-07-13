import { describe, expect, it } from 'bun:test';
import { join } from 'node:path';
import {
	derivePublicKey,
	exportSpkiDer,
	importPkcs8Pem,
	importSpkiDer,
	parseCertificateDer,
	pemEncode,
	unwrap,
} from '#micro509';
import type { Mismatch } from '#test/fuzz/compare';
import { compareCertificate } from '#test/fuzz/compare';
import { dumpFailure } from '#test/fuzz/failure';
import { makeRng } from '#test/fuzz/prng';
import { drawCase, importInputFor } from '#test/fuzz/spec';
import { differentialEnabled, openSslAvailable } from '#test/helpers';
import { runOpenSsl, withTempDir } from '#test/oracles/openssl';
import { generateCertificate, readCertFields } from '#test/oracles/openssl-gen';

/** Env override, falling back only when the variable is missing or non-numeric (0 is honored). */
function envInt(name: string, fallback: number): number {
	const parsed = Number.parseInt(process.env[name] ?? '', 10);
	return Number.isNaN(parsed) ? fallback : parsed;
}

const SEED = envInt('FUZZ_SEED', 0x5eed);
const ITERATIONS = envInt('FUZZ_ITERATIONS', 64);
/**
 * Per-case budget: RSA-4096 keygen is a random prime hunt with a fat runtime
 * tail, and CA-signed cases run two of them — bun's 5s default times out on
 * slow CI runners.
 */
const CASE_TIMEOUT_MS = 60_000;

/** Independent, order-stable seed per iteration so a failing case reproduces alone. */
function iterationSeed(index: number): number {
	return (SEED ^ Math.imul(index + 1, 0x9e37_79b1)) >>> 0;
}

describe.concurrent.skipIf(!openSslAvailable || !differentialEnabled)(
	'OpenSSL generation differential fuzz',
	() => {
		for (let index = 0; index < ITERATIONS; index += 1) {
			it(
				`case ${index}: micro509 decode matches OpenSSL`,
				async () => {
					const { spec } = drawCase(makeRng(iterationSeed(index)), index);
					const { certPem, certDer, subjectKeyPem } = await generateCertificate(spec);

					// Every failure below — field mismatch, parse/codec throw, or a missed
					// expect — must leave a repro dump, so the whole check runs under one
					// catch with a single dump site.
					let mismatches: readonly Mismatch[] = [];
					try {
						const micro = unwrap(parseCertificateDer(certDer));
						const openssl = await readCertFields(certPem);
						mismatches = compareCertificate({ micro, openssl, spec });
						if (mismatches.length > 0) {
							const summary = mismatches
								.map(
									(m) =>
										`  ${m.field}: openssl=${m.openssl.slice(0, 80)} micro509=${m.micro509.slice(0, 80)}`,
								)
								.join('\n');
							throw new Error(`decode divergence:\n${summary}`);
						}

						// Cross-parse interop: OpenSSL must accept micro509's PEM encoding of
						// the same DER, so the codec is checked against the oracle rather than
						// only against its own decoder.
						await withTempDir(async (dir) => {
							const reEncodedPath = join(dir, 'reencoded.pem');
							await Bun.write(reEncodedPath, pemEncode('CERTIFICATE', openssl.der));
							const parsed = await runOpenSsl(['x509', '-in', reEncodedPath, '-noout']);
							if (parsed.exitCode !== 0) {
								throw new Error(`openssl rejected micro509 PEM encoding: ${parsed.stderr}`);
							}
						});

						// Standalone key codec, exercising the shipped key ergonomics: the SPKI
						// import infers its algorithm straight from the DER (no hint), and the
						// PKCS#8 private key bridges to its public half via derivePublicKey. Both
						// re-exported SPKIs must byte-match OpenSSL's.
						const inferredSpki = await exportSpkiDer(unwrap(await importSpkiDer(openssl.spkiDer)));
						expect(inferredSpki).toEqual(openssl.spkiDer);

						const privateKey = unwrap(
							await importPkcs8Pem(subjectKeyPem, importInputFor(spec.algo)),
						);
						const derivedSpki = await exportSpkiDer(await derivePublicKey(privateKey));
						expect(derivedSpki).toEqual(openssl.spkiDer);
					} catch (error) {
						const version = (await runOpenSsl(['version'])).stdout.trim();
						const failure = error instanceof Error ? error.message : String(error);
						const dir = await dumpFailure({
							seed: SEED,
							index,
							spec,
							certPem,
							keyPem: subjectKeyPem,
							opensslVersion: version,
							mismatches,
							...(mismatches.length === 0 ? { error: failure } : {}),
						});
						throw new Error(
							`case ${index} (${spec.algo.kind}/${spec.issuance}) failed, repro in ${dir}:\n${failure}`,
							{ cause: error },
						);
					}
				},
				CASE_TIMEOUT_MS,
			);
		}

		// Negative control: the comparator must actually be able to report a
		// mismatch, so a comparator bug can't masquerade as a clean fuzz pass.
		it(
			'comparator detects an injected serial mismatch',
			async () => {
				const { spec } = drawCase(makeRng(iterationSeed(0)), 0);
				const { certDer, certPem } = await generateCertificate(spec);
				const micro = unwrap(parseCertificateDer(certDer));
				const openssl = await readCertFields(certPem);
				const tampered = { ...openssl, serialHex: 'deadbeef' };
				const mismatches = compareCertificate({ micro, openssl: tampered, spec });
				expect(mismatches.some((m) => m.field === 'serial')).toBe(true);
			},
			CASE_TIMEOUT_MS,
		);
	},
);
