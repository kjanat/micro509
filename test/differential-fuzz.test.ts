import { describe, expect, it } from 'bun:test';
import {
	derivePublicKey,
	exportSpkiDer,
	importPkcs8Pem,
	importSpkiDer,
	parseCertificateDer,
	unwrap,
} from '#micro509';
import { compareCertificate } from './fuzz/compare.ts';
import { dumpFailure } from './fuzz/failure.ts';
import { makeRng } from './fuzz/prng.ts';
import { drawCase, importInputFor } from './fuzz/spec.ts';
import { generateCertificate, readCertFields } from './oracles/openssl-gen.ts';
import { probeOpenSsl, runOpenSsl } from './oracles/openssl.ts';

// Same opt-in gate as the hand-written differential suite: OpenSSL is
// version-sensitive, so CI runs this only in the dedicated differential job.
const differential =
	(await probeOpenSsl()) &&
	(process.env.CI === undefined || process.env.DIFFERENTIAL_OPENSSL === '1')
		? describe
		: describe.skip;

const SEED = Number.parseInt(process.env.FUZZ_SEED ?? '', 10) || 0x5eed;
const ITERATIONS = Number.parseInt(process.env.FUZZ_ITERATIONS ?? '', 10) || 64;

/** Independent, order-stable seed per iteration so a failing case reproduces alone. */
function iterationSeed(index: number): number {
	return (SEED ^ Math.imul(index + 1, 0x9e37_79b1)) >>> 0;
}

differential('OpenSSL generation differential fuzz', () => {
	for (let index = 0; index < ITERATIONS; index += 1) {
		it(`case ${index}: micro509 decode matches OpenSSL`, async () => {
			const { spec } = drawCase(makeRng(iterationSeed(index)), index);
			const { certPem, certDer, subjectKeyPem } = await generateCertificate(spec);

			const micro = unwrap(parseCertificateDer(certDer));
			const openssl = await readCertFields(certPem);
			const mismatches = compareCertificate({ micro, openssl, spec });

			if (mismatches.length > 0) {
				const version = (await runOpenSsl(['version'])).stdout.trim();
				const dir = await dumpFailure({
					seed: SEED,
					index,
					spec,
					certPem,
					keyPem: subjectKeyPem,
					opensslVersion: version,
					mismatches,
				});
				const summary = mismatches
					.map(
						(m) =>
							`  ${m.field}: openssl=${m.openssl.slice(0, 80)} micro509=${m.micro509.slice(0, 80)}`,
					)
					.join('\n');
				throw new Error(
					`decode divergence (${spec.algo.kind}/${spec.issuance}), repro in ${dir}:\n${summary}`,
				);
			}

			// Standalone key codec, exercising the shipped key ergonomics: the SPKI
			// import infers its algorithm straight from the DER (no hint), and the
			// PKCS#8 private key bridges to its public half via derivePublicKey. Both
			// re-exported SPKIs must byte-match OpenSSL's.
			const inferredSpki = await exportSpkiDer(unwrap(await importSpkiDer(openssl.spkiDer)));
			expect(inferredSpki).toEqual(openssl.spkiDer);

			const privateKey = unwrap(await importPkcs8Pem(subjectKeyPem, importInputFor(spec.algo)));
			const derivedSpki = await exportSpkiDer(await derivePublicKey(privateKey));
			expect(derivedSpki).toEqual(openssl.spkiDer);
		});
	}

	// Negative control: the comparator must actually be able to report a
	// mismatch, so a comparator bug can't masquerade as a clean fuzz pass.
	it('comparator detects an injected serial mismatch', async () => {
		const { spec } = drawCase(makeRng(iterationSeed(0)), 0);
		const { certDer, certPem } = await generateCertificate(spec);
		const micro = unwrap(parseCertificateDer(certDer));
		const openssl = await readCertFields(certPem);
		const tampered = { ...openssl, serialHex: 'deadbeef' };
		const mismatches = compareCertificate({ micro, openssl: tampered, spec });
		expect(mismatches.some((m) => m.field === 'serial')).toBe(true);
	});
});
