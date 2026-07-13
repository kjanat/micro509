import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { generateKeyPair } from '#micro509';
import type { CertificateFingerprintAlgorithm } from '#micro509/x509';
import {
	certificateFingerprint,
	createSelfSignedCertificate,
	parseCertificateDerOrThrow,
	parseCertificatePemOrThrow,
} from '#micro509/x509';
import { differentialEnabled, openSslAvailable } from '#test/helpers';
import { fingerprintCertificateWithOpenSsl } from '#test/oracles/openssl';

const ALGORITHMS: CertificateFingerprintAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

const NODE_HASH: Record<CertificateFingerprintAlgorithm, string> = {
	'SHA-1': 'sha1',
	'SHA-256': 'sha256',
	'SHA-384': 'sha384',
	'SHA-512': 'sha512',
};

async function sampleCertificate() {
	const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
	return await createSelfSignedCertificate({
		subject: { commonName: 'fingerprint.example', organization: 'Fingerprint Test' },
		keyPair,
		extensions: {
			basicConstraints: { ca: false },
			keyUsage: ['digitalSignature'],
			subjectAltNames: [{ type: 'dns', value: 'fingerprint.example' }],
		},
	});
}

describe('certificateFingerprint', () => {
	it('defaults to SHA-256', async () => {
		const { certificate } = await sampleCertificate();

		const fingerprint = await certificateFingerprint(certificate.pem);
		const expected = createHash('sha256').update(certificate.der).digest();

		expect(fingerprint.bytes).toEqual(new Uint8Array(expected));
		expect(fingerprint.bytes.length).toBe(32);
	});

	it.each(ALGORITHMS)('matches node:crypto for %s over the DER', async (algorithm) => {
		const { certificate } = await sampleCertificate();

		const fingerprint = await certificateFingerprint(certificate.pem, algorithm);
		const expected = new Uint8Array(
			createHash(NODE_HASH[algorithm]).update(certificate.der).digest(),
		);

		expect(fingerprint.bytes).toEqual(expected);
		expect(fingerprint.hex).toBe(Buffer.from(expected).toString('hex'));
	});

	it('renders hex lowercase-without-separators and colonHex uppercase-colon-separated', async () => {
		const { certificate } = await sampleCertificate();

		const fingerprint = await certificateFingerprint(certificate.der, 'SHA-256');

		expect(fingerprint.hex).toMatch(/^[0-9a-f]{64}$/);
		expect(fingerprint.colonHex).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
		// The two hex forms describe the same bytes.
		expect(fingerprint.colonHex.replaceAll(':', '').toLowerCase()).toBe(fingerprint.hex);
	});

	it('produces identical fingerprints from PEM, DER, and parsed-certificate sources', async () => {
		const { certificate } = await sampleCertificate();
		const parsed = parseCertificatePemOrThrow(certificate.pem);

		const [fromPem, fromDer, fromParsed] = await Promise.all([
			certificateFingerprint(certificate.pem),
			certificateFingerprint(certificate.der),
			certificateFingerprint(parsed),
		]);

		expect(fromDer.hex).toBe(fromPem.hex);
		expect(fromParsed.hex).toBe(fromPem.hex);
		expect(fromDer.colonHex).toBe(fromPem.colonHex);
	});

	it('produces different fingerprints for different certificates', async () => {
		const [first, second] = await Promise.all([sampleCertificate(), sampleCertificate()]);

		const [a, b] = await Promise.all([
			certificateFingerprint(first.certificate.der),
			certificateFingerprint(second.certificate.der),
		]);

		expect(a.hex).not.toBe(b.hex);
	});

	it('throws on malformed input', async () => {
		await expect(certificateFingerprint('not a pem')).rejects.toThrow();
		await expect(certificateFingerprint(new Uint8Array([0x30, 0x00]))).rejects.toThrow();
	});

	it('is unaffected by extra fields on a parsed certificate (hashes der only)', async () => {
		const { certificate } = await sampleCertificate();
		const parsed = parseCertificateDerOrThrow(certificate.der);
		// A caller-mutated copy that keeps der intact must fingerprint identically.
		const mutated = { ...parsed, serialNumberHex: 'deadbeef' };

		const [original, tampered] = await Promise.all([
			certificateFingerprint(parsed),
			certificateFingerprint(mutated),
		]);

		expect(tampered.hex).toBe(original.hex);
	});
});

describe.skipIf(!openSslAvailable || !differentialEnabled)(
	'certificateFingerprint OpenSSL differential',
	() => {
		it.each(
			ALGORITHMS,
		)('colonHex matches `openssl x509 -fingerprint` for %s', async (algorithm) => {
			const { certificate } = await sampleCertificate();

			const fingerprint = await certificateFingerprint(certificate.pem, algorithm);
			const opensslColonHex = await fingerprintCertificateWithOpenSsl({
				certificatePem: certificate.pem,
				algorithm: NODE_HASH[algorithm] as 'sha1' | 'sha256' | 'sha384' | 'sha512',
			});

			expect(fingerprint.colonHex).toBe(opensslColonHex);
		});
	},
);
