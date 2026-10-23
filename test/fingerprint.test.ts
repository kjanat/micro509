import { describe, expect, it } from 'bun:test';
import { createHash } from 'node:crypto';
import { generateKeyPair, verifyCertificateChain } from '#micro509';
import type { CertificateFingerprintAlgorithm } from '#micro509/x509';
import {
	certificateFingerprint,
	createCertificate,
	createSelfSignedCertificate,
	parseCertificateDerOrThrow,
	parseCertificatePemOrThrow,
	subjectPublicKeyInfoFingerprint,
} from '#micro509/x509';
import {
	differentialEnabled,
	expectRejectedWith,
	issueChain,
	openSslAvailable,
} from '#test/helpers';
import { fingerprintCertificateWithOpenSsl } from '#test/oracles/openssl';

const ALGORITHMS: CertificateFingerprintAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

const NODE_HASH: Record<CertificateFingerprintAlgorithm, 'sha1' | 'sha256' | 'sha384' | 'sha512'> =
	{
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

	it('throws on malformed input', () => {
		expect(certificateFingerprint('not a pem')).rejects.toThrow();
		expect(certificateFingerprint(new Uint8Array([0x30, 0x00]))).rejects.toThrow();
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

describe('subjectPublicKeyInfoFingerprint', () => {
	it('hashes the complete SPKI and gives the same value to cross-signed certificates', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const issuers = await Promise.all([
			createSelfSignedCertificate({ subject: { commonName: 'Issuer One' } }),
			createSelfSignedCertificate({ subject: { commonName: 'Issuer Two' } }),
		]);
		const createIssued = (issuer: (typeof issuers)[number], commonName: string) =>
			createCertificate({
				issuer: { commonName },
				subject: { commonName: 'same-key.example' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerCertificate: issuer.certificate.der,
				extensions: { keyUsage: ['digitalSignature'] },
			});
		const [one, two] = await Promise.all(
			issuers.map((issuer, index) => createIssued(issuer, `Issuer ${index === 0 ? 'One' : 'Two'}`)),
		);
		if (one === undefined || two === undefined)
			throw new Error('expected two cross-signed certificates');
		const parsed = parseCertificateDerOrThrow(one.der);
		const result = await subjectPublicKeyInfoFingerprint(one.pem);
		const expected = createHash('sha256').update(parsed.subjectPublicKeyInfoDer).digest();
		const [sameSpki, firstCertificate, secondCertificate] = await Promise.all([
			subjectPublicKeyInfoFingerprint(two.der),
			certificateFingerprint(one.der),
			certificateFingerprint(two.der),
		]);
		expect(result.bytes).toEqual(new Uint8Array(expected));
		expect(sameSpki.hex).toBe(result.hex);
		expect(firstCertificate.hex).not.toBe(secondCertificate.hex);
	});

	it('accepts parsed certificates and rejects invalid sources', async () => {
		const { certificate } = await sampleCertificate();
		const parsed = parseCertificatePemOrThrow(certificate.pem);
		const [pem, der, parsedResult] = await Promise.all([
			subjectPublicKeyInfoFingerprint(certificate.pem),
			subjectPublicKeyInfoFingerprint(certificate.der),
			subjectPublicKeyInfoFingerprint(parsed),
		]);
		expect(der.hex).toBe(pem.hex);
		expect(parsedResult.hex).toBe(pem.hex);
		await expectRejectedWith(subjectPublicKeyInfoFingerprint('invalid'), Error);
	});

	it('fingerprints X25519 SPKI without importing the subject key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'X25519 Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const x25519 = await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, true, [
			'deriveBits',
		]);
		const certificate = await createCertificate({
			issuer: { commonName: 'X25519 Issuer' },
			subject: { commonName: 'x25519.example' },
			publicKey: x25519.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			extensions: { keyUsage: ['keyAgreement'] },
		});
		const fingerprint = await subjectPublicKeyInfoFingerprint(certificate.der);
		const verified = await verifyCertificateChain({
			leaf: certificate.der,
			roots: [ca.certificate.der],
		});
		expect(fingerprint.bytes).toHaveLength(32);
		expect(fingerprint.colonHex).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
		expect(verified.ok).toBe(true);
	});

	it('hashes reparsed DER when the parsed SPKI field is caller-mutated', async () => {
		const { certificate } = await sampleCertificate();
		const parsed = parseCertificateDerOrThrow(certificate.der);
		const mutated = { ...parsed, subjectPublicKeyInfoDer: Uint8Array.of(1, 2, 3) };
		const [original, fromMutated] = await Promise.all([
			subjectPublicKeyInfoFingerprint(parsed),
			subjectPublicKeyInfoFingerprint(mutated),
		]);
		expect(fromMutated.bytes).toEqual(original.bytes);
		expect(fromMutated.colonHex).toBe(original.colonHex);
	});

	it('snapshots the SPKI denylist before asynchronous verification starts', async () => {
		const chain = await issueChain();
		const hash = (await subjectPublicKeyInfoFingerprint(chain.leaf.der)).hex;
		const blocked = [hash];
		const blockedVerification = verifyCertificateChain({
			leaf: chain.leaf.der,
			intermediates: [chain.intermediate.der],
			roots: [chain.root.certificate.der],
			distrustedSpkiSha256: blocked,
		});
		blocked.length = 0;
		const blockedResult = await blockedVerification;
		expect(blockedResult).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 0 });

		const initiallyEmpty: string[] = [];
		const allowedVerification = verifyCertificateChain({
			leaf: chain.leaf.der,
			intermediates: [chain.intermediate.der],
			roots: [chain.root.certificate.der],
			distrustedSpkiSha256: initiallyEmpty,
		});
		initiallyEmpty.push(hash);
		const allowedResult = await allowedVerification;
		expect(allowedResult.ok).toBe(true);
	});
});

describe.skipIf(!openSslAvailable || !differentialEnabled)(
	'certificateFingerprint OpenSSL differential',
	() => {
		it.each(ALGORITHMS)(
			'colonHex matches `openssl x509 -fingerprint` for %s',
			async (algorithm) => {
				const { certificate } = await sampleCertificate();

				const fingerprint = await certificateFingerprint(certificate.pem, algorithm);
				const opensslColonHex = await fingerprintCertificateWithOpenSsl({
					certificatePem: certificate.pem,
					algorithm: NODE_HASH[algorithm],
				});

				expect(fingerprint.colonHex).toBe(opensslColonHex);
			},
		);
	},
);
