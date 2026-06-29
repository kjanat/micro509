import { describe, expect, it } from 'bun:test';
import {
	createPkcs7SignedDataDer,
	createPkcs7SignedDataPem,
	createSelfSignedCertificate,
	parsePkcs7SignedDataDer,
	verifyPkcs7SignedData,
} from 'micro509';
import type { KeyAlgorithmInput } from 'micro509/keys';

const encoder = new TextEncoder();

/** Mints a self-signed signing identity with the digitalSignature key usage. */
async function signingIdentity(commonName: string, algorithm?: KeyAlgorithmInput) {
	return createSelfSignedCertificate({
		subject: { commonName },
		...(algorithm === undefined ? {} : { algorithm }),
		extensions: { keyUsage: ['digitalSignature'] },
	});
}

describe('createPkcs7SignedData', () => {
	const cases: ReadonlyArray<{
		readonly name: string;
		readonly algorithm: KeyAlgorithmInput;
		readonly digest: string;
	}> = [
		{ name: 'ECDSA P-256', algorithm: { kind: 'ecdsa', curve: 'P-256' }, digest: 'SHA-256' },
		{ name: 'ECDSA P-384', algorithm: { kind: 'ecdsa', curve: 'P-384' }, digest: 'SHA-384' },
		{ name: 'ECDSA P-521', algorithm: { kind: 'ecdsa', curve: 'P-521' }, digest: 'SHA-512' },
		{ name: 'RSA-2048', algorithm: { kind: 'rsa', modulusLength: 2048 }, digest: 'SHA-256' },
		{ name: 'Ed25519', algorithm: { kind: 'ed25519' }, digest: 'SHA-512' },
	];

	for (const testCase of cases) {
		it(`signs and verifies a round-trip (${testCase.name})`, async () => {
			const signer = await signingIdentity(`Signer ${testCase.name}`, testCase.algorithm);
			const content = encoder.encode('hello cms');
			const signed = await createPkcs7SignedDataPem({
				content,
				signers: [{ certificate: signer.certificate.pem, privateKey: signer.keyPair.privateKey }],
			});
			expect(signed.ok).toBe(true);
			if (!signed.ok) throw new Error(signed.error.code);

			const result = await verifyPkcs7SignedData(signed.value.pem);
			expect(result.ok).toBe(true);
			if (!result.ok) throw new Error(result.error.code);
			expect(result.value.signerInfos).toHaveLength(1);
			expect(result.value.signerInfos[0]?.hasSignedAttrs).toBe(true);
			expect(result.value.signerInfos[0]?.digestAlgorithmName).toBe(testCase.digest);
			expect(result.value.encapsulatedContent).toEqual(content);
		});
	}

	it('round-trips through parse before verify', async () => {
		const signer = await signingIdentity('Parse Signer');
		const content = encoder.encode('parse then verify');
		const der = await createPkcs7SignedDataDer({
			content,
			signers: [{ certificate: signer.certificate.pem, privateKey: signer.keyPair.privateKey }],
		});
		expect(der.ok).toBe(true);
		if (!der.ok) throw new Error(der.error.code);

		const parsed = parsePkcs7SignedDataDer(der.value);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error(parsed.error.code);
		expect(parsed.value.version).toBe(1);
		expect(parsed.value.certificates).toHaveLength(1);

		const verified = await verifyPkcs7SignedData(parsed.value);
		expect(verified.ok).toBe(true);
	});

	it('rejects a tampered signature', async () => {
		const signer = await signingIdentity('Tamper Signer');
		const content = encoder.encode('original content');
		const der = await createPkcs7SignedDataDer({
			content,
			signers: [{ certificate: signer.certificate.pem, privateKey: signer.keyPair.privateKey }],
		});
		expect(der.ok).toBe(true);
		if (!der.ok) throw new Error(der.error.code);
		const tampered = new Uint8Array(der.value);
		// Corrupt the final byte (inside the signature OCTET STRING).
		tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0xff;

		const result = await verifyPkcs7SignedData(tampered);
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('signature_invalid');
	});

	it('verifies multiple signers and embeds every signer certificate', async () => {
		const first = await signingIdentity('Signer A', { kind: 'ecdsa', curve: 'P-256' });
		const second = await signingIdentity('Signer B', { kind: 'ed25519' });
		const content = encoder.encode('two signers');
		const der = await createPkcs7SignedDataDer({
			content,
			signers: [
				{ certificate: first.certificate.pem, privateKey: first.keyPair.privateKey },
				{ certificate: second.certificate.pem, privateKey: second.keyPair.privateKey },
			],
		});
		expect(der.ok).toBe(true);
		if (!der.ok) throw new Error(der.error.code);

		const result = await verifyPkcs7SignedData(der.value);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.error.code);
		expect(result.value.signerInfos).toHaveLength(2);
		expect(result.value.certificates).toHaveLength(2);
	});

	it('embeds additional certificates without duplicating the signer', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Extra CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
		});
		const signer = await signingIdentity('Signer With Chain');
		const der = await createPkcs7SignedDataDer({
			content: encoder.encode('with chain'),
			signers: [{ certificate: signer.certificate.pem, privateKey: signer.keyPair.privateKey }],
			additionalCertificates: [ca.certificate.pem, signer.certificate.pem],
		});
		expect(der.ok).toBe(true);
		if (!der.ok) throw new Error(der.error.code);

		const result = await verifyPkcs7SignedData(der.value);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.error.code);
		// signer + CA, deduplicated (signer also passed via additionalCertificates).
		expect(result.value.certificates).toHaveLength(2);
	});

	it('returns no_signers when no signers are provided', async () => {
		const result = await createPkcs7SignedDataDer({ content: encoder.encode('x'), signers: [] });
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('no_signers');
	});

	it('returns invalid_signer_certificate when a signer source is not one cert', async () => {
		const a = await signingIdentity('Multi A');
		const b = await signingIdentity('Multi B');
		const result = await createPkcs7SignedDataDer({
			content: encoder.encode('x'),
			signers: [
				{
					certificate: a.certificate.pem + b.certificate.pem,
					privateKey: a.keyPair.privateKey,
				},
			],
		});
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.error.code).toBe('invalid_signer_certificate');
	});
});
