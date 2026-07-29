import { describe, expect, it } from 'bun:test';
import {
	ecdsaSignatureDerToRaw,
	ecdsaSignatureRawToDer,
	signData,
	verifySignature,
} from '#micro509/crypto';
import { exportSpkiDer, generateKeyPair } from '#micro509/keys';
import { unwrap } from '#micro509/result';
import { createSelfSignedCertificate, parseCertificatePem } from '#micro509/x509';

const encoder = new TextEncoder();

describe('crypto domain', () => {
	const cases = [
		{ name: 'ECDSA P-256', algorithm: { kind: 'ecdsa', curve: 'P-256' } },
		{ name: 'ECDSA P-384', algorithm: { kind: 'ecdsa', curve: 'P-384' } },
		{ name: 'ECDSA P-521', algorithm: { kind: 'ecdsa', curve: 'P-521' } },
		{ name: 'RSA PKCS#1 v1.5', algorithm: { kind: 'rsa', modulusLength: 2048 } },
		{ name: 'Ed25519', algorithm: { kind: 'ed25519' } },
	] as const;

	for (const testCase of cases) {
		it(`signData output verifies through verifySignature (${testCase.name})`, async () => {
			const { certificate, keyPair } = await createSelfSignedCertificate({
				subject: { commonName: `sig.${testCase.name}` },
				algorithm: testCase.algorithm,
			});
			const parsed = unwrap(parseCertificatePem(certificate.pem));
			const data = encoder.encode('detached payload');
			const signed = await signData(keyPair.privateKey, data);

			const result = await verifySignature({
				signerSpkiDer: parsed.subjectPublicKeyInfoDer,
				signatureAlgorithm: {
					oid: signed.algorithmOid,
					...(signed.parametersDer === undefined ? {} : { parametersDer: signed.parametersDer }),
				},
				publicKeyAlgorithm: {
					oid: parsed.publicKeyAlgorithmOid,
					...(parsed.publicKeyParametersOid === undefined
						? {}
						: { parametersOid: parsed.publicKeyParametersOid }),
				},
				signature: signed.signature,
				data,
			});
			expect(result.ok).toBe(true);
			if (!result.ok) throw new Error(result.code);
			expect(result.valid).toBe(true);

			const tampered = await verifySignature({
				signerSpkiDer: parsed.subjectPublicKeyInfoDer,
				signatureAlgorithm: { oid: signed.algorithmOid },
				publicKeyAlgorithm: {
					oid: parsed.publicKeyAlgorithmOid,
					...(parsed.publicKeyParametersOid === undefined
						? {}
						: { parametersOid: parsed.publicKeyParametersOid }),
				},
				signature: signed.signature,
				data: encoder.encode('other payload'),
			});
			expect(tampered.ok).toBe(true);
			if (!tampered.ok) throw new Error(tampered.code);
			expect(tampered.valid).toBe(false);
		});
	}

	it('verifySignature returns the unsupported-algorithm failure branch', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const spki = await exportSpkiDer(keyPair.publicKey);
		const result = await verifySignature({
			signerSpkiDer: spki,
			signatureAlgorithm: { oid: '1.2.3.4' },
			publicKeyAlgorithm: { oid: '1.2.840.10045.2.1', parametersOid: '1.2.840.10045.3.1.7' },
			signature: Uint8Array.of(0x00),
			data: Uint8Array.of(0x00),
		});
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error('unreachable');
		expect(result.code).toBe('unsupported_signature_algorithm_parameters');
	});

	it('ECDSA signatures round-trip between DER and raw per curve width', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const signed = await signData(keyPair.privateKey, encoder.encode('ecdsa'));

		const raw = ecdsaSignatureDerToRaw(signed.signature, 'P-256');
		expect(raw).toHaveLength(64);
		const der = ecdsaSignatureRawToDer(raw, 'P-256');
		expect(ecdsaSignatureDerToRaw(der, 'P-256')).toEqual(raw);

		expect(() => ecdsaSignatureRawToDer(raw, 'P-384')).toThrow(
			'Unexpected ECDSA raw signature length',
		);
		expect(() => ecdsaSignatureDerToRaw(Uint8Array.of(0x30, 0x00), 'P-256')).toThrow();
	});

	it.each<['P-384' | 'P-521', number]>([
		['P-384', 96],
		['P-521', 132],
	])('converts %s signatures at their %i-byte raw width', (curve, width) => {
		const raw = new Uint8Array(width).fill(0x5a);
		const der = ecdsaSignatureRawToDer(raw, curve);
		expect(ecdsaSignatureDerToRaw(der, curve)).toEqual(raw);
	});

	it('verifySignature accepts a raw ECDSA signature via the alternate-encoding retry', async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: 'raw-ecdsa.example' },
			algorithm: { kind: 'ecdsa', curve: 'P-256' },
		});
		const parsed = unwrap(parseCertificatePem(certificate.pem));
		const data = encoder.encode('raw signature');
		const signed = await signData(keyPair.privateKey, data);

		const result = await verifySignature({
			signerSpkiDer: parsed.subjectPublicKeyInfoDer,
			signatureAlgorithm: { oid: signed.algorithmOid },
			publicKeyAlgorithm: {
				oid: parsed.publicKeyAlgorithmOid,
				...(parsed.publicKeyParametersOid === undefined
					? {}
					: { parametersOid: parsed.publicKeyParametersOid }),
			},
			signature: ecdsaSignatureDerToRaw(signed.signature, 'P-256'),
			data,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.code);
		expect(result.valid).toBe(true);
	});

	it('signData resolves RSA-PSS only with an explicit profile, and the output verifies', async () => {
		const keyPair = await generateKeyPair({ kind: 'rsa', scheme: 'pss', modulusLength: 2048 });
		expect(signData(keyPair.privateKey, Uint8Array.of(1))).rejects.toThrow(
			'RSA-PSS signing requires an explicit signature profile',
		);
		const data = encoder.encode('pss payload');
		const signed = await signData(keyPair.privateKey, data, { kind: 'rsa-pss' });
		expect(signed.algorithmOid).toBe('1.2.840.113549.1.1.10');
		expect(signed.parametersDer).toBeInstanceOf(Uint8Array);
		if (signed.parametersDer === undefined) throw new Error('expected RSA-PSS parameters');

		const spki = await exportSpkiDer(keyPair.publicKey);
		const result = await verifySignature({
			signerSpkiDer: spki,
			signatureAlgorithm: { oid: signed.algorithmOid, parametersDer: signed.parametersDer },
			publicKeyAlgorithm: { oid: '1.2.840.113549.1.1.1' },
			signature: signed.signature,
			data,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.code);
		expect(result.valid).toBe(true);
	});
});
