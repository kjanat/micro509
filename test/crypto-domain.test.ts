import { describe, expect, it } from 'bun:test';
import {
	ecdsaSignatureDerToRaw,
	ecdsaSignatureRawToDer,
	signData,
	verifySignature,
	verifySignatureWithKey,
} from '#micro509/crypto';
import { exportSpkiDer, generateKeyPair } from '#micro509/keys';
import {
	createPkcs7SignedData,
	parsePkcs7SignedDataDer,
	verifyPkcs7SignedData,
} from '#micro509/pkcs';
import { unwrap } from '#micro509/result';
import { verifyCertificateChain } from '#micro509/verify';
import {
	createCertificate,
	createSelfSignedCertificate,
	parseCertificateDer,
	parseCertificatePem,
} from '#micro509/x509';
import {
	digestInfoVariants,
	pkcs8 as exponentThreePkcs8,
	findOddDigest,
	forgeExponentThreeSignature,
	modulusLength,
	oddDigestMessage,
	recoverEncodedMessage,
	signDigestInfo,
} from './fixtures/rsa-exponent-three.mjs';

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

	it.each([
		['empty r', Uint8Array.of(0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01)],
		['empty s', Uint8Array.of(0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00)],
		['negative r', Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01)],
		['negative s', Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x80)],
		['non-minimal r', Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01)],
		['non-minimal s', Uint8Array.of(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01)],
	] as const)('rejects an ECDSA DER signature with %s', (_name, signature) => {
		expect(() => ecdsaSignatureDerToRaw(signature, 'P-256')).toThrow();
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

const rsaEncryption = '1.2.840.113549.1.1.1';
const sha256WithRsaEncryption = '1.2.840.113549.1.1.11';
const pkcs1Sha256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

const advisoryDigestInfoShapes = [
	'absent parameters',
	'NULL parameters with content',
	'long-form DigestInfo length',
	'long-form DigestAlgorithm length',
	'long-form OID length',
	'long-form NULL length',
	'long-form digest length',
	'indefinite DigestInfo length',
	'constructed parameters',
	'INTEGER parameters',
	'padded OID subidentifier',
	'octets after the DigestInfo',
] as const;

async function exponentThreeKeys() {
	const privateKey = await crypto.subtle.importKey(
		'pkcs8',
		Uint8Array.from(atob(exponentThreePkcs8), (char) => char.charCodeAt(0)),
		pkcs1Sha256,
		true,
		['sign'],
	);
	const { n, e } = await crypto.subtle.exportKey('jwk', privateKey);
	const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n, e }, pkcs1Sha256, true, [
		'verify',
	]);
	return {
		privateKey,
		publicKey,
		spki: await exportSpkiDer(publicKey),
		modulusBytes: await modulusLength(publicKey),
	};
}

async function verifyBothWays(
	keys: Awaited<ReturnType<typeof exponentThreeKeys>>,
	signature: Uint8Array,
	data: Uint8Array,
) {
	const bySpki = await verifySignature({
		signerSpkiDer: keys.spki,
		signatureAlgorithm: { oid: sha256WithRsaEncryption },
		publicKeyAlgorithm: { oid: rsaEncryption },
		signature,
		data,
	});
	const byKey = await verifySignatureWithKey({
		publicKey: keys.publicKey,
		signatureAlgorithm: { oid: sha256WithRsaEncryption },
		signatureEncoding: 'raw',
		signature,
		data,
	});
	if (!bySpki.ok) throw new Error(bySpki.code);
	if (!byKey.ok) throw new Error(byKey.code);
	return { bySpki: bySpki.valid, byKey: byKey.valid };
}

describe('RFC 8017 §8.2.2 RSASSA-PKCS1-v1_5 verification for public exponent 3 (GHSA-6qrw-m8cv-hcxf)', () => {
	it('the odd-digest search stops after 64 attempts with a named error', async () => {
		let evenDigestBytes: Uint8Array | undefined;
		for (let attempt = 0; attempt < 64 && evenDigestBytes === undefined; attempt += 1) {
			const bytes = encoder.encode(`even digest ${attempt}`);
			const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
			if (((digest[31] ?? 0) & 1) === 0) evenDigestBytes = bytes;
		}
		if (evenDigestBytes === undefined) throw new Error('no even SHA-256 digest found');
		const signedBytes = evenDigestBytes;
		const attempts: number[] = [];
		const error = await findOddDigest('exhaustion probe', async (attempt) => {
			attempts.push(attempt);
			return { value: attempt, signedBytes };
		}).then(
			() => undefined,
			(rejection: unknown) => rejection,
		);
		expect(error).toBeInstanceOf(Error);
		expect(String(error)).toContain('exhaustion probe: no odd SHA-256 digest in 64 attempts');
		expect(attempts).toEqual(Array.from({ length: 64 }, (_, attempt) => attempt));
	});

	it('the fixture lists the canonical DigestInfo and every advisory shape', () => {
		const variants = digestInfoVariants(new Uint8Array(32));
		expect(variants.filter((variant) => variant.valid).map((variant) => variant.name)).toEqual([
			'canonical DER',
		]);
		expect(variants.filter((variant) => !variant.valid).map((variant) => variant.name)).toEqual([
			...advisoryDigestInfoShapes,
		]);
		expect(new Set(variants.map((variant) => variant.name)).size).toBe(13);
	});

	it('step 4: only the DER DigestInfo of §9.2 verifies; every advisory shape is an invalid signature', async () => {
		const keys = await exponentThreeKeys();
		const data = encoder.encode('GHSA-6qrw-m8cv-hcxf');
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
		const variants = digestInfoVariants(digest);
		const native = new Uint8Array(await crypto.subtle.sign(pkcs1Sha256, keys.privateKey, data));
		const actual: Record<string, { bySpki: boolean; byKey: boolean }> = {};
		for (const variant of variants) {
			const signature = await signDigestInfo(keys.privateKey, variant.digestInfo);
			if (variant.valid) expect(signature).toEqual(native);
			actual[variant.name] = await verifyBothWays(keys, signature, data);
		}
		expect(actual).toEqual({
			'canonical DER': { bySpki: true, byKey: true },
			...Object.fromEntries(
				advisoryDigestInfoShapes.map((name) => [name, { bySpki: false, byKey: false }]),
			),
		});
	});

	it('refuses a cube-root forgery built without the private key whose recovered digest matches', async () => {
		const keys = await exponentThreeKeys();
		expect(keys.modulusBytes).toBe(256);
		const { data, digest } = await oddDigestMessage('GHSA-6qrw-m8cv-hcxf forgery');
		const forged = forgeExponentThreeSignature(digest, keys.modulusBytes);
		const recovered = await recoverEncodedMessage(keys.publicKey, forged);
		expect(recovered.subarray(0, 11)).toEqual(Uint8Array.of(0, 1, ...new Array(8).fill(0xff), 0));
		expect(recovered.subarray(11, 17)).toEqual(Uint8Array.of(0x30, 0x81, 0xf2, 0x30, 0x81, 0xcd));
		expect(recovered.subarray(28, 31)).toEqual(Uint8Array.of(0x05, 0x81, 0xbf));
		expect(recovered.subarray(-34)).toEqual(Uint8Array.of(0x04, 0x20, ...digest));
		expect(await verifyBothWays(keys, forged, data)).toEqual({ bySpki: false, byKey: false });
	});

	it('refuses a certificate whose signature is a cube-root forgery under an e=3 issuer', async () => {
		const keys = await exponentThreeKeys();
		const root = await createCertificate({
			issuer: { commonName: 'Exponent Three Root' },
			subject: { commonName: 'Exponent Three Root' },
			publicKey: keys.publicKey,
			signerPrivateKey: keys.privateKey,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const { value: leaf, digest } = await findOddDigest('certificate', async (attempt) => {
			const issued = await createCertificate({
				issuer: { commonName: 'Exponent Three Root' },
				subject: { commonName: 'forged.example' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: keys.privateKey,
				issuerCertificate: root.der,
				serialNumber: Uint8Array.of(attempt + 1),
				extensions: { keyUsage: ['digitalSignature'] },
			});
			const parsed = unwrap(parseCertificateDer(issued.der));
			return { value: { der: issued.der, parsed }, signedBytes: parsed.tbsCertificateDer };
		});
		const signature = leaf.parsed.signatureValue;
		expect(signature).toHaveLength(keys.modulusBytes);
		expect(leaf.der.subarray(-signature.length)).toEqual(signature);
		const forgedDer = leaf.der.slice();
		forgedDer.set(
			forgeExponentThreeSignature(digest, signature.length),
			forgedDer.length - signature.length,
		);
		const forgedParsed = unwrap(parseCertificateDer(forgedDer));
		expect(forgedParsed.tbsCertificateDer).toEqual(leaf.parsed.tbsCertificateDer);
		expect(forgedParsed.signatureValue).not.toEqual(signature);
		expect(await verifyCertificateChain({ leaf: leaf.der, roots: [root.der] })).toMatchObject({
			ok: true,
		});
		expect(await verifyCertificateChain({ leaf: forgedDer, roots: [root.der] })).toMatchObject({
			ok: false,
			code: 'signature_invalid',
			index: 0,
		});
	});

	it('refuses a CMS SignerInfo whose signature is a cube-root forgery under an e=3 signer', async () => {
		const keys = await exponentThreeKeys();
		const signer = await createCertificate({
			issuer: { commonName: 'Exponent Three Signer' },
			subject: { commonName: 'Exponent Three Signer' },
			publicKey: keys.publicKey,
			signerPrivateKey: keys.privateKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const { value: signed, digest } = await findOddDigest('CMS SignerInfo', async (attempt) => {
			const created = unwrap(
				await createPkcs7SignedData({
					content: encoder.encode(`GHSA-6qrw-m8cv-hcxf CMS ${attempt}`),
					signers: [{ certificate: signer.der, privateKey: keys.privateKey }],
				}),
			);
			const signerInfo = unwrap(parsePkcs7SignedDataDer(created.der)).signerInfos[0];
			if (signerInfo?.hasSignedAttrs !== true) throw new Error('expected signed attributes');
			const signedBytes = signerInfo.signedAttrsDer.slice();
			signedBytes[0] = 0x31;
			return { value: { der: created.der, signature: signerInfo.signature }, signedBytes };
		});
		expect(signed.signature).toHaveLength(keys.modulusBytes);
		expect(signed.der.subarray(-signed.signature.length)).toEqual(signed.signature);
		const forgedDer = signed.der.slice();
		forgedDer.set(
			forgeExponentThreeSignature(digest, signed.signature.length),
			forgedDer.length - signed.signature.length,
		);
		expect(await verifyPkcs7SignedData(signed.der)).toMatchObject({ ok: true });
		expect(await verifyPkcs7SignedData(forgedDer)).toMatchObject({
			ok: false,
			code: 'signature_invalid',
		});
	});
});
