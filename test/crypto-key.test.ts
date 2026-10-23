import { describe, expect, it } from 'bun:test';
import {
	ecdsaSignatureDerToRaw,
	signData,
	verifySignature,
	verifySignatureWithKey,
} from '#micro509/crypto';
import {
	explicitContext,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { exportSpkiDer, generateKeyPair } from '#micro509/keys';

const data = new TextEncoder().encode('reused public key');
const cases = [
	{ kind: 'ecdsa', curve: 'P-256' },
	{ kind: 'ecdsa', curve: 'P-384' },
	{ kind: 'ecdsa', curve: 'P-521' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-256' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-384' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-512' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-256', scheme: 'pss' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-384', scheme: 'pss' },
	{ kind: 'rsa', modulusLength: 2048, hash: 'SHA-512', scheme: 'pss' },
	{ kind: 'ed25519' },
] as const;

function publicAlgorithm(algorithm: (typeof cases)[number]) {
	return algorithm.kind === 'ecdsa'
		? {
				oid: '1.2.840.10045.2.1',
				parametersOid:
					algorithm.curve === 'P-256'
						? '1.2.840.10045.3.1.7'
						: algorithm.curve === 'P-384'
							? '1.3.132.0.34'
							: '1.3.132.0.35',
			}
		: { oid: algorithm.kind === 'rsa' ? '1.2.840.113549.1.1.1' : '1.3.101.112' };
}

describe('verifySignatureWithKey', () => {
	for (const algorithm of cases) {
		it(`reuses ${JSON.stringify(algorithm)} and matches SPKI verification`, async () => {
			const keys = await generateKeyPair(algorithm);
			const wrong = await generateKeyPair(algorithm);
			const signed = await signData(
				keys.privateKey,
				data,
				algorithm.kind === 'rsa' && 'scheme' in algorithm ? { kind: 'rsa-pss' } : undefined,
			);
			const signatureAlgorithm = {
				oid: signed.algorithmOid,
				...(signed.parametersDer === undefined ? {} : { parametersDer: signed.parametersDer }),
			};
			const input = {
				publicKey: keys.publicKey,
				signatureAlgorithm,
				signatureEncoding: algorithm.kind === 'ecdsa' ? 'der' : 'raw',
				signature: signed.signature,
				data,
			} as const;
			expect(await verifySignatureWithKey(input)).toEqual({ ok: true, valid: true });
			expect(await verifySignatureWithKey(input)).toEqual({ ok: true, valid: true });
			expect(await verifySignatureWithKey({ ...input, data: Uint8Array.of(0) })).toEqual({
				ok: true,
				valid: false,
			});
			expect(await verifySignatureWithKey({ ...input, publicKey: wrong.publicKey })).toEqual({
				ok: true,
				valid: false,
			});
			const changed = signed.signature.slice();
			changed[changed.length - 1] = (changed[changed.length - 1] ?? 0) ^ 1;
			expect(await verifySignatureWithKey({ ...input, signature: changed })).toEqual({
				ok: true,
				valid: false,
			});
			const publicKeyAlgorithm = publicAlgorithm(algorithm);
			expect(
				await verifySignature({
					signerSpkiDer: await exportSpkiDer(keys.publicKey),
					signatureAlgorithm,
					publicKeyAlgorithm,
					signature: signed.signature,
					data,
				}),
			).toEqual(await verifySignatureWithKey(input));
			if (algorithm.kind === 'ecdsa') {
				const raw = ecdsaSignatureDerToRaw(signed.signature, algorithm.curve);
				expect(
					await verifySignatureWithKey({ ...input, signatureEncoding: 'raw', signature: raw }),
				).toEqual({ ok: true, valid: true });
				expect(await verifySignatureWithKey({ ...input, signatureEncoding: 'raw' })).toEqual({
					ok: true,
					valid: false,
				});
				expect(await verifySignatureWithKey({ ...input, signature: raw })).toEqual({
					ok: true,
					valid: false,
				});
			} else {
				expect(await verifySignatureWithKey({ ...input, signatureEncoding: 'der' })).toMatchObject({
					ok: false,
					code: 'unsupported_signature_algorithm_parameters',
				});
			}
		});
	}

	it('rejects malformed ECDSA DER including trailing bytes', async () => {
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const signed = await signData(keys.privateKey, data);
		for (const signature of [
			Uint8Array.of(0x30, 0),
			Uint8Array.of(0x30, 0x06, 2, 1, 0x80, 2, 1, 1),
			new Uint8Array([...signed.signature, 0]),
		]) {
			expect(
				await verifySignatureWithKey({
					publicKey: keys.publicKey,
					signatureAlgorithm: { oid: signed.algorithmOid },
					signatureEncoding: 'der',
					signature,
					data,
				}),
			).toEqual({ ok: true, valid: false });
		}
	});

	it('preserves RSA-PSS parameter policy and verifies the declared salt length', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', scheme: 'pss', modulusLength: 2048 });
		const signed = await signData(keys.privateKey, data, { kind: 'rsa-pss' });
		const input = {
			publicKey: keys.publicKey,
			signatureAlgorithm: { oid: signed.algorithmOid, parametersDer: signed.parametersDer },
			signatureEncoding: 'raw',
			signature: signed.signature,
			data,
		} as const;
		const wrongSaltSignature = new Uint8Array(
			await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 16 }, keys.privateKey, data),
		);
		expect(await verifySignatureWithKey({ ...input, signature: wrongSaltSignature })).toEqual({
			ok: true,
			valid: false,
		});
		const hashAlgorithm = (oid: string) => sequence([objectIdentifier(oid), nullValue()]);
		const parameters = (hash: string, mgf: string, mgfHash: string, salt: number) =>
			sequence([
				explicitContext(0, hashAlgorithm(hash)),
				explicitContext(1, sequence([objectIdentifier(mgf), hashAlgorithm(mgfHash)])),
				explicitContext(2, integerFromNumber(salt)),
			]);
		for (const parametersDer of [
			parameters(OIDS.sha256, OIDS.mgf1, OIDS.sha256, 16),
			parameters(OIDS.sha1, OIDS.mgf1, OIDS.sha1, 20),
			parameters(OIDS.sha256, OIDS.mgf1, OIDS.sha384, 32),
			parameters(OIDS.sha256, OIDS.sha256, OIDS.sha256, 32),
		]) {
			expect(
				await verifySignatureWithKey({
					...input,
					signatureAlgorithm: { oid: signed.algorithmOid, parametersDer },
				}),
			).toMatchObject({ ok: false, code: 'unsupported_signature_algorithm_parameters' });
		}
	});

	it('verifies a directly imported non-extractable RS256 public key', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
		const publicKey = await crypto.subtle.importKey(
			'jwk',
			jwk,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false,
			['verify'],
		);
		const signed = await signData(keys.privateKey, data);
		const input = {
			publicKey,
			signatureAlgorithm: { oid: signed.algorithmOid },
			signatureEncoding: 'raw',
			signature: signed.signature,
			data,
		} as const;
		expect(
			await verifySignatureWithKey({
				...input,
				signatureAlgorithm: {
					oid: signed.algorithmOid,
					parametersDer: Uint8Array.of(0x1f, 0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x00),
				},
			}),
		).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(publicKey.extractable).toBe(false);
		expect(await verifySignatureWithKey(input)).toEqual({ ok: true, valid: true });
		expect(await verifySignatureWithKey(input)).toEqual({ ok: true, valid: true });
		expect(await verifySignatureWithKey({ ...input, publicKey: keys.privateKey })).toMatchObject({
			ok: false,
			code: 'verification_error',
		});
		const noUsage = await crypto.subtle.importKey(
			'jwk',
			{ ...jwk, key_ops: [] },
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false,
			[],
		);
		expect(await verifySignatureWithKey({ ...input, publicKey: noUsage })).toMatchObject({
			ok: false,
			code: 'verification_error',
		});
		for (const oid of ['1.2.840.113549.1.1.12', '1.2.840.113549.1.1.10', '1.2.3', '1.3.101.112']) {
			expect(await verifySignatureWithKey({ ...input, signatureAlgorithm: { oid } })).toMatchObject(
				{ ok: false, code: 'unsupported_signature_algorithm_parameters' },
			);
		}
		const pss = await generateKeyPair({ kind: 'rsa', scheme: 'pss', modulusLength: 2048 });
		const pssSigned = await signData(pss.privateKey, data, { kind: 'rsa-pss' });
		expect(
			await verifySignatureWithKey({
				...input,
				signatureAlgorithm: { oid: pssSigned.algorithmOid, parametersDer: pssSigned.parametersDer },
			}),
		).toMatchObject({ ok: false, code: 'unsupported_signature_algorithm_parameters' });
	});
});
