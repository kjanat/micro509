import { expect, it } from 'bun:test';
import {
	CompactEncrypt,
	compactDecrypt,
	exportPKCS8,
	exportSPKI,
	generateKeyPair as joseGenerate,
} from 'jose-v5';
import type { DecryptJweOptions, EncryptJweInput } from '#micro509/jose';
import {
	base64UrlDecode,
	base64UrlEncode,
	decryptCompactJwe,
	encryptCompactJwe,
} from '#micro509/jose';
import { generateKeyPair, importPkcs8Pem, importSpkiPem } from '#micro509/keys';
import { unwrap } from '#micro509/result';
import { callUntyped } from '#test/helpers';

const independent = await joseGenerate('RSA-OAEP-512', { extractable: true });
// DER rsaEncryption does not encode OAEP hash; bind SHA-512 explicitly on import.
const descriptor = { kind: 'rsa', scheme: 'oaep', hash: 'SHA-512' } as const;
const publicKey = unwrap(await importSpkiPem(await exportSPKI(independent.publicKey), descriptor));
const privateKey = unwrap(
	await importPkcs8Pem(await exportPKCS8(independent.privateKey), descriptor),
);
const other = await generateKeyPair(descriptor);
const policy: DecryptJweOptions = {
	privateKey,
	keyManagementAlgorithms: ['RSA-OAEP-512'],
	contentEncryptionAlgorithms: ['A256GCM'],
};
const header = { alg: 'RSA-OAEP-512', enc: 'A256GCM' } as const;
const bytes = new TextEncoder().encode('café 🦊 / + _ -');
const input: EncryptJweInput = {
	publicKey,
	plaintext: bytes,
	algorithm: 'RSA-OAEP-512',
	encryption: 'A256GCM',
	header: { typ: 'state', custom: true },
};
const independentToken = await new CompactEncrypt(bytes)
	.setProtectedHeader({ ...header, typ: 'state', custom: true })
	.encrypt(independent.publicKey);

function replace(token: string, index: number, segment: string): string {
	const parts = token.split('.');
	parts[index] = segment;
	return parts.join('.');
}
function headerSegment(value: unknown): string {
	return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}
function changed(token: string, index: number): string {
	const segment = token.split('.')[index];
	if (segment === undefined) throw new Error('missing segment');
	const data = base64UrlDecode(segment);
	if (data === undefined || data.length === 0) throw new Error('missing bytes');
	data[0] = (data[0] ?? 0) ^ 1;
	return replace(token, index, base64UrlEncode(data));
}

it('interoperates in both directions with jose 5 PKCS8/SPKI keys and Unicode bytes', async () => {
	const ours = unwrap(await encryptCompactJwe(input));
	const theirs = await compactDecrypt(ours, independent.privateKey, {
		keyManagementAlgorithms: ['RSA-OAEP-512'],
		contentEncryptionAlgorithms: ['A256GCM'],
	});
	expect(theirs.plaintext).toEqual(bytes);
	expect(theirs.protectedHeader).toEqual({ ...header, typ: 'state', custom: true });
	const decrypted = unwrap(await decryptCompactJwe(independentToken, policy));
	expect(decrypted.plaintext).toEqual(bytes);
	expect(decrypted.header.members.custom).toBe(true);
	expect(decrypted.authenticated).toBe(true);
	const another = unwrap(await encryptCompactJwe(input));
	expect(another).not.toBe(ours);
	for (const size of [0, 1, 2, 3, 16_384]) {
		const plaintext = new Uint8Array(size).fill(37);
		const token = unwrap(await encryptCompactJwe({ ...input, plaintext }));
		expect(unwrap(await decryptCompactJwe(token, policy)).plaintext).toEqual(plaintext);
	}
});

it('authenticates the original header spelling and every encrypted part', async () => {
	// A valid JWE produced outside either JOSE implementation with whitespace/order-sensitive AAD.
	const protectedSegment = base64UrlEncode(
		new TextEncoder().encode('{ "enc":"A256GCM", "alg":"RSA-OAEP-512" }'),
	);
	const cek = crypto.getRandomValues(new Uint8Array(32));
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
	const encrypted = new Uint8Array(
		await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv,
				additionalData: new TextEncoder().encode(protectedSegment),
				tagLength: 128,
			},
			aes,
			bytes,
		),
	);
	const wrapped = new Uint8Array(await crypto.subtle.encrypt('RSA-OAEP', publicKey, cek));
	const token = [
		protectedSegment,
		base64UrlEncode(wrapped),
		base64UrlEncode(iv),
		base64UrlEncode(encrypted.subarray(0, -16)),
		base64UrlEncode(encrypted.subarray(-16)),
	].join('.');
	expect(unwrap(await decryptCompactJwe(token, policy)).plaintext).toEqual(bytes);
	const retaggedHeader = replace(token, 0, headerSegment({ ...header, typ: 'changed' }));
	for (const bad of [
		retaggedHeader,
		changed(token, 1),
		changed(token, 2),
		changed(token, 3),
		changed(token, 4),
	])
		expect(await decryptCompactJwe(bad, policy)).toMatchObject({
			code: 'decryption_failed',
			message: 'JWE decryption failed',
		});
	expect(await decryptCompactJwe(token, { ...policy, privateKey: other.privateKey })).toMatchObject(
		{ code: 'decryption_failed' },
	);
});

it('uses the same failure for bad OAEP padding, RSA ciphertext lengths, CEK lengths and tag mismatches', async () => {
	const failures = [
		changed(independentToken, 1),
		changed(independentToken, 4),
		replace(independentToken, 1, ''),
		replace(independentToken, 1, base64UrlEncode(new Uint8Array(255))),
	];
	for (const length of [0, 16, 31, 33]) {
		const wrapped = await crypto.subtle.encrypt('RSA-OAEP', publicKey, new Uint8Array(length));
		failures.push(replace(independentToken, 1, base64UrlEncode(new Uint8Array(wrapped))));
	}
	for (const token of failures)
		expect(await decryptCompactJwe(token, policy)).toEqual({
			ok: false,
			code: 'decryption_failed',
			message: 'JWE decryption failed',
			error: { ok: false, code: 'decryption_failed', message: 'JWE decryption failed' },
		});
});

it('requires both allowlists and refuses disallowed algorithms independently', async () => {
	for (const options of [
		undefined,
		null,
		{},
		{ ...policy, keyManagementAlgorithms: [] },
		{ ...policy, contentEncryptionAlgorithms: [] },
		{ ...policy, keyManagementAlgorithms: ['RSA-OAEP'] },
		{ ...policy, contentEncryptionAlgorithms: ['A128GCM'] },
	])
		expect(await callUntyped(decryptCompactJwe, independentToken, options)).toMatchObject({
			code: 'invalid_options',
		});
	expect(
		await decryptCompactJwe(
			replace(independentToken, 0, headerSegment({ ...header, alg: 'RSA-OAEP' })),
			policy,
		),
	).toMatchObject({ code: 'algorithm_not_allowed' });
	expect(
		await decryptCompactJwe(
			replace(independentToken, 0, headerSegment({ ...header, enc: 'A128GCM' })),
			policy,
		),
	).toMatchObject({ code: 'encryption_not_allowed' });
	expect(await callUntyped(encryptCompactJwe, { ...input, algorithm: 'RSA-OAEP' })).toMatchObject({
		code: 'algorithm_not_allowed',
	});
	expect(await callUntyped(encryptCompactJwe, { ...input, encryption: 'A128GCM' })).toMatchObject({
		code: 'encryption_not_allowed',
	});
});

it('binds key type, OAEP hash, modulus, exponent and operation usage', async () => {
	const rs256 = await generateKeyPair({ kind: 'rsa' });
	const sha256 = await generateKeyPair({ kind: 'rsa', scheme: 'oaep' });
	const ec = await generateKeyPair({ kind: 'ecdsa' });
	for (const key of [privateKey, rs256.publicKey, sha256.publicKey, ec.publicKey])
		expect(await encryptCompactJwe({ ...input, publicKey: key })).toMatchObject({
			code: 'key_unsuitable',
		});
	for (const key of [publicKey, rs256.privateKey, sha256.privateKey, ec.privateKey])
		expect(await decryptCompactJwe(independentToken, { ...policy, privateKey: key })).toMatchObject(
			{ code: 'key_unsuitable' },
		);
	const weak = await crypto.subtle.generateKey(
		{
			name: 'RSA-OAEP',
			modulusLength: 1024,
			hash: 'SHA-512',
			publicExponent: Uint8Array.of(1, 0, 1),
		},
		true,
		['encrypt', 'decrypt'],
	);
	expect(await encryptCompactJwe({ ...input, publicKey: weak.publicKey })).toMatchObject({
		code: 'key_unsuitable',
	});
	const wrapOnly = await crypto.subtle.importKey(
		'spki',
		await crypto.subtle.exportKey('spki', publicKey),
		{ name: 'RSA-OAEP', hash: 'SHA-512' },
		false,
		['wrapKey'],
	);
	expect(await encryptCompactJwe({ ...input, publicKey: wrapOnly })).toMatchObject({
		code: 'key_unsuitable',
	});
	expect(await callUntyped(encryptCompactJwe, { ...input, publicKey: {} })).toMatchObject({
		code: 'key_unsuitable',
	});
});

it('rejects malformed encoding, headers, critical extensions, compression and wrong IV/tag sizes', async () => {
	for (const token of ['', 'a.b.c', 'a.b.c.d.e.f', '.a.a.a.a'])
		expect(await decryptCompactJwe(token, policy)).toMatchObject({ code: 'malformed_token' });
	expect(await callUntyped(decryptCompactJwe, 3, policy)).toMatchObject({
		code: 'malformed_token',
	});
	for (const [index, segment] of [
		[0, 'AA=='],
		[1, '+/8'],
		[2, 'Zh'],
		[3, 'A'],
		[4, '_é'],
	] as const)
		expect(
			await decryptCompactJwe(replace(independentToken, index, segment), policy),
		).toMatchObject({ code: 'invalid_encoding' });
	for (const value of [
		null,
		[],
		{},
		{ alg: 3, enc: 'A256GCM' },
		{ ...header, kid: 1 },
		{ ...header, crit: [] },
		{ ...header, crit: ['absent'] },
		{ ...header, crit: [1] },
		{ ...header, crit: ['x', 'x'], x: true },
	])
		expect(
			(await decryptCompactJwe(replace(independentToken, 0, headerSegment(value)), policy)).ok,
		).toBe(false);
	expect(
		await decryptCompactJwe(
			replace(independentToken, 0, headerSegment({ ...header, x: true, crit: ['x'] })),
			policy,
		),
	).toMatchObject({ code: 'unsupported_critical_header' });
	expect(
		await decryptCompactJwe(
			replace(independentToken, 0, headerSegment({ ...header, zip: 'DEF' })),
			policy,
		),
	).toMatchObject({ code: 'unsupported_compression' });
	for (const [index, length] of [
		[2, 11],
		[4, 15],
	] as const)
		expect(
			await decryptCompactJwe(
				replace(independentToken, index, base64UrlEncode(new Uint8Array(length))),
				policy,
			),
		).toMatchObject({ code: 'malformed_token' });
	const duplicate = '{"alg":"RSA-OAEP-512","enc":"A256GCM","enc":"A256GCM"}';
	expect(
		await decryptCompactJwe(
			replace(independentToken, 0, base64UrlEncode(new TextEncoder().encode(duplicate))),
			policy,
		),
	).toMatchObject({ code: 'duplicate_member' });
	expect(await decryptCompactJwe(replace(independentToken, 0, '_w'), policy)).toMatchObject({
		code: 'invalid_utf8',
	});
});

it('bounds token, plaintext, encrypted CEK, protected header and JSON before crypto', async () => {
	expect(await encryptCompactJwe({ ...input, plaintext: new Uint8Array(16_385) })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(await encryptCompactJwe({ ...input, limits: { maxTokenLength: 20 } })).toMatchObject({
		code: 'token_too_large',
	});
	expect(await encryptCompactJwe({ ...input, limits: { maxSignatureBytes: 10 } })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(await encryptCompactJwe({ ...input, limits: { maxHeaderBytes: 2 } })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(await encryptCompactJwe({ ...input, header: { x: 'x'.repeat(4096) } })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(
		await decryptCompactJwe(independentToken, { ...policy, limits: { maxTokenLength: 20 } }),
	).toMatchObject({ code: 'token_too_large' });
	expect(
		await decryptCompactJwe(independentToken, { ...policy, limits: { maxPayloadBytes: 2 } }),
	).toMatchObject({ code: 'limit_exceeded' });
	expect(
		await decryptCompactJwe(independentToken, { ...policy, limits: { maxSignatureBytes: 200 } }),
	).toMatchObject({ code: 'limit_exceeded' });
	expect(
		await decryptCompactJwe(independentToken, { ...policy, limits: { maxHeaderBytes: 2 } }),
	).toMatchObject({ code: 'limit_exceeded' });
	for (const value of [0, NaN])
		expect(await encryptCompactJwe({ ...input, limits: { maxPayloadBytes: value } })).toMatchObject(
			{ code: 'invalid_options' },
		);
	expect(
		await decryptCompactJwe(independentToken, { ...policy, limits: { maxJsonNodes: 1 } }),
	).toMatchObject({ code: 'limit_exceeded' });
});

it('validates encryption configuration as data, preserving noncritical parameters', async () => {
	for (const value of [null, undefined, {}, { ...input, plaintext: 'not bytes' }])
		expect(await callUntyped(encryptCompactJwe, value)).toMatchObject({ code: 'invalid_options' });
	for (const value of [
		{ alg: 'wrong' },
		{ enc: 'wrong' },
		{ zip: 'DEF' },
		{ crit: ['x'], x: true },
		[],
		null,
		{
			toJSON() {
				throw new Error('must not execute');
			},
		},
	])
		expect((await callUntyped(encryptCompactJwe, { ...input, header: value })).ok).toBe(false);
	const token = unwrap(
		await encryptCompactJwe({
			...input,
			header: { ['__proto__']: { safe: true }, audience: ['a', 'b'] },
		}),
	);
	expect(unwrap(await decryptCompactJwe(token, policy)).header.members.audience).toEqual([
		'a',
		'b',
	]);
});
