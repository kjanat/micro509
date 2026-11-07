import { expect, it } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { importPrivateKeyPem as rootImport } from '#micro509';
import {
	bitString,
	integerFromNumber,
	objectIdentifier,
	octetString,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { signJwt, verifyJwt } from '#micro509/jose';
import {
	exportEncryptedPkcs1Pem,
	exportEncryptedPkcs8Pem,
	exportEncryptedSec1Pem,
	exportPkcs1Pem,
	exportSec1Pem,
	generateKeyPair,
	importEncryptedPkcs8Pem,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Der,
	importPkcs8Pem,
	importPkcs8PemOrThrow,
	importPrivateJwk,
	importPrivateJwkOrThrow,
	importPrivateKeyPem,
	importPrivateKeyPemOrThrow,
	importPublicJwk,
	importPublicJwkOrThrow,
	importSec1Der,
	importSpkiDer,
	importSpkiPem,
} from '#micro509/keys';
import { pemEncode } from '#micro509/pem';
import { isResultError, unwrap } from '#micro509/result';
import { callUntyped, joseTestKeys, openSslAvailable } from '#test/helpers';

const [rsa] = await joseTestKeys();
const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });

it('dispatches single private-key labels using existing importers, inference and explicit descriptors', async () => {
	expect(rootImport).toBe(importPrivateKeyPem);
	const cases = [
		[await rsa.exportPkcs8Pem(), rsa.publicKey],
		[await exportPkcs1Pem(rsa.privateKey), rsa.publicKey],
		[await exportSec1Pem(ec.privateKey), ec.publicKey],
	] as const;
	for (const [pem, publicKey] of cases) {
		const key = unwrap(await importPrivateKeyPem(`metadata\n${pem}`));
		const algorithm = key.algorithm.name === 'ECDSA' ? 'ES256' : 'RS256';
		const token = await signJwt({
			privateKey: key,
			algorithm,
			claims: { iss: 'a', aud: 'b', exp: 200 },
		});
		expect(
			(
				await verifyJwt(token, {
					key: publicKey,
					algorithms: [algorithm],
					tokenType: { unchecked: true },
					claims: { issuer: 'a', audience: 'b', now: () => new Date(100_000) },
				})
			).ok,
		).toBe(true);
	}
	const sha512 = unwrap(
		await importPrivateKeyPem(await exportPkcs1Pem(rsa.privateKey), {
			kind: 'rsa',
			scheme: 'oaep',
			hash: 'SHA-512',
		}),
	);
	expect(sha512.algorithm).toMatchObject({ name: 'RSA-OAEP', hash: { name: 'SHA-512' } });
	expect(sha512.usages).toEqual(['decrypt']);
	const ed = await generateKeyPair({ kind: 'ed25519' });
	expect(unwrap(await importPrivateKeyPem(await ed.exportPkcs8Pem())).algorithm.name).toBe(
		'Ed25519',
	);
});

it('rejects bundles, unsupported containers, encrypted keys, broken armor and family/curve mismatches', async () => {
	const pem = await rsa.exportPkcs8Pem();
	const cases = [
		[pem + pem, 'multiple_blocks'],
		[pem + pemEncode('CERTIFICATE', Uint8Array.of(1)), 'multiple_blocks'],
		['', 'unsupported_container'],
		[await rsa.exportSpkiPem(), 'unsupported_container'],
		[pemEncode('OPENSSH PRIVATE KEY', Uint8Array.of(1)), 'unsupported_container'],
		[
			await exportEncryptedPkcs8Pem(rsa.privateKey, { password: 'secret', iterations: 1 }),
			'encrypted_key',
		],
		[await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'secret' }), 'encrypted_key'],
		[await exportEncryptedSec1Pem(ec.privateKey, { password: 'secret' }), 'encrypted_key'],
	] as const;
	for (const [input, reason] of cases)
		expect(await importPrivateKeyPem(input)).toMatchObject({
			code: 'malformed',
			details: { stage: 'container', reason },
		});
	expect(
		await importPrivateKeyPem('-----BEGIN PRIVATE KEY-----\nAA==\n-----END PUBLIC KEY-----'),
	).toMatchObject({ details: { stage: 'pem', reason: 'invalid_armor' } });
	for (const input of [pem, await exportPkcs1Pem(rsa.privateKey)])
		expect(await importPrivateKeyPem(input, { kind: 'ecdsa', curve: 'P-256' })).toMatchObject({
			details: { stage: 'algorithm', reason: 'algorithm_mismatch' },
		});
	expect(
		await importPrivateKeyPem(await exportSec1Pem(ec.privateKey), { kind: 'rsa' }),
	).toMatchObject({ details: { stage: 'algorithm', reason: 'algorithm_mismatch' } });
	expect(
		await importPrivateKeyPem(await exportSec1Pem(ec.privateKey), {
			kind: 'ecdsa',
			curve: 'P-384',
		}),
	).toMatchObject({ details: { stage: 'algorithm', reason: 'algorithm_mismatch' } });
});

it('reports safe stages through result.error, flattened result, OrThrow and unwrap', async () => {
	const badBody = '-----BEGIN PRIVATE KEY-----\nAB==\n-----END PRIVATE KEY-----';
	const badDer = pemEncode('PRIVATE KEY', Uint8Array.of(0x30, 0));
	for (const [input, stage, reason] of [
		[badBody, 'base64', 'invalid_base64'],
		[badDer, 'asn1', 'invalid_asn1'],
	] as const) {
		const result = await importPkcs8Pem(input);
		expect(result).toMatchObject({
			code: 'malformed',
			details: { container: 'pkcs8', stage, reason },
		});
		if (result.ok) throw new Error('unexpected import');
		expect(result.details).toEqual(result.error.details);
		for (const run of [
			() => importPkcs8PemOrThrow(input),
			async () => unwrap(result),
			() => importPrivateKeyPemOrThrow(input),
		]) {
			try {
				await run();
				throw new Error('unexpected success');
			} catch (error) {
				expect(isResultError(error)).toBe(true);
				if (!isResultError(error)) throw error;
				expect(error.error.details).toMatchObject({ stage, reason });
			}
		}
		expect(JSON.stringify(result)).not.toContain(input);
	}
	expect(await importPkcs8Pem('broken')).toMatchObject({
		details: { stage: 'pem', reason: 'invalid_armor' },
	});
	expect(await importPkcs8Base64('AB==')).toMatchObject({
		details: { stage: 'base64', reason: 'invalid_base64' },
	});
	expect(await importSpkiPem('broken')).toMatchObject({
		details: { container: 'spki', stage: 'pem' },
	});
	expect(await importSec1Der(Uint8Array.of(0x30, 0))).toMatchObject({
		details: { container: 'sec1', stage: 'asn1' },
	});
});

it('separates ASN.1, unsupported algorithm, explicit mismatch and backend refusal without native prose', async () => {
	const oid = objectIdentifier(OIDS.sha256);
	const unsupported = sequence([sequence([oid]), bitString(Uint8Array.of(1))]);
	expect(await importSpkiDer(unsupported)).toMatchObject({
		details: { stage: 'algorithm', reason: 'unsupported_algorithm' },
	});
	expect(
		await importSpkiDer(await rsa.exportSpkiDer(), { kind: 'ecdsa', curve: 'P-256' }),
	).toMatchObject({ details: { stage: 'algorithm', reason: 'algorithm_mismatch' } });
	const invalidPoint = {
		kty: 'EC',
		crv: 'P-256',
		x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
		y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
	};
	const backend = await importPublicJwk(invalidPoint, { kind: 'ecdsa', curve: 'P-256' });
	expect(backend).toMatchObject({
		details: { stage: 'backend', reason: 'backend_rejected', container: 'jwk' },
	});
	if (!backend.ok) expect(backend.message).toBe('Key import refused at backend: backend_rejected');
	const overlongOid = Uint8Array.of(0x06, 66, 42, ...new Array<number>(64).fill(0x81), 0);
	const limited = sequence([sequence([overlongOid]), bitString(Uint8Array.of(1))]);
	expect(await importSpkiDer(limited)).toMatchObject({
		code: 'limit_exceeded',
		details: { stage: 'asn1', reason: 'decode_limit' },
	});
	const badPkcs8 = sequence([integerFromNumber(0), sequence([oid]), octetString(Uint8Array.of(1))]);
	expect(await importPkcs8Der(badPkcs8)).toMatchObject({
		details: { stage: 'algorithm', reason: 'unsupported_algorithm' },
	});
});

it('keeps encrypted-import codes and lets programmer errors escape', async () => {
	const encrypted = await exportEncryptedPkcs8Pem(ec.privateKey, {
		password: 'secret',
		iterations: 2,
	});
	expect(await importEncryptedPkcs8Pem(encrypted, 'wrong')).toMatchObject({
		code: 'invalid_password',
	});
	expect(
		await importEncryptedPkcs8Pem(encrypted, 'secret', undefined, { maxKdfIterations: 1 }),
	).toMatchObject({ code: 'kdf_iterations_exceeded' });
	let rejected: unknown;
	try {
		await callUntyped(importPrivateKeyPem, 42);
	} catch (error) {
		rejected = error;
	}
	expect(rejected).toBeInstanceOf(TypeError);
});

it.skipIf(!openSslAvailable)(
	'preserves valid multiprime RSA imports through PKCS1 and label dispatch',
	async () => {
		const pem = execFileSync('openssl', ['genrsa', '-traditional', '-primes', '3', '2048'], {
			encoding: 'utf8',
			stdio: ['ignore', 'pipe', 'pipe'],
		});
		for (const result of [await importPkcs1Pem(pem), await importPrivateKeyPem(pem)]) {
			// Backends may not implement multiprime RSA; the container parser must allow its valid shape.
			if (!result.ok) {
				expect(result.details?.stage).toBe('backend');
				continue;
			}
			const signature = await crypto.subtle.sign(
				'RSASSA-PKCS1-v1_5',
				result.value,
				new Uint8Array(1),
			);
			expect(signature.byteLength).toBe(256);
		}
	},
);

it('maps native JWK key_ops validation into structured backend refusals', async () => {
	for (const pair of [rsa, ec]) {
		const publicJwk = { ...(await pair.exportPublicJwk()), key_ops: ['bogus'] };
		const privateJwk = { ...(await pair.exportPrivateJwk()), key_ops: ['bogus'] };
		for (const result of [await importPublicJwk(publicJwk), await importPrivateJwk(privateJwk)]) {
			expect(result).toMatchObject({
				code: 'malformed',
				details: { container: 'jwk', stage: 'backend', reason: 'backend_rejected' },
			});
			if (!result.ok) expect(result.error.details).toEqual(result.details);
		}
		for (const run of [
			() => importPublicJwkOrThrow(publicJwk),
			() => importPrivateJwkOrThrow(privateJwk),
		]) {
			let rejected: unknown;
			try {
				await run();
			} catch (error) {
				rejected = error;
			}
			expect(isResultError(rejected)).toBe(true);
			if (!isResultError(rejected)) throw new Error('expected coded backend refusal');
			expect(rejected.error).toMatchObject({
				code: 'malformed',
				details: { stage: 'backend', reason: 'backend_rejected' },
			});
		}
	}
});

it('does not hide a TypeError thrown while preparing developer algorithm parameters', async () => {
	const algorithm = {
		kind: 'rsa',
		get hash(): 'SHA-256' {
			throw new TypeError('broken configuration getter');
		},
	} as const;
	let rejected: unknown;
	try {
		await importPublicJwk(await rsa.exportPublicJwk(), algorithm);
	} catch (error) {
		rejected = error;
	}
	expect(rejected).toBeInstanceOf(TypeError);
	expect(isResultError(rejected)).toBe(false);
});
