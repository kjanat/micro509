import { describe, expect, it } from 'bun:test';
import {
	CompactSign,
	compactVerify,
	exportJWK,
	generateKeyPair,
	importJWK,
	jwtVerify,
	SignJWT,
} from 'jose';
import { ecdsaSignatureRawToDer } from '#micro509/crypto';
import { base64UrlDecode, base64UrlEncode } from '#micro509/internal/jose/base64url';
import type { JwsAlgorithm, JwsKeyResolver } from '#micro509/jose';
import {
	createJwksKeyResolver,
	createRemoteJwksKeyResolver,
	importJwkEntry,
	parseJwks,
	selectJwk,
	signCompactJws,
	signJwt,
	verifyCompactJws,
	verifyJwt,
} from '#micro509/jose';
import { callUntyped, expectRejectedErrorCode } from '#test/helpers';

const ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'] as const;
const payload = new TextEncoder().encode('JOSE interoperability: café');
const now = 1_900_000_000;
const claims = { iss: 'https://issuer.example', aud: 'orders', exp: now + 60 };
const claimsPolicy = { issuer: claims.iss, audience: claims.aud, now: () => new Date(now * 1000) };
const fixtures = await Promise.all(
	ALGORITHMS.map(async (algorithm) => ({
		algorithm,
		keys: await generateKeyPair(algorithm, { extractable: true }),
		other: await generateKeyPair(algorithm),
	})),
);

function jwks(...keys: (JsonWebKey & { readonly kid?: string })[]) {
	const parsed = parseJwks(JSON.stringify({ keys }));
	if (!parsed.ok) throw new Error(parsed.code);
	return parsed.value;
}

function verify(token: string, algorithm: JwsAlgorithm, key: CryptoKey | JwsKeyResolver) {
	return verifyCompactJws(token, { algorithms: [algorithm], key, tokenType: { unchecked: true } });
}

for (const { algorithm, keys, other } of fixtures) {
	describe(algorithm, () => {
		it('interoperates with independently signed compact JWS and JWT in both directions', async () => {
			const signed = await signCompactJws({ algorithm, privateKey: keys.privateKey, payload });
			const independent = await compactVerify(signed, keys.publicKey, { algorithms: [algorithm] });
			expect(independent.payload).toEqual(payload);
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm })
				.sign(keys.privateKey);
			expect(await verify(token, algorithm, keys.publicKey)).toMatchObject({
				ok: true,
				value: { payload },
			});
			const jwt = await signJwt({ algorithm, privateKey: keys.privateKey, claims });
			const checked = await jwtVerify(jwt, keys.publicKey, {
				algorithms: [algorithm],
				issuer: claims.iss,
				audience: claims.aud,
				currentDate: new Date(now * 1000),
			});
			expect(checked.payload).toEqual(claims);
			const independentJwt = await new SignJWT(claims)
				.setProtectedHeader({ alg: algorithm, typ: 'JWT' })
				.sign(keys.privateKey);
			expect(
				await verifyJwt(independentJwt, {
					algorithms: [algorithm],
					key: keys.publicKey,
					tokenType: 'JWT',
					claims: claimsPolicy,
				}),
			).toMatchObject({ ok: true, value: { claims } });
		});

		it('resolves local and remote JWKS with the same algorithm policy', async () => {
			const publicJwk = {
				...(await exportJWK(keys.publicKey)),
				alg: algorithm,
				kid: 'shared',
				use: 'sig',
			};
			const set = jwks(publicJwk);
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm, kid: 'shared' })
				.sign(keys.privateKey);
			expect((await verify(token, algorithm, createJwksKeyResolver(set))).ok).toBe(true);
			const server = Bun.serve({
				hostname: '127.0.0.1',
				port: 0,
				fetch: () => Response.json({ keys: [publicJwk] }),
			});
			try {
				const resolver = createRemoteJwksKeyResolver({ url: new URL('/jwks', server.url) });
				expect((await verify(token, algorithm, resolver)).ok).toBe(true);
			} finally {
				await server.stop(true);
			}
			for (const changed of [
				{ alg: 'HS256' },
				{ use: 'enc' },
				{ key_ops: ['sign'] },
				{ use: 'sig', key_ops: ['verify', 'decrypt'] },
			]) {
				expect(
					selectJwk(jwks({ ...publicJwk, ...changed }), { algorithm, kid: 'shared' }),
				).toMatchObject({ ok: false, code: 'key_unsuitable' });
			}
			expect(selectJwk(jwks(publicJwk, publicJwk), { algorithm, kid: 'shared' })).toMatchObject({
				ok: false,
				code: 'ambiguous_key',
			});
		});

		it('distinguishes wrong keys, incompatible profiles and disallowed algorithms', async () => {
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm })
				.sign(keys.privateKey);
			expect(await verify(token, algorithm, other.publicKey)).toMatchObject({
				ok: false,
				code: 'invalid_signature',
			});
			for (const candidate of fixtures) {
				if (candidate.algorithm === algorithm) continue;
				expect(await verify(token, algorithm, candidate.keys.publicKey)).toMatchObject({
					ok: false,
					code: 'key_unsuitable',
				});
				await expectRejectedErrorCode(
					signCompactJws({ algorithm, privateKey: candidate.keys.privateKey, payload }),
					'incompatible_key',
				);
			}
			const disallowed = algorithm === 'RS256' ? 'ES256' : 'RS256';
			expect(await verify(token, disallowed, keys.publicKey)).toMatchObject({
				ok: false,
				code: 'algorithm_not_allowed',
			});
			await expectRejectedErrorCode(
				signCompactJws({ algorithm, privateKey: keys.publicKey, payload }),
				'incompatible_key',
			);
			expect(await verify(token, algorithm, keys.privateKey)).toMatchObject({
				ok: false,
				code: 'key_unsuitable',
			});
		});

		it('rejects altered payloads and malformed signatures while preserving resource limits', async () => {
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm })
				.sign(keys.privateKey);
			const [header, body, signature] = token.split('.');
			if (header === undefined || body === undefined || signature === undefined)
				throw new Error('Expected compact token');
			const bytes = base64UrlDecode(signature);
			if (bytes === undefined) throw new Error('Expected signature');
			for (const bad of [
				bytes.slice(1),
				new Uint8Array(bytes.length),
				new Uint8Array(bytes.length + 1),
			]) {
				expect(
					await verify(`${header}.${body}.${base64UrlEncode(bad)}`, algorithm, keys.publicKey),
				).toMatchObject({ ok: false, code: 'invalid_signature' });
			}
			expect(
				await verify(
					`${header}.${base64UrlEncode(new TextEncoder().encode('altered'))}.${signature}`,
					algorithm,
					keys.publicKey,
				),
			).toMatchObject({ ok: false, code: 'invalid_signature' });
			expect(
				await verifyCompactJws(token, {
					algorithms: [algorithm],
					key: keys.publicKey,
					tokenType: { unchecked: true },
					limits: { maxSignatureBytes: bytes.length - 1 },
				}),
			).toMatchObject({ ok: false, code: 'limit_exceeded' });
			if (algorithm === 'ES256' || algorithm === 'ES384') {
				expect(bytes.length).toBe(algorithm === 'ES256' ? 64 : 96);
				const der = ecdsaSignatureRawToDer(bytes, algorithm === 'ES256' ? 'P-256' : 'P-384');
				expect(
					await verify(`${header}.${body}.${base64UrlEncode(der)}`, algorithm, keys.publicKey),
				).toMatchObject({ ok: false, code: 'invalid_signature' });
			}
		});
	});
}

describe('algorithm-bound JWKS imports', () => {
	it('keeps RSA hashes separate locally and through remote snapshot refreshes', async () => {
		const rsa = fixtures[0];
		if (rsa === undefined) throw new Error('Expected RSA fixture');
		const publicJwk = await exportJWK(rsa.keys.publicKey);
		const privateJwk = await exportJWK(rsa.keys.privateKey);
		delete publicJwk.alg;
		delete privateJwk.alg;
		const set = jwks({ ...publicJwk, kid: 'same-key' });
		const local = createJwksKeyResolver(set);
		let time = 0;
		let hits = 0;
		const server = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			fetch: () => {
				hits++;
				return Response.json(
					{ keys: [{ ...publicJwk, kid: 'same-key' }] },
					{ headers: { 'cache-control': 'max-age=3600' } },
				);
			},
		});
		try {
			const remote = createRemoteJwksKeyResolver({
				url: new URL('/jwks', server.url),
				now: () => time,
				cooldownMs: 1,
			});
			const resolve = async (resolver: JwsKeyResolver, algorithm: JwsAlgorithm) => {
				const result = await resolver({
					algorithm,
					header: { alg: algorithm, kid: 'same-key', members: {} },
					kid: 'same-key',
				});
				if (!result.ok) throw new Error(result.code);
				return result.value;
			};
			const cached = new Map<JwsAlgorithm, CryptoKey>();
			for (const round of [0, 1]) {
				for (const algorithm of ['RS256', 'RS384', 'RS512'] as const) {
					const signingKey = await importJWK(privateJwk, algorithm);
					const token = await new CompactSign(payload)
						.setProtectedHeader({ alg: algorithm, kid: 'same-key' })
						.sign(signingKey);
					expect((await verify(token, algorithm, local)).ok).toBe(true);
					expect((await verify(token, algorithm, remote)).ok).toBe(true);
					const imported = await resolve(remote, algorithm);
					if (round === 0) cached.set(algorithm, imported);
					else {
						const previous = cached.get(algorithm);
						if (previous === undefined) throw new Error('Expected cached key');
						expect(imported).toBe(previous);
					}
				}
				time += 1001;
				if (round === 0) {
					expect(
						await remote({
							algorithm: 'RS256',
							header: { alg: 'RS256', members: {} },
							kid: 'unknown',
						}),
					).toMatchObject({ ok: false, code: 'key_not_found' });
				}
			}
			expect(hits).toBe(2);
		} finally {
			await server.stop(true);
		}
	});

	it('validates EC coordinate width, canonical encoding, curve and point validity', async () => {
		for (const fixture of fixtures.filter(({ algorithm }) => algorithm.startsWith('ES'))) {
			const valid = { ...(await exportJWK(fixture.keys.publicKey)), kid: 'ec' };
			const width = fixture.algorithm === 'ES256' ? 32 : 48;
			const cases = [
				{ ...valid, crv: 'P-521' },
				{ ...valid, x: '' },
				{ ...valid, y: '' },
				{ ...valid, x: `${valid.x}=` },
				{ ...valid, y: base64UrlEncode(new Uint8Array(width + 1)) },
				{ ...valid, x: base64UrlEncode(new Uint8Array(width - 1)) },
			];
			for (const candidate of cases) {
				expect(
					selectJwk(jwks(candidate), { algorithm: fixture.algorithm, kid: 'ec' }),
				).toMatchObject({ ok: false, code: 'key_unsuitable' });
			}
			const offCurve = jwks({
				...valid,
				x: base64UrlEncode(new Uint8Array(width)),
				y: base64UrlEncode(new Uint8Array(width)),
			}).keys[0];
			if (offCurve === undefined || offCurve.kind !== 'ec') throw new Error('Expected EC entry');
			expect(await importJwkEntry(offCurve, fixture.algorithm)).toMatchObject({
				ok: false,
				code: 'key_unsuitable',
			});
			const { y: omitted, ...compressed } = valid;
			expect(omitted).toBeDefined();
			expect(jwks(compressed).keys[0]).toMatchObject({ kind: 'unsupported' });
		}
	});

	it('does not select unsupported algorithms or use mismatched imports', async () => {
		const rsa = fixtures[0];
		if (rsa === undefined) throw new Error('Expected RSA fixture');
		const selected = selectJwk(jwks(await exportJWK(rsa.keys.publicKey)), { algorithm: 'RS256' });
		if (!selected.ok) throw new Error(selected.code);
		expect(await callUntyped(importJwkEntry, selected.value, 'HS256')).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
		});
		expect(
			callUntyped(selectJwk, jwks(await exportJWK(rsa.keys.publicKey)), { algorithm: 'HS256' }),
		).toMatchObject({ ok: false, code: 'key_unsuitable' });
		expect(await importJwkEntry(selected.value, 'ES256')).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
		});
	});
});

describe('key constraints across profiles', () => {
	it('retains the 2048-bit RSA minimum for every admitted RSA hash', async () => {
		for (const [algorithm, hash] of [
			['RS256', 'SHA-256'],
			['RS384', 'SHA-384'],
			['RS512', 'SHA-512'],
		] as const) {
			const weak = await crypto.subtle.generateKey(
				{
					name: 'RSASSA-PKCS1-v1_5',
					modulusLength: 1024,
					publicExponent: Uint8Array.of(1, 0, 1),
					hash,
				},
				true,
				['sign', 'verify'],
			);
			const fixture = fixtures.find((candidate) => candidate.algorithm === algorithm);
			if (fixture === undefined) throw new Error('Expected RSA fixture');
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm })
				.sign(fixture.keys.privateKey);
			expect(await verify(token, algorithm, weak.publicKey)).toMatchObject({
				ok: false,
				code: 'key_unsuitable',
			});
			await expectRejectedErrorCode(
				signCompactJws({ algorithm, privateKey: weak.privateKey, payload }),
				'incompatible_key',
			);
		}
	});

	it('disambiguates equal kid values by RSA/EC type, hash metadata and curve', async () => {
		const entries = await Promise.all(
			fixtures.map(async ({ algorithm, keys }) => ({
				...(await exportJWK(keys.publicKey)),
				alg: algorithm,
				kid: 'same',
			})),
		);
		const set = jwks(...entries);
		for (const { algorithm, keys } of fixtures) {
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm, kid: 'same' })
				.sign(keys.privateKey);
			expect((await verify(token, algorithm, createJwksKeyResolver(set))).ok).toBe(true);
		}
	});
});

it('keeps the signing algorithm stable while WebCrypto is pending', async () => {
	const fixture = fixtures.find(({ algorithm }) => algorithm === 'ES256');
	if (fixture === undefined) throw new Error('Expected EC fixture');
	const input: { algorithm: JwsAlgorithm; privateKey: CryptoKey; payload: Uint8Array } = {
		algorithm: 'ES256',
		privateKey: fixture.keys.privateKey,
		payload,
	};
	const signing = signCompactJws(input);
	input.algorithm = 'RS256';
	expect(await verify(await signing, 'ES256', fixture.keys.publicKey)).toMatchObject({ ok: true });
});

it('excludes off-curve EC entries before deciding local or remote JWKS ambiguity', async () => {
	for (const fixture of fixtures.filter(({ algorithm }) => algorithm.startsWith('ES'))) {
		const algorithm = fixture.algorithm;
		const width = algorithm === 'ES256' ? 32 : 48;
		const valid = { ...(await exportJWK(fixture.keys.publicKey)), kid: 'ec', alg: algorithm };
		const invalid = {
			...valid,
			x: base64UrlEncode(new Uint8Array(width)),
			y: base64UrlEncode(new Uint8Array(width)),
		};
		for (const kid of [undefined, 'ec']) {
			const selector = { algorithm, ...(kid === undefined ? {} : { kid }) };
			const selected = selectJwk(jwks(invalid, valid), selector);
			expect(selected).toMatchObject({ ok: true, value: { x: valid.x, y: valid.y } });
			const token = await new CompactSign(payload)
				.setProtectedHeader({ alg: algorithm, ...(kid === undefined ? {} : { kid }) })
				.sign(fixture.keys.privateKey);
			expect((await verify(token, algorithm, createJwksKeyResolver(jwks(invalid, valid)))).ok).toBe(
				true,
			);
			const server = Bun.serve({
				hostname: '127.0.0.1',
				port: 0,
				fetch: () => Response.json({ keys: [invalid, valid] }),
			});
			try {
				const resolver = createRemoteJwksKeyResolver({ url: new URL('/jwks', server.url) });
				expect((await verify(token, algorithm, resolver)).ok).toBe(true);
			} finally {
				await server.stop(true);
			}
			expect(selectJwk(jwks(invalid), selector)).toMatchObject({
				ok: false,
				code: 'key_unsuitable',
			});
			expect(selectJwk(jwks(valid, valid), selector)).toMatchObject({
				ok: false,
				code: 'ambiguous_key',
			});
		}
	}
});
