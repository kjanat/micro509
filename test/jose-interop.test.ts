import { describe, expect, it } from 'bun:test';
import {
	CompactSign,
	compactVerify,
	createLocalJWKSet,
	exportJWK,
	generateKeyPair,
	importJWK,
	jwtVerify,
	SignJWT,
} from 'jose';
import type { JwtClaimsPolicy } from '#micro509/jose';
import {
	createJwksKeyResolver,
	parseCompactJws,
	parseJwks,
	signCompactJws,
	signJwt,
	verifyCompactJws,
	verifyJwt,
} from '#micro509/jose';
import {
	base64UrlOfText,
	callUntyped,
	joseTestKeys,
	rsaJwkEntry,
	signRawRs256Token,
} from '#test/helpers';

const [primary, secondary] = await joseTestKeys();
const NOW = 1_800_000_000;
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'api://orders';
const primaryJwk = await primary.exportPublicJwk();

function micro509Accepts(
	token: string,
	policy: Partial<JwtClaimsPolicy> = {},
	tokenType = 'JWT',
): Promise<boolean> {
	return verifyJwt(token, {
		algorithms: ['RS256'],
		key: primary.publicKey,
		tokenType,
		claims: {
			issuer: ISSUER,
			audience: AUDIENCE,
			now: () => new Date(NOW * 1000),
			...policy,
		},
	}).then((result) => result.ok);
}

async function joseAccepts(
	token: string,
	options: {
		clockTolerance?: number;
		maxTokenAge?: number;
		requiredClaims?: string[];
		typ?: string;
	} = {},
): Promise<boolean> {
	try {
		await jwtVerify(token, primary.publicKey, {
			issuer: ISSUER,
			audience: AUDIENCE,
			algorithms: ['RS256'],
			currentDate: new Date(NOW * 1000),
			...options,
		});
		return true;
	} catch {
		return false;
	}
}

async function microToken(claims: Record<string, unknown>): Promise<string> {
	return await signJwt({
		privateKey: primary.privateKey,
		algorithm: 'RS256',
		claims: JSON.parse(JSON.stringify(claims)),
	});
}

async function joseToken(claims: Record<string, unknown>): Promise<string> {
	return await new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
		.sign(primary.privateKey);
}

describe('jose interoperability: RS256 tokens', () => {
	it('verifies a micro509-signed JWT with jose', async () => {
		const token = await signJwt({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			header: { kid: 'k1' },
			claims: { iss: ISSUER, aud: AUDIENCE, sub: 'u', exp: NOW + 60, nbf: NOW - 1, iat: NOW - 1 },
		});
		const verified = await jwtVerify(token, primary.publicKey, {
			issuer: ISSUER,
			audience: AUDIENCE,
			algorithms: ['RS256'],
			typ: 'JWT',
			currentDate: new Date(NOW * 1000),
		});
		expect(verified.protectedHeader).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
		expect(verified.payload).toEqual({
			iss: ISSUER,
			aud: AUDIENCE,
			sub: 'u',
			exp: NOW + 60,
			nbf: NOW - 1,
			iat: NOW - 1,
		});
	});

	it('verifies a jose-signed JWT with micro509', async () => {
		const token = await new SignJWT({ role: 'admin' })
			.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'k1' })
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setSubject('u')
			.setIssuedAt(NOW - 1)
			.setNotBefore(NOW - 1)
			.setExpirationTime(NOW + 60)
			.sign(primary.privateKey);
		const result = await verifyJwt(token, {
			algorithms: ['RS256'],
			key: primary.publicKey,
			tokenType: 'JWT',
			claims: { issuer: ISSUER, audience: AUDIENCE, now: () => new Date(NOW * 1000) },
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.header).toMatchObject({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
		expect(result.value.claims.role).toBe('admin');
		expect(result.value.registered).toEqual({
			iss: ISSUER,
			aud: AUDIENCE,
			sub: 'u',
			exp: NOW + 60,
			nbf: NOW - 1,
			iat: NOW - 1,
		});
	});

	it('interoperates over compact JWS with arbitrary payload bytes', async () => {
		const bytes = Uint8Array.from({ length: 300 }, (_, index) => index % 256);
		const fromMicro = await signCompactJws({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			payload: bytes,
		});
		const joseView = await compactVerify(fromMicro, primary.publicKey);
		expect(joseView.payload).toEqual(bytes);
		const fromJose = await new CompactSign(bytes)
			.setProtectedHeader({ alg: 'RS256' })
			.sign(primary.privateKey);
		const microView = await verifyCompactJws(fromJose, {
			algorithms: ['RS256'],
			key: primary.publicKey,
			tokenType: { absent: true },
		});
		expect(microView.ok && microView.value.payload).toEqual(bytes);
	});

	it('produces byte-identical signatures for identical signing input', async () => {
		const protectedHeader = '{"alg":"RS256"}';
		const body = '{"a":1}';
		const micro = await signRawRs256Token(primary.privateKey, protectedHeader, body);
		const reference = await new CompactSign(new TextEncoder().encode(body))
			.setProtectedHeader({ alg: 'RS256' })
			.sign(primary.privateKey);
		expect(reference).toBe(micro);
	});

	it('both reject the same tampering', async () => {
		const token = await microToken({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 });
		const [header, body, signature] = token.split('.');
		const tampered: readonly string[] = [
			`${header}.${base64UrlOfText(`{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":${NOW + 9999}}`)}.${signature}`,
			`${header}.${body}.${signature?.slice(0, -2)}AA`,
			`${base64UrlOfText('{"alg":"RS256","typ":"JWT","kid":"x"}')}.${body}.${signature}`,
			`${header}.${body}`,
			`${header}.${body}.${signature}.extra`,
			'',
			'a.b.c',
		];
		for (const candidate of tampered) {
			expect({
				candidate: candidate.slice(0, 24),
				micro: await micro509Accepts(candidate),
			}).toEqual({
				candidate: candidate.slice(0, 24),
				micro: false,
			});
			expect({ candidate: candidate.slice(0, 24), jose: await joseAccepts(candidate) }).toEqual({
				candidate: candidate.slice(0, 24),
				jose: false,
			});
		}
		expect(await micro509Accepts(token)).toBe(true);
		expect(await joseAccepts(token)).toBe(true);
	});

	it('both reject a different key', async () => {
		const token = await signJwt({
			privateKey: secondary.privateKey,
			algorithm: 'RS256',
			claims: { iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 },
		});
		expect(await micro509Accepts(token)).toBe(false);
		expect(await joseAccepts(token)).toBe(false);
	});

	it('both reject unsigned and other-algorithm tokens', async () => {
		const unsigned = `${base64UrlOfText('{"alg":"none"}')}.${base64UrlOfText(JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 }))}.`;
		expect(await micro509Accepts(unsigned)).toBe(false);
		expect(await joseAccepts(unsigned)).toBe(false);
		const hmac = await new SignJWT({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 })
			.setProtectedHeader({ alg: 'HS256' })
			.sign(new TextEncoder().encode('0123456789abcdef0123456789abcdef'));
		expect(await micro509Accepts(hmac)).toBe(false);
		expect(await joseAccepts(hmac)).toBe(false);
		const pss = await generateKeyPair('PS256', { extractable: true });
		const pssToken = await new SignJWT({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 })
			.setProtectedHeader({ alg: 'PS256' })
			.sign(pss.privateKey);
		expect(await micro509Accepts(pssToken)).toBe(false);
		expect(await joseAccepts(pssToken)).toBe(false);
	});

	it('both reject critical headers they do not understand', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","typ":"JWT","crit":["x-ext"],"x-ext":1}',
			JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 }),
		);
		expect(await micro509Accepts(token)).toBe(false);
		expect(await joseAccepts(token)).toBe(false);
	});
});

describe('jose interoperability: claim semantics', () => {
	const cases: readonly { readonly name: string; readonly claims: Record<string, unknown> }[] = [
		{ name: 'valid', claims: { exp: NOW + 60 } },
		{ name: 'exp one second ahead', claims: { exp: NOW + 1 } },
		{ name: 'exp at the instant', claims: { exp: NOW } },
		{ name: 'exp one second past', claims: { exp: NOW - 1 } },
		{ name: 'exp fractional ahead', claims: { exp: NOW + 0.5 } },
		{ name: 'exp fractional past', claims: { exp: NOW - 0.5 } },
		{ name: 'nbf at the instant', claims: { exp: NOW + 60, nbf: NOW } },
		{ name: 'nbf one second ahead', claims: { exp: NOW + 60, nbf: NOW + 1 } },
		{ name: 'nbf fractional ahead', claims: { exp: NOW + 60, nbf: NOW + 0.5 } },
		{ name: 'audience array containing', claims: { exp: NOW + 60, aud: ['x', AUDIENCE] } },
		{ name: 'audience array missing', claims: { exp: NOW + 60, aud: ['x', 'y'] } },
		{ name: 'audience empty array', claims: { exp: NOW + 60, aud: [] } },
		{ name: 'audience case differs', claims: { exp: NOW + 60, aud: AUDIENCE.toUpperCase() } },
		{ name: 'issuer differs', claims: { exp: NOW + 60, iss: 'https://other.example' } },
		{ name: 'issuer with trailing slash', claims: { exp: NOW + 60, iss: `${ISSUER}/` } },
		{ name: 'exp as string', claims: { exp: String(NOW + 60) } },
		{ name: 'nbf as string', claims: { exp: NOW + 60, nbf: String(NOW - 1) } },
		{ name: 'exp null', claims: { exp: null } },
		{ name: 'exp boolean', claims: { exp: true } },
		{ name: 'aud number', claims: { exp: NOW + 60, aud: 5 } },
		{ name: 'iss number', claims: { exp: NOW + 60, iss: 5 } },
	];

	for (const { name, claims } of cases) {
		it(`agrees on ${name}`, async () => {
			const full = { iss: ISSUER, aud: AUDIENCE, ...claims };
			const token = await joseToken(full);
			expect({ name, micro: await micro509Accepts(token) }).toEqual({
				name,
				micro: await joseAccepts(token),
			});
		});
	}

	it('agrees on the clock tolerance boundary', async () => {
		const expiredBy = async (seconds: number) =>
			await joseToken({ iss: ISSUER, aud: AUDIENCE, exp: NOW - seconds });
		for (const seconds of [0, 1, 29, 30, 31]) {
			const token = await expiredBy(seconds);
			expect({
				seconds,
				micro: await micro509Accepts(token, { clockToleranceSeconds: 30 }),
			}).toEqual({
				seconds,
				micro: await joseAccepts(token, { clockTolerance: 30 }),
			});
		}
		const early = async (seconds: number) =>
			await joseToken({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60, nbf: NOW + seconds });
		for (const seconds of [0, 29, 30, 31]) {
			const token = await early(seconds);
			expect({
				seconds,
				micro: await micro509Accepts(token, { clockToleranceSeconds: 30 }),
			}).toEqual({
				seconds,
				micro: await joseAccepts(token, { clockTolerance: 30 }),
			});
		}
	});

	it('agrees on the maximum token age boundary', async () => {
		for (const age of [0, 1, 299, 300, 301, 600]) {
			const token = await joseToken({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60, iat: NOW - age });
			expect({ age, micro: await micro509Accepts(token, { maxAgeSeconds: 300 }) }).toEqual({
				age,
				micro: await joseAccepts(token, { maxTokenAge: 300 }),
			});
		}
	});

	it('agrees on the token type', async () => {
		const claims = { iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 };
		const token = await new SignJWT(claims)
			.setProtectedHeader({ alg: 'RS256', typ: 'at+jwt' })
			.sign(primary.privateKey);
		for (const expected of ['at+jwt', 'AT+JWT', 'application/at+jwt', 'JWT', 'at+jwt2']) {
			expect({ expected, micro: await micro509Accepts(token, {}, expected) }).toEqual({
				expected,
				micro: await joseAccepts(token, { typ: expected }),
			});
		}
	});
});

describe('jose interoperability: JWK Sets', () => {
	it('selects the same key as jose and rejects what jose rejects', async () => {
		const keys = [
			await rsaJwkEntry(primary, { kid: 'a', use: 'sig', alg: 'RS256' }),
			await rsaJwkEntry(secondary, { kid: 'b', use: 'sig' }),
			{
				kty: 'EC',
				crv: 'P-256',
				x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
				y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
				kid: 'ec',
			},
		];
		const jwks = parseJwks(JSON.stringify({ keys }));
		if (!jwks.ok) throw new Error('unreachable');
		const resolver = createJwksKeyResolver(jwks.value);
		const joseSet = callUntyped(createLocalJWKSet, { keys: keys.map((key) => ({ ...key })) });
		for (const [kid, pair, expected] of [
			['a', primary, true],
			['b', secondary, true],
			['a', secondary, false],
			['b', primary, false],
			['missing', primary, false],
			['ec', primary, false],
		] as const) {
			const token = await signCompactJws({
				privateKey: pair.privateKey,
				algorithm: 'RS256',
				payload: new TextEncoder().encode('{}'),
				header: { kid },
			});
			const micro = await verifyCompactJws(token, {
				algorithms: ['RS256'],
				key: resolver,
				tokenType: { unchecked: true },
			});
			let joseOk = true;
			try {
				await compactVerify(token, joseSet, { algorithms: ['RS256'] });
			} catch {
				joseOk = false;
			}
			expect({ kid, micro: micro.ok, jose: joseOk }).toEqual({
				kid,
				micro: expected,
				jose: expected,
			});
		}
	});

	it('both refuse an ambiguous set', async () => {
		const keys = [
			await rsaJwkEntry(primary, { kid: 'dup' }),
			await rsaJwkEntry(secondary, { kid: 'dup' }),
		];
		const jwks = parseJwks(JSON.stringify({ keys }));
		if (!jwks.ok) throw new Error('unreachable');
		const token = await signCompactJws({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			payload: new TextEncoder().encode('{}'),
			header: { kid: 'dup' },
		});
		const micro = await verifyCompactJws(token, {
			algorithms: ['RS256'],
			key: createJwksKeyResolver(jwks.value),
			tokenType: { unchecked: true },
		});
		expect(micro).toMatchObject({ ok: false, code: 'ambiguous_key' });
		await expect(compactVerify(token, callUntyped(createLocalJWKSet, { keys }))).rejects.toThrow();
	});

	it('verifies jose-generated keys exported through jose', async () => {
		const generated = await generateKeyPair('RS256', { extractable: true, modulusLength: 2048 });
		const jwk = {
			...(await exportJWK(generated.publicKey)),
			kid: 'jose-key',
			use: 'sig',
			alg: 'RS256',
		};
		const jwks = parseJwks(JSON.stringify({ keys: [jwk] }));
		if (!jwks.ok) throw new Error('unreachable');
		const token = await new SignJWT({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 })
			.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'jose-key' })
			.sign(generated.privateKey);
		const result = await verifyJwt(token, {
			algorithms: ['RS256'],
			key: createJwksKeyResolver(jwks.value),
			tokenType: 'JWT',
			claims: { issuer: ISSUER, audience: AUDIENCE, now: () => new Date(NOW * 1000) },
		});
		expect(result.ok).toBe(true);
	});

	it('lets jose verify with a key imported from micro509-exported JWK', async () => {
		const imported = await importJWK({ ...primaryJwk, alg: 'RS256' }, 'RS256');
		const token = await microToken({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 });
		await expect(
			jwtVerify(token, imported, { currentDate: new Date(NOW * 1000), issuer: ISSUER }),
		).resolves.toBeDefined();
	});
});

describe('jose interoperability: intentional differences', () => {
	const baseClaims = { iss: ISSUER, aud: AUDIENCE, exp: NOW + 60 };

	it('rejects duplicate header members where jose keeps the last', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"none","alg":"RS256","typ":"JWT"}',
			JSON.stringify(baseClaims),
		);
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
		const result = parseCompactJws(token);
		expect(result).toMatchObject({ ok: false, code: 'duplicate_member' });
	});

	it('rejects duplicate claims where jose keeps the last', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","typ":"JWT"}',
			`{"iss":"https://evil.example","iss":"${ISSUER}","aud":"${AUDIENCE}","exp":${NOW + 60}}`,
		);
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
	});

	it('rejects non-zero trailing base64url bits where jose decodes them', async () => {
		const header = '{"alg":"RS256","typ":"JWT"} ';
		const payload = JSON.stringify(baseClaims);
		const good = await signRawRs256Token(primary.privateKey, header, payload);
		const [headerSegment, body, signature] = good.split('.');
		if (headerSegment === undefined) throw new Error('unreachable');
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		const last = headerSegment.slice(-1);
		const twin = `${headerSegment.slice(0, -1)}${alphabet[(alphabet.indexOf(last) + 1) % 64]}`;
		const token = `${twin}.${body}.${signature}`;
		expect(await micro509Accepts(token)).toBe(false);
		expect(parseCompactJws(token)).toMatchObject({ ok: false, code: 'invalid_encoding' });
		expect(await joseAccepts(token)).toBe(false);
	});

	it('requires exp unless told otherwise, where jose does not', async () => {
		const token = await joseToken({ iss: ISSUER, aud: AUDIENCE });
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
		expect(await micro509Accepts(token, { requiredClaims: [] })).toBe(true);
		expect(await joseAccepts(token, { requiredClaims: ['exp'] })).toBe(false);
	});

	it('rejects a future iat by default, where jose checks only with a maximum age', async () => {
		const token = await joseToken({ ...baseClaims, iat: NOW + 3600 });
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
		expect(await micro509Accepts(token, { futureIssuedAt: 'allow' })).toBe(true);
	});

	it('rejects lone surrogate escapes that JSON.parse accepts', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","typ":"JWT"}',
			`{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":${NOW + 60},"note":"\\ud800"}`,
		);
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
	});

	it('rejects an audience array holding a non-string where jose matches the string', async () => {
		const token = await joseToken({ ...baseClaims, aud: [AUDIENCE, 5] });
		expect(await joseAccepts(token)).toBe(true);
		expect(await micro509Accepts(token)).toBe(false);
	});

	it('rejects a BOM-prefixed payload', async () => {
		const text = `﻿${JSON.stringify(baseClaims)}`;
		const token = await signRawRs256Token(primary.privateKey, '{"alg":"RS256","typ":"JWT"}', text);
		expect(await micro509Accepts(token)).toBe(false);
	});
});
