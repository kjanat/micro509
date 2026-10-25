import { describe, expect, it } from 'bun:test';
import { signData } from '#micro509/crypto';
import { base64UrlEncode } from '#micro509/internal/jose/base64url';
import type { JwtClaimsPolicy, VerifyJwtOptions } from '#micro509/jose';
import {
	createJwksKeyResolver,
	decodeJwtUnverified,
	MAX_CLOCK_TOLERANCE_SECONDS,
	parseJwks,
	signJwt,
	verifyJwt,
} from '#micro509/jose';
import {
	base64UrlOfText,
	callUntyped,
	expectRejectedErrorCode,
	joseTestKeys,
	signRawRs256Token,
} from '#test/helpers';

import { forgeExponentOneJwt } from './fixtures/jose-exponent-one.mjs';

const [primary, secondary] = await joseTestKeys();
const NOW = 1_800_000_000;
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'api://orders';

function claimsPolicy(overrides: Partial<JwtClaimsPolicy> = {}): JwtClaimsPolicy {
	return {
		issuer: ISSUER,
		audience: AUDIENCE,
		now: () => new Date(NOW * 1000),
		...overrides,
	};
}

function options(
	claims: Partial<JwtClaimsPolicy> = {},
	overrides: Partial<VerifyJwtOptions> = {},
): VerifyJwtOptions {
	return {
		algorithms: ['RS256'],
		key: primary.publicKey,
		tokenType: 'JWT',
		claims: claimsPolicy(claims),
		...overrides,
	};
}

function validClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		iss: 'https://issuer.example',
		aud: 'api://orders',
		sub: 'user-1',
		exp: NOW + 60,
		...overrides,
	};
}

async function tokenFor(claims: Record<string, unknown>, typ = 'JWT'): Promise<string> {
	return await signRawRs256Token(
		primary.privateKey,
		JSON.stringify({ alg: 'RS256', typ }),
		JSON.stringify(claims),
	);
}

async function code(
	claims: Record<string, unknown>,
	policy: Partial<JwtClaimsPolicy> = {},
	overrides: Partial<VerifyJwtOptions> = {},
): Promise<string> {
	const result = await verifyJwt(await tokenFor(claims), options(policy, overrides));
	return result.ok ? 'ok' : result.code;
}

describe('verifyJwt', () => {
	it('rejects an exponent-one forgery through JWKS and a non-extractable public key', async () => {
		const { token: forged, jwk } = await forgeExponentOneJwt(primary.publicKey, validClaims());
		const jwks = parseJwks(JSON.stringify({ keys: [jwk] }));
		if (!jwks.ok) throw new Error(jwks.code);
		const publicKey = await crypto.subtle.importKey(
			'jwk',
			jwk,
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			false,
			['verify'],
		);
		expect(publicKey.extractable).toBe(false);
		for (const key of [publicKey, createJwksKeyResolver(jwks.value)]) {
			const result = await verifyJwt(forged, options({}, { key }));
			expect(result.ok ? 'accepted' : result.code).toBe('key_unsuitable');
		}
	});

	it('returns the verified header, every claim and the typed registered claims', async () => {
		const token = await signJwt({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			header: { kid: 'k1' },
			claims: {
				...validClaims({ iat: NOW - 5, nbf: NOW - 5, jti: 'j1' }),
				custom: { a: [1, 'x'] },
			},
		});
		const result = await verifyJwt(token, options());
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.verified).toBe(true);
		expect(result.value.header).toMatchObject({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
		expect(result.value.claims.custom).toEqual({ a: [1, 'x'] });
		expect(result.value.registered).toEqual({
			iss: 'https://issuer.example',
			sub: 'user-1',
			aud: 'api://orders',
			exp: NOW + 60,
			nbf: NOW - 5,
			iat: NOW - 5,
			jti: 'j1',
		});
	});

	it('rejects a bad signature before looking at claims', async () => {
		const token = await tokenFor(validClaims({ exp: NOW - 1000 }));
		const result = await verifyJwt(token, options({}, { key: secondary.publicKey }));
		expect(result).toMatchObject({ ok: false, code: 'invalid_signature' });
	});

	it('keeps unverified decoding distinct from verified results', async () => {
		const token = await tokenFor(validClaims());
		const decoded = decodeJwtUnverified(token);
		expect(decoded.ok).toBe(true);
		if (!decoded.ok) throw new Error('unreachable');
		expect(decoded.value.verified).toBe(false);
		expect(decoded.value.claims.iss).toBe('https://issuer.example');
		expect('registered' in decoded.value).toBe(false);
		const forged = `${token.split('.')[0]}.${base64UrlOfText('{"iss":"evil"}')}.${token.split('.')[2]}`;
		expect(decodeJwtUnverified(forged).ok).toBe(true);
		expect(await verifyJwt(forged, options())).toMatchObject({
			ok: false,
			code: 'invalid_signature',
		});
	});

	it('requires the payload to be a duplicate-free JSON object', async () => {
		const sign = (payload: string) =>
			signRawRs256Token(primary.privateKey, '{"alg":"RS256","typ":"JWT"}', payload);
		const cases: readonly (readonly [string, string])[] = [
			['[]', 'invalid_payload'],
			['"x"', 'invalid_payload'],
			['', 'invalid_json'],
			['{"exp":1', 'invalid_json'],
			['{"iss":"a","iss":"b","exp":1}', 'duplicate_member'],
			[`{"exp":${NOW + 60},"exp":${NOW + 60}}`, 'duplicate_member'],
			['{"a":{"b":1,"b":2}}', 'duplicate_member'],
		];
		for (const [payload, expected] of cases) {
			const result = await verifyJwt(await sign(payload), options());
			expect({ payload, code: result.ok ? 'ok' : result.code }).toEqual({
				payload,
				code: expected,
			});
		}
	});

	it('rejects invalid UTF-8 in the payload', async () => {
		const signingInput = `${base64UrlOfText('{"alg":"RS256","typ":"JWT"}')}.${'e8_-'}`;
		const bytes = new TextEncoder().encode(signingInput);
		const { signature } = await signData(primary.privateKey, bytes);
		const token = `${signingInput}.${base64UrlEncode(signature)}`;
		expect(await verifyJwt(token, options())).toMatchObject({ ok: false, code: 'invalid_utf8' });
	});

	it('refuses a nested JWT', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","typ":"JWT","cty":"JWT"}',
			'"a.b.c"',
		);
		expect(await verifyJwt(token, options())).toMatchObject({
			ok: false,
			code: 'unsupported_nested_jwt',
		});
		expect(decodeJwtUnverified(token)).toMatchObject({ ok: false, code: 'unsupported_nested_jwt' });
	});
});

describe('token profiles', () => {
	it('rejects a token of another profile and accepts it under its own', async () => {
		const accessToken = await tokenFor(validClaims(), 'at+jwt');
		const idToken = await tokenFor(validClaims(), 'JWT');
		const accessPolicy = options({}, { tokenType: 'at+jwt' });
		const idPolicy = options({}, { tokenType: 'JWT' });
		expect((await verifyJwt(accessToken, accessPolicy)).ok).toBe(true);
		expect((await verifyJwt(idToken, idPolicy)).ok).toBe(true);
		expect(await verifyJwt(idToken, accessPolicy)).toMatchObject({
			ok: false,
			code: 'token_type_mismatch',
		});
		expect(await verifyJwt(accessToken, idPolicy)).toMatchObject({
			ok: false,
			code: 'token_type_mismatch',
		});
	});

	it('separates profiles by audience and issuer as well as by type', async () => {
		const token = await tokenFor(validClaims({ aud: 'api://billing' }), 'at+jwt');
		const orders = options({}, { tokenType: 'at+jwt' });
		expect(await verifyJwt(token, orders)).toMatchObject({ ok: false, code: 'audience_mismatch' });
		const billing = options({ audience: 'api://billing' }, { tokenType: 'at+jwt' });
		expect((await verifyJwt(token, billing)).ok).toBe(true);
	});
});

describe('required claims', () => {
	it('requires exp by default and lets the caller choose what is required', async () => {
		const noExp = validClaims();
		delete noExp.exp;
		expect(await code(noExp)).toBe('missing_claim');
		expect(await code(noExp, { requiredClaims: [] })).toBe('ok');
		expect(await code(validClaims(), { requiredClaims: ['exp', 'sub', 'jti'] })).toBe(
			'missing_claim',
		);
		expect(await code(validClaims({ jti: 'x' }), { requiredClaims: ['exp', 'sub', 'jti'] })).toBe(
			'ok',
		);
	});

	it('names the failing claim without echoing its value', async () => {
		const noExp = validClaims();
		delete noExp.exp;
		const result = await verifyJwt(await tokenFor(noExp), options());
		expect(result).toMatchObject({ ok: false, details: { claim: 'exp' } });
		const wrong = await verifyJwt(
			await tokenFor(validClaims({ iss: 'https://secret.example' })),
			options(),
		);
		expect(JSON.stringify(wrong)).not.toContain('secret.example');
	});
});

describe('issuer and audience', () => {
	it('matches issuer exactly and accepts any of several', async () => {
		expect(await code(validClaims({ iss: 'https://issuer.example/' }))).toBe('issuer_mismatch');
		expect(await code(validClaims({ iss: 'HTTPS://issuer.example' }))).toBe('issuer_mismatch');
		const missing = validClaims();
		delete missing.iss;
		expect(await code(missing)).toBe('issuer_mismatch');
		const both = { issuer: ['https://a.example', 'https://issuer.example'] } as const;
		expect(await code(validClaims(), both)).toBe('ok');
		expect(await code(validClaims({ iss: 'https://a.example' }), both)).toBe('ok');
		expect(await code(validClaims({ iss: 'https://c.example' }), both)).toBe('issuer_mismatch');
	});

	it('handles audience strings and arrays', async () => {
		expect(await code(validClaims({ aud: ['x', 'api://orders', 'y'] }))).toBe('ok');
		expect(await code(validClaims({ aud: ['x', 'y'] }))).toBe('audience_mismatch');
		expect(await code(validClaims({ aud: [] }))).toBe('audience_mismatch');
		expect(await code(validClaims({ aud: 'API://ORDERS' }))).toBe('audience_mismatch');
		const missing = validClaims();
		delete missing.aud;
		expect(await code(missing)).toBe('audience_mismatch');
		const several = { audience: ['api://orders', 'api://billing'] } as const;
		expect(await code(validClaims({ aud: 'api://billing' }), several)).toBe('ok');
	});

	it('rejects mistyped identity claims', async () => {
		expect(await code(validClaims({ aud: 5 }))).toBe('invalid_claim');
		expect(await code(validClaims({ aud: ['a', 5] }))).toBe('invalid_claim');
		expect(await code(validClaims({ aud: null }))).toBe('invalid_claim');
		expect(await code(validClaims({ aud: {} }))).toBe('invalid_claim');
		expect(await code(validClaims({ iss: 5 }))).toBe('invalid_claim');
		expect(await code(validClaims({ iss: ['https://issuer.example'] }))).toBe('invalid_claim');
		expect(await code(validClaims({ sub: 5 }))).toBe('invalid_claim');
		expect(await code(validClaims({ jti: 5 }))).toBe('invalid_claim');
	});

	it('skips a check only when the caller says so explicitly', async () => {
		const bare = { exp: NOW + 60 };
		expect(await code(bare, { issuer: { unchecked: true }, audience: { unchecked: true } })).toBe(
			'ok',
		);
		expect(await code(bare, { issuer: { unchecked: true } })).toBe('audience_mismatch');
		expect(await code(bare, { audience: { unchecked: true } })).toBe('issuer_mismatch');
		expect(
			await code(
				{ ...bare, aud: 5 },
				{ issuer: { unchecked: true }, audience: { unchecked: true } },
			),
		).toBe('invalid_claim');
	});

	it('refuses an unusable policy', async () => {
		expect(await code(validClaims(), { issuer: [] })).toBe('invalid_options');
		expect(await code(validClaims(), { audience: [] })).toBe('invalid_options');
		const token = await tokenFor(validClaims());
		for (const claims of [
			{ audience: AUDIENCE },
			{ issuer: ISSUER, audience: {} },
			{ issuer: [5], audience: AUDIENCE },
		]) {
			const result = await callUntyped(verifyJwt, token, {
				algorithms: ['RS256'],
				key: primary.publicKey,
				tokenType: 'JWT',
				claims: { now: claimsPolicy().now, ...claims },
			});
			expect({ claims, code: result.ok ? 'ok' : result.code }).toEqual({
				claims,
				code: 'invalid_options',
			});
		}
	});
});

describe('time claims', () => {
	it('treats exp as exclusive: expired at the instant, valid one second before', async () => {
		expect(await code(validClaims({ exp: NOW + 1 }))).toBe('ok');
		expect(await code(validClaims({ exp: NOW + 0.5 }))).toBe('ok');
		expect(await code(validClaims({ exp: NOW }))).toBe('expired');
		expect(await code(validClaims({ exp: NOW - 0.5 }))).toBe('expired');
		expect(await code(validClaims({ exp: NOW - 1 }))).toBe('expired');
		expect(await code(validClaims({ exp: 0 }))).toBe('expired');
		expect(await code(validClaims({ exp: -5 }))).toBe('expired');
	});

	it('treats nbf as inclusive: valid at the instant, rejected one second before', async () => {
		expect(await code(validClaims({ nbf: NOW }))).toBe('ok');
		expect(await code(validClaims({ nbf: NOW - 1 }))).toBe('ok');
		expect(await code(validClaims({ nbf: NOW + 0.5 }))).toBe('not_yet_valid');
		expect(await code(validClaims({ nbf: NOW + 1 }))).toBe('not_yet_valid');
	});

	it('moves the exp and nbf boundaries by exactly the clock tolerance', async () => {
		const tolerance = { clockToleranceSeconds: 30 };
		expect(await code(validClaims({ exp: NOW - 29 }), tolerance)).toBe('ok');
		expect(await code(validClaims({ exp: NOW - 30 }), tolerance)).toBe('expired');
		expect(await code(validClaims({ nbf: NOW + 30 }), tolerance)).toBe('ok');
		expect(await code(validClaims({ nbf: NOW + 31 }), tolerance)).toBe('not_yet_valid');
		expect(await code(validClaims({ exp: NOW - 1 }), { clockToleranceSeconds: 0 })).toBe('expired');
	});

	it('bounds the clock tolerance', async () => {
		expect(await code(validClaims(), { clockToleranceSeconds: MAX_CLOCK_TOLERANCE_SECONDS })).toBe(
			'ok',
		);
		for (const bad of [-1, MAX_CLOCK_TOLERANCE_SECONDS + 1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(await code(validClaims(), { clockToleranceSeconds: bad })).toBe('invalid_options');
		}
	});

	it('requires NumericDate values and never coerces strings', async () => {
		for (const name of ['exp', 'nbf', 'iat'] as const) {
			for (const bad of [String(NOW + 60), null, true, [NOW + 60], {}, '']) {
				expect({ name, bad, code: await code(validClaims({ [name]: bad })) }).toEqual({
					name,
					bad,
					code: 'invalid_claim',
				});
			}
		}
	});

	it('rejects non-finite NumericDate literals at the parser', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","typ":"JWT"}',
			`{"iss":"https://issuer.example","aud":"api://orders","exp":1e999}`,
		);
		expect(await verifyJwt(token, options())).toMatchObject({ ok: false, code: 'invalid_json' });
	});

	it('accepts fractional NumericDates', async () => {
		expect(await code(validClaims({ exp: NOW + 0.001, iat: NOW - 0.001 }))).toBe('ok');
	});

	it('rejects a future iat by default and allows it on request', async () => {
		expect(await code(validClaims({ iat: NOW + 1 }))).toBe('issued_in_future');
		expect(await code(validClaims({ iat: NOW }))).toBe('ok');
		expect(await code(validClaims({ iat: NOW + 1 }), { futureIssuedAt: 'allow' })).toBe('ok');
		expect(await code(validClaims({ iat: NOW + 30 }), { clockToleranceSeconds: 30 })).toBe('ok');
		expect(await code(validClaims({ iat: NOW + 31 }), { clockToleranceSeconds: 30 })).toBe(
			'issued_in_future',
		);
	});

	it('enforces a maximum token age measured from iat', async () => {
		const policy = { maxAgeSeconds: 300 };
		expect(await code(validClaims({ iat: NOW - 300 }), policy)).toBe('ok');
		expect(await code(validClaims({ iat: NOW - 301 }), policy)).toBe('token_too_old');
		expect(await code(validClaims({ iat: NOW - 0.5 }), policy)).toBe('ok');
		expect(await code(validClaims(), policy)).toBe('missing_claim');
		expect(
			await code(validClaims({ iat: NOW - 310 }), { ...policy, clockToleranceSeconds: 10 }),
		).toBe('ok');
		expect(
			await code(validClaims({ iat: NOW - 311 }), { ...policy, clockToleranceSeconds: 10 }),
		).toBe('token_too_old');
		expect(await code(validClaims({ iat: NOW }), { maxAgeSeconds: 0 })).toBe('ok');
		for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(await code(validClaims({ iat: NOW }), { maxAgeSeconds: bad })).toBe('invalid_options');
		}
	});

	it('checks time claims against a caller-supplied clock only', async () => {
		const token = await tokenFor(validClaims());
		const later = options({ now: () => new Date((NOW + 61) * 1000) });
		expect(await verifyJwt(token, later)).toMatchObject({ ok: false, code: 'expired' });
		const earlier = options({ now: () => new Date((NOW + 59) * 1000) });
		expect((await verifyJwt(token, earlier)).ok).toBe(true);
	});

	it('uses the system clock when none is given', async () => {
		const now = Math.floor(Date.now() / 1000);
		const token = await tokenFor({ ...validClaims(), exp: now + 3600 });
		const result = await verifyJwt(token, {
			algorithms: ['RS256'],
			key: primary.publicKey,
			tokenType: 'JWT',
			claims: { issuer: 'https://issuer.example', audience: 'api://orders' },
		});
		expect(result.ok).toBe(true);
	});
});

describe('signJwt', () => {
	it('defaults typ to JWT and lets the caller override it', async () => {
		const jwt = await signJwt({ privateKey: primary.privateKey, algorithm: 'RS256', claims: {} });
		expect(decodeJwtUnverified(jwt)).toMatchObject({ ok: true, value: { header: { typ: 'JWT' } } });
		const at = await signJwt({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			header: { typ: 'at+jwt' },
			claims: {},
		});
		expect(decodeJwtUnverified(at)).toMatchObject({
			ok: true,
			value: { header: { typ: 'at+jwt' } },
		});
	});

	it('throws coded errors for unusable input', async () => {
		await expectRejectedErrorCode(
			signJwt({ privateKey: primary.publicKey, algorithm: 'RS256', claims: {} }),
			'incompatible_key',
		);
		const circular: Record<string, unknown> = {};
		circular.self = circular;
		await expectRejectedErrorCode(
			callUntyped(signJwt, {
				privateKey: primary.privateKey,
				algorithm: 'RS256',
				claims: circular,
			}),
			'invalid_claims',
		);
	});
});

describe('claims policy hardening', () => {
	const token = () => tokenFor(validClaims());

	async function verifyWith(claims: unknown, extra: Record<string, unknown> = {}): Promise<string> {
		const result = await callUntyped(verifyJwt, await token(), {
			algorithms: ['RS256'],
			key: primary.publicKey,
			tokenType: 'JWT',
			claims,
			...extra,
		});
		return result.ok ? 'ok' : result.code;
	}

	it('refuses an invalid clock instead of treating time as unchecked', async () => {
		const expired = await tokenFor(validClaims({ exp: 1 }));
		for (const now of [
			() => new Date(Number.NaN),
			() => {
				throw new Error('clock broke');
			},
			() => Date.now(),
			() => '2026-01-01',
			() => undefined,
			() => null,
			() => ({ getTime: () => NOW * 1000 }),
		]) {
			const result = await callUntyped(verifyJwt, expired, {
				algorithms: ['RS256'],
				key: primary.publicKey,
				tokenType: 'JWT',
				claims: { issuer: ISSUER, audience: AUDIENCE, now },
			});
			expect({ now: String(now), code: result.ok ? 'ok' : result.code }).toEqual({
				now: String(now),
				code: 'invalid_options',
			});
		}
		expect(await verifyWith({ issuer: ISSUER, audience: AUDIENCE, now: 5 })).toBe(
			'invalid_options',
		);
	});

	it('handles null and mistyped policy members without throwing', async () => {
		for (const claims of [
			null,
			undefined,
			5,
			'x',
			{ issuer: null, audience: AUDIENCE },
			{ issuer: ISSUER, audience: null },
			{ issuer: { unchecked: false }, audience: AUDIENCE },
			{ issuer: { unchecked: 1 }, audience: AUDIENCE },
			{ issuer: { unchecked: true, other: 1 }, audience: AUDIENCE },
			{ issuer: ISSUER, audience: AUDIENCE, requiredClaims: 'exp' },
			{ issuer: ISSUER, audience: AUDIENCE, requiredClaims: [1] },
			{ issuer: ISSUER, audience: AUDIENCE, futureIssuedAt: 'maybe' },
			{ issuer: ISSUER, audience: AUDIENCE, clockToleranceSeconds: '5' },
			{ issuer: ISSUER, audience: AUDIENCE, maxAgeSeconds: '5' },
		]) {
			expect({ claims, code: await verifyWith(claims) }).toEqual({
				claims,
				code: 'invalid_options',
			});
		}
		expect(await callUntyped(verifyJwt, await token(), null)).toMatchObject({
			ok: false,
			code: 'invalid_options',
		});
	});

	it('uses the claims policy as it was when the call began', async () => {
		const policy = {
			issuer: [ISSUER],
			audience: [AUDIENCE],
			requiredClaims: ['exp'],
			now: claimsPolicy().now,
		};
		const result = await callUntyped(verifyJwt, await token(), {
			algorithms: ['RS256'],
			tokenType: 'JWT',
			claims: policy,
			key: async () => {
				policy.issuer.length = 0;
				policy.issuer.push('https://evil.example');
				policy.audience[0] = 'api://other';
				policy.requiredClaims.push('jti');
				policy.now = () => new Date(0);
				return { ok: true, value: primary.publicKey };
			},
		});
		expect(result.ok).toBe(true);
	});

	it('bounds payload parsing with the validated limits', async () => {
		const result = await verifyJwt(await token(), options({}, { limits: { maxPayloadBytes: 8 } }));
		expect(result).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(decodeJwtUnverified(await token(), { maxJsonNodes: 1 })).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
		expect(
			callUntyped(decodeJwtUnverified, await token(), { maxJsonDepth: Number.NaN }),
		).toMatchObject({
			ok: false,
			code: 'invalid_options',
		});
	});
});
