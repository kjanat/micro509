import { describe, expect, it } from 'bun:test';
import { base64UrlEncode } from '#micro509/internal/jose/base64url';
import type { VerifyJwsOptions } from '#micro509/jose';
import {
	DEFAULT_JOSE_LIMITS,
	parseCompactJws,
	signCompactJws,
	verifyCompactJws,
} from '#micro509/jose';
import { isResultError } from '#micro509/result';
import {
	base64UrlOfText,
	callUntyped,
	expectRejectedErrorCode,
	joseTestKeys,
	signRawRs256Token,
} from '#test/helpers';

const [primary, secondary] = await joseTestKeys();
const payload = new TextEncoder().encode('{"hello":"world"}');

function options(overrides: Partial<VerifyJwsOptions> = {}): VerifyJwsOptions {
	return {
		algorithms: ['RS256'],
		key: primary.publicKey,
		tokenType: { unchecked: true },
		...overrides,
	};
}

async function sign(header: { typ?: string; kid?: string; cty?: string } = {}): Promise<string> {
	return signCompactJws({
		privateKey: primary.privateKey,
		algorithm: 'RS256',
		payload,
		header,
	});
}

function segments(token: string): [string, string, string] {
	const [header, body, signature] = token.split('.');
	if (header === undefined || body === undefined || signature === undefined) {
		throw new Error('unreachable');
	}
	return [header, body, signature];
}

function failureCode(result: { readonly ok: boolean; readonly code?: string }): string | undefined {
	return result.ok ? undefined : result.code;
}

describe('compact JWS signing and verification', () => {
	it('round-trips and returns the verified header and payload', async () => {
		const token = await sign({ typ: 'JWT', kid: 'k1' });
		const result = await verifyCompactJws(token, options());
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.verified).toBe(true);
		expect(result.value.header).toMatchObject({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
		expect(result.value.payload).toEqual(payload);
	});

	it('emits alg first and only the requested header members', async () => {
		const [header] = segments(await sign({ typ: 'JWT', kid: 'k1', cty: 'x' }));
		const decoded = new TextDecoder().decode(
			Uint8Array.from(atob(header.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
				c.charCodeAt(0),
			),
		);
		expect(decoded).toBe('{"alg":"RS256","typ":"JWT","kid":"k1","cty":"x"}');
	});

	it('verifies an empty payload', async () => {
		const token = await signCompactJws({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			payload: new Uint8Array(),
		});
		const result = await verifyCompactJws(token, options());
		expect(result.ok && result.value.payload.length).toBe(0);
	});

	it('rejects a different key, an altered payload and an altered signature', async () => {
		const token = await sign();
		const [header, body, signature] = segments(token);
		expect(failureCode(await verifyCompactJws(token, options({ key: secondary.publicKey })))).toBe(
			'invalid_signature',
		);
		const altered = `${header}.${base64UrlOfText('{"hello":"mallory"}')}.${signature}`;
		expect(failureCode(await verifyCompactJws(altered, options()))).toBe('invalid_signature');
		const flipped = `${signature.slice(0, -4)}${signature.endsWith('AAAA') ? 'BBBB' : 'AAAA'}`;
		expect(failureCode(await verifyCompactJws(`${header}.${body}.${flipped}`, options()))).toBe(
			'invalid_signature',
		);
	});

	it('rejects a signature shorter or longer than the modulus', async () => {
		const [header, body, signature] = segments(await sign());
		const short = signature.slice(0, 340);
		expect(failureCode(await verifyCompactJws(`${header}.${body}.${short}`, options()))).toBe(
			'invalid_signature',
		);
		expect(
			failureCode(await verifyCompactJws(`${header}.${body}.${signature}AAAA`, options())),
		).toBe('invalid_signature');
		expect(failureCode(await verifyCompactJws(`${header}.${body}.`, options()))).toBe(
			'invalid_signature',
		);
	});

	it('rejects a header altered after signing', async () => {
		const [, body, signature] = segments(await sign());
		const forged = `${base64UrlOfText('{"alg":"RS256","kid":"other"}')}.${body}.${signature}`;
		expect(failureCode(await verifyCompactJws(forged, options()))).toBe('invalid_signature');
	});

	it('never echoes the token in a failure', async () => {
		const token = await sign();
		const result = await verifyCompactJws(`${token}x`, options({ key: secondary.publicKey }));
		expect(JSON.stringify(result)).not.toContain(segments(token)[1]);
	});
});

describe('algorithm policy', () => {
	it('refuses unsigned tokens even when the caller lists none-looking input', async () => {
		const unsigned = `${base64UrlOfText('{"alg":"none"}')}.${base64UrlOfText('{}')}.`;
		expect(failureCode(await verifyCompactJws(unsigned, options()))).toBe('unsigned_token');
		const withSignature = `${base64UrlOfText('{"alg":"none"}')}.${base64UrlOfText('{}')}.AAAA`;
		expect(failureCode(await verifyCompactJws(withSignature, options()))).toBe('unsigned_token');
	});

	it('refuses algorithms outside the caller list, comparing case-sensitively', async () => {
		for (const alg of ['HS256', 'RS384', 'PS256', 'ES256', 'EdDSA', 'rs256', 'RS256 ', 'NONE']) {
			const token = `${base64UrlOfText(JSON.stringify({ alg }))}.${base64UrlOfText('{}')}.AAAA`;
			const code = failureCode(await verifyCompactJws(token, options()));
			expect({ alg, code }).toEqual({
				alg,
				code: alg === 'NONE' ? 'algorithm_not_allowed' : 'algorithm_not_allowed',
			});
		}
	});

	it('does not confuse an HMAC token keyed with public key bytes for RS256', async () => {
		const spki = new Uint8Array(await crypto.subtle.exportKey('spki', primary.publicKey));
		const hmacKey = await crypto.subtle.importKey(
			'raw',
			spki,
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign'],
		);
		const signingInput = `${base64UrlOfText('{"alg":"HS256"}')}.${base64UrlOfText('{}')}`;
		const mac = new Uint8Array(
			await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(signingInput)),
		);
		const token = `${signingInput}.${base64UrlEncode(mac)}`;
		expect(failureCode(await verifyCompactJws(token, options()))).toBe('algorithm_not_allowed');
	});

	it('requires an explicit supported algorithm list', async () => {
		const token = await sign();
		const empty = await callUntyped(verifyCompactJws, token, { ...options(), algorithms: [] });
		expect(failureCode(empty)).toBe('invalid_options');
		const unknown = await callUntyped(verifyCompactJws, token, {
			...options(),
			algorithms: ['HS256'],
		});
		expect(failureCode(unknown)).toBe('invalid_options');
		const missing = await callUntyped(verifyCompactJws, token, { key: primary.publicKey });
		expect(failureCode(missing)).toBe('invalid_options');
	});
});

describe('token type policy', () => {
	it('matches typ as a media type, case-insensitively, restoring application/', async () => {
		const token = await sign({ typ: 'at+JWT' });
		for (const expected of ['at+jwt', 'AT+JWT', 'application/at+jwt', 'Application/AT+jwt']) {
			const result = await verifyCompactJws(token, options({ tokenType: expected }));
			expect({ expected, ok: result.ok }).toEqual({ expected, ok: true });
		}
		const slashed = await sign({ typ: 'application/at+jwt' });
		expect((await verifyCompactJws(slashed, options({ tokenType: 'at+jwt' }))).ok).toBe(true);
	});

	it('rejects another type, a missing typ, and a present typ when absent is required', async () => {
		expect(
			failureCode(
				await verifyCompactJws(await sign({ typ: 'JWT' }), options({ tokenType: 'at+jwt' })),
			),
		).toBe('token_type_mismatch');
		expect(failureCode(await verifyCompactJws(await sign(), options({ tokenType: 'JWT' })))).toBe(
			'token_type_mismatch',
		);
		expect(
			failureCode(
				await verifyCompactJws(
					await sign({ typ: 'JWT' }),
					options({ tokenType: { absent: true } }),
				),
			),
		).toBe('token_type_mismatch');
		expect(
			(await verifyCompactJws(await sign(), options({ tokenType: { absent: true } }))).ok,
		).toBe(true);
	});

	it('compares media type parameters by exact value and name case-insensitively', async () => {
		const token = await sign({ typ: 'x+jwt; Profile=Abc' });
		expect((await verifyCompactJws(token, options({ tokenType: 'x+jwt;profile=Abc' }))).ok).toBe(
			true,
		);
		expect(
			failureCode(await verifyCompactJws(token, options({ tokenType: 'x+jwt;profile=abc' }))),
		).toBe('token_type_mismatch');
	});

	it('compares media type parameters without a value by lower-cased name', async () => {
		const token = await sign({ typ: 'x+jwt; Flag' });
		expect((await verifyCompactJws(token, options({ tokenType: 'x+jwt;flag' }))).ok).toBe(true);
		expect(failureCode(await verifyCompactJws(token, options({ tokenType: 'x+jwt;other' })))).toBe(
			'token_type_mismatch',
		);
	});

	it('applies the type policy before resolving a key', async () => {
		let calls = 0;
		const result = await verifyCompactJws(
			await sign({ typ: 'JWT' }),
			options({
				tokenType: 'at+jwt',
				key: async () => {
					calls++;
					return { ok: true, value: primary.publicKey };
				},
			}),
		);
		expect(failureCode(result)).toBe('token_type_mismatch');
		expect(calls).toBe(0);
	});

	it('requires a token type policy', async () => {
		const result = await callUntyped(verifyCompactJws, await sign(), {
			algorithms: ['RS256'],
			key: primary.publicKey,
		});
		expect(failureCode(result)).toBe('invalid_options');
	});
});

describe('structural refusal', () => {
	it('requires exactly three segments', async () => {
		const token = await sign();
		expect(failureCode(parseCompactJws('a.b'))).toBe('malformed_token');
		expect(failureCode(parseCompactJws(`${token}.x`))).toBe('malformed_token');
		expect(failureCode(parseCompactJws('a.b.c.d.e'))).toBe('malformed_token');
		expect(failureCode(parseCompactJws(`.${segments(token)[1]}.${segments(token)[2]}`))).toBe(
			'malformed_token',
		);
		expect(failureCode(callUntyped(parseCompactJws, 42))).toBe('malformed_token');
	});

	it('rejects padding, standard-alphabet characters, whitespace and non-canonical bits', async () => {
		const [header, body, signature] = segments(await sign());
		for (const bad of [`${header}=`, `${header} `, `${header}\n`, `${header}+`, `${header}/`]) {
			expect(failureCode(parseCompactJws(`${bad}.${body}.${signature}`))).toBe('invalid_encoding');
		}
		expect(failureCode(parseCompactJws(`${header}.${body}=.${signature}`))).toBe(
			'invalid_encoding',
		);
		expect(failureCode(parseCompactJws(`${header}.${body}.${signature}=`))).toBe(
			'invalid_encoding',
		);
		expect(failureCode(parseCompactJws(`${header.slice(0, -1)}.${body}.${signature}`))).toMatch(
			/invalid_encoding|invalid_utf8|invalid_json|invalid_header/,
		);
	});

	it('rejects non-zero pad bits in the final character', () => {
		const good = base64UrlOfText('{"alg":"RS256"} ');
		expect(good).toHaveLength(22);
		expect(parseCompactJws(`${good}.e30.AAAA`).ok).toBe(true);
		const last = good[good.length - 1] ?? '';
		const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
		const neighbour = alphabet[(alphabet.indexOf(last) + 1) % 64] ?? '';
		const twin = `${good.slice(0, -1)}${neighbour}`;
		expect(failureCode(parseCompactJws(`${twin}.e30.AAAA`))).toBe('invalid_encoding');
		expect(failureCode(parseCompactJws(`${good}.e31.AAAA`))).toBe('invalid_encoding');
		expect(failureCode(parseCompactJws(`${good}.e30.AAB`))).toBe('invalid_encoding');
	});

	it('rejects invalid UTF-8 and a UTF-8 BOM in the header', () => {
		const badUtf8 = base64UrlEncode(Uint8Array.of(0x7b, 0xff, 0x7d));
		expect(failureCode(parseCompactJws(`${badUtf8}.e30.AAAA`))).toBe('invalid_utf8');
		const overlong = base64UrlEncode(Uint8Array.of(0x7b, 0xc0, 0xaf, 0x7d));
		expect(failureCode(parseCompactJws(`${overlong}.e30.AAAA`))).toBe('invalid_utf8');
		const bom = base64UrlEncode(
			Uint8Array.of(0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"alg":"RS256"}')),
		);
		expect(failureCode(parseCompactJws(`${bom}.e30.AAAA`))).toBe('invalid_json');
	});

	it('rejects headers that are not a JSON object with a string alg', () => {
		const cases: readonly (readonly [string, string])[] = [
			['[]', 'invalid_header'],
			['"RS256"', 'invalid_header'],
			['null', 'invalid_header'],
			['{}', 'invalid_header'],
			['{"alg":5}', 'invalid_header'],
			['{"alg":""}', 'invalid_header'],
			['{"alg":null}', 'invalid_header'],
			['{"alg":"RS256","kid":5}', 'invalid_header'],
			['{"alg":"RS256","typ":[]}', 'invalid_header'],
			['{"alg":"RS256","cty":false}', 'invalid_header'],
			['{"alg":"RS256",}', 'invalid_json'],
			['{"alg":"RS256"} ', 'ok'],
			['{"alg":"RS256"}x', 'invalid_json'],
			['{"alg":"RS256","alg":"RS256"}', 'duplicate_member'],
			['{"alg":"RS256","kid":"a","kid":"b"}', 'duplicate_member'],
			['{"alg":"RS256","\\u0061lg":"none"}', 'duplicate_member'],
		];
		for (const [headerText, expected] of cases) {
			const result = parseCompactJws(`${base64UrlOfText(headerText)}.e30.AAAA`);
			expect({ headerText, code: result.ok ? 'ok' : result.code }).toEqual({
				headerText,
				code: expected,
			});
		}
	});

	it('refuses critical headers and unencoded payloads explicitly', async () => {
		const crit = parseCompactJws(
			`${base64UrlOfText('{"alg":"RS256","crit":["exp"],"exp":1}')}.e30.AAAA`,
		);
		expect(crit).toMatchObject({ ok: false, code: 'unsupported_critical_header' });
		if (crit.ok) throw new Error('unreachable');
		expect(crit.details?.crit).toEqual(['exp']);
		for (const [headerText, expected] of [
			['{"alg":"RS256","crit":[]}', 'invalid_header'],
			['{"alg":"RS256","crit":"b64"}', 'invalid_header'],
			['{"alg":"RS256","crit":[1]}', 'invalid_header'],
			['{"alg":"RS256","crit":["x","x"],"x":1}', 'invalid_header'],
			['{"alg":"RS256","crit":["x"]}', 'unsupported_critical_header'],
			['{"alg":"RS256","b64":false}', 'unsupported_unencoded_payload'],
			['{"alg":"RS256","b64":false,"crit":["b64"]}', 'unsupported_unencoded_payload'],
			['{"alg":"RS256","crit":["b64"]}', 'unsupported_unencoded_payload'],
			['{"alg":"RS256","b64":"false"}', 'invalid_header'],
		] as const) {
			const result = parseCompactJws(`${base64UrlOfText(headerText)}.e30.AAAA`);
			expect({ headerText, code: result.ok ? 'ok' : result.code }).toEqual({
				headerText,
				code: expected,
			});
		}
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","crit":["x"],"x":1}',
			'{}',
		);
		expect(failureCode(await verifyCompactJws(token, options()))).toBe(
			'unsupported_critical_header',
		);
	});

	it('ignores jku, jwk, x5u and x5c rather than following them', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			JSON.stringify({
				alg: 'RS256',
				jku: 'https://attacker.example/jwks',
				x5u: 'https://attacker.example/cert',
				jwk: { kty: 'RSA', n: 'AQAB', e: 'AQAB' },
				x5c: ['AAAA'],
			}),
			'{}',
		);
		expect((await verifyCompactJws(token, options())).ok).toBe(true);
		expect(failureCode(await verifyCompactJws(token, options({ key: secondary.publicKey })))).toBe(
			'invalid_signature',
		);
	});

	it('keeps unrecognized header members reachable', async () => {
		const token = await signRawRs256Token(
			primary.privateKey,
			'{"alg":"RS256","x-custom":[1,2]}',
			'{}',
		);
		const parsed = parseCompactJws(token);
		expect(parsed.ok && parsed.value.header.members['x-custom']).toEqual([1, 2]);
	});
});

describe('bounds', () => {
	it('rejects an oversized token before decoding anything', () => {
		const huge = `${'A'.repeat(DEFAULT_JOSE_LIMITS.maxTokenLength)}.A.A`;
		expect(failureCode(parseCompactJws(huge))).toBe('token_too_large');
		expect(failureCode(parseCompactJws('a.b.c', { maxTokenLength: 4 }))).toBe('token_too_large');
	});

	it('bounds each decoded segment', async () => {
		const [header, body, signature] = segments(await sign());
		expect(
			failureCode(parseCompactJws(`${header}.${body}.${signature}`, { maxHeaderBytes: 8 })),
		).toBe('limit_exceeded');
		expect(
			failureCode(parseCompactJws(`${header}.${body}.${signature}`, { maxPayloadBytes: 4 })),
		).toBe('limit_exceeded');
		expect(
			failureCode(parseCompactJws(`${header}.${body}.${signature}`, { maxSignatureBytes: 16 })),
		).toBe('limit_exceeded');
		expect(
			parseCompactJws(`${header}.${body}.${signature}`, { maxPayloadBytes: payload.length }).ok,
		).toBe(true);
	});

	it('bounds header JSON nesting and node count', () => {
		const deep = `{"alg":"RS256","x":${'['.repeat(40)}${']'.repeat(40)}}`;
		expect(failureCode(parseCompactJws(`${base64UrlOfText(deep)}.e30.AAAA`))).toBe(
			'limit_exceeded',
		);
		const members = Array.from({ length: 50 }, (_, index) => `"k${index}":1`).join(',');
		expect(
			failureCode(
				parseCompactJws(`${base64UrlOfText(`{"alg":"RS256",${members}}`)}.e30.AAAA`, {
					maxJsonNodes: 20,
				}),
			),
		).toBe('limit_exceeded');
	});
});

describe('key suitability', () => {
	it('rejects a private key, a key without verify usage, and a non-RSA key', async () => {
		const token = await sign();
		expect(failureCode(await verifyCompactJws(token, options({ key: primary.privateKey })))).toBe(
			'key_unsuitable',
		);
		const noVerify = await crypto.subtle.importKey(
			'spki',
			await crypto.subtle.exportKey('spki', primary.publicKey),
			{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
			true,
			[],
		);
		expect(failureCode(await verifyCompactJws(token, options({ key: noVerify })))).toBe(
			'key_unsuitable',
		);
		const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
			'sign',
			'verify',
		]);
		expect(failureCode(await verifyCompactJws(token, options({ key: ec.publicKey })))).toBe(
			'key_unsuitable',
		);
	});

	it('rejects RSA keys bound to another scheme or hash, and moduli under 2048 bits', async () => {
		const token = await sign();
		const pss = await crypto.subtle.generateKey(
			{
				name: 'RSA-PSS',
				modulusLength: 2048,
				publicExponent: Uint8Array.of(1, 0, 1),
				hash: 'SHA-256',
			},
			true,
			['sign', 'verify'],
		);
		expect(failureCode(await verifyCompactJws(token, options({ key: pss.publicKey })))).toBe(
			'key_unsuitable',
		);
		const sha384 = await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 2048,
				publicExponent: Uint8Array.of(1, 0, 1),
				hash: 'SHA-384',
			},
			true,
			['sign', 'verify'],
		);
		expect(failureCode(await verifyCompactJws(token, options({ key: sha384.publicKey })))).toBe(
			'key_unsuitable',
		);
		const small = await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 1024,
				publicExponent: Uint8Array.of(1, 0, 1),
				hash: 'SHA-256',
			},
			true,
			['sign', 'verify'],
		);
		expect(failureCode(await verifyCompactJws(token, options({ key: small.publicKey })))).toBe(
			'key_unsuitable',
		);
	});

	it('passes the unauthenticated header, algorithm and kid to a resolver', async () => {
		const token = await sign({ kid: 'abc' });
		const controller = new AbortController();
		const seen: unknown[] = [];
		const result = await verifyCompactJws(
			token,
			options({
				signal: controller.signal,
				key: async (request) => {
					seen.push(request.kid, request.algorithm, request.signal === controller.signal);
					return { ok: true, value: primary.publicKey };
				},
			}),
		);
		expect(result.ok).toBe(true);
		expect(seen).toEqual(['abc', 'RS256', true]);
	});

	it('returns a resolver failure unchanged', async () => {
		const result = await verifyCompactJws(
			await sign(),
			options({
				key: async () => ({
					ok: false,
					code: 'key_not_found',
					message: 'none',
					error: { ok: false, code: 'key_not_found', message: 'none' },
				}),
			}),
		);
		expect(failureCode(result)).toBe('key_not_found');
	});
});

describe('signing input validation', () => {
	it('throws coded ResultErrors for unusable keys, algorithms and headers', async () => {
		await expectRejectedErrorCode(
			signCompactJws({ privateKey: primary.publicKey, algorithm: 'RS256', payload }),
			'incompatible_key',
		);
		await expectRejectedErrorCode(
			callUntyped(signCompactJws, { privateKey: primary.privateKey, algorithm: 'HS256', payload }),
			'unsupported_algorithm',
		);
		await expectRejectedErrorCode(
			callUntyped(signCompactJws, {
				privateKey: primary.privateKey,
				algorithm: 'RS256',
				payload,
				header: { kid: 5 },
			}),
			'invalid_header',
		);
		const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
			'sign',
			'verify',
		]);
		await expectRejectedErrorCode(
			signCompactJws({ privateKey: ec.privateKey, algorithm: 'RS256', payload }),
			'incompatible_key',
		);
		try {
			await signCompactJws({ privateKey: primary.publicKey, algorithm: 'RS256', payload });
		} catch (error) {
			expect(isResultError(error)).toBe(true);
		}
	});
});

describe('verification options are validated, not trusted', () => {
	async function codeWith(overrides: Record<string, unknown>): Promise<string> {
		const result = await callUntyped(verifyCompactJws, await sign({ typ: 'JWT' }), {
			algorithms: ['RS256'],
			key: primary.publicKey,
			tokenType: 'JWT',
			...overrides,
		});
		return result.ok ? 'ok' : result.code;
	}

	it('requires literal true discriminants and rejects ambiguous token type objects', async () => {
		for (const tokenType of [
			{ unchecked: false },
			{ absent: false },
			{ unchecked: 1 },
			{ unchecked: 'true' },
			{ absent: true, unchecked: true },
			{ unchecked: true, extra: true },
			{},
			[],
			null,
			undefined,
			5,
			true,
		]) {
			expect({ tokenType, code: await codeWith({ tokenType }) }).toEqual({
				tokenType,
				code: 'invalid_options',
			});
		}
		expect(await codeWith({ tokenType: { unchecked: true } })).toBe('ok');
		expect(await codeWith({ tokenType: { absent: true } })).toBe('token_type_mismatch');
	});

	it('rejects unusable keys, signals and algorithm entries', async () => {
		for (const overrides of [
			{ key: undefined },
			{ key: null },
			{ key: 'key' },
			{ key: {} },
			{ signal: {} },
			{ algorithms: 'RS256' },
			{ algorithms: [null] },
		]) {
			expect({ overrides, code: await codeWith(overrides) }).toEqual({
				overrides,
				code: 'invalid_options',
			});
		}
		expect(await callUntyped(verifyCompactJws, await sign(), null)).toMatchObject({
			ok: false,
			code: 'invalid_options',
		});
	});

	it('refuses limits that would disable a bound', async () => {
		const bad = [
			Number.NaN,
			Number.POSITIVE_INFINITY,
			0,
			-1,
			1.5,
			'5',
			null,
			Number.MAX_SAFE_INTEGER + 1,
		];
		for (const name of [
			'maxTokenLength',
			'maxHeaderBytes',
			'maxPayloadBytes',
			'maxSignatureBytes',
			'maxJsonDepth',
			'maxJsonNodes',
		]) {
			for (const value of bad) {
				expect({ name, value, code: await codeWith({ limits: { [name]: value } }) }).toEqual({
					name,
					value,
					code: 'invalid_options',
				});
				expect(callUntyped(parseCompactJws, 'a.b.c', { [name]: value })).toMatchObject({
					ok: false,
					code: 'invalid_options',
				});
			}
		}
		expect(await codeWith({ limits: { maxJsonDepth: 65 } })).toBe('invalid_options');
		expect(await codeWith({ limits: { maxJsonDepth: 64 } })).toBe('ok');
		expect(await codeWith({ limits: 5 })).toBe('invalid_options');
		expect(await codeWith({ limits: { maxPayloadBytes: undefined } })).toBe('ok');
		expect(await codeWith({ limits: {} })).toBe('ok');
	});

	it('uses the options as they were when the call began', async () => {
		const algorithms: string[] = ['RS256'];
		const result = await callUntyped(verifyCompactJws, await sign(), {
			algorithms,
			tokenType: { absent: true },
			key: async () => {
				algorithms.length = 0;
				algorithms.push('HS256');
				return { ok: true, value: primary.publicKey };
			},
		});
		expect(result.ok).toBe(true);
		expect(algorithms).toEqual(['HS256']);
	});
});

describe('resolver and crypto failures are typed and sanitized', () => {
	async function resolved(key: unknown, signal?: AbortSignal) {
		const result = await callUntyped(verifyCompactJws, await sign({ kid: 'k' }), {
			algorithms: ['RS256'],
			key,
			tokenType: { unchecked: true },
			...(signal === undefined ? {} : { signal }),
		});
		return result.ok ? undefined : result;
	}

	it('turns a throwing or rejecting resolver into key_resolution_failed without its message', async () => {
		const thrown = await resolved(() => {
			throw new Error('secret-token-material');
		});
		expect(thrown).toMatchObject({ ok: false, code: 'key_resolution_failed' });
		expect(JSON.stringify(thrown)).not.toContain('secret-token-material');
		const rejected = await resolved(async () => {
			throw new TypeError('also secret');
		});
		expect(rejected).toMatchObject({ ok: false, code: 'key_resolution_failed' });
		expect(JSON.stringify(rejected)).not.toContain('also secret');
	});

	it('reports a resolver that fails because the caller cancelled as aborted', async () => {
		const controller = new AbortController();
		const result = await resolved(async () => {
			controller.abort();
			throw new DOMException('aborted', 'AbortError');
		}, controller.signal);
		expect(result).toMatchObject({ ok: false, code: 'aborted' });
	});

	it('rejects results that are not a resolution', async () => {
		for (const value of [
			undefined,
			null,
			5,
			'ok',
			{},
			{ ok: true },
			{ ok: true, value: {} },
			{ ok: true, value: 'key' },
			{ ok: false },
			{ ok: false, code: 'something_else' },
			{ ok: false, code: 7 },
		]) {
			expect({ value, code: (await resolved(async () => value))?.code }).toEqual({
				value,
				code: 'key_resolution_failed',
			});
		}
	});

	it('passes through only the code, kid and status of a resolver failure', async () => {
		const result = await resolved(async () => ({
			ok: false,
			code: 'jwks_unavailable',
			message: 'leaks https://internal.example/token=abc',
			details: { status: 503, kid: 'k', alg: 'x', claim: 'y', crit: ['z'] },
		}));
		expect(result).toMatchObject({
			ok: false,
			code: 'jwks_unavailable',
			details: { status: 503, kid: 'k' },
		});
		expect(JSON.stringify(result)).not.toContain('internal.example');
		expect(result?.details).toEqual({ kid: 'k', status: 503 });
		const bare = await resolved(async () => ({ ok: false, code: 'key_not_found', details: 5 }));
		expect(bare).toMatchObject({ ok: false, code: 'key_not_found' });
		const noDetails = await resolved(async () => ({
			ok: false,
			code: 'key_not_found',
			details: { status: 1.5, kid: 5 },
		}));
		expect(noDetails?.details).toEqual({});
	});

	it('refuses a key-like object it cannot inspect or that WebCrypto refuses to use', async () => {
		expect(await resolved(Object.create(primary.publicKey))).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
		});
		const forged = Object.create(Object.getPrototypeOf(primary.publicKey), {
			type: { value: 'public' },
			usages: { value: ['verify'] },
			algorithm: {
				value: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' }, modulusLength: 2048 },
			},
		});
		expect(await resolved(forged)).toMatchObject({ ok: false, code: 'invalid_signature' });
	});
});
