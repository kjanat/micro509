import { expect, it } from 'bun:test';
import { createJwksKeyResolver, parseJwks, signJwt, validateJwks, verifyJwt } from '#micro509/jose';
import { joseTestKeys, rsaJwkEntry } from '#test/helpers';

it('uses a detached object snapshot in a real resolver', async () => {
	const [pair] = await joseTestKeys();
	const jwk = await rsaJwkEntry(pair, { kid: 'primary', key_ops: ['verify'] });
	const input = { keys: [jwk], extra: { names: ['café', '🦊'] } };
	const result = validateJwks(input);
	expect(result.ok).toBe(true);
	if (!result.ok) throw new Error(result.code);
	input.keys.length = 0;
	input.extra.names[0] = 'changed';
	jwk.kid = 'changed';
	expect(result.value.members.extra).toEqual({ names: ['café', '🦊'] });
	const token = await signJwt({
		privateKey: pair.privateKey,
		algorithm: 'RS256',
		header: { kid: 'primary' },
		claims: { iss: 'issuer', aud: 'app', exp: 200 },
	});
	const verified = await verifyJwt(token, {
		key: createJwksKeyResolver(result.value),
		algorithms: ['RS256'],
		tokenType: { unchecked: true },
		claims: {
			issuer: 'issuer',
			audience: 'app',
			requiredClaims: ['exp'],
			now: () => new Date(100_000),
		},
	});
	expect(verified.ok).toBe(true);
});

it('refuses non-JSON data without invoking getters or toJSON', () => {
	let called = false;
	const getter = Object.defineProperty({}, 'keys', {
		enumerable: true,
		get() {
			called = true;
			return [];
		},
	});
	const circular: Record<string, unknown> = { keys: [] };
	circular.self = circular;
	for (const value of [
		getter,
		circular,
		{
			keys: [],
			toJSON() {
				called = true;
				return {};
			},
		},
		{ keys: [], x: undefined },
		{ keys: [], x: NaN },
		{ keys: [], x: Infinity },
		{ keys: [], x: 1n },
		{ keys: [], x: Symbol() },
		{ keys: [], x: new Date() },
		{ keys: [], x: new Map() },
		{ keys: [], x: '\ud800' },
		{ keys: [], x: new Array(1) },
		{ keys: [], [Symbol()]: 'x' },
	]) {
		expect(validateJwks(value)).toMatchObject({ ok: false, code: 'jwks_malformed' });
	}
	expect(called).toBe(false);
});

it('bounds keys, nodes, nesting and UTF-8 string sizes before copying', () => {
	expect(validateJwks({ keys: [{}, {}] }, { maxKeys: 1 })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(validateJwks({ keys: [], x: 'é'.repeat(40) }, { maxBytes: 60 })).toMatchObject({
		code: 'limit_exceeded',
	});
	expect(validateJwks({ keys: [], x: '\n'.repeat(40) }, { maxBytes: 60 })).toMatchObject({
		code: 'limit_exceeded',
	});
	let value: unknown = [];
	for (let i = 0; i < 10; i++) value = [value];
	expect(validateJwks({ keys: [], x: value })).toMatchObject({ code: 'limit_exceeded' });
	expect(
		validateJwks({ keys: [], x: Array.from({ length: 130 }, () => 0) }, { maxKeys: 1 }),
	).toMatchObject({ code: 'limit_exceeded' });
	for (const maxBytes of [0, NaN, 16_777_217])
		expect(validateJwks({ keys: [] }, { maxBytes })).toMatchObject({ code: 'invalid_options' });
	expect(validateJwks({ keys: [] }, { maxBytes: 11 }).ok).toBe(true);
	expect(validateJwks({ keys: [] }, { maxBytes: 10 })).toMatchObject({ code: 'limit_exceeded' });
});

it('shares document validation but cannot recover lexical duplicates after JSON.parse', () => {
	for (const value of [[], null, {}, { keys: {} }, { keys: [1] }, { keys: [null] }])
		expect(validateJwks(value)).toMatchObject({ code: 'jwks_malformed' });
	const raw = '{"keys":[],"keys":[{"kty":"oct","k":"AA"}]}';
	expect(parseJwks(raw)).toMatchObject({ code: 'jwks_malformed' });
	expect(validateJwks(JSON.parse(raw)).ok).toBe(true);
	const plain = Object.create(null);
	Object.defineProperty(plain, 'keys', { value: [], enumerable: true });
	expect(validateJwks(plain).ok).toBe(true);
});

it('counts scalar and escaped JSON data and keeps dangerous names as own members', () => {
	const value = {
		keys: [],
		['__proto__']: { safe: true },
		x: [null, false, true, 0, 1e30, '\\"\b\t\n\f\r\u0001é€🦊'],
	};
	const result = validateJwks(value);
	expect(result.ok).toBe(true);
	if (!result.ok) throw new Error(result.code);
	expect(Object.hasOwn(result.value.members, '__proto__')).toBe(true);
	expect(Object.getPrototypeOf(result.value.members)).toBe(Object.prototype);
	const raw = JSON.stringify(value);
	const size = new TextEncoder().encode(raw).length;
	expect(validateJwks(value, { maxBytes: size }).ok).toBe(true);
	expect(validateJwks(value, { maxBytes: size - 1 })).toMatchObject({ code: 'limit_exceeded' });
	const hidden = Object.defineProperty({ keys: [] }, 'hidden', { value: true });
	expect(validateJwks(hidden)).toMatchObject({ code: 'jwks_malformed' });
	expect(validateJwks({ keys: [], x: '\udc00' })).toMatchObject({ code: 'jwks_malformed' });
	const shared = { x: true };
	expect(validateJwks({ keys: [], a: shared, b: shared }).ok).toBe(true);
});
