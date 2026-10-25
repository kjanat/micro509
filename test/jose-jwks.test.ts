import { describe, expect, it } from 'bun:test';
import {
	createJwksKeyResolver,
	DEFAULT_JWKS_LIMITS,
	importJwkEntry,
	parseJwks,
	selectJwk,
	signCompactJws,
	verifyCompactJws,
} from '#micro509/jose';
import { callUntyped, joseTestKeys, rsaJwkEntry } from '#test/helpers';

const [primary, secondary] = await joseTestKeys();
const payload = new TextEncoder().encode('{}');

function document(...keys: readonly Record<string, unknown>[]): string {
	return JSON.stringify({ keys });
}

function parsed(...keys: readonly Record<string, unknown>[]) {
	const result = parseJwks(document(...keys));
	if (!result.ok) throw new Error(`unreachable: ${result.code}`);
	return result.value;
}

async function tokenWith(kid: string | undefined, pair = primary): Promise<string> {
	return await signCompactJws({
		privateKey: pair.privateKey,
		algorithm: 'RS256',
		payload,
		header: kid === undefined ? {} : { kid },
	});
}

function verifyWith(token: string, jwks: ReturnType<typeof parsed>) {
	return verifyCompactJws(token, {
		algorithms: ['RS256'],
		key: createJwksKeyResolver(jwks),
		tokenType: { unchecked: true },
	});
}

describe('parseJwks', () => {
	it('parses RSA keys and keeps entries it will not use as typed variants', async () => {
		const result = parseJwks(
			document(
				await rsaJwkEntry(primary, { kid: 'a', use: 'sig', alg: 'RS256', key_ops: ['verify'] }),
				{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'ec' },
				{ kty: 'oct', k: 'AAAA' },
				{ kty: 'RSA', kid: 'broken' },
				{ kid: 'no-kty' },
				{ kty: 'RSA', n: 'AQAB', e: 'AQAB', kid: 5 },
			),
		);
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.keys.map((entry) => entry.kind)).toEqual([
			'rsa',
			'unsupported',
			'unsupported',
			'unsupported',
			'unsupported',
			'unsupported',
		]);
		expect(result.value.keys[0]).toMatchObject({
			kind: 'rsa',
			kid: 'a',
			use: 'sig',
			alg: 'RS256',
			keyOps: ['verify'],
		});
		expect(result.value.keys[1]).toMatchObject({ kind: 'unsupported', kty: 'EC', kid: 'ec' });
	});

	it('refuses documents that are not a JWK Set', () => {
		const bad = [
			'',
			'[]',
			'null',
			'{}',
			'{"keys":{}}',
			'{"keys":[1]}',
			'{"keys":[null]}',
			'{"keys":[[]]}',
			'{"keys":[],"keys":[]}',
			'{"keys":[{"kty":"RSA","kty":"RSA"}]}',
			'{"keys":[]',
			'﻿{"keys":[]}',
		];
		for (const text of bad) {
			expect({ text, ok: parseJwks(text).ok }).toEqual({ text, ok: false });
		}
		expect(parseJwks('{"keys":[]}').ok).toBe(true);
		expect(parseJwks('{"keys":[],"extra":[1,2]}').ok).toBe(true);
	});

	it('rejects invalid UTF-8', () => {
		expect(parseJwks(Uint8Array.of(0x7b, 0xff, 0x7d))).toMatchObject({
			ok: false,
			code: 'jwks_malformed',
		});
	});

	it('bounds document size, key count and nesting', () => {
		expect(parseJwks(`{"keys":[],"pad":"${'x'.repeat(100)}"}`, { maxBytes: 50 })).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
		const many = Array.from({ length: DEFAULT_JWKS_LIMITS.maxKeys + 1 }, () => ({ kty: 'oct' }));
		expect(parseJwks(document(...many))).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(parseJwks(document(...many.slice(1))).ok).toBe(true);
		expect(parseJwks(document(...many.slice(0, 3)), { maxKeys: 2 })).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
		expect(parseJwks(`{"keys":[],"x":${'['.repeat(20)}${']'.repeat(20)}}`)).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
	});
});

describe('selectJwk', () => {
	it('selects by kid', async () => {
		const jwks = parsed(
			await rsaJwkEntry(primary, { kid: 'a' }),
			await rsaJwkEntry(secondary, { kid: 'b' }),
		);
		const a = selectJwk(jwks, { algorithm: 'RS256', kid: 'a' });
		const b = selectJwk(jwks, { algorithm: 'RS256', kid: 'b' });
		expect(a.ok && a.value.kid).toBe('a');
		expect(b.ok && b.value.kid).toBe('b');
		expect(selectJwk(jwks, { algorithm: 'RS256', kid: 'A' })).toMatchObject({
			ok: false,
			code: 'key_not_found',
		});
	});

	it('requires kid to disambiguate and rejects ambiguity', async () => {
		const two = parsed(
			await rsaJwkEntry(primary, { kid: 'a' }),
			await rsaJwkEntry(secondary, { kid: 'b' }),
		);
		expect(selectJwk(two, { algorithm: 'RS256' })).toMatchObject({
			ok: false,
			code: 'ambiguous_key',
		});
		const one = parsed(await rsaJwkEntry(primary, {}));
		expect(selectJwk(one, { algorithm: 'RS256' }).ok).toBe(true);
		expect(selectJwk(one, { algorithm: 'RS256', kid: 'x' })).toMatchObject({
			ok: false,
			code: 'key_not_found',
		});
	});

	it('rejects duplicate kids that both qualify, and picks the one that does', async () => {
		const duplicate = parsed(
			await rsaJwkEntry(primary, { kid: 'd' }),
			await rsaJwkEntry(secondary, { kid: 'd' }),
		);
		expect(selectJwk(duplicate, { algorithm: 'RS256', kid: 'd' })).toMatchObject({
			ok: false,
			code: 'ambiguous_key',
		});
		const disambiguated = parsed(
			await rsaJwkEntry(primary, { kid: 'd', use: 'enc' }),
			await rsaJwkEntry(secondary, { kid: 'd', use: 'sig' }),
		);
		const picked = selectJwk(disambiguated, { algorithm: 'RS256', kid: 'd' });
		expect(picked.ok && picked.value.use).toBe('sig');
	});

	it('skips keys unsuitable by type, use, key_ops, alg or parameters', async () => {
		const base = await rsaJwkEntry(primary, {});
		const cases: readonly Record<string, unknown>[] = [
			{ ...base, kid: 'k', use: 'enc' },
			{ ...base, kid: 'k', use: 'other' },
			{ ...base, kid: 'k', key_ops: ['sign'] },
			{ ...base, kid: 'k', key_ops: [] },
			{ ...base, kid: 'k', alg: 'RS384' },
			{ ...base, kid: 'k', alg: 'PS256' },
			{ ...base, kid: 'k', alg: 'rs256' },
			{ ...base, kid: 'k', use: 'sig', key_ops: ['verify', 'encrypt'] },
			{ kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA', kid: 'k' },
			{ ...base, kid: 'k', n: '' },
			{ ...base, kid: 'k', n: 'AQAB' },
			{ ...base, kid: 'k', n: `AA${String(base.n)}` },
			{ ...base, kid: 'k', e: 'AAEAAQ' },
			{ ...base, kid: 'k', e: '' },
			{ ...base, kid: 'k', n: `${String(base.n)}=` },
			{ ...base, kid: 'k', n: 'A'.repeat(1400) },
		];
		for (const entry of cases) {
			const result = selectJwk(parsed(entry), { algorithm: 'RS256', kid: 'k' });
			expect({
				entry: JSON.stringify(entry).slice(0, 40),
				code: result.ok ? 'ok' : result.code,
			}).toEqual({
				entry: JSON.stringify(entry).slice(0, 40),
				code: 'key_unsuitable',
			});
		}
	});

	it('accepts consistent use and key_ops and an alg that names the algorithm', async () => {
		const jwks = parsed(
			await rsaJwkEntry(primary, { kid: 'k', use: 'sig', key_ops: ['verify'], alg: 'RS256' }),
		);
		expect(selectJwk(jwks, { algorithm: 'RS256', kid: 'k' }).ok).toBe(true);
		const both = parsed(
			await rsaJwkEntry(primary, { kid: 'k', use: 'sig', key_ops: ['sign', 'verify'] }),
		);
		expect(selectJwk(both, { algorithm: 'RS256', kid: 'k' }).ok).toBe(true);
	});
});

describe('createJwksKeyResolver', () => {
	it('verifies tokens against the key their kid names', async () => {
		const jwks = parsed(
			await rsaJwkEntry(primary, { kid: 'a' }),
			await rsaJwkEntry(secondary, { kid: 'b' }),
		);
		expect((await verifyWith(await tokenWith('a'), jwks)).ok).toBe(true);
		expect((await verifyWith(await tokenWith('b', secondary), jwks)).ok).toBe(true);
		expect(await verifyWith(await tokenWith('a', secondary), jwks)).toMatchObject({
			ok: false,
			code: 'invalid_signature',
		});
		expect(await verifyWith(await tokenWith('zzz'), jwks)).toMatchObject({
			ok: false,
			code: 'key_not_found',
		});
		expect(await verifyWith(await tokenWith(undefined), jwks)).toMatchObject({
			ok: false,
			code: 'ambiguous_key',
		});
	});

	it('truncates an oversized kid in failure details', async () => {
		const jwks = parsed(await rsaJwkEntry(primary, { kid: 'a' }));
		const result = await verifyWith(await tokenWith('k'.repeat(500)), jwks);
		expect(result).toMatchObject({ ok: false, code: 'key_not_found' });
		if (result.ok) throw new Error('unreachable');
		expect(result.details?.kid).toBe('k'.repeat(64));
	});

	it('imports each key once', async () => {
		const jwks = parsed(await rsaJwkEntry(primary, { kid: 'a' }));
		const resolver = createJwksKeyResolver(jwks);
		const header = { alg: 'RS256', kid: 'a', members: {} } as const;
		const request = { header, algorithm: 'RS256', kid: 'a' } as const;
		const first = await resolver(request);
		const second = await resolver(request);
		expect(first.ok && second.ok && first.value === second.value).toBe(true);
	});

	it('imports a verify-only RS256 key', async () => {
		const jwks = parsed(await rsaJwkEntry(primary, { kid: 'a' }));
		const resolved = await createJwksKeyResolver(jwks)({
			header: { alg: 'RS256', kid: 'a', members: {} },
			algorithm: 'RS256',
			kid: 'a',
		});
		if (!resolved.ok) throw new Error('unreachable');
		expect(resolved.value.type).toBe('public');
		expect(resolved.value.usages).toEqual(['verify']);
		expect(resolved.value.algorithm).toMatchObject({ name: 'RSASSA-PKCS1-v1_5' });
	});

	it('reports a key WebCrypto refuses as unsuitable', async () => {
		const entry = { kind: 'rsa', kid: 'bad', n: '!!!', e: 'AQAB', members: {} } as const;
		expect(await importJwkEntry(entry)).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
			details: { kid: 'bad' },
		});
		expect(await importJwkEntry({ kind: 'rsa', n: '', e: '', members: {} })).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
		});
	});

	it('reports an RSA entry with non-minimal parameters as unsuitable', async () => {
		const base = await rsaJwkEntry(primary, { kid: 'a' });
		const jwks = parsed({ ...base, n: `AA${String(base.n)}` });
		expect(await verifyWith(await tokenWith('a'), jwks)).toMatchObject({
			ok: false,
			code: 'key_unsuitable',
		});
	});
});

describe('parseJwks limits and preservation', () => {
	it('refuses limits that would disable a bound', () => {
		for (const name of ['maxBytes', 'maxKeys']) {
			for (const value of [
				Number.NaN,
				Number.POSITIVE_INFINITY,
				0,
				-1,
				1.5,
				'5',
				null,
				Number.MAX_SAFE_INTEGER + 1,
				2 ** 40,
			]) {
				expect({
					name,
					value,
					result: callUntyped(parseJwks, '{"keys":[]}', { [name]: value }),
				}).toMatchObject({
					result: { ok: false, code: 'invalid_options' },
				});
			}
		}
		expect(callUntyped(parseJwks, '{"keys":[]}', 5)).toMatchObject({
			ok: false,
			code: 'invalid_options',
		});
		expect(parseJwks('{"keys":[]}', { maxBytes: undefined, maxKeys: undefined }).ok).toBe(true);
	});

	it('rejects an oversized string before encoding it', () => {
		const huge = `{"keys":[],"pad":"${'x'.repeat(5_000_000)}"}`;
		expect(parseJwks(huge)).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(parseJwks(huge, { maxBytes: 16_777_216 }).ok).toBe(true);
	});

	it('bounds the encoded size of bytes and of multi-byte strings', () => {
		expect(parseJwks(new Uint8Array(100), { maxBytes: 50 })).toMatchObject({
			ok: false,
			code: 'limit_exceeded',
		});
		const wide = `{"keys":[],"p":"${'é'.repeat(40)}"}`;
		expect(wide.length).toBeLessThan(100);
		expect(parseJwks(wide, { maxBytes: 90 })).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(parseJwks(new TextEncoder().encode(wide), { maxBytes: 200 }).ok).toBe(true);
	});

	it('rejects input that is neither a string nor bytes', () => {
		for (const input of [undefined, null, 5, {}, []]) {
			expect(callUntyped(parseJwks, input)).toMatchObject({ ok: false, code: 'jwks_malformed' });
		}
	});

	it('keeps every member of the document, of RSA entries and of unsupported entries', async () => {
		const rsa = {
			...(await rsaJwkEntry(primary, { kid: 'a' })),
			x5c: ['AAAA'],
			x5t: 'abc',
			extra: { n: [1, null] },
		};
		const ec = { kty: 'EC', crv: 'P-256', x: 'xx', y: 'yy', d: 'private', kid: 'ec' };
		const broken = { kty: 'RSA', kid: 5, n: 'AQAB', e: 'AQAB', custom: true };
		const document = { keys: [rsa, ec, broken], 'x-set': { source: 'test' } };
		const result = parseJwks(JSON.stringify(document));
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.members).toEqual(document);
		expect(result.value.keys.map((entry) => entry.members)).toEqual([rsa, ec, broken]);
		expect(result.value.keys[1]).toMatchObject({ kind: 'unsupported', kty: 'EC' });
		expect(result.value.keys[2]).toMatchObject({ kind: 'unsupported', kty: 'RSA' });
	});

	it('keeps __proto__ members as data', () => {
		const result = parseJwks(
			'{"keys":[{"kty":"oct","__proto__":{"polluted":true}}],"__proto__":1}',
		);
		if (!result.ok) throw new Error('unreachable');
		expect(Object.keys(result.value.members)).toEqual(['keys', '__proto__']);
		expect(Object.keys(result.value.keys[0]?.members ?? {})).toEqual(['kty', '__proto__']);
		const probe: { polluted?: boolean } = {};
		expect(probe.polluted).toBeUndefined();
	});
});
