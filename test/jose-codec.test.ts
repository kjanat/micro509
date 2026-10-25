import { describe, expect, it } from 'bun:test';
import { base64UrlDecode, base64UrlEncode } from '#micro509/internal/jose/base64url';
import type { StrictJsonLimits } from '#micro509/internal/jose/strict-json';
import { parseStrictJson } from '#micro509/internal/jose/strict-json';

const limits: StrictJsonLimits = { maxDepth: 8, maxNodes: 64 };

describe('base64url codec', () => {
	it('round-trips every length from 0 to 64 bytes', () => {
		for (let length = 0; length <= 64; length++) {
			const bytes = crypto.getRandomValues(new Uint8Array(length));
			const encoded = base64UrlEncode(bytes);
			expect(encoded).not.toMatch(/[+/=]/);
			expect(base64UrlDecode(encoded)).toEqual(bytes);
		}
	});

	it('matches the RFC 4648 §10 vectors without padding', () => {
		const vectors: readonly (readonly [string, string])[] = [
			['', ''],
			['f', 'Zg'],
			['fo', 'Zm8'],
			['foo', 'Zm9v'],
			['foob', 'Zm9vYg'],
			['fooba', 'Zm9vYmE'],
			['foobar', 'Zm9vYmFy'],
		];
		for (const [plain, encoded] of vectors) {
			const bytes = new TextEncoder().encode(plain);
			expect(base64UrlEncode(bytes)).toBe(encoded);
			expect(base64UrlDecode(encoded)).toEqual(bytes);
		}
	});

	it('uses the URL-safe alphabet for 0xfb 0xff', () => {
		expect(base64UrlEncode(Uint8Array.of(0xfb, 0xff))).toBe('-_8');
		expect(base64UrlDecode('-_8')).toEqual(Uint8Array.of(0xfb, 0xff));
	});

	it('rejects padding, standard alphabet, whitespace and non-ASCII', () => {
		for (const value of ['Zg==', 'Zm8=', '+/8', 'Zm 9v', 'Zm9v\n', 'Zm9vé', 'ĀAAA', 'Zm9v!']) {
			expect(base64UrlDecode(value)).toBeUndefined();
		}
	});

	it('rejects a length that leaves a single dangling character', () => {
		expect(base64UrlDecode('A')).toBeUndefined();
		expect(base64UrlDecode('AAAAA')).toBeUndefined();
	});

	it('rejects non-zero trailing bits', () => {
		expect(base64UrlDecode('Zg')).toEqual(Uint8Array.of(0x66));
		expect(base64UrlDecode('Zh')).toBeUndefined();
		expect(base64UrlDecode('Zm9')).toBeUndefined();
		expect(base64UrlDecode('Zm8')).toEqual(new TextEncoder().encode('fo'));
	});
});

describe('strict JSON', () => {
	function parse(text: string) {
		return parseStrictJson(text, limits);
	}

	it('parses every value kind', () => {
		const result = parse('{"a":[1,-2.5e1,true,false,null,"x\\n\\u00e9\\ud83d\\ude00"],"b":{}}');
		expect(result).toEqual({
			ok: true,
			value: { a: [1, -25, true, false, null, 'x\né😀'], b: {} },
		});
	});

	it('tolerates RFC 8259 whitespace only', () => {
		expect(parse(' \t\r\n{"a" : 1 }\n').ok).toBe(true);
		expect(parse('\u000b{}')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse(' {}')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse('﻿{}')).toMatchObject({ ok: false, code: 'invalid_json' });
	});

	it('rejects duplicate members at any depth, comparing decoded names', () => {
		expect(parse('{"a":1,"a":2}')).toMatchObject({ ok: false, code: 'duplicate_member' });
		expect(parse('{"x":{"a":1,"a":2}}')).toMatchObject({ ok: false, code: 'duplicate_member' });
		expect(parse('{"a":1,"\\u0061":2}')).toMatchObject({ ok: false, code: 'duplicate_member' });
		expect(parse('[{"a":1,"a":1}]')).toMatchObject({ ok: false, code: 'duplicate_member' });
	});

	it('keeps __proto__ as an own data member', () => {
		const result = parse('{"__proto__":{"admin":true}}');
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		const value = result.value;
		if (typeof value !== 'object' || value === null || Array.isArray(value)) {
			throw new Error('unreachable');
		}
		expect(Object.keys(value)).toEqual(['__proto__']);
		expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
		const probe: { admin?: boolean } = {};
		expect(probe.admin).toBeUndefined();
	});

	it('rejects malformed documents', () => {
		const malformed = [
			'',
			'{',
			'{"a"}',
			'{"a":}',
			'{"a":1,}',
			'[1,]',
			'{a:1}',
			"{'a':1}",
			'[01]',
			'[1.]',
			'[.5]',
			'[+1]',
			'[NaN]',
			'[Infinity]',
			'[1e999]',
			'["\u0001"]',
			'["\\x"]',
			'["\\u12"]',
			'["abc',
			'{} {}',
			'{}x',
			'tru',
			'nul',
			'// c\n{}',
		];
		for (const text of malformed) {
			expect({ text, result: parse(text) }).toMatchObject({
				result: { ok: false, code: 'invalid_json' },
			});
		}
	});

	it('rejects lone surrogate escapes and accepts pairs', () => {
		expect(parse('"\\ud800"')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse('"\\udc00"')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse('"\\ud800\\u0041"')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse('"\\ud800x"')).toMatchObject({ ok: false, code: 'invalid_json' });
		expect(parse('"\\ud83d\\ude00"')).toEqual({ ok: true, value: '😀' });
	});

	it('enforces depth and node limits', () => {
		const deep = `${'['.repeat(9)}${']'.repeat(9)}`;
		expect(parse(deep)).toMatchObject({ ok: false, code: 'limit_exceeded' });
		expect(parse(`${'['.repeat(8)}${']'.repeat(8)}`).ok).toBe(true);
		const wide = `[${new Array(70).fill('0').join(',')}]`;
		expect(parse(wide)).toMatchObject({ ok: false, code: 'limit_exceeded' });
		const members = `{${Array.from({ length: 40 }, (_, index) => `"k${index}":1`).join(',')}}`;
		expect(parse(members)).toMatchObject({ ok: false, code: 'limit_exceeded' });
	});

	it('lets a stack overflow from an unbounded depth limit propagate', () => {
		const unbounded: StrictJsonLimits = {
			maxDepth: Number.MAX_SAFE_INTEGER,
			maxNodes: Number.MAX_SAFE_INTEGER,
		};
		expect(() => parseStrictJson('['.repeat(500_000), unbounded)).toThrow(RangeError);
	});
});
