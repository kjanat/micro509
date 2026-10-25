import { describe, expect, test } from 'bun:test';
import { multiplyHigh } from '#micro509/kdf/argon2-arithmetic';

const edges = [
	0, 1, 2, 0xffff, 0x1_0000, 0x1_0001, 0x3fff_ffff, 0x4000_0000, 0x4000_0001, 0x7fff_ffff,
	0x8000_0000, 0x8000_0001, 0xffff_fbff, 0xffff_fc00, 0xffff_fc01, 0xffff_fffe, 0xffff_ffff,
];

// Deterministic full-width operands complement the carry and rounding edges.
let seed = 0x9106;
function nextWord(): number {
	seed ^= seed << 13;
	seed ^= seed >>> 17;
	seed ^= seed << 5;
	return seed >>> 0;
}

describe('Argon2 high product word agrees with exact BigInt arithmetic', () => {
	describe.each([
		{
			name: 'carry and rounding boundaries',
			pairs: edges.flatMap((a) => edges.map((b) => ({ a, b }))),
		},
		{
			name: 'deterministic full-width operands',
			pairs: Array.from({ length: 512 }, () => ({ a: nextWord(), b: nextWord() })),
		},
	])('$name', ({ pairs }) => {
		test.each(pairs)('$a × $b', ({ a, b }) => {
			expect(multiplyHigh(a, b, Math.imul(a, b))).toBe(Number((BigInt(a) * BigInt(b)) >> 32n));
		});
	});
});
