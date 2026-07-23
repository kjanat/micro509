import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
	A1_UNASSIGNED_RANGES,
	B2_CASE_FOLD,
	NFKC_3_2_CORRECTIONS,
} from '#micro509/internal/shared/rfc3454-tables';

/**
 * Re-derives the frozen Unicode 3.2 tables directly from the vendored RFC 3454
 * text and asserts the committed `rfc3454-tables.ts` matches. This is the
 * generation step turned into a guard: the tables cannot silently drift from the
 * RFC, and completeness is proven rather than reviewed by hand.
 */

const rfc = readFileSync(new URL('../docs/rfc/rfc3454.txt', import.meta.url), 'utf8');

function tableLines(name: string): string[] {
	const out: string[] = [];
	let inside = false;
	for (const line of rfc.split('\n')) {
		if (line.includes(`Start Table ${name}`)) {
			inside = true;
			continue;
		}
		if (line.includes(`End Table ${name}`)) {
			inside = false;
			continue;
		}
		if (inside) {
			out.push(line);
		}
	}
	return out;
}

describe('RFC 3454 frozen tables', () => {
	it('Table A.1 unassigned ranges match the vendored RFC', () => {
		const expected: [number, number][] = [];
		for (const line of tableLines('A.1')) {
			const match = line.match(/^\s+([0-9A-Fa-f]+)(?:-([0-9A-Fa-f]+))?\s*$/);
			if (match === null) {
				continue;
			}
			const low = Number.parseInt(match[1] ?? '', 16);
			const high = match[2] === undefined ? low : Number.parseInt(match[2], 16);
			expected.push([low, high]);
		}
		expect(expected.length).toBeGreaterThan(300);
		expect(A1_UNASSIGNED_RANGES.map(([lo, hi]) => [lo, hi])).toEqual(expected);
	});

	it('Table B.2 case folds match the vendored RFC', () => {
		const expected = new Map<string, string>();
		for (const line of tableLines('B.2')) {
			const match = line.match(/^\s+([0-9A-Fa-f]+);\s+([0-9A-Fa-f ]+);/);
			if (match === null) {
				continue;
			}
			const source = String.fromCodePoint(Number.parseInt(match[1] ?? '', 16));
			const target = (match[2] ?? '')
				.trim()
				.split(/\s+/)
				.map((hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
				.join('');
			// The generator drops identity folds; the RFC has none, but stay safe.
			if (target !== source) {
				expected.set(source, target);
			}
		}
		expect(expected.size).toBeGreaterThan(1000);
		expect(B2_CASE_FOLD.size).toBe(expected.size);
		for (const [source, target] of expected) {
			expect(B2_CASE_FOLD.get(source)).toBe(target);
		}
		for (const source of B2_CASE_FOLD.keys()) {
			expect(expected.has(source)).toBe(true);
		}
	});

	it('freezes the five Unicode 4.0 NFKC corrections to their 3.2 targets', () => {
		expect([...NFKC_3_2_CORRECTIONS.entries()]).toEqual([
			[String.fromCodePoint(0x2f868), String.fromCodePoint(0x2136a)],
			[String.fromCodePoint(0x2f874), String.fromCodePoint(0x5f33)],
			[String.fromCodePoint(0x2f91f), String.fromCodePoint(0x43ab)],
			[String.fromCodePoint(0x2f95f), String.fromCodePoint(0x7aae)],
			[String.fromCodePoint(0x2f9bf), String.fromCodePoint(0x4d57)],
		]);
	});
});
