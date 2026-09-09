/** Re-derives the frozen combining-mark table from the vendored RFC 4518 text. */

import { expect, test } from 'bun:test';
import { COMBINING_MARK_RANGES } from '#micro509/internal/shared/rfc4518-tables';
import { rfcDir } from '#test/helpers';

const rfc = await Bun.file(`${rfcDir}/rfc4518.txt`).text();

test('RFC 4518 Appendix A combining-mark ranges match the vendored RFC', () => {
	const appendix = rfc.split('Appendix A.  Combining Marks').at(-1)?.split('Appendix B.')[0] ?? '';
	const expected: [number, number][] = [];
	for (const token of appendix.match(/[0-9A-F]{4,6}(?:-[0-9A-F]{4,6})?/g) ?? []) {
		const [lowHex = '', highHex = lowHex] = token.split('-');
		expected.push([Number.parseInt(lowHex, 16), Number.parseInt(highHex, 16)]);
	}
	expect(expected.length).toBeGreaterThan(100);
	expect(COMBINING_MARK_RANGES.map(([low, high]) => [low, high])).toEqual(expected);
});
