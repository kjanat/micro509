/**
 * Derives the IDNA2008 tables micro509 freezes from the sources vendored under
 * `docs/idna/`: the IANA IDNA derived-property CSV and the Unicode Character
 * Database files for the same Unicode version.
 *
 * @module
 */

export const IDNA_UNICODE_VERSION = '12.0.0';

export const BIDI_CLASSES = [
	'L',
	'R',
	'AL',
	'AN',
	'EN',
	'ES',
	'CS',
	'ET',
	'ON',
	'BN',
	'NSM',
] as const;
export const JOINING_TYPES = ['D', 'L', 'R', 'T'] as const;
export const SCRIPTS = ['Greek', 'Hebrew', 'Hiragana', 'Katakana', 'Han'] as const;

export interface IdnaTables {
	readonly pvalid: readonly number[];
	readonly contextj: readonly number[];
	readonly contexto: readonly number[];
	readonly bidi: ReadonlyMap<(typeof BIDI_CLASSES)[number], readonly number[]>;
	readonly joining: ReadonlyMap<(typeof JOINING_TYPES)[number], readonly number[]>;
	readonly virama: readonly number[];
	readonly scripts: ReadonlyMap<(typeof SCRIPTS)[number], readonly number[]>;
	readonly marks: readonly number[];
	readonly widthDecompositions: readonly number[];
}

type Range = readonly [number, number];

function parseRange(field: string): Range {
	const [first = '', last = first] = field.trim().split(/\.\.|-/);
	return [Number.parseInt(first, 16), Number.parseInt(last, 16)];
}

/** Sorts and merges touching ranges, then flattens them to `[first, last, first, last, …]`. */
export function flattenRanges(ranges: readonly Range[]): number[] {
	const sorted = [...ranges].sort((left, right) => left[0] - right[0]);
	const merged: [number, number][] = [];
	for (const [first, last] of sorted) {
		const previous = merged.at(-1);
		if (previous !== undefined && first <= previous[1] + 1) {
			previous[1] = Math.max(previous[1], last);
		} else {
			merged.push([first, last]);
		}
	}
	return merged.flat();
}

/** Ranges from a UCD `code ; value` file whose value matches one of `values`. */
function ucdRanges(text: string, accept: (value: string) => boolean): Range[] {
	const ranges: Range[] = [];
	for (const line of text.split('\n')) {
		const data = line.split('#')[0]?.trim() ?? '';
		if (data.length === 0) continue;
		const [codes = '', value = ''] = data.split(';').map((field) => field.trim());
		if (accept(value)) ranges.push(parseRange(codes));
	}
	return ranges;
}

/** `[code point, mapping, …]` for each `<wide>` or `<narrow>` decomposition in UnicodeData.txt. */
function widthDecompositions(text: string): number[] {
	const pairs: number[] = [];
	for (const line of text.split('\n')) {
		const fields = line.split(';');
		const [type, ...mapping] = (fields[5] ?? '').split(' ');
		if (type !== '<wide>' && type !== '<narrow>') continue;
		if (mapping.length !== 1) throw new Error(`multi-code-point ${type} mapping: ${line}`);
		pairs.push(Number.parseInt(fields[0] ?? '', 16), Number.parseInt(mapping[0] ?? '', 16));
	}
	return pairs;
}

export async function deriveIdnaTables(dir: string): Promise<IdnaTables> {
	const read = (name: string) => Bun.file(`${dir}/${name}`).text();
	const csv = await read(`idna-tables-properties-${IDNA_UNICODE_VERSION}.csv`);
	const property = new Map<string, Range[]>();
	for (const line of csv.split(/\r?\n/).slice(1)) {
		const [codes = '', value = ''] = line.split(',');
		if (codes.length === 0) continue;
		property.set(value, [...(property.get(value) ?? []), parseRange(codes)]);
	}
	const ucd = `ucd-${IDNA_UNICODE_VERSION}`;
	const bidiText = await read(`${ucd}/DerivedBidiClass.txt`);
	const joiningText = await read(`${ucd}/DerivedJoiningType.txt`);
	const combiningText = await read(`${ucd}/DerivedCombiningClass.txt`);
	const scriptText = await read(`${ucd}/Scripts.txt`);
	const categoryText = await read(`${ucd}/DerivedGeneralCategory.txt`);
	const unicodeDataText = await read(`${ucd}/UnicodeData.txt`);
	const byValue = <T extends string>(text: string, values: readonly T[]): Map<T, number[]> =>
		new Map(
			values.map((value) => [value, flattenRanges(ucdRanges(text, (found) => found === value))]),
		);
	return {
		pvalid: flattenRanges(property.get('PVALID') ?? []),
		contextj: flattenRanges(property.get('CONTEXTJ') ?? []),
		contexto: flattenRanges(property.get('CONTEXTO') ?? []),
		bidi: byValue(bidiText, BIDI_CLASSES),
		joining: byValue(joiningText, JOINING_TYPES),
		virama: flattenRanges(ucdRanges(combiningText, (value) => value === '9')),
		scripts: byValue(scriptText, SCRIPTS),
		marks: flattenRanges(
			ucdRanges(categoryText, (value) => value === 'Mn' || value === 'Mc' || value === 'Me'),
		),
		widthDecompositions: widthDecompositions(unicodeDataText),
	};
}
