import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ParsedDocument, RfcMeta, SourceLine } from './types.ts';

const NUMBERED = /^(\d+(?:\.\d+)*)\.\s+(\S.*)$/;
const APPENDIX = /^Appendix\s+([A-Z])\.?\s+(\S.*)$/;
const LETTERED = /^([A-Z](?:\.\d+)+)\.\s+(\S.*)$/;
const FIELD = /^\s{0,8}([A-Z][A-Za-z' #]*):\s+(\S.*)$/;
const DATE = /^\s*((?:\d{1,2}\s+)?[A-Z][a-z]+\s+(?:\d{1,2},\s*)?\d{4})\s*$/;

const UNNUMBERED: ReadonlySet<string> = new Set(
	[
		'Abstract',
		'Acknowledgement',
		'Acknowledgements',
		'Acknowledgment',
		'Acknowledgments',
		'Author Information',
		"Author's Address",
		"Authors' Addresses",
		'Contributors',
		'Copyright Notice',
		"Editor's Address",
		"Editors' Addresses",
		'Full Copyright Statement',
		'IANA Considerations',
		'IESG Note',
		'Index',
		'Intellectual Property',
		'Intellectual Property Statement',
		'Introduction',
		'Normative References',
		'Informative References',
		'References',
		'Security Considerations',
		'Status of This Memo',
		'Table of Contents',
	].map((title) => title.toUpperCase()),
);

function frontMatterTitle(text: string): string | undefined {
	return UNNUMBERED.has(text.toUpperCase()) ? text : undefined;
}

function depthOf(value: string): number {
	return value.split('.').length;
}

function headingAt(entry: SourceLine, index: number): Heading | undefined {
	const text = entry.text.trimEnd();
	if (text === '' || /^\s/.test(text)) return undefined;
	const appendix = APPENDIX.exec(text);
	if (appendix?.[1] !== undefined && appendix[2] !== undefined) {
		return {
			number: appendix[1],
			title: cleanTitle(appendix[2]),
			depth: 1,
			line: entry.line,
			index,
		};
	}
	const numbered = NUMBERED.exec(text);
	if (numbered?.[1] !== undefined && numbered[2] !== undefined) {
		return {
			number: numbered[1],
			title: cleanTitle(numbered[2]),
			depth: depthOf(numbered[1]),
			line: entry.line,
			index,
		};
	}
	const lettered = LETTERED.exec(text);
	if (lettered?.[1] !== undefined && lettered[2] !== undefined) {
		return {
			number: lettered[1],
			title: cleanTitle(lettered[2]),
			depth: depthOf(lettered[1]),
			line: entry.line,
			index,
		};
	}
	const front = frontMatterTitle(text);
	if (front !== undefined) {
		return { number: front, title: front, depth: 1, line: entry.line, index };
	}
	return undefined;
}

function headingsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const headings: Heading[] = [];
	lines.forEach((entry, index) => {
		const heading = headingAt(entry, index);
		if (heading !== undefined) headings.push(heading);
	});
	return headings;
}

function fieldValue(raw: string): string {
	return (raw.split(/\s{2,}/)[0] ?? '').trim();
}

function numberList(raw: string | undefined): readonly number[] {
	if (raw === undefined) return [];
	return [...raw.matchAll(/\d+/g)]
		.map((match) => Number.parseInt(match[0], 10))
		.filter((value) => Number.isInteger(value) && value > 0);
}

function paragraphs(lines: readonly SourceLine[]): readonly (readonly string[])[] {
	const collected: string[][] = [];
	let current: string[] = [];
	for (const entry of lines) {
		if (entry.text.trim() === '') {
			if (current.length > 0) collected.push(current);
			current = [];
			continue;
		}
		current.push(entry.text);
	}
	if (current.length > 0) collected.push(current);
	return collected;
}

function isFieldParagraph(block: readonly string[]): boolean {
	return block.every((text) => FIELD.test(text));
}

function isDateParagraph(block: readonly string[]): boolean {
	return block.length === 1 && DATE.test(block[0] ?? '');
}

function isTitleParagraph(block: readonly string[]): boolean {
	return (
		block.length <= 4 &&
		block.every((text) => text.trim().length <= 76 && !text.trimEnd().endsWith('.'))
	);
}

function titleOf(blocks: readonly (readonly string[])[]): string {
	const parts: string[] = [];
	for (const block of blocks.slice(1)) {
		if (isFieldParagraph(block)) continue;
		if (isDateParagraph(block) || !isTitleParagraph(block)) break;
		if (block.length === 1 && frontMatterTitle(cleanTitle(block[0] ?? '')) !== undefined) break;
		parts.push(...block.map((text) => text.trim()));
	}
	return cleanTitle(parts.join(' '));
}

function dateOf(preamble: readonly SourceLine[]): string | undefined {
	let standalone: string | undefined;
	for (const entry of preamble) {
		const match = DATE.exec(entry.text);
		if (match?.[1] !== undefined) standalone = cleanTitle(match[1]);
	}
	if (standalone !== undefined) return standalone;
	for (const entry of preamble) {
		const columns = entry.text.split(/\s{2,}/).map((column) => column.trim());
		const last = columns[columns.length - 1];
		if (last !== undefined && columns.length > 1 && DATE.test(last)) return last;
	}
	return undefined;
}

function metaOf(
	lines: readonly SourceLine[],
	headings: readonly Heading[],
	fallback: number,
): RfcMeta {
	const end = Math.min(headings[0]?.index ?? lines.length, 80);
	const preamble = lines.slice(0, end);
	const fields = new Map<string, string>();
	let stream: string | undefined;
	for (const entry of preamble) {
		const text = entry.text.trimEnd();
		if (text === '') continue;
		const field = FIELD.exec(text);
		if (field?.[1] !== undefined && field[2] !== undefined) {
			if (!fields.has(field[1])) fields.set(field[1], fieldValue(field[2]));
			continue;
		}
		if (stream === undefined && !/^\s/.test(text)) stream = fieldValue(text);
	}
	const declared = Number.parseInt(fields.get('Request for Comments') ?? '', 10);
	return {
		kind: 'rfc',
		title: titleOf(paragraphs(preamble)),
		number: Number.isInteger(declared) ? declared : fallback,
		stream,
		date: dateOf(preamble),
		category: fields.get('Category'),
		issn: fields.get('ISSN'),
		updates: numberList(fields.get('Updates')),
		obsoletes: numberList(fields.get('Obsoletes')),
	};
}

export function parseRfc(source: string, fallbackNumber: number): ParsedDocument {
	const { lines, seams } = stripPageArtifacts(sourceLines(source));
	const headings = headingsOf(lines);
	return { meta: metaOf(lines, headings, fallbackNumber), lines, seams, headings };
}
