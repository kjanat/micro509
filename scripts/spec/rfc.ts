import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ParsedDocument, RfcMeta, SourceLine } from './types.ts';

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
		'Author Address',
		"Author's Address",
		"Author's Addresses",
		"Authors' Address",
		"Authors' Addresses",
		'Contributors',
		'Copyright and License Notice',
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
		'Notes',
		'Overview',
		'Patent Statement',
		'Informative References',
		'References',
		'Revision History',
		'Security Considerations',
		'Status of This Memo',
		'Summary',
		'Table of Contents',
	].map((title) => title.toUpperCase()),
);

function frontMatterTitle(text: string): string | undefined {
	const bare = text.replace(/:$/, '');
	return UNNUMBERED.has(bare.toUpperCase()) ? bare : undefined;
}

const OUTLINE = /^(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)(\.?)\s+(\S.*)$/;
const APPENDIX = /^Appendix\s+([A-Z](?:\.\d+)*)\.?(?:\s*[:-]+\s*|\s+)(\S.*)$/;
const LEADERS = /\.{2,}\s*\d*\s*$|(?:\s\.){3,}/;
const CHAPTER = /^Chapter\s+(\d+)(?:\s*-+\s*|\s+)(\S.*)$/;
const TITLE_START = /^[^\d\s]/;
const TOC_ENTRY =
	/^\s*(?:Appendix\s+)?(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)\.?\s+(\S.*?)\s*(?:\.{2,}|(?:\s\.){2,})\s*\.?\s*\d+\s*$/;
const TITLE_LINE = /^[A-Z][^.;:]*[^\s.,;:]$/;
const LETTER_BASE = 1000;

interface Candidate {
	readonly number: string;
	readonly title: string;
	readonly indent: number;
	readonly column: number;
	readonly strong: boolean;
	readonly outline: readonly number[];
}

function outlineOf(number: string): readonly number[] {
	return number.split('.').map((part) => {
		const code = part.charCodeAt(0);
		return code >= 65 && code <= 90 ? LETTER_BASE + code - 64 : Number.parseInt(part, 10);
	});
}

function samePrefix(left: readonly number[], right: readonly number[], length: number): boolean {
	for (let index = 0; index < length; index += 1) {
		if (left[index] !== right[index]) return false;
	}
	return true;
}

function isSuccessor(previous: readonly number[] | undefined, next: readonly number[]): boolean {
	const first = next[0] ?? 0;
	if (previous === undefined)
		return next.length === 1 && (first === 1 || first === LETTER_BASE + 1);
	if (next.length === 1 && first === LETTER_BASE + 1) return (previous[0] ?? 0) < LETTER_BASE;
	if (next.length === previous.length + 1) {
		return samePrefix(previous, next, previous.length) && next[previous.length] === 1;
	}
	if (next.length > previous.length) return false;
	const last = next.length - 1;
	return samePrefix(previous, next, last) && next[last] === (previous[last] ?? 0) + 1;
}

function candidateOf(text: string): Candidate | undefined {
	const body = text.trim();
	if (body === '' || LEADERS.test(body)) return undefined;
	const indent = text.length - text.trimStart().length;
	const chapter = CHAPTER.exec(body);
	if (chapter?.[1] !== undefined && chapter[2] !== undefined && indent === 0) {
		return {
			number: chapter[1],
			title: cleanTitle(chapter[2]),
			indent,
			column: body.length - chapter[2].length,
			strong: true,
			outline: outlineOf(chapter[1]),
		};
	}
	const appendix = APPENDIX.exec(body);
	if (appendix?.[1] !== undefined && appendix[2] !== undefined) {
		return {
			number: appendix[1],
			title: cleanTitle(appendix[2]),
			indent,
			column: indent + body.length - appendix[2].length,
			strong: indent === 0,
			outline: outlineOf(appendix[1]),
		};
	}
	const outline = OUTLINE.exec(body);
	if (outline?.[1] === undefined || outline[3] === undefined) return undefined;
	const number = outline[1];
	const dotted = outline[2] === '.';
	if (!dotted && !number.includes('.') && /^[A-Z]$/.test(number)) return undefined;
	const strong = indent === 0 && dotted && !/^[A-Z]$/.test(number);
	if (!strong && (!TITLE_START.test(outline[3]) || outlineOf(number).includes(0))) {
		return undefined;
	}
	return {
		number,
		title: cleanTitle(outline[3]),
		indent,
		column: indent + body.length - outline[3].length,
		strong,
		outline: outlineOf(number),
	};
}

function tocTitles(lines: readonly SourceLine[]): ReadonlyMap<string, string> {
	const titles = new Map<string, string>();
	for (const entry of lines) {
		const match = TOC_ENTRY.exec(entry.text);
		if (match?.[1] === undefined || match[2] === undefined || titles.has(match[1])) continue;
		titles.set(match[1], cleanTitle(match[2]));
	}
	return titles;
}

function titleFor(
	lines: readonly SourceLine[],
	index: number,
	candidate: Candidate,
	toc: ReadonlyMap<string, string>,
): string {
	const listed = toc.get(candidate.number);
	if (listed !== undefined && candidate.title.startsWith(`${listed} `)) {
		if (candidate.title.length - listed.length > 20) return listed;
	}
	return continuation(lines, index, candidate);
}

function continuation(lines: readonly SourceLine[], index: number, candidate: Candidate): string {
	const heading = lines[index]?.text ?? '';
	const next = lines[index + 1]?.text ?? '';
	if (heading.trimEnd().length < 60 || next.trim() === '') return candidate.title;
	if (/\S {3,}\S/.test(heading.slice(candidate.column)) || /[.,;:]$/.test(next.trimEnd()))
		return candidate.title;
	if (next.length - next.trimStart().length !== candidate.column) return candidate.title;
	return cleanTitle(`${candidate.title} ${next}`);
}

function acceptsStrong(candidate: Candidate, seen: ReadonlySet<string>, top: number): boolean {
	const [first = 0, ...rest] = candidate.outline;
	if (first > LETTER_BASE && rest.length > 0) {
		return seen.has(candidate.number.split('.').slice(0, -1).join('.'));
	}
	return first > LETTER_BASE || rest.length > 0 || first > top;
}

interface Outline {
	readonly flushDepths: ReadonlySet<number>;
	readonly localAppendixNumbering: boolean;
	readonly seen: Set<string>;
	previous: readonly number[] | undefined;
	top: number;
	appendix: boolean;
	appendixNumbered: boolean;
}

function isLetter(outline: readonly number[]): boolean {
	return (outline[0] ?? 0) > LETTER_BASE;
}

function hasLocalAppendixNumbering(candidates: readonly (Candidate | undefined)[]): boolean {
	let appendix = false;
	for (const candidate of candidates) {
		if (candidate === undefined || !candidate.strong || candidate.outline.length !== 1) continue;
		if (isLetter(candidate.outline)) appendix = true;
		else if (appendix && candidate.outline[0] === 1) return true;
	}
	return false;
}

function isBlank(lines: readonly SourceLine[], index: number): boolean {
	return (lines[index]?.text ?? '').trim() === '';
}

function startsPage(
	lines: readonly SourceLine[],
	seams: ReadonlySet<number>,
	index: number,
): boolean {
	for (let cursor = index - 1; cursor >= 0 && isBlank(lines, cursor); cursor -= 1) {
		if (seams.has(lines[cursor]?.line ?? 0)) return true;
	}
	return index === 0;
}

function runningHeads(
	lines: readonly SourceLine[],
	seams: ReadonlySet<number>,
): ReadonlySet<string> {
	const counts = new Map<string, number>();
	lines.forEach((entry, index) => {
		if (!startsPage(lines, seams, index) || isBlank(lines, index)) return;
		const key = entry.text.trim();
		counts.set(key, (counts.get(key) ?? 0) + 1);
	});
	return new Set([...counts].filter(([, total]) => total >= 3).map(([text]) => text));
}

function titleLineHeading(
	lines: readonly SourceLine[],
	seams: ReadonlySet<number>,
	heads: ReadonlySet<string>,
	index: number,
): Heading | undefined {
	const entry = lines[index];
	if (entry === undefined || entry.text.length > 72 || !TITLE_LINE.test(entry.text)) {
		return undefined;
	}
	if (/\S {3,}\S/.test(entry.text) || FIELD.test(entry.text)) return undefined;
	if (!isBlank(lines, index - 1) || !isBlank(lines, index + 1)) return undefined;
	if (heads.has(entry.text.trim()) && startsPage(lines, seams, index)) return undefined;
	const title = cleanTitle(entry.text);
	return { number: title, title, depth: 1, line: entry.line, index };
}

function frontMatterHeading(entry: SourceLine, index: number): Heading | undefined {
	const front = /^\S/.test(entry.text) ? frontMatterTitle(cleanTitle(entry.text)) : undefined;
	return front === undefined
		? undefined
		: { number: front, title: front, depth: 1, line: entry.line, index };
}

function accepts(outline: Outline, candidate: Candidate): boolean {
	if (candidate.strong) return acceptsStrong(candidate, outline.seen, outline.top);
	const local =
		outline.localAppendixNumbering &&
		outline.appendix &&
		!outline.appendixNumbered &&
		!isLetter(candidate.outline);
	const placed =
		local || candidate.indent === 0 || !outline.flushDepths.has(candidate.outline.length);
	const previous =
		local && outline.previous !== undefined && isLetter(outline.previous)
			? undefined
			: outline.previous;
	return placed && isSuccessor(previous, candidate.outline);
}

function withinAppendix(outline: Outline, candidate: Candidate): boolean {
	return outline.localAppendixNumbering && outline.appendix && !isLetter(candidate.outline);
}

function record(outline: Outline, candidate: Candidate): void {
	const [first = 0, ...rest] = candidate.outline;
	if (rest.length === 0 && first > LETTER_BASE) {
		outline.appendix = true;
		outline.appendixNumbered = false;
	} else if (candidate.strong && outline.appendix) {
		outline.appendixNumbered = true;
	}
	if (rest.length === 0) outline.top = first > LETTER_BASE ? 0 : first;
	outline.seen.add(candidate.number);
	outline.previous = candidate.outline;
}

function headingsOf(lines: readonly SourceLine[], seams: ReadonlySet<number>): readonly Heading[] {
	const candidates = lines.map((entry) => candidateOf(entry.text));
	const flushDepths = new Set<number>();
	for (const candidate of candidates) {
		if (candidate?.indent === 0) flushDepths.add(candidate.outline.length);
	}
	const heads = flushDepths.size === 0 ? runningHeads(lines, seams) : undefined;
	const toc = tocTitles(lines);
	const outline: Outline = {
		flushDepths,
		localAppendixNumbering: hasLocalAppendixNumbering(candidates),
		seen: new Set(),
		previous: undefined,
		top: 0,
		appendix: false,
		appendixNumbered: false,
	};
	let titled = false;
	const headings: Heading[] = [];
	candidates.forEach((candidate, index) => {
		const entry = lines[index];
		if (entry === undefined) return;
		if (candidate === undefined) {
			const front = frontMatterHeading(entry, index);
			const titleLine =
				front !== undefined || heads === undefined
					? undefined
					: titleLineHeading(lines, seams, heads, index);
			const unnumbered = front ?? titleLine;
			if (unnumbered === undefined) return;
			headings.push(unnumbered);
			outline.appendix = false;
			titled = titleLine !== undefined;
			return;
		}
		if (!accepts(outline, candidate)) return;
		record(outline, candidate);
		headings.push({
			number: candidate.number,
			title: titleFor(lines, index, candidate, toc),
			depth: candidate.outline.length + (titled || withinAppendix(outline, candidate) ? 1 : 0),
			line: entry.line,
			index,
		});
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
	const headings = headingsOf(lines, seams);
	return { meta: metaOf(lines, headings, fallbackNumber), lines, seams, headings };
}
