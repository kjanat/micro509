import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ParsedDocument, PkitsMeta, SourceLine } from './types.ts';

const CLAUSE = /^\s{0,10}(\d+(?:\.\d+)*)\s+([A-Z]\S*.*)$/;
const VERSION = /^\s*Version\s+(\S+)/;
const DATE = /^\s*([A-Z][a-z]+\s+\d{1,2},\s+\d{4})/;

function wellFormed(value: string): boolean {
	return value.split('.').every((part) => part === String(Number.parseInt(part, 10)));
}

function parentOf(value: string): string | undefined {
	const parts = value.split('.');
	return parts.length === 1 ? undefined : parts.slice(0, -1).join('.');
}

function headingsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const headings: Heading[] = [];
	const seen = new Set<string>();
	lines.forEach((entry, index) => {
		const text = entry.text.trimEnd();
		if (text.includes('....')) return;
		const match = CLAUSE.exec(text);
		const number = match?.[1];
		const title = match?.[2];
		if (number === undefined || title === undefined) return;
		if (!wellFormed(number)) return;
		const parent = parentOf(number);
		if (parent !== undefined && !seen.has(parent)) return;
		seen.add(number);
		headings.push({
			number,
			title: cleanTitle(title),
			depth: number.split('.').length,
			line: entry.line,
			index,
		});
	});
	return headings;
}

function metaOf(lines: readonly SourceLine[], headings: readonly Heading[]): PkitsMeta {
	const end = headings[0]?.index ?? Math.min(lines.length, 40);
	const preamble = lines.slice(0, end);
	const titleParts: string[] = [];
	for (const entry of preamble) {
		if (entry.text.trim() === '') {
			if (titleParts.length > 0) break;
			continue;
		}
		titleParts.push(entry.text);
	}
	let version: string | undefined;
	let date: string | undefined;
	for (const entry of preamble) {
		const cleaned = cleanTitle(entry.text);
		version ??= VERSION.exec(cleaned)?.[1];
		date ??= DATE.exec(cleaned)?.[1];
	}
	return {
		kind: 'pkits',
		title: cleanTitle(titleParts.join(' ')),
		version,
		date,
	};
}

export function parsePkits(source: string): ParsedDocument {
	const { lines, seams } = stripPageArtifacts(sourceLines(source));
	const headings = headingsOf(lines);
	return { meta: metaOf(lines, headings), lines, seams, headings };
}
