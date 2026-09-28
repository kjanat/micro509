import type { ClauseCandidate } from './itu.ts';
import { longestChain, partsOf } from './itu.ts';
import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, MsMeta, ParsedDocument, SourceLine } from './types.ts';

const COVER = /^\[(MS-[A-Z0-9]+)\]:\s*$/;
const RUNNING_ID = /^\s*\[(MS-[A-Z0-9]+)\] - v(\d{8})\s*$/;
const PAGE_NUMBER = /^\s*\d+ \/ \d+\s*$/;
const COPYRIGHT = /^\s*Copyright © \d{4} Microsoft Corporation\s*$/;
const RELEASE = /^\s*Release: ([A-Z][a-z]+ \d{1,2}, \d{4})\s*$/;
const SECTION = /^(\d+(?:\.\d+)*) +(\S.*)$/;
const STEM = /^(MS-[A-Z0-9]+)-v(\d{8})$/;

interface Cover {
	readonly document: string;
	readonly subject: string;
}

function coverOf(lines: readonly SourceLine[]): Cover {
	const index = lines.findIndex((entry) => COVER.test(entry.text));
	return {
		document: COVER.exec(lines[index]?.text ?? '')?.[1] ?? '',
		subject: cleanTitle(lines[index + 1]?.text ?? ''),
	};
}

function metaOf(lines: readonly SourceLine[], { document, subject }: Cover): MsMeta {
	const running = lines.map((entry) => RUNNING_ID.exec(entry.text)).find((match) => match !== null);
	const release = lines.map((entry) => RELEASE.exec(entry.text)).find((match) => match !== null);
	return {
		kind: 'ms',
		title: `[${document}]: ${subject}`,
		document,
		version: running?.[2] === undefined ? undefined : `v${running[2]}`,
		date: release?.[1],
	};
}

function nextContent(lines: readonly SourceLine[], index: number): string | undefined {
	for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
		const text = lines[cursor]?.text ?? '';
		if (text.trim() !== '') return text;
	}
	return undefined;
}

function withoutRunningFooters(
	lines: readonly SourceLine[],
	subject: string,
): readonly SourceLine[] {
	return lines.filter((entry, index) => {
		const text = entry.text;
		if (RUNNING_ID.test(text) || COPYRIGHT.test(text) || RELEASE.test(text)) return false;
		if (PAGE_NUMBER.test(text)) return !RUNNING_ID.test(nextContent(lines, index) ?? '');
		return !(cleanTitle(text) === subject && RUNNING_ID.test(lines[index - 1]?.text ?? ''));
	});
}

function headingsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const candidates: ClauseCandidate[] = [];
	lines.forEach((entry, index) => {
		const text = entry.text.trimEnd();
		if (text.includes('....')) return;
		const match = SECTION.exec(text);
		const number = match?.[1];
		const title = match?.[2];
		if (number === undefined || title === undefined) return;
		const parts = partsOf(number);
		if (parts === undefined) return;
		candidates.push({
			parts,
			heading: { number, title: cleanTitle(title), depth: parts.length, line: entry.line, index },
		});
	});
	return longestChain(candidates);
}

export function msIdentifier(stem: string, directory: string): string {
	const slug = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]+/g, '-');
	const match = STEM.exec(stem);
	if (match?.[1] === undefined || match[2] === undefined)
		return `ms-${slug(directory)}-${slug(stem)}`;
	return `${slug(match[1])}-${match[2]}`;
}

export function parseMs(source: string): ParsedDocument {
	const all = sourceLines(source);
	const cover = coverOf(all);
	const { lines, seams } = stripPageArtifacts(withoutRunningFooters(all, cover.subject));
	return { meta: metaOf(all, cover), lines, seams, headings: headingsOf(lines) };
}
