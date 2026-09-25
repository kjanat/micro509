import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ParsedDocument, SourceLine, W3cMeta } from './types.ts';

const TOC_ENTRY = /^\s*(?:[•□☆*+-]|\d+\.)\s+((?:\d+|[A-Z])(?:\.\d+)*)\.?(?:\s+(.*))?$/;
const BODY_HEADING = /^((?:\d+|[A-Z])(?:\.\d+)*)\.?(?:\s+(.*))?$/;
const STATUS =
	/^(?:W3C\s+(.*?)|(Living Standard)\s+—\s+Last Updated)\s+(\d{1,2}\s+[A-Z][a-z]+\s+\d{4})\s*$/;
const PUBLISHERS: ReadonlySet<string> = new Set(['', 'W3C', 'WHATWG']);

function tocTitles(lines: readonly SourceLine[]): ReadonlyMap<string, string> {
	const titles = new Map<string, string>();
	let started = false;
	for (const entry of lines) {
		const text = entry.text.trimEnd();
		if (!started) {
			if (text.trim() === 'Table of Contents') started = true;
			continue;
		}
		const match = TOC_ENTRY.exec(text);
		if (match?.[1] === undefined) {
			if (titles.size > 0 && /^\S/.test(text)) break;
			continue;
		}
		if (!titles.has(match[1])) titles.set(match[1], cleanTitle(match[2] ?? ''));
	}
	return titles;
}

function headingsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const titles = tocTitles(lines);
	const headings: Heading[] = [];
	const seen = new Set<string>();
	lines.forEach((entry, index) => {
		const text = entry.text.trimEnd();
		const match = BODY_HEADING.exec(text);
		const number = match?.[1];
		if (number === undefined || seen.has(number)) return;
		const expected = titles.get(number);
		if (expected === undefined) return;
		const title = cleanTitle(match?.[2] ?? '');
		if (title !== expected) return;
		seen.add(number);
		headings.push({
			number,
			title,
			depth: number.split('.').length,
			line: entry.line,
			index,
		});
	});
	return headings;
}

function metaOf(lines: readonly SourceLine[]): W3cMeta {
	const head = lines.slice(0, 40);
	let title = '';
	let status: string | undefined;
	let date: string | undefined;
	for (const entry of head) {
		const text = cleanTitle(entry.text);
		if (PUBLISHERS.has(text)) continue;
		const match = STATUS.exec(text);
		if (match !== null) {
			status ??= match[1] ?? match[2];
			date ??= match[3];
			continue;
		}
		if (title === '') title = text;
	}
	return { kind: 'w3c', title, status, date };
}

export function w3cIdentifier(stem: string): string {
	const tokens = stem
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter((token) => token !== '' && token !== 'w3c')
		.map((token) => (token === 'webcryptoapi' ? 'webcrypto' : token))
		.map((token) => (/^\d{8}$/.test(token) ? token.slice(0, 4) : token));
	const specIndex = tokens.findIndex((token) => token.startsWith('webcrypto'));
	if (specIndex === -1) return ['w3c', ...tokens].join('-');
	const spec = tokens[specIndex] ?? 'webcrypto';
	const rest = tokens.filter((_, index) => index !== specIndex);
	return ['w3c', spec, ...rest].join('-');
}

export function parseW3c(source: string): ParsedDocument {
	const { lines, seams } = stripPageArtifacts(sourceLines(source));
	return { meta: metaOf(lines), lines, seams, headings: headingsOf(lines) };
}

const LICENSE_LINK = /<a\b[^>]*\bhref="([^"]+)"[^>]*>/g;

const LEGAL_PAGE =
	/\/Consortium\/Legal\/(?:\d{4}\/)?copyright-(?:documents|software-and-document)|\/copyright\/(?:document|software)-license/;

export function licenseLinks(html: string, base: string): readonly string[] {
	const links = new Set<string>();
	for (const match of html.matchAll(LICENSE_LINK)) {
		const [tag, href] = match;
		if (href === undefined) continue;
		if (/\brel="license"/.test(tag) || LEGAL_PAGE.test(href)) links.add(new URL(href, base).href);
	}
	return [...links];
}

export function provenance(source: string, licenses: readonly string[]): string {
	const retrieved = new Date().toISOString().slice(0, 10);
	return [
		'',
		`Source: ${source}`,
		`Retrieved: ${retrieved}`,
		...licenses.map((license) => `License: ${license}`),
		'',
	].join('\n');
}
