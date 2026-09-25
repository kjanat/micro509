import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ItuMeta, ItuVariant, ParsedDocument, SourceLine } from './types.ts';

const CLAUSE = /^(\d+(?:\.\d+)*|[A-Z](?:\.\d+)+)(?:\t|\s{2,})\s*([A-Za-z]\S*.*)$/;
const ANNEX = /^\s*Annex ([A-Z])(?:(?:\t|\s{2,})\s*(\S.*))?$/;
const ANNEX_BASE = 1000;
const TOC_ROW = /\t\s*\d+\s*$/;
const CHANGE_ITEM = /^(\d+)\)\s+(\S.*)$/;
const T_REC = /^T-REC-(X\.\d+)-(\d{4})(\d{2})-\w+!([^!]*)!/;

function partsOf(value: string): readonly number[] | undefined {
	const parts: number[] = [];
	for (const [position, part] of value.split('.').entries()) {
		if (position === 0 && /^[A-Z]$/.test(part)) {
			parts.push(ANNEX_BASE + part.charCodeAt(0));
			continue;
		}
		if (part !== String(Number.parseInt(part, 10))) return undefined;
		parts.push(Number.parseInt(part, 10));
	}
	return parts;
}

function follows(previous: readonly number[], candidate: readonly number[]): boolean {
	const last = candidate.length - 1;
	if (candidate.length === previous.length + 1) {
		return previous.every((part, index) => part === candidate[index]);
	}
	if (candidate.length > previous.length) return false;
	return (
		candidate.slice(0, last).every((part, index) => part === previous[index]) &&
		(candidate[last] ?? 0) > (previous[last] ?? 0)
	);
}

interface ClauseCandidate {
	readonly parts: readonly number[];
	readonly heading: Heading;
}

function longestChain(candidates: readonly ClauseCandidate[]): readonly Heading[] {
	const length: number[] = [];
	const back: (number | undefined)[] = [];
	let end: number | undefined;
	candidates.forEach((candidate, index) => {
		const starts = candidate.parts.length === 1;
		let best = starts ? 1 : 0;
		let from: number | undefined;
		for (let before = 0; before < index; before += 1) {
			const reached = length[before] ?? 0;
			const prior = candidates[before];
			if (reached === 0 || prior === undefined || reached + 1 <= best) continue;
			if (follows(prior.parts, candidate.parts)) {
				best = reached + 1;
				from = before;
			}
		}
		length.push(best);
		back.push(from);
		if (best > 0 && (end === undefined || best >= (length[end] ?? 0))) end = index;
	});
	const chain: Heading[] = [];
	for (let at = end; at !== undefined; at = back[at]) {
		const candidate = candidates[at];
		if (candidate !== undefined) chain.unshift(candidate.heading);
	}
	return chain;
}

const MARKED_HEADING = /^(#{1,6}) (\S.*)$/;
const MARK = /^(~~|__)(.*)\1$/;
const HEADING_NUMBER = /^(?:(\d+(?:\.\d+)*)|(\d+)\)|Annex ([A-Z]))\s+(.*)$/;

function markedHeadingsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const headings: Heading[] = [];
	lines.forEach((entry, index) => {
		const match = MARKED_HEADING.exec(entry.text.trimEnd());
		const level = match?.[1];
		const raw = match?.[2];
		if (level === undefined || raw === undefined) return;
		const marked = MARK.exec(raw);
		const mark = marked?.[1] ?? '';
		const text = marked?.[2] ?? raw;
		const numbered = HEADING_NUMBER.exec(text);
		const number = numbered?.[1] ?? numbered?.[2] ?? numbered?.[3];
		const rest = cleanTitle(numbered?.[4] ?? text);
		headings.push({
			number: number ?? rest,
			title: `${mark}${rest}${mark}`,
			depth: level.length,
			line: entry.line,
			index,
		});
	});
	return headings;
}

function changeItemsOf(lines: readonly SourceLine[]): readonly Heading[] {
	const headings: Heading[] = [];
	lines.forEach((entry, index) => {
		if (entry.text.includes('....')) return;
		const match = CHANGE_ITEM.exec(entry.text.trim());
		const number = match?.[1];
		const title = match?.[2];
		if (number === undefined || title === undefined) return;
		headings.push({ number, title: cleanTitle(title), depth: 1, line: entry.line, index });
	});
	return headings;
}

function headingsOf(lines: readonly SourceLine[], variant: ItuVariant): readonly Heading[] {
	if (lines.some((entry) => MARKED_HEADING.test(entry.text))) return markedHeadingsOf(lines);
	if (variant === 'corrigendum' || variant === 'amendment' || variant === 'erratum') {
		return changeItemsOf(lines);
	}
	const candidates: ClauseCandidate[] = [];
	lines.forEach((entry, index) => {
		const text = entry.text.trimEnd();
		if (text.includes('....') || TOC_ROW.test(text)) return;
		const annex = ANNEX.exec(text);
		const letter = annex?.[1];
		if (letter !== undefined) {
			candidates.push({
				parts: [ANNEX_BASE + letter.charCodeAt(0)],
				heading: {
					number: letter,
					title: cleanTitle(annex?.[2] ?? `Annex ${letter}`),
					depth: 1,
					line: entry.line,
					index,
				},
			});
			return;
		}
		const match = CLAUSE.exec(text);
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

function variantOf(token: string): { variant: ItuVariant; variantNumber: number | undefined } {
	if (token === '') return { variant: 'base', variantNumber: undefined };
	const match = /^(Cor|Amd|Err)(\d+)$/.exec(token);
	const count = match?.[2] === undefined ? undefined : Number.parseInt(match[2], 10);
	if (match?.[1] === 'Cor') return { variant: 'corrigendum', variantNumber: count };
	if (match?.[1] === 'Amd') return { variant: 'amendment', variantNumber: count };
	if (match?.[1] === 'Err') return { variant: 'erratum', variantNumber: count };
	return { variant: 'other', variantNumber: undefined };
}

function labelOf(variant: ItuVariant, variantNumber: number | undefined): string {
	const suffix = variantNumber === undefined ? '' : ` ${variantNumber}`;
	if (variant === 'corrigendum') return ` Corrigendum${suffix}`;
	if (variant === 'amendment') return ` Amendment${suffix}`;
	if (variant === 'erratum') return ` Erratum${suffix}`;
	return '';
}

export function ituMeta(stem: string, directory: string): ItuMeta {
	const match = T_REC.exec(stem);
	if (match?.[1] === undefined) {
		return {
			kind: 'itu',
			title: `ITU-T ${directory} (${stem})`,
			recommendation: directory,
			edition: undefined,
			variant: 'other',
			variantNumber: undefined,
		};
	}
	const edition = `${match[3]}/${match[2]}`;
	const { variant, variantNumber } = variantOf(match[4] ?? '');
	return {
		kind: 'itu',
		title: `Recommendation ITU-T ${match[1]} (${edition})${labelOf(variant, variantNumber)}`,
		recommendation: match[1],
		edition,
		variant,
		variantNumber,
	};
}

export function ituIdentifier(stem: string, directory: string): string {
	const slug = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]+/g, '');
	const match = T_REC.exec(stem);
	if (match?.[1] === undefined) return `itu-${slug(directory)}-${slug(stem)}`;
	const suffix = match[4] === undefined || match[4] === '' ? '' : `-${slug(match[4])}`;
	return `itu-${slug(match[1])}-${match[2]}${suffix}`;
}

export function parseItu(source: string, stem: string, directory: string): ParsedDocument {
	const { lines, seams } = stripPageArtifacts(sourceLines(source));
	const meta = ituMeta(stem, directory);
	return { meta, lines, seams, headings: headingsOf(lines, meta.variant) };
}
