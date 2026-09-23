import { cleanTitle, sourceLines, stripPageArtifacts } from './text.ts';
import type { Heading, ItuMeta, ItuVariant, ParsedDocument, SourceLine } from './types.ts';

const CLAUSE = /^(\d+(?:\.\d+)*)\s{2,}([A-Za-z]\S*.*)$/;
const T_REC = /^T-REC-(X\.\d+)-(\d{4})(\d{2})-\w+!([^!]*)!/;

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
	return { meta: ituMeta(stem, directory), lines, seams, headings: headingsOf(lines) };
}
