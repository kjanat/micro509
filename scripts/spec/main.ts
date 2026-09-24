import type { Out } from 'dreamcli';
import { arg, CLIError, cli, command, flag, isMainModule } from 'dreamcli';
import {
	discover,
	enclosingHeading,
	findHeading,
	loadDocument,
	resolveReference,
	rfcRelations,
	sectionLines,
} from './corpus.ts';
import { blocksOf, minimumIndent, renderBody } from './text.ts';
import type { DocKind, SourceLine, SpecDocument } from './types.ts';
import { unreachable } from './types.ts';

type ListedDocument =
	| {
			readonly id: string;
			readonly kind: 'rfc';
			readonly title: string;
			readonly path: string;
			readonly number: number;
			readonly stream: string | undefined;
			readonly date: string | undefined;
			readonly category: string | undefined;
			readonly issn: string | undefined;
			readonly updates: readonly number[];
			readonly obsoletes: readonly number[];
			readonly updatedBy: readonly number[];
			readonly obsoletedBy: readonly number[];
	  }
	| {
			readonly id: string;
			readonly kind: 'pkits';
			readonly title: string;
			readonly path: string;
			readonly version: string | undefined;
			readonly date: string | undefined;
	  }
	| {
			readonly id: string;
			readonly kind: 'itu';
			readonly title: string;
			readonly path: string;
			readonly recommendation: string;
			readonly edition: string | undefined;
			readonly variant: string;
			readonly variantNumber: number | undefined;
	  }
	| {
			readonly id: string;
			readonly kind: 'w3c';
			readonly title: string;
			readonly path: string;
			readonly status: string | undefined;
			readonly date: string | undefined;
	  };

type ListRow = {
	readonly id: string;
	readonly kind: DocKind;
	readonly date: string;
	readonly title: string;
	readonly notes: string;
};

type ContextLine = {
	readonly line: number;
	readonly text: string;
};

type SearchHit = {
	readonly doc: string;
	readonly path: string;
	readonly section: { readonly number: string; readonly title: string } | null;
	readonly line: number;
	readonly text: string;
	readonly before: readonly ContextLine[];
	readonly after: readonly ContextLine[];
};

function allDocuments(): readonly SpecDocument[] {
	return discover().map(loadDocument);
}

function sectionLabel(number: string, title: string): string {
	return number === title ? title : `§${number}  ${title}`;
}

function describe(
	document: SpecDocument,
	relations: ReturnType<typeof rfcRelations>,
): ListedDocument {
	const meta = document.meta;
	const common = { id: document.id, title: meta.title, path: document.relativePath };
	switch (meta.kind) {
		case 'rfc': {
			const related = relations.get(meta.number);
			return {
				...common,
				kind: 'rfc',
				number: meta.number,
				stream: meta.stream,
				date: meta.date,
				category: meta.category,
				issn: meta.issn,
				updates: meta.updates,
				obsoletes: meta.obsoletes,
				updatedBy: related?.updatedBy ?? [],
				obsoletedBy: related?.obsoletedBy ?? [],
			};
		}
		case 'pkits':
			return { ...common, kind: 'pkits', version: meta.version, date: meta.date };
		case 'itu':
			return {
				...common,
				kind: 'itu',
				recommendation: meta.recommendation,
				edition: meta.edition,
				variant: meta.variant,
				variantNumber: meta.variantNumber,
			};
		case 'w3c':
			return { ...common, kind: 'w3c', status: meta.status, date: meta.date };
		default:
			return unreachable(meta);
	}
}

function noteOf(entry: ListedDocument): string {
	const notes: string[] = [];
	switch (entry.kind) {
		case 'rfc': {
			if (entry.category !== undefined) notes.push(entry.category);
			if (entry.obsoletes.length > 0) notes.push(`obsoletes ${entry.obsoletes.join(', ')}`);
			if (entry.updates.length > 0) notes.push(`updates ${entry.updates.join(', ')}`);
			if (entry.obsoletedBy.length > 0) notes.push(`obsoleted by ${entry.obsoletedBy.join(', ')}`);
			if (entry.updatedBy.length > 0) notes.push(`updated by ${entry.updatedBy.join(', ')}`);
			break;
		}
		case 'pkits':
			if (entry.version !== undefined) notes.push(`version ${entry.version}`);
			break;
		case 'itu':
			if (entry.edition !== undefined) notes.push(`edition ${entry.edition}`);
			notes.push(entry.variant);
			break;
		case 'w3c':
			if (entry.status !== undefined) notes.push(entry.status);
			break;
		default:
			return unreachable(entry);
	}
	return notes.join('; ');
}

function dateOf(entry: ListedDocument): string {
	switch (entry.kind) {
		case 'rfc':
		case 'pkits':
		case 'w3c':
			return entry.date ?? '';
		case 'itu':
			return entry.edition ?? '';
		default:
			return unreachable(entry);
	}
}

export const listCommand = command('list')
	.description('List every vendored standards document with a stable id and its metadata')
	.example('spec list', 'Show the whole corpus')
	.example('spec list --json', 'Emit the corpus as machine-readable JSON')
	.action(({ out }) => {
		const documents = allDocuments();
		const relations = rfcRelations(documents);
		const entries = documents.map((document) => describe(document, relations));
		if (out.jsonMode) {
			out.json({ documents: entries });
			return;
		}
		const rows: readonly ListRow[] = entries.map((entry) => ({
			id: entry.id,
			kind: entry.kind,
			date: dateOf(entry),
			title: entry.title,
			notes: noteOf(entry),
		}));
		out.table(rows, [
			{ key: 'id', header: 'Id' },
			{ key: 'kind', header: 'Kind' },
			{ key: 'date', header: 'Date' },
			{ key: 'title', header: 'Title' },
			{ key: 'notes', header: 'Notes' },
		]);
	});

export const headingsCommand = command('headings')
	.description('Print the section outline of one document')
	.example('spec headings rfc5280 --depth 3', 'Outline RFC 5280 three levels deep')
	.arg('doc', arg.string().describe('Document id from `spec list`, or a bare RFC number'))
	.flag(
		'depth',
		flag.number({ int: true, min: 1 }).default(2).describe('Deepest heading level to print'),
	)
	.action(({ args, flags, out }) => {
		const document = loadDocument(resolveReference(discover(), args.doc));
		const headings = document.headings.filter((heading) => heading.depth <= flags.depth);
		if (out.jsonMode) {
			out.json({
				doc: document.id,
				path: document.relativePath,
				depth: flags.depth,
				headings: headings.map((heading) => ({
					number: heading.number,
					title: heading.title,
					depth: heading.depth,
					line: heading.line,
				})),
			});
			return;
		}
		out.log(`${document.id}  ${document.meta.title}`);
		out.log('');
		for (const heading of headings) {
			const indent = '  '.repeat(heading.depth - 1);
			const label =
				heading.number === heading.title ? heading.title : `${heading.number}  ${heading.title}`;
			out.log(`${String(heading.line).padStart(6)}  ${indent}${label}`);
		}
	});

export const readCommand = command('read')
	.description('Print one whole section body, free of page headers and footers')
	.example('spec read rfc5280 5.1.2.5', 'Read the nextUpdate section of RFC 5280')
	.example('spec read 9608 4', 'Read section 4 of RFC 9608 by bare number')
	.arg('doc', arg.string().describe('Document id from `spec list`, or a bare RFC number'))
	.arg('section', arg.string().describe('Section number such as 5.1.2.5, or heading text'))
	.flag('raw', flag.boolean().describe('Keep the original line breaks and indentation'))
	.action(({ args, flags, out }) => {
		const document = loadDocument(resolveReference(discover(), args.doc));
		const heading = findHeading(document, args.section);
		const body = sectionLines(document, heading);
		const rendered = flags.raw
			? body.map((entry) => entry.text)
			: renderBody(blocksOf(body, document.seams), minimumIndent(body));
		if (out.jsonMode) {
			out.json({
				doc: document.id,
				path: document.relativePath,
				section: {
					number: heading.number,
					title: heading.title,
					depth: heading.depth,
					line: heading.line,
				},
				raw: flags.raw,
				body: rendered.join('\n'),
			});
			return;
		}
		out.log(`${document.id} ${sectionLabel(heading.number, heading.title)}`);
		out.log(`${document.relativePath}:${heading.line}`);
		out.log('');
		for (const line of rendered) out.log(line);
	});

function contextAround(
	lines: readonly SourceLine[],
	index: number,
	span: number,
	direction: -1 | 1,
): readonly ContextLine[] {
	const collected: ContextLine[] = [];
	for (let step = 1; step <= span; step += 1) {
		const entry = lines[index + step * direction];
		if (entry === undefined) break;
		collected.push({ line: entry.line, text: entry.text });
	}
	return direction === -1 ? collected.reverse() : collected;
}

function compile(pattern: string, ignoreCase: boolean): RegExp {
	if (pattern.trim() === '') {
		throw new CLIError('search needs a pattern', {
			code: 'SPEC_PATTERN_INVALID',
			suggest: 'pass one or more terms, for example `bun spec search nextUpdate`',
		});
	}
	try {
		return new RegExp(pattern, ignoreCase ? 'i' : '');
	} catch (cause) {
		throw new CLIError(`invalid search pattern: ${pattern}`, {
			code: 'SPEC_PATTERN_INVALID',
			suggest: 'escape regular-expression metacharacters, or quote the pattern',
			cause,
		});
	}
}

type DocumentSearch = {
	readonly hits: readonly SearchHit[];
	readonly more: boolean;
};

function searchDocument(
	document: SpecDocument,
	pattern: RegExp,
	span: number,
	remaining: number,
): DocumentSearch {
	const hits: SearchHit[] = [];
	for (let index = 0; index < document.lines.length; index += 1) {
		const entry = document.lines[index];
		if (entry === undefined || !pattern.test(entry.text)) continue;
		if (hits.length >= remaining) return { hits, more: true };
		const section = enclosingHeading(document, index);
		hits.push({
			doc: document.id,
			path: document.relativePath,
			section: section === undefined ? null : { number: section.number, title: section.title },
			line: entry.line,
			text: entry.text,
			before: contextAround(document.lines, index, span, -1),
			after: contextAround(document.lines, index, span, 1),
		});
	}
	return { hits, more: false };
}

type RenderLine = {
	readonly line: number;
	readonly text: string;
	readonly match: boolean;
	readonly label: string;
};

function record(
	lines: Map<number, RenderLine>,
	entry: ContextLine,
	match: boolean,
	label: string,
): void {
	const existing = lines.get(entry.line);
	if (existing !== undefined && (existing.match || !match)) return;
	lines.set(entry.line, { line: entry.line, text: entry.text, match, label });
}

function runsOf(lines: readonly RenderLine[]): readonly (readonly RenderLine[])[] {
	const runs: RenderLine[][] = [];
	let current: RenderLine[] = [];
	let label: string | undefined;
	for (const entry of lines) {
		const previous = current[current.length - 1];
		const gap = previous !== undefined && entry.line - previous.line > 1;
		const relabel = entry.match && label !== undefined && entry.label !== label;
		if (gap || relabel) {
			runs.push(current);
			current = [];
			label = undefined;
		}
		if (entry.match) label = entry.label;
		current.push(entry);
	}
	if (current.length > 0) runs.push(current);
	return runs;
}

type DocumentHits = {
	readonly doc: string;
	readonly lines: readonly RenderLine[];
};

function hitLabel(hit: SearchHit): string {
	return hit.section === null
		? hit.doc
		: `${hit.doc} ${sectionLabel(hit.section.number, hit.section.title)}`;
}

function mergeHits(hits: readonly SearchHit[]): readonly DocumentHits[] {
	const order: string[] = [];
	const byDocument = new Map<string, Map<number, RenderLine>>();
	for (const hit of hits) {
		const existing = byDocument.get(hit.doc);
		const lines = existing ?? new Map<number, RenderLine>();
		if (existing === undefined) {
			byDocument.set(hit.doc, lines);
			order.push(hit.doc);
		}
		const label = hitLabel(hit);
		for (const line of hit.before) record(lines, line, false, label);
		record(lines, { line: hit.line, text: hit.text }, true, label);
		for (const line of hit.after) record(lines, line, false, label);
	}
	return order.map((doc) => ({
		doc,
		lines: [...(byDocument.get(doc) ?? new Map<number, RenderLine>()).values()].sort(
			(left, right) => left.line - right.line,
		),
	}));
}

function renderHits(out: Out, hits: readonly SearchHit[]): void {
	let group = '';
	for (const document of mergeHits(hits)) {
		for (const run of runsOf(document.lines)) {
			const label = run.find((entry) => entry.match)?.label ?? document.doc;
			if (label === group) {
				out.log('  --');
			} else {
				if (group !== '') out.log('');
				out.log(label);
				group = label;
			}
			for (const entry of run) {
				out.log(`${String(entry.line).padStart(6)}${entry.match ? ':' : '-'} ${entry.text}`);
			}
		}
	}
}

export const searchCommand = command('search')
	.description('Search the corpus and report the enclosing section of every match')
	.example('spec search nextUpdate --context 2', 'Census a term across every document')
	.example('spec search "MUST NOT" --doc rfc6960', 'Search one document')
	.arg('terms', arg.string().variadic().describe('Pattern, matched as a regular expression'))
	.flag('doc', flag.string().describe('Restrict the search to one document id'))
	.flag(
		'context',
		flag
			.number({ int: true, min: 0 })
			.default(0)
			.alias('C')
			.describe('Lines of context to show around each match'),
	)
	.flag('ignore-case', flag.boolean().alias('i').describe('Match without regard to case'))
	.flag(
		'limit',
		flag.number({ int: true, min: 1 }).default(200).describe('Maximum matches to report'),
	)
	.action(({ args, flags, out }) => {
		const source = args.terms.join(' ');
		const pattern = compile(source, flags['ignore-case']);
		const refs = discover();
		const scope = flags.doc === undefined ? refs : [resolveReference(refs, flags.doc)];
		const hits: SearchHit[] = [];
		let truncated = false;
		for (const ref of scope) {
			const found = searchDocument(
				loadDocument(ref),
				pattern,
				flags.context,
				flags.limit - hits.length,
			);
			hits.push(...found.hits);
			if (found.more) {
				truncated = true;
				break;
			}
		}
		if (out.jsonMode) {
			out.json({ pattern: source, matches: hits, truncated });
			return;
		}
		renderHits(out, hits);
		if (truncated) out.status(`stopped at --limit ${flags.limit}`);
	});

export const specCli = cli('spec')
	.description('Read the vendored standards corpus under docs/ by section')
	.command(listCommand)
	.command(headingsCommand)
	.command(readCommand)
	.command(searchCommand);

if (isMainModule(import.meta)) await specCli.run();
