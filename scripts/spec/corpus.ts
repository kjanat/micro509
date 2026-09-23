import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLIError } from 'dreamcli';
import { ituIdentifier, parseItu } from './itu.ts';
import { parsePkits } from './pkits.ts';
import { parseRfc } from './rfc.ts';
import type { DocumentRef, Heading, SourceLine, SpecDocument } from './types.ts';
import { parseW3c, w3cIdentifier } from './w3c.ts';

const RFC_FILE = /^rfc(\d+)\.txt$/;

export const repositoryRoot = path.resolve(
	path.dirname(fileURLToPath(import.meta.url)),
	'..',
	'..',
);

function textFiles(directory: string): readonly string[] {
	if (!existsSync(directory)) return [];
	return readdirSync(directory)
		.filter((name) => name.endsWith('.txt'))
		.sort();
}

function subdirectories(directory: string): readonly string[] {
	if (!existsSync(directory)) return [];
	return readdirSync(directory)
		.filter((name) => statSync(path.join(directory, name)).isDirectory())
		.sort();
}

function reference(id: string, kind: DocumentRef['kind'], absolute: string): DocumentRef {
	return {
		id,
		kind,
		path: absolute,
		relativePath: path.relative(repositoryRoot, absolute).split(path.sep).join('/'),
	};
}

function rfcReferences(root: string): readonly DocumentRef[] {
	const directory = path.join(root, 'docs', 'rfc');
	const numbered: { readonly number: number; readonly ref: DocumentRef }[] = [];
	const others: DocumentRef[] = [];
	for (const name of textFiles(directory)) {
		const absolute = path.join(directory, name);
		const match = RFC_FILE.exec(name);
		if (match?.[1] !== undefined) {
			const value = Number.parseInt(match[1], 10);
			numbered.push({ number: value, ref: reference(`rfc${value}`, 'rfc', absolute) });
			continue;
		}
		if (name === 'pkits.txt') others.push(reference('pkits', 'pkits', absolute));
	}
	numbered.sort((left, right) => left.number - right.number);
	return [...numbered.map((entry) => entry.ref), ...others];
}

function nestedReferences(
	root: string,
	folder: string,
	kind: DocumentRef['kind'],
	identify: (stem: string, directory: string) => string,
): readonly DocumentRef[] {
	const base = path.join(root, 'docs', folder);
	const refs: DocumentRef[] = [];
	for (const directory of subdirectories(base)) {
		for (const name of textFiles(path.join(base, directory))) {
			const stem = name.slice(0, -'.txt'.length);
			refs.push(reference(identify(stem, directory), kind, path.join(base, directory, name)));
		}
	}
	return refs.sort((left, right) => left.id.localeCompare(right.id));
}

function deduplicate(refs: readonly DocumentRef[]): readonly DocumentRef[] {
	const taken = new Set<string>();
	return refs.map((ref) => {
		if (!taken.has(ref.id)) {
			taken.add(ref.id);
			return ref;
		}
		let suffix = 2;
		while (taken.has(`${ref.id}-${suffix}`)) suffix += 1;
		const id = `${ref.id}-${suffix}`;
		taken.add(id);
		return { ...ref, id };
	});
}

export function discover(root: string = repositoryRoot): readonly DocumentRef[] {
	return deduplicate([
		...rfcReferences(root),
		...nestedReferences(root, 'itu', 'itu', ituIdentifier),
		...nestedReferences(root, 'w3c', 'w3c', (stem) => w3cIdentifier(stem)),
	]);
}

const cache = new Map<string, SpecDocument>();

export function loadDocument(ref: DocumentRef): SpecDocument {
	const cached = cache.get(ref.path);
	if (cached !== undefined) return cached;
	const source = readFileSync(ref.path, 'utf8');
	const parsed =
		ref.kind === 'rfc'
			? parseRfc(source, Number.parseInt(ref.id.slice(3), 10))
			: ref.kind === 'pkits'
				? parsePkits(source)
				: ref.kind === 'itu'
					? parseItu(source, path.basename(ref.path, '.txt'), path.basename(path.dirname(ref.path)))
					: parseW3c(source);
	const document: SpecDocument = {
		...parsed,
		id: ref.id,
		kind: ref.kind,
		relativePath: ref.relativePath,
	};
	cache.set(ref.path, document);
	return document;
}

export function resolveReference(refs: readonly DocumentRef[], wanted: string): DocumentRef {
	const direct = refs.find((ref) => ref.id === wanted);
	if (direct !== undefined) return direct;
	const bare = /^\d+$/.test(wanted) ? refs.find((ref) => ref.id === `rfc${wanted}`) : undefined;
	if (bare !== undefined) return bare;
	const lowered = wanted.toLowerCase();
	const insensitive = refs.find((ref) => ref.id.toLowerCase() === lowered);
	if (insensitive !== undefined) return insensitive;
	const near = refs.filter((ref) => ref.id.includes(lowered)).map((ref) => ref.id);
	throw new CLIError(`unknown document: ${wanted}`, {
		code: 'SPEC_DOC_UNKNOWN',
		suggest:
			near.length > 0 ? `did you mean ${near.slice(0, 5).join(', ')}?` : 'run `bun spec list`',
		details: { wanted },
	});
}

export function findHeading(document: SpecDocument, wanted: string): Heading {
	const byNumber = document.headings.find((heading) => heading.number === wanted);
	if (byNumber !== undefined) return byNumber;
	const lowered = wanted.toLowerCase();
	const byNumberCase = document.headings.find(
		(heading) => heading.number.toLowerCase() === lowered,
	);
	if (byNumberCase !== undefined) return byNumberCase;
	const byTitle = document.headings.find((heading) => heading.title.toLowerCase() === lowered);
	if (byTitle !== undefined) return byTitle;
	const byPartial = document.headings.find((heading) =>
		heading.title.toLowerCase().includes(lowered),
	);
	if (byPartial !== undefined) return byPartial;
	throw new CLIError(`unknown section in ${document.id}: ${wanted}`, {
		code: 'SPEC_SECTION_UNKNOWN',
		suggest: `run \`bun spec headings ${document.id}\``,
		details: { document: document.id, wanted },
	});
}

export function sectionLines(document: SpecDocument, heading: Heading): readonly SourceLine[] {
	const next = document.headings.find(
		(candidate) => candidate.index > heading.index && candidate.depth <= heading.depth,
	);
	return document.lines.slice(heading.index + 1, next?.index ?? document.lines.length);
}

export function enclosingHeading(document: SpecDocument, index: number): Heading | undefined {
	let found: Heading | undefined;
	for (const heading of document.headings) {
		if (heading.index > index) break;
		found = heading;
	}
	return found;
}

export interface RfcRelations {
	readonly updatedBy: readonly number[];
	readonly obsoletedBy: readonly number[];
}

export function rfcRelations(
	documents: readonly SpecDocument[],
): ReadonlyMap<number, RfcRelations> {
	const updatedBy = new Map<number, number[]>();
	const obsoletedBy = new Map<number, number[]>();
	for (const document of documents) {
		if (document.meta.kind !== 'rfc') continue;
		for (const target of document.meta.updates) {
			updatedBy.set(target, [...(updatedBy.get(target) ?? []), document.meta.number]);
		}
		for (const target of document.meta.obsoletes) {
			obsoletedBy.set(target, [...(obsoletedBy.get(target) ?? []), document.meta.number]);
		}
	}
	const relations = new Map<number, RfcRelations>();
	for (const document of documents) {
		if (document.meta.kind !== 'rfc') continue;
		relations.set(document.meta.number, {
			updatedBy: [...(updatedBy.get(document.meta.number) ?? [])].sort((a, b) => a - b),
			obsoletedBy: [...(obsoletedBy.get(document.meta.number) ?? [])].sort((a, b) => a - b),
		});
	}
	return relations;
}
