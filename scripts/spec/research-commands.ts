import path from 'node:path';
import type { Out } from 'dreamcli';
import { arg, CLIError, command, flag } from 'dreamcli';
import { censusLines } from './census-data.ts';
import { discover, enclosingHeading, loadDocument, repositoryRoot } from './corpus.ts';
import type { ResourceOptions, ResourceProvenance } from './resource.ts';
import { loadJsonResource } from './resource.ts';
import type { Erratum, RfcStatus } from './status-data.ts';
import { parseErrata, parseRfcStatus, rfcNumber } from './status-data.ts';

interface StatusDocument extends RfcStatus {
	readonly vendored: boolean;
	readonly provenance: ResourceProvenance;
	readonly successors: readonly {
		readonly number: string;
		readonly relation: 'updates' | 'obsoletes';
		readonly vendored: boolean;
	}[];
	readonly errata: readonly Erratum[];
}

function patternsOf(terms: readonly string[], caseSensitive: boolean): readonly RegExp[] {
	try {
		if (terms.length === 0 || terms.some((term) => term.trim() === '')) {
			throw new Error('provide at least one non-empty expression');
		}
		return [...new Set(terms)].map((term) => new RegExp(term, caseSensitive ? '' : 'i'));
	} catch (cause) {
		throw new CLIError('invalid census expression', {
			code: 'SPEC_PATTERN_INVALID',
			cause,
			suggest: 'Quote each concept separately, e.g. bun spec census REAL NR3 mantissa',
		});
	}
}

export const censusCommand = command('census')
	.description('Scan every indexed document for independent concepts; never truncate coverage')
	.example('spec census REAL NR3 mantissa "decimal encoding"', 'Discover documents before reading')
	.example(
		'spec census nextUpdate freshness --samples 0 --json',
		'Complete counts without excerpts',
	)
	.arg('terms', arg.string().variadic().describe('Separate regular expressions, one per concept'))
	.flag('case-sensitive', flag.boolean().describe('Match case exactly (default: insensitive)'))
	.flag(
		'samples',
		flag.number({ int: true, min: 0 }).default(1).describe('Examples per query per document'),
	)
	.action(({ args, flags, out }) => {
		const patterns = patternsOf(args.terms, flags['case-sensitive']);
		const documents = discover().map((ref) => {
			const document = loadDocument(ref);
			const queries = censusLines(document.lines, patterns, flags.samples).map((query) => ({
				...query,
				samples: query.samples.map((sample) => {
					const index = document.lines.findIndex((line) => line.line === sample.line);
					const heading = enclosingHeading(document, index);
					return {
						...sample,
						section:
							heading === undefined ? null : { number: heading.number, title: heading.title },
					};
				}),
			}));
			return { doc: document.id, path: document.relativePath, queries };
		});
		const queries = patterns.map((pattern) => ({
			pattern: pattern.source,
			matches: documents.reduce(
				(total, doc) =>
					total + (doc.queries.find((query) => query.pattern === pattern.source)?.matches ?? 0),
				0,
			),
		}));
		if (out.jsonMode) {
			out.json({
				searched: documents.length,
				caseSensitive: flags['case-sensitive'],
				queries,
				documents,
				truncated: false,
			});
			return;
		}
		out.log(
			`Scanned all ${documents.length} indexed documents. Counts are matching lines per expression.`,
		);
		for (const query of queries) out.log(`${query.pattern}: ${query.matches} matches`);
		for (const document of documents) {
			for (const query of document.queries) {
				if (query.matches === 0) continue;
				out.log(`\n${document.doc} | ${query.pattern} | ${query.matches} matches`);
				for (const sample of query.samples) {
					out.log(
						`${document.path}:${sample.line} §${sample.section?.number ?? '?'} ${sample.text}`,
					);
				}
			}
		}
	});

function numbersOf(documents: readonly string[]): readonly string[] {
	if (documents.length === 0) {
		throw new CLIError('status needs at least one RFC', { code: 'SPEC_DOC_UNKNOWN' });
	}
	return [
		...new Set(
			documents.map((document) => {
				const number = rfcNumber(document);
				if (number === undefined) {
					throw new CLIError(`status currently supports RFC identifiers, not ${document}`, {
						code: 'SPEC_DOC_UNKNOWN',
						suggest:
							'Use a bare RFC number or rfc<number>; ITU/W3C currency still requires source inspection',
					});
				}
				return number;
			}),
		),
	];
}

interface StatusFlags {
	readonly offline: boolean;
	readonly refresh: boolean;
	readonly 'cache-dir': string | undefined;
	readonly 'max-age': number;
}

interface StatusEvidence {
	readonly documents: readonly StatusDocument[];
	readonly errataProvenance: ResourceProvenance;
	readonly warnings: readonly string[];
}

function statusOptions(flags: StatusFlags): ResourceOptions {
	if (flags.offline && flags.refresh) {
		throw new CLIError('--offline and --refresh conflict', { code: 'SPEC_STATUS_OPTIONS' });
	}
	return {
		directory: path.resolve(
			flags['cache-dir'] ?? path.join(repositoryRoot, 'node_modules', '.cache', 'spec-status'),
		),
		offline: flags.offline,
		refresh: flags.refresh,
		maxAgeSeconds: flags['max-age'],
	};
}

function vendoredRfcs(): ReadonlySet<string> {
	return new Set(
		discover()
			.filter((ref) => ref.kind === 'rfc')
			.map((ref) => ref.id),
	);
}

function successorsOf(
	status: RfcStatus,
	vendored: ReadonlySet<string>,
): StatusDocument['successors'] {
	return [
		...status.updatedBy.map((number) => ({
			number,
			relation: 'updates' as const,
			vendored: vendored.has(`rfc${number}`),
		})),
		...status.obsoletedBy.map((number) => ({
			number,
			relation: 'obsoletes' as const,
			vendored: vendored.has(`rfc${number}`),
		})),
	];
}

async function loadStatusDocument(
	number: string,
	options: ResourceOptions,
	vendored: ReadonlySet<string>,
	errata: readonly Erratum[],
	warnings: string[],
): Promise<StatusDocument> {
	const metadata = await loadJsonResource(
		`https://www.rfc-editor.org/rfc/rfc${number}.json`,
		(value) => parseRfcStatus(value, number),
		options,
	);
	if (metadata.cacheWarning !== undefined) warnings.push(metadata.cacheWarning);
	return {
		...metadata.value,
		vendored: vendored.has(`rfc${number}`),
		provenance: metadata.provenance,
		successors: successorsOf(metadata.value, vendored),
		errata: errata.filter((report) => report.number === number),
	};
}

async function loadStatusEvidence(
	numbers: readonly string[],
	options: ResourceOptions,
): Promise<StatusEvidence> {
	const errata = await loadJsonResource(
		'https://www.rfc-editor.org/errata.json',
		parseErrata,
		options,
	);
	const warnings: string[] = errata.cacheWarning === undefined ? [] : [errata.cacheWarning];
	const vendored = vendoredRfcs();
	const documents: StatusDocument[] = [];
	for (const number of numbers) {
		documents.push(await loadStatusDocument(number, options, vendored, errata.value, warnings));
	}
	return { documents, errataProvenance: errata.provenance, warnings };
}

function renderStatusDocument(out: Out, document: StatusDocument, offline: boolean): void {
	const evidence = document.provenance;
	out.log(`RFC ${document.number}: ${document.title} (${document.status})`);
	out.log(
		`  ${evidence.source} observation ${evidence.fetchedAt}; ${evidence.fresh ? 'within cache age' : 'STALE'}${offline ? '; OFFLINE' : ''}`,
	);
	out.log(`  vendored: ${document.vendored ? 'yes' : 'no'}`);
	out.log(`  updates: ${document.updates.join(', ') || 'none recorded'}`);
	out.log(`  obsoletes: ${document.obsoletes.join(', ') || 'none recorded'}`);
	out.log(`  updated by: ${document.updatedBy.join(', ') || 'none recorded'}`);
	out.log(`  obsoleted by: ${document.obsoletedBy.join(', ') || 'none recorded'}`);
	for (const successor of document.successors) {
		if (!successor.vendored) {
			out.log(`  missing ${successor.relation} text: bun spec fetch rfc ${successor.number}`);
		}
	}
	out.log(`  errata: ${document.errata.length}`);
	for (const report of document.errata) {
		out.log(
			`    ${report.id} ${report.status} (${report.type}, §${report.section || '?'}) ${report.url}`,
		);
	}
}

function renderStatus(out: Out, evidence: StatusEvidence, offline: boolean): void {
	for (const document of evidence.documents) renderStatusDocument(out, document, offline);
	const errata = evidence.errataProvenance;
	out.log(
		`Errata ${errata.source} observation: ${errata.fetchedAt}; ${errata.fresh ? 'within cache age' : 'STALE'}`,
	);
	out.log(
		'Relationships identify text to inspect, not automatic policy changes. Errata retain their published status.',
	);
	for (const warning of evidence.warnings) out.warn(warning);
}

async function runStatus(
	documents: readonly string[],
	flags: StatusFlags,
	out: Out,
): Promise<void> {
	const numbers = numbersOf(documents);
	const options = statusOptions(flags);
	try {
		const evidence = await loadStatusEvidence(numbers, options);
		if (out.jsonMode) {
			out.json({
				offline: flags.offline,
				documents: evidence.documents,
				errataProvenance: evidence.errataProvenance,
				warnings: evidence.warnings,
			});
			return;
		}
		renderStatus(out, evidence, flags.offline);
	} catch (cause) {
		throw new CLIError('RFC status unavailable; no current-status conclusion was produced', {
			code: 'SPEC_STATUS_UNAVAILABLE',
			cause,
			suggest: 'Retry online, or use --offline to inspect a previously cached observation',
		});
	}
}

export const statusCommand = command('status')
	.description(
		'Check RFC Editor relationships, vendored successors and errata with dated provenance',
	)
	.example('spec status rfc5280 rfc3261', 'Use validated metadata cached for up to one day')
	.example('spec status 5280 --refresh --json', 'Require a new online observation')
	.example('spec status 5280 --offline', 'Inspect cached evidence without a network request')
	.arg('documents', arg.string().variadic().describe('RFC identifiers or bare numbers'))
	.flag(
		'offline',
		flag.boolean().describe('Use only cached evidence, explicitly reporting staleness'),
	)
	.flag('refresh', flag.boolean().describe('Bypass fresh caches; never silently fall back'))
	.flag(
		'cache-dir',
		flag
			.string()
			.describe('Status cache directory (default: repository node_modules/.cache/spec-status)'),
	)
	.flag(
		'max-age',
		flag.number({ int: true, min: 0 }).default(86400).describe('Cache freshness in seconds'),
	)
	.action(({ args, flags, out }) => runStatus(args.documents, flags, out));
