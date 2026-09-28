import { describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runCommand } from 'dreamcli/testkit';
import { fetchCommand } from '../scripts/fetch-spec.bun.ts';
import { censusLines } from '../scripts/spec/census-data.ts';
import { discover } from '../scripts/spec/corpus.ts';
import { censusCommand, readCommand, statusCommand } from '../scripts/spec/main.ts';
import type { ResourceOptions } from '../scripts/spec/resource.ts';
import { isRecord, loadJsonResource, resourceCachePath } from '../scripts/spec/resource.ts';
import { parseErrata, parseRfcStatus, rfcNumber } from '../scripts/spec/status-data.ts';
import { blocksOf, renderBlocks, renderBody, sourceLines } from '../scripts/spec/text.ts';

const metadata = {
	doc_id: 'RFC5280',
	title: 'Fixture title',
	status: 'PROPOSED STANDARD',
	updates: [],
	obsoletes: ['RFC3280'],
	updated_by: ['RFC6818'],
	obsoleted_by: [],
} as const;
const report = {
	errata_id: '1',
	'doc-id': 'RFC05280',
	errata_status_code: 'Reported',
	errata_type_code: 'Technical',
	section: '4.1',
} as const;

function object(value: unknown): Readonly<Record<string, unknown>> {
	if (!isRecord(value)) throw new Error('expected an object');
	return value;
}

function array(value: unknown): readonly unknown[] {
	if (!Array.isArray(value)) throw new Error('expected an array');
	return value;
}

function json(stdout: readonly string[]): Readonly<Record<string, unknown>> {
	const value: unknown = JSON.parse(stdout.join(''));
	return object(value);
}

async function rejected(operation: Promise<unknown>): Promise<Error> {
	try {
		await operation;
	} catch (error) {
		if (error instanceof Error) return error;
		throw error;
	}
	throw new Error('expected the operation to fail');
}

describe('RFC metadata validation', () => {
	test.each(['5280', 'rfc5280', 'RFC05280'])('normalizes %s', (value) => {
		expect(rfcNumber(value)).toBe('5280');
	});
	test.each(['0', '-1', '5280.txt', '../5280', '9e3', '9007199254740992'])(
		'rejects %s',
		(value) => {
			expect(rfcNumber(value)).toBeUndefined();
		},
	);
	test('preserves separate direct update and obsolescence relationships', () => {
		expect(parseRfcStatus(metadata, '5280')).toEqual({
			number: '5280',
			title: 'Fixture title',
			status: 'PROPOSED STANDARD',
			updates: [],
			obsoletes: ['3280'],
			updatedBy: ['6818'],
			obsoletedBy: [],
		});
	});
	test('does not accept missing relationship data or the wrong document', () => {
		expect(parseRfcStatus({ ...metadata, updated_by: undefined }, '5280')).toBeUndefined();
		expect(parseRfcStatus({ ...metadata, updated_by: ['bad'] }, '5280')).toBeUndefined();
		expect(parseRfcStatus(metadata, '3261')).toBeUndefined();
	});
	test('normalizes and deduplicates relationship identifiers', () => {
		expect(
			parseRfcStatus({ ...metadata, updated_by: ['RFC06818', 'RFC6818', 'RFC9549'] }, '5280')
				?.updatedBy,
		).toEqual(['6818', '9549']);
	});
	test('keeps every published erratum status without promoting it', () => {
		for (const status of [
			'Reported',
			'Verified',
			'Held for Document Update',
			'Rejected',
			'Future status',
		]) {
			expect(parseErrata([{ ...report, errata_status_code: status }])?.[0]?.status).toBe(status);
		}
	});
	test('rejects a malformed or empty index instead of claiming zero errata', () => {
		expect(parseErrata({})).toBeUndefined();
		expect(parseErrata([])).toBeUndefined();
		expect(parseErrata([report, {}])).toBeUndefined();
		expect(parseErrata([report, report])).toBeUndefined();
	});
});

interface FixtureServer {
	readonly url: string;
	readonly options: ResourceOptions;
	readonly requests: () => number;
	readonly respond: (body: string, status?: number) => void;
}

/** A real loopback HTTP server and filesystem, not mocked fetch or filesystem APIs. */
async function withServer(action: (fixture: FixtureServer) => Promise<void>): Promise<void> {
	const directory = await mkdtemp(path.join(tmpdir(), 'spec-status-'));
	let count = 0;
	let body = '42';
	let status = 200;
	const server = Bun.serve({
		hostname: '127.0.0.1',
		port: 0,
		fetch() {
			count += 1;
			return new Response(body, { status, headers: { 'Content-Type': 'application/json' } });
		},
	});
	try {
		await action({
			url: `http://127.0.0.1:${server.port}/status`,
			options: { directory, offline: false, refresh: false, maxAgeSeconds: 86400 },
			requests: () => count,
			respond: (nextBody, nextStatus = 200) => {
				body = nextBody;
				status = nextStatus;
			},
		});
	} finally {
		server.stop(true);
		await rm(directory, { recursive: true, force: true });
	}
}

function numberPayload(value: unknown): number | undefined {
	return typeof value === 'number' ? value : undefined;
}

describe('dated status cache', () => {
	test('uses a validated fresh cache and refreshes only when requested', async () => {
		await withServer(async ({ url, options, requests }) => {
			const first = await loadJsonResource(url, numberPayload, options);
			const second = await loadJsonResource(url, numberPayload, options);
			expect(first.provenance.source).toBe('network');
			expect(second.provenance).toEqual({ ...first.provenance, source: 'cache' });
			expect(requests()).toBe(1);
			await loadJsonResource(url, numberPayload, { ...options, refresh: true });
			expect(requests()).toBe(2);
		});
	});
	test('reports stale offline evidence without making a request', async () => {
		await withServer(async ({ url, options, requests }) => {
			await loadJsonResource(url, numberPayload, options);
			const result = await loadJsonResource(url, numberPayload, {
				...options,
				offline: true,
				maxAgeSeconds: 0,
			});
			expect(result.value).toBe(42);
			expect(result.provenance.fresh).toBe(false);
			expect(result.provenance.source).toBe('cache');
			expect(requests()).toBe(1);
		});
	});
	test('fails on missing offline evidence and contradictory options', async () => {
		await withServer(async ({ url, options, requests }) => {
			expect(
				(await rejected(loadJsonResource(url, numberPayload, { ...options, offline: true })))
					.message,
			).toContain('no usable offline cache');
			expect(
				(
					await rejected(
						loadJsonResource(url, numberPayload, { ...options, offline: true, refresh: true }),
					)
				).message,
			).toContain('conflict');
			expect(requests()).toBe(0);
		});
	});
	test('does not conceal HTTP failure with an older cached success', async () => {
		await withServer(async ({ url, options, respond, requests }) => {
			await loadJsonResource(url, numberPayload, options);
			respond('unavailable', 503);
			expect(
				(await rejected(loadJsonResource(url, numberPayload, { ...options, refresh: true })))
					.message,
			).toContain('503');
			expect(
				(await loadJsonResource(url, numberPayload, { ...options, offline: true })).value,
			).toBe(42);
			expect(requests()).toBe(2);
		});
	});
	test('validates live JSON before replacing good cached evidence', async () => {
		await withServer(async ({ url, options, respond }) => {
			await loadJsonResource(url, numberPayload, options);
			respond('{}');
			expect(
				(await rejected(loadJsonResource(url, numberPayload, { ...options, refresh: true })))
					.message,
			).toContain('incomplete response');
			expect(
				(await loadJsonResource(url, numberPayload, { ...options, offline: true })).value,
			).toBe(42);
		});
	});
	test('rejects corrupt, misfiled and future-dated cache envelopes', async () => {
		await withServer(async ({ url, options, requests }) => {
			await loadJsonResource(url, numberPayload, options);
			const file = resourceCachePath(options.directory, url);
			for (const content of [
				'not JSON',
				JSON.stringify({
					version: 1,
					url: 'https://wrong.example/',
					fetchedAt: new Date().toISOString(),
					payload: 42,
				}),
				JSON.stringify({ version: 1, url, fetchedAt: '2999-01-01T00:00:00.000Z', payload: 42 }),
			]) {
				await writeFile(file, content);
				expect(
					(await rejected(loadJsonResource(url, numberPayload, { ...options, offline: true })))
						.message,
				).toContain('no usable offline cache');
			}
			expect(requests()).toBe(1);
			await loadJsonResource(url, numberPayload, options);
			expect(requests()).toBe(2);
		});
	});
	test('reports a cache write failure without discarding valid network evidence', async () => {
		await withServer(async ({ url, options }) => {
			const blocked = path.join(options.directory, 'file');
			await writeFile(blocked, 'not a directory');
			const result = await loadJsonResource(url, numberPayload, { ...options, directory: blocked });
			expect(result.value).toBe(42);
			expect(result.cacheWarning).toContain('could not cache');
		});
	});
	test('writes complete cache envelopes under concurrent refreshes', async () => {
		await withServer(async ({ url, options }) => {
			await Promise.all(
				Array.from({ length: 5 }, () =>
					loadJsonResource(url, numberPayload, { ...options, refresh: true }),
				),
			);
			const cached: unknown = JSON.parse(
				await readFile(resourceCachePath(options.directory, url), 'utf8'),
			);
			expect(object(cached)['payload']).toBe(42);
			expect((await readdir(options.directory)).some((file) => file.endsWith('.tmp'))).toBe(false);
		});
	});
});

describe('complete multi-concept census', () => {
	test('counts beyond sample limits and preserves zero-hit concepts', () => {
		const lines = sourceLines(`${'alpha\n'.repeat(350)}OMEGA`);
		const result = censusLines(lines, [/alpha/g, /omega/i, /absent/], 1);
		expect(result.map((query) => query.matches)).toEqual([350, 1, 0]);
		expect(result.map((query) => query.samples.length)).toEqual([1, 1, 0]);
		expect(result[1]?.samples[0]?.line).toBe(351);
	});
	test('zero samples suppresses only excerpts', () => {
		expect(censusLines(sourceLines('x\nx'), [/x/], 0)).toEqual([
			{ pattern: 'x', matches: 2, samples: [] },
		]);
	});
	test('the CLI reports every indexed document rather than stopping at 200 hits', async () => {
		const result = await runCommand(censusCommand, [
			'MUST',
			'NoSuchTerm_fa975',
			'--samples',
			'0',
			'--json',
		]);
		expect(result.exitCode).toBe(0);
		const payload = json(result.stdout);
		expect(payload['searched']).toBe(discover().length);
		expect(array(payload['documents']).length).toBe(discover().length);
		expect(payload['truncated']).toBe(false);
		expect(object(array(payload['queries'])[1])['matches']).toBe(0);
	});
	test('rejects an invalid expression before searching', async () => {
		const result = await runCommand(censusCommand, ['[']);
		expect(result.error?.code).toBe('SPEC_PATTERN_INVALID');
	});
});

describe('section citation provenance', () => {
	test('maps a paragraph across page seams to its original source lines', () => {
		const blocks = [
			{
				lines: [
					{ line: 10, text: '  A wrapped' },
					{ line: 11, text: '  paragraph continues' },
				],
				seamBefore: false,
			},
			{ lines: [{ line: 20, text: '  across a page.' }], seamBefore: true },
		] as const;
		expect(renderBlocks(blocks, 2)).toEqual([
			{
				startLine: 10,
				endLine: 20,
				sourceLines: [...blocks[0].lines, ...blocks[1].lines],
				text: 'A wrapped paragraph continues across a page.',
			},
		]);
		expect(renderBody(blocks, 2)).toEqual(['A wrapped paragraph continues across a page.']);
	});
	test('keeps preformatted source lines and separate paragraphs distinct', () => {
		const blocks = blocksOf(
			sourceLines('A paragraph.\n\nThing ::= INTEGER\n  field\n\nAnother paragraph.'),
			new Set(),
		);
		expect(renderBlocks(blocks, 0).map((block) => [block.startLine, block.endLine])).toEqual([
			[1, 1],
			[3, 4],
			[6, 6],
		]);
		expect(renderBody(blocks, 0)).toEqual([
			'A paragraph.',
			'',
			'Thing ::= INTEGER',
			'  field',
			'',
			'Another paragraph.',
		]);
	});
	test('handles an empty section without invented line numbers', () => {
		expect(renderBlocks([], 0)).toEqual([]);
		expect(renderBody([], 0)).toEqual([]);
	});
	test('includes source mappings in JSON while preserving the body field', async () => {
		const result = await runCommand(readCommand, ['rfc5280', '5.1.2.5', '--json']);
		const payload = json(result.stdout);
		expect(result.exitCode).toBe(0);
		expect(typeof payload['body']).toBe('string');
		expect(array(payload['blocks']).length).toBeGreaterThan(0);
		expect(array(payload['sourceLines']).length).toBeGreaterThan(0);
	});
	test('labels both normalized paragraphs and raw file lines', async () => {
		const paragraphs = await runCommand(readCommand, ['rfc5280', '5.1.2.5', '--lines']);
		const raw = await runCommand(readCommand, ['rfc5280', '5.1.2.5', '--raw', '--lines']);
		expect(paragraphs.stdout.join('')).toMatch(/\[L\d+-L\d+\]/);
		expect(raw.stdout.join('')).toMatch(/\[L\d+\]/);
	});
});

describe('spec command integration', () => {
	test('status renders dated offline evidence through the real command', async () => {
		const directory = await mkdtemp(path.join(tmpdir(), 'spec-status-cli-'));
		try {
			const fetchedAt = new Date(Date.now() - 1000).toISOString();
			for (const [url, payload] of [
				['https://www.rfc-editor.org/rfc/rfc5280.json', { ...metadata, updated_by: ['RFC999999'] }],
				['https://www.rfc-editor.org/errata.json', [report]],
			] as const) {
				await writeFile(
					resourceCachePath(directory, url),
					JSON.stringify({ version: 1, url, fetchedAt, payload }),
				);
			}
			const argv = ['5280', 'RFC5280', '--offline', '--max-age', '0', '--cache-dir', directory];
			const result = await runCommand(statusCommand, [...argv, '--json']);
			expect(result.exitCode).toBe(0);
			const payload = json(result.stdout);
			expect(payload['offline']).toBe(true);
			expect(array(payload['documents']).length).toBe(1);
			const document = object(array(payload['documents'])[0]);
			expect(object(document['provenance'])['source']).toBe('cache');
			expect(object(document['provenance'])['fresh']).toBe(false);
			expect(object(array(document['successors'])[0])['vendored']).toBe(false);
			expect(object(array(document['errata'])[0])['status']).toBe('Reported');
			const human = await runCommand(statusCommand, argv);
			expect(human.exitCode).toBe(0);
			expect(human.stdout.join('')).toContain('STALE; OFFLINE');
			expect(human.stdout.join('')).toContain('bun spec fetch rfc 999999');
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});
	test('status fails with a coded error when offline evidence is absent', async () => {
		const directory = await mkdtemp(path.join(tmpdir(), 'spec-status-missing-'));
		try {
			const result = await runCommand(statusCommand, [
				'5280',
				'--offline',
				'--cache-dir',
				directory,
			]);
			expect(result.error?.code).toBe('SPEC_STATUS_UNAVAILABLE');
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});
	test('fetch help exposes all three existing fetchers without fetching', async () => {
		const result = await runCommand(fetchCommand, ['--help']);
		expect(result.exitCode).toBe(0);
		for (const name of ['rfc', 'itu', 'w3c']) expect(result.stdout.join('')).toContain(name);
	});
	test('status rejects unsupported document kinds and conflicting modes before network access', async () => {
		const unsupported = await runCommand(statusCommand, ['pkits', '--offline']);
		const conflict = await runCommand(statusCommand, ['5280', '--offline', '--refresh']);
		expect(unsupported.error?.code).toBe('SPEC_DOC_UNKNOWN');
		expect(conflict.error?.code).toBe('SPEC_STATUS_OPTIONS');
	});
});

describe('status relationship rendering', () => {
	test.each([
		{
			name: 'non-empty relationships',
			updates: ['RFC100', 'RFC101'],
			obsoletes: ['RFC200'],
			updated_by: ['RFC300'],
			obsoleted_by: ['RFC400', 'RFC401'],
		},
		{ name: 'empty relationships', updates: [], obsoletes: [], updated_by: [], obsoleted_by: [] },
	])('keeps all four directions in human and JSON output: $name', async (relations) => {
		const directory = await mkdtemp(path.join(tmpdir(), 'spec-status-relations-'));
		try {
			const fetchedAt = new Date(Date.now() - 1000).toISOString();
			// Synthetic relationships exercise every direction without depending on live RFC status.
			for (const [url, payload] of [
				['https://www.rfc-editor.org/rfc/rfc5280.json', { ...metadata, ...relations }],
				['https://www.rfc-editor.org/errata.json', [report]],
			] as const) {
				await writeFile(
					resourceCachePath(directory, url),
					JSON.stringify({ version: 1, url, fetchedAt, payload }),
				);
			}
			const argv = ['5280', '--offline', '--cache-dir', directory];
			const human = await runCommand(statusCommand, argv);
			const machine = await runCommand(statusCommand, [...argv, '--json']);
			expect(human.exitCode).toBe(0);
			expect(machine.exitCode).toBe(0);
			const lines = human.stdout.join('').split('\n');
			const document = object(array(json(machine.stdout)['documents'])[0]);
			for (const [label, key, values] of [
				['updates', 'updates', relations.updates],
				['obsoletes', 'obsoletes', relations.obsoletes],
				['updated by', 'updatedBy', relations.updated_by],
				['obsoleted by', 'obsoletedBy', relations.obsoleted_by],
			] as const) {
				const expected = values.map((value) => value.slice(3));
				expect(document[key]).toEqual(expected);
				expect(lines).toContain(`  ${label}: ${expected.join(', ') || 'none recorded'}`);
			}
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});
});
