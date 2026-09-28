import { describe, expect, test } from 'bun:test';
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { repositoryRoot } from '../scripts/spec/corpus.ts';
import { isRecord } from '../scripts/spec/resource.ts';

// Authored fixture text, not redistributed Microsoft source or mocked parser output.
const msLines = [
	'[MS-FIXTURE]:',
	'Synthetic research fixture',
	'',
	'1 Introduction',
	'',
	'  Introductory fixture text.',
	'',
	'1.1 Evidence',
	'',
	'  A fixture paragraph preserves',
	'  its original source positions.',
	'',
	'  MUST include MsOnly_130 in the complete census.',
	'',
	'2 Other material',
	'',
	'  This belongs to a different section.',
	'',
	'1 / 1',
	'[MS-FIXTURE] - v20260928',
	'Synthetic research fixture',
	'Copyright © 2026 Microsoft Corporation',
	'Release: September 28, 2026',
	'',
] as const;
const msId = 'ms-fixture-20260928';

function object(value: unknown): Readonly<Record<string, unknown>> {
	if (!isRecord(value)) {
		throw new Error('expected a JSON object');
	}
	return value;
}

function array(value: unknown): readonly unknown[] {
	if (!Array.isArray(value)) throw new Error('expected a JSON array');
	return value;
}

function json(text: string): Readonly<Record<string, unknown>> {
	const value: unknown = JSON.parse(text);
	return object(value);
}

async function runBun(root: string, args: readonly string[], cwd = path.join(root, 'caller')) {
	const child = Bun.spawn([process.execPath, ...args], {
		cwd,
		stdin: 'ignore',
		stdout: 'pipe',
		stderr: 'pipe',
		env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
	});
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	if (exitCode !== 0) throw new Error(`fixture CLI exited ${exitCode}: ${stderr}\n${stdout}`);
	return stdout;
}

function spec(root: string, args: readonly string[]): Promise<string> {
	return runBun(root, [path.join(root, 'scripts', 'spec', 'main.ts'), ...args]);
}

/** Run the actual CLI and parsers in a private corpus; never modify the working corpus. */
async function withCorpus(action: (root: string) => Promise<void>): Promise<void> {
	const root = await mkdtemp(path.join(tmpdir(), 'micro509-spec-ms-'));
	try {
		await mkdir(path.join(root, 'scripts'), { recursive: true });
		await cp(path.join(repositoryRoot, 'scripts', 'spec'), path.join(root, 'scripts', 'spec'), {
			recursive: true,
		});
		await cp(path.join(repositoryRoot, 'scripts', 'fetch-spec.bun.ts'), path.join(root, 'scripts', 'fetch-spec.bun.ts'));
		await cp(path.join(repositoryRoot, 'package.json'), path.join(root, 'package.json'));
		await symlink(path.join(repositoryRoot, 'node_modules'), path.join(root, 'node_modules'),
			process.platform === 'win32' ? 'junction' : 'dir');
		await mkdir(path.join(root, 'caller'));
		await mkdir(path.join(root, 'docs', 'rfc'), { recursive: true });
		await mkdir(path.join(root, 'docs', 'ms', 'MS-FIXTURE'), { recursive: true });
		await writeFile(path.join(root, 'docs', 'ms', 'MS-FIXTURE', 'MS-FIXTURE-v20260928.txt'), msLines.join('\n'));
		await writeFile(path.join(root, 'docs', 'rfc', 'rfc999999.txt'), [
			'Network Working Group                                      Fixture Author',
			'Request for Comments: 999999                               September 2026',
			'Category: Informational',
			'',
			'                         Synthetic Census Fixture',
			'',
			'1. Introduction',
			'',
			...Array.from({ length: 350 }, () => '   MUST count this fixture line.'),
			'',
		].join('\n'));
		await action(root);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}

describe('MS-aware research CLI integration', () => {
	test('lists Microsoft metadata from the existing parser, independently of caller CWD', async () => {
		await withCorpus(async (root) => {
			const payload = json(await spec(root, ['list', '--json']));
			const entry = array(payload['documents']).map(object).find((doc) => doc['id'] === msId);
			expect(entry).toBeDefined();
			expect(entry?.['kind']).toBe('ms');
			expect(entry?.['document']).toBe('MS-FIXTURE');
			expect(entry?.['version']).toBe('v20260928');
			expect(entry?.['date']).toBe('September 28, 2026');
		});
	});

	test('censuses Microsoft documents after RFC matches exhaust the excerpt limit', async () => {
		await withCorpus(async (root) => {
			const excerpt = json(await spec(root, ['search', 'MUST', '--limit', '2', '--json']));
			expect(excerpt['truncated']).toBe(true);
			expect(array(excerpt['matches']).map((hit) => object(hit)['doc'])).toEqual(['rfc999999', 'rfc999999']);
			const payload = json(await spec(root, ['census', 'MUST', 'MsOnly_130', 'Missing_130', '--samples', '1', '--json']));
			expect(payload['searched']).toBe(2);
			expect(payload['truncated']).toBe(false);
			expect(array(payload['queries']).map((query) => object(query)['matches'])).toEqual([351, 1, 0]);
			const ms = array(payload['documents']).map(object).find((doc) => doc['doc'] === msId);
			expect(ms).toBeDefined();
			const query = array(ms?.['queries']).map(object).find((entry) => entry['pattern'] === 'MsOnly_130');
			expect(query?.['matches']).toBe(1);
			const sample = object(array(query?.['samples'])[0]);
			expect(object(sample['section'])['number']).toBe('1.1');
			expect(sample['line']).toBe(13);
		});
	});

	test('reads Microsoft sections with exact original source mappings', async () => {
		await withCorpus(async (root) => {
			const payload = json(await spec(root, ['read', msId, '1.1', '--json']));
			expect(payload['body']).toContain('A fixture paragraph preserves its original source positions.');
			expect(payload['body']).not.toContain('different section');
			const block = array(payload['blocks']).map(object).find((entry) => entry['startLine'] === 10);
			expect(block?.['endLine']).toBe(11);
			expect(block?.['sourceLines']).toEqual([
				{ line: 10, text: msLines[9] }, { line: 11, text: msLines[10] },
			]);
			const human = await spec(root, ['read', msId, '1.1', '--lines']);
			const raw = await spec(root, ['read', msId, '1.1', '--raw', '--lines']);
			expect(human).toContain('[L10-L11] A fixture paragraph preserves its original source positions.');
			expect(raw).toContain(`[L10] ${msLines[9]}`);
			expect(raw).toContain(`[L11] ${msLines[10]}`);
		});
	});

	test('indexes MS headings and preserves bounded excerpt search', async () => {
		await withCorpus(async (root) => {
			const outline = json(await spec(root, ['headings', msId, '--depth', '4', '--json']));
			expect(array(outline['headings']).map((heading) => object(heading)['number'])).toEqual(['1', '1.1', '2']);
			const found = json(await spec(root, ['search', 'MsOnly_130', '--doc', msId, '--json']));
			expect(found['truncated']).toBe(false);
			expect(array(found['matches']).length).toBe(1);
			expect(object(array(found['matches'])[0])['line']).toBe(13);
		});
	});

	test('exposes all four fetchers and MS help from nested, legacy and package entry points', async () => {
		await withCorpus(async (root) => {
			const help = await spec(root, ['fetch', '--help']);
			for (const name of ['rfc', 'itu', 'w3c', 'ms']) expect(help).toContain(name);
			const nested = await spec(root, ['fetch', 'ms', '--help']);
			const legacy = await runBun(root, [path.join(root, 'scripts', 'fetch-spec.bun.ts'), 'ms', '--help']);
			const alias = await runBun(root, ['run', 'ms', '--help'], root);
			for (const output of [nested, legacy, alias]) expect(output).toContain('MS-WCCE');
		});
	});

	test('importing the MS-capable fetcher does not execute its legacy CLI', async () => {
		await withCorpus(async (root) => {
			const moduleUrl = pathToFileURL(path.join(root, 'scripts', 'fetch-spec.bun.ts')).href;
			const output = await runBun(root, ['--eval', `await import(${JSON.stringify(moduleUrl)}); console.log('IMPORT_ONLY');`]);
			expect(output.trim()).toBe('IMPORT_ONLY');
		});
	});
});
