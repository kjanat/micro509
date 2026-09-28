import { describe, expect, test } from 'bun:test';
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runCommand } from 'dreamcli/testkit';
import { decide } from '../.claude/hooks/spec-lookup-gate.ts';
import {
	discover,
	findHeading,
	repositoryRoot,
	resolveReference,
	sectionLines,
} from '../scripts/spec/corpus.ts';
import { ituIdentifier, ituMeta, parseItu } from '../scripts/spec/itu.ts';
import { ITU_ITEM, ituSourceStem } from '../scripts/spec/itu-source.ts';
import { readCommand } from '../scripts/spec/main.ts';
import { readWindow } from '../scripts/spec/read-window.ts';
import { isRecord } from '../scripts/spec/resource.ts';
import { runsOf } from '../scripts/spec/search-runs.ts';
import { sourceDiagnostics } from '../scripts/spec/source-quality.ts';

function verdict(command: string): string {
	return decide(
		{ tool: 'Bash', agent: undefined, cwd: repositoryRoot, input: { command } },
		repositoryRoot,
	).kind;
}

async function scratch(action: (root: string) => Promise<void>): Promise<void> {
	const root = await mkdtemp(path.join(tmpdir(), 'spec-maintenance-'));
	try {
		await action(root);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}

function object(value: unknown): Record<string, unknown> {
	if (!isRecord(value)) throw new Error('expected an object');
	return value;
}

function cover(recommendation: string, date = '02/2021'): string {
	return `International Telecommunication Union\nITU-T ${recommendation}\n(${date})\nSynthetic test recommendation\n\n1  Scope\n\n   Authored fixture, not standards text.\n`;
}

describe('runtime operands and Git maintenance', () => {
	test.each([
		'--conditions development',
		'--conditions=development',
		'-C development',
		'-Cdevelopment',
		'--title research',
		'--diagnostic-dir logs',
		'--env-file-if-exists absent',
		'--max-old-space-size 2048',
		'--trace-event-categories node',
	])('consumes Node option %s before the reader', (options) => {
		for (const prefix of ['node', 'nice -n 5 node', 'npm exec -- node']) {
			expect(verdict(`${prefix} ${options} scripts/spec/main.ts read rfc5280 4.1`)).toBe('deny');
			expect(
				verdict(`${prefix} ${options} scripts/spec/main.ts status 5280 --offline --cache-dir read`),
			).toBe('pass');
		}
	});
	test.each([
		'git add docs/rfc',
		'git add -- docs/rfc',
		'git add -A docs/rfc',
		'git -C /tmp/repo add -- docs/rfc',
		'git -c core.quotePath=false add docs/rfc',
		'nice -n 5 git add docs/rfc',
		'git status --short docs/rfc',
		'git ls-files docs/rfc',
		'git check-ignore docs/itu',
		'git add -- docs/rfc/-p',
	])('allows non-reading bookkeeping: %s', (command) => {
		expect(verdict(command)).toBe('pass');
	});
	test.each([
		'git add -p docs/rfc',
		'git add --patch docs/rfc',
		'git add --interactive docs/rfc',
		'git add -e docs/rfc',
		'git show HEAD:docs/rfc/rfc5280.txt',
		'git grep nextUpdate docs/rfc',
		'git add docs/rfc && cat docs/rfc/rfc5280.txt',
		'git add "$(cat docs/rfc/rfc5280.txt)"',
	])('still delegates actual or interactive reads: %s', (command) => {
		expect(verdict(command)).toBe('deny');
	});
});

describe('ITU series and bundled identities', () => {
	test.each([
		'T-REC-T.61-198811-S!!PDF-E',
		'T-REC-T.51-199209-I!!PDF-E',
		'T-REC-T.52-199304-I!!PDF-E',
		'T-REC-X.509-202310-I!Cor2!PDF-E',
	])('accepts a complete item outside an X-only whitelist: %s', (item) => {
		expect(ITU_ITEM.test(item)).toBe(true);
		expect(ituMeta(item, 'wrong-directory').variant).not.toBe('other');
	});
	test.each([
		'T-REC-T.61-198813-S!!PDF-E',
		'../T-REC-T.61-198811-S!!PDF-E',
		'T-REC-T.61-198811-S',
		'T-REC-T.61-198811-S!!MSW-E',
	])('rejects invalid fetch input %s', (item) => {
		expect(ITU_ITEM.test(item)).toBe(false);
	});
	test.each(['X.680', 'X.690', 'X.691', 'X.692', 'X.693'])(
		'reads %s and its date from a bundle member cover',
		(recommendation) => {
			const source = cover(recommendation);
			const stem = `${recommendation.replace('.', '')}1`;
			expect(ituIdentifier(stem, 'X.680', source)).toBe(
				`itu-${recommendation.replace('.', '').toLowerCase()}-2021`,
			);
			expect(ituMeta(stem, 'X.680', source)).toMatchObject({
				recommendation,
				edition: '02/2021',
				variant: 'base',
			});
		},
	);
	test('does not invent a date from a bundle filename or a citation after the contents', () => {
		expect(ituSourceStem('X6911', 'ITU-T X.691\nNo edition evidence')).toBe('X6911');
		expect(ituSourceStem('X6911', 'CONTENTS\nITU-T X.691\n(02/2021)')).toBe('X6911');
		expect(ituMeta('X6911', 'X.680').edition).toBeUndefined();
	});
	test('discovers bundle documents under their own identifiers without rewriting files', async () => {
		await scratch(async (root) => {
			const directory = path.join(root, 'docs/itu/X.680');
			await mkdir(directory, { recursive: true });
			for (const number of [680, 690, 691, 692, 693]) {
				await writeFile(path.join(directory, `X${number}1.txt`), cover(`X.${number}`));
			}
			const refs = discover(root);
			expect(refs.map((ref) => ref.id)).toEqual(
				[680, 690, 691, 692, 693].map((n) => `itu-x${n}-2021`),
			);
			expect(resolveReference(refs, 'itu-x691-2021').path).toBe(path.join(directory, 'X6911.txt'));
		});
	});
	test.each(['', '# '])(
		'keeps short numbered body clauses without turning short headings into body text (%s)',
		(marker) => {
			const sentence = 'The value is present.';
			const source = `1  Scope\n\n1.1  Definitions\n\n${marker}1.1.1  ${sentence}\n\n${marker}1.1.2  Value syntax\n`;
			const normalized =
				marker === ''
					? source
					: source.replace(/^1 {2}/m, '# 1  ').replace(/^1\.1 {2}/m, '# 1.1  ');
			const parsed = parseItu(normalized, 'T-REC-X.680-202102-I!!MSW-E', 'X.680');
			const document = {
				...parsed,
				id: 'itu-x680-2021',
				kind: 'itu' as const,
				relativePath: 'fixture.txt',
			};
			const body = findHeading(document, '1.1.1');
			expect(body).toMatchObject({ title: '', depth: 3, inlineBody: true });
			expect(sectionLines(document, body)[0]?.text).toContain(sentence);
			const heading = findHeading(document, '1.1.2');
			expect(heading).toMatchObject({ title: 'Value syntax', depth: 3 });
			expect(heading.inlineBody).toBeUndefined();
		},
	);
	test.each(['', '# '])(
		'keeps numbered body clauses addressable without giant outline titles (%s)',
		(marker) => {
			const paragraph =
				'The implementation shall retain the following authored fixture paragraph in its original entirety rather than turn all of these words into an outline title.';
			const source = `1  Scope\n\n1.1  Definitions\n\n${marker}1.1.1  ${paragraph}\n\n${marker}1.1.2  ${paragraph}\n`;
			// Mark every real heading when simulating a Word-derived source.
			const normalized =
				marker === ''
					? source
					: source.replace(/^1 {2}/m, '# 1  ').replace(/^1\.1 {2}/m, '# 1.1  ');
			const parsed = parseItu(normalized, 'T-REC-X.680-202102-I!!MSW-E', 'X.680');
			const document = {
				...parsed,
				id: 'itu-x680-2021',
				kind: 'itu' as const,
				relativePath: 'fixture.txt',
			};
			const clause = findHeading(document, '1.1.1');
			expect(clause).toMatchObject({ title: '', depth: 3, inlineBody: true });
			expect(
				sectionLines(document, clause)
					.map((line) => line.text)
					.join('\n'),
			).toContain(paragraph);
			expect(parsed.headings.filter((h) => !h.inlineBody).map((h) => h.number)).toEqual([
				'1',
				'1.1',
			]);
		},
	);
});

describe('bounded section reads and extraction diagnostics', () => {
	test('returns a traversable window without losing original source line numbers', () => {
		const lines = Array.from({ length: 2360 }, (_, n) => ({ line: n + 100, text: `fixture ${n}` }));
		const first = readWindow(lines, 0, 20);
		expect(first.selection).toEqual({
			offset: 0,
			totalLines: 2360,
			returnedLines: 20,
			truncated: true,
			nextOffset: 20,
		});
		expect(first.lines[0]?.line).toBe(100);
		expect(readWindow(lines, 20, 20).lines[0]?.line).toBe(120);
		expect(readWindow(lines).selection.truncated).toBe(false);
		expect(readWindow(lines, 2360, 20).selection.nextOffset).toBeNull();
		expect(() => readWindow(lines, 2361)).toThrow();
	});
	test('the actual read command windows the same section, retaining default full reads', async () => {
		const full = await runCommand(readCommand, ['5280', '4.1', '--json']);
		const first = await runCommand(readCommand, ['5280', '4.1', '--json', '--limit', '20']);
		const second = await runCommand(readCommand, [
			'5280',
			'4.1',
			'--json',
			'--offset',
			'20',
			'--limit',
			'20',
		]);
		for (const result of [full, first, second]) expect(result.exitCode).toBe(0);
		const entire = object(JSON.parse(full.stdout.join('')));
		const one = object(JSON.parse(first.stdout.join('')));
		const two = object(JSON.parse(second.stdout.join('')));
		if (!Array.isArray(entire['sourceLines'])) throw new Error('expected source lines');
		expect(one['sourceLines']).toEqual(entire['sourceLines'].slice(0, 20));
		expect(two['sourceLines']).toEqual(entire['sourceLines'].slice(20, 40));
		expect(object(one['selection'])['nextOffset']).toBe(20);
		expect(object(entire['selection'])['truncated']).toBe(false);
	});
	test('flags broken fields and sparse pages without manufacturing text', () => {
		const source =
			'Page\nError: Reference source not found\n\f' +
			'Substantial authored prose. '.repeat(20) +
			'\f';
		const diagnostics = sourceDiagnostics(source, true);
		expect(diagnostics).toContainEqual(
			expect.objectContaining({ code: 'BROKEN_REFERENCE', line: 2 }),
		);
		expect(diagnostics.filter((d) => d.code === 'SPARSE_PDF_PAGE').map((d) => d.page)).toEqual([1]);
		expect(sourceDiagnostics('Error! Bookmark not defined.')[0]?.code).toBe('BROKEN_REFERENCE');
		expect(sourceDiagnostics('No broken field here')).toEqual([]);
	});
});

describe('search context at removed page furniture', () => {
	test.each([true, false])('attaches orphan %s-side context to its real match', (before) => {
		const lines = before
			? [
					{ line: 10, text: 'context', match: false, label: 'doc §1' },
					{ line: 20, text: 'match', match: true, label: 'doc §1' },
				]
			: [
					{ line: 10, text: 'match', match: true, label: 'doc §1' },
					{ line: 20, text: 'context', match: false, label: 'doc §1' },
				];
		const runs = runsOf(lines);
		expect(runs.length).toBe(1);
		expect(runs.flat()).toEqual(lines);
		expect(runs.every((run) => run.some((line) => line.match))).toBe(true);
	});
	test('retains section labels when context and adjacent matches overlap', () => {
		const lines = [
			{ line: 1, text: 'first', match: true, label: 'doc §1' },
			{ line: 10, text: 'context', match: false, label: 'doc §2' },
			{ line: 20, text: 'second', match: true, label: 'doc §2' },
		];
		const runs = runsOf(lines);
		expect(runs.flat()).toEqual(lines);
		expect(runs.map((run) => run.find((line) => line.match)?.label)).toEqual(['doc §1', 'doc §2']);
	});
});

test.skipIf(Bun.which('dprint') === null)(
	'root Errata.md is discovered and formatted by the repository config',
	async () => {
		await scratch(async (root) => {
			await cp(path.join(repositoryRoot, '.dprint.jsonc'), path.join(root, '.dprint.jsonc'));
			await cp(path.join(repositoryRoot, '.gitignore'), path.join(root, '.gitignore'));
			await symlink(
				path.join(repositoryRoot, 'node_modules'),
				path.join(root, 'node_modules'),
				process.platform === 'win32' ? 'junction' : 'dir',
			);
			await writeFile(path.join(root, 'Errata.md'), '# Fixture\n\nThis is   authored test text.\n');
			const executable = Bun.which('dprint');
			if (executable === null) throw new Error('dprint disappeared');
			for (const args of [
				['output-file-paths', 'Errata.md'],
				['fmt', 'Errata.md'],
				['check', 'Errata.md'],
			]) {
				const child = Bun.spawn([executable, ...args], {
					cwd: root,
					stdout: 'pipe',
					stderr: 'pipe',
				});
				const [stdout, stderr, code] = await Promise.all([
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
					child.exited,
				]);
				if (code !== 0) throw new Error(`dprint ${args.join(' ')}: ${code}\n${stderr}`);
				if (args[0] === 'output-file-paths') expect(stdout).toContain('Errata.md');
			}
		});
	},
	120_000,
);
