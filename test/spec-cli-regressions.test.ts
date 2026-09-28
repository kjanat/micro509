import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { command } from 'dreamcli';
import { runCommand } from 'dreamcli/testkit';
import { decide } from '../.claude/hooks/spec-lookup-gate.ts';
import { discover, repositoryRoot, resolveReference } from '../scripts/spec/corpus.ts';
import { reportFetched } from '../scripts/spec/fetch-result.ts';
import { isRecord } from '../scripts/spec/resource.ts';

function verdict(command: string, agent?: string): string {
	return decide({ tool: 'Bash', agent, cwd: repositoryRoot, input: { command } }, repositoryRoot)
		.kind;
}

describe('reader command boundaries', () => {
	test.each(['read', 'search', 'headings', 'census'])(
		'keeps %s as a status option value, not a subcommand',
		(value) => {
			for (const prefix of [
				'bun spec',
				'bun spec --json',
				'nice -n 5 bun run spec --quiet',
				'npx tsx scripts/spec/main.ts',
				'bunx --bun tsx scripts/spec/main.ts',
				'npm exec -- tsx scripts/spec/main.ts --json',
			]) {
				for (const option of [`--cache-dir ${value}`, `--cache-dir=${value}`]) {
					expect(verdict(`${prefix} status 5280 --offline ${option}`)).toBe('pass');
				}
			}
		},
	);

	test.each([
		'bun spec read rfc5280 4.1',
		'bun spec --json --quiet=false read rfc5280 4.1',
		'bun spec -- read rfc5280 4.1',
		'bun --cwd . run spec --json census REAL NR3',
		'node --import tsx scripts/spec/main.ts --json headings rfc5280',
		'deno run -A scripts/spec/main.ts search nextUpdate',
		'npx tsx scripts/spec/main.ts read rfc5280 4.1',
		'npx --yes --package tsx tsx scripts/spec/main.ts read rfc5280 4.1',
		'npx -p tsx -- tsx scripts/spec/main.ts --json read rfc5280 4.1',
		'npx --package=tsx -- tsx scripts/spec/main.ts headings rfc5280',
		'npx tsx@4 scripts/spec/main.ts read rfc5280 4.1',
		'bunx tsx scripts/spec/main.ts read rfc5280 4.1',
		'bunx --bun tsx scripts/spec/main.ts read rfc5280 4.1',
		'bunx -p tsx --bun tsx scripts/spec/main.ts read rfc5280 4.1',
		'bun x --bun tsx scripts/spec/main.ts read rfc5280 4.1',
		'bun --cwd . x --bun tsx scripts/spec/main.ts read rfc5280 4.1',
		'npm exec -- tsx scripts/spec/main.ts read rfc5280 4.1',
		'npm x -- tsx scripts/spec/main.ts --json census REAL NR3',
		'npm --workspace fixture exec --package tsx -- tsx scripts/spec/main.ts read rfc5280 4.1',
		'npm exec --package=tsx -- tsx scripts/spec/main.ts read rfc5280 4.1',
		'nice -n 5 env -u UNUSED npx --yes tsx scripts/spec/main.ts read ms-wcce-20260824 3.1',
		'/usr/bin/npx --package tsx /usr/bin/tsx scripts/spec/main.ts read rfc5280 4.1',
	])('delegates the actual reader: %s', (invocation) => {
		expect(verdict(invocation)).toBe('deny');
		expect(verdict(invocation, 'spec-lookup')).toBe('pass');
	});

	test.each([
		'echo npx tsx scripts/spec/main.ts read rfc5280 4.1',
		'npx echo scripts/spec/main.ts read rfc5280 4.1',
		'bunx echo scripts/spec/main.ts read rfc5280 4.1',
		'npm exec -- echo scripts/spec/main.ts read rfc5280 4.1',
		'npm install tsx scripts/spec/main.ts read',
		'npm view tsx scripts/spec/main.ts read',
		'npm exec --package scripts/spec/main.ts -- echo read',
		'npx --package scripts/spec/main.ts echo read',
		'node --require scripts/spec/main.ts other.ts read',
		'bun --cwd spec run other read',
		'bun other.ts spec read rfc5280 4.1',
		'node -e "console.log(1)" scripts/spec/main.ts read rfc5280 4.1',
		'npx --call "echo reader" tsx scripts/spec/main.ts read rfc5280 4.1',
		'bun spec status read',
		'bun spec list read',
		'bun spec fetch ms read',
	])('does not mistake operands or non-execution for a reader: %s', (invocation) => {
		expect(verdict(invocation)).toBe('pass');
	});
});

const fetchCases = [
	['rfc', 'rfc/rfc5280.txt', 'rfc5280'],
	['w3c', 'w3c/WebIDL/webidl.txt', 'w3c-webidl'],
	['w3c', 'w3c/WebCryptoAPI/w3c-webcrypto-editors-draft.txt', 'w3c-webcrypto-editors-draft'],
	['w3c', 'w3c/WebCryptoAPI/W3C-TR-webcrypto-current.txt', 'w3c-webcrypto-tr-current'],
	['w3c', 'w3c/WebCryptoAPI/W3C-REC-WebCryptoAPI-20170126.txt', 'w3c-webcrypto-rec-2017'],
	['itu', 'itu/X.509/T-REC-X.509-201910-I!!PDF-E.txt', 'itu-x509-2019'],
	['itu', 'itu/X.509/T-REC-X.509-201910-I!!MSW-E.txt', 'itu-x509-2019'],
	['itu', 'itu/X.509/T-REC-X.509-202310-I!Cor2!MSW-E.txt', 'itu-x509-2023-cor2'],
	['ms', 'ms/MS-FIXTURE/MS-FIXTURE-v20260928.txt', 'ms-fixture-20260928'],
] as const;

async function withCorpus(action: (root: string) => Promise<void>): Promise<void> {
	const root = await mkdtemp(path.join(tmpdir(), 'spec-fetch-id-'));
	try {
		await action(root);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}

async function written(root: string, relative: string): Promise<string> {
	const destination = path.join(root, 'docs', relative);
	await mkdir(path.dirname(destination), { recursive: true });
	// Discovery depends on filenames, not proprietary source text or live HTTP.
	await writeFile(destination, 'Synthetic identifier fixture.\n');
	return destination;
}

async function reported(root: string, destination: string) {
	const cmd = command('report').action(({ out }) => {
		reportFetched(out, destination, 'https://example.test/source', root);
	});
	const result = await runCommand(cmd, ['--json']);
	expect(result.exitCode).toBe(0);
	const value: unknown = JSON.parse(result.stdout.join(''));
	if (!isRecord(value)) throw new Error('expected fetch result object');
	return value;
}

describe('fetch identifiers round-trip through corpus discovery', () => {
	test.each(fetchCases)('%s %s resolves as %s', async (kind, relative, id) => {
		await withCorpus(async (root) => {
			const destination = await written(root, relative);
			const result = await reported(root, destination);
			expect(result).toEqual({
				kind,
				id,
				path: `docs/${relative}`,
				url: 'https://example.test/source',
			});
			const reportedId = result['id'];
			if (typeof reportedId !== 'string') throw new Error('expected fetch id');
			expect(resolveReference(discover(root), reportedId).path).toBe(destination);
		});
	});

	test('uses discovery collision suffixes rather than recomputing a near-identical id', async () => {
		await withCorpus(async (root) => {
			await written(root, 'w3c/A/webidl.txt');
			const destination = await written(root, 'w3c/B/webidl.txt');
			const result = await reported(root, destination);
			expect(result['id']).toBe('w3c-webidl-2');
			expect(resolveReference(discover(root), 'w3c-webidl-2').path).toBe(destination);
		});
	});

	test('keeps human output as a repository-relative path', async () => {
		await withCorpus(async (root) => {
			const destination = await written(root, 'w3c/WebIDL/webidl.txt');
			const cmd = command('report').action(({ out }) =>
				reportFetched(out, destination, 'https://example.test/source', root),
			);
			const result = await runCommand(cmd, []);
			expect(result.exitCode).toBe(0);
			expect(result.stdout.join('').trim()).toBe('docs/w3c/WebIDL/webidl.txt');
		});
	});

	test('does not report an invented id for an unindexed destination', async () => {
		await withCorpus(async (root) => {
			const destination = await written(root, 'not-indexed.txt');
			const cmd = command('report').action(({ out }) =>
				reportFetched(out, destination, 'https://example.test/source', root),
			);
			const result = await runCommand(cmd, ['--json']);
			expect(result.error?.code).toBe('SPEC_FETCH_UNINDEXED');
		});
	});
});
