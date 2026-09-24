import { describe, expect, test } from 'bun:test';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { runCommand } from 'dreamcli/testkit';
import { projectRoot, rfcDir } from '#test/helpers';
import { headingsCommand, listCommand, readCommand, searchCommand } from '../scripts/spec/main.ts';

type Entry = Readonly<Record<string, unknown>>;

function isEntry(value: unknown): value is Entry {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function entry(value: unknown): Entry {
	if (!isEntry(value)) throw new Error('expected an object payload');
	return value;
}

function list(value: unknown): readonly unknown[] {
	if (!Array.isArray(value)) throw new Error('expected an array payload');
	const values: unknown[] = value;
	return values;
}

function text(value: unknown): string {
	if (typeof value !== 'string') throw new Error(`expected a string, got ${typeof value}`);
	return value;
}

function count(value: unknown): number {
	if (typeof value !== 'number') throw new Error(`expected a number, got ${typeof value}`);
	return value;
}

function numbers(value: unknown): readonly number[] {
	return list(value).map(count);
}

function entries(value: unknown): readonly Entry[] {
	return list(value).map(entry);
}

function payloadOf(stdout: readonly string[]): Entry {
	return entry(JSON.parse(stdout.join('')));
}

async function documents(): Promise<readonly Entry[]> {
	const result = await runCommand(listCommand, ['--json']);
	expect(result.exitCode).toBe(0);
	return entries(payloadOf(result.stdout).documents);
}

function document(all: readonly Entry[], id: string): Entry {
	const found = all.find((candidate) => candidate.id === id);
	if (found === undefined) throw new Error(`no document listed with id ${id}`);
	return found;
}

async function headingsOf(argv: readonly string[]): Promise<readonly Entry[]> {
	const result = await runCommand(headingsCommand, [...argv, '--json']);
	expect(result.exitCode).toBe(0);
	return entries(payloadOf(result.stdout).headings);
}

async function hitsOf(argv: readonly string[]): Promise<readonly Entry[]> {
	const result = await runCommand(searchCommand, [...argv, '--json']);
	expect(result.exitCode).toBe(0);
	return entries(payloadOf(result.stdout).matches);
}

function sectionNumbers(hits: readonly Entry[], doc: string): readonly string[] {
	return hits
		.filter((hit) => hit.doc === doc)
		.map((hit) => (hit.section === null ? '' : text(entry(hit.section).number)));
}

const ituPresent = existsSync(path.join(projectRoot, 'docs', 'itu'));
const rfc5280Lines = readFileSync(path.join(rfcDir, 'rfc5280.txt'), 'utf8').split('\n');

describe('spec list', () => {
	test('describes rfc5280 with its title, date, and obsoletes header', async () => {
		const rfc5280 = document(await documents(), 'rfc5280');
		expect(text(rfc5280.title)).toBe(
			'Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile',
		);
		expect(text(rfc5280.date)).toBe('May 2008');
		expect(text(rfc5280.category)).toBe('Standards Track');
		expect(numbers(rfc5280.obsoletes)).toEqual([3280, 4325, 4630]);
		expect(numbers(rfc5280.updates)).toEqual([]);
		expect(text(rfc5280.path)).toBe('docs/rfc/rfc5280.txt');
	});

	test('derives updated-by and obsoleted-by from the other vendored headers', async () => {
		const all = await documents();
		expect(numbers(document(all, 'rfc5280').updatedBy)).toContain(6818);
		expect(numbers(document(all, 'rfc5280').updatedBy)).toContain(9608);
		expect(numbers(document(all, 'rfc3447').obsoletedBy)).toContain(8017);
	});

	test('reads the Updates header of an updating RFC', async () => {
		const rfc9608 = document(await documents(), 'rfc9608');
		expect(numbers(rfc9608.updates)).toEqual([5280]);
		expect(text(rfc9608.date)).toBe('June 2024');
	});

	test('includes the NIST PKITS document', async () => {
		const pkits = document(await documents(), 'pkits');
		expect(text(pkits.kind)).toBe('pkits');
		expect(text(pkits.path)).toBe('docs/rfc/pkits.txt');
		expect(text(pkits.title)).toContain('Public Key Interoperability Test Suite');
	});

	test('includes the W3C WebCrypto variants', async () => {
		const ids = (await documents())
			.filter((candidate) => candidate.kind === 'w3c')
			.map((candidate) => text(candidate.id));
		expect(ids).toContain('w3c-webcrypto-rec-2017');
		expect(ids.length).toBeGreaterThanOrEqual(3);
	});

	test.skipIf(!ituPresent)('includes the ITU-T X.509 editions and corrigenda', async () => {
		const ids = (await documents())
			.filter((candidate) => candidate.kind === 'itu')
			.map((candidate) => text(candidate.id));
		expect(ids).toContain('itu-x509-2019');
		expect(ids).toContain('itu-x509-2023-cor2');
	});

	test('renders a human table without --json', async () => {
		const result = await runCommand(listCommand, []);
		expect(result.exitCode).toBe(0);
		expect(result.stdout.join('')).toContain('rfc5280');
	});
});

describe('spec headings', () => {
	test('lists rfc5280 subsections down to the requested depth', async () => {
		const headings = await headingsOf(['rfc5280', '--depth', '4']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '5.1.2.5', title: 'Next Update' }),
		);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '6.1.3', title: 'Basic Certificate Processing' }),
		);
	});

	test('honours the default depth of two', async () => {
		const headings = await headingsOf(['rfc5280']);
		expect(headings.every((heading) => count(heading.depth) <= 2)).toBe(true);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '5.1', title: 'CRL Fields' }),
		);
	});

	test('reports heading line numbers that index the original file', async () => {
		const headings = await headingsOf(['rfc5280', '--depth', '4']);
		const nextUpdate = headings.find((heading) => heading.number === '5.1.2.5');
		expect(nextUpdate).toBeDefined();
		expect(rfc5280Lines[count(entry(nextUpdate).line) - 1]).toBe('5.1.2.5.  Next Update');
	});

	test('lists PKITS sections', async () => {
		const headings = await headingsOf(['pkits', '--depth', '2']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '4.4', title: 'Basic Certificate Revocation Tests' }),
		);
	});

	test('lists PKITS sections whose titles start in lowercase', async () => {
		const headings = await headingsOf(['pkits', '--depth', '4']);
		const numbers = headings.map((heading) => text(heading.number));
		expect(numbers).toContain('6.1.5.205');
		expect(new Set(numbers).size).toBe(numbers.length);
	});

	test('lists W3C sections', async () => {
		const headings = await headingsOf(['w3c-webcrypto-rec-2017']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '14', title: 'SubtleCrypto interface' }),
		);
	});

	test('keeps numbered sections that follow the appendices', async () => {
		expect(await headingsOf(['rfc5322', '--depth', '2'])).toContainEqual(
			expect.objectContaining({ number: '7.1', title: 'Normative References' }),
		);
	});

	test('does not let a lettered table row swallow the rest of the outline', async () => {
		const numbers = (await headingsOf(['rfc2156', '--depth', '4'])).map((heading) =>
			text(heading.number),
		);
		expect(numbers).toContain('5.3.9');
		expect(numbers).toContain('L');
		expect(numbers).not.toContain('X.4.4');
		expect(numbers).not.toContain('X.4.5');
	});

	test('lists unnumbered margin titles in a document with no numbered margin headings', async () => {
		const titles = (await headingsOf(['rfc934'])).map((heading) => text(heading.title));
		expect(titles).toContain('Introduction, Scope, and Motivation');
		expect(titles).toContain('Blind Carbon Copies');
		expect(titles.filter((title) => title === 'Message Encapsulation')).toHaveLength(1);
	});

	test('lists indented appendix-local sections', async () => {
		const titles = (await headingsOf(['rfc2156', '--depth', '3'])).map((heading) =>
			text(heading.title),
		);
		expect(titles).toContain('Probes');
		expect(await headingsOf(['rfc2156', '--depth', '2'])).toContainEqual(
			expect.objectContaining({ number: '1', title: 'Probes', depth: 2 }),
		);
		expect(titles).toContain('SMTP Extension mapping to X.400');
	});

	test('keeps list items and references out of appendix-local numbering', async () => {
		const titles = (await headingsOf(['rfc2156', '--depth', '2'])).map((heading) =>
			text(heading.title),
		);
		expect(titles).toContain('Syntax Definitions');
		expect(titles).toContain('Table Lookups');
		expect(titles.some((title) => title.startsWith('CCITT'))).toBe(false);
		expect(titles.some((title) => title.startsWith('OR Address Space'))).toBe(false);
	});

	test('nests numbered sections under an unnumbered title', async () => {
		expect(await headingsOf(['rfc934', '--depth', '3'])).toContainEqual(
			expect.objectContaining({ number: '1', title: 'The Header Portion', depth: 2 }),
		);
	});

	test('lists a colon-terminated notes heading', async () => {
		expect((await headingsOf(['rfc1421'])).map((heading) => text(heading.title))).toContain(
			'NOTES',
		);
	});

	test('cuts a heading fused with its first paragraph back to its contents entry', async () => {
		expect(await headingsOf(['rfc2985'])).toContainEqual(
			expect.objectContaining({ number: 'B', title: 'BNF schema summary' }),
		);
	});

	test('lists chapter headings', async () => {
		expect(await headingsOf(['rfc2156'])).toContainEqual(
			expect.objectContaining({ number: '1', title: 'Overview' }),
		);
	});

	test('does not append body text to a list-style heading', async () => {
		expect(await headingsOf(['rfc2119'])).toContainEqual(
			expect.objectContaining({ number: '1', title: expect.stringMatching(/^MUST\s/) }),
		);
		const rfc2119Lines = readFileSync(path.join(rfcDir, 'rfc2119.txt'), 'utf8').split('\n');
		for (const heading of await headingsOf(['rfc2119'])) {
			const source = rfc2119Lines[count(heading.line) - 1] ?? '';
			expect(source.replace(/\s+/g, ' ')).toContain(text(heading.title));
		}
	});

	test('accepts weak headings whose titles start with punctuation', async () => {
		expect((await headingsOf(['rfc822', '--depth', '2'])).map((h) => text(h.number))).toContain(
			'2.7',
		);
		expect((await headingsOf(['rfc2821', '--depth', '2'])).map((h) => text(h.number))).toContain(
			'F.6',
		);
	});

	test('lists periodless numbered headings', async () => {
		const headings = await headingsOf(['rfc3279', '--depth', '3']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '2.1', title: 'One-way Hash Functions' }),
		);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '2.2.3', title: 'ECDSA Signature Algorithm' }),
		);
	});

	test('lists indented headings when the document has none at the margin', async () => {
		const headings = await headingsOf(['rfc822', '--depth', '3']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '1', title: 'INTRODUCTION' }),
		);
		expect(headings).toContainEqual(expect.objectContaining({ number: '1.1', title: 'SCOPE' }));
		expect(headings).toContainEqual(expect.objectContaining({ number: 'A.1', title: 'ADDRESSES' }));
	});

	test('lists indented subsections below margin-level sections', async () => {
		const headings = await headingsOf(['rfc1123', '--depth', '2']);
		expect(headings).toContainEqual(
			expect.objectContaining({ number: '1.1', title: 'The Internet Architecture' }),
		);
	});

	test('lists nested and colon-delimited appendix headings', async () => {
		expect(await headingsOf(['rfc5322', '--depth', '2'])).toContainEqual(
			expect.objectContaining({ number: 'A.1', title: 'Addressing Examples' }),
		);
		expect(await headingsOf(['rfc3274'])).toContainEqual(
			expect.objectContaining({ number: 'A', title: 'ASN.1 Module' }),
		);
	});

	test('skips numbered list items that break the outline', async () => {
		const headings = await headingsOf(['rfc1123', '--depth', '1']);
		const numbers = headings
			.map((heading) => text(heading.number))
			.filter((number) => /^\d+$/.test(number));
		expect(numbers).toEqual([...numbers].sort((left, right) => Number(left) - Number(right)));
		expect(new Set(numbers).size).toBe(numbers.length);
	});

	test('joins a heading title that wraps onto the next line', async () => {
		const headings = await headingsOf(['rfc5322', '--depth', '3']);
		expect(headings).toContainEqual(
			expect.objectContaining({
				number: 'A.1.1',
				title: 'A Message from One Person to Another with Simple Addressing',
			}),
		);
	});

	test.skipIf(!ituPresent)('lists ITU-T clause numbers', async () => {
		const headings = await headingsOf(['itu-x509-2019']);
		expect(headings.map((heading) => heading.number)).toContain('12');
	});
});

describe('spec read', () => {
	test('returns the whole section body', async () => {
		const result = await runCommand(readCommand, ['rfc5280', '5.1.2.5']);
		expect(result.exitCode).toBe(0);
		const body = result.stdout.join('');
		expect(body).toContain('Conforming CRL issuers MUST include the nextUpdate field');
		expect(body).toContain('The behavior of clients processing CRLs that omit nextUpdate');
	});

	test('stops before the next sibling heading', async () => {
		const result = await runCommand(readCommand, ['rfc5280', '5.1.2.5']);
		expect(result.stdout.join('')).not.toContain('Revoked Certificates');
	});

	test('never emits page headers or footers', async () => {
		const result = await runCommand(readCommand, ['rfc5280', '6.1.3']);
		expect(result.exitCode).toBe(0);
		for (const line of result.stdout.join('').split('\n')) {
			expect(line).not.toMatch(/\[Page \d+\]/);
			expect(line).not.toMatch(/^RFC 5280 /);
		}
	});

	test('accepts a bare RFC number', async () => {
		const result = await runCommand(readCommand, ['9608', '4']);
		expect(result.exitCode).toBe(0);
		expect(result.stdout.join('')).toContain('Step (a)(3) is skipped');
	});

	test('accepts a heading-text match', async () => {
		const result = await runCommand(readCommand, ['rfc5280', 'Next Update', '--json']);
		expect(result.exitCode).toBe(0);
		expect(text(entry(payloadOf(result.stdout).section).number)).toBe('5.1.2.5');
	});

	test('de-wraps prose by default and preserves the source lines with --raw', async () => {
		const wrappedLine = '   Conforming CRL issuers MUST include the nextUpdate field in all CRLs.';
		const dewrapped = await runCommand(readCommand, ['rfc5280', '5.1.2.5']);
		const raw = await runCommand(readCommand, ['rfc5280', '5.1.2.5', '--raw']);
		expect(raw.exitCode).toBe(0);
		expect(raw.stdout.join('')).toContain(`${wrappedLine}\n`);
		expect(dewrapped.stdout.join('')).not.toContain(wrappedLine);
		expect(dewrapped.stdout.join('')).toContain(
			'Conforming CRL issuers MUST include the nextUpdate field in all CRLs.  Note that',
		);
	});
});

describe('spec search', () => {
	test('finds nextUpdate in rfc5280 and rfc6960 with their enclosing sections', async () => {
		const hits = await hitsOf(['nextUpdate']);
		expect(sectionNumbers(hits, 'rfc5280')).toContain('5.1.2.5');
		expect(sectionNumbers(hits, 'rfc6960')).toContain('4.2.2.1');
	});

	test('reports line numbers that index the original file', async () => {
		const hits = await hitsOf(['nextUpdate', '--doc', 'rfc5280']);
		expect(hits.length).toBeGreaterThan(0);
		for (const hit of hits) expect(rfc5280Lines[count(hit.line) - 1]).toContain('nextUpdate');
	});

	test('returns surrounding context lines', async () => {
		const hits = await hitsOf([
			'Conforming CRL issuers MUST include the nextUpdate',
			'--doc',
			'rfc5280',
			'--context',
			'2',
		]);
		expect(hits.length).toBe(1);
		const hit = entry(hits[0]);
		expect(list(hit.before).length).toBe(2);
		expect(
			entries(hit.after)
				.map((line) => text(line.text))
				.join(' '),
		).toContain('OPTIONAL');
	});

	test('is case sensitive unless -i is given', async () => {
		expect((await hitsOf(['NEXTUPDATE', '--doc', 'rfc5280'])).length).toBe(0);
		expect((await hitsOf(['NEXTUPDATE', '--doc', 'rfc5280', '-i'])).length).toBeGreaterThan(0);
	});

	test('reports truncation when one document holds more matches than the limit', async () => {
		const result = await runCommand(searchCommand, [
			'nextUpdate',
			'--doc',
			'rfc5280',
			'--limit',
			'1',
			'--json',
		]);
		const payload = payloadOf(result.stdout);
		expect(entries(payload.matches).length).toBe(1);
		expect(payload.truncated).toBe(true);
	});

	test('does not report truncation when the limit equals the match count', async () => {
		const all = await hitsOf(['nextUpdate']);
		const result = await runCommand(searchCommand, [
			'nextUpdate',
			'--limit',
			String(all.length),
			'--json',
		]);
		const payload = payloadOf(result.stdout);
		expect(entries(payload.matches).length).toBe(all.length);
		expect(payload.truncated).toBe(false);
	});

	test('labels every rendered match with its own enclosing section', async () => {
		const argv = ['thisUpdate|nextUpdate', '--doc', 'rfc5280', '--context', '25'];
		const sections = new Map(
			(await hitsOf(argv)).map((hit) => [
				count(hit.line),
				hit.section === null ? '' : text(entry(hit.section).number),
			]),
		);
		const result = await runCommand(searchCommand, argv);
		let label = '';
		let checked = 0;
		for (const line of result.stdout.join('').split('\n')) {
			const match = /^\s*(\d+):/.exec(line);
			if (match?.[1] !== undefined) {
				expect(label).toStartWith(`rfc5280 §${sections.get(Number(match[1])) ?? ''}  `);
				checked += 1;
			} else if (/^rfc5280/.test(line)) {
				label = line;
			}
		}
		expect(checked).toBe(sections.size);
	});

	test('never returns a page header or footer line', async () => {
		const hits = await hitsOf(['Standards Track', '--doc', 'rfc5280']);
		for (const hit of hits) expect(text(hit.text)).not.toMatch(/\[Page \d+\]/);
	});
});

describe('spec errors', () => {
	test('rejects an unknown document id', async () => {
		const result = await runCommand(headingsCommand, ['rfc99999']);
		expect(result.exitCode).not.toBe(0);
		expect(result.error?.code).toBe('SPEC_DOC_UNKNOWN');
	});

	test('rejects an unknown section', async () => {
		const result = await runCommand(readCommand, ['rfc5280', '99.4.2']);
		expect(result.exitCode).not.toBe(0);
		expect(result.error?.code).toBe('SPEC_SECTION_UNKNOWN');
	});

	test('rejects an invalid search pattern', async () => {
		const result = await runCommand(searchCommand, ['nextUpdate(', '--doc', 'rfc5280']);
		expect(result.exitCode).not.toBe(0);
		expect(result.error?.code).toBe('SPEC_PATTERN_INVALID');
	});
});
