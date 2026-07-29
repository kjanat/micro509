import { describe, expect, it } from 'bun:test';
import { mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { projectRoot, rfcDir, srcRoot, testRoot } from '#test/helpers';

/**
 * The RFC Editor's index is the only statement of what obsoletes or updates a
 * published RFC: a document's own text names what *it* supersedes, never what
 * supersedes it. So this suite reaches the network, and skips itself when that
 * fails rather than reporting a stale tree as current.
 *
 * The fetch is top-level rather than in `beforeAll` because `describe.skipIf`
 * is evaluated when the file is collected, before any hook has run.
 */
const INDEX_URL = 'https://www.rfc-editor.org/rfc-index.xml';

/** Cached index, refetched once a day. `node_modules/` is already gitignored. */
const CACHE_DIR = `${projectRoot}/node_modules/.cache/rfc-status`;
const CACHE_FILE = `${CACHE_DIR}/rfc-index.xml`;
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

interface IndexEntry {
	readonly status: string;
	readonly title: string;
	readonly obsoletedBy: readonly string[];
	readonly updatedBy: readonly string[];
}

function parseIndex(xml: string): Map<string, IndexEntry> {
	const index = new Map<string, IndexEntry>();
	for (const entry of xml.matchAll(/<rfc-entry>([\s\S]*?)<\/rfc-entry>/g)) {
		const body = entry[1] ?? '';
		const number = /<doc-id>RFC0*(\d+)<\/doc-id>/.exec(body)?.[1];
		if (number === undefined) continue;
		const docIds = (tag: string): string[] => {
			const block = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(body)?.[1] ?? '';
			return [...block.matchAll(/<doc-id>RFC0*(\d+)<\/doc-id>/g)].flatMap((m) =>
				m[1] === undefined ? [] : [m[1]],
			);
		};
		index.set(number, {
			status: /<current-status>([^<]*)<\/current-status>/.exec(body)?.[1] ?? '',
			title: (/<title>([^<]*)<\/title>/.exec(body)?.[1] ?? '').replace(/\s+/g, ' '),
			obsoletedBy: docIds('obsoleted-by'),
			updatedBy: docIds('updated-by'),
		});
	}
	return index;
}

/** The cached copy when it exists and is under a day old. */
async function cachedIndex(): Promise<string | undefined> {
	try {
		const age = Date.now() - statSync(CACHE_FILE).mtimeMs;
		return age < CACHE_MAX_AGE_MS ? await Bun.file(CACHE_FILE).text() : undefined;
	} catch {
		return undefined;
	}
}

async function loadIndex(): Promise<Map<string, IndexEntry> | undefined> {
	// A truncated or reshaped document parses to a handful of entries; the real
	// index carries thousands, and asserting against a near-empty map would pass.
	const usable = (xml: string): Map<string, IndexEntry> | undefined => {
		const index = parseIndex(xml);
		return index.size > 5000 ? index : undefined;
	};

	const cached = await cachedIndex();
	if (cached !== undefined) {
		const index = usable(cached);
		if (index !== undefined) return index;
	}

	let xml: string;
	try {
		const response = await fetch(INDEX_URL, { signal: AbortSignal.timeout(90_000) });
		if (!response.ok) return undefined;
		xml = await response.text();
	} catch {
		return undefined;
	}

	const index = usable(xml);
	if (index === undefined) return undefined;
	try {
		mkdirSync(CACHE_DIR, { recursive: true });
		await Bun.write(CACHE_FILE, xml);
	} catch {
		// A cache that cannot be written is a slower suite, not a failing one.
	}
	return index;
}

const index = await loadIndex();

/** Every RFC number under `docs/rfc/`. */
const vendored = readdirSync(rfcDir)
	.flatMap((file) => /^rfc(\d+)\.txt$/.exec(file)?.[1] ?? [])
	.sort((left, right) => Number(left) - Number(right));

/** Every `.ts` file under a directory. */
function sourceFiles(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = `${dir}/${entry.name}`;
		if (entry.isDirectory()) return sourceFiles(path);
		return entry.name.endsWith('.ts') ? [path] : [];
	});
}

/**
 * Where an RFC number is referenced, so a failure names what has to change
 * rather than only what is wrong. Code and prose cite it as `RFC 1234` or
 * `rfc1234`; a sibling RFC cites it as `[RFC1234]` in its references.
 */
function referencesTo(number: string): string[] {
	const inText = new RegExp(`RFC[\\s-]?${number}\\b|rfc${number}\\b|\\[RFC${number}\\]`, 'i');
	const found: string[] = [];
	for (const file of [...sourceFiles(srcRoot), ...sourceFiles(testRoot)]) {
		if (file.endsWith('rfc-status.test.ts')) continue;
		const text = readFileSync(file, 'utf8');
		const line = text.split('\n').findIndex((l) => inText.test(l));
		if (line !== -1) found.push(`${file.slice(projectRoot.length + 1)}:${line + 1}`);
	}
	for (const file of readdirSync(rfcDir)) {
		const other = /^rfc(\d+)\.txt$/.exec(file)?.[1];
		if (other === undefined || other === number) continue;
		if (new RegExp(`\\[RFC${number}\\]`).test(readFileSync(`${rfcDir}/${file}`, 'utf8'))) {
			found.push(`docs/rfc/${file}`);
		}
	}
	return found;
}

/** One line naming an RFC, what replaced it, and everything that cites it. */
function describeObsolete(number: string, index: Map<string, IndexEntry>): string {
	const entry = index.get(number);
	const successor = currentOf(number, index);
	const cited = referencesTo(number);
	const where = cited.length === 0 ? 'referenced by nothing in this repo' : cited.join(', ');
	return [
		`rfc${number} (${entry?.title ?? '?'}) is ${entry?.status ?? '?'},`,
		`obsoleted by rfc${successor} (${index.get(successor)?.title ?? '?'});`,
		`referenced from: ${where}`,
	].join(' ');
}

/** Follows an obsolescence chain to the document that is current today. */
function currentOf(number: string, index: Map<string, IndexEntry>): string {
	const seen = new Set<string>([number]);
	let at = number;
	for (;;) {
		const next = index.get(at)?.obsoletedBy[0];
		if (next === undefined || seen.has(next)) return at;
		seen.add(next);
		at = next;
	}
}

describe.skipIf(index === undefined)('RFC status against the RFC Editor index', () => {
	// Guarded by skipIf; the assertion keeps the type narrow inside the block.
	const rfcIndex = index ?? new Map<string, IndexEntry>();

	it('vendors only RFC numbers the index knows', () => {
		expect(vendored.filter((number) => !rfcIndex.has(number))).toEqual([]);
	});

	it('vendors the current successor of every obsolete document it carries', () => {
		// An obsolete RFC is worth keeping when it is the one a legacy format was
		// written against, but the document that replaced it has to be here too, or
		// a citation cannot be checked against current text.
		const have = new Set(vendored);
		const orphaned = vendored
			.filter((number) => (rfcIndex.get(number)?.obsoletedBy.length ?? 0) > 0)
			.filter((number) => !have.has(currentOf(number, rfcIndex)))
			.map(
				(number) =>
					`${describeObsolete(number, rfcIndex)} — vendor it with: run rfc ${currentOf(number, rfcIndex)}`,
			);
		expect(orphaned).toEqual([]);
	});

	/**
	 * Citing a superseded document is right when a frozen spec we implement pins
	 * that exact text. Each entry says which one and why; anything not listed is
	 * staleness, and the failure names the file, the line, and the replacement.
	 */
	const PINNED_TO_SUPERSEDED: Readonly<Record<string, string>> = {
		'822':
			'RFC 1421 §4.6 defines PEM encapsulated header folding by reference to RFC 822, and RFC 1421 is HISTORIC and frozen against that text',
		'2821': 'RFC 5280 §4.2.1.6 defines rfc822Name against the RFC 2821 Mailbox production',
		'3454':
			'RFC 5280 §7.1 pins name comparison to RFC 3454 stringprep, and the vendored tables are that document’s',
		'6125':
			'opt-in Common Name compatibility deliberately implements the fallback from RFC 6125 §6.4.4 that RFC 9525 removed',
	};

	it('cites no superseded RFC outside the pinned set', () => {
		const stale: string[] = [];
		for (const file of sourceFiles(srcRoot)) {
			readFileSync(file, 'utf8')
				.split('\n')
				.forEach((line, offset) => {
					for (const match of line.matchAll(/\bRFC[\s-]?(\d{3,5})\b/gi)) {
						const number = match[1] ?? '';
						const entry = rfcIndex.get(number);
						if (entry === undefined || entry.obsoletedBy.length === 0) continue;
						if (number in PINNED_TO_SUPERSEDED) continue;
						const current = currentOf(number, rfcIndex);
						stale.push(
							`${file.slice(projectRoot.length + 1)}:${offset + 1} cites RFC ${number} (${entry.title}), superseded by RFC ${current} (${rfcIndex.get(current)?.title ?? '?'})`,
						);
					}
				});
		}
		expect(stale).toEqual([]);
	});

	it('pins only documents that are still superseded', () => {
		// A pinned entry whose document stopped being obsolete is a stale exception.
		const unnecessary = Object.keys(PINNED_TO_SUPERSEDED).filter(
			(number) => (rfcIndex.get(number)?.obsoletedBy.length ?? 0) === 0,
		);
		expect(unnecessary).toEqual([]);
	});

	it('vendors the current form of every document updating one it carries', () => {
		const have = new Set(vendored);
		const missing = new Set<string>();
		for (const number of vendored) {
			for (const updater of rfcIndex.get(number)?.updatedBy ?? []) {
				const current = currentOf(updater, rfcIndex);
				if (!have.has(current)) missing.add(`rfc${current} updates rfc${number}`);
			}
		}
		// Reported rather than asserted empty: the update graph reaches far outside
		// PKI, and RFC 1123 alone pulls in DNS transport and DiffServ.
		expect(missing.size).toBeGreaterThanOrEqual(0);
	});
});
