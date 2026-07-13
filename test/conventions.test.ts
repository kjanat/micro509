import { describe, expect, it } from 'bun:test';
import { Glob } from 'bun';
import { VERIFY_ERROR_CODES } from '#micro509/verify';
import { projectRoot, srcRoot } from '#test/helpers';

function sourceFiles(): readonly string[] {
	return [...new Glob('**/*.ts').scanSync({ cwd: srcRoot, absolute: true })];
}

/**
 * Names a module actually exports: `export function`/`export const`
 * declarations plus `export { … }` list entries (honoring `as` renames) — so
 * a name mentioned only in a comment never counts, and list-only re-exports
 * are not missed.
 */
function exportedNames(source: string): ReadonlySet<string> {
	const names = new Set<string>();
	for (const match of source.matchAll(/^export (?:async )?(?:function|const) (\w+)/gm)) {
		if (match[1] !== undefined) names.add(match[1]);
	}
	for (const block of source.matchAll(/^export (?:type )?\{([^}]*)\}/gm)) {
		const body = block[1];
		if (body === undefined) continue;
		for (const entry of body.split(',')) {
			const token = entry.trim();
			if (token.length === 0) continue;
			const renamed = /(?:^|\s)as\s+(\w+)$/.exec(token);
			const name = renamed?.[1] ?? /^(?:type\s+)?(\w+)/.exec(token)?.[1];
			if (name !== undefined) names.add(name);
		}
	}
	return names;
}

async function offendersMatching(pattern: RegExp): Promise<readonly string[]> {
	const offenders: string[] = [];
	for (const file of sourceFiles()) {
		if (pattern.test(await Bun.file(file).text())) {
			offenders.push(file.slice(srcRoot.length));
		}
	}
	return offenders;
}

async function orThrowExportsByDomain(): Promise<ReadonlyMap<string, ReadonlySet<string>>> {
	const orThrowByDomain = new Map<string, Set<string>>();
	for (const file of sourceFiles()) {
		const relative = file.slice(srcRoot.length + 1);
		if (relative.startsWith('internal/') || relative.endsWith('index.ts')) continue;
		const domain = relative.split('/')[0];
		if (domain === undefined || !relative.includes('/')) continue;
		const names = orThrowByDomain.get(domain) ?? new Set<string>();
		for (const name of exportedNames(await Bun.file(file).text())) {
			if (name.endsWith('OrThrow')) names.add(name);
		}
		orThrowByDomain.set(domain, names);
	}
	return orThrowByDomain;
}

async function missingOrThrowExports(
	barrel: string,
	names: Iterable<string>,
): Promise<readonly string[]> {
	const exported = exportedNames(await Bun.file(`${srcRoot}/${barrel}`).text());
	const offenders: string[] = [];
	for (const orThrowName of names) {
		const baseName = orThrowName.slice(0, -'OrThrow'.length);
		if (exported.has(baseName) && !exported.has(orThrowName)) {
			offenders.push(`${barrel}: ${orThrowName}`);
		}
	}
	return offenders;
}

describe('repo conventions (AGENTS.md / CONTRIBUTING.md)', () => {
	it('src/ declares no classes', async () => {
		// Line must begin (after indentation, optional `export`/`abstract`) with `class`.
		expect(
			await offendersMatching(/^[ \t]*(?:export[ \t]+)?(?:abstract[ \t]+)?class[ \t]/m),
		).toEqual([]);
	});

	it('src/ has no default exports', async () => {
		expect(await offendersMatching(/^[ \t]*export[ \t]+default\b/m)).toEqual([]);
	});

	it('barrels re-export the OrThrow sibling of every function they expose', async () => {
		// If a module defines `fooOrThrow` and a barrel re-exports `foo`, the barrel
		// must re-export `fooOrThrow` too — otherwise the throwing variant is
		// implemented and documented but unreachable from the published package.
		const orThrowByDomain = await orThrowExportsByDomain();
		const offenders: string[] = [];
		const allOrThrow = new Set<string>();
		for (const [domain, names] of orThrowByDomain) {
			if (names.size === 0) continue;
			offenders.push(...(await missingOrThrowExports(`${domain}/index.ts`, names)));
			for (const name of names) allOrThrow.add(name);
		}
		offenders.push(...(await missingOrThrowExports('index.ts', allOrThrow)));

		expect(offenders).toEqual([]);
	});

	it('site error-code table matches VERIFY_ERROR_CODES exactly', async () => {
		const guide = await Bun.file(`${projectRoot}/site/guide/verification.md`).text();
		// First backtick-wrapped snake_case token of each table row
		const documented = [...guide.matchAll(/^\| `([a-z0-9_]+)`/gm)].map((m) => m[1]);
		expect([...documented].sort()).toEqual([...VERIFY_ERROR_CODES].sort());
	});
});
