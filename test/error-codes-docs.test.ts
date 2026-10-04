import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createTscBridge } from '@kjanat/tsc-bridge';
import { Glob } from 'bun';
import { projectRoot } from '#test/helpers';

const ENTRYPOINTS = [...new Glob('src/*.ts').scanSync({ cwd: projectRoot })];

async function exportedCodeUnions(): Promise<ReadonlyMap<string, ReadonlySet<string>>> {
	const bridge = createTscBridge({ cwd: projectRoot });
	try {
		const unions = await bridge.exportedCodeUnions('tsconfig.src.json', ENTRYPOINTS);
		return new Map(unions.map(({ name, codes }) => [name, new Set(codes)]));
	} finally {
		await bridge.close();
	}
}

const unions = await exportedCodeUnions();

function codesOnLine(line: string): readonly string[] {
	const row = line.match(/^\| `([a-z][a-z0-9_]+)`/);
	if (row?.[1] !== undefined) return [row[1]];
	if (!/^(?:`[a-z][a-z0-9_]+`,?\s*)+$/.test(line.trim())) return [];
	return [...line.matchAll(/`([a-z][a-z0-9_]+)`/g)].flatMap((token) =>
		token[1] === undefined ? [] : [token[1]],
	);
}

function documentedSections(markdown: string): ReadonlyMap<string, ReadonlySet<string>> {
	const sections = new Map<string, ReadonlySet<string>>();
	const headings = [...markdown.matchAll(/^### (\w+)$/gm)];
	for (const [index, heading] of headings.entries()) {
		const name = heading[1];
		if (name === undefined) continue;
		const start = heading.index ?? 0;
		const end = headings[index + 1]?.index ?? markdown.length;
		const body = markdown.slice(start, end);
		sections.set(name, new Set(body.split('\n').flatMap(codesOnLine)));
	}
	return sections;
}

describe('error-code reference page', () => {
	const markdown = readFileSync(path.join(projectRoot, 'site/reference/errors.md'), 'utf8');
	const sections = documentedSections(markdown);

	it('documents every exported error-code union', () => {
		const missing = [...unions.keys()].filter((name) => !sections.has(name));
		expect(missing).toEqual([]);
	});

	it('documents no union that is not exported', () => {
		const stale = [...sections.keys()].filter((name) => !unions.has(name));
		expect(stale).toEqual([]);
	});

	for (const [name, codes] of unions) {
		it(`section ${name} lists exactly its codes`, () => {
			const documented = sections.get(name) ?? new Set<string>();
			const missing = [...codes].filter((code) => !documented.has(code));
			const extra = [...documented].filter((code) => !codes.has(code));
			expect({ missing, extra }).toEqual({ missing: [], extra: [] });
		});
	}
});
