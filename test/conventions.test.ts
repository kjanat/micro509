import { Glob } from 'bun';
import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';

/**
 * Guards the structural rules from AGENTS.md / CONTRIBUTING.md that neither
 * tsc nor biome enforce — so a banned construct can't be merged again (a class
 * and a default export both slipped through before this gate existed).
 */

const srcDir = new URL('../src/', import.meta.url).pathname;

function sourceFiles(): readonly string[] {
	return [...new Glob('**/*.ts').scanSync({ cwd: srcDir, absolute: true })];
}

function offendersMatching(pattern: RegExp): readonly string[] {
	const offenders: string[] = [];
	for (const file of sourceFiles()) {
		if (pattern.test(readFileSync(file, 'utf8'))) {
			offenders.push(file.slice(srcDir.length));
		}
	}
	return offenders;
}

describe('repo conventions (AGENTS.md / CONTRIBUTING.md)', () => {
	it('src/ declares no classes', () => {
		// Line must begin (after indentation, optional `export`/`abstract`) with `class`.
		expect(offendersMatching(/^[ \t]*(?:export[ \t]+)?(?:abstract[ \t]+)?class[ \t]/m)).toEqual([]);
	});

	it('src/ has no default exports', () => {
		expect(offendersMatching(/^[ \t]*export[ \t]+default\b/m)).toEqual([]);
	});
});
