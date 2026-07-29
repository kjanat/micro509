import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { projectRoot } from '#test/helpers';

const ENTRYPOINTS = [
	'src/index.ts',
	'src/crypto/index.ts',
	'src/der/index.ts',
	'src/keys/index.ts',
	'src/pem/index.ts',
	'src/pkcs/index.ts',
	'src/result/index.ts',
	'src/revocation/index.ts',
	'src/verify/index.ts',
	'src/x509/index.ts',
];

function exportedCodeUnions(): ReadonlyMap<string, ReadonlySet<string>> {
	const configPath = path.join(projectRoot, 'tsconfig.src.json');
	const config = ts.parseJsonConfigFileContent(
		ts.readConfigFile(configPath, ts.sys.readFile).config,
		ts.sys,
		projectRoot,
	);
	const program = ts.createProgram(
		ENTRYPOINTS.map((entry) => path.join(projectRoot, entry)),
		config.options,
	);
	const checker = program.getTypeChecker();
	const unions = new Map<string, ReadonlySet<string>>();
	for (const entry of ENTRYPOINTS) {
		const source = program.getSourceFile(path.join(projectRoot, entry));
		if (source === undefined) continue;
		const moduleSymbol = checker.getSymbolAtLocation(source);
		if (moduleSymbol === undefined) continue;
		for (const symbol of checker.getExportsOfModule(moduleSymbol)) {
			const name = symbol.getName();
			if (!/(ErrorCode|ReasonCode)$/.test(name)) continue;
			const declared = checker.getDeclaredTypeOfSymbol(symbol);
			const parts = declared.isUnion() ? declared.types : [declared];
			const codes = parts
				.filter((part): part is ts.StringLiteralType => part.isStringLiteral())
				.map((part) => part.value);
			if (codes.length === 0) continue;
			unions.set(name, new Set(codes));
		}
	}
	return unions;
}

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
	const unions = exportedCodeUnions();
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
