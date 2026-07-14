import { afterEach, describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeDenoImportMap } from './index.ts';

const roots: string[] = [];

afterEach(() => {
	for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function fixture(
	imports: Readonly<Record<string, unknown>>,
	files: readonly string[] = [],
): string {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), 'deno-import-map-'));
	roots.push(root);
	fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ imports }));
	for (const file of files) {
		const target = path.join(root, file);
		fs.mkdirSync(path.dirname(target), { recursive: true });
		fs.writeFileSync(target, '');
	}
	return root;
}

function generate(root: string, out = 'deno.import_map.json'): string {
	return writeDenoImportMap({ root, out });
}

describe('writeDenoImportMap', () => {
	it('expands matching files with extensionless and extension keys', () => {
		const root = fixture({ '#lib/*': './src/lib/*.ts' }, [
			'src/lib/bytes.ts',
			'src/lib/codecs/hex.ts',
			'src/lib/ignored.js',
		]);
		const out = generate(root, '.cache/maps/deno.import_map.json');

		expect(out).toBe(path.join(root, '.cache/maps/deno.import_map.json'));
		expect(JSON.parse(fs.readFileSync(out, 'utf8'))).toEqual({
			imports: {
				'#lib/bytes': './src/lib/bytes.ts',
				'#lib/bytes.ts': './src/lib/bytes.ts',
				'#lib/codecs/hex': './src/lib/codecs/hex.ts',
				'#lib/codecs/hex.ts': './src/lib/codecs/hex.ts',
			},
		});
	});

	it('combines exact and pattern entries and skips non-string targets', () => {
		const root = fixture(
			{
				'#config': './src/config.ts',
				'#lib/*': './src/lib/*.ts',
				'#conditional': { import: './src/import.ts', default: './src/default.ts' },
			},
			['src/config.ts', 'src/lib/value.ts'],
		);

		expect(JSON.parse(fs.readFileSync(generate(root), 'utf8'))).toEqual({
			imports: {
				'#config': './src/config.ts',
				'#lib/value': './src/lib/value.ts',
				'#lib/value.ts': './src/lib/value.ts',
			},
		});
	});

	it('merges additional imports after manifest mappings', () => {
		const root = fixture({ '#config': './src/config.ts' });
		const out = writeDenoImportMap({
			root,
			out: 'deno.import_map.json',
			additionalImports: {
				'#config': './types/config.d.ts',
				'bun:test': './node_modules/bun-types/test.d.ts',
				virtual: 'https://example.com/virtual.ts',
			},
		});

		expect(JSON.parse(fs.readFileSync(out, 'utf8'))).toEqual({
			imports: {
				'#config': './types/config.d.ts',
				'bun:test': './node_modules/bun-types/test.d.ts',
				virtual: 'https://example.com/virtual.ts',
			},
		});
	});

	it('writes stable code-unit-sorted tab-indented output', () => {
		const first = fixture({
			'#z': './z.ts',
			'#ä': './umlaut.ts',
			'#a': './a.ts',
			'#A': './upper.ts',
		});
		const second = fixture({
			'#A': './upper.ts',
			'#a': './a.ts',
			'#ä': './umlaut.ts',
			'#z': './z.ts',
		});
		const expected = `{
	"imports": {
		"#A": "./upper.ts",
		"#a": "./a.ts",
		"#z": "./z.ts",
		"#ä": "./umlaut.ts"
	}
}
`;

		expect(fs.readFileSync(generate(first), 'utf8')).toBe(expected);
		expect(fs.readFileSync(generate(second), 'utf8')).toBe(expected);
	});

	it('writes an empty map when a pattern directory is missing', () => {
		const root = fixture({ '#missing/*': './missing/*.ts' });

		expect(JSON.parse(fs.readFileSync(generate(root), 'utf8'))).toEqual({ imports: {} });
	});
});
