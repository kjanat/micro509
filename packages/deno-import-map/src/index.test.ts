/// <reference types="bun"/>
import { describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeDenoImportMap } from './index.ts';

describe('writeDenoImportMap', () => {
	it('defaults to package.json and creates missing output directories', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'deno-import-map-'));
		try {
			fs.writeFileSync(
				path.join(root, 'package.json'),
				JSON.stringify({ imports: { '#config': './src/config.ts' } }),
			);

			const out = writeDenoImportMap({
				root,
				out: '.cache/maps/deno.import_map.json',
			});

			expect(out).toBe(path.join(root, '.cache/maps/deno.import_map.json'));
			expect(JSON.parse(fs.readFileSync(out, 'utf8'))).toEqual({
				imports: { '#config': './src/config.ts' },
			});
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});
