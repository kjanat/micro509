import { afterEach, describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateApiDocs } from './index.ts';

const tempRoots: string[] = [];

afterEach(() => {
	for (const root of tempRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('generateApiDocs', () => {
	it('writes compact module indexes and versioned canonical symbol pages', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'micro509-api-docs-'));
		tempRoots.push(root);
		const sourceDir = path.join(root, 'src');
		const outDir = path.join(root, 'generated');
		fs.mkdirSync(sourceDir, { recursive: true });
		fs.writeFileSync(
			path.join(sourceDir, 'index.ts'),
			[
				'/** Fixture API module.',
				' * @module',
				' */',
				'/** Stable identity value. */',
				'export interface SubjectAltName { readonly dns: string }',
				'/** Creates a subject name using {@linkcode SubjectAltName}. */',
				'export function createName(): SubjectAltName { return { dns: "example.test" }; }',
			].join('\n'),
		);

		generateApiDocs({
			root,
			outDir,
			name: 'fixture',
			entrypoints: ['src/index.ts'],
			apiBase: '/v1.2.3/api/',
		});

		const modulePage = fs.readFileSync(path.join(outDir, 'root.md'), 'utf8');
		const functionPage = fs.readFileSync(path.join(outDir, 'fn/createName.md'), 'utf8');
		const typePage = fs.readFileSync(path.join(outDir, 'type/SubjectAltName.md'), 'utf8');
		expect(modulePage).toContain('Fixture API module.');
		expect(modulePage).toContain('[`createName`](/v1.2.3/api/fn/createName)');
		expect(modulePage).not.toContain('function createName(');
		expect(functionPage).toContain('function createName(): SubjectAltName');
		expect(functionPage).toContain('/v1.2.3/api/type/SubjectAltName');
		expect(typePage).toContain('interface SubjectAltName');
	});
});
