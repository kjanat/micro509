import { describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { compilerInputs } from './inputs.ts';

async function fixture() {
	await mkdir('.cache', { recursive: true });
	const root = await mkdtemp(join(process.cwd(), '.cache/tsc-inputs-'));
	await mkdir(join(root, 'tsc/bridge/src'), { recursive: true });
	const pkg = {
		name: 'micro509',
		version: '0.17.1',
		description: 'PKI toolkit',
		scripts: { 'build:tsc': 'tsdown -F compiler', build: 'tsdown -F micro509' },
		devDependencies: { tsdown: 'catalog:build' },
		catalogs: { build: { tsdown: '^0.23.0' } },
	};
	const manifest = () => writeFile(join(root, 'package.json'), JSON.stringify(pkg));
	await manifest();
	await Promise.all(
		['bun.lock', 'tsdown.config.ts', '.dprint.json', 'tsc/bridge/src/index.ts'].map((path) =>
			writeFile(join(root, path), '{}'),
		),
	);
	return {
		root,
		pkg,
		manifest,
		[Symbol.asyncDispose]: () => rm(root, { recursive: true, force: true }),
	};
}

describe('compiler build inputs', () => {
	test.each(['version', 'description', 'library build', 'changelog'] as const)(
		'ignores changes to %s',
		async (change) => {
			await using context = await fixture();
			const { root, pkg, manifest } = context;
			const before = await compilerInputs(root);
			switch (change) {
				case 'version':
					pkg.version = '0.17.2';
					break;
				case 'description':
					pkg.description = 'Updated description';
					break;
				case 'library build':
					pkg.scripts.build = 'tsdown -F micro509 --watch';
					break;
				case 'changelog':
					await writeFile(join(root, 'CHANGELOG.md'), 'New release');
					break;
			}
			await manifest();
			expect(await compilerInputs(root)).toBe(before);
		},
	);

	test.each(['source', 'lockfile', 'config', 'compiler command', 'dependency', 'catalog'] as const)(
		'invalidates changes to %s',
		async (change) => {
			await using context = await fixture();
			const { root, pkg, manifest } = context;
			const before = await compilerInputs(root);
			switch (change) {
				case 'source':
					await writeFile(join(root, 'tsc/bridge/src/index.ts'), 'export const changed = true;');
					break;
				case 'lockfile':
					await writeFile(join(root, 'bun.lock'), '{"changed":true}');
					break;
				case 'config':
					await writeFile(join(root, 'tsdown.config.ts'), 'export const changed = true;');
					break;
				case 'compiler command':
					pkg.scripts['build:tsc'] += ' --minify';
					break;
				case 'dependency':
					pkg.devDependencies.tsdown = '^0.24.0';
					break;
				case 'catalog':
					pkg.catalogs.build.tsdown = '^0.24.0';
					break;
			}
			await manifest();
			expect(await compilerInputs(root)).not.toBe(before);
		},
	);
});
