import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import jsr from '#jsr' with { type: 'json' };
import pkg from '#pkg' with { type: 'json' };

import { defineConfig } from 'tsdown';

const jsrJson: Omit<typeof jsr, 'exports' | 'version'> & {
	exports: Record<string, string>;
	version: string;
} = { ...jsr, exports: {} };

const entry = {
	index: 'src/index.ts',
	keys: 'src/keys/index.ts',
	pem: 'src/pem/index.ts',
	pkcs: 'src/pkcs/index.ts',
	result: 'src/result/index.ts',
	revocation: 'src/revocation/index.ts',
	verify: 'src/verify/index.ts',
	x509: 'src/x509/index.ts',
} as const satisfies Record<string, string>;

export default defineConfig({
	entry,
	name: pkg.name,
	format: 'esm',
	dts: true,
	clean: true,
	platform: 'neutral',
	target: 'es2024',
	tsconfig: 'tsconfig.src.json',
	sourcemap: true,
	unbundle: true,
	hash: false,
	minify: true,
	inputOptions: { resolve: { mainFields: ['browser', 'module', 'main'] } },
	hooks: {
		'build:done': async () => {
			jsrJson.exports = Object.fromEntries(
				Object.entries(entry).map(([name, sourcePath]) => [
					name === 'index' ? '.' : `./${name}`,
					`./${sourcePath}`,
				]),
			);
			jsrJson.version = pkg.version;
			await writeFile('jsr.json', `${JSON.stringify(jsrJson, null, '\t')}\n`);
		},
	},
	exports: {
		enabled: true,
		packageJson: true,
		customExports(exports) {
			for (const [key, path] of Object.entries(exports)) {
				const typesPath = path.replace(/\.([mc]?)js$/, '.d.$1ts');
				if (typesPath !== path && existsSync(typesPath)) {
					exports[key] = { types: typesPath, default: path };
				}
			}
			return exports;
		},
	},
	onSuccess: 'bunx sort-package-json --quiet {package,jsr}.json',
	attw: { profile: 'esm-only', ignoreRules: ['no-resolution'] },
	unused: true,
	publint: true,
});
