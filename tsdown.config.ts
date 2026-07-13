import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import type { UserConfig } from 'tsdown';
import { defineConfig } from 'tsdown';
import jsr from '#jsr' with { type: 'json' };
import pkg from '#pkg' with { type: 'json' };

export const entries = {
	index: 'src/index.ts',
	keys: 'src/keys/index.ts',
	pem: 'src/pem/index.ts',
	pkcs: 'src/pkcs/index.ts',
	result: 'src/result/index.ts',
	revocation: 'src/revocation/index.ts',
	verify: 'src/verify/index.ts',
	x509: 'src/x509/index.ts',
} satisfies UserConfig['entry'];

export default defineConfig({
	entry: entries,
	name: pkg.name,
	format: 'esm',
	dts: true,
	clean: true,
	platform: 'neutral',
	target: 'baseline-widely-available',
	tsconfig: './tsconfig.src.json',
	sourcemap: true,
	unbundle: true,
	hash: false,
	minify: {
		compress: { joinVars: true, unused: true },
		mangle: { keepNames: true },
		codegen: { legalComments: 'external', removeWhitespace: false },
	},
	inputOptions: { resolve: { mainFields: ['browser', 'module', 'main'] } },
	hooks: {
		'build:done': async () => {
			const jsrNext = { ...jsr, exports: {} };
			jsrNext.exports = Object.fromEntries(
				Object.entries(entries).map(([name, sourcePath]) => [
					name === 'index' ? '.' : `./${name}`,
					`./${sourcePath}`,
				]),
			);
			jsrNext.version = pkg.version;
			await writeFile('jsr.json', `${JSON.stringify(jsrNext, null, '\t')}\n`);
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
	attw: { profile: 'esm-only', enabled: 'ci-only' },
	report: 'ci-only',
	publint: 'ci-only',
	unused: 'ci-only',
	failOnWarn: 'ci-only',
	onSuccess: 'dprint fmt {jsr,package}.json'
});
