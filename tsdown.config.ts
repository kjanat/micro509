import { existsSync, readdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { defineConfig } from 'tsdown';
import jsr from '#jsr' with { type: 'json' };
import pkg from '#pkg' with { type: 'json' };

export default defineConfig((options) => ({
	entry: ['src/*.ts'],
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
	attw: { profile: 'esm-only', enabled: 'ci-only' },
	report: 'ci-only',
	publint: 'ci-only',
	unused: 'ci-only',
	failOnWarn: 'ci-only',
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
	watch: options.watch ? ['src/**/*.ts'] : false,
	...(options.watch
		? {}
		: {
				onSuccess: 'dprint fmt {jsr,package}.json',
				hooks: {
					'build:done': async () => {
						const exports = Object.fromEntries(
							readdirSync('src')
								.filter((file) => file.endsWith('.ts'))
								.map((file) => {
									const name = file.slice(0, -'.ts'.length);
									return [name === 'index' ? '.' : `./${name}`, `./src/${file}`];
								})
								.sort(),
						);
						const jsrNext = { ...jsr, exports, version: pkg.version };
						await writeFile('jsr.json', `${JSON.stringify(jsrNext, null, '\t')}\n`);
					},
				},
			}),
}));
