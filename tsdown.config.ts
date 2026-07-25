import { existsSync, readdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { defineConfig } from 'tsdown';
import jsr from '#jsr' with { type: 'json' };
import pkg from '#pkg' with { type: 'json' };

/**
 * Root source files are the package's public entrypoints; everything else lives
 * in a domain directory or under `src/internal/`. Adding `src/foo.ts` publishes
 * `micro509/foo`, which `test/conventions.test.ts` guards against doing by
 * accident.
 */
const ROOT_ENTRY_GLOB = 'src/*.ts';

/** The root entry files, `index` first and the rest alphabetical. */
function rootEntryStems(): readonly string[] {
	return readdirSync('src', { withFileTypes: true })
		.filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
		.map((entry) => entry.name.slice(0, -'.ts'.length))
		.sort((left, right) =>
			left === 'index' ? -1 : right === 'index' ? 1 : left.localeCompare(right),
		);
}

export default defineConfig((options) => ({
	entry: [ROOT_ENTRY_GLOB],
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
						const jsrNext = { ...jsr, exports: {} };
						jsrNext.exports = Object.fromEntries(
							rootEntryStems().map((stem) => [
								stem === 'index' ? '.' : `./${stem}`,
								`./src/${stem}.ts`,
							]),
						);
						jsrNext.version = pkg.version;
						await writeFile('jsr.json', `${JSON.stringify(jsrNext, null, '\t')}\n`);
					},
				},
			}),
}));
