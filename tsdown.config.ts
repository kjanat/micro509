import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { getBuffer as getFmtBiome } from '@dprint/biome';
import { createContext } from '@dprint/formatter';
import { getPath as getFmtJson } from '@dprint/json';
import { wasm } from 'rolldown-plugin-wasm';
import type { UserConfig } from 'tsdown';
import { defineConfig } from 'tsdown';
import jsr from '#jsr' with { type: 'json' };
import pkg from '#pkg' with { type: 'json' };
import fmtCfg from './.dprint.json' with { type: 'json' };

const fmt = createContext({ useTabs: true, indentWidth: 2, lineWidth: 100, newLineKind: 'lf' });
fmt.addPlugin(getFmtBiome(), fmtCfg.biome);
fmt.addPlugin(readFileSync(getFmtJson()), fmtCfg.json);

const entries = readdirSync(join(import.meta.dirname, 'src'))
	.filter((file) => file.endsWith('.ts'))
	.sort()
	.map((file) => `src/${file}`);

const exports = {
	enabled: true,
	packageJson: true,
	customExports(exports, { pkg }) {
		const root = typeof pkg.packageJsonPath === 'string' ? dirname(pkg.packageJsonPath) : '.';
		for (const [key, value] of Object.entries(exports)) {
			const conditions = typeof value === 'string' ? { default: value } : value;
			const path = conditions?.default;
			if (typeof path !== 'string') continue;
			const typesPath = path.replace(/\.([mc]?)js$/, '.d.$1ts');
			if (typesPath !== path && existsSync(join(root, typesPath))) {
				exports[key] = { types: typesPath, ...conditions };
			}
		}
		return exports;
	},
} satisfies UserConfig['exports'];

export default defineConfig((options) => [
	{
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
		attw: { profile: 'esm-only', enabled: 'ci-only' },
		report: 'ci-only',
		publint: 'ci-only',
		unused: 'ci-only',
		failOnWarn: 'ci-only',
		exports,
		watch: options.watch ? ['src/**/*.ts'] : false,
		...(options.watch
			? {}
			: {
					hooks: {
						'build:done': async () => {
							// jsr.json
							const jsrNext = { ...jsr, exports: {} };
							jsrNext.exports = Object.fromEntries(
								entries
									.map((sourcePath) => {
										const name = basename(sourcePath, '.ts');
										return [name === 'index' ? '.' : `./${name}`, `./${sourcePath}`] as const;
									})
									.sort(([left], [right]) => (left < right ? -1 : 1)),
							);
							jsrNext.version = pkg.version;
							const unformattedJsr = `${JSON.stringify(jsrNext, null, '\t')}\n`;
							const formattedJsr = fmt.formatText({
								filePath: 'jsr.json',
								fileText: unformattedJsr,
							});
							await writeFile('jsr.json', formattedJsr);

							// package.json
							const unformattedPkg = await readFile('./package.json', 'utf8');
							const formattedPkg = fmt.formatText({
								filePath: 'package.json',
								fileText: unformattedPkg,
							});

							if (unformattedPkg !== formattedPkg) await writeFile('./package.json', formattedPkg);
						},
					},
				}),
	},
	{
		cwd: import.meta.dirname,
		workspace: {
			config: undefined,
			exclude: undefined,
			include: 'tsc/*',
		},
		dts: true,
		exports,
		plugins: [wasm()],
	},
]);
