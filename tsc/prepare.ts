import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { $ } from 'bun';
import { cachedBuild, fingerprint } from './cache.ts';
import { compilerInputs, goInputs } from './inputs.ts';

const root = join(import.meta.dirname, '..');
const packages = ['bridge', 'compat', 'protocol', 'vue-mapper', 'wasm'];
const binaries = [
	'tsc/bridge/bin/tsc-bridge',
	'tsc/compat/bin/compat.wasm',
	'tsc/compat/bin/wasm_exec.cjs',
	'tsc/wasm/bin/tsc-bridge.wasm',
	'tsc/wasm/bin/wasm_exec.js',
];
const shell = $.cwd(root);

if (process.env.WORKERS_CI) {
	await shell`run -s @kjanat/tsc-bridge:fetch`;
	await shell`tsdown -F @kjanat/tsc-protocol -F @kjanat/tsc-bridge`;
} else {
	const go = await cachedBuild({
		root,
		stamp: '.cache/tsc/go',
		inputs: () => goInputs(root),
		outputs: async () => binaries,
		build: async () => {
			await shell`run -sq @kjanat/tsc-bridge:build @kjanat/tsc-wasm:build @kjanat/tsc-compat:build`;
		},
	});
	console.log(`[tsc] ${go === 'cached' ? 'Reusing verified Go artifacts' : 'Built Go artifacts'}`);
	const nodeVersion = process.env.TSC_NODE_VERSION || (await shell`node --version`.text()).trim();
	const result = await cachedBuild({
		root,
		stamp: '.cache/tsc/bundles',
		inputs: async () =>
			createHash('sha256')
				.update(await compilerInputs(root))
				.update(await fingerprint(root, binaries))
				.update(JSON.stringify([process.platform, process.arch, Bun.version, nodeVersion]))
				.digest('hex'),
		outputs: async () => {
			const files: string[] = [];
			for (const name of packages) {
				// Require entrypoints even when an entire output directory was deleted.
				files.push(`tsc/${name}/dist/index.mjs`, `tsc/${name}/dist/index.d.mts`);
				files.push(
					...(await Array.fromAsync(
						new Bun.Glob(`tsc/${name}/dist/**/*`).scan({ cwd: root, onlyFiles: true }),
					)),
				);
			}
			return [...new Set(files)];
		},
		build: async () => {
			await shell`run -s build:tsc`;
		},
	});
	console.log(
		`[tsc] ${result === 'cached' ? 'Reusing verified compiler bundles' : 'Built compiler bundles'}`,
	);
}
