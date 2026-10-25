import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { $ } from 'bun';
import { cachedBuild, fingerprint } from './cache.ts';

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
	const toolchain =
		await shell`go -C tsc/bridge env -json GOVERSION GOOS GOARCH GOAMD64 GOARM GOARM64 CGO_ENABLED GOEXPERIMENT GOFLAGS CC CXX CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS`.text();
	const nodeVersion = (await shell`node --version`.text()).trim();
	const result = await cachedBuild({
		root,
		stamp: '.cache/tsc/build',
		inputs: async () => {
			const sources = await Array.fromAsync(
				new Bun.Glob('tsc/**/*.{ts,json,go,mod,sum}').scan({ cwd: root, onlyFiles: true }),
			);
			const paths = sources.filter(
				(path) => !/\/(bin|dist|node_modules|test)\//.test(path) && !path.endsWith('.test.ts'),
			);
			paths.push('bun.lock', 'package.json', 'tsdown.config.ts', '.dprint.json');
			paths.push(
				...(await Array.fromAsync(new Bun.Glob('go.work*').scan({ cwd: root, onlyFiles: true }))),
			);
			return createHash('sha256')
				.update(await fingerprint(root, paths))
				.update(toolchain)
				.update(JSON.stringify([process.platform, process.arch, Bun.version, nodeVersion]))
				.digest('hex');
		},
		outputs: async () => {
			const files = [...binaries];
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
			await shell`run -sq @kjanat/tsc-bridge:build @kjanat/tsc-wasm:build @kjanat/tsc-compat:build`;
			await shell`run -s build:tsc`;
		},
	});
	console.log(
		`[tsc] ${result === 'cached' ? 'Reusing verified compiler artifacts' : 'Built compiler artifacts'}`,
	);
}
