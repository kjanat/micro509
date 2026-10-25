import { expect, test } from 'bun:test';
import { rejects } from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'tsdown';
import { argon2Artifacts } from '../src/artifacts.ts';
import { buildArgon2, compilerVersion } from '../src/build.ts';
import { argon2Plugin } from '../src/index.ts';

const repository = fileURLToPath(new URL('../../../', import.meta.url));
const emcc = spawnSync('emcc', ['--version'], { encoding: 'utf8' });
const compilerAvailable = emcc.status === 0 && emcc.stdout.includes(` ${compilerVersion} `);
const outputs = [argon2Artifacts.wasm, argon2Artifacts.manifest];
const bridgeFile = `${argon2Artifacts.vendor}/bridge.c`;
const headerFile = `${argon2Artifacts.vendor}/src/core.h`;

async function fixture(): Promise<string> {
	const root = await mkdtemp(join(tmpdir(), 'micro509-argon2-plugin-'));
	for (const path of [
		argon2Artifacts.vendor,
		dirname(argon2Artifacts.wasm),
		argon2Artifacts.tooling,
	]) {
		await cp(join(repository, path), join(root, path), { recursive: true });
	}
	await writeFile(join(root, 'package.json'), '{"name":"argon2-fixture","type":"module"}');
	return root;
}

test('fresh artifacts work without a compiler and touching a source does not rebuild', async () => {
	const root = await fixture();
	try {
		const before = await Promise.all(outputs.map((path) => stat(join(root, path))));
		await utimes(join(root, bridgeFile), new Date(), new Date());
		const result = await buildArgon2(root, { compiler: join(root, 'absent-emcc') });
		expect(result.rebuilt).toBe(false);
		const after = await Promise.all(outputs.map((path) => stat(join(root, path))));
		expect(after.map((entry) => entry.mtimeMs)).toEqual(before.map((entry) => entry.mtimeMs));
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test.skipIf(!compilerAvailable)(
	'source and recipe changes rebuild once across simultaneous consumers',
	async () => {
		const root = await fixture();
		try {
			for (const path of [
				headerFile,
				`${argon2Artifacts.tooling}/build.ts`,
				`${argon2Artifacts.tooling}/artifacts.ts`,
			]) {
				await writeFile(
					join(root, path),
					`${await readFile(join(root, path), 'utf8')}\n/* changed input */\n`,
				);
				const results = await Promise.all([buildArgon2(root), buildArgon2(root)]);
				expect(results.map((result) => result.rebuilt)).toEqual([true, false]);
			}
			expect((await buildArgon2(root, { mode: 'check' })).rebuilt).toBe(true);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	30_000,
);

test.skipIf(!compilerAvailable)(
	'repairs missing and corrupted artifacts and preserves them on compiler failure',
	async () => {
		const root = await fixture();
		try {
			for (const output of outputs) {
				const expected = await readFile(join(root, output));
				await rm(join(root, output));
				expect((await buildArgon2(root)).rebuilt).toBe(true);
				expect(await readFile(join(root, output))).toEqual(expected);
				await writeFile(join(root, output), 'corrupted');
				expect((await buildArgon2(root)).rebuilt).toBe(true);
				expect(await readFile(join(root, output))).toEqual(expected);
			}
			const bridge = join(root, bridgeFile);
			const original = await readFile(bridge, 'utf8');
			const before = await Promise.all(outputs.map((path) => readFile(join(root, path))));
			await writeFile(bridge, `${original}\n#error deliberate compilation failure\n`);
			await rejects(
				buildArgon2(root, { compiler: join(root, 'absent-emcc') }),
				/Install Emscripten/,
			);
			await rejects(buildArgon2(root), /deliberate compilation failure/);
			expect(await Promise.all(outputs.map((path) => readFile(join(root, path))))).toEqual(before);
			await writeFile(bridge, original);
			expect((await buildArgon2(root)).rebuilt).toBe(false);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	30_000,
);

test.skipIf(!compilerAvailable)(
	'tsdown builds missing inputs and emits the Workers asset',
	async () => {
		const root = await fixture();
		try {
			await rm(join(root, argon2Artifacts.wasm));
			await writeFile(
				join(root, 'entry.ts'),
				`export { moduleFor } from '${argon2Artifacts.moduleSpecifier}';`,
			);
			const built = await build({
				config: false,
				cwd: root,
				entry: ['entry.ts'],
				dts: false,
				exports: false,
				outDir: 'dist',
				logLevel: 'silent',
				plugins: [argon2Plugin({ root, workerd: true })],
			});
			expect(await readFile(join(root, 'dist', argon2Artifacts.output))).toEqual(
				await readFile(join(root, argon2Artifacts.wasm)),
			);
			const entry = built.bundles
				.flatMap((bundle) => bundle.chunks)
				.find((chunk) => chunk.type === 'chunk' && chunk.isEntry);
			if (entry === undefined) throw new Error('Missing bundled entry');
			expect(await readFile(join(root, 'dist', entry.fileName), 'utf8')).toContain(
				argon2Artifacts.assetImport,
			);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	30_000,
);

test.skipIf(!compilerAvailable)(
	'watch rebuilds after a C header changes',
	async () => {
		const root = await fixture();
		let handle: Awaited<ReturnType<typeof build>> | undefined;
		try {
			await mkdir(join(root, 'dist'), { recursive: true });
			await writeFile(
				join(root, 'entry.ts'),
				`export { moduleFor } from './${argon2Artifacts.loader}';`,
			);
			const initial = await readFile(join(root, argon2Artifacts.manifest), 'utf8');
			const rebuilt = Promise.withResolvers<void>();
			handle = await build({
				config: false,
				cwd: root,
				entry: ['entry.ts'],
				dts: false,
				exports: false,
				outDir: 'dist',
				watch: true,
				logLevel: 'silent',
				plugins: [argon2Plugin({ root })],
				hooks: {
					'build:done': async () => {
						if ((await readFile(join(root, argon2Artifacts.manifest), 'utf8')) !== initial)
							rebuilt.resolve();
					},
				},
			});
			const header = join(root, headerFile);
			await writeFile(header, `${await readFile(header, 'utf8')}\n/* watch change */\n`);
			await rebuilt.promise;
			expect((await buildArgon2(root, { compiler: join(root, 'absent-emcc') })).rebuilt).toBe(
				false,
			);
		} finally {
			await handle?.watch.close();
			await rm(root, { recursive: true, force: true });
		}
	},
	30_000,
);

test('tsdown emits a relocatable WASM asset without embedding it in JavaScript', async () => {
	const root = await fixture();
	try {
		await writeFile(
			join(root, 'entry.ts'),
			`export { moduleFor } from './${argon2Artifacts.loader}';`,
		);
		const built = await build({
			config: false,
			cwd: root,
			entry: ['entry.ts'],
			dts: false,
			exports: false,
			outDir: 'dist',
			logLevel: 'silent',
			plugins: [argon2Plugin({ root })],
		});
		const entry = built.bundles
			.flatMap((bundle) => bundle.chunks)
			.find((chunk) => chunk.type === 'chunk' && chunk.isEntry);
		if (entry === undefined) throw new Error('Missing bundled entry');
		const source = await readFile(join(root, 'dist', entry.fileName), 'utf8');
		expect(source).not.toContain('AGFzbQE');
		expect(source).not.toContain('wasmBase64');
		expect(await readFile(join(root, 'dist', argon2Artifacts.output))).toEqual(
			await readFile(join(root, argon2Artifacts.wasm)),
		);
		const consumer = spawnSync(
			'node',
			[
				'--input-type=module',
				'--eval',
				`import assert from 'node:assert/strict';
import { moduleFor } from ${JSON.stringify(pathToFileURL(join(root, 'dist', entry.fileName)).href)};
assert.equal(WebAssembly.Module.imports(await moduleFor()).length, 2);`,
			],
			{ encoding: 'utf8' },
		);
		expect(consumer.stderr).toBe('');
		expect(consumer.status).toBe(0);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
