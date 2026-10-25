import { describe, expect, test } from 'bun:test';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { cachedBuild, fingerprint } from './cache.ts';

async function fixture() {
	await mkdir('.cache', { recursive: true });
	const root = await mkdtemp(join(process.cwd(), '.cache/tsc-test-'));
	const state = { builds: 0, toolchain: 'compiler-a' };
	await writeFile(join(root, 'input.ts'), 'export const answer: number = 42;\n');
	return {
		root,
		state,
		[Symbol.asyncDispose]: () => rm(root, { recursive: true, force: true }),
		build: () =>
			cachedBuild({
				root,
				stamp: 'cache/build',
				inputs: async () => `${state.toolchain}:${await fingerprint(root, ['input.ts'])}`,
				outputs: async () => ['dist/input.js'],
				build: async () => {
					state.builds++;
					const result = await Bun.build({
						entrypoints: [join(root, 'input.ts')],
						outdir: join(root, 'dist'),
					});
					if (!result.success) throw new AggregateError(result.logs, 'Fixture build failed');
				},
			}),
	};
}

describe('compiler artifact cache', () => {
	test('builds once and reuses verified output', async () => {
		await using context = await fixture();
		const { build, state } = context;
		expect(await build()).toBe('built');
		expect(await build()).toBe('cached');
		expect(state.builds).toBe(1);
	});

	test.each(['source', 'toolchain', 'missing output', 'corrupt output', 'mode', 'stamp'] as const)(
		'rebuilds after a change to %s',
		async (change) => {
			await using context = await fixture();
			const { root, build, state } = context;
			await build();
			switch (change) {
				case 'source':
					await writeFile(join(root, 'input.ts'), 'export const answer = 43;\n');
					break;
				case 'toolchain':
					state.toolchain = 'compiler-b';
					break;
				case 'missing output':
					await rm(join(root, 'dist'), { recursive: true });
					break;
				case 'corrupt output':
					await writeFile(join(root, 'dist/input.js'), 'broken');
					break;
				case 'mode':
					await chmod(join(root, 'dist/input.js'), 0o755);
					break;
				case 'stamp':
					await writeFile(join(root, 'cache/build'), 'broken');
					break;
			}
			expect(await build()).toBe('built');
			expect(await build()).toBe('cached');
			expect(state.builds).toBe(2);
		},
	);

	test('accepts restored artifacts and stamp', async () => {
		await using context = await fixture();
		const { root, build, state } = context;
		await build();
		await copyFile(join(root, 'dist/input.js'), join(root, 'saved.js'));
		await rm(join(root, 'dist/input.js'));
		await copyFile(join(root, 'saved.js'), join(root, 'dist/input.js'));
		expect(await build()).toBe('cached');
		expect(state.builds).toBe(1);
	});

	test('does not stamp failed builds', async () => {
		await using context = await fixture();
		const { root, build } = context;
		await build();
		const stamp = await readFile(join(root, 'cache/build'), 'utf8');
		await writeFile(join(root, 'input.ts'), 'export const = ;');
		const error = await build().catch((error: unknown) => error);
		expect(error).toBeInstanceOf(Error);
		expect(await readFile(join(root, 'cache/build'), 'utf8')).toBe(stamp);
		await writeFile(join(root, 'input.ts'), 'export const answer = 43;');
		expect(await build()).toBe('built');
	});
});
