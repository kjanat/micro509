import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { argon2Artifacts } from './artifacts.ts';

const run = promisify(execFile);
export const compilerVersion = '5.0.2';
const compilerArgs = [
	...['bridge.c', 'src/core.c', 'src/ref.c', 'src/blake2/blake2b.c'].map(
		(file) => `${argon2Artifacts.vendor}/${file}`,
	),
	`-I${argon2Artifacts.vendor}/include`,
	'-O3',
	'-DARGON2_NO_THREADS',
	'-sSTANDALONE_WASM=1',
	'--no-entry',
	'-sIMPORTED_MEMORY=1',
	'-sINITIAL_MEMORY=2097152',
	'-sSTACK_SIZE=65536',
	'-sALLOW_MEMORY_GROWTH=1',
	'-sMAXIMUM_MEMORY=2147483648',
	'-sABORTING_MALLOC=0',
	'-sEXPORTED_FUNCTIONS=["_malloc","_begin","_step","_finish"]',
];

function hash(value: string | Uint8Array) {
	return createHash('sha256').update(value).digest('hex');
}

async function readOptional(file: string) {
	try {
		return await readFile(file);
	} catch (error) {
		if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined;
		throw error;
	}
}

/** Content-based inputs, including every vendored C source/header and the build recipe.
 */
export async function argon2Inputs(root: string) {
	const vendor = argon2Artifacts.vendor;
	const entries = await readdir(join(root, vendor), { recursive: true, withFileTypes: true });
	const files = [
		...['build.ts', 'artifacts.ts'].map((file) => join(argon2Artifacts.tooling, file)),
		...entries
			.filter((entry) => entry.isFile() && /\.[ch]$/.test(entry.name))
			.map((entry) => join(entry.parentPath, entry.name)),
	];
	const paths = files.map((file) => resolve(root, file)).sort();
	const digest = createHash('sha256');
	for (const file of paths) {
		// Paths are relative in the hash so a fresh checkout reuses the artifacts.
		const relative = file.slice(resolve(root).length + 1).replaceAll('\\', '/');
		digest
			.update(relative)
			.update('\0')
			.update(hash(await readFile(file)))
			.update('\0');
	}
	const directories = entries
		.filter((entry) => entry.isDirectory())
		.map((entry) => join(entry.parentPath, entry.name));
	return {
		digest: digest.digest('hex'),
		files: paths,
		directories: [join(root, vendor), ...directories],
	};
}

function manifest(inputs: string, wasm: Uint8Array) {
	return `${JSON.stringify(
		{ schema: 1, compilerVersion, inputs, wasm: hash(wasm) },
		null,
		'\t',
	)}\n`;
}

/** Replace only changed files, atomically, so no-op builds do not trigger watch loops.
 */
async function writeChanged(file: string, content: Uint8Array | string) {
	const bytes = Buffer.from(content);
	if ((await readOptional(file))?.equals(bytes)) return;
	await mkdir(dirname(file), { recursive: true });
	const temporary = `${file}.${randomUUID()}.tmp`;
	try {
		await writeFile(temporary, bytes);
		await rename(temporary, file);
	} finally {
		await rm(temporary, { force: true });
	}
}

interface BuildOptions {
	mode?: 'ensure' | 'force' | 'check';
	compiler?: string;
}

async function build(root: string, options: BuildOptions) {
	const inputs = await argon2Inputs(root);
	const existingWasm = await readOptional(join(root, argon2Artifacts.wasm));
	const existingManifest = await readOptional(join(root, argon2Artifacts.manifest));
	if (
		(options.mode ?? 'ensure') === 'ensure' &&
		existingWasm &&
		existingManifest?.toString() === manifest(inputs.digest, existingWasm)
	) {
		return { rebuilt: false, digest: hash(existingWasm) };
	}
	const compiler = options.compiler ?? 'emcc';
	try {
		const { stdout } = await run(compiler, ['--version']);
		if (!stdout.includes(` ${compilerVersion} `))
			throw new Error(`Expected Emscripten ${compilerVersion}`);
	} catch (cause) {
		throw new Error(
			`Argon2 artifacts need rebuilding. Install Emscripten ${compilerVersion} and make emcc available, then rerun the build.`,
			{ cause },
		);
	}
	const temporary = await mkdtemp(join(tmpdir(), 'micro509-argon2-'));
	try {
		const output = join(temporary, basename(argon2Artifacts.wasm));
		await run(compiler, [...compilerArgs, '-o', output], { cwd: root });
		const bytes = await readFile(output);
		const module = await WebAssembly.compile(bytes);
		const imports = WebAssembly.Module.imports(module);
		if (
			imports.length !== 2 ||
			imports.some(
				(entry) =>
					entry.module !== 'env' ||
					!(
						(entry.name === 'memory' && entry.kind === 'memory') ||
						(entry.name === 'emscripten_notify_memory_growth' && entry.kind === 'function')
					),
			)
		)
			throw new Error('Unexpected Argon2 WASM host imports');
		const nextManifest = manifest(inputs.digest, bytes);
		if ((await argon2Inputs(root)).digest !== inputs.digest) {
			throw new Error('Argon2 inputs changed during compilation; rerun the build');
		}
		if (options.mode === 'check') {
			if (!existingWasm?.equals(bytes) || existingManifest?.toString() !== nextManifest) {
				throw new Error('Checked-in Argon2 artifacts do not match the pinned build');
			}
		} else {
			await writeChanged(join(root, argon2Artifacts.wasm), bytes);
			// Commit metadata last: interrupted writes always invalidate the next check.
			await writeChanged(join(root, argon2Artifacts.manifest), nextManifest);
		}
		return { rebuilt: true, digest: hash(bytes) };
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

/** Serialize shared artifacts across the ordinary and Workers builds in one process.
 */
const pending = new Map<string, Promise<{ rebuilt: boolean; digest: string }>>();

export function buildArgon2(root: string, options: BuildOptions = {}) {
	const key = resolve(root);
	const previous = pending.get(key) ?? Promise.resolve();
	const next = previous.catch(() => undefined).then(() => build(key, options));
	pending.set(key, next);
	return next.finally(() => {
		if (pending.get(key) === next) pending.delete(key);
	});
}
