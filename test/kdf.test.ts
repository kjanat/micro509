import { describe, expect, it } from 'bun:test';
import { argon2, createHash } from 'node:crypto';
import type { Argon2Backend, Argon2Input, Argon2Limits, Argon2Result } from '#micro509/kdf';
import { deriveArgon2 } from '#micro509/kdf';
import { rfc9106Vectors } from './fixtures/argon2.mjs';

// A real optional backend exercises the extension boundary on Bun, whose native
// WebCrypto currently lacks Argon2. node:crypto is confined to this test.
const nodeBackend: Argon2Backend = (input) => {
	if (input.version !== 0x13) {
		return Promise.resolve({ ok: false, error: { code: 'unsupported', message: 'Version' } });
	}
	return new Promise((resolve, reject) => {
		argon2(
			input.algorithm,
			{
				message: input.password,
				nonce: input.salt,
				memory: input.memoryKiB,
				passes: input.passes,
				parallelism: input.parallelism,
				tagLength: input.outputBytes,
				secret: input.secret,
				associatedData: input.associatedData,
			},
			(error, output) => {
				if (error) reject(error);
				else resolve({ ok: true, value: output });
			},
		);
	});
};

function input(): Argon2Input {
	return {
		algorithm: 'argon2id',
		version: 0x13,
		password: new Uint8Array(32).fill(1),
		salt: new Uint8Array(16).fill(2),
		memoryKiB: 32,
		passes: 3,
		parallelism: 4,
		outputBytes: 32,
	};
}

function hex(result: Argon2Result): string {
	if (!result.ok) throw new Error(result.error.code);
	return Buffer.from(result.value).toString('hex');
}

describe('Argon2 key derivation', () => {
	it.each([
		[null, 'invalid_parameters'],
		[{ ...input(), algorithm: 'argon2i' }, 'unsupported'],
		[{ ...input(), version: NaN }, 'unsupported'],
		[{ ...input(), version: 20 }, 'unsupported'],
		[{ ...input(), password: 'password' }, 'invalid_parameters'],
		[{ ...input(), salt: null }, 'invalid_parameters'],
		[{ ...input(), secret: 'secret' }, 'invalid_parameters'],
		[{ ...input(), associatedData: [] }, 'invalid_parameters'],
	] as const)('rejects invalid JavaScript input %#', async (request, code) => {
		const result: unknown = await Reflect.apply(deriveArgon2, undefined, [request]);
		expect(result).toMatchObject({ ok: false, error: { code } });
	});
	it.each(rfc9106Vectors)(
		'matches RFC 9106 $input.algorithm with secret and associated data',
		async (vector) => {
			expect(hex(await deriveArgon2(vector.input, { backend: nodeBackend }))).toBe(vector.expected);
			const native = await deriveArgon2(vector.input);
			if (native.ok) expect(hex(native)).toBe(vector.expected);
			else expect(native.error.code).toBe('unsupported');
		},
	);

	it('matches the Bitwarden SDK vector after caller-side salt hashing and MiB conversion', async () => {
		const request: Argon2Input = {
			algorithm: 'argon2id',
			version: 0x13,
			password: new TextEncoder().encode('67t9b5g67$%Dh89n'),
			salt: createHash('sha256').update('test_key').digest(),
			memoryKiB: 32 * 1024,
			passes: 4,
			parallelism: 2,
			outputBytes: 32,
		};
		expect(hex(await deriveArgon2(request, { backend: nodeBackend }))).toBe(
			'cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2',
		);
	});

	it.each([
		['argon2d', '57db1f93bbf3ec526d66002a1e024cc4500444509fdf0ae254572ae4382e6fdf'],
		['argon2id', 'ef1e65a8a7156708fdaa8c10cb20db4743839552a83837185db7f3ac1956fd48'],
	] as const)('matches independent KDBX-style %s key material', async (algorithm, expected) => {
		// Raw KDF fixture generated with @noble/hashes 2.4.0, not a full KDBX
		// container. KDBX M is bytes: 1048576 / 1024 = 1024 KiB.
		const request: Argon2Input = {
			algorithm,
			version: 0x13,
			password: Uint8Array.from({ length: 32 }, (_, i) => i),
			salt: Uint8Array.from({ length: 32 }, (_, i) => 255 - i),
			memoryKiB: 1024,
			passes: 3,
			parallelism: 2,
			outputBytes: 32,
		};
		expect(hex(await deriveArgon2(request, { backend: nodeBackend }))).toBe(expected);
		expect(await deriveArgon2({ ...request, version: 0x10 })).toMatchObject({
			ok: false,
			error: { code: 'unsupported' },
		});
	});

	it.each([NaN, Infinity, -1, 0, 1.5, 0x100000000])(
		'rejects invalid passes %s before backend work',
		async (passes) => {
			expect(await deriveArgon2({ ...input(), passes })).toMatchObject({
				ok: false,
				error: { code: 'invalid_parameters' },
			});
		},
	);

	it.each([
		{ parallelism: 0 },
		{ parallelism: 0x1000000 },
		{ parallelism: NaN },
		{ memoryKiB: 31 },
		{ memoryKiB: Infinity },
		{ memoryKiB: 32.5 },
		{ outputBytes: 3 },
		{ outputBytes: -1 },
		{ outputBytes: Infinity },
	])('rejects malformed numeric parameters %j', async (change) => {
		expect(await deriveArgon2({ ...input(), ...change })).toMatchObject({
			ok: false,
			error: { code: 'invalid_parameters' },
		});
	});

	it.each([
		{ maxMemoryKiB: 31 },
		{ maxPasses: 2 },
		{ maxParallelism: 3 },
		{ maxOutputBytes: 31 },
		{ maxInputBytes: 47 },
	] satisfies Argon2Limits[])(
		'rejects caller resource limits before native work %j',
		async (limits) => {
			expect(await deriveArgon2(input(), { limits })).toMatchObject({
				ok: false,
				error: { code: 'limit_exceeded' },
			});
		},
	);

	it.each([NaN, Infinity, -1, 0, 1.5, 0x100000000])('rejects invalid limit %s', async (maximum) => {
		for (const limits of [
			{ maxMemoryKiB: maximum },
			{ maxPasses: maximum },
			{ maxParallelism: maximum },
			{ maxOutputBytes: maximum },
			{ maxInputBytes: maximum },
		]) {
			expect(await deriveArgon2(input(), { limits })).toMatchObject({
				ok: false,
				error: { code: 'invalid_parameters' },
			});
		}
	});

	it('includes secret and associated data in the input budget', async () => {
		expect(
			await deriveArgon2(
				{ ...input(), secret: new Uint8Array(8), associatedData: new Uint8Array(12) },
				{
					limits: { maxInputBytes: 67 },
				},
			),
		).toMatchObject({ ok: false, error: { code: 'limit_exceeded' } });
	});

	it('accepts exact caller ceilings and does not round memory before hashing', async () => {
		const request = { ...input(), memoryKiB: 33 };
		const options = {
			backend: nodeBackend,
			limits: {
				maxMemoryKiB: 33,
				maxPasses: 3,
				maxParallelism: 4,
				maxOutputBytes: 32,
				maxInputBytes: 48,
			},
		};
		const result = await deriveArgon2(request, options);
		expect(hex(result)).toBe(hex(await nodeBackend(request)));
		expect(hex(result)).not.toBe(hex(await deriveArgon2(input(), { backend: nodeBackend })));
	});

	it('copies before await, erases owned buffers, and gives the caller an independent output', async () => {
		const request = {
			...input(),
			secret: new Uint8Array(8).fill(3),
			associatedData: new Uint8Array(12).fill(4),
		};
		const owned: Argon2Input[] = [];
		const backendOutputs: Uint8Array[] = [];
		const backend: Argon2Backend = async (snapshot) => {
			owned.push(snapshot);
			const result = await nodeBackend(snapshot);
			if (result.ok) backendOutputs.push(result.value);
			return result;
		};
		const pending = deriveArgon2(request, { backend });
		request.password.fill(9);
		request.salt.fill(9);
		request.outputBytes = 4;
		const result = await pending;
		expect(hex(result)).toBe(rfc9106Vectors[1]?.expected ?? 'missing fixture');
		expect(request.password.every((byte) => byte === 9)).toBe(true);
		expect(request.secret.every((byte) => byte === 3)).toBe(true);
		for (const snapshot of owned) {
			for (const bytes of [
				snapshot.password,
				snapshot.salt,
				snapshot.secret,
				snapshot.associatedData,
			]) {
				expect(bytes?.every((byte) => byte === 0)).toBe(true);
			}
		}
		expect(backendOutputs.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
	});

	it('refuses a real backend output of the wrong length and erases the rejected key', async () => {
		const request = {
			...input(),
			secret: new Uint8Array(8).fill(3),
			associatedData: new Uint8Array(12).fill(4),
		};
		const snapshots: Argon2Input[] = [];
		const outputs: Uint8Array[] = [];
		const backend: Argon2Backend = async (snapshot) => {
			snapshots.push(snapshot);
			const result = await nodeBackend({ ...snapshot, outputBytes: snapshot.outputBytes + 1 });
			if (!result.ok) throw new Error(result.error.code);
			expect(result.value.byteLength).toBe(33);
			expect(result.value.some((byte) => byte !== 0)).toBe(true);
			outputs.push(result.value);
			return result;
		};
		expect(await deriveArgon2(request, { backend })).toMatchObject({
			ok: false,
			error: {
				code: 'derivation_failed',
				message: 'Argon2 backend returned an incorrect output length',
			},
		});
		expect(outputs).toHaveLength(1);
		expect(outputs[0]?.every((byte) => byte === 0)).toBe(true);
		for (const snapshot of snapshots) {
			for (const bytes of [
				snapshot.password,
				snapshot.salt,
				snapshot.secret,
				snapshot.associatedData,
			]) {
				expect(bytes?.every((byte) => byte === 0)).toBe(true);
			}
		}
		expect(request.password.every((byte) => byte === 1)).toBe(true);
		expect(request.secret.every((byte) => byte === 3)).toBe(true);
	});

	it('rejects an ArrayBuffer returned by a JavaScript adapter instead of Uint8Array', async () => {
		const snapshots: Argon2Input[] = [];
		const backend = async (snapshot: Argon2Input) => {
			snapshots.push(snapshot);
			const result = await nodeBackend(snapshot);
			if (!result.ok) throw new Error(result.error.code);
			const value = new Uint8Array(result.value).buffer;
			result.value.fill(0);
			return { ok: true, value };
		};
		const result: unknown = await Reflect.apply(deriveArgon2, undefined, [input(), { backend }]);
		expect(result).toMatchObject({
			ok: false,
			error: { code: 'derivation_failed', message: 'Argon2 backend returned invalid output' },
		});
		expect(snapshots).toHaveLength(1);
		expect(snapshots[0]?.password.every((byte) => byte === 0)).toBe(true);
		expect(snapshots[0]?.salt.every((byte) => byte === 0)).toBe(true);
	});

	it('handles genuine backend refusal and failure without exposing inputs', async () => {
		const unsupported = await deriveArgon2({ ...input(), version: 0x10 }, { backend: nodeBackend });
		expect(unsupported).toMatchObject({ ok: false, error: { code: 'unsupported' } });
		const request = { ...input(), salt: new Uint8Array(0) };
		expect(await deriveArgon2(request, { backend: nodeBackend })).toMatchObject({
			ok: false,
			error: { code: 'derivation_failed' },
		});
		expect(await deriveArgon2(request)).toMatchObject({
			ok: false,
			error: { code: 'unsupported' },
		});
	});

	it('rejects a native output bit-length overflow before allocation', async () => {
		expect(
			await deriveArgon2(
				{ ...input(), outputBytes: 0x20000000 },
				{
					limits: { maxOutputBytes: 0x20000000 },
				},
			),
		).toMatchObject({ ok: false, error: { code: 'unsupported' } });
	});

	it('does not expose or initialize KDF through certificate entrypoints', async () => {
		for (const file of ['src/index.ts', 'src/x509.ts', 'src/verify.ts']) {
			const bundle = await Bun.build({
				entrypoints: [new URL(`../${file}`, import.meta.url).pathname],
				target: 'browser',
			});
			expect(bundle.success).toBe(true);
			for (const output of bundle.outputs) {
				expect(await output.text()).not.toMatch(/deriveArgon2|nativeArgon2|raw-secret/);
			}
		}
	});

	it.each(['password', 'salt', 'secret', 'associatedData'] as const)(
		'rejects detached %s buffers without throwing',
		async (field) => {
			const bytes = new Uint8Array(16);
			structuredClone(bytes, { transfer: [bytes.buffer] });
			expect(await deriveArgon2({ ...input(), [field]: bytes })).toMatchObject({
				ok: false,
				error: { code: 'invalid_parameters' },
			});
		},
	);
});
