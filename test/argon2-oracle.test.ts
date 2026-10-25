import { describe, expect, test } from 'bun:test';
import type { Argon2Input } from '#micro509/kdf';
import { deriveArgon2 } from '#micro509/kdf';
import { wasmArgon2 } from '#test/oracles/argon2/wasm';
import { libargon2Vectors, rfc9106Argon2iVector, rfc9106Vectors } from './fixtures/argon2.mjs';

async function compare(input: Argon2Input): Promise<void> {
	const original = structuredClone(input);
	const expected = await deriveArgon2(input, { backend: wasmArgon2 });
	const actual = await deriveArgon2(input, { backend: 'portable' });
	expect(expected.ok).toBe(true);
	expect(actual).toEqual(expected);
	expect(input).toEqual(original);
}

describe('TypeScript Argon2 against the reference WASM oracle', () => {
	test.each([...rfc9106Vectors, rfc9106Argon2iVector, ...libargon2Vectors])(
		'$input.algorithm v$input.version agrees with the published vector and oracle',
		async ({ input, expected }) => {
			const oracle = await deriveArgon2(input, { backend: wasmArgon2 });
			expect(oracle.ok).toBe(true);
			if (!oracle.ok) throw new Error(oracle.error.code);
			expect(Buffer.from(oracle.value).toString('hex')).toBe(expected);
			await compare(input);
		},
	);

	describe.each(['argon2d', 'argon2i', 'argon2id'] as const)('%s', (algorithm) => {
		describe.each([0x10, 0x13] as const)('version %i', (version) => {
			test.each([
				// Minimum memory; first slice has no blocks left after initialization.
				{ parallelism: 1, memoryKiB: 8, passes: 1, outputBytes: 4, inputBytes: 0 },
				{ parallelism: 4, memoryKiB: 32, passes: 3, outputBytes: 17, inputBytes: 1 },
				// H0 crosses BLAKE2b block boundaries; H' crosses its 64-byte boundary.
				{ parallelism: 3, memoryKiB: 49, passes: 2, outputBytes: 64, inputBytes: 79 },
				{ parallelism: 2, memoryKiB: 37, passes: 4, outputBytes: 65, inputBytes: 80 },
				{ parallelism: 1, memoryKiB: 17, passes: 2, outputBytes: 96, inputBytes: 81 },
				{ parallelism: 3, memoryKiB: 25, passes: 2, outputBytes: 97, inputBytes: 128 },
				// More than 128 blocks in a segment forces another address block.
				{ parallelism: 2, memoryKiB: 1033, passes: 2, outputBytes: 1024, inputBytes: 257 },
			])(
				'matches memory=$memoryKiB lanes=$parallelism passes=$passes output=$outputBytes input=$inputBytes',
				async ({ inputBytes, ...parameters }) => {
					await compare({
						algorithm,
						version,
						...parameters,
						password: Uint8Array.from({ length: inputBytes }, (_, i) => (i * 173 + 251) & 255),
						salt: Uint8Array.from({ length: 8 }, (_, i) => i * 31),
					});
				},
			);
			test('matches binary secret and associated data across BLAKE2b blocks', async () => {
				await compare({
					algorithm,
					version,
					memoryKiB: 65,
					parallelism: 4,
					passes: 3,
					outputBytes: 100,
					password: new Uint8Array(127).fill(255),
					salt: new Uint8Array(129).fill(128),
					secret: new Uint8Array(131).fill(254),
					associatedData: new Uint8Array(133).fill(253),
				});
			});
		});
	});

	test('matches the RFC 9106 64 MiB profile', async () => {
		await compare({
			algorithm: 'argon2id',
			version: 0x13,
			memoryKiB: 64 * 1024,
			parallelism: 4,
			passes: 3,
			outputBytes: 32,
			password: new TextEncoder().encode('demo password'),
			salt: new Uint8Array(16).fill(2),
		});
	}, 30_000);
});
