import assert from 'node:assert/strict';
import { argon2 } from 'node:crypto';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { deriveArgon2 } from '#micro509/kdf';
import { rfc9106Vectors } from '../fixtures/argon2.mjs';

// This suite requires native WebCrypto Argon2. Bun exercises the unsupported
// runtime path separately. Node reports source coverage without a transpiler.
for (const { input, expected } of rfc9106Vectors) {
	test(`native WebCrypto ${input.algorithm} matches RFC 9106 with secret and associated data`, async () => {
		const result = await deriveArgon2(input);
		assert.equal(result.ok, true);
		assert.equal(Buffer.from(result.value).toString('hex'), expected);
	});
}

test('native WebCrypto without optional inputs matches node:crypto', async () => {
	/** @type {import('#micro509/kdf').Argon2Input} */
	const input = {
		algorithm: 'argon2id',
		version: 0x13,
		password: new TextEncoder().encode('native interoperability'),
		salt: new TextEncoder().encode('sixteen-byte-salt'),
		memoryKiB: 33,
		passes: 2,
		parallelism: 4,
		outputBytes: 48,
	};
	const expected = await promisify(argon2)(input.algorithm, {
		message: input.password,
		nonce: input.salt,
		memory: input.memoryKiB,
		passes: input.passes,
		parallelism: input.parallelism,
		tagLength: input.outputBytes,
	});
	const result = await deriveArgon2(input);
	assert.equal(result.ok, true);
	assert.deepEqual(result.value, new Uint8Array(expected));
});

test('native boundary rejects invalid requests before allocating native memory', async () => {
	const vector = rfc9106Vectors[0];
	assert.ok(vector);
	for (const request of [
		null,
		{ ...vector.input, algorithm: 'argon2i' },
		{ ...vector.input, version: 20 },
		{ ...vector.input, passes: 0 },
		{ ...vector.input, password: 'password' },
		{ ...vector.input, memoryKiB: 0 },
		{ ...vector.input, version: 0x10 },
		{ ...vector.input, salt: new Uint8Array(0) },
	]) {
		const result = await Reflect.apply(deriveArgon2, undefined, [request]);
		assert.equal(result.ok, false);
	}
	for (const limits of [{ maxPasses: NaN }, { maxInputBytes: 1 }, { maxMemoryKiB: 1 }]) {
		assert.equal((await deriveArgon2(vector.input, { limits })).ok, false);
	}
	assert.equal(
		(
			await deriveArgon2(
				{ ...vector.input, outputBytes: 0x20000000 },
				{
					limits: { maxOutputBytes: 0x20000000 },
				},
			)
		).ok,
		false,
	);
	const detached = new Uint8Array(16);
	structuredClone(detached, { transfer: [detached.buffer] });
	assert.equal((await deriveArgon2({ ...vector.input, password: detached })).ok, false);
});
