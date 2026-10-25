import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deriveArgon2 } from '#micro509/kdf';
import { rfc9106Vectors } from '../fixtures/argon2.mjs';

// Run on Node 22 to exercise real WebCrypto KeyFormat enum rejection.
test('the runtime rejects raw-secret as an unsupported KeyFormat', async () => {
	await assert.rejects(
		Reflect.apply(crypto.subtle.importKey, crypto.subtle, [
			'raw-secret',
			new Uint8Array(16),
			'Argon2id',
			false,
			['deriveBits'],
		]),
		TypeError,
	);
});

for (const { input, expected } of rfc9106Vectors) {
	test(`${input.algorithm} falls back after KeyFormat rejection`, async () => {
		const native = await deriveArgon2(input, { backend: 'native' });
		assert.equal(native.ok, false);
		assert.equal(native.error.code, 'unsupported');
		for (const result of [
			await deriveArgon2(input),
			await deriveArgon2(input, { backend: 'portable' }),
		]) {
			assert.equal(result.ok, true);
			assert.equal(Buffer.from(result.value).toString('hex'), expected);
		}
	});
}
