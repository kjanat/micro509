import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setFlagsFromString } from 'node:v8';
import { deriveArgon2 } from '#micro509/kdf';
import { moduleFor } from '#test/oracles/argon2/argon2-module';
import { wasmArgon2 } from '#test/oracles/argon2/wasm';
import { rfc9106Vectors } from '../fixtures/argon2.mjs';

test('portable allocation failure returns a typed error and preserves caller buffers', async () => {
	const vector = rfc9106Vectors[1];
	assert.ok(vector);
	const original = structuredClone(vector.input);
	// Compile before imposing the limit: Node's TypeScript loader also uses WASM.
	await moduleFor();
	// This test file runs in its own Node process. A 2 MiB runtime ceiling is
	// smaller than the implementation's stack, input buffers and Argon2 memory.
	setFlagsFromString('--wasm-max-mem-pages=32');
	const result = await deriveArgon2(vector.input, { backend: wasmArgon2 });
	assert.equal(result.ok, false);
	assert.equal(result.error.code, 'derivation_failed');
	assert.deepEqual(vector.input, original);
});
