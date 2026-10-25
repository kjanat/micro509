import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { compileModule, moduleFor } from '#micro509/kdf/argon2-module';

test('compiles the packaged file and reuses the compiled module', async () => {
	const module = await moduleFor();
	assert.ok(module instanceof WebAssembly.Module);
	assert.equal(await moduleFor(), module);
});

test('loads a binary HTTP asset and rejects failed downloads', async () => {
	const wasm = await readFile(new URL('../../src/kdf/argon2.wasm', import.meta.url));
	const server = createServer((request, response) => {
		if (request.url !== '/argon2.wasm') {
			response.writeHead(404);
			response.end();
			return;
		}
		response.writeHead(200, { 'content-type': 'application/wasm' });
		response.end(wasm);
	});
	try {
		await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(undefined)));
		const address = server.address();
		assert.ok(address && typeof address !== 'string');
		const base = `http://127.0.0.1:${address.port}`;
		await assert.rejects(compileModule(new URL('/missing.wasm', base)));
		const module = await compileModule(new URL('/argon2.wasm', base));
		assert.deepEqual(WebAssembly.Module.imports(module), [
			{ module: 'env', name: 'emscripten_notify_memory_growth', kind: 'function' },
			{ module: 'env', name: 'memory', kind: 'memory' },
		]);
	} finally {
		server.closeAllConnections();
		await new Promise((resolve, reject) =>
			server.close((error) => (error ? reject(error) : resolve(undefined))),
		);
	}
});
