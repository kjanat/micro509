#!/usr/bin/env bun
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { createTscBridge } from '@kjanat/tsc-bridge';

globalThis.fs = fs;
await import('./bin/wasm_exec.js');
const bytes = fs.readFileSync(new URL('./bin/tsc-bridge.wasm', import.meta.url));
const go = new Go();
const started = performance.now();
const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
const running = go.run(instance);
const startupMs = performance.now() - started;
console.log(
	JSON.stringify({ wasmBytes: bytes.length, gzipBytes: gzipSync(bytes).length, startupMs }),
);
async function call(req) {
	const start = performance.now();
	const response = JSON.parse(await globalThis.tscProbeInvoke(JSON.stringify({ id: 1, ...req })));
	if (response.error) throw new Error(response.error);
	console.log(
		JSON.stringify({
			method: req.method,
			ms: performance.now() - start,
			diagnostics: response.diagnostics.length,
			unions: response.unions.length,
		}),
	);
	return response;
}
try {
	const result = await call({ method: 'transpile', source: 'export const answer: number = 42;' });
	assert.deepEqual(result.diagnostics, []);
	assert.equal(
		(await import(`data:text/javascript,${encodeURIComponent(result.outputText)}`)).answer,
		42,
	);
	const bad = await call({ method: 'transpile', source: 'export const answer: = 42;' });
	assert.ok(bad.diagnostics.some((d) => d.category === 1));
	const configPath = fileURLToPath(new URL('../../tsconfig.src.json', import.meta.url));
	const checked = await call({ method: 'checkProject', configPath });
	assert.deepEqual(checked.diagnostics, []);
	const unions = await call({
		method: 'exportedCodeUnions',
		configPath,
		entrypoints: ['src/index.ts'],
	});
	const native = createTscBridge();
	try {
		assert.deepEqual(unions.unions, await native.exportedCodeUnions(configPath, ['src/index.ts']));
	} finally {
		await native.close();
	}
	console.log(
		JSON.stringify({
			verified: true,
			unionCount: unions.unions.length,
			codeCount: unions.unions.reduce((n, u) => n + u.codes.length, 0),
			memoryBytes: instance.exports.mem.buffer.byteLength,
		}),
	);
} finally {
	globalThis.tscProbeClose();
	await running;
	// Dispose timers owned by this wasm_exec.js runtime.
	for (const timer of go._scheduledTimeouts.values()) clearTimeout(timer);
	go._scheduledTimeouts.clear();
	delete globalThis.tscProbeInvoke;
	delete globalThis.tscProbeClose;
}
