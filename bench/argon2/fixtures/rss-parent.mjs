import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

// Keep this allocation alive while the benchmark starts its isolated worker.
// Linux ru_maxrss can carry the parent's footprint across exec.
const ballast = new Uint8Array(192 * 1024 * 1024).fill(1);
process.argv[1] = fileURLToPath(new URL('../benchmark.ts', import.meta.url));
await import('../benchmark.ts');
assert.equal(ballast[0], 1);
