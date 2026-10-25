import { describe, expect, test } from 'bun:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);

describe.each(['node', 'bun'])('Argon2 benchmark under %s', (runtime) => {
	test.each(['typescript', 'wasm'])(
		'%s reports isolated memory and checked samples',
		async (backend) => {
			const { stdout } = await execute(runtime, [
				...(runtime === 'bun' ? ['--bun'] : []),
				'bench/argon2/benchmark.ts',
				'--backend',
				backend,
				'--algorithm',
				'argon2id',
				'--memory-kib',
				'32',
				'--passes',
				'1',
				'--warmups',
				'0',
				'--samples',
				'1',
				'--concurrency',
				'2',
				'--source',
				'--json',
			]);
			const report: unknown = JSON.parse(stdout);
			assert.ok(report && typeof report === 'object' && 'results' in report);
			expect(report).toMatchObject({
				environment: { runtime: expect.stringMatching(runtime === 'bun' ? /^Bun / : /^Node /) },
			});
			assert.ok(Array.isArray(report.results));
			expect(report.results).toHaveLength(1);
			const result: unknown = report.results[0];
			assert.ok(result && typeof result === 'object');
			expect(result).toMatchObject({ algorithm: 'argon2id', backend, supported: true });
			assert.ok('baselineRssMiB' in result && typeof result.baselineRssMiB === 'number');
			assert.ok('processPeakRssMiB' in result && typeof result.processPeakRssMiB === 'number');
			expect(result.baselineRssMiB).toBeGreaterThan(0);
			expect(result.processPeakRssMiB).toBeGreaterThanOrEqual(result.baselineRssMiB);
			assert.ok('samplesMs' in result && 'batchMs' in result);
			expect(result.samplesMs).toHaveLength(2);
			expect(result.batchMs).toHaveLength(1);
		},
		15_000,
	);
});
