#!/usr/bin/env node
/** Reproducible Argon2 latency, throughput, and event-loop benchmark. */
import assert from 'node:assert/strict';
import { argon2, argon2Sync, createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { cpus } from 'node:os';
import { performance } from 'node:perf_hooks';
import { promisify } from 'node:util';
import { cli, command, flag } from 'dreamcli';
import type { Argon2Input, Argon2Result } from '#micro509/kdf';
import pkg from '#pkg' with { type: 'json' };
import { wasmArgon2 } from '#test/oracles/argon2/wasm';

const algorithms = ['argon2id', 'argon2i', 'argon2d'] as const;
const backends = ['typescript', 'wasm', 'native', 'node'] as const;
const nodeArgon2 = promisify(argon2);
const root = new URL('../../', import.meta.url);

async function implementationHashes(source = false) {
	return Promise.all(
		['argon2', 'argon2-core', 'argon2-arithmetic', 'argon2-portable'].map(async (name) => {
			const path = source ? `src/kdf/${name}.ts` : `dist/kdf/${name}.js`;
			return {
				path,
				sha256: createHash('sha256')
					.update(await readFile(new URL(path, root)))
					.digest('hex'),
			};
		}),
	);
}

function nativeParameters(input: Argon2Input) {
	return {
		message: input.password,
		nonce: input.salt,
		memory: input.memoryKiB,
		passes: input.passes,
		parallelism: input.parallelism,
		tagLength: input.outputBytes,
	};
}

interface Measurement {
	readonly samplesMs: readonly number[];
	readonly batchMs: number;
	readonly maxTimerDelayMs: number;
}

async function measure(
	derive: () => Promise<Argon2Result>,
	expected: Uint8Array,
	concurrency: number,
): Promise<Measurement | undefined> {
	let previous = performance.now();
	let maxTimerDelayMs = 0;
	const timer = setInterval(() => {
		const now = performance.now();
		maxTimerDelayMs = Math.max(maxTimerDelayMs, now - previous - 5);
		previous = now;
	}, 5);
	try {
		const start = performance.now();
		// Wait for every call before starting the next batch, including failures.
		const settled = await Promise.allSettled(
			Array.from({ length: concurrency }, async () => {
				const started = performance.now();
				const result = await derive();
				return { result, ms: performance.now() - started };
			}),
		);
		const batchMs = performance.now() - start;
		await new Promise<void>((resolve) => setTimeout(resolve, 10));
		const samplesMs: number[] = [];
		let unsupported = false;
		for (const entry of settled) {
			if (entry.status === 'rejected') throw entry.reason;
			const { result, ms } = entry.value;
			if (!result.ok && result.error.code === 'unsupported') {
				unsupported = true;
				continue;
			}
			assert.equal(result.ok, true, JSON.stringify(result));
			try {
				assert.deepEqual(result.value, expected);
			} finally {
				result.value.fill(0);
			}
			samplesMs.push(ms);
		}
		return unsupported ? undefined : { samplesMs, batchMs, maxTimerDelayMs };
	} finally {
		clearInterval(timer);
	}
}

async function benchmark(
	derive: () => Promise<Argon2Result>,
	expected: Uint8Array,
	warmups: number,
	samples: number,
	concurrency: number,
) {
	let firstBatch: Measurement | undefined;
	for (let index = 0; index < warmups; index++) {
		const result = await measure(derive, expected, concurrency);
		if (!result) return { supported: false } as const;
		firstBatch ??= result;
	}
	const measured: Measurement[] = [];
	for (let index = 0; index < samples; index++) {
		const result = await measure(derive, expected, concurrency);
		if (!result) return { supported: false } as const;
		firstBatch ??= result;
		measured.push(result);
	}
	const samplesMs = measured.flatMap((batch) => batch.samplesMs);
	const sorted = samplesMs.toSorted((a, b) => a - b);
	const middle = Math.floor(sorted.length / 2);
	const medianMs =
		sorted.length % 2 === 0
			? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
			: (sorted[middle] ?? 0);
	return {
		supported: true,
		firstBatchMs: firstBatch?.batchMs,
		medianMs,
		minMs: sorted[0],
		maxMs: sorted.at(-1),
		samplesMs,
		batchMs: measured.map((batch) => batch.batchMs),
		derivationsPerSecond:
			(1000 * samplesMs.length) / measured.reduce((sum, batch) => sum + batch.batchMs, 0),
		maxTimerDelayMs: Math.max(...measured.map((batch) => batch.maxTimerDelayMs)),
	};
}

const run = command('run')
	.description('Compare checked Argon2 derivations; backends run sequentially')
	.flag('algorithm', flag.enum(['all', ...algorithms]).default('all'))
	.flag('backend', flag.enum(['all', ...backends]).default('all'))
	.flag('memory-kib', flag.number({ int: true, min: 8, max: 262144 }).default(65536))
	.flag('passes', flag.number({ int: true, min: 1, max: 16 }).default(3))
	.flag('lanes', flag.number({ int: true, min: 1, max: 16 }).default(4))
	.flag('output-bytes', flag.number({ int: true, min: 4, max: 1024 }).default(32))
	.flag('warmups', flag.number({ int: true, min: 0, max: 100 }).default(2))
	.flag('samples', flag.number({ int: true, min: 1, max: 1000 }).default(5))
	.flag('concurrency', flag.number({ int: true, min: 1, max: 4 }).default(1))
	.flag(
		'source',
		flag.boolean().describe('Measure the current source instead of the built package'),
	)
	.flag('output', flag.string().describe('Write the complete JSON report to this file'))
	.action(async ({ flags, out }) => {
		assert.ok(
			flags['memory-kib'] >= 8 * flags.lanes,
			'Memory must be at least eight times the lane count',
		);
		const { deriveArgon2 } = flags.source
			? await import('#micro509/kdf')
			: await import('micro509/kdf');
		const implementation = await implementationHashes(flags.source);
		const runtime = typeof Bun === 'undefined' ? `Node ${process.version}` : `Bun ${Bun.version}`;
		const parameters = {
			version: 0x13,
			memoryKiB: flags['memory-kib'],
			passes: flags.passes,
			parallelism: flags.lanes,
			outputBytes: flags['output-bytes'],
		} as const;
		const environment = {
			runtime,
			cpu: cpus()[0]?.model,
			platform: process.platform,
			arch: process.arch,
			date: new Date().toISOString(),
			packageVersion: pkg.version,
			implementation,
			warmups: flags.warmups,
			samples: flags.samples,
			concurrency: flags.concurrency,
		};
		const results = [];
		for (const algorithm of flags.algorithm === 'all' ? algorithms : [flags.algorithm]) {
			const input: Argon2Input = {
				...parameters,
				algorithm,
				password: new TextEncoder().encode('public benchmark input'),
				salt: new Uint8Array(16).fill(2),
			};
			const expected = new Uint8Array(argon2Sync(algorithm, nativeParameters(input)));
			for (const backend of flags.backend === 'all' ? backends : [flags.backend]) {
				const derive = async (): Promise<Argon2Result> =>
					backend === 'node'
						? {
								ok: true,
								value: new Uint8Array(await nodeArgon2(algorithm, nativeParameters(input))),
							}
						: deriveArgon2(input, {
								backend:
									backend === 'typescript'
										? 'portable'
										: backend === 'wasm'
											? wasmArgon2
											: 'native',
							});
				const result = {
					algorithm,
					backend,
					...(await benchmark(derive, expected, flags.warmups, flags.samples, flags.concurrency)),
				};
				results.push(result);
				if (!out.jsonMode)
					out.log(
						result.supported
							? `${runtime} ${algorithm} ${backend}: ${result.medianMs.toFixed(2)} ms, ${result.derivationsPerSecond.toFixed(2)}/s, max timer delay ${result.maxTimerDelayMs.toFixed(2)} ms`
							: `${runtime} ${algorithm} ${backend}: unsupported`,
					);
			}
		}
		const report = { environment, parameters, results };
		if (flags.output) await writeFile(flags.output, `${JSON.stringify(report, null, 2)}\n`);
		if (out.jsonMode) out.json(report);
	});

await cli('bench:argon2').default(run).run();
