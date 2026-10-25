#!/usr/bin/env node
/** Compare the adapter with node:crypto in separate invocations. @module */
import { argon2 } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import pkg from '#pkg' with { type: 'json' };

const exportUrl = new URL(pkg.exports['./kdf'].default, import.meta.resolve('#pkg'));
/** @type {typeof import('#micro509/kdf')} */
const { deriveArgon2 } = await import(exportUrl.href);

const [mode = 'native', concurrencyText = '1'] = process.argv.slice(2);
const concurrency = Number(concurrencyText);
if (
	(mode !== 'native' && mode !== 'node' && mode !== 'portable') ||
	!Number.isInteger(concurrency) ||
	concurrency < 1 ||
	concurrency > 4
) {
	throw new Error('Usage: node scripts/benchmark-argon2.mjs <native|portable|node> <1..4>');
}

/** @type {import('#micro509/kdf').Argon2Input} */
const input = {
	algorithm: 'argon2id',
	version: 0x13,
	password: new TextEncoder().encode('public benchmark input'),
	salt: new Uint8Array(16).fill(2),
	memoryKiB: 65536,
	passes: 3,
	parallelism: 4,
	outputBytes: 32,
};

async function derive() {
	if (mode === 'native' || mode === 'portable') {
		const result = await deriveArgon2(input, { backend: mode });
		if (!result.ok) throw new Error(result.error.code);
		result.value.fill(0);
	} else {
		await new Promise((resolve, reject) => {
			argon2(
				'argon2id',
				{
					message: input.password,
					nonce: input.salt,
					memory: input.memoryKiB,
					passes: input.passes,
					parallelism: input.parallelism,
					tagLength: input.outputBytes,
				},
				(error, output) => {
					if (error) reject(error);
					else {
						output.fill(0);
						resolve(undefined);
					}
				},
			);
		});
	}
}

const baselineRss = process.memoryUsage().rss;
let largestTimerDelayMs = 0;
let previousTick = performance.now();
const timer = setInterval(() => {
	const now = performance.now();
	largestTimerDelayMs = Math.max(largestTimerDelayMs, now - previousTick - 5);
	previousTick = now;
}, 5);
/** @type {number[]} */
const durations = [];
try {
	for (let batch = 0; batch < 3; batch++) {
		await Promise.all(
			Array.from({ length: concurrency }, async () => {
				const start = performance.now();
				await derive();
				durations.push(performance.now() - start);
			}),
		);
	}
	await new Promise((resolve) => setTimeout(resolve, 10));
} finally {
	clearInterval(timer);
}
durations.sort((a, b) => a - b);
console.log(
	JSON.stringify(
		{
			runtime: process.version,
			mode,
			concurrency,
			memoryKiB: input.memoryKiB,
			passes: input.passes,
			parallelism: input.parallelism,
			medianCallMs: durations[Math.floor(durations.length / 2)],
			baselineRssMiB: baselineRss / 1048576,
			processPeakRssMiB: process.resourceUsage().maxRSS / 1024,
			largestTimerDelayMs,
		},
		null,
		2,
	),
);
