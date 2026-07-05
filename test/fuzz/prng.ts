/**
 * Tiny seeded PRNG for the OpenSSL differential fuzzer.
 *
 * `mulberry32` is a well-known 32-bit generator: fast, dependency-free, and —
 * crucially — deterministic from a seed so a failing fuzz iteration reproduces
 * its *parameter draw* exactly (the OpenSSL-generated key bytes stay random,
 * which widens coverage across runs; the offending artifact is dumped on
 * failure for a permanent repro).
 */

export interface Rng {
	/** Next float in [0, 1). */
	next(): number;
	/** Integer in [0, maxExclusive). */
	int(maxExclusive: number): number;
	/** Uniformly pick one element. */
	pick<T>(items: readonly T[]): T;
	/** True with probability `p` (default 0.5). */
	bool(p?: number): boolean;
	/** Lowercase hex string of `byteLength` random bytes. */
	hex(byteLength: number): string;
}

/** Construct a deterministic {@link Rng} from a 32-bit seed. */
export function makeRng(seed: number): Rng {
	let state = seed >>> 0;
	const next = (): number => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 0x1_0000_0000;
	};
	const int = (maxExclusive: number): number => Math.floor(next() * maxExclusive);
	return {
		next,
		int,
		pick: <T>(items: readonly T[]): T => {
			const item = items[int(items.length)];
			if (item === undefined) throw new Error('makeRng.pick called on an empty array');
			return item;
		},
		bool: (p = 0.5): boolean => next() < p,
		hex: (byteLength: number): string => {
			let out = '';
			for (let i = 0; i < byteLength; i += 1) out += int(256).toString(16).padStart(2, '0');
			return out;
		},
	};
}
