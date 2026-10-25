/**
 * Exact high word of an unsigned 32×32 product; `low` is Math.imul(a, b).
 *
 * Subtracting the exact low word leaves a multiple of 2^32 with at most 2048
 * units of floating-point error. Scaling by 2^32 reduces that error below
 * 2^-20, so adding 0.5 and truncating recovers the exact integer high word.
 * BlaMka already computes the low word and passes it here for reuse.
 */
export function multiplyHigh(a: number, b: number, low: number): number {
	return ((a * b - (low >>> 0)) / 0x1_0000_0000 + 0.5) >>> 0;
}
