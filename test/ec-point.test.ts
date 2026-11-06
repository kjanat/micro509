import { describe, expect, it } from 'bun:test';
import { isPrimeEcPoint } from '#micro509/internal/crypto/prime-ec';

for (const [curve, width] of [
	['P-256', 32],
	['P-384', 48],
	['P-521', 66],
] as const) {
	describe(curve, () => {
		it('accepts WebCrypto public points and rejects malformed, off-curve and out-of-field coordinates', async () => {
			const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, [
				'sign',
				'verify',
			]);
			const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
			const x = raw.slice(1, 1 + width);
			const y = raw.slice(1 + width);
			expect(isPrimeEcPoint(curve, x, y)).toBe(true);
			expect(isPrimeEcPoint(curve, x.slice(1), y)).toBe(false);
			expect(isPrimeEcPoint(curve, x, y.slice(1))).toBe(false);
			expect(isPrimeEcPoint(curve, new Uint8Array(width), new Uint8Array(width))).toBe(false);
			expect(isPrimeEcPoint(curve, new Uint8Array(width).fill(255), y)).toBe(false);
			expect(isPrimeEcPoint(curve, x, new Uint8Array(width).fill(255))).toBe(false);
		});
	});
}
