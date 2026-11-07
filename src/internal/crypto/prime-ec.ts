/** Prime-field curve parameters and membership checks for public affine coordinates. @module */

import { toHex } from '#micro509/internal/asn1/asn1';

/** NIST prime curves used by existing key and SSH workflows. */
type PrimeEcCurveName = 'P-256' | 'P-384' | 'P-521';

/** Public parameters of a curve with equation y² = x³ - 3x + b over its prime field. */
interface PrimeEcCurve {
	readonly size: number;
	readonly prime: bigint;
	readonly b: bigint;
}

/** Shared parameters, including those used to decompress SSH public points. */
export const PRIME_EC_CURVES: Readonly<Record<PrimeEcCurveName, PrimeEcCurve>> = {
	'P-256': {
		size: 32,
		prime: 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n,
		b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
	},
	'P-384': {
		size: 48,
		prime: 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n,
		b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
	},
	'P-521': {
		size: 66,
		prime: 2n ** 521n - 1n,
		b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
	},
};

/**
 * Checks fixed-width public coordinates before synchronous key selection. These curves have
 * cofactor one; finite field coordinates satisfying the equation represent a valid public point.
 * Signature operations and key import still run through WebCrypto.
 */
export function isPrimeEcPoint(curve: PrimeEcCurveName, x: Uint8Array, y: Uint8Array): boolean {
	const { size, prime, b } = PRIME_EC_CURVES[curve];
	if (x.length !== size || y.length !== size) return false;
	const xValue = BigInt(`0x${toHex(x)}`);
	const yValue = BigInt(`0x${toHex(y)}`);
	if (xValue >= prime || yValue >= prime) return false;
	const rhs = ((((xValue * xValue - 3n) * xValue + b) % prime) + prime) % prime;
	return (yValue * yValue) % prime === rhs;
}
