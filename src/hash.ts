/**
 * Internal digest helpers used where WebCrypto portability or legacy compatibility
 * requires local hashing.
 *
 * The implementations stay narrow on purpose and only cover the algorithms this library
 * still needs internally.
 */

// ── Shared Merkle–Damgård primitives ──────────────────────────────

/** Unsigned 32-bit left-rotate. */
function rotl(x: number, n: number): number {
	return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * Merkle–Damgård padding: append 0x80, zero-pad to 56 mod 64,
 * append original bit-length as 64-bit integer.
 */
function mdPad(data: Uint8Array, littleEndian: boolean): Uint8Array {
	const bitLen = BigInt(data.length) * 8n;
	const padded = new Uint8Array(Math.ceil((data.length + 1 + 8) / 64) * 64);
	padded.set(data);
	padded[data.length] = 0x80;
	const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
	view.setBigUint64(padded.length - 8, bitLen, littleEndian);
	return padded;
}

/** Bounds-checked read from a readonly number table. */
function tbl(arr: readonly number[], i: number): number {
	const v = arr[i];
	if (v === undefined) throw new RangeError(`table index ${i}`);
	return v;
}

/** Bounds-checked read from a Uint32Array. */
function w32(arr: Uint32Array, i: number): number {
	const v = arr[i];
	if (v === undefined) throw new RangeError(`word index ${i}`);
	return v;
}

// ── MD5 (RFC 1321) ───────────────────────────────────────────────

/**
 * Defines the md5 s used by this module.
 */
const MD5_S = /* dprint-ignore */ [
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
	20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6,
	10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
] as const satisfies readonly number[];

/**
 * Defines the md5 k used by this module.
 */
const MD5_K = /* dprint-ignore */ [
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
] as const satisfies readonly number[];

/**
 * Computes the MD5 digest for the provided bytes.
 *
 * @param data The raw bytes to process.
 * @returns The MD5 digest bytes.
 */
export function md5(data: Uint8Array): Uint8Array<ArrayBuffer> {
	const padded = mdPad(data, true);

	let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

	const M = new Uint32Array(16);

	for (let offset = 0; offset < padded.length; offset += 64) {
		const view = new DataView(padded.buffer, padded.byteOffset + offset, 64);
		for (let j = 0; j < 16; j++) {
			M[j] = view.getUint32(j * 4, true);
		}

		let [A, B, C, D] = [a0, b0, c0, d0];

		for (let i = 0; i < 64; i++) {
			let F: number;
			let g: number;

			if (i < 16) {
				F = ((B & C) | (~B & D)) >>> 0;
				g = i;
			} else if (i < 32) {
				F = ((D & B) | (~D & C)) >>> 0;
				g = (5 * i + 1) & 15;
			} else if (i < 48) {
				F = (B ^ C ^ D) >>> 0;
				g = (3 * i + 5) & 15;
			} else {
				F = (C ^ (B | ~D)) >>> 0;
				g = (7 * i) & 15;
			}

			F = (F + A + tbl(MD5_K, i) + w32(M, g)) >>> 0;
			const oldD = D;
			D = C;
			C = B;
			B = (B + rotl(F, tbl(MD5_S, i))) >>> 0;
			A = oldD;
		}

		a0 = (a0 + A) >>> 0;
		b0 = (b0 + B) >>> 0;
		c0 = (c0 + C) >>> 0;
		d0 = (d0 + D) >>> 0;
	}

	const out = new Uint8Array(16);
	const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
	dv.setUint32(0, a0, true);
	dv.setUint32(4, b0, true);
	dv.setUint32(8, c0, true);
	dv.setUint32(12, d0, true);
	return out;
}

// ── SHA-1 (RFC 3174) ─────────────────────────────────────────────

/**
 * Computes the SHA-1 digest for the provided bytes.
 *
 * @param data The raw bytes to process.
 * @returns The SHA-1 digest bytes.
 */
export function sha1(data: Uint8Array): Uint8Array<ArrayBuffer> {
	const padded = mdPad(data, false);

	let [h0, h1, h2, h3, h4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

	const W = new Uint32Array(80);
	const pv = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);

	for (let off = 0; off < padded.length; off += 64) {
		for (let i = 0; i < 16; i++) {
			W[i] = pv.getUint32(off + i * 4, false);
		}
		for (let i = 16; i < 80; i++) {
			W[i] = rotl(w32(W, i - 3) ^ w32(W, i - 8) ^ w32(W, i - 14) ^ w32(W, i - 16), 1);
		}

		let [a, b, c, d, e] = [h0, h1, h2, h3, h4];

		for (let i = 0; i < 80; i++) {
			let f: number;
			let k: number;

			if (i <= 19) {
				f = ((b & c) | (~b & d)) >>> 0;
				k = 0x5a827999;
			} else if (i <= 39) {
				f = (b ^ c ^ d) >>> 0;
				k = 0x6ed9eba1;
			} else if (i <= 59) {
				f = ((b & c) | (b & d) | (c & d)) >>> 0;
				k = 0x8f1bbcdc;
			} else {
				f = (b ^ c ^ d) >>> 0;
				k = 0xca62c1d6;
			}

			const temp = (rotl(a, 5) + f + e + k + w32(W, i)) >>> 0;
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = temp;
		}

		h0 = (h0 + a) >>> 0;
		h1 = (h1 + b) >>> 0;
		h2 = (h2 + c) >>> 0;
		h3 = (h3 + d) >>> 0;
		h4 = (h4 + e) >>> 0;
	}

	const out = new Uint8Array(20);
	const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
	dv.setUint32(0, h0, false);
	dv.setUint32(4, h1, false);
	dv.setUint32(8, h2, false);
	dv.setUint32(12, h3, false);
	dv.setUint32(16, h4, false);
	return out;
}
