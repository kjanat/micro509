/**
 * RFC 3492 Punycode, the Bootstring profile IDNA2008 uses to carry a U-label
 * as the ASCII part of an A-label.
 *
 * @module
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 0x80;
const DELIMITER = 0x2d;
const MAX_CODE_POINT = 0x10ffff;
const MAX_INT = 0x7fffffff;

/** RFC 3492 §6.1 bias adaptation. */
function adapt(delta: number, numPoints: number, firstTime: boolean): number {
	let scaled = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
	scaled += Math.floor(scaled / numPoints);
	let k = 0;
	while (scaled > ((BASE - TMIN) * TMAX) >> 1) {
		scaled = Math.floor(scaled / (BASE - TMIN));
		k += BASE;
	}
	return k + Math.floor(((BASE - TMIN + 1) * scaled) / (scaled + SKEW));
}

function threshold(k: number, bias: number): number {
	return k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
}

/** RFC 3492 §5 lowercase digit for `digit` in 0..35. */
function encodeDigit(digit: number): number {
	return digit < 26 ? digit + 0x61 : digit + 0x16;
}

/** RFC 3492 §5 value of a basic code point, or `undefined` when it is not a digit. */
function decodeDigit(codePoint: number): number | undefined {
	if (codePoint >= 0x30 && codePoint <= 0x39) return codePoint - 0x16;
	if (codePoint >= 0x41 && codePoint <= 0x5a) return codePoint - 0x41;
	if (codePoint >= 0x61 && codePoint <= 0x7a) return codePoint - 0x61;
	return undefined;
}

/**
 * RFC 3492 §6.3 encoding of a code point sequence, without an ACE prefix.
 *
 * @throws {RangeError} on overflow (§6.4).
 */
export function punycodeEncode(input: string): string {
	const codePoints = Array.from(input, (character) => character.codePointAt(0) ?? 0);
	const output: number[] = codePoints.filter((codePoint) => codePoint < INITIAL_N);
	const basicCount = output.length;
	let handled = basicCount;
	if (basicCount > 0) output.push(DELIMITER);
	let n = INITIAL_N;
	let delta = 0;
	let bias = INITIAL_BIAS;
	while (handled < codePoints.length) {
		const next = Math.min(...codePoints.filter((codePoint) => codePoint >= n));
		if (next - n > Math.floor((MAX_INT - delta) / (handled + 1))) {
			throw new RangeError('Punycode overflow');
		}
		delta += (next - n) * (handled + 1);
		n = next;
		for (const codePoint of codePoints) {
			if (codePoint < n && ++delta > MAX_INT) {
				throw new RangeError('Punycode overflow');
			}
			if (codePoint !== n) continue;
			let q = delta;
			for (let k = BASE; ; k += BASE) {
				const t = threshold(k, bias);
				if (q < t) break;
				output.push(encodeDigit(t + ((q - t) % (BASE - t))));
				q = Math.floor((q - t) / (BASE - t));
			}
			output.push(encodeDigit(q));
			bias = adapt(delta, handled + 1, handled === basicCount);
			delta = 0;
			handled += 1;
		}
		delta += 1;
		n += 1;
	}
	return String.fromCharCode(...output);
}

/**
 * RFC 3492 §6.2 generalized variable-length integer starting at `position`,
 * added to `i`.
 *
 * @throws {RangeError} on a bad digit, end of input, or overflow (§6.4).
 */
function readDelta(
	input: string,
	position: number,
	i: number,
	bias: number,
): { readonly i: number; readonly position: number } {
	let next = i;
	let cursor = position;
	let w = 1;
	for (let k = BASE; ; k += BASE) {
		if (cursor >= input.length) throw new RangeError('Punycode input ends mid-number');
		const digit = decodeDigit(input.charCodeAt(cursor));
		cursor += 1;
		if (digit === undefined) throw new RangeError('Punycode input has a bad digit');
		if (digit > Math.floor((MAX_INT - next) / w)) throw new RangeError('Punycode overflow');
		next += digit * w;
		const t = threshold(k, bias);
		if (digit < t) return { i: next, position: cursor };
		if (w > Math.floor(MAX_INT / (BASE - t))) throw new RangeError('Punycode overflow');
		w *= BASE - t;
	}
}

/**
 * RFC 3492 §6.2 decoding of a Punycode string, without an ACE prefix.
 *
 * @throws {RangeError} on a non-basic code point, a bad digit, or overflow (§6.4).
 */
export function punycodeDecode(input: string): string {
	for (let index = 0; index < input.length; index += 1) {
		if (input.charCodeAt(index) >= INITIAL_N) {
			throw new RangeError('Punycode input must be ASCII');
		}
	}
	const delimiterIndex = input.lastIndexOf('-');
	const output: number[] =
		delimiterIndex > 0
			? Array.from(input.slice(0, delimiterIndex), (character) => character.charCodeAt(0))
			: [];
	let position = delimiterIndex > 0 ? delimiterIndex + 1 : 0;
	let n = INITIAL_N;
	let i = 0;
	let bias = INITIAL_BIAS;
	while (position < input.length) {
		const oldI = i;
		({ i, position } = readDelta(input, position, i, bias));
		const length = output.length + 1;
		bias = adapt(i - oldI, length, oldI === 0);
		if (Math.floor(i / length) > MAX_INT - n) throw new RangeError('Punycode overflow');
		n += Math.floor(i / length);
		i %= length;
		if (n > MAX_CODE_POINT || (n >= 0xd800 && n <= 0xdfff)) {
			throw new RangeError('Punycode decodes to an invalid code point');
		}
		output.splice(i, 0, n);
		i += 1;
	}
	return String.fromCodePoint(...output);
}
