/**
 * Low-level DER encoding and reading helpers shared across the library.
 *
 * These utilities build and traverse ASN.1 TLV (tag-length-value) structures.
 *
 * @module
 */

import { throwDecodeRefusal } from '#micro509/internal/asn1/decode-refusal';

/**
 * Maximum nesting depth allowed when recursively walking a DER structure.
 *
 * Guards against stack exhaustion from pathologically nested input.
 */
export const DEFAULT_MAX_DER_DEPTH = 64;

/**
 * Produces the DER length octets for a given byte count.
 *
 * Values < 128 use the short form (one octet);
 * larger values use the long form (leading octet encodes the number of subsequent length bytes).
 */
export function encodeLength(length: number): Uint8Array {
	assertNonNegativeSafeInteger(length, 'DER length');
	if (length < 128) {
		return Uint8Array.of(length);
	}

	const parts = encodeBase256(length);
	return Uint8Array.of(0x80 | parts.length, ...parts);
}

/** Concatenates multiple byte arrays into a single {@linkcode Uint8Array}. */
export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
	const length = parts.reduce((sum, part) => sum + part.length, 0);
	const out = new Uint8Array(length);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

/** Compares two optional byte arrays; two absent values are equal. */
export function optionalBytesEqual(
	left: Uint8Array | undefined,
	right: Uint8Array | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

/**
 * Builds a complete DER TLV (tag-length-value) element:
 *
 * - one tag octet,
 * - the DER-encoded length, then
 * - the raw value bytes.
 */
export function tlv(tag: number, value: Uint8Array): Uint8Array {
	assertSingleOctetDerTag(tag);
	return concatBytes([Uint8Array.of(tag), encodeLength(value.length), value]);
}

/** Wraps concatenated children in a SEQUENCE (tag `0x30`). */
export function sequence(parts: readonly Uint8Array[]): Uint8Array {
	return tlv(0x30, concatBytes(parts));
}

/**
 * Wraps children in a SET (tag `0x31`) after DER-sorting them lexicographically by encoded bytes,
 * as required by {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690} DER.
 */
export function setOf(parts: readonly Uint8Array[]): Uint8Array {
	const sorted = parts.slice().sort((a, b) => {
		const len = Math.min(a.length, b.length);
		for (let i = 0; i < len; i++) {
			const diff = (a[i] ?? 0) - (b[i] ?? 0);
			if (diff !== 0) return diff;
		}
		return a.length - b.length;
	});
	return tlv(0x31, concatBytes(sorted));
}

/**
 * Wraps a value in an explicit context-specific constructed tag (`0xa0 + tag`).
 *
 * Used for optional SEQUENCE fields tagged with `[tag] EXPLICIT`.
 */
export function explicitContext(tag: number, value: Uint8Array): Uint8Array {
	assertContextSpecificTagNumber(tag);
	return tlv(0xa0 + tag, value);
}

/**
 * Wraps a value in an implicit context-specific constructed tag (`0xa0 + tag`).
 *
 * Used for `[tag] IMPLICIT` fields whose underlying type is constructed (e.g. SEQUENCE).
 */
export function implicitConstructedContext(tag: number, value: Uint8Array): Uint8Array {
	assertContextSpecificTagNumber(tag);
	return tlv(0xa0 + tag, value);
}

/**
 * Wraps a value in an implicit context-specific primitive tag (`0x80 + tag`).
 *
 * Used for `[tag] IMPLICIT` fields whose underlying type is primitive (e.g. OCTET STRING).
 */
export function implicitPrimitiveContext(tag: number, value: Uint8Array): Uint8Array {
	assertContextSpecificTagNumber(tag);
	return tlv(0x80 + tag, value);
}

/**
 * Encodes raw big-endian bytes as a DER INTEGER (tag `0x02`).
 *
 * Strips leading zero bytes for minimal encoding and prepends a zero byte when the high bit is set
 * to keep the value non-negative.
 */
export function integer(bytes: Uint8Array): Uint8Array {
	if (bytes.length === 0) {
		return tlv(0x02, Uint8Array.of(0));
	}

	let start = 0;
	while (start < bytes.length - 1 && bytes[start] === 0) {
		start += 1;
	}

	const value = bytes.slice(start);
	if ((value[0] ?? 0) >= 0x80) {
		return tlv(0x02, concatBytes([Uint8Array.of(0), value]));
	}

	return tlv(0x02, value);
}

/**
 * Encodes a non-negative JavaScript `number` as a DER INTEGER.
 *
 * @throws if the value is not a non-negative safe integer.
 */
export function integerFromNumber(value: number): Uint8Array {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error('INTEGER must be a non-negative safe integer');
	}

	if (value === 0) {
		return integer(Uint8Array.of(0));
	}

	return integer(Uint8Array.from(encodeBase256(value)));
}

/** Encodes a DER ENUMERATED (tag `0x0a`) from a non-negative safe integer. */
export function enumeratedFromNumber(value: number): Uint8Array {
	return concatBytes([Uint8Array.of(0x0a), integerFromNumber(value).subarray(1)]);
}

/** Encodes a DER BOOLEAN (tag `0x01`): `true` → `0xff`, `false` → `0x00`. */
export function bool(value: boolean): Uint8Array {
	return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

/** Produces a DER NULL element (tag `0x05`, zero-length value). */
export function nullValue(): Uint8Array {
	return tlv(0x05, new Uint8Array());
}

/** Wraps raw bytes in an OCTET STRING element (tag `0x04`). */
export function octetString(value: Uint8Array): Uint8Array {
	return tlv(0x04, value);
}

/**
 * Encodes a DER BIT STRING (tag `0x03`).
 *
 * The value is prefixed with a single octet indicating how many trailing bits in the last byte are unused.
 *
 * @param unusedBits Number of unused trailing bits (0–7). Defaults to 0.
 */
export function bitString(value: Uint8Array, unusedBits = 0): Uint8Array {
	if (unusedBits < 0 || unusedBits > 7) {
		throw new Error('unusedBits must be between 0 and 7');
	}
	if (value.length === 0 && unusedBits !== 0) {
		throw new Error('unusedBits must be 0 when value is empty');
	}
	if (value.length > 0 && unusedBits > 0) {
		const lastByte = value[value.length - 1] ?? 0;
		if ((lastByte & ((1 << unusedBits) - 1)) !== 0) {
			throw new Error('unused bits in the last byte must be zero');
		}
	}
	return tlv(0x03, concatBytes([Uint8Array.of(unusedBits), value]));
}

export function hasLoneSurrogate(value: string): boolean {
	for (let index = 0; index < value.length; index += 1) {
		const unit = value.charCodeAt(index);
		if (unit >= 0xd800 && unit <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				index += 1;
				continue;
			}
			return true;
		}
		if (unit >= 0xdc00 && unit <= 0xdfff) {
			return true;
		}
	}
	return false;
}

/**
 * Encodes a DER UTF8String (tag `0x0c`).
 *
 * @throws on a lone surrogate, which has no UTF-8 encoding.
 */
export function utf8String(value: string): Uint8Array {
	if (hasLoneSurrogate(value)) {
		throw new Error('Invalid UTF8String: lone surrogate');
	}
	return tlv(0x0c, new TextEncoder().encode(value));
}

/**
 * Encodes a DER PrintableString (tag `0x13`).
 *
 * @throws if the input contains characters outside the ITU-T X.680 §41.4 Table 10 PrintableString set.
 */
export function printableString(value: string): Uint8Array {
	if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
		throw new Error('Invalid PrintableString: contains characters outside the allowed set');
	}
	return tlv(0x13, new TextEncoder().encode(value));
}

/**
 * Encodes a DER VisibleString (tag `0x1a`).
 *
 * @throws if the input contains a character outside the printable ASCII range 0x20 to 0x7e.
 */
export function visibleString(value: string): Uint8Array {
	if (!/^[\x20-\x7e]*$/.test(value)) {
		throw new Error('Invalid VisibleString: contains characters outside 0x20 to 0x7e');
	}
	return tlv(0x1a, new TextEncoder().encode(value));
}

/** Validates a string is ASCII (IA5) and returns its content bytes, without a tag. */
export function ia5Bytes(value: string): Uint8Array {
	for (let i = 0; i < value.length; i++) {
		if (value.charCodeAt(i) > 0x7f) {
			throw new Error('Invalid IA5String: contains non-ASCII characters');
		}
	}
	return new TextEncoder().encode(value);
}

/**
 * Encodes a DER IA5String (tag `0x16`).
 *
 * @throws if the input contains any non-ASCII character (code point > 0x7f).
 */
export function ia5String(value: string): Uint8Array {
	return tlv(0x16, ia5Bytes(value));
}

/**
 * Encodes a DER BMPString (tag `0x1e`) as big-endian UTF-16.
 *
 * @throws on lone surrogates, on U+FFFE and U+FFFF, which X.680 §41.15 leaves
 * out of BMPString, and on code points above the Basic Multilingual Plane.
 */
export function bmpString(value: string): Uint8Array {
	const units: number[] = [];
	for (const character of value) {
		const codePoint = character.codePointAt(0) ?? 0;
		if (codePoint > 0xffff) {
			throw new Error('Invalid BMPString: code point above the Basic Multilingual Plane');
		}
		if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
			throw new Error('Invalid BMPString: lone surrogate');
		}
		if (codePoint >= 0xfffe) {
			throw new Error('Invalid BMPString: U+FFFE and U+FFFF are not BMPString characters');
		}
		units.push((codePoint >> 8) & 0xff, codePoint & 0xff);
	}
	return tlv(0x1e, Uint8Array.from(units));
}

/**
 * Encodes a DER UniversalString (tag `0x1c`) as big-endian UTF-32.
 *
 * @throws on lone surrogates.
 */
export function universalString(value: string): Uint8Array {
	const bytes: number[] = [];
	for (const character of value) {
		const codePoint = character.codePointAt(0) ?? 0;
		if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
			throw new Error('Invalid UniversalString: lone surrogate');
		}
		bytes.push(
			(codePoint >> 24) & 0xff,
			(codePoint >> 16) & 0xff,
			(codePoint >> 8) & 0xff,
			codePoint & 0xff,
		);
	}
	return tlv(0x1c, Uint8Array.from(bytes));
}

/** micro509's bound on one OBJECT IDENTIFIER sub-identifier's base-128 encoding; X.660 §7.6 leaves arc values unbounded. */
export const MAX_OID_SUBIDENTIFIER_OCTETS = 64;

const OID_SUBIDENTIFIER_LIMIT = 1n << BigInt(7 * MAX_OID_SUBIDENTIFIER_OCTETS);

const OID_SUBIDENTIFIER_MAX_DIGITS = OID_SUBIDENTIFIER_LIMIT.toString().length;

function parseOidArc(segment: string): bigint {
	if (!/^\d+$/.test(segment)) {
		throw new Error(`Invalid OID segment: ${segment}`);
	}
	const significant = segment.replace(/^0+/, '');
	if (significant.length > OID_SUBIDENTIFIER_MAX_DIGITS) {
		throwOidLimit();
	}
	return BigInt(significant.length === 0 ? '0' : significant);
}

function throwOidLimit(): never {
	return throwDecodeRefusal(
		'limit_exceeded',
		`OID sub-identifier exceeds ${MAX_OID_SUBIDENTIFIER_OCTETS} octets`,
	);
}

/** Encode a non-negative integer as a base-128 sub-identifier ({@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §8.19.2}). */
function encodeBase128(value: bigint): number[] {
	if (value >= OID_SUBIDENTIFIER_LIMIT) {
		throwOidLimit();
	}
	const reversed: number[] = [Number(value & 0x7fn)];
	for (let current = value >> 7n; current > 0n; current >>= 7n) {
		reversed.push(0x80 | Number(current & 0x7fn));
	}
	return reversed.reverse();
}

/**
 * Encodes a dotted-decimal OID string as a DER OBJECT IDENTIFIER (tag `0x06`).
 *
 * Validates arc constraints per X.660 §7.6: the root arc must be 0–2, and under
 * roots 0 and 1 the second arc must be 0–39. X.690 §8.19.4 defines the `(X*40)+Y`
 * packing of the first two arcs into one subidentifier.\
 * Sub-identifiers are encoded with base-128 continuation.
 */
export function objectIdentifier(oid: string): Uint8Array {
	const segments = oid.split('.').map(parseOidArc);
	if (segments.length < 2) {
		throw new Error(`Invalid OID: ${oid}`);
	}

	const [first, second, ...rest] = segments;
	if (first === undefined || second === undefined) {
		throw new Error(`Invalid OID: ${oid}`);
	}
	if (first !== 0n && first !== 1n && first !== 2n) {
		throw new Error(`Invalid OID first arc: ${first}`);
	}
	if ((first === 0n || first === 1n) && second >= 40n) {
		throw new Error(`Invalid OID second arc: ${second} (must be < 40 when first arc is ${first})`);
	}
	const bytes: number[] = encodeBase128(first * 40n + second);
	for (const segment of rest) {
		bytes.push(...encodeBase128(segment));
	}

	return tlv(0x06, Uint8Array.from(bytes));
}

/**
 * Encodes a `Date` as a DER UTCTime (tag `0x17`), format `YYMMDDHHMMSSZ`.
 *
 * Only the two-digit year is stored; suitable for dates in 1950–2049.
 */
export function utcTime(date: Date): Uint8Array {
	assertValidDate(date, 'UTCTime');
	const year = date.getUTCFullYear();
	if (year < 1950 || year > 2049) {
		throw new RangeError('UTCTime year must be between 1950 and 2049');
	}
	const value = `${[
		twoDigits(year % 100),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x17, new TextEncoder().encode(value));
}

/**
 * Encodes a {@linkcode Date} as a DER GeneralizedTime (tag `0x18`), format `YYYYMMDDHHMMSSZ`.
 *
 * Uses a four-digit year; required for dates outside the 1950–2049 range.
 */
export function generalizedTime(date: Date): Uint8Array {
	assertValidDate(date, 'GeneralizedTime');
	const year = date.getUTCFullYear();
	if (year < 0 || year > 9999) {
		throw new RangeError('GeneralizedTime year must be between 0 and 9999');
	}
	const value = `${[
		String(year).padStart(4, '0'),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x18, new TextEncoder().encode(value));
}

/**
 * Encodes a {@linkcode Date} as the appropriate DER time type per RFC 5280.
 *
 * - {@linkcode utcTime} for 1950–2049
 * - {@linkcode generalizedTime} otherwise
 */
export function time(date: Date): Uint8Array {
	if (date.getUTCFullYear() >= 2050 || date.getUTCFullYear() < 1950) {
		return generalizedTime(date);
	}
	return utcTime(date);
}

/** Zero-pads a number to two digits for time encoding. */
function twoDigits(value: number): string {
	return String(value).padStart(2, '0');
}

/** Encodes a non-negative integer as big-endian base-256 octets. */
function encodeBase256(value: number): readonly number[] {
	assertNonNegativeSafeInteger(value, 'DER integer');
	const parts: number[] = [];
	let current = value;
	while (current > 0) {
		parts.unshift(current & 0xff);
		current = Math.floor(current / 256);
	}
	return parts;
}

/** A single parsed ASN.1 TLV element with byte-range metadata. */
export interface DerElement {
	/** Leading identifier octet (e.g. `0x30` for SEQUENCE, `0x02` for INTEGER, `0x9f` for any context-specific primitive tag from 31 up). */
	readonly tag: number;
	/** Tag number within the class, from the leading octet below 31 and from the subsequent identifier octets from 31 up. */
	readonly tagNumber: number;
	/** Number of bytes occupied by the identifier and length octets. */
	readonly headerLength: number;
	/** Byte length of the value portion (excluding tag and length octets). */
	readonly length: number;
	/** Byte offset where the value portion begins in the source buffer. */
	readonly start: number;
	/** Byte offset one past the last value byte. Equals the next element's header offset. */
	readonly end: number;
	/** The raw value bytes (slice of the source buffer). */
	readonly value: Uint8Array;
}

/** Options for {@linkcode readSequenceChildren}. */
export interface ReadSequenceChildrenOptions {
	/** Maximum nesting depth for the DER depth check. @default {@linkcode DEFAULT_MAX_DER_DEPTH}. */
	readonly maxDepth?: number;
	/** Constructed tags whose inner bytes may not parse as valid TLV children (e.g. opaque extension values). */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/** Options for {@linkcode readRootElement}. */
export interface ReadRootElementOptions {
	/** Maximum nesting depth for the DER depth check. @default {@linkcode DEFAULT_MAX_DER_DEPTH}. */
	readonly maxDepth?: number;
	/** Constructed tags whose inner bytes may not parse as valid TLV children (e.g. opaque extension values). */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/** The identifier octets of a BER or DER element. */
export interface Identifier {
	/** Leading identifier octet. */
	readonly tag: number;
	/** Tag number within the class. */
	readonly tagNumber: number;
	/** Number of identifier octets. */
	readonly length: number;
}

/**
 * Reads the identifier octets at {@linkcode offset} by X.690 §8.1.2, which BER
 * and DER share.
 *
 * @throws on truncated identifier octets, a high-tag-number form with a leading
 * zero group or a tag number below 31, and `limit_exceeded` on a tag number
 * above {@linkcode Number.MAX_SAFE_INTEGER}.
 */
export function readIdentifier(bytes: Uint8Array, offset: number): Identifier {
	const tag = bytes[offset];
	if (tag === undefined) {
		throw new Error('Unexpected end of identifier octets');
	}
	if ((tag & 0x1f) !== 0x1f) {
		return { tag, tagNumber: tag & 0x1f, length: 1 };
	}
	if (bytes[offset + 1] === 0x80) {
		throw new Error('High-tag-number form must not open with a zero group');
	}
	let end = offset + 1;
	while (((bytes[end] ?? 0) & 0x80) !== 0) {
		end += 1;
	}
	if (bytes[end] === undefined) {
		throw new Error('Unexpected end of identifier octets');
	}
	let tagNumber = 0;
	for (let index = offset + 1; index <= end; index += 1) {
		const group = (bytes[index] ?? 0) & 0x7f;
		if (tagNumber > (Number.MAX_SAFE_INTEGER - group) / 128) {
			throwDecodeRefusal('limit_exceeded', 'Tag number exceeds Number.MAX_SAFE_INTEGER');
		}
		tagNumber = tagNumber * 128 + group;
	}
	if (tagNumber < 31) {
		throw new Error('Tag numbers below 31 must use the low-tag-number form');
	}
	return { tag, tagNumber, length: end - offset + 1 };
}

/**
 * Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
 *
 * Parses the identifier octets, decodes the DER length octets, and slices out the value bytes.
 *
 * @throws on truncated input, malformed identifier octets, indefinite lengths, and non-minimal length encodings.
 * @param offset Byte position of the leading identifier octet. Defaults to 0.
 */
export function readElement(bytes: Uint8Array, offset = 0): DerElement {
	if (bytes[offset] === undefined) {
		throw new Error('Unexpected end of DER input');
	}
	const identifier = readIdentifier(bytes, offset);
	const lengthOffset = offset + identifier.length;
	const lengthByte = bytes[lengthOffset];
	if (lengthByte === undefined) {
		throw new Error('Unexpected end of DER input');
	}

	const { lengthOctets, length } = readDerLength(bytes, lengthOffset, lengthByte);

	const headerLength = identifier.length + lengthOctets;
	const start = offset + headerLength;
	const end = start + length;
	if (end > bytes.length) {
		throw new Error('DER element exceeds input length');
	}

	return {
		tag: identifier.tag,
		tagNumber: identifier.tagNumber,
		headerLength,
		length,
		start,
		end,
		value: bytes.slice(start, end),
	};
}

/** Decodes and validates the definite-length field of a DER element. */
function readDerLength(
	bytes: Uint8Array,
	lengthOffset: number,
	lengthByte: number,
): { readonly lengthOctets: number; readonly length: number } {
	if ((lengthByte & 0x80) === 0) {
		return { lengthOctets: 1, length: lengthByte };
	}
	const octets = lengthByte & 0x7f;
	if (octets === 0) {
		throw new Error('Indefinite lengths are not supported');
	}
	const firstLengthOctet = bytes[lengthOffset + 1];
	if (firstLengthOctet === undefined) {
		throw new Error('Unexpected end of DER input');
	}
	if (firstLengthOctet === 0) {
		throw new Error('Non-minimal DER length encoding');
	}
	const length = readLongFormDerLength(bytes, lengthOffset, octets);
	if (length < 128) {
		throw new Error('Non-minimal DER length encoding');
	}
	return { lengthOctets: 1 + octets, length };
}

function readLongFormDerLength(bytes: Uint8Array, lengthOffset: number, octets: number): number {
	let length = 0;
	for (let index = 0; index < octets; index += 1) {
		const next = bytes[lengthOffset + 1 + index];
		if (next === undefined) {
			throw new Error('Unexpected end of DER input');
		}
		if (length > Math.floor((Number.MAX_SAFE_INTEGER - next) / 256)) {
			throw new Error('DER length exceeds safe integer range');
		}
		length = length * 256 + next;
	}
	return length;
}

/**
 * Walks the full DER tree rooted in {@linkcode bytes}.
 *
 * Constructed tags with content that cannot be parsed as valid children are tolerated when listed in {@linkcode options | allowOpaqueConstructedTags}.
 *
 * @throws if nesting exceeds {@linkcode maxDepth}.
 */
export function assertDerMaxDepth(
	bytes: Uint8Array,
	maxDepth: number = DEFAULT_MAX_DER_DEPTH,
	options?: {
		/** Constructed tags whose inner bytes may not parse as valid TLV children. */
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
): void {
	walkDerTree(bytes, maxDepth, options, () => undefined);
}

/**
 * Walks the full DER tree rooted in {@linkcode bytes}, calling {@linkcode visit}
 * on each element before reading its children.
 *
 * @throws if the tree is malformed or nests beyond {@linkcode maxDepth}.
 */
export function walkDerTree(
	bytes: Uint8Array,
	maxDepth: number,
	options: { readonly allowOpaqueConstructedTags?: readonly number[] } | undefined,
	visit: (element: DerElement) => void,
): void {
	if (!Number.isSafeInteger(maxDepth) || maxDepth < 1) {
		throw new Error('DER max depth must be a positive safe integer');
	}
	const root = readElement(bytes, 0);
	if (root.end !== bytes.length) {
		throw new Error('Trailing data after DER element');
	}
	const stack: {
		readonly element: DerElement;
		readonly depth: number;
	}[] = [{ element: root, depth: 1 }];
	while (stack.length > 0) {
		const current = stack.pop();
		if (current === undefined) {
			continue;
		}
		if (current.depth > maxDepth) {
			throwDecodeRefusal('limit_exceeded', `DER exceeds max depth of ${maxDepth}`);
		}
		visit(current.element);
		if ((current.element.tag & 0x20) === 0) {
			continue;
		}
		pushDerChildren(bytes, current, stack, options);
	}
}

function pushDerChildren(
	bytes: Uint8Array,
	current: { readonly element: DerElement; readonly depth: number },
	stack: { readonly element: DerElement; readonly depth: number }[],
	options?: {
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
): void {
	let offset = current.element.start;
	let treatedAsOpaqueLeaf = false;
	while (offset < current.element.end) {
		const child = readDerChildOrOpaque(bytes, current.element, offset, options);
		if (child === undefined) {
			treatedAsOpaqueLeaf = true;
			offset = current.element.end;
			break;
		}
		stack.push({ element: child, depth: current.depth + 1 });
		offset = child.end;
	}
	if (!treatedAsOpaqueLeaf && offset !== current.element.end) {
		throw new Error('Malformed DER container');
	}
}

function readDerChildOrOpaque(
	bytes: Uint8Array,
	parent: DerElement,
	offset: number,
	options?: {
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
): DerElement | undefined {
	let child: DerElement;
	try {
		child = readElement(bytes, offset);
	} catch (error) {
		if (canTreatAsOpaqueLeaf(parent, offset, options)) return undefined;
		throw error;
	}
	if (child.end <= parent.end) {
		return child;
	}
	if (canTreatAsOpaqueLeaf(parent, offset, options)) return undefined;
	throw new Error('DER child exceeds parent length');
}

/**
 * Reads the single top-level TLV element from {@linkcode bytes}.
 *
 * Optionally validates nesting depth.
 *
 * @throws if there is trailing data after the element.
 */
export function readRootElement(bytes: Uint8Array, options?: ReadRootElementOptions): DerElement {
	const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DER_DEPTH;
	assertDerMaxDepth(bytes, maxDepth, options);
	const element = readElement(bytes, 0);
	if (element.end !== bytes.length) {
		throw new Error('Trailing data after DER element');
	}
	return element;
}

/**
 * Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children.
 *
 * @throws if the root element is not a SEQUENCE or if child boundaries are inconsistent.
 */
export function readSequenceChildren(
	bytes: Uint8Array,
	options?: ReadSequenceChildrenOptions,
): DerElement[] {
	const sequenceElement = readRootElement(bytes, options);
	if (sequenceElement.tag !== 0x30) {
		throw new Error('Expected SEQUENCE');
	}

	const children: DerElement[] = [];
	let offset = sequenceElement.start;
	while (offset < sequenceElement.end) {
		const element = readElement(bytes, offset);
		if (element.end > sequenceElement.end) {
			throw new Error('DER child exceeds parent length');
		}
		children.push(element);
		offset = element.end;
	}
	if (offset !== sequenceElement.end) {
		throw new Error('Malformed DER sequence');
	}
	return children;
}

/** @throws if {@linkcode value} is not a non-negative safe integer. */
function assertNonNegativeSafeInteger(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer`);
	}
}

function assertSingleOctetDerTag(tag: number): void {
	if (!Number.isSafeInteger(tag) || tag < 0 || tag > 0xff) {
		throw new RangeError('DER tag octet must be between 0 and 255');
	}
	if ((tag & 0x1f) === 0x1f) {
		throw new Error('High-tag-number DER tags are not supported');
	}
}

function assertContextSpecificTagNumber(tag: number): void {
	if (!Number.isSafeInteger(tag) || tag < 0 || tag >= 31) {
		throw new RangeError('Context-specific tag number must be between 0 and 30');
	}
}

function assertValidDate(date: Date, label: 'UTCTime' | 'GeneralizedTime'): void {
	if (Number.isNaN(date.getTime())) {
		throw new RangeError(`${label} requires a valid Date`);
	}
}

/**
 * @returns `true` when a constructed element's content should be treated as an opaque leaf (not recursed into)
 * because its tag appears in the {@linkcode options | allowOpaqueConstructedTags} list and the offset is at the element start.
 */
function canTreatAsOpaqueLeaf(
	element: DerElement,
	offset: number,
	options?: {
		/** Constructed tags whose inner bytes may not parse as valid TLV children. */
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
): boolean {
	return (
		offset === element.start && options?.allowOpaqueConstructedTags?.includes(element.tag) === true
	);
}
