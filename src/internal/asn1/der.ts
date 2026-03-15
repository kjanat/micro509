/**
 * Low-level DER encoding and reading helpers shared across the library.
 *
 * These utilities build and traverse ASN.1 TLV (tag-length-value) structures
 * without pulling in external dependencies.
 *
 * @module
 */

/**
 * Maximum nesting depth allowed when recursively walking a DER structure.
 * Guards against stack exhaustion from pathologically nested input.
 */
export const DEFAULT_MAX_DER_DEPTH = 64;

/**
 * Produces the DER length octets for a given byte count.
 * Values < 128 use the short form (one octet); larger values use the
 * long form (leading octet encodes the number of subsequent length bytes).
 */
export function encodeLength(length: number): Uint8Array {
	assertNonNegativeSafeInteger(length, 'DER length');
	if (length < 128) {
		return Uint8Array.of(length);
	}

	const parts = encodeBase256(length);
	return Uint8Array.of(0x80 | parts.length, ...parts);
}

/** Concatenates multiple byte arrays into a single `Uint8Array`. */
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

/**
 * Builds a complete DER TLV (tag-length-value) element: one tag octet,
 * the DER-encoded length, then the raw value bytes.
 */
export function tlv(tag: number, value: Uint8Array): Uint8Array {
	return concatBytes([Uint8Array.of(tag), encodeLength(value.length), value]);
}

/** Wraps concatenated children in a SEQUENCE (tag `0x30`). */
export function sequence(parts: readonly Uint8Array[]): Uint8Array {
	return tlv(0x30, concatBytes(parts));
}

/**
 * Wraps children in a SET (tag `0x31`) after DER-sorting them
 * lexicographically by encoded bytes, as required by X.690 DER.
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
 * Used for optional SEQUENCE fields tagged with `[tag] EXPLICIT`.
 */
export function explicitContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

/**
 * Wraps a value in an implicit context-specific constructed tag (`0xa0 + tag`).
 * Used for `[tag] IMPLICIT` fields whose underlying type is constructed (e.g. SEQUENCE).
 */
export function implicitConstructedContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

/**
 * Wraps a value in an implicit context-specific primitive tag (`0x80 + tag`).
 * Used for `[tag] IMPLICIT` fields whose underlying type is primitive (e.g. OCTET STRING).
 */
export function implicitPrimitiveContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0x80 + tag, value);
}

/**
 * Encodes raw big-endian bytes as a DER INTEGER (tag `0x02`).
 * Strips leading zero bytes for minimal encoding and prepends a zero
 * byte when the high bit is set to keep the value non-negative.
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
 * Throws if the value is not a non-negative safe integer.
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
 * Encodes a DER BIT STRING (tag `0x03`). The value is prefixed with a
 * single octet indicating how many trailing bits in the last byte are unused.
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

/** Encodes a DER UTF8String (tag `0x0c`). */
export function utf8String(value: string): Uint8Array {
	return tlv(0x0c, new TextEncoder().encode(value));
}

/**
 * Encodes a DER PrintableString (tag `0x13`).
 * Throws if the input contains characters outside the X.520 PrintableString set.
 */
export function printableString(value: string): Uint8Array {
	if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
		throw new Error('Invalid PrintableString: contains characters outside the allowed set');
	}
	return tlv(0x13, new TextEncoder().encode(value));
}

/**
 * Encodes a DER IA5String (tag `0x16`).
 * Throws if the input contains any non-ASCII character (code point > 0x7f).
 */
export function ia5String(value: string): Uint8Array {
	for (let i = 0; i < value.length; i++) {
		if (value.charCodeAt(i) > 0x7f) {
			throw new Error('Invalid IA5String: contains non-ASCII characters');
		}
	}
	return tlv(0x16, new TextEncoder().encode(value));
}

/** Encode a non-negative integer as a base-128 sub-identifier (X.690 §8.19.2). */
function encodeBase128(value: bigint): number[] {
	const encoded: number[] = [Number(value & 0x7fn)];
	let current = value >> 7n;
	while (current > 0n) {
		encoded.unshift(0x80 | Number(current & 0x7fn));
		current >>= 7n;
	}
	return encoded;
}

/**
 * Encodes a dotted-decimal OID string as a DER OBJECT IDENTIFIER (tag `0x06`).
 * Validates arc constraints per X.660: first arc must be 0–2, second < 40
 * for arcs 0 and 1. Sub-identifiers are encoded with base-128 continuation.
 */
export function objectIdentifier(oid: string): Uint8Array {
	const digitPattern = /^\d+$/;
	const segments = oid.split('.').map((segment) => {
		if (!digitPattern.test(segment)) {
			throw new Error(`Invalid OID segment: ${segment}`);
		}
		return BigInt(segment);
	});
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
 * Only the two-digit year is stored; suitable for dates in 1950–2049.
 */
export function utcTime(date: Date): Uint8Array {
	const value = `${[
		twoDigits(date.getUTCFullYear() % 100),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x17, new TextEncoder().encode(value));
}

/**
 * Encodes a `Date` as a DER GeneralizedTime (tag `0x18`), format `YYYYMMDDHHMMSSZ`.
 * Uses a four-digit year; required for dates outside the 1950–2049 range.
 */
export function generalizedTime(date: Date): Uint8Array {
	const value = `${[
		String(date.getUTCFullYear()).padStart(4, '0'),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x18, new TextEncoder().encode(value));
}

/**
 * Encodes a `Date` as the appropriate DER time type per RFC 5280:
 * {@linkcode utcTime} for 1950–2049, {@linkcode generalizedTime} otherwise.
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
	/** ASN.1 tag byte (e.g. `0x30` for SEQUENCE, `0x02` for INTEGER). */
	readonly tag: number;
	/** Number of bytes occupied by the tag + length octets. */
	readonly headerLength: number;
	/** Byte length of the value portion (excluding tag and length octets). */
	readonly length: number;
	/** Byte offset where the value portion begins in the source buffer. */
	readonly start: number;
	/** Byte offset one past the last value byte — equals the next element's header offset. */
	readonly end: number;
	/** The raw value bytes (slice of the source buffer). */
	readonly value: Uint8Array;
}

/** Options for {@linkcode readSequenceChildren}. */
export interface ReadSequenceChildrenOptions {
	/** Maximum nesting depth for the DER depth check. Default: {@linkcode DEFAULT_MAX_DER_DEPTH}. */
	readonly maxDepth?: number;
	/** Constructed tags whose inner bytes may not parse as valid TLV children (e.g. opaque extension values). */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/** Options for {@linkcode readRootElement}. */
export interface ReadRootElementOptions {
	/** Maximum nesting depth for the DER depth check. Default: {@linkcode DEFAULT_MAX_DER_DEPTH}. */
	readonly maxDepth?: number;
	/** Constructed tags whose inner bytes may not parse as valid TLV children (e.g. opaque extension values). */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/**
 * Reads one TLV element from `bytes` starting at `offset`.
 * Parses the tag byte, decodes the DER length octets, and slices out the
 * value bytes. Throws on truncated input, indefinite lengths, and
 * non-minimal length encodings.
 *
 * @param offset Byte position of the tag octet. Defaults to 0.
 */
export function readElement(bytes: Uint8Array, offset = 0): DerElement {
	const tag = bytes[offset];
	if (tag === undefined) {
		throw new Error('Unexpected end of DER input');
	}
	const lengthByte = bytes[offset + 1];
	if (lengthByte === undefined) {
		throw new Error('Unexpected end of DER input');
	}

	let headerLength = 2;
	let length = 0;
	if ((lengthByte & 0x80) === 0) {
		length = lengthByte;
	} else {
		const octets = lengthByte & 0x7f;
		if (octets === 0) {
			throw new Error('Indefinite lengths are not supported');
		}
		const firstLengthOctet = bytes[offset + 2];
		if (firstLengthOctet === undefined) {
			throw new Error('Unexpected end of DER input');
		}
		if (firstLengthOctet === 0) {
			throw new Error('Non-minimal DER length encoding');
		}
		headerLength += octets;
		for (let index = 0; index < octets; index += 1) {
			const next = bytes[offset + 2 + index];
			if (next === undefined) {
				throw new Error('Unexpected end of DER input');
			}
			if (length > Math.floor((Number.MAX_SAFE_INTEGER - next) / 256)) {
				throw new Error('DER length exceeds safe integer range');
			}
			length = length * 256 + next;
		}
		if (length < 128) {
			throw new Error('Non-minimal DER length encoding');
		}
	}

	const start = offset + headerLength;
	const end = start + length;
	if (end > bytes.length) {
		throw new Error('DER element exceeds input length');
	}

	return {
		tag,
		headerLength,
		length,
		start,
		end,
		value: bytes.slice(start, end),
	};
}

/**
 * Walks the full DER tree rooted in `bytes` and throws if nesting exceeds
 * `maxDepth`. Constructed tags with content that cannot be parsed as valid
 * children are tolerated when listed in `allowOpaqueConstructedTags`.
 */
export function assertDerMaxDepth(
	bytes: Uint8Array,
	maxDepth: number = DEFAULT_MAX_DER_DEPTH,
	options?: {
		/** Constructed tags whose inner bytes may not parse as valid TLV children. */
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
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
			throw new Error(`DER exceeds max depth of ${maxDepth}`);
		}
		if ((current.element.tag & 0x20) === 0) {
			continue;
		}
		let offset = current.element.start;
		let treatedAsOpaqueLeaf = false;
		while (offset < current.element.end) {
			let child: DerElement;
			try {
				child = readElement(bytes, offset);
			} catch (error) {
				if (canTreatAsOpaqueLeaf(current.element, offset, options)) {
					treatedAsOpaqueLeaf = true;
					offset = current.element.end;
					break;
				}
				throw error;
			}
			if (child.end > current.element.end) {
				if (canTreatAsOpaqueLeaf(current.element, offset, options)) {
					treatedAsOpaqueLeaf = true;
					offset = current.element.end;
					break;
				}
				throw new Error('DER child exceeds parent length');
			}
			stack.push({ element: child, depth: current.depth + 1 });
			offset = child.end;
		}
		if (!treatedAsOpaqueLeaf && offset !== current.element.end) {
			throw new Error('Malformed DER container');
		}
	}
}

/**
 * Reads the single top-level TLV element from `bytes`, optionally
 * validating nesting depth. Throws if there is trailing data after the element.
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
 * Reads a DER-encoded SEQUENCE from `bytes` and returns its direct children.
 * Throws if the root element is not a SEQUENCE or if child boundaries are inconsistent.
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

/** Throws if `value` is not a non-negative safe integer. */
function assertNonNegativeSafeInteger(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer`);
	}
}

/**
 * Returns `true` when a constructed element's content should be treated as
 * an opaque leaf (not recursed into) because its tag appears in the
 * `allowOpaqueConstructedTags` list and the offset is at the element start.
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
