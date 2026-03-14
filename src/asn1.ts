/**
 * ASN.1 decoding helpers used by the higher-level DER, parse, and crypto modules.
 *
 * These utilities stay intentionally small and strict so malformed input fails early and
 * higher-level modules can build on one consistent decoding layer.
 *
 * @module
 */

import { type DerElement, readElement } from './der.ts';

/** Shared UTF-8 text decoder for ASN.1 string types. */
const textDecoder = new TextDecoder();

/**
 * Decodes a DER-encoded OBJECT IDENTIFIER value into its dotted-decimal string
 * form (e.g. `"1.2.840.113549.1.1.1"`).
 *
 * Throws on empty input, truncated multi-byte sub-identifiers, or incomplete
 * continuation octets.
 */
export function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error('OID is empty');
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	let inContinuation = false;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error('Malformed OID');
		}
		current = current * 128 + (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
			inContinuation = false;
		} else {
			inContinuation = true;
		}
	}
	if (inContinuation) {
		throw new Error('Malformed OID: incomplete continuation');
	}
	return values.join('.');
}

/** Converts raw bytes to a lowercase hex string with no separator. */
export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

/**
 * Copies a `Uint8Array` into a standalone `ArrayBuffer` suitable for
 * Web Crypto operations that require a non-shared backing buffer.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}

/**
 * Iterates through all direct child TLV elements inside a constructed
 * {@linkcode DerElement} (SEQUENCE, SET, or context-tagged container).
 *
 * Throws if any child overflows the parent boundary or if there is
 * leftover data between the last child and the parent end offset.
 */
export function childrenOf(source: Uint8Array, parent: DerElement): DerElement[] {
	const children: DerElement[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		if (child.end > parent.end) {
			throw new Error('DER child exceeds parent length');
		}
		children.push(child);
		offset = child.end;
	}
	if (offset !== parent.end) {
		throw new Error('Malformed DER container');
	}
	return children;
}

/**
 * Asserts that a value is not `undefined`, returning it narrowed.
 * Used to enforce the presence of mandatory ASN.1 fields during parsing.
 *
 * @param label Human-readable field name included in the error message on failure.
 */
export function requireElement<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

/**
 * Strips the leading "unused bits" octet from a BIT STRING element,
 * returning just the payload bytes. Throws if the tag is not `0x03`.
 *
 * Used to extract signature values and public keys from their BIT STRING wrapper.
 */
export function extractBitStringValue(element: DerElement): Uint8Array {
	if (element.tag !== 0x03) {
		throw new Error('Expected BIT STRING');
	}
	return element.value.slice(1);
}

/**
 * Parses a {@linkcode DerElement} with tag UTCTime (`0x17`) or GeneralizedTime (`0x18`)
 * into a `Date`.
 *
 * For UTCTime, the two-digit year is interpreted per RFC 5280: values >= 50 map
 * to 19xx, values < 50 map to 20xx. Throws on unrecognized time tags.
 */
export function parseTime(element: DerElement): Date {
	const value = textDecoder.decode(element.value);
	if (element.tag === 0x17) {
		const yearPrefix = Number.parseInt(value.slice(0, 2), 10) >= 50 ? '19' : '20';
		return new Date(
			`${yearPrefix}${value.slice(0, 2)}-${value.slice(2, 4)}-${value.slice(4, 6)}T${value.slice(6, 8)}:${value.slice(
				8,
				10,
			)}:${value.slice(10, 12)}Z`,
		);
	}
	if (element.tag === 0x18) {
		return new Date(
			`${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(
				12,
				14,
			)}Z`,
		);
	}
	throw new Error(`Unsupported time tag: ${element.tag}`);
}

/**
 * Decodes a big-endian unsigned byte sequence into a JavaScript `number`.
 * Throws if the value exceeds 6 bytes (48 bits), which is the safe-integer
 * boundary for lossless arithmetic.
 */
export function decodeIntegerNumber(bytes: Uint8Array): number {
	if (bytes.length > 6) {
		throw new Error(`Integer too large for safe number (${bytes.length} bytes)`);
	}
	let value = 0;
	for (const byte of bytes) {
		value = value * 256 + byte;
	}
	return value;
}

/**
 * Like {@linkcode decodeIntegerNumber} but additionally enforces DER rules for
 * non-negative integers: the high bit must be clear, and leading zero padding
 * must be minimal.
 *
 * @param label Field name for error messages (defaults to `"INTEGER"`).
 */
export function decodeNonNegativeIntegerNumber(bytes: Uint8Array, label = 'INTEGER'): number {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error(`${label} is empty`);
	}
	if ((first & 0x80) !== 0) {
		throw new Error(`${label} must be non-negative`);
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error(`${label} must use minimal encoding`);
	}
	return decodeIntegerNumber(bytes);
}

/**
 * Converts a hex string (even or odd length) to a `Uint8Array`.
 * Odd-length strings are left-padded with a zero nibble.
 */
export function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const out = new Uint8Array(normalized.length / 2);
	for (let index = 0; index < out.length; index += 1) {
		out[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
	}
	return out;
}

/** Decodes a DER BOOLEAN value: any non-zero first byte is `true`. */
export function decodeBoolean(bytes: Uint8Array): boolean {
	return (bytes[0] ?? 0) !== 0;
}

/**
 * Decodes a DER string element by tag. Supports UTF8String (`0x0c`),
 * PrintableString (`0x13`), and IA5String (`0x16`).
 * Throws on unsupported string tags.
 */
export function decodeString(tag: number, bytes: Uint8Array): string {
	switch (tag) {
		case 0x0c:
		case 0x13:
		case 0x16:
			return textDecoder.decode(bytes);
		default:
			throw new Error(`Unsupported string tag: ${tag}`);
	}
}
