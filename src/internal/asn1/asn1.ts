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
	if (bytes.length === 0) {
		throw new Error('OID is empty');
	}
	const firstSubidentifier = decodeOidSubidentifier(bytes, 0);
	let offset = firstSubidentifier.nextOffset;
	const values =
		firstSubidentifier.value < 40
			? [0, firstSubidentifier.value]
			: firstSubidentifier.value < 80
				? [1, firstSubidentifier.value - 40]
				: [2, firstSubidentifier.value - 80];
	while (offset < bytes.length) {
		const subidentifier = decodeOidSubidentifier(bytes, offset);
		values.push(subidentifier.value);
		offset = subidentifier.nextOffset;
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
	const unusedBits = element.value[0];
	if (unusedBits === undefined || unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	if (unusedBits !== 0) {
		throw new Error('BIT STRING must have zero unused bits');
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
		const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
		if (match === null) {
			throw new Error('Invalid UTCTime');
		}
		const yearText = requireElement(match[1], 'UTCTime year');
		const monthText = requireElement(match[2], 'UTCTime month');
		const dayText = requireElement(match[3], 'UTCTime day');
		const hourText = requireElement(match[4], 'UTCTime hour');
		const minuteText = requireElement(match[5], 'UTCTime minute');
		const secondText = requireElement(match[6], 'UTCTime second');
		const year = Number.parseInt(yearText, 10);
		return buildStrictUtcDate(
			year >= 50 ? 1900 + year : 2000 + year,
			monthText,
			dayText,
			hourText,
			minuteText,
			secondText,
			'UTCTime',
		);
	}
	if (element.tag === 0x18) {
		const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
		if (match === null) {
			throw new Error('Invalid GeneralizedTime');
		}
		const yearText = requireElement(match[1], 'GeneralizedTime year');
		const monthText = requireElement(match[2], 'GeneralizedTime month');
		const dayText = requireElement(match[3], 'GeneralizedTime day');
		const hourText = requireElement(match[4], 'GeneralizedTime hour');
		const minuteText = requireElement(match[5], 'GeneralizedTime minute');
		const secondText = requireElement(match[6], 'GeneralizedTime second');
		return buildStrictUtcDate(
			Number.parseInt(yearText, 10),
			monthText,
			dayText,
			hourText,
			minuteText,
			secondText,
			'GeneralizedTime',
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
	const first = bytes[0];
	if (first === undefined) {
		throw new Error('INTEGER is empty');
	}
	if ((first & 0x80) !== 0) {
		throw new Error('INTEGER must be non-negative');
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error('INTEGER must use minimal encoding');
	}
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
	if (bytes.length !== 1) {
		throw new Error('BOOLEAN must contain exactly one octet');
	}
	const value = bytes[0];
	if (value !== 0x00 && value !== 0xff) {
		throw new Error('BOOLEAN must use DER encoding');
	}
	return value === 0xff;
}

function buildStrictUtcDate(
	year: number,
	monthText: string,
	dayText: string,
	hourText: string,
	minuteText: string,
	secondText: string,
	label: 'UTCTime' | 'GeneralizedTime',
): Date {
	const month = Number.parseInt(monthText, 10);
	const day = Number.parseInt(dayText, 10);
	const hour = Number.parseInt(hourText, 10);
	const minute = Number.parseInt(minuteText, 10);
	const second = Number.parseInt(secondText, 10);
	const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
	if (
		Number.isNaN(date.getTime()) ||
		date.getUTCFullYear() !== year ||
		date.getUTCMonth() !== month - 1 ||
		date.getUTCDate() !== day ||
		date.getUTCHours() !== hour ||
		date.getUTCMinutes() !== minute ||
		date.getUTCSeconds() !== second
	) {
		throw new Error(`Invalid ${label}`);
	}
	return date;
}

function decodeOidSubidentifier(
	bytes: Uint8Array,
	start: number,
): {
	readonly value: number;
	readonly nextOffset: number;
} {
	const first = bytes[start];
	if (first === undefined) {
		throw new Error('Malformed OID');
	}
	if (first === 0x80) {
		throw new Error('Malformed OID: non-minimal base-128 encoding');
	}
	let value = 0;
	let offset = start;
	for (; offset < bytes.length; offset += 1) {
		const next = bytes[offset];
		if (next === undefined) {
			throw new Error('Malformed OID');
		}
		value = value * 128 + (next & 0x7f);
		if ((next & 0x80) === 0) {
			return {
				value,
				nextOffset: offset + 1,
			};
		}
	}
	throw new Error('Malformed OID: incomplete continuation');
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
