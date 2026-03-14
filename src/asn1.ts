/**
 * ASN.1 decoding helpers used by the higher-level DER, parse, and crypto modules.
 *
 * These utilities stay intentionally small and strict so malformed input fails early and
 * higher-level modules can build on one consistent decoding layer.
 */

import { type DerElement, readElement } from './der.ts';

/**
 * Stores the shared UTF-8 text decoder used by this module.
 */
const textDecoder = new TextDecoder();

/**
 * Decodes object identifier.
 *
 * @param bytes The raw bytes to process.
 * @returns The decoded object identifier.
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

/**
 * To hex.
 *
 * @param bytes The raw bytes to process.
 * @returns The computed value.
 */
export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

/**
 * To array buffer.
 *
 * @param bytes The raw bytes to process.
 * @returns The computed value.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}

/**
 * Children of.
 *
 * @param source The source value to process.
 * @param parent The parent value.
 * @returns The computed value.
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
 * Requires and returns element.
 *
 * @param value The value to process.
 * @param label The label value.
 * @returns The computed value.
 */
export function requireElement<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

/**
 * Extract bit string value.
 *
 * @param element The ASN.1 element to process.
 * @returns The computed value.
 */
export function extractBitStringValue(element: DerElement): Uint8Array {
	if (element.tag !== 0x03) {
		throw new Error('Expected BIT STRING');
	}
	return element.value.slice(1);
}

/**
 * Parses time.
 *
 * @param element The ASN.1 element to process.
 * @returns The parsed time.
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
 * Decodes integer number.
 *
 * @param bytes The raw bytes to process.
 * @returns The decoded integer number.
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
 * Decodes non negative integer number.
 *
 * @param bytes The raw bytes to process.
 * @param label The label value.
 * @returns The decoded non negative integer number.
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
 * Hex to bytes.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const out = new Uint8Array(normalized.length / 2);
	for (let index = 0; index < out.length; index += 1) {
		out[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
	}
	return out;
}

/**
 * Decodes boolean.
 *
 * @param bytes The raw bytes to process.
 * @returns The decoded boolean.
 */
export function decodeBoolean(bytes: Uint8Array): boolean {
	return (bytes[0] ?? 0) !== 0;
}

/**
 * Decodes string.
 *
 * @param tag The tag value.
 * @param bytes The raw bytes to process.
 * @returns The decoded string.
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
