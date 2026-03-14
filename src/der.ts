/**
 * Low-level DER encoding and reading helpers shared across the library.
 *
 * These utilities build and traverse ASN.1 TLV structures without pulling in external
 * dependencies.
 */

/**
 * Defines the default max der depth used by this module.
 */
export const DEFAULT_MAX_DER_DEPTH = 64;

/**
 * Encodes length.
 *
 * @param length The length value.
 * @returns The encoded length.
 */
export function encodeLength(length: number): Uint8Array {
	assertNonNegativeSafeInteger(length, 'DER length');
	if (length < 128) {
		return Uint8Array.of(length);
	}

	const parts = encodeBase256(length);
	return Uint8Array.of(0x80 | parts.length, ...parts);
}

/**
 * Concatenates bytes.
 *
 * @param parts The parts value.
 * @returns The computed value.
 */
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
 * TLV.
 *
 * @param tag The tag value.
 * @param value The value to process.
 * @returns The computed value.
 */
export function tlv(tag: number, value: Uint8Array): Uint8Array {
	return concatBytes([Uint8Array.of(tag), encodeLength(value.length), value]);
}

/**
 * Sequence.
 *
 * @param parts The parts value.
 * @returns The computed value.
 */
export function sequence(parts: readonly Uint8Array[]): Uint8Array {
	return tlv(0x30, concatBytes(parts));
}

/**
 * Set of.
 *
 * @param parts The parts value.
 * @returns The computed value.
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
 * Explicit context.
 *
 * @param tag The tag value.
 * @param value The value to process.
 * @returns The computed value.
 */
export function explicitContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

/**
 * Implicit constructed context.
 *
 * @param tag The tag value.
 * @param value The value to process.
 * @returns The computed value.
 */
export function implicitConstructedContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

/**
 * Implicit primitive context.
 *
 * @param tag The tag value.
 * @param value The value to process.
 * @returns The computed value.
 */
export function implicitPrimitiveContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0x80 + tag, value);
}

/**
 * Integer.
 *
 * @param bytes The raw bytes to process.
 * @returns The computed value.
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
 * Integer from number.
 *
 * @param value The value to process.
 * @returns The computed value.
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

/**
 * Bool.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function bool(value: boolean): Uint8Array {
	return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

/**
 * Null value.
 *
 * @returns The computed value.
 */
export function nullValue(): Uint8Array {
	return tlv(0x05, new Uint8Array());
}

/**
 * Octet string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function octetString(value: Uint8Array): Uint8Array {
	return tlv(0x04, value);
}

/**
 * Bit string.
 *
 * @param value The value to process.
 * @param unusedBits The unused bits value.
 * @returns The computed value.
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

/**
 * UTF-8 string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function utf8String(value: string): Uint8Array {
	return tlv(0x0c, new TextEncoder().encode(value));
}

/**
 * Printable string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function printableString(value: string): Uint8Array {
	if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
		throw new Error('Invalid PrintableString: contains characters outside the allowed set');
	}
	return tlv(0x13, new TextEncoder().encode(value));
}

/**
 * Ia5 string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function ia5String(value: string): Uint8Array {
	for (let i = 0; i < value.length; i++) {
		if (value.charCodeAt(i) > 0x7f) {
			throw new Error('Invalid IA5String: contains non-ASCII characters');
		}
	}
	return tlv(0x16, new TextEncoder().encode(value));
}

/**
 * Object identifier.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
export function objectIdentifier(oid: string): Uint8Array {
	const segments = oid.split('.').map((segment) => Number(segment));
	if (segments.length < 2) {
		throw new Error(`Invalid OID: ${oid}`);
	}

	const [first, second, ...rest] = segments;
	if (first === undefined || second === undefined) {
		throw new Error(`Invalid OID: ${oid}`);
	}
	if (first !== 0 && first !== 1 && first !== 2) {
		throw new Error(`Invalid OID first arc: ${first}`);
	}
	if ((first === 0 || first === 1) && second >= 40) {
		throw new Error(`Invalid OID second arc: ${second} (must be < 40 when first arc is ${first})`);
	}
	const bytes: number[] = [first * 40 + second];
	for (const segment of rest) {
		if (!Number.isInteger(segment) || segment < 0) {
			throw new Error(`Invalid OID segment in ${oid}`);
		}
		const encoded: number[] = [segment & 0x7f];
		let current = segment >> 7;
		while (current > 0) {
			encoded.unshift(0x80 | (current & 0x7f));
			current >>= 7;
		}
		bytes.push(...encoded);
	}

	return tlv(0x06, Uint8Array.from(bytes));
}

/**
 * Utc time.
 *
 * @param date The date value.
 * @returns The computed value.
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
 * Generalized time.
 *
 * @param date The date value.
 * @returns The computed value.
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
 * Time.
 *
 * @param date The date value.
 * @returns The computed value.
 */
export function time(date: Date): Uint8Array {
	if (date.getUTCFullYear() >= 2050 || date.getUTCFullYear() < 1950) {
		return generalizedTime(date);
	}
	return utcTime(date);
}

/**
 * Two digits.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function twoDigits(value: number): string {
	return String(value).padStart(2, '0');
}

/**
 * Encodes base256.
 *
 * @param value The value to process.
 * @returns The encoded base256.
 */
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

/**
 * Describes DER element.
 */
export interface DerElement {
	/**
	 * Carries the tag value.
	 */
	readonly tag: number;
	/**
	 * Carries the header length value.
	 */
	readonly headerLength: number;
	/**
	 * Carries the length value.
	 */
	readonly length: number;
	/**
	 * Carries the start value.
	 */
	readonly start: number;
	/**
	 * Carries the end value.
	 */
	readonly end: number;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: Uint8Array;
}

/**
 * Configures read sequence children operations.
 */
export interface ReadSequenceChildrenOptions {
	/**
	 * Carries the max depth value.
	 */
	readonly maxDepth?: number;
	/**
	 * Carries the allow opaqu e constructed tags value.
	 */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/**
 * Configures read root element operations.
 */
export interface ReadRootElementOptions {
	/**
	 * Carries the max depth value.
	 */
	readonly maxDepth?: number;
	/**
	 * Carries the allow opaqu e constructed tags value.
	 */
	readonly allowOpaqueConstructedTags?: readonly number[];
}

/**
 * Read element.
 *
 * @param bytes The raw bytes to process.
 * @param offset The offset value.
 * @returns The computed value.
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
 * Assert DER max depth.
 *
 * @param bytes The raw bytes to process.
 * @param maxDepth The max depth value.
 * @param options The options that control the operation.
 */
export function assertDerMaxDepth(
	bytes: Uint8Array,
	maxDepth: number = DEFAULT_MAX_DER_DEPTH,
	options?: {
		/**
		 * Carries the allow opaqu e constructed tags value.
		 */
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
		/**
		 * Carries the element value.
		 */
		readonly element: DerElement;
		/**
		 * Carries the depth value.
		 */
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
 * Read root element.
 *
 * @param bytes The raw bytes to process.
 * @param options The options that control the operation.
 * @returns The computed value.
 */
export function readRootElement(bytes: Uint8Array, options?: ReadRootElementOptions): DerElement {
	if (options?.maxDepth !== undefined) {
		assertDerMaxDepth(bytes, options.maxDepth, options);
	}
	const element = readElement(bytes, 0);
	if (element.end !== bytes.length) {
		throw new Error('Trailing data after DER element');
	}
	return element;
}

/**
 * Read sequence children.
 *
 * @param bytes The raw bytes to process.
 * @param options The options that control the operation.
 * @returns The computed value.
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

/**
 * Assert non negative safe integer.
 *
 * @param value The value to process.
 * @param label The label value.
 */
function assertNonNegativeSafeInteger(value: number, label: string): void {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer`);
	}
}

/**
 * Can treat as opaque leaf.
 *
 * @param element The ASN.1 element to process.
 * @param offset The offset value.
 * @param options The options that control the operation.
 * @returns The computed value.
 */
function canTreatAsOpaqueLeaf(
	element: DerElement,
	offset: number,
	options?: {
		/**
		 * Carries the allow opaqu e constructed tags value.
		 */
		readonly allowOpaqueConstructedTags?: readonly number[];
	},
): boolean {
	return (
		offset === element.start && options?.allowOpaqueConstructedTags?.includes(element.tag) === true
	);
}
