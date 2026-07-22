/**
 * Element-oriented DER decoders.
 *
 * Each decoder validates the element's tag before reading its value, so a
 * mis-tagged element fails with a named error instead of yielding a wrong value.
 *
 * @module
 */

import {
	decodeBoolean,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	parseTime,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';

function requireTag(element: DerElement, tag: number, label: string): DerElement {
	if (element.tag !== tag) {
		throw new Error(`Expected ${label}`);
	}
	return element;
}

/** Decodes a BOOLEAN element (tag `0x01`). Requires the DER forms `0x00` and `0xff`. */
export function decodeDerBoolean(element: DerElement): boolean {
	return decodeBoolean(requireTag(element, 0x01, 'BOOLEAN').value);
}

/**
 * Decodes an INTEGER element (tag `0x02`) into a `number`.
 * Throws on negative values, non-minimal encodings, and values above
 * `Number.MAX_SAFE_INTEGER`.
 */
export function decodeDerInteger(element: DerElement): number {
	return decodeIntegerNumber(requireTag(element, 0x02, 'INTEGER').value);
}

/** Decodes an OCTET STRING element (tag `0x04`) into its payload bytes. */
export function decodeDerOctetString(element: DerElement): Uint8Array {
	return requireTag(element, 0x04, 'OCTET STRING').value;
}

/** Decodes an OBJECT IDENTIFIER element (tag `0x06`) into dotted-decimal form. */
export function decodeDerOid(element: DerElement): string {
	return decodeObjectIdentifier(requireTag(element, 0x06, 'OBJECT IDENTIFIER').value);
}

/**
 * Decodes a string element into text, dispatching on its tag.
 *
 * Supports UTF8String, PrintableString, IA5String, UniversalString, and BMPString.
 * TeletexString and other string tags throw.
 */
export function decodeDerString(element: DerElement): string {
	return decodeString(element.tag, element.value);
}

/** Decodes a UTCTime (`0x17`) or GeneralizedTime (`0x18`) element into a `Date`. */
export function decodeDerTime(element: DerElement): Date {
	return parseTime(element);
}
