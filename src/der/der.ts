/**
 * Element-oriented DER readers and decoders.
 *
 * Each decoder validates the element's tag before reading its value, so a
 * mis-tagged element fails instead of yielding a wrong value.
 *
 * The `OrThrow` variants throw on malformed input.
 * The plain variants return a {@linkcode DecodeDerResult}.
 *
 * @module
 */

import type { DerBitString } from '#micro509/internal/asn1/asn1';
import {
	childrenOf,
	decodeBitString,
	decodeBoolean,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	parseTime,
} from '#micro509/internal/asn1/asn1';
import type {
	DerElement,
	ReadRootElementOptions,
	ReadSequenceChildrenOptions,
} from '#micro509/internal/asn1/der';
import { readElement, readRootElement, readSequenceChildren } from '#micro509/internal/asn1/der';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, rethrowIfInvariant, successResult } from '#micro509/result/result';

/** Machine-readable failure reason for the DER readers and decoders. */
export type DecodeDerErrorCode = 'malformed';

/** Structured failure payload for DER reading and decoding. */
export interface DecodeDerFailure extends Micro509Error<DecodeDerErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from a DER reader or decoder. */
export type DecodeDerResult<TValue> =
	| { readonly ok: true; readonly value: TValue }
	| ErrorResult<DecodeDerErrorCode, Record<never, never>, DecodeDerFailure>;

function attempt<TValue>(decode: () => TValue, fallback: string): DecodeDerResult<TValue> {
	try {
		return successResult(decode());
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult('malformed', error instanceof Error ? error.message : fallback);
	}
}

function requireTag(element: DerElement, tag: number, label: string): DerElement {
	if (element.tag !== tag) {
		throw new Error(`Expected ${label}`);
	}
	return element;
}

/**
 * Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
 *
 * @param offset Byte position of the tag octet. Defaults to 0.
 * @throws if the element is truncated, indefinite-length, or non-minimally encoded.
 */
export function readDerElementOrThrow(bytes: Uint8Array, offset = 0): DerElement {
	return readElement(bytes, offset);
}

/**
 * Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
 *
 * @param offset Byte position of the tag octet. Defaults to 0.
 */
export function readDerElement(bytes: Uint8Array, offset = 0): DecodeDerResult<DerElement> {
	return attempt(() => readDerElementOrThrow(bytes, offset), 'Malformed DER element');
}

/**
 * Reads the single top-level TLV element from {@linkcode bytes}.
 *
 * @throws if {@linkcode bytes} carries trailing data, or nesting exceeds the depth guard.
 */
export function readDerRootOrThrow(
	bytes: Uint8Array,
	options?: ReadRootElementOptions,
): DerElement {
	return readRootElement(bytes, options);
}

/** Reads the single top-level TLV element from {@linkcode bytes}. */
export function readDerRoot(
	bytes: Uint8Array,
	options?: ReadRootElementOptions,
): DecodeDerResult<DerElement> {
	return attempt(() => readDerRootOrThrow(bytes, options), 'Malformed DER element');
}

/**
 * Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children.
 *
 * @throws if the root element is not a SEQUENCE, or if child boundaries are inconsistent.
 */
export function readDerSequenceOrThrow(
	bytes: Uint8Array,
	options?: ReadSequenceChildrenOptions,
): DerElement[] {
	return readSequenceChildren(bytes, options);
}

/** Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children. */
export function readDerSequence(
	bytes: Uint8Array,
	options?: ReadSequenceChildrenOptions,
): DecodeDerResult<DerElement[]> {
	return attempt(() => readDerSequenceOrThrow(bytes, options), 'Malformed DER sequence');
}

/**
 * Reads the direct children of a constructed {@linkcode parent} within {@linkcode source}.
 *
 * @throws if a child overflows {@linkcode parent}, or data is left between the last child and its end.
 */
export function derChildrenOrThrow(source: Uint8Array, parent: DerElement): DerElement[] {
	return childrenOf(source, parent);
}

/** Reads the direct children of a constructed {@linkcode parent} within {@linkcode source}. */
export function derChildren(source: Uint8Array, parent: DerElement): DecodeDerResult<DerElement[]> {
	return attempt(() => derChildrenOrThrow(source, parent), 'Malformed DER container');
}

/**
 * Decodes a BOOLEAN element (tag `0x01`).
 *
 * @throws if {@linkcode element} is mis-tagged, or holds anything but `0x00` or `0xff`.
 */
export function decodeDerBooleanOrThrow(element: DerElement): boolean {
	return decodeBoolean(requireTag(element, 0x01, 'BOOLEAN').value);
}

/** Decodes a BOOLEAN element (tag `0x01`). */
export function decodeDerBoolean(element: DerElement): DecodeDerResult<boolean> {
	return attempt(() => decodeDerBooleanOrThrow(element), 'Malformed BOOLEAN');
}

/**
 * Decodes an INTEGER element (tag `0x02`) into a `number`.
 *
 * @throws if {@linkcode element} is mis-tagged, negative, non-minimally encoded,
 * or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
 */
export function decodeDerIntegerOrThrow(element: DerElement): number {
	return decodeIntegerNumber(requireTag(element, 0x02, 'INTEGER').value);
}

/** Decodes an INTEGER element (tag `0x02`) into a `number`. */
export function decodeDerInteger(element: DerElement): DecodeDerResult<number> {
	return attempt(() => decodeDerIntegerOrThrow(element), 'Malformed INTEGER');
}

/**
 * Decodes an OCTET STRING element (tag `0x04`) into its payload bytes.
 *
 * @throws if {@linkcode element} is mis-tagged.
 */
export function decodeDerOctetStringOrThrow(element: DerElement): Uint8Array {
	return requireTag(element, 0x04, 'OCTET STRING').value;
}

/** Decodes an OCTET STRING element (tag `0x04`) into its payload bytes. */
export function decodeDerOctetString(element: DerElement): DecodeDerResult<Uint8Array> {
	return attempt(() => decodeDerOctetStringOrThrow(element), 'Malformed OCTET STRING');
}

/**
 * Decodes an OBJECT IDENTIFIER element (tag `0x06`) into dotted-decimal form.
 *
 * @throws if {@linkcode element} is mis-tagged, or holds a malformed sub-identifier.
 */
export function decodeDerOidOrThrow(element: DerElement): string {
	return decodeObjectIdentifier(requireTag(element, 0x06, 'OBJECT IDENTIFIER').value);
}

/** Decodes an OBJECT IDENTIFIER element (tag `0x06`) into dotted-decimal form. */
export function decodeDerOid(element: DerElement): DecodeDerResult<string> {
	return attempt(() => decodeDerOidOrThrow(element), 'Malformed OBJECT IDENTIFIER');
}

/**
 * Decodes a BIT STRING element (tag `0x03`) into a {@linkcode DerBitString}.
 *
 * Unused trailing bits are returned as encoded. X.690 §11.2.2 requires them to be zero,
 * and certificates in the wild violate it, so the check is left to the caller.
 *
 * @throws if {@linkcode element} is mis-tagged, or claims more than seven unused bits.
 */
export function decodeDerBitStringOrThrow(element: DerElement): DerBitString {
	return decodeBitString(element);
}

/**
 * Decodes a BIT STRING element (tag `0x03`) into a {@linkcode DerBitString}.
 *
 * Unused trailing bits are returned as encoded. X.690 §11.2.2 requires them to be zero,
 * and certificates in the wild violate it, so the check is left to the caller.
 */
export function decodeDerBitString(element: DerElement): DecodeDerResult<DerBitString> {
	return attempt(() => decodeDerBitStringOrThrow(element), 'Malformed BIT STRING');
}

/**
 * Decodes a string element into text, dispatching on its tag.
 *
 * Supports UTF8String, PrintableString, IA5String, UniversalString, and BMPString.
 *
 * @throws on TeletexString, and on every other string tag.
 */
export function decodeDerStringOrThrow(element: DerElement): string {
	return decodeString(element.tag, element.value);
}

/**
 * Decodes a string element into text, dispatching on its tag.
 *
 * Supports UTF8String, PrintableString, IA5String, UniversalString, and BMPString.
 */
export function decodeDerString(element: DerElement): DecodeDerResult<string> {
	return attempt(() => decodeDerStringOrThrow(element), 'Malformed string');
}

/**
 * Decodes a UTCTime (tag `0x17`) or GeneralizedTime (tag `0x18`) element into a {@linkcode Date}.
 *
 * @throws if {@linkcode element} carries any other tag, or a malformed time value.
 */
export function decodeDerTimeOrThrow(element: DerElement): Date {
	return parseTime(element);
}

/** Decodes a UTCTime (tag `0x17`) or GeneralizedTime (tag `0x18`) element into a {@linkcode Date}. */
export function decodeDerTime(element: DerElement): DecodeDerResult<Date> {
	return attempt(() => decodeDerTimeOrThrow(element), 'Malformed time');
}
