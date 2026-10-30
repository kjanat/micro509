import { c as rethrowIfInvariant, l as successResult, s as n } from "./result-C9WPk47A.js";
import { B as printableString, C as bool, D as explicitContext, F as integerFromNumber, G as sequence, I as nullValue, J as time, K as setOf, L as objectIdentifier, M as implicitConstructedContext, N as implicitPrimitiveContext, O as generalizedTime, P as integer, Q as utf8String, R as octetString, S as bmpString, U as readRootElement, V as readElement, W as readSequenceChildren, X as universalString, Y as tlv, Z as utcTime, a as decodeBoolean, b as assertDerMaxDepth, d as decodeString, et as decodeFailureResult, g as parseTime, i as decodeBitString, j as ia5String, m as hexToBytes, q as t, r as childrenOf, s as decodeIntegerNumber, u as decodeObjectIdentifier, w as concatBytes, x as bitString, y as toHex } from "./asn1-jyOu_Jva.js";
// ../../dist/der/der.js
function attempt(i, a) {
	try {
		return successResult(i());
	} catch (n$1) {
		return rethrowIfInvariant(n$1), decodeFailureResult(n$1, n, a);
	}
}
function requireTag(e, t, n) {
	if (e.tag !== t) throw Error(`Expected ${n}`);
	return e;
}
/**
* Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
*
* @param offset Byte position of the tag octet. Defaults to 0.
* @throws if the element is truncated, indefinite-length, or non-minimally encoded.
*/
function readDerElementOrThrow(e, t = 0) {
	return readElement(e, t);
}
/**
* Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
*
* @param offset Byte position of the tag octet. Defaults to 0.
*/
function readDerElement(e, t = 0) {
	return attempt(() => readDerElementOrThrow(e, t), "Malformed DER element");
}
/**
* Reads the single top-level TLV element from {@linkcode bytes}.
*
* @throws if {@linkcode bytes} carries trailing data, or nesting exceeds the depth guard.
*/
function readDerRootOrThrow(e, t) {
	return readRootElement(e, t);
}
/** Reads the single top-level TLV element from {@linkcode bytes}. */
function readDerRoot(e, t) {
	return attempt(() => readDerRootOrThrow(e, t), "Malformed DER element");
}
/**
* Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children.
*
* @throws if the root element is not a SEQUENCE, or if child boundaries are inconsistent.
*/
function readDerSequenceOrThrow(e, t) {
	return readSequenceChildren(e, t);
}
/** Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children. */
function readDerSequence(e, t) {
	return attempt(() => readDerSequenceOrThrow(e, t), "Malformed DER sequence");
}
/**
* Reads the direct children of a constructed {@linkcode parent} within {@linkcode source}.
*
* @throws if a child overflows {@linkcode parent}, or data is left between the last child and its end.
*/
function derChildrenOrThrow(e, t) {
	return childrenOf(e, t);
}
/** Reads the direct children of a constructed {@linkcode parent} within {@linkcode source}. */
function derChildren(e, t) {
	return attempt(() => derChildrenOrThrow(e, t), "Malformed DER container");
}
/**
* Decodes a BOOLEAN element (tag `0x01`).
*
* @throws if {@linkcode element} is mis-tagged, or holds anything but `0x00` or `0xff`.
*/
function decodeDerBooleanOrThrow(e) {
	return decodeBoolean(requireTag(e, 1, "BOOLEAN").value);
}
/** Decodes a BOOLEAN element (tag `0x01`). */
function decodeDerBoolean(e) {
	return attempt(() => decodeDerBooleanOrThrow(e), "Malformed BOOLEAN");
}
/**
* Decodes an INTEGER element (tag `0x02`) into a `number`.
*
* @throws if {@linkcode element} is mis-tagged, negative, non-minimally encoded,
* or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
*/
function decodeDerIntegerOrThrow(e) {
	return decodeIntegerNumber(requireTag(e, 2, "INTEGER").value);
}
/** Decodes an INTEGER element (tag `0x02`) into a `number`. */
function decodeDerInteger(e) {
	return attempt(() => decodeDerIntegerOrThrow(e), "Malformed INTEGER");
}
/**
* Decodes an OCTET STRING element (tag `0x04`) into its payload bytes.
*
* @throws if {@linkcode element} is mis-tagged.
*/
function decodeDerOctetStringOrThrow(e) {
	return requireTag(e, 4, "OCTET STRING").value;
}
/** Decodes an OCTET STRING element (tag `0x04`) into its payload bytes. */
function decodeDerOctetString(e) {
	return attempt(() => decodeDerOctetStringOrThrow(e), "Malformed OCTET STRING");
}
/**
* Decodes an OBJECT IDENTIFIER element (tag `0x06`) into dotted-decimal form.
*
* @throws if {@linkcode element} is mis-tagged, or holds a malformed sub-identifier.
*/
function decodeDerOidOrThrow(e) {
	return decodeObjectIdentifier(requireTag(e, 6, "OBJECT IDENTIFIER").value);
}
/** Decodes an OBJECT IDENTIFIER element (tag `0x06`) into dotted-decimal form. */
function decodeDerOid(e) {
	return attempt(() => decodeDerOidOrThrow(e), "Malformed OBJECT IDENTIFIER");
}
/**
* Decodes a BIT STRING element (tag `0x03`) into a {@linkcode DerBitString}.
*
* Unused trailing bits are returned as encoded, with a violation of {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §11.2.1} reported
* through {@linkcode DerBitString.nonZeroPadding}, since certificates in the wild carry them.
*
* @throws if {@linkcode element} is mis-tagged, or claims more than seven unused bits.
*/
function decodeDerBitStringOrThrow(e) {
	return decodeBitString(e);
}
/**
* Decodes a BIT STRING element (tag `0x03`) into a {@linkcode DerBitString}.
*
* Unused trailing bits are returned as encoded, with a violation of {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §11.2.1} reported
* through {@linkcode DerBitString.nonZeroPadding}, since certificates in the wild carry them.
*/
function decodeDerBitString(e) {
	return attempt(() => decodeDerBitStringOrThrow(e), "Malformed BIT STRING");
}
/**
* Decodes a string element into text, dispatching on its tag.
*
* Supports UTF8String, PrintableString, TeletexString, IA5String, UniversalString, and BMPString.
* A TeletexString decodes only in its X.690 §8.23.5.2 initial state.
*
* @throws on every other string tag, and on a TeletexString octet outside that state.
*/
function decodeDerStringOrThrow(e) {
	return decodeString(e.tag, e.value);
}
/**
* Decodes a string element into text, dispatching on its tag.
*
* Supports UTF8String, PrintableString, TeletexString, IA5String, UniversalString, and BMPString.
* A TeletexString decodes only in its X.690 §8.23.5.2 initial state.
*/
function decodeDerString(e) {
	return attempt(() => decodeDerStringOrThrow(e), "Malformed string");
}
/**
* Decodes a UTCTime (tag `0x17`) or GeneralizedTime (tag `0x18`) element into a {@linkcode Date}.
*
* @throws if {@linkcode element} carries any other tag, or a malformed time value.
*/
function decodeDerTimeOrThrow(e) {
	return parseTime(e);
}
/** Decodes a UTCTime (tag `0x17`) or GeneralizedTime (tag `0x18`) element into a {@linkcode Date}. */
function decodeDerTime(e) {
	return attempt(() => decodeDerTimeOrThrow(e), "Malformed time");
}
export { t as DEFAULT_MAX_DER_DEPTH, assertDerMaxDepth, concatBytes, decodeDerBitString, decodeDerBitStringOrThrow, decodeDerBoolean, decodeDerBooleanOrThrow, decodeDerInteger, decodeDerIntegerOrThrow, decodeDerOctetString, decodeDerOctetStringOrThrow, decodeDerOid, decodeDerOidOrThrow, decodeDerString, decodeDerStringOrThrow, decodeDerTime, decodeDerTimeOrThrow, bitString as derBitString, bmpString as derBmpString, bool as derBoolean, derChildren, derChildrenOrThrow, explicitContext as derExplicitContext, generalizedTime as derGeneralizedTime, ia5String as derIa5String, implicitConstructedContext as derImplicitConstructedContext, implicitPrimitiveContext as derImplicitPrimitiveContext, integer as derInteger, integerFromNumber as derIntegerFromNumber, nullValue as derNull, octetString as derOctetString, objectIdentifier as derOid, printableString as derPrintableString, sequence as derSequence, setOf as derSet, time as derTime, tlv as derTlv, universalString as derUniversalString, utcTime as derUtcTime, utf8String as derUtf8String, hexToBytes, readDerElement, readDerElementOrThrow, readDerRoot, readDerRootOrThrow, readDerSequence, readDerSequenceOrThrow, toHex };
