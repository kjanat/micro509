/**
 * DER reading and writing primitives.
 *
 * The building blocks every other entrypoint is made of, for the cases the typed
 * APIs do not cover: decoding a private extension's `extnValue` inside an
 * {@linkcode ExtensionDecoder}, encoding the bytes a `CustomExtension` carries, or
 * inspecting a structure this library does not model.
 *
 * Reading is strict DER: definite lengths only, minimal length encodings, no
 * high-tag-number form, and a nesting-depth guard. BER-only constructs are
 * rejected rather than tolerated.
 *
 * All operations are synchronous, and every function throws on malformed input.
 *
 * @module micro509/der
 */

export {
	decodeDerBoolean,
	decodeDerInteger,
	decodeDerOctetString,
	decodeDerOid,
	decodeDerString,
	decodeDerTime,
} from '#micro509/der/der';

export type { DerBitString } from '#micro509/internal/asn1/asn1';
export {
	childrenOf as derChildren,
	decodeBitString as decodeDerBitString,
	hexToBytes,
	toHex,
} from '#micro509/internal/asn1/asn1';

export type {
	DerElement,
	ReadRootElementOptions,
	ReadSequenceChildrenOptions,
} from '#micro509/internal/asn1/der';
export {
	assertDerMaxDepth,
	bitString as derBitString,
	bmpString as derBmpString,
	bool as derBoolean,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext as derExplicitContext,
	generalizedTime as derGeneralizedTime,
	ia5String as derIa5String,
	implicitConstructedContext as derImplicitConstructedContext,
	implicitPrimitiveContext as derImplicitPrimitiveContext,
	integer as derInteger,
	integerFromNumber as derIntegerFromNumber,
	nullValue as derNull,
	objectIdentifier as derOid,
	octetString as derOctetString,
	printableString as derPrintableString,
	readElement as readDerElement,
	readRootElement as readDerRoot,
	readSequenceChildren as readDerSequence,
	sequence as derSequence,
	setOf as derSet,
	time as derTime,
	tlv as derTlv,
	universalString as derUniversalString,
	utcTime as derUtcTime,
	utf8String as derUtf8String,
} from '#micro509/internal/asn1/der';
