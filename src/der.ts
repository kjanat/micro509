/**
 * DER reading and writing primitives.
 *
 * The building blocks every other entrypoint is made of, for the cases the typed APIs do not cover:
 *
 * - decoding a private extension's {@linkcode https://www.rfc-editor.org/info/rfc5280/#section-4.1 | extnValue} inside an {@linkcode https://micro509.kjanat.dev/next/api/x509#type-extensiondecoder | ExtensionDecoder}
 * - encoding the bytes a {@linkcode https://micro509.kjanat.dev/next/api/x509#type-customextension | CustomExtension} carries
 * - inspecting a structure this library does not model
 *
 * Reading accepts definite lengths and minimal length encodings, rejects the high-tag-number form,
 * and applies a nesting-depth guard capped at {@linkcode DEFAULT_MAX_DER_DEPTH}.
 * BER-only constructs fail.
 *
 * Readers and decoders take untrusted bytes, so each one comes as a pair:
 *
 * - {@linkcode https://micro509.kjanat.dev/next/api/der#fn-decodederinteger | decodeDerInteger} returns a {@linkcode https://micro509.kjanat.dev/next/api/der#type-decodederresult | DecodeDerResult}
 * - {@linkcode https://micro509.kjanat.dev/next/api/der#fn-decodederintegerorthrow | decodeDerIntegerOrThrow} throws
 *
 * Writers take typed input and throw, matching {@linkcode https://micro509.kjanat.dev/next/api/x509#fn-encodename | encodeName} and {@linkcode https://micro509.kjanat.dev/next/api/pem#fn-pemencode | pemEncode}.
 *
 * All operations are synchronous.
 *
 * @module micro509/der
 */

export type {
	DecodeDerErrorCode,
	DecodeDerFailure,
	DecodeDerResult,
} from '#micro509/der/der';
export {
	decodeDerBitString,
	decodeDerBitStringOrThrow,
	decodeDerBoolean,
	decodeDerBooleanOrThrow,
	decodeDerInteger,
	decodeDerIntegerOrThrow,
	decodeDerOctetString,
	decodeDerOctetStringOrThrow,
	decodeDerOid,
	decodeDerOidOrThrow,
	decodeDerString,
	decodeDerStringOrThrow,
	decodeDerTime,
	decodeDerTimeOrThrow,
	derChildren,
	derChildrenOrThrow,
	readDerElement,
	readDerElementOrThrow,
	readDerRoot,
	readDerRootOrThrow,
	readDerSequence,
	readDerSequenceOrThrow,
} from '#micro509/der/der';

export type { DerBitString } from '#micro509/internal/asn1/asn1';
export { hexToBytes, toHex } from '#micro509/internal/asn1/asn1';

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
	sequence as derSequence,
	setOf as derSet,
	time as derTime,
	tlv as derTlv,
	universalString as derUniversalString,
	utcTime as derUtcTime,
	utf8String as derUtf8String,
} from '#micro509/internal/asn1/der';
