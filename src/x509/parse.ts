/**
 * Certificate and CSR parse boundary.
 *
 * Decodes DER and PEM inputs into typed {@linkcode ParsedCertificate} and
 * {@linkcode ParsedCertificateSigningRequest} structures.\
 * Includes an extension-decoder framework for callers that need richer metadata beyond the built-in
 * extensions.
 *
 * @module
 */

import {
	childrenOf,
	decodeBoolean,
	decodeIntegerNumber,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	DEFAULT_MAX_DER_DEPTH,
	readElement,
	readRootElement,
	readSequenceChildren,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	describePublicKeyAlgorithm,
	describeSignatureAlgorithm,
} from '#micro509/internal/crypto/algorithm-names';
import { decodeIpAddress } from '#micro509/internal/shared/ip';
import { readDirectoryNameTlv } from '#micro509/internal/x509/directory-name';
import type { ParsedBitFlags } from '#micro509/internal/x509/extension-bits';
import {
	parseDistributionPointReasonFlagsContent,
	parseKeyUsageExtension,
} from '#micro509/internal/x509/extension-bits';
import type {
	KnownParsedExtensionAccumulator,
	MutableKnownParsedExtensionAccumulator,
} from '#micro509/internal/x509/extension-registry';
import { decodeAndApplyKnownExtension } from '#micro509/internal/x509/extension-registry';
import { GENERAL_NAME_WIRE_TAGS } from '#micro509/internal/x509/general-name-tags';
import type { ImportKeyResult, PublicKeyImportInput } from '#micro509/keys/keys';
import {
	derivePublicKey,
	exportSpkiDer,
	importSpkiDer,
	importSpkiDerOrThrow,
} from '#micro509/keys/keys';
import { pemDecodeOrThrow, splitPemBlocksOrThrow } from '#micro509/pem/pem';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, rethrowIfInvariant, successResult } from '#micro509/result/result';
import type {
	AuthorityInformationAccess,
	BasicConstraints,
	CertificatePolicies,
	DistributionPointReason,
	ExtendedKeyUsage,
	GeneralName,
	GeneralSubtree,
	InhibitAnyPolicy,
	KeyUsage,
	NameConstraints,
	ParsedNameConstraintForm,
	PolicyConstraints,
	PolicyMappings,
	SubjectAltName,
} from '#micro509/x509/extensions';
import {
	parseAuthorityInfoAccessMethodOid,
	parseExtendedKeyUsageOid,
} from '#micro509/x509/extensions';
import type { NameFieldKey } from '#micro509/x509/name';
import { nameFieldKeyFromOid } from '#micro509/x509/name';

export type {
	AuthorityInformationAccess,
	BasicConstraints,
	CertificatePolicies,
	DistributionPointReason,
	ExtendedKeyUsage,
	GeneralName,
	GeneralSubtree,
	InhibitAnyPolicy,
	KeyUsage,
	NameConstraints,
	ParsedBitFlags,
	ParsedNameConstraintForm,
	PolicyConstraints,
	PolicyMappings,
	SubjectAltName,
} from '#micro509/x509/extensions';
export type { NameFieldKey } from '#micro509/x509/name';

/** Machine-readable failure reason for {@linkcode parseCertificateDer} / {@linkcode parseCertificatePem}. */
export type ParseCertificateErrorCode = 'malformed';

/** Structured failure payload for certificate parsing. */
export interface ParseCertificateFailure extends Micro509Error<ParseCertificateErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parseCertificateDer} / {@linkcode parseCertificatePem}. */
export type ParseCertificateResult<TMap extends ExtensionDecoderMap = Record<never, never>> =
	| { readonly ok: true; readonly value: ParsedCertificate<TMap> }
	| ErrorResult<ParseCertificateErrorCode, Record<never, never>, ParseCertificateFailure>;

/** Success-or-failure result from {@linkcode parseCertificateChainPem}. */
export type ParseCertificateChainResult<TMap extends ExtensionDecoderMap = Record<never, never>> =
	| { readonly ok: true; readonly value: readonly ParsedCertificate<TMap>[] }
	| ErrorResult<ParseCertificateErrorCode, Record<never, never>, ParseCertificateFailure>;

/** Machine-readable failure reason for the CSR parsers. */
export type ParseCertificateSigningRequestErrorCode = 'malformed';

/** Structured failure payload for CSR parsing. */
export interface ParseCertificateSigningRequestFailure
	extends Micro509Error<ParseCertificateSigningRequestErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Success-or-failure result from {@linkcode parseCertificateSigningRequestDer} /
 * {@linkcode parseCertificateSigningRequestPem}.
 */
export type ParseCertificateSigningRequestResult<
	TMap extends ExtensionDecoderMap = Record<never, never>,
> =
	| { readonly ok: true; readonly value: ParsedCertificateSigningRequest<TMap> }
	| ErrorResult<
			ParseCertificateSigningRequestErrorCode,
			Record<never, never>,
			ParseCertificateSigningRequestFailure
	  >;

/** Shared UTF-8 decoder for IA5String / UTF8String values. */
const textDecoder = new TextDecoder();

/**
 * A single decoded name attribute from an X.501 RelativeDistinguishedName.
 *
 * RFC 5280 / X.501 call this structure an `AttributeTypeAndValue`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 */
export interface ParsedNameAttribute {
	/** Dotted-decimal OID of the attribute type (e.g. `"2.5.4.3"` for CN). */
	readonly oid: string;
	/** Friendly key when the OID maps to a well-known field (CN, O, etc.). */
	readonly key?: NameFieldKey;
	/** ASN.1 tag of the value encoding (UTF8String = 0x0c, PrintableString = 0x13, etc.). */
	readonly valueTag: number;
	/** Decoded string content of the attribute value. */
	readonly value: string;
}

/**
 * An X.501 Distinguished Name decoded from an issuer or subject field.
 *
 * Provides three views of the same data: ordered RDNs, a flat attribute
 * list, and a convenience key-value map for well-known fields.
 */
export interface ParsedName {
	/** Hex-encoded DER of the complete Name SEQUENCE, usable for byte-exact comparisons. */
	readonly derHex: string;
	/** Ordered list of RelativeDistinguishedNames, preserving multi-valued RDN structure. */
	readonly rdns: readonly ParsedRelativeDistinguishedName[];
	/** Flat list of every attribute across all RDNs, in encounter order. */
	readonly attributes: readonly ParsedNameAttribute[];
	/** First-occurrence map of well-known fields (CN, O, OU, etc.) for quick lookups. */
	readonly values: Readonly<Partial<Record<NameFieldKey, string>>>;
}

/** A single RelativeDistinguishedName SET from an X.501 Name. */
export interface ParsedRelativeDistinguishedName {
	/** Hex-encoded DER of this RDN SET element. */
	readonly derHex: string;
	/** Attributes within this RDN (usually one, but multi-valued RDNs are legal). */
	readonly attributes: readonly ParsedNameAttribute[];
	/** First-occurrence map of well-known fields within this RDN. */
	readonly values: Readonly<Partial<Record<NameFieldKey, string>>>;
}

/**
 * The name component of a CRL Distribution Point (RFC 5280 §4.2.1.13).
 * Exactly one of `fullName` or `relativeName` will be present.
 */
export interface ParsedDistributionPointName {
	/** Absolute GeneralName(s) identifying the distribution point. */
	readonly fullName?: readonly GeneralName[];
	/** Name relative to the CRL issuer's distinguished name. */
	readonly relativeName?: ParsedRelativeDistinguishedName;
}

/** A decoded DistributionPoint from the CRL Distribution Points extension. */
export interface ParsedDistributionPoint {
	/** Where to fetch the CRL — a fullName URI or relativeName. */
	readonly distributionPoint?: ParsedDistributionPointName;
	/** Revocation reason subset this distribution point covers. Absent means all reasons. */
	readonly reasons?: ParsedBitFlags<DistributionPointReason>;
	/** Entity that signed the CRL, when different from the certificate issuer. */
	readonly crlIssuer?: readonly GeneralName[];
}

/**
 * Decoded Issuing Distribution Point CRL extension (RFC 5280 §5.2.5).
 * Constrains which certificates a CRL covers (scope, reasons, indirection).
 */
export interface ParsedIssuingDistributionPoint {
	/** Where to fetch this CRL, if specified. */
	readonly distributionPoint?: ParsedDistributionPointName;
	/** When true, this CRL only covers end-entity certificates. Default false. */
	readonly onlyContainsUserCerts?: boolean;
	/** When true, this CRL only covers CA certificates. Default false. */
	readonly onlyContainsCACerts?: boolean;
	/** Limits the CRL to these revocation reasons. Absent means all reasons. */
	readonly onlySomeReasons?: ParsedBitFlags<DistributionPointReason>;
	/** When true, this CRL may contain entries from CAs other than the issuer. Default false. */
	readonly indirectCrl?: boolean;
	/** When true, this CRL only covers attribute certificates. Default false. */
	readonly onlyContainsAttributeCerts?: boolean;
}

/** A raw X.509v3 extension before type-specific decoding. */
export interface ParsedExtension {
	/** Dotted-decimal OID identifying this extension. */
	readonly oid: string;
	/** Whether a validator MUST reject the certificate if it cannot process this extension. */
	readonly critical: boolean;
	/** DER-encoded OCTET STRING payload (extnValue). */
	readonly valueDer: Uint8Array;
	/** Hex-encoded form of `valueDer` for display and comparison. */
	readonly valueHex: string;
}

/**
 * User-supplied decoder for a single extension OID.
 *
 * Register with {@linkcode ParseOptions.decoders} or {@linkcode ParseOptions.decoderMap}
 * to decode custom extensions during parsing.
 */
export interface ExtensionDecoder<TValue> {
	/** OID this decoder handles. */
	readonly oid: string;
	/** Decode the raw {@linkcode ParsedExtension} into a typed value. */
	decode(extension: ParsedExtension): TValue;
}

/**
 * Identity helper that narrows the type of a custom {@linkcode ExtensionDecoder} literal.
 *
 * @param decoder Decoder definition to return unchanged.
 * @returns The same decoder, properly typed.
 */
export function defineExtensionDecoder<TValue>(
	decoder: ExtensionDecoder<TValue>,
): ExtensionDecoder<TValue> {
	return decoder;
}

/**
 * Identity helper that narrows the type of a custom {@linkcode ExtensionDecoderMap} literal.
 *
 * @param decoderMap Map of named decoders to return unchanged.
 * @returns The same map, properly typed.
 */
export function defineExtensionDecoderMap<TMap extends ExtensionDecoderMap>(
	decoderMap: TMap,
): TMap {
	return decoderMap;
}

/** String-keyed map of {@linkcode ExtensionDecoder}s, used with {@linkcode ParseOptions.decoderMap}. */
export type ExtensionDecoderMap = Record<string, ExtensionDecoder<unknown>>;

/** Inferred result type when decoding extensions via an {@linkcode ExtensionDecoderMap}. */
export type DecodedExtensionMap<TMap extends ExtensionDecoderMap> = {
	[TKey in keyof TMap]?: TMap[TKey] extends ExtensionDecoder<infer TValue>
		? DecodedExtensionValue<TValue>
		: never;
};

/** A successfully decoded extension value paired with its OID and criticality. */
export interface DecodedExtensionValue<TValue> {
	/** Dotted-decimal OID of the decoded extension. */
	readonly oid: string;
	/** Whether the extension was marked critical in the certificate. */
	readonly critical: boolean;
	/** Typed value produced by the {@linkcode ExtensionDecoder}. */
	readonly value: TValue;
}

/**
 * Options for {@linkcode parseCertificateDer}, {@linkcode parseCertificatePem},
 * and CSR parse functions.
 *
 * Supply custom extension decoders to have their results included in the parsed output alongside
 * the built-in extensions.
 */
export interface ParseOptions<TMap extends ExtensionDecoderMap = Record<never, never>> {
	/** Array of decoders; decoded values appear in `decodedExtensions`. */
	readonly decoders?: readonly ExtensionDecoder<unknown>[];
	/** Named decoder map; decoded values appear in `decodedExtensionMap` keyed by map key. */
	readonly decoderMap?: TMap;
}

/**
 * A fully decoded X.509 certificate.
 *
 * Built-in extensions (basicConstraints, keyUsage, etc.) are decoded into
 * typed fields automatically.\
 * Supply {@linkcode ParseOptions} to also decode custom extensions.
 */
export interface ParsedCertificate<TMap extends ExtensionDecoderMap = Record<never, never>> {
	/** Complete DER encoding of the certificate (copied from the input). */
	readonly der: Uint8Array;
	/** X.509 version number (1, 2, or 3). Almost always 3. */
	readonly version: number;
	/** Hex-encoded serial number assigned by the issuing CA. */
	readonly serialNumberHex: string;
	/** DER encoding of the TBSCertificate, used for signature verification. */
	readonly tbsCertificateDer: Uint8Array;
	/** DER encoding of the SubjectPublicKeyInfo, used for key import. */
	readonly subjectPublicKeyInfoDer: Uint8Array;
	/** Raw signature bytes (BIT STRING content, padding removed). */
	readonly signatureValue: Uint8Array;
	/** Distinguished name of the certificate issuer. */
	readonly issuer: ParsedName;
	/** Distinguished name of the certificate subject. */
	readonly subject: ParsedName;
	/** Start of the certificate validity period. */
	readonly notBefore: Date;
	/** End of the certificate validity period. */
	readonly notAfter: Date;
	/** OID of the algorithm used to sign this certificate (e.g. `"1.2.840.113549.1.1.11"` for SHA-256 with RSA). */
	readonly signatureAlgorithmOid: string;
	/** Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`). */
	readonly signatureAlgorithmName: string;
	/** DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters. */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
	/** OID of the subject's public key algorithm (e.g. `"1.2.840.10045.2.1"` for EC). */
	readonly publicKeyAlgorithmOid: string;
	/** Human-readable public key algorithm name (e.g. `"EC P-256"`). */
	readonly publicKeyAlgorithmName: string;
	/** DER-encoded parameters for the public key algorithm. Absent when implicit. */
	readonly publicKeyAlgorithmParametersDer?: Uint8Array;
	/** OID of the named curve or other key sub-parameter, when present. */
	readonly publicKeyParametersOid?: string;
	/** All extensions as raw {@linkcode ParsedExtension}s, in certificate order. */
	readonly extensions: readonly ParsedExtension[];
	/** Decoded Basic Constraints (RFC 5280 §4.2.1.9). */
	readonly basicConstraints?: BasicConstraints;
	/** Decoded Key Usage bit flags (RFC 5280 §4.2.1.3). */
	readonly keyUsage?: ParsedBitFlags<KeyUsage>;
	/** Decoded Extended Key Usage purposes (RFC 5280 §4.2.1.12). */
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	/** Decoded Subject Alternative Names (RFC 5280 §4.2.1.6). */
	readonly subjectAltNames?: readonly SubjectAltName[];
	/** Decoded Issuer Alternative Names (RFC 5280 §4.2.1.7). */
	readonly issuerAltNames?: readonly SubjectAltName[];
	/** Decoded Name Constraints (RFC 5280 §4.2.1.10). */
	readonly nameConstraints?: NameConstraints<ParsedNameConstraintForm>;
	/** Decoded Certificate Policies (RFC 5280 §4.2.1.4). */
	readonly certificatePolicies?: CertificatePolicies;
	/** Decoded Policy Mappings (RFC 5280 §4.2.1.5). */
	readonly policyMappings?: PolicyMappings;
	/** Decoded Policy Constraints (RFC 5280 §4.2.1.11). */
	readonly policyConstraints?: PolicyConstraints;
	/** Decoded Inhibit anyPolicy (RFC 5280 §4.2.1.14). */
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
	/** Decoded Authority Information Access — GeneralName access locations (RFC 5280 §4.2.2.1). */
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	/** Decoded CRL Distribution Points (RFC 5280 §4.2.1.13). */
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	/** Custom-decoded extensions from {@linkcode ParseOptions.decoders}. */
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	/** Custom-decoded extensions from {@linkcode ParseOptions.decoderMap}, keyed by map key. */
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
	/** Hex-encoded Subject Key Identifier (RFC 5280 §4.2.1.2). */
	readonly subjectKeyIdentifier?: string;
	/** Hex-encoded Authority Key Identifier (RFC 5280 §4.2.1.1). */
	readonly authorityKeyIdentifier?: string;
}

/**
 * A fully decoded PKCS#10 Certificate Signing Request.
 *
 * Extension fields mirror {@linkcode ParsedCertificate} but come from the
 * CSR's extensionRequest attribute rather than the v3 extensions block.
 */
export interface ParsedCertificateSigningRequest<
	TMap extends ExtensionDecoderMap = Record<never, never>,
> {
	/** PKCS#10 version number (always 1). */
	readonly version: number;
	/** DER encoding of the CertificationRequestInfo, used for signature verification. */
	readonly certificationRequestInfoDer: Uint8Array;
	/** DER encoding of the SubjectPublicKeyInfo. */
	readonly subjectPublicKeyInfoDer: Uint8Array;
	/** Raw signature bytes (BIT STRING content, padding removed). */
	readonly signatureValue: Uint8Array;
	/** Distinguished name the requester wants on the certificate. */
	readonly subject: ParsedName;
	/** OID of the algorithm used to sign this CSR. */
	readonly signatureAlgorithmOid: string;
	/** Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`). */
	readonly signatureAlgorithmName: string;
	/** DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters. */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
	/** OID of the subject's public key algorithm. */
	readonly publicKeyAlgorithmOid: string;
	/** Human-readable public key algorithm name (e.g. `"EC P-256"`). */
	readonly publicKeyAlgorithmName: string;
	/** DER-encoded parameters for the public key algorithm. */
	readonly publicKeyAlgorithmParametersDer?: Uint8Array;
	/** OID of the named curve or other key sub-parameter, when present. */
	readonly publicKeyParametersOid?: string;
	/** All requested extensions as raw {@linkcode ParsedExtension}s. */
	readonly requestedExtensions: readonly ParsedExtension[];
	/** Decoded Basic Constraints from the extensionRequest attribute. */
	readonly basicConstraints?: BasicConstraints;
	/** Decoded Key Usage from the extensionRequest attribute. */
	readonly keyUsage?: ParsedBitFlags<KeyUsage>;
	/** Decoded Extended Key Usage from the extensionRequest attribute. */
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	/** Decoded Subject Alternative Names from the extensionRequest attribute. */
	readonly subjectAltNames?: readonly SubjectAltName[];
	/** Decoded Name Constraints from the extensionRequest attribute. */
	readonly nameConstraints?: NameConstraints<ParsedNameConstraintForm>;
	/** Decoded Certificate Policies from the extensionRequest attribute. */
	readonly certificatePolicies?: CertificatePolicies;
	/** Decoded Policy Mappings from the extensionRequest attribute. */
	readonly policyMappings?: PolicyMappings;
	/** Decoded Policy Constraints from the extensionRequest attribute. */
	readonly policyConstraints?: PolicyConstraints;
	/** Decoded Inhibit anyPolicy from the extensionRequest attribute. */
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
	/** Decoded Authority Information Access from the extensionRequest attribute. */
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	/** Decoded CRL Distribution Points from the extensionRequest attribute. */
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	/** Custom-decoded extensions from {@linkcode ParseOptions.decoders}. */
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	/** Custom-decoded extensions from {@linkcode ParseOptions.decoderMap}. */
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
}

interface ParsedTbsCertificateFields {
	readonly version: number;
	readonly serialNumber: DerElement;
	readonly tbsSignatureAlgorithm: DerElement;
	readonly issuer: DerElement;
	readonly validity: DerElement;
	readonly subject: DerElement;
	readonly subjectPublicKeyInfo: DerElement;
	readonly extensions?: DerElement;
}

interface ParsedCertificateVersionField {
	readonly version: number;
	readonly nextIndex: number;
}

interface ParsedCustomExtensions<TMap extends ExtensionDecoderMap> {
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
}

interface ParsedCertificationRequestInfoFields {
	readonly version: number;
	readonly subject: DerElement;
	readonly subjectPublicKeyInfo: DerElement;
	readonly attributes?: DerElement;
}

interface MutableDistributionPointFields {
	distributionPoint?: ParsedDistributionPointName;
	reasons?: ParsedBitFlags<DistributionPointReason>;
	crlIssuer?: readonly GeneralName[];
}

/**
 * Throwing core for {@linkcode parseCertificateDer}.
 *
 * Decodes a DER-encoded X.509 certificate into a {@linkcode ParsedCertificate},
 * throwing on malformed input. All built-in extensions (basicConstraints,
 * keyUsage, subjectAltNames, etc.) are decoded automatically.\
 * Pass {@linkcode ParseOptions} to also decode custom extensions.
 *
 * @param der Raw DER bytes of an X.509 certificate.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateDerOrThrow<TMap extends ExtensionDecoderMap = Record<never, never>>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (topLevel.length !== 3) {
		throw new Error('Malformed Certificate');
	}
	const tbsCertificate = requireElement(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const fields = parseTbsCertificateFields(der, tbsCertificate);
	const parsedExtensions = parseExtensionContainer(der, fields.extensions);
	const parsedValidity = parseValidity(der, fields.validity);
	const parsedSpki = parseSubjectPublicKeyInfo(der, fields.subjectPublicKeyInfo);
	const parsedTbsSignatureAlgorithm = parseAlgorithmIdentifier(der, fields.tbsSignatureAlgorithm);
	const parsedSignatureAlgorithm = parseAlgorithmIdentifier(der, signatureAlgorithm);
	assertMatchingCertificateSignatureAlgorithms(
		parsedTbsSignatureAlgorithm,
		parsedSignatureAlgorithm,
	);
	const customExtensions = parseCustomExtensions(parsedExtensions.all, options);

	return {
		der: new Uint8Array(der),
		version: fields.version,
		serialNumberHex: toHex(fields.serialNumber.value),
		tbsCertificateDer: der.slice(
			tbsCertificate.start - tbsCertificate.headerLength,
			tbsCertificate.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			fields.subjectPublicKeyInfo.start - fields.subjectPublicKeyInfo.headerLength,
			fields.subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseName(der, fields.issuer),
		subject: parseName(der, fields.subject),
		notBefore: parsedValidity.notBefore,
		notAfter: parsedValidity.notAfter,
		signatureAlgorithmOid: parsedSignatureAlgorithm.oid,
		signatureAlgorithmName: describeSignatureAlgorithm(
			parsedSignatureAlgorithm.oid,
			parsedSignatureAlgorithm.parametersDer,
		),
		...(parsedSignatureAlgorithm.parametersDer !== undefined
			? { signatureAlgorithmParametersDer: parsedSignatureAlgorithm.parametersDer }
			: {}),
		publicKeyAlgorithmOid: parsedSpki.oid,
		publicKeyAlgorithmName: describePublicKeyAlgorithm(parsedSpki.oid, parsedSpki.parametersOid),
		...(parsedSpki.parametersDer !== undefined
			? { publicKeyAlgorithmParametersDer: parsedSpki.parametersDer }
			: {}),
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		extensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined ? { keyUsage: parsedExtensions.keyUsage } : {}),
		...(parsedExtensions.extendedKeyUsage !== undefined
			? { extendedKeyUsage: parsedExtensions.extendedKeyUsage }
			: {}),
		...(parsedExtensions.subjectAltNames !== undefined
			? { subjectAltNames: parsedExtensions.subjectAltNames }
			: {}),
		...(parsedExtensions.issuerAltNames !== undefined
			? { issuerAltNames: parsedExtensions.issuerAltNames }
			: {}),
		...(parsedExtensions.nameConstraints !== undefined
			? { nameConstraints: parsedExtensions.nameConstraints }
			: {}),
		...(parsedExtensions.certificatePolicies !== undefined
			? { certificatePolicies: parsedExtensions.certificatePolicies }
			: {}),
		...(parsedExtensions.policyMappings !== undefined
			? { policyMappings: parsedExtensions.policyMappings }
			: {}),
		...(parsedExtensions.policyConstraints !== undefined
			? { policyConstraints: parsedExtensions.policyConstraints }
			: {}),
		...(parsedExtensions.inhibitAnyPolicy !== undefined
			? { inhibitAnyPolicy: parsedExtensions.inhibitAnyPolicy }
			: {}),
		...(parsedExtensions.authorityInfoAccess !== undefined
			? { authorityInfoAccess: parsedExtensions.authorityInfoAccess }
			: {}),
		...(parsedExtensions.crlDistributionPoints !== undefined
			? { crlDistributionPoints: parsedExtensions.crlDistributionPoints }
			: {}),
		...(customExtensions.decodedExtensions === undefined
			? {}
			: { decodedExtensions: customExtensions.decodedExtensions }),
		...(customExtensions.decodedExtensionMap === undefined
			? {}
			: { decodedExtensionMap: customExtensions.decodedExtensionMap }),
		...(parsedExtensions.subjectKeyIdentifier !== undefined
			? { subjectKeyIdentifier: parsedExtensions.subjectKeyIdentifier }
			: {}),
		...(parsedExtensions.authorityKeyIdentifier !== undefined
			? { authorityKeyIdentifier: parsedExtensions.authorityKeyIdentifier }
			: {}),
	};
}

function parseCustomExtensions<TMap extends ExtensionDecoderMap>(
	extensions: readonly ParsedExtension[],
	options: ParseOptions<TMap> | undefined,
): ParsedCustomExtensions<TMap> {
	return {
		...(options?.decoders === undefined
			? {}
			: { decodedExtensions: decodeExtensions(extensions, options.decoders) }),
		...(options?.decoderMap === undefined
			? {}
			: { decodedExtensionMap: decodeExtensionMap(extensions, options.decoderMap) }),
	};
}

/** Extracts and validates the structural fields of a TBSCertificate sequence. */
function parseTbsCertificateFields(
	der: Uint8Array,
	tbsCertificate: DerElement,
): ParsedTbsCertificateFields {
	const tbsChildren = childrenOf(der, tbsCertificate);
	const versionField = parseCertificateVersionField(der, tbsChildren);
	const version = versionField.version;
	const index = versionField.nextIndex;
	const serialNumber = requireElement(tbsChildren[index], 'serialNumber');
	if (serialNumber.tag !== 0x02) {
		throw new Error('serialNumber must use INTEGER');
	}
	const cursor = validateOptionalTbsCertificateFields(tbsChildren, index + 6, version);
	return {
		version,
		serialNumber,
		tbsSignatureAlgorithm: requireElement(tbsChildren[index + 1], 'TBSCertificate signature'),
		issuer: requireElement(tbsChildren[index + 2], 'issuer'),
		validity: requireElement(tbsChildren[index + 3], 'validity'),
		subject: requireElement(tbsChildren[index + 4], 'subject'),
		subjectPublicKeyInfo: requireElement(tbsChildren[index + 5], 'subjectPublicKeyInfo'),
		...(tbsChildren[cursor - 1]?.tag === 0xa3 ? { extensions: tbsChildren[cursor - 1] } : {}),
	};
}

function parseCertificateVersionField(
	der: Uint8Array,
	tbsChildren: readonly DerElement[],
): ParsedCertificateVersionField {
	const maybeVersion = tbsChildren[0];
	if (maybeVersion?.tag !== 0xa0) {
		return { version: 1, nextIndex: 0 };
	}
	const versionChildren = childrenOf(der, maybeVersion);
	const versionElement = requireElement(versionChildren[0], 'version INTEGER');
	if (versionChildren.length !== 1 || versionElement.tag !== 0x02) {
		throw new Error('version must use INTEGER');
	}
	const version = decodeIntegerNumber(versionElement.value) + 1;
	if (version < 1 || version > 3) {
		throw new Error(`Unsupported certificate version: ${String(version)}`);
	}
	return { version, nextIndex: 1 };
}

function validateOptionalTbsCertificateFields(
	tbsChildren: readonly DerElement[],
	startCursor: number,
	version: number,
): number {
	let cursor = startCursor;
	if (tbsChildren[cursor]?.tag === 0x81) {
		validateCertificateUniqueId(tbsChildren[cursor], version, 'issuerUniqueID');
		cursor += 1;
	}
	if (tbsChildren[cursor]?.tag === 0x82) {
		validateCertificateUniqueId(tbsChildren[cursor], version, 'subjectUniqueID');
		cursor += 1;
	}
	if (tbsChildren[cursor]?.tag === 0xa3) {
		if (version !== 3) {
			throw new Error('extensions require certificate version 3');
		}
		cursor += 1;
	}
	if (cursor !== tbsChildren.length) {
		throw new Error(
			`Unsupported TBSCertificate field tag: ${String(requireElement(tbsChildren[cursor], 'TBSCertificate field').tag)}`,
		);
	}
	return cursor;
}

function validateCertificateUniqueId(
	element: DerElement | undefined,
	version: number,
	label: string,
): void {
	const uniqueIdElement = requireElement(element, label);
	if (version < 2) {
		throw new Error(`${label} requires certificate version 2 or 3`);
	}
	validateImplicitBitStringContent(uniqueIdElement.value, label);
}

/**
 * Decode a DER-encoded X.509 certificate into a {@linkcode ParsedCertificate}.
 *
 * @example
 * ```ts
 * import { parseCertificateDer } from 'micro509';
 *
 * const result = parseCertificateDer(derBytes);
 * if (result.ok) {
 * 	console.log(result.value.subject.values.commonName); // "example.com"
 * }
 * ```
 *
 * @param der Raw DER bytes of an X.509 certificate.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateDer<TMap extends ExtensionDecoderMap = Record<never, never>>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParseCertificateResult<TMap> {
	try {
		return successResult(parseCertificateDerOrThrow(der, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed certificate',
		);
	}
}

/**
 * Decode a PEM-encoded X.509 certificate into a {@linkcode ParsedCertificate}.
 *
 * Expects a single `-----BEGIN CERTIFICATE-----` block. For bundles
 * containing multiple certificates, use {@linkcode parseCertificateChainPem}.
 *
 * @example
 * Throws on malformed input. For a typed failure instead, use the
 * Result-returning {@linkcode parseCertificatePem}.
 *
 * ```ts
 * const certificate = parseCertificatePemOrThrow(pemString); // throws if malformed
 * console.log(certificate.issuer.values.organization); // "Let's Encrypt"
 * ```
 *
 * @param pem PEM string with a CERTIFICATE block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificatePemOrThrow<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pem: string,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	return parseCertificateDerOrThrow(pemDecodeOrThrow('CERTIFICATE', pem), options);
}

/**
 * Decode a PEM-encoded X.509 certificate into a {@linkcode ParsedCertificate}.
 *
 * Expects a single `-----BEGIN CERTIFICATE-----` block. For bundles
 * containing multiple certificates, use {@linkcode parseCertificateChainPem}.
 *
 * **Synchronous:** returns a {@linkcode ParseCertificateResult} directly. Do
 * not `await` this function.
 *
 * @param pem PEM string with a CERTIFICATE block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificatePem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pem: string,
	options?: ParseOptions<TMap>,
): ParseCertificateResult<TMap> {
	try {
		return successResult(parseCertificatePemOrThrow(pem, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed certificate',
		);
	}
}

/** Normalizes a PEM bundle or single DER certificate source into parsed certificates. */
export function parseCertificatesFromSource<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(source: string | Uint8Array, options?: ParseOptions<TMap>): readonly ParsedCertificate<TMap>[] {
	return typeof source === 'string'
		? parseCertificatesFromPemBlocks(source, options)
		: [parseCertificateDerOrThrow(new Uint8Array(source), options)];
}

/** Normalizes a PEM, DER, or already-parsed certificate source into one parsed certificate. */
export function parseCertificateFromSource<TMap extends ExtensionDecoderMap = Record<never, never>>(
	source: ParsedCertificate<TMap> | string | Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	if (typeof source === 'string') {
		return parseCertificatePemOrThrow(source, options);
	}
	if (hasParsedCertificateShape(source)) {
		return source;
	}
	const derSource: Uint8Array = source;
	return parseCertificateDerOrThrow(new Uint8Array(derSource), options);
}

/**
 * Decode a PEM bundle containing one or more certificates, throwing on malformed input.
 *
 * Non-CERTIFICATE blocks (e.g. private keys) are silently skipped.
 *
 * @param pemBundle PEM text that may contain multiple CERTIFICATE blocks.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateChainPemOrThrow<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pemBundle: string, options?: ParseOptions<TMap>): readonly ParsedCertificate<TMap>[] {
	return parseCertificatesFromPemBlocks(pemBundle, options);
}

/**
 * Decode a PEM bundle containing one or more certificates.
 *
 * Non-CERTIFICATE blocks (e.g. private keys) are silently skipped. Returns a
 * typed `malformed` failure for invalid PEM or certificate DER.
 *
 * @param pemBundle PEM text that may contain multiple CERTIFICATE blocks.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateChainPem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pemBundle: string,
	options?: ParseOptions<TMap>,
): ParseCertificateChainResult<TMap> {
	try {
		return successResult(parseCertificateChainPemOrThrow(pemBundle, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed certificate chain',
		);
	}
}

/**
 * Decode a DER-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param der Raw DER bytes of a PKCS#10 certificate signing request.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestDerOrThrow<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(der: Uint8Array, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (topLevel.length !== 3) {
		throw new Error('Malformed CertificationRequest');
	}
	const certificationRequestInfo = requireElement(topLevel[0], 'CertificationRequestInfo');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const fields = parseCertificationRequestInfoFields(der, certificationRequestInfo);
	const parsedExtensions = parseRequestedExtensions(der, fields.attributes);
	const parsedSpki = parseSubjectPublicKeyInfo(der, fields.subjectPublicKeyInfo);
	const parsedSignatureAlgorithm = parseAlgorithmIdentifier(der, signatureAlgorithm);
	const customExtensions = parseCustomExtensions(parsedExtensions.all, options);

	return {
		version: fields.version,
		certificationRequestInfoDer: der.slice(
			certificationRequestInfo.start - certificationRequestInfo.headerLength,
			certificationRequestInfo.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			fields.subjectPublicKeyInfo.start - fields.subjectPublicKeyInfo.headerLength,
			fields.subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		subject: parseName(der, fields.subject),
		signatureAlgorithmOid: parsedSignatureAlgorithm.oid,
		signatureAlgorithmName: describeSignatureAlgorithm(
			parsedSignatureAlgorithm.oid,
			parsedSignatureAlgorithm.parametersDer,
		),
		...(parsedSignatureAlgorithm.parametersDer !== undefined
			? { signatureAlgorithmParametersDer: parsedSignatureAlgorithm.parametersDer }
			: {}),
		publicKeyAlgorithmOid: parsedSpki.oid,
		publicKeyAlgorithmName: describePublicKeyAlgorithm(parsedSpki.oid, parsedSpki.parametersOid),
		...(parsedSpki.parametersDer !== undefined
			? { publicKeyAlgorithmParametersDer: parsedSpki.parametersDer }
			: {}),
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		requestedExtensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined ? { keyUsage: parsedExtensions.keyUsage } : {}),
		...(parsedExtensions.extendedKeyUsage !== undefined
			? { extendedKeyUsage: parsedExtensions.extendedKeyUsage }
			: {}),
		...(parsedExtensions.subjectAltNames !== undefined
			? { subjectAltNames: parsedExtensions.subjectAltNames }
			: {}),
		...(parsedExtensions.nameConstraints !== undefined
			? { nameConstraints: parsedExtensions.nameConstraints }
			: {}),
		...(parsedExtensions.certificatePolicies !== undefined
			? { certificatePolicies: parsedExtensions.certificatePolicies }
			: {}),
		...(parsedExtensions.policyMappings !== undefined
			? { policyMappings: parsedExtensions.policyMappings }
			: {}),
		...(parsedExtensions.policyConstraints !== undefined
			? { policyConstraints: parsedExtensions.policyConstraints }
			: {}),
		...(parsedExtensions.inhibitAnyPolicy !== undefined
			? { inhibitAnyPolicy: parsedExtensions.inhibitAnyPolicy }
			: {}),
		...(parsedExtensions.authorityInfoAccess !== undefined
			? { authorityInfoAccess: parsedExtensions.authorityInfoAccess }
			: {}),
		...(parsedExtensions.crlDistributionPoints !== undefined
			? { crlDistributionPoints: parsedExtensions.crlDistributionPoints }
			: {}),
		...(customExtensions.decodedExtensions === undefined
			? {}
			: { decodedExtensions: customExtensions.decodedExtensions }),
		...(customExtensions.decodedExtensionMap === undefined
			? {}
			: { decodedExtensionMap: customExtensions.decodedExtensionMap }),
	};
}

function parseCertificationRequestInfoFields(
	der: Uint8Array,
	certificationRequestInfo: DerElement,
): ParsedCertificationRequestInfoFields {
	const criChildren = childrenOf(der, certificationRequestInfo);
	if (criChildren.length < 3 || criChildren.length > 4) {
		throw new Error('Malformed CertificationRequestInfo');
	}
	const versionElement = requireElement(criChildren[0], 'version');
	if (versionElement.tag !== 0x02) {
		throw new Error('version must use INTEGER');
	}
	const version = decodeIntegerNumber(versionElement.value) + 1;
	if (version !== 1) {
		throw new Error(`Unsupported CertificationRequestInfo version: ${String(version)}`);
	}
	const attributes = criChildren[3];
	if (attributes !== undefined && attributes.tag !== 0xa0) {
		throw new Error('CertificationRequestInfo attributes must use [0]');
	}
	return {
		version,
		subject: requireElement(criChildren[1], 'subject'),
		subjectPublicKeyInfo: requireElement(criChildren[2], 'subjectPublicKeyInfo'),
		...(attributes === undefined ? {} : { attributes }),
	};
}

/**
 * Decode a DER-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param der Raw DER bytes of a PKCS#10 certificate signing request.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestDer<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(der: Uint8Array, options?: ParseOptions<TMap>): ParseCertificateSigningRequestResult<TMap> {
	try {
		return successResult(parseCertificateSigningRequestDerOrThrow(der, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed certificate signing request',
		);
	}
}

function parseCertificatesFromPemBlocks<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pemBundle: string,
	options?: ParseOptions<TMap>,
): readonly ParsedCertificate<TMap>[] {
	return splitPemBlocksOrThrow(pemBundle)
		.filter((block) => block.label === 'CERTIFICATE')
		.map((block) => parseCertificateDerOrThrow(block.bytes, options));
}

function hasParsedCertificateShape<TMap extends ExtensionDecoderMap = Record<never, never>>(
	value: ParsedCertificate<TMap> | Uint8Array,
): value is ParsedCertificate<TMap> {
	return 'subjectPublicKeyInfoDer' in value;
}

/**
 * Decode a PEM-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param pem PEM string with a CERTIFICATE REQUEST block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestPemOrThrow<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pem: string, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	return parseCertificateSigningRequestDerOrThrow(
		pemDecodeOrThrow('CERTIFICATE REQUEST', pem),
		options,
	);
}

/**
 * Decode a PEM-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param pem PEM string with a CERTIFICATE REQUEST block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestPem<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pem: string, options?: ParseOptions<TMap>): ParseCertificateSigningRequestResult<TMap> {
	try {
		return successResult(parseCertificateSigningRequestPemOrThrow(pem, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed',
			error instanceof Error ? error.message : 'Malformed certificate signing request',
		);
	}
}

/**
 * Import the subject public key of a parsed certificate or CSR as a WebCrypto `CryptoKey`.
 *
 * The key algorithm — and, for EC keys, the curve — is inferred from the
 * SubjectPublicKeyInfo's own AlgorithmIdentifier (the same resolution
 * {@linkcode importSpkiDerOrThrow} applies when no algorithm is given), so
 * callers never map {@linkcode ParsedCertificate.publicKeyAlgorithmOid} /
 * {@linkcode ParsedCertificate.publicKeyParametersOid} by hand.\
 * RSA keys import with the default `pkcs1-v1_5`/`SHA-256` parameters (a plain
 * `rsaEncryption` SPKI encodes neither padding scheme nor hash); pass
 * `algorithm` to choose other RSA parameters or to assert an expected
 * algorithm.
 *
 * @param parsed Parsed certificate or CSR whose subject public key to import.
 * @param algorithm Optional expected algorithm; must match the key contents when given.
 * @returns Extractable `CryptoKey` with `verify` usage.
 *
 * @throws {Error} If the SubjectPublicKeyInfo is malformed, encodes an
 * unsupported algorithm, or doesn't match `algorithm`
 *
 * @example
 * ```ts
 * const parsed = parseCertificatePemOrThrow(pem);
 * const publicKey = await getSubjectPublicKeyOrThrow(parsed);
 * ```
 *
 * @see {@linkcode getSubjectPublicKey} for the non-throwing variant
 */
export function getSubjectPublicKeyOrThrow<TMap extends ExtensionDecoderMap = Record<never, never>>(
	parsed: ParsedCertificate<TMap> | ParsedCertificateSigningRequest<TMap>,
	algorithm?: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDerOrThrow(parsed.subjectPublicKeyInfoDer, algorithm);
}

/**
 * Import the subject public key of a parsed certificate or CSR as a WebCrypto `CryptoKey`.
 *
 * @see `getSubjectPublicKeyOrThrow` for the throwing variant
 */
export function getSubjectPublicKey<TMap extends ExtensionDecoderMap = Record<never, never>>(
	parsed: ParsedCertificate<TMap> | ParsedCertificateSigningRequest<TMap>,
	algorithm?: PublicKeyImportInput,
): Promise<ImportKeyResult<CryptoKey>> {
	return importSpkiDer(parsed.subjectPublicKeyInfoDer, algorithm);
}

/** Outcome of comparing a private key's derived public half to a certificate's SPKI. */
type CertificatePrivateKeyComparison = 'match' | 'key_mismatch' | 'key_type_mismatch';

/** Extract the AlgorithmIdentifier TLV from a SubjectPublicKeyInfo DER buffer. */
function subjectPublicKeyInfoAlgorithmDer(subjectPublicKeyInfoDer: Uint8Array): Uint8Array {
	const children = readSequenceChildren(subjectPublicKeyInfoDer, {
		maxDepth: DEFAULT_MAX_DER_DEPTH,
	});
	const algorithm = requireElement(children[0], 'SubjectPublicKeyInfo algorithm');
	return subjectPublicKeyInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end);
}

/**
 * Derive the public half of `privateKey`, export it as SPKI DER, and classify
 * how it relates to a certificate's SubjectPublicKeyInfo. Single source of truth
 * for {@linkcode certificateMatchesPrivateKey} and {@linkcode matchCertificatePrivateKey}.
 *
 * Equal SPKI bytes mean the key owns the certificate. When they differ, the
 * AlgorithmIdentifier portions decide whether it is a same-algorithm key
 * mismatch or a cross-algorithm (`key_type_mismatch`) one.
 */
async function compareCertificateToPrivateKey(
	subjectPublicKeyInfoDer: Uint8Array,
	privateKey: CryptoKey,
): Promise<CertificatePrivateKeyComparison> {
	const derivedSpki = await exportSpkiDer(await derivePublicKey(privateKey));
	if (optionalBytesEqual(derivedSpki, subjectPublicKeyInfoDer)) {
		return 'match';
	}
	const sameAlgorithm = optionalBytesEqual(
		subjectPublicKeyInfoAlgorithmDer(derivedSpki),
		subjectPublicKeyInfoAlgorithmDer(subjectPublicKeyInfoDer),
	);
	return sameAlgorithm ? 'key_mismatch' : 'key_type_mismatch';
}

/**
 * Check whether a certificate's subject public key belongs to a private key.
 *
 * Confirming that an uploaded private key actually matches the certificate it
 * was submitted with is the first thing a key-intake or issuance endpoint must
 * do. This derives the public half of `privateKey`, exports it as
 * SubjectPublicKeyInfo DER, and compares those bytes against the certificate's
 * own SubjectPublicKeyInfo — the canonical, algorithm-agnostic way to test key
 * ownership. (Comparing JWKs field by field, or signing a probe and verifying
 * it, are both more fragile.)
 *
 * A private key of a different type — e.g. an ECDSA key against an RSA
 * certificate — simply produces different SPKI DER and returns `false`, so
 * callers get a single boolean without branching on the kind of mismatch. Reach
 * for {@linkcode matchCertificatePrivateKey} when you need the reason a match
 * failed (or a typed failure instead of a thrown error) at a trust boundary.
 *
 * The comparison is over the exact DER encoding. A certificate whose
 * SubjectPublicKeyInfo pins RSASSA-PSS parameters (rather than the plain
 * `rsaEncryption` OID that WebCrypto emits) therefore will not match even for
 * the same modulus; such certificates are rare in practice.
 *
 * @param certificate PEM string, DER bytes, or an already-parsed certificate.
 * @param privateKey An extractable private `CryptoKey`.
 * @returns `true` when the private key's public half matches the certificate's
 * subject public key.
 *
 * @throws {Error} If `certificate` is malformed, or `privateKey` is not an
 * extractable private key of a supported type (propagated from
 * {@linkcode derivePublicKey}). Use {@linkcode matchCertificatePrivateKey} for a
 * typed `Result` instead of thrown errors.
 *
 * @example
 * ```ts
 * const privateKey = await importPkcs8PemOrThrow(keyPem, { kind: 'ecdsa', curve: 'P-256' });
 * if (!(await certificateMatchesPrivateKey(certificatePem, privateKey))) {
 *   throw new Error('uploaded key does not match the certificate');
 * }
 * ```
 *
 * @see {@linkcode matchCertificatePrivateKey} for the typed-`Result` variant with a mismatch reason
 * @see {@linkcode getSubjectPublicKeyOrThrow} to obtain the certificate's public key directly
 * @see {@linkcode derivePublicKey} for the private-to-public bridge this builds on
 */
export async function certificateMatchesPrivateKey<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(
	certificate: ParsedCertificate<TMap> | string | Uint8Array,
	privateKey: CryptoKey,
): Promise<boolean> {
	const parsed = parseCertificateFromSource(certificate);
	return (
		(await compareCertificateToPrivateKey(parsed.subjectPublicKeyInfoDer, privateKey)) === 'match'
	);
}

/** Machine-readable failure reason for {@linkcode matchCertificatePrivateKey}. */
export type MatchCertificatePrivateKeyErrorCode =
	| 'malformed_certificate'
	| 'unsupported_private_key'
	| 'key_type_mismatch'
	| 'key_mismatch';

/** Structured failure payload for {@linkcode matchCertificatePrivateKey}. */
export interface MatchCertificatePrivateKeyFailure
	extends Micro509Error<MatchCertificatePrivateKeyErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** A successful match: the private key's public half is the certificate's subject public key. */
export interface MatchCertificatePrivateKeySuccess {
	/** Always `true` for success. */
	readonly ok: true;
	/** No payload on success — the match itself is the signal. */
	readonly value: undefined;
}

/** Failure branch of {@linkcode MatchCertificatePrivateKeyResult} with structured error details. */
export type MatchCertificatePrivateKeyFailureResult = ErrorResult<
	MatchCertificatePrivateKeyErrorCode,
	Record<never, never>,
	MatchCertificatePrivateKeyFailure
>;

/** Result of {@linkcode matchCertificatePrivateKey}. */
export type MatchCertificatePrivateKeyResult =
	| MatchCertificatePrivateKeySuccess
	| MatchCertificatePrivateKeyFailureResult;

/**
 * Check whether a certificate's subject public key belongs to a private key,
 * returning a typed {@linkcode MatchCertificatePrivateKeyResult}.
 *
 * The `Result`-returning companion to {@linkcode certificateMatchesPrivateKey}:
 * where the boolean helper answers only "does it match?" (and throws on bad
 * input), this surfaces the expected failures a key-intake or issuance endpoint
 * meets on untrusted input as typed codes rather than exceptions — matching the
 * house rule of returning `Result` for expected failures and throwing only for
 * invariants. `ok: true` means the key owns the certificate; a failure carries
 * one of:
 *
 * - `malformed_certificate` — `certificate` could not be parsed.
 * - `unsupported_private_key` — `privateKey` is not an extractable private key
 *   of a supported type (from {@linkcode derivePublicKey}).
 * - `key_type_mismatch` — the key is a different algorithm than the
 *   certificate's subject public key.
 * - `key_mismatch` — the key is the right algorithm but a different key.
 *
 * As with {@linkcode certificateMatchesPrivateKey}, the comparison is over exact
 * SPKI DER, so a certificate pinning RSASSA-PSS parameters reports
 * `key_type_mismatch` against the `rsaEncryption` SPKI WebCrypto emits.
 *
 * @param certificate PEM string, DER bytes, or an already-parsed certificate.
 * @param privateKey An extractable private `CryptoKey`.
 * @returns A success when the key matches, or a typed failure otherwise.
 *
 * @example
 * ```ts
 * const result = await matchCertificatePrivateKey(certificatePem, privateKey);
 * if (!result.ok) {
 *   // result.code is 'malformed_certificate' | 'unsupported_private_key'
 *   //              | 'key_type_mismatch' | 'key_mismatch'
 *   throw new Error(`key does not match certificate: ${result.code}`);
 * }
 * ```
 *
 * @see {@linkcode certificateMatchesPrivateKey} for the plain-boolean variant
 */
export async function matchCertificatePrivateKey<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(
	certificate: ParsedCertificate<TMap> | string | Uint8Array,
	privateKey: CryptoKey,
): Promise<MatchCertificatePrivateKeyResult> {
	let parsed: ParsedCertificate<TMap>;
	try {
		parsed = parseCertificateFromSource(certificate);
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'malformed_certificate',
			error instanceof Error ? error.message : 'Malformed certificate',
		);
	}
	let comparison: CertificatePrivateKeyComparison;
	try {
		comparison = await compareCertificateToPrivateKey(parsed.subjectPublicKeyInfoDer, privateKey);
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult(
			'unsupported_private_key',
			error instanceof Error ? error.message : 'Unsupported private key',
		);
	}
	switch (comparison) {
		case 'match':
			return successResult(undefined);
		case 'key_mismatch':
			return failureResult(
				'key_mismatch',
				"Private key does not match the certificate's subject public key",
			);
		case 'key_type_mismatch':
			return failureResult(
				'key_type_mismatch',
				"Private key algorithm does not match the certificate's subject public key algorithm",
			);
	}
}

/**
 * Find a raw extension by OID within a parsed extension list.
 *
 * @param extensions Extension list from a {@linkcode ParsedCertificate} or CSR.
 * @param oid Dotted-decimal OID to look up.
 * @returns The matching extension, or `undefined` if not present.
 */
export function findExtension(
	extensions: readonly ParsedExtension[],
	oid: string,
): ParsedExtension | undefined {
	return extensions.find((extension) => extension.oid === oid);
}

/**
 * Decode a single extension using a custom {@linkcode ExtensionDecoder}.
 *
 * @param extensions Extension list to search.
 * @param decoder Decoder whose OID will be matched.
 * @returns The decoded value, or `undefined` if the extension is absent.
 */
export function decodeExtension<TValue>(
	extensions: readonly ParsedExtension[],
	decoder: ExtensionDecoder<TValue>,
): TValue | undefined {
	const extension = findExtension(extensions, decoder.oid);
	if (extension === undefined) {
		return undefined;
	}
	return decoder.decode(extension);
}

/**
 * Decode all matching extensions using an array of {@linkcode ExtensionDecoder}s.
 *
 * @param extensions Extension list to search.
 * @param decoders Decoders to apply. Only matching OIDs produce output.
 */
export function decodeExtensions(
	extensions: readonly ParsedExtension[],
	decoders: readonly ExtensionDecoder<unknown>[],
): readonly DecodedExtensionValue<unknown>[] {
	const decoded: DecodedExtensionValue<unknown>[] = [];
	for (const decoder of decoders) {
		const extension = findExtension(extensions, decoder.oid);
		if (extension === undefined) {
			continue;
		}
		decoded.push({
			oid: extension.oid,
			critical: extension.critical,
			value: decoder.decode(extension),
		});
	}
	return decoded;
}

/**
 * Decode all matching extensions using a named {@linkcode ExtensionDecoderMap}.
 *
 * @param extensions Extension list to search.
 * @param decoderMap Named decoders. Results are keyed by the same map keys.
 */
export function decodeExtensionMap<TMap extends ExtensionDecoderMap>(
	extensions: readonly ParsedExtension[],
	decoderMap: TMap,
): DecodedExtensionMap<TMap> {
	let decoded: DecodedExtensionMap<TMap> = {};
	for (const key in decoderMap) {
		const decoder = decoderMap[key];
		if (decoder === undefined) {
			continue;
		}
		const extension = findExtension(extensions, decoder.oid);
		if (extension === undefined) {
			continue;
		}
		decoded = {
			...decoded,
			[key]: {
				oid: extension.oid,
				critical: extension.critical,
				value: decoder.decode(extension),
			},
		};
	}
	return decoded;
}

/** Aggregate of raw + decoded extensions produced during certificate/CSR parsing. */
interface ParsedExtensions extends KnownParsedExtensionAccumulator {
	/** Every extension as a raw {@linkcode ParsedExtension}, in wire order. */
	readonly all: readonly ParsedExtension[];
}

/** Decode the explicit [3] extensions wrapper from a TBSCertificate. */
function parseExtensionContainer(
	source: Uint8Array,
	container: DerElement | undefined,
): ParsedExtensions {
	if (container === undefined) {
		return { all: [] };
	}
	const sequenceElement = requireElement(childrenOf(source, container)[0], 'extensions sequence');
	return parseExtensionSequence(source, sequenceElement, 'certificate');
}

/** Extract extensions from the CSR extensionRequest attribute. */
function parseRequestedExtensions(
	source: Uint8Array,
	attributes: DerElement | undefined,
): ParsedExtensions {
	if (attributes === undefined) {
		return { all: [] };
	}
	if (attributes.tag !== 0xa0) {
		throw new Error('CertificationRequestInfo attributes must use [0]');
	}
	let requestedExtensions: ParsedExtensions | undefined;
	for (const attribute of childrenOf(source, attributes)) {
		const attributeChildren = childrenOf(source, attribute);
		if (attributeChildren.length !== 2) {
			throw new Error('Malformed CSR attribute');
		}
		const oid = requireElement(attributeChildren[0], 'attribute OID');
		if (decodeObjectIdentifier(oid.value) !== OIDS.extensionRequest) {
			continue;
		}
		if (requestedExtensions !== undefined) {
			throw new Error('extensionRequest attribute must not repeat');
		}
		const valuesSet = requireElement(attributeChildren[1], 'attribute values');
		if (valuesSet.tag !== 0x31) {
			throw new Error('extensionRequest attribute values must use SET');
		}
		const values = childrenOf(source, valuesSet);
		if (values.length !== 1) {
			throw new Error('extensionRequest attribute must contain exactly one value');
		}
		const requested = requireElement(values[0], 'requested extensions');
		requestedExtensions = parseExtensionSequence(source, requested, 'csr');
	}
	return requestedExtensions ?? { all: [] };
}

/** Walk a SEQUENCE OF Extension and decode each one, populating known-extension slots. */
function parseExtensionSequence(
	source: Uint8Array,
	sequenceElement: DerElement,
	context: 'certificate' | 'csr',
): ParsedExtensions {
	const parsed: ParsedExtension[] = [];
	const knownParsed: MutableKnownParsedExtensionAccumulator = {};
	const seenOids = new Set<string>();

	for (const extension of childrenOf(source, sequenceElement)) {
		const children = childrenOf(source, extension);
		if (children.length < 2 || children.length > 3) {
			throw new Error('Malformed Extension');
		}
		const oidElement = requireElement(children[0], 'extension OID');
		const oid = decodeObjectIdentifier(oidElement.value);
		if (seenOids.has(oid)) {
			throw new Error(`Duplicate extension OID: ${oid}`);
		}
		seenOids.add(oid);
		let offset = 1;
		let critical = false;
		const maybeCritical = children[offset];
		if (maybeCritical?.tag === 0x01) {
			critical = decodeBoolean(maybeCritical.value);
			offset += 1;
		}
		const extnValue = requireElement(children[offset], 'extension value');
		if (extnValue.tag !== 0x04 || offset !== children.length - 1) {
			throw new Error('Extension value must use OCTET STRING');
		}
		parsed.push({
			oid,
			critical,
			valueDer: new Uint8Array(extnValue.value),
			valueHex: toHex(extnValue.value),
		});
		decodeAndApplyKnownExtension(context, oid, knownParsed, extnValue.value);
	}

	return {
		all: parsed,
		...knownParsed,
	};
}

/** Decode an X.501 Name (issuer / subject) into a {@linkcode ParsedName}. */
function parseName(source: Uint8Array, element: DerElement): ParsedName {
	const rdns: ParsedRelativeDistinguishedName[] = [];
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const setElement of childrenOf(source, element)) {
		const rdn = parseNameAttributeSet(source, setElement);
		rdns.push(rdn);
		for (const attribute of rdn.attributes) {
			attributes.push(attribute);
			if (attribute.key !== undefined && values[attribute.key] === undefined) {
				values[attribute.key] = attribute.value;
			}
		}
	}
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
		rdns,
		attributes,
		values,
	};
}

/** Decode a single RDN SET element. */
function parseRelativeDistinguishedName(
	source: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	return parseNameAttributeSet(source, element);
}

/** Decode the AttributeTypeAndValue pairs within a SET element. */
function parseNameAttributeSet(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const fieldKey = nameFieldKeyFromOid(oid);
		const fieldValue = decodeString(valueElement.tag, valueElement.value);
		const attribute: ParsedNameAttribute =
			fieldKey !== undefined
				? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
				: { oid, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
}

/** Decode the Validity SEQUENCE into notBefore / notAfter Dates. */
function parseValidity(
	source: Uint8Array,
	element: DerElement,
): {
	readonly notBefore: Date;
	readonly notAfter: Date;
} {
	const children = childrenOf(source, element);
	return {
		notBefore: parseTime(requireElement(children[0], 'notBefore')),
		notAfter: parseTime(requireElement(children[1], 'notAfter')),
	};
}

/** Extract the algorithm identifier from a SubjectPublicKeyInfo SEQUENCE. */
function parseSubjectPublicKeyInfo(
	source: Uint8Array,
	element: DerElement,
): ParsedAlgorithmIdentifier {
	if (element.tag !== 0x30) {
		throw new Error('SubjectPublicKeyInfo must use SEQUENCE');
	}
	const children = childrenOf(source, element);
	if (children.length !== 2) {
		throw new Error('SubjectPublicKeyInfo must contain algorithm and subjectPublicKey');
	}
	const algorithmElement = requireElement(children[0], 'SPKI algorithm');
	if (algorithmElement.tag !== 0x30) {
		throw new Error('SubjectPublicKeyInfo algorithm must use SEQUENCE');
	}
	const algorithm = parseAlgorithmIdentifier(source, algorithmElement);
	extractBitStringValue(requireElement(children[1], 'subjectPublicKey BIT STRING'));
	return algorithm;
}

/** Decoded AlgorithmIdentifier: OID plus optional DER parameters. */
interface ParsedAlgorithmIdentifier {
	/** Dotted-decimal algorithm OID. */
	readonly oid: string;
	/** Full DER of the parameters element, when present. */
	readonly parametersDer?: Uint8Array;
	/** Decoded OID when the parameters element is itself an OID (e.g. named curves). */
	readonly parametersOid?: string;
}

/** Decode an AlgorithmIdentifier SEQUENCE (OID + optional parameters). */
function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): ParsedAlgorithmIdentifier {
	const children = childrenOf(source, element);
	if (children.length === 0 || children.length > 2) {
		throw new Error('Malformed AlgorithmIdentifier');
	}
	const oid = decodeObjectIdentifier(requireElement(children[0], 'algorithm OID').value);
	const parameters = children[1];
	if (parameters === undefined) {
		return { oid };
	}
	const parametersDer = source.slice(parameters.start - parameters.headerLength, parameters.end);
	if (parameters?.tag === 0x06) {
		return { oid, parametersDer, parametersOid: decodeObjectIdentifier(parameters.value) };
	}
	return { oid, parametersDer };
}

function assertMatchingCertificateSignatureAlgorithms(
	tbsSignatureAlgorithm: ParsedAlgorithmIdentifier,
	signatureAlgorithm: ParsedAlgorithmIdentifier,
): void {
	if (
		tbsSignatureAlgorithm.oid !== signatureAlgorithm.oid ||
		!optionalBytesEqual(tbsSignatureAlgorithm.parametersDer, signatureAlgorithm.parametersDer)
	) {
		throw new Error('Certificate signatureAlgorithm must match TBSCertificate signature');
	}
}

function optionalBytesEqual(left: Uint8Array | undefined, right: Uint8Array | undefined): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

/** @internal Decode the Basic Constraints extension value DER. */
export function parseBasicConstraints(bytes: Uint8Array): BasicConstraints {
	const element = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (element.tag !== 0x30) {
		throw new Error('basicConstraints must use SEQUENCE');
	}
	const children = childrenOf(bytes, element);
	let ca = false;
	let pathLength: number | undefined;
	let sawCa = false;
	let sawPathLength = false;
	for (const child of children) {
		if (child.tag === 0x01) {
			if (sawCa) {
				throw new Error('basicConstraints cA must not repeat');
			}
			if (sawPathLength) {
				throw new Error('basicConstraints cA must precede pathLength');
			}
			sawCa = true;
			ca = decodeBoolean(child.value);
			continue;
		}
		if (child.tag === 0x02) {
			if (sawPathLength) {
				throw new Error('basicConstraints pathLength must not repeat');
			}
			sawPathLength = true;
			pathLength = decodeNonNegativeIntegerNumber(child.value, 'basicConstraints pathLength');
			continue;
		}
		throw new Error(`Unsupported basicConstraints field tag: ${String(child.tag)}`);
	}
	if (pathLength !== undefined && ca !== true) {
		throw new Error('basicConstraints pathLength requires cA = true');
	}
	if (ca) {
		return pathLength !== undefined ? { ca: true, pathLength } : { ca: true };
	}
	return { ca: false };
}

/** @internal Decode the Key Usage BIT STRING extension value. */
export function parseKeyUsage(bytes: Uint8Array): ParsedBitFlags<KeyUsage> {
	return parseKeyUsageExtension(bytes);
}

/** @internal Decode the Extended Key Usage SEQUENCE OF OIDs. */
export function parseExtendedKeyUsage(bytes: Uint8Array): readonly ExtendedKeyUsage[] {
	const children = readSequenceChildren(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (children.length === 0) {
		throw new Error('extendedKeyUsage must not be empty');
	}
	return children.map((element) => {
		if (element.tag !== 0x06) {
			throw new Error('extendedKeyUsage entry must use OBJECT IDENTIFIER');
		}
		return parseExtendedKeyUsageOid(decodeObjectIdentifier(element.value));
	});
}

/** @internal Decode the Certificate Policies extension value. */
export function parseCertificatePolicies(bytes: Uint8Array): CertificatePolicies {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'certificatePolicies sequence',
	);
	const policyElements = childrenOf(bytes, sequenceElement);
	if (policyElements.length === 0) {
		throw new Error('certificatePolicies must not be empty');
	}
	return policyElements.map((policyElement) => parsePolicyInformation(bytes, policyElement));
}

/** Decode a single PolicyInformation SEQUENCE (OID + optional qualifiers). */
function parsePolicyInformation(source: Uint8Array, element: DerElement) {
	const children = childrenOf(source, element);
	const policyIdentifier = decodeObjectIdentifier(
		requireElement(children[0], 'policyIdentifier').value,
	);
	const qualifiersElement = children[1];
	if (children.length > 2) {
		throw new Error('policyInformation has unexpected trailing fields');
	}
	if (qualifiersElement === undefined) {
		return { policyIdentifier };
	}
	const qualifiers = childrenOf(source, qualifiersElement);
	if (qualifiers.length === 0) {
		throw new Error('policyQualifiers must not be empty');
	}
	return {
		policyIdentifier,
		policyQualifiers: qualifiers.map((qualifierElement) =>
			parsePolicyQualifierInfo(source, qualifierElement),
		),
	};
}

/** Decode a PolicyQualifierInfo (CPS URI, UserNotice, or opaque OID). */
function parsePolicyQualifierInfo(source: Uint8Array, element: DerElement) {
	const children = childrenOf(source, element);
	const qualifierId = decodeObjectIdentifier(
		requireElement(children[0], 'policyQualifierId').value,
	);
	const qualifierValue = requireElement(children[1], 'policyQualifier');
	if (children.length > 2) {
		throw new Error('policyQualifierInfo has unexpected trailing fields');
	}
	if (qualifierId === OIDS.cpsPolicyQualifier) {
		if (qualifierValue.tag !== 0x16) {
			throw new Error('cps policy qualifier must use IA5String');
		}
		return { type: 'cps' as const, uri: decodeString(qualifierValue.tag, qualifierValue.value) };
	}
	if (qualifierId === OIDS.userNoticePolicyQualifier) {
		return {
			type: 'userNotice' as const,
			...parseUserNoticePolicyQualifierInfo(source, qualifierValue),
		};
	}
	return {
		type: 'oid' as const,
		oid: qualifierId,
		qualifierDer: source.slice(
			qualifierValue.start - qualifierValue.headerLength,
			qualifierValue.end,
		),
	};
}

/** Decode a UserNotice qualifier (optional noticeRef + optional explicitText). */
function parseUserNoticePolicyQualifierInfo(
	source: Uint8Array,
	element: DerElement,
): {
	readonly noticeRef?: {
		readonly organization: string;
		readonly noticeNumbers: readonly number[];
	};
	readonly explicitText?: string;
} {
	const children = childrenOf(source, element);
	let noticeRef:
		| {
				readonly organization: string;
				readonly noticeNumbers: readonly number[];
		  }
		| undefined;
	let explicitText: string | undefined;
	for (const child of children) {
		if (child.tag === 0x30) {
			if (noticeRef !== undefined) {
				throw new Error('userNotice must not contain multiple noticeRef values');
			}
			noticeRef = parsePolicyNoticeReference(source, child);
			continue;
		}
		if (explicitText !== undefined) {
			throw new Error('userNotice must not contain multiple explicitText values');
		}
		explicitText = parseDisplayText(child);
	}
	return {
		...(noticeRef === undefined ? {} : { noticeRef }),
		...(explicitText === undefined ? {} : { explicitText }),
	};
}

/** Decode a NoticeReference (organization name + notice number list). */
function parsePolicyNoticeReference(
	source: Uint8Array,
	element: DerElement,
): {
	readonly organization: string;
	readonly noticeNumbers: readonly number[];
} {
	if (element.tag !== 0x30) {
		throw new Error('noticeRef must use SEQUENCE');
	}
	const children = childrenOf(source, element);
	const organization = parseDisplayText(requireElement(children[0], 'noticeRef organization'));
	const noticeNumbersElement = requireElement(children[1], 'noticeRef noticeNumbers');
	if (children.length > 2) {
		throw new Error('noticeRef has unexpected trailing fields');
	}
	return {
		organization,
		noticeNumbers: parsePolicyNoticeNumbers(source, noticeNumbersElement),
	};
}

/** Decode a SEQUENCE OF INTEGER notice numbers. */
function parsePolicyNoticeNumbers(source: Uint8Array, element: DerElement): readonly number[] {
	if (element.tag !== 0x30) {
		throw new Error('noticeRef noticeNumbers must use SEQUENCE');
	}
	const noticeNumberElements = childrenOf(source, element);
	if (noticeNumberElements.length === 0) {
		throw new Error('noticeRef noticeNumbers must not be empty');
	}
	return noticeNumberElements.map((noticeNumberElement) => {
		if (noticeNumberElement.tag !== 0x02) {
			throw new Error('noticeRef noticeNumber must use INTEGER');
		}
		return decodeNonNegativeIntegerNumber(noticeNumberElement.value, 'noticeRef noticeNumber');
	});
}

/** @internal Decode the Policy Mappings extension value. */
export function parsePolicyMappings(bytes: Uint8Array): PolicyMappings {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'policyMappings sequence',
	);
	const mappingElements = childrenOf(bytes, sequenceElement);
	if (mappingElements.length === 0) {
		throw new Error('policyMappings must not be empty');
	}
	return mappingElements.map((mappingElement) => {
		const children = childrenOf(bytes, mappingElement);
		const issuerDomainPolicy = decodeObjectIdentifier(
			requireElement(children[0], 'policyMappings issuerDomainPolicy').value,
		);
		const subjectDomainPolicy = decodeObjectIdentifier(
			requireElement(children[1], 'policyMappings subjectDomainPolicy').value,
		);
		if (children.length > 2) {
			throw new Error('policyMappings entry has unexpected trailing fields');
		}
		if (issuerDomainPolicy === OIDS.anyPolicy || subjectDomainPolicy === OIDS.anyPolicy) {
			throw new Error('policyMappings must not use anyPolicy');
		}
		return { issuerDomainPolicy, subjectDomainPolicy };
	});
}

/** @internal Decode the Policy Constraints extension value. */
export function parsePolicyConstraints(bytes: Uint8Array): PolicyConstraints {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'policyConstraints sequence',
	);
	let requireExplicitPolicy: number | undefined;
	let inhibitPolicyMapping: number | undefined;
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			if (requireExplicitPolicy !== undefined) {
				throw new Error('policyConstraints must not repeat requireExplicitPolicy');
			}
			requireExplicitPolicy = decodeNonNegativeIntegerNumber(
				child.value,
				'policyConstraints requireExplicitPolicy',
			);
			continue;
		}
		if (child.tag === 0x81) {
			if (inhibitPolicyMapping !== undefined) {
				throw new Error('policyConstraints must not repeat inhibitPolicyMapping');
			}
			inhibitPolicyMapping = decodeNonNegativeIntegerNumber(
				child.value,
				'policyConstraints inhibitPolicyMapping',
			);
			continue;
		}
		throw new Error(`Unsupported policyConstraints field tag: ${child.tag}`);
	}
	if (requireExplicitPolicy === undefined && inhibitPolicyMapping === undefined) {
		throw new Error('policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping');
	}
	return {
		...(requireExplicitPolicy === undefined ? {} : { requireExplicitPolicy }),
		...(inhibitPolicyMapping === undefined ? {} : { inhibitPolicyMapping }),
	};
}

/** @internal Decode the Inhibit anyPolicy extension (single INTEGER). */
export function parseInhibitAnyPolicy(bytes: Uint8Array): InhibitAnyPolicy {
	const integerElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'inhibitAnyPolicy integer',
	);
	if (integerElement.tag !== 0x02) {
		throw new Error('inhibitAnyPolicy must be an INTEGER');
	}
	return {
		skipCerts: decodeNonNegativeIntegerNumber(integerElement.value, 'inhibitAnyPolicy skipCerts'),
	};
}

/** @internal Decode a subjectAltName or issuerAltName SEQUENCE OF GeneralName. */
export function parseSubjectAltNames(
	bytes: Uint8Array,
	label = 'subjectAltName',
): readonly SubjectAltName[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		`${label} sequence`,
	);
	if (sequenceElement.tag !== 0x30) {
		throw new Error(`${label} must use SEQUENCE`);
	}
	return parseGeneralNames(bytes, sequenceElement);
}

/** @internal Decode a bare DER-encoded X.501 Name, as carried in a `directoryName` GeneralName. */
export function parseDistinguishedNameDer(bytes: Uint8Array): ParsedName {
	const nameElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'distinguished name sequence',
	);
	if (nameElement.tag !== 0x30) {
		throw new Error('distinguished name must use SEQUENCE');
	}
	return parseName(bytes, nameElement);
}

/** @internal Decode the Authority Information Access extension value. */
export function parseAuthorityInfoAccess(bytes: Uint8Array): readonly AuthorityInformationAccess[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'authorityInfoAccess sequence',
	);
	if (sequenceElement.tag !== 0x30) {
		throw new Error('authorityInfoAccess must use SEQUENCE');
	}
	const accessDescriptions = childrenOf(bytes, sequenceElement);
	if (accessDescriptions.length === 0) {
		throw new Error('authorityInfoAccess must not be empty');
	}
	return accessDescriptions.map((element) => {
		if (element.tag !== 0x30) {
			throw new Error('authorityInfoAccess entry must use SEQUENCE');
		}
		const children = childrenOf(bytes, element);
		if (children.length !== 2) {
			throw new Error('authorityInfoAccess entry must contain method and location only');
		}
		const method = requireElement(children[0], 'authorityInfoAccess method');
		const location = requireElement(children[1], 'authorityInfoAccess location');
		if (method.tag !== 0x06) {
			throw new Error('authorityInfoAccess method must use OBJECT IDENTIFIER');
		}
		return {
			method: parseAuthorityInfoAccessMethodOid(decodeObjectIdentifier(method.value)),
			location: parseGeneralName(bytes, location),
		};
	});
}

/** @internal Decode the CRL Distribution Points extension value. */
export function parseCrlDistributionPoints(bytes: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'CRLDistributionPoints sequence',
	);
	if (sequenceElement.tag !== 0x30) {
		throw new Error('CRLDistributionPoints must use SEQUENCE');
	}
	const elements = childrenOf(bytes, sequenceElement);
	if (elements.length === 0) {
		throw new Error('CRLDistributionPoints must not be empty');
	}
	const points: ParsedDistributionPoint[] = [];
	for (const distributionPoint of elements) {
		points.push(parseDistributionPoint(bytes, distributionPoint));
	}
	return points;
}

/** Decode a single DistributionPoint SEQUENCE. */
function parseDistributionPoint(source: Uint8Array, element: DerElement): ParsedDistributionPoint {
	if (element.tag !== 0x30) {
		throw new Error('DistributionPoint must use SEQUENCE');
	}
	const fields: MutableDistributionPointFields = {};
	for (const child of childrenOf(source, element)) {
		parseDistributionPointField(source, child, fields);
	}
	if (fields.distributionPoint === undefined && fields.crlIssuer === undefined) {
		throw new Error('DistributionPoint must include distributionPoint or crlIssuer');
	}
	return {
		...(fields.distributionPoint === undefined
			? {}
			: { distributionPoint: fields.distributionPoint }),
		...(fields.reasons === undefined ? {} : { reasons: fields.reasons }),
		...(fields.crlIssuer === undefined ? {} : { crlIssuer: fields.crlIssuer }),
	};
}

function parseDistributionPointField(
	source: Uint8Array,
	child: DerElement,
	fields: MutableDistributionPointFields,
): void {
	switch (child.tag) {
		case 0xa0:
			if (fields.distributionPoint !== undefined)
				throw new Error('DistributionPoint distributionPoint must not repeat');
			fields.distributionPoint = parseDistributionPointName(source, child);
			return;
		case 0x81:
			if (fields.reasons !== undefined)
				throw new Error('DistributionPoint reasons must not repeat');
			fields.reasons = parseDistributionPointReasonFlagsContent(child.value);
			return;
		case 0xa2:
			if (fields.crlIssuer !== undefined)
				throw new Error('DistributionPoint crlIssuer must not repeat');
			fields.crlIssuer = parseGeneralNames(source, child);
			return;
		default:
			throw new Error(`Unsupported DistributionPoint field tag: ${String(child.tag)}`);
	}
}

/** Decode a DistributionPointName (fullName or relativeName). */
function parseDistributionPointName(
	source: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName {
	const children = childrenOf(source, element);
	if (children.length !== 1) {
		throw new Error('distributionPointName must contain exactly one choice');
	}
	const distributionPointName = requireElement(children[0], 'distributionPointName');
	if (distributionPointName.tag === 0xa0) {
		const fullName = childrenOf(source, distributionPointName);
		if (fullName.length === 0) {
			throw new Error('distributionPointName fullName must not be empty');
		}
		for (const name of fullName) {
			if ((name.tag & 0xc0) !== 0x80) {
				throw new Error('distributionPointName fullName must contain GeneralName entries');
			}
		}
		return {
			fullName: fullName.map((name) => parseGeneralName(source, name)),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		return { relativeName: parseRelativeDistinguishedName(source, distributionPointName) };
	}
	throw new Error(`Unsupported distributionPointName tag: ${distributionPointName.tag}`);
}

/** Decode a SEQUENCE OF GeneralName. */
function parseGeneralNames(source: Uint8Array, element: DerElement): readonly GeneralName[] {
	const names = childrenOf(source, element);
	if (names.length === 0) {
		throw new Error('GeneralNames must not be empty');
	}
	for (const name of names) {
		if ((name.tag & 0xc0) !== 0x80) {
			throw new Error('GeneralNames must contain GeneralName entries');
		}
	}
	return names.map((name) => parseGeneralName(source, name));
}

/** Decode a single GeneralName from its implicit context tag. */
function parseGeneralName(source: Uint8Array, element: DerElement): GeneralName {
	switch (element.tag) {
		case 0xa0: {
			const otherName = parseOtherName(source, element);
			if (otherName !== undefined) {
				return otherName;
			}
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
		}
		case 0x81:
			return { type: 'email' as const, value: decodeString(0x16, element.value) };
		case 0x82:
			return { type: 'dns' as const, value: decodeString(0x16, element.value) };
		case 0x86:
			return { type: 'uri' as const, value: decodeString(0x16, element.value) };
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(readDirectoryNameTlv(element)),
			};
		default:
			// x400Address [3], ediPartyName [5], and registeredID [8] are valid but
			// unsupported; any other tag/class/constructedness is not a GeneralName.
			if (!GENERAL_NAME_WIRE_TAGS.has(element.tag)) {
				throw new Error(`Invalid GeneralName tag: ${element.tag}`);
			}
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
	}
}

/**
 * Decode an otherName [0] as a known type (currently only SRV-ID).
 *
 * `otherName [0] OtherName` is in the IMPLICIT-TAGS module, so the [0] tag
 * replaces OtherName's SEQUENCE tag: the type-id and `value [0] EXPLICIT` are
 * the direct children, with no inner SEQUENCE. A malformed envelope, or a
 * malformed payload of a recognised OID, throws. A structurally valid OtherName
 * with an unsupported OID returns `undefined`, so the caller preserves it as
 * `{ type: 'unknown' }`.
 */
function parseOtherName(source: Uint8Array, element: DerElement): SubjectAltName | undefined {
	const children = childrenOf(source, element);
	const typeId = children[0];
	const valueElement = children[1];
	if (
		children.length !== 2 ||
		typeId === undefined ||
		valueElement === undefined ||
		typeId.tag !== 0x06 ||
		valueElement.tag !== 0xa0
	) {
		throw new Error('Malformed otherName');
	}
	const valueChildren = childrenOf(source, valueElement);
	const value = valueChildren[0];
	if (valueChildren.length !== 1 || value === undefined) {
		throw new Error('otherName value [0] must wrap exactly one element');
	}
	if (decodeObjectIdentifier(typeId.value) !== OIDS.idOnDnsSrv) {
		return undefined;
	}
	if (value.tag !== 0x16 || value.value.length === 0) {
		throw new Error('SRV-ID otherName must wrap a non-empty IA5String');
	}
	return { type: 'srv', value: decodeString(value.tag, value.value) };
}

/** @internal Decode the Name Constraints extension value. */
export function parseNameConstraints(bytes: Uint8Array): NameConstraints<ParsedNameConstraintForm> {
	const sequenceElement = requireElement(
		readRootElement(bytes, {
			maxDepth: DEFAULT_MAX_DER_DEPTH,
			allowOpaqueConstructedTags: [0xa0, 0xa3, 0xa5],
		}),
		'nameConstraints sequence',
	);
	if (sequenceElement.tag !== 0x30) {
		throw new Error('nameConstraints must use SEQUENCE');
	}
	let permittedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
	let excludedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0xa0) {
			if (permittedSubtrees !== undefined) {
				throw new Error('nameConstraints permittedSubtrees must not repeat');
			}
			permittedSubtrees = parseGeneralSubtrees(bytes, child);
		} else if (child.tag === 0xa1) {
			if (excludedSubtrees !== undefined) {
				throw new Error('nameConstraints excludedSubtrees must not repeat');
			}
			excludedSubtrees = parseGeneralSubtrees(bytes, child);
		} else {
			throw new Error(`Unsupported nameConstraints field tag: ${String(child.tag)}`);
		}
	}
	return {
		...(permittedSubtrees !== undefined ? { permittedSubtrees } : {}),
		...(excludedSubtrees !== undefined ? { excludedSubtrees } : {}),
	};
}

/** Decode a SEQUENCE OF GeneralSubtree from a permittedSubtrees or excludedSubtrees wrapper. */
function parseGeneralSubtrees(
	source: Uint8Array,
	container: DerElement,
): readonly GeneralSubtree<ParsedNameConstraintForm>[] {
	const subtrees: GeneralSubtree<ParsedNameConstraintForm>[] = [];
	const subtreeElements = childrenOf(source, container);
	if (subtreeElements.length === 0) {
		throw new Error('name constraints GeneralSubtrees must not be empty');
	}
	for (const subtreeElement of subtreeElements) {
		const form = parseGeneralSubtree(source, subtreeElement);
		if (form !== undefined) {
			subtrees.push({ base: form });
		}
	}
	return subtrees;
}

function parseGeneralSubtree(
	source: Uint8Array,
	subtreeElement: DerElement,
): ParsedNameConstraintForm | undefined {
	if (subtreeElement.tag !== 0x30) {
		throw new Error('name constraints GeneralSubtree must use SEQUENCE');
	}
	const children = childrenOf(source, subtreeElement);
	const baseElement = children[0];
	if (baseElement === undefined) {
		throw new Error('GeneralSubtree base is required');
	}
	validateGeneralSubtreeBounds(children.slice(1));
	return parseNameConstraintGeneralName(baseElement);
}

function validateGeneralSubtreeBounds(children: readonly DerElement[]): void {
	let sawMinimum = false;
	for (const child of children) {
		if (child.tag === 0x80) {
			if (sawMinimum) throw new Error('name constraints GeneralSubtree minimum must not repeat');
			sawMinimum = true;
			if (
				decodeNonNegativeIntegerNumber(child.value, 'name constraints GeneralSubtree minimum') !== 0
			) {
				throw new Error('name constraints GeneralSubtree minimum must be 0');
			}
			continue;
		}
		if (child.tag === 0x81)
			throw new Error('name constraints GeneralSubtree maximum is not supported');
		throw new Error(`Unsupported name constraints GeneralSubtree field tag: ${String(child.tag)}`);
	}
}

/** Decode a GeneralName for use in name constraints (IP carries address+mask). */
function parseNameConstraintGeneralName(element: DerElement): ParsedNameConstraintForm | undefined {
	switch (element.tag) {
		case 0xa0:
			return { type: 'otherName', value: new Uint8Array(element.value) };
		case 0x81:
			return { type: 'email', value: decodeString(0x16, element.value) };
		case 0x82:
			return { type: 'dns', value: decodeString(0x16, element.value) };
		case 0xa3:
			return { type: 'x400Address', value: new Uint8Array(element.value) };
		case 0x86:
			return { type: 'uri', value: decodeString(0x16, element.value) };
		case 0x87: {
			if (element.value.length === 8) {
				return {
					type: 'ip',
					addressBytes: element.value.slice(0, 4),
					maskBytes: element.value.slice(4, 8),
				};
			}
			if (element.value.length === 32) {
				return {
					type: 'ip',
					addressBytes: element.value.slice(0, 16),
					maskBytes: element.value.slice(16, 32),
				};
			}
			throw new Error(
				`Invalid IP name constraint: expected 8 (IPv4) or 32 (IPv6) bytes, got ${String(element.value.length)}`,
			);
		}
		case 0xa4:
			return {
				type: 'directoryName',
				derHex: toHex(readDirectoryNameTlv(element)),
			};
		case 0xa5:
			return { type: 'ediPartyName', value: new Uint8Array(element.value) };
		case 0x88:
			return { type: 'registeredID', value: decodeObjectIdentifier(element.value) };
	}
	throw new Error(`Unsupported name constraint GeneralName tag: ${String(element.tag)}`);
}

/** Decode a DisplayText (UTF8String, IA5String, VisibleString, or BMPString). */
function parseDisplayText(element: DerElement): string {
	switch (element.tag) {
		case 0x0c:
		case 0x16:
		case 0x1a:
			return textDecoder.decode(element.value);
		case 0x1e:
			return decodeBmpString(element.value);
		default:
			throw new Error(`Unsupported DisplayText tag: ${element.tag}`);
	}
}

/** Decode a BMPString (UCS-2 big-endian) to a JS string. */
function decodeBmpString(bytes: Uint8Array): string {
	if (bytes.length % 2 !== 0) {
		throw new Error('Invalid BMPString length');
	}
	let value = '';
	for (let index = 0; index < bytes.length; index += 2) {
		const left = bytes[index];
		const right = bytes[index + 1];
		if (left === undefined || right === undefined) {
			throw new Error('Invalid BMPString content');
		}
		value += String.fromCharCode((left << 8) | right);
	}
	return value;
}

/** @internal Decode the Authority Key Identifier extension, returning the keyIdentifier hex or undefined. */
interface MutableAuthorityKeyIdentifierState {
	keyIdentifier?: string;
	sawAuthorityCertIssuer: boolean;
	sawAuthorityCertSerialNumber: boolean;
	lastFieldOrder: number;
}

export function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = requireElement(readElement(bytes, 0), 'authorityKeyIdentifier sequence');
	if (sequenceElement.end !== bytes.length) {
		throw new Error('Trailing data after DER element');
	}
	const state: MutableAuthorityKeyIdentifierState = {
		sawAuthorityCertIssuer: false,
		sawAuthorityCertSerialNumber: false,
		lastFieldOrder: -1,
	};
	let offset = sequenceElement.start;
	while (offset < sequenceElement.end) {
		const child = readElement(bytes, offset);
		if (child.end > sequenceElement.end) {
			throw new Error('DER child exceeds parent length');
		}
		parseAuthorityKeyIdentifierField(bytes, child, state);
		offset = child.end;
	}
	if (offset !== sequenceElement.end) {
		throw new Error('Malformed DER sequence');
	}
	if (state.sawAuthorityCertIssuer !== state.sawAuthorityCertSerialNumber) {
		throw new Error(
			'authorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber must appear together',
		);
	}
	return state.keyIdentifier;
}

function parseAuthorityKeyIdentifierField(
	bytes: Uint8Array,
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	switch (child.tag) {
		case 0x80:
			parseAuthorityKeyIdentifierKeyId(child, state);
			return;
		case 0xa1:
			parseAuthorityKeyIdentifierIssuer(bytes, child, state);
			return;
		case 0x82:
			parseAuthorityKeyIdentifierSerial(child, state);
			return;
		default:
			throw new Error(`Unsupported authorityKeyIdentifier field tag: ${String(child.tag)}`);
	}
}

function parseAuthorityKeyIdentifierKeyId(
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.keyIdentifier !== undefined) {
		throw new Error('authorityKeyIdentifier keyIdentifier must not repeat');
	}
	if (state.lastFieldOrder >= 0) {
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	}
	state.keyIdentifier = toHex(child.value);
	state.lastFieldOrder = 0;
}

function parseAuthorityKeyIdentifierIssuer(
	bytes: Uint8Array,
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.sawAuthorityCertIssuer) {
		throw new Error('authorityKeyIdentifier authorityCertIssuer must not repeat');
	}
	if (state.lastFieldOrder >= 1) {
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	}
	const issuerNames = childrenOf(bytes, child);
	if (issuerNames.length === 0) {
		throw new Error('authorityKeyIdentifier authorityCertIssuer must contain GeneralName entries');
	}
	for (const issuerName of issuerNames) {
		if ((issuerName.tag & 0xc0) !== 0x80) {
			throw new Error(
				'authorityKeyIdentifier authorityCertIssuer must contain GeneralName entries',
			);
		}
		parseGeneralName(bytes, issuerName);
	}
	state.sawAuthorityCertIssuer = true;
	state.lastFieldOrder = 1;
}

function parseAuthorityKeyIdentifierSerial(
	child: DerElement,
	state: MutableAuthorityKeyIdentifierState,
): void {
	if (state.sawAuthorityCertSerialNumber) {
		throw new Error('authorityKeyIdentifier authorityCertSerialNumber must not repeat');
	}
	if (state.lastFieldOrder >= 2 || !state.sawAuthorityCertIssuer) {
		throw new Error('authorityKeyIdentifier fields must preserve DER order');
	}
	validateImplicitSerialNumberEncoding(
		child.value,
		'authorityKeyIdentifier authorityCertSerialNumber',
	);
	state.sawAuthorityCertSerialNumber = true;
	state.lastFieldOrder = 2;
}

function validateImplicitSerialNumberEncoding(bytes: Uint8Array, label: string): void {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error(`${label} must not be empty`);
	}
	if ((first & 0x80) !== 0) {
		throw new Error(`${label} must be non-negative`);
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error(`${label} must use minimal encoding`);
	}
}

function validateImplicitBitStringContent(bytes: Uint8Array, label: string): void {
	const unusedBits = bytes[0];
	if (unusedBits === undefined || unusedBits > 7) {
		throw new Error(`${label} must use BIT STRING encoding`);
	}
	const bitStringBytes = bytes.slice(1);
	if (bitStringBytes.length === 0) {
		if (unusedBits !== 0) {
			throw new Error(`${label} must use BIT STRING encoding`);
		}
		return;
	}
	if (unusedBits === 0) {
		return;
	}
	const lastByte = bitStringBytes[bitStringBytes.length - 1];
	if (lastByte === undefined) {
		throw new Error(`${label} must use BIT STRING encoding`);
	}
	const paddingMask = (1 << unusedBits) - 1;
	if ((lastByte & paddingMask) !== 0) {
		throw new Error(`${label} BIT STRING must not set padding bits`);
	}
}
