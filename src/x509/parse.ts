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
} from '../internal/asn1/asn1.ts';
import type { DerElement } from '../internal/asn1/der.ts';
import {
	DEFAULT_MAX_DER_DEPTH,
	encodeLength,
	readElement,
	readRootElement,
	readSequenceChildren,
} from '../internal/asn1/der.ts';
import {
	parseDistributionPointReasonFlagsContent,
	parseKeyUsageExtension,
} from '../internal/x509/extension-bits.ts';
import {
	decodeAndApplyKnownExtension,
	type KnownParsedExtensionAccumulator,
	type MutableKnownParsedExtensionAccumulator,
} from '../internal/x509/extension-registry.ts';
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
} from './extensions.ts';
import { parseAuthorityInfoAccessMethodOid, parseExtendedKeyUsageOid } from './extensions.ts';
import { decodeIpAddress } from '../internal/shared/ip.ts';
import { type NameFieldKey, nameFieldKeyFromOid } from './name.ts';
import { OIDS } from '../internal/asn1/oids.ts';
import { pemDecode, splitPemBlocks } from '../pem/pem.ts';

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
	ParsedNameConstraintForm,
	PolicyConstraints,
	PolicyMappings,
	SubjectAltName,
} from './extensions.ts';
export type { NameFieldKey } from './name.ts';

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
	readonly values: Partial<Record<NameFieldKey, string>>;
}

/** A single RelativeDistinguishedName SET from an X.501 Name. */
export interface ParsedRelativeDistinguishedName {
	/** Hex-encoded DER of this RDN SET element. */
	readonly derHex: string;
	/** Attributes within this RDN (usually one, but multi-valued RDNs are legal). */
	readonly attributes: readonly ParsedNameAttribute[];
	/** First-occurrence map of well-known fields within this RDN. */
	readonly values: Partial<Record<NameFieldKey, string>>;
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
	readonly reasons?: readonly DistributionPointReason[];
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
	readonly onlySomeReasons?: readonly DistributionPointReason[];
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
	/** DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters. */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
	/** OID of the subject's public key algorithm (e.g. `"1.2.840.10045.2.1"` for EC). */
	readonly publicKeyAlgorithmOid: string;
	/** DER-encoded parameters for the public key algorithm. Absent when implicit. */
	readonly publicKeyAlgorithmParametersDer?: Uint8Array;
	/** OID of the named curve or other key sub-parameter, when present. */
	readonly publicKeyParametersOid?: string;
	/** All extensions as raw {@linkcode ParsedExtension}s, in certificate order. */
	readonly extensions: readonly ParsedExtension[];
	/** Decoded Basic Constraints (RFC 5280 §4.2.1.9). */
	readonly basicConstraints?: BasicConstraints;
	/** Decoded Key Usage bit flags (RFC 5280 §4.2.1.3). */
	readonly keyUsage?: readonly KeyUsage[];
	/** Decoded Extended Key Usage purposes (RFC 5280 §4.2.1.12). */
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	/** Decoded Subject Alternative Names (RFC 5280 §4.2.1.6). */
	readonly subjectAltNames?: readonly SubjectAltName[];
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
	/** Decoded Authority Information Access — OCSP and CA Issuer URIs (RFC 5280 §4.2.2.1). */
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
	/** DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters. */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
	/** OID of the subject's public key algorithm. */
	readonly publicKeyAlgorithmOid: string;
	/** DER-encoded parameters for the public key algorithm. */
	readonly publicKeyAlgorithmParametersDer?: Uint8Array;
	/** OID of the named curve or other key sub-parameter, when present. */
	readonly publicKeyParametersOid?: string;
	/** All requested extensions as raw {@linkcode ParsedExtension}s. */
	readonly requestedExtensions: readonly ParsedExtension[];
	/** Decoded Basic Constraints from the extensionRequest attribute. */
	readonly basicConstraints?: BasicConstraints;
	/** Decoded Key Usage from the extensionRequest attribute. */
	readonly keyUsage?: readonly KeyUsage[];
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

/**
 * Decode a DER-encoded X.509 certificate into a {@linkcode ParsedCertificate}.
 *
 * All built-in extensions (basicConstraints, keyUsage, subjectAltNames, etc.)
 * are decoded automatically.\
 * Pass {@linkcode ParseOptions} to also decode custom extensions.
 *
 * @example
 * ```ts
 * import { parseCertificateDer } from 'micro509';
 *
 * const cert = parseCertificateDer(derBytes);
 * console.log(cert.subject.values.commonName); // "example.com"
 * console.log(cert.keyUsage);                  // ["digitalSignature", "keyEncipherment"]
 * ```
 *
 * @param der Raw DER bytes of an X.509 certificate.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateDer<TMap extends ExtensionDecoderMap = Record<never, never>>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const tbsCertificate = requireElement(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const tbsChildren = childrenOf(der, tbsCertificate);

	let index = 0;
	let version = 1;
	const maybeVersion = tbsChildren[index];
	if (maybeVersion?.tag === 0xa0) {
		const versionElement = requireElement(childrenOf(der, maybeVersion)[0], 'version INTEGER');
		version = decodeIntegerNumber(versionElement.value) + 1;
		index += 1;
	}

	const serialNumber = requireElement(tbsChildren[index], 'serialNumber');
	const issuer = requireElement(tbsChildren[index + 2], 'issuer');
	const validity = requireElement(tbsChildren[index + 3], 'validity');
	const subject = requireElement(tbsChildren[index + 4], 'subject');
	const subjectPublicKeyInfo = requireElement(tbsChildren[index + 5], 'subjectPublicKeyInfo');
	const extensions = tbsChildren.find((element) => element.tag === 0xa3);
	const parsedExtensions = parseExtensionContainer(der, extensions);
	const parsedValidity = parseValidity(der, validity);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const parsedSignatureAlgorithm = parseAlgorithmIdentifier(der, signatureAlgorithm);
	const decodedExtensions =
		options?.decoders === undefined
			? undefined
			: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap =
		options?.decoderMap === undefined
			? undefined
			: decodeExtensionMap(parsedExtensions.all, options.decoderMap);

	return {
		der: new Uint8Array(der),
		version,
		serialNumberHex: toHex(serialNumber.value),
		tbsCertificateDer: der.slice(
			tbsCertificate.start - tbsCertificate.headerLength,
			tbsCertificate.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			subjectPublicKeyInfo.start - subjectPublicKeyInfo.headerLength,
			subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseName(der, issuer),
		subject: parseName(der, subject),
		notBefore: parsedValidity.notBefore,
		notAfter: parsedValidity.notAfter,
		signatureAlgorithmOid: parsedSignatureAlgorithm.oid,
		...(parsedSignatureAlgorithm.parametersDer !== undefined
			? { signatureAlgorithmParametersDer: parsedSignatureAlgorithm.parametersDer }
			: {}),
		publicKeyAlgorithmOid: parsedSpki.oid,
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
		...(decodedExtensions !== undefined ? { decodedExtensions } : {}),
		...(decodedExtensionMap !== undefined ? { decodedExtensionMap } : {}),
		...(parsedExtensions.subjectKeyIdentifier !== undefined
			? { subjectKeyIdentifier: parsedExtensions.subjectKeyIdentifier }
			: {}),
		...(parsedExtensions.authorityKeyIdentifier !== undefined
			? { authorityKeyIdentifier: parsedExtensions.authorityKeyIdentifier }
			: {}),
	};
}

/**
 * Decode a PEM-encoded X.509 certificate into a {@linkcode ParsedCertificate}.
 *
 * Expects a single `-----BEGIN CERTIFICATE-----` block. For bundles
 * containing multiple certificates, use {@linkcode parseCertificateChainPem}.
 *
 * @example
 * ```ts
 * import { parseCertificatePem } from 'micro509';
 *
 * const cert = parseCertificatePem(pemString);
 * console.log(cert.issuer.values.organization); // "Let's Encrypt"
 * console.log(cert.notAfter);          // Date
 * ```
 *
 * @param pem PEM string with a CERTIFICATE block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificatePem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pem: string,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	return parseCertificateDer(pemDecode('CERTIFICATE', pem), options);
}

/**
 * Decode a PEM bundle containing one or more certificates.
 *
 * Non-CERTIFICATE blocks (e.g. private keys) are silently skipped.
 *
 * @param pemBundle PEM text that may contain multiple CERTIFICATE blocks.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateChainPem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pemBundle: string,
	options?: ParseOptions<TMap>,
): readonly ParsedCertificate<TMap>[] {
	return splitPemBlocks(pemBundle)
		.filter((block) => block.label === 'CERTIFICATE')
		.map((block) => parseCertificateDer(block.bytes, options));
}

/**
 * Decode a DER-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param der Raw DER bytes of a PKCS#10 certificate signing request.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestDer<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(der: Uint8Array, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const certificationRequestInfo = requireElement(topLevel[0], 'CertificationRequestInfo');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const criChildren = childrenOf(der, certificationRequestInfo);
	const version = decodeIntegerNumber(requireElement(criChildren[0], 'version').value) + 1;
	const subject = requireElement(criChildren[1], 'subject');
	const subjectPublicKeyInfo = requireElement(criChildren[2], 'subjectPublicKeyInfo');
	const attributes = criChildren[3];
	const parsedExtensions = parseRequestedExtensions(der, attributes);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const parsedSignatureAlgorithm = parseAlgorithmIdentifier(der, signatureAlgorithm);
	const decodedExtensions =
		options?.decoders === undefined
			? undefined
			: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap =
		options?.decoderMap === undefined
			? undefined
			: decodeExtensionMap(parsedExtensions.all, options.decoderMap);

	return {
		version,
		certificationRequestInfoDer: der.slice(
			certificationRequestInfo.start - certificationRequestInfo.headerLength,
			certificationRequestInfo.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			subjectPublicKeyInfo.start - subjectPublicKeyInfo.headerLength,
			subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		subject: parseName(der, subject),
		signatureAlgorithmOid: parsedSignatureAlgorithm.oid,
		...(parsedSignatureAlgorithm.parametersDer !== undefined
			? { signatureAlgorithmParametersDer: parsedSignatureAlgorithm.parametersDer }
			: {}),
		publicKeyAlgorithmOid: parsedSpki.oid,
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
		...(decodedExtensions !== undefined ? { decodedExtensions } : {}),
		...(decodedExtensionMap !== undefined ? { decodedExtensionMap } : {}),
	};
}

/**
 * Decode a PEM-encoded PKCS#10 CSR into a {@linkcode ParsedCertificateSigningRequest}.
 *
 * @param pem PEM string with a CERTIFICATE REQUEST block.
 * @param options Custom extension decoders to apply during parsing.
 */
export function parseCertificateSigningRequestPem<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pem: string, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	return parseCertificateSigningRequestDer(pemDecode('CERTIFICATE REQUEST', pem), options);
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
	for (const attribute of childrenOf(source, attributes)) {
		const attributeChildren = childrenOf(source, attribute);
		const oid = requireElement(attributeChildren[0], 'attribute OID');
		if (decodeObjectIdentifier(oid.value) !== OIDS.extensionRequest) {
			continue;
		}
		const valuesSet = requireElement(attributeChildren[1], 'attribute values');
		const requested = requireElement(childrenOf(source, valuesSet)[0], 'requested extensions');
		return parseExtensionSequence(source, requested, 'csr');
	}
	return { all: [] };
}

/** Walk a SEQUENCE OF Extension and decode each one, populating known-extension slots. */
function parseExtensionSequence(
	source: Uint8Array,
	sequenceElement: DerElement,
	context: 'certificate' | 'csr',
): ParsedExtensions {
	const parsed: ParsedExtension[] = [];
	const knownParsed: MutableKnownParsedExtensionAccumulator = {};

	for (const extension of childrenOf(source, sequenceElement)) {
		const children = childrenOf(source, extension);
		const oidElement = requireElement(children[0], 'extension OID');
		const oid = decodeObjectIdentifier(oidElement.value);
		let offset = 1;
		let critical = false;
		const maybeCritical = children[offset];
		if (maybeCritical?.tag === 0x01) {
			critical = decodeBoolean(maybeCritical.value);
			offset += 1;
		}
		const extnValue = requireElement(children[offset], 'extension value');
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
	const children = childrenOf(source, element);
	const algorithm = parseAlgorithmIdentifier(source, requireElement(children[0], 'SPKI algorithm'));
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

/** @internal Decode the Basic Constraints extension value DER. */
export function parseBasicConstraints(bytes: Uint8Array): BasicConstraints {
	const element = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const children = childrenOf(bytes, element);
	let ca = false;
	let pathLength: number | undefined;
	for (const child of children) {
		if (child.tag === 0x01) {
			ca = decodeBoolean(child.value);
		}
		if (child.tag === 0x02) {
			pathLength = decodeNonNegativeIntegerNumber(child.value, 'basicConstraints pathLength');
		}
	}
	return pathLength !== undefined ? { ca, pathLength } : { ca };
}

/** @internal Decode the Key Usage BIT STRING extension value. */
export function parseKeyUsage(bytes: Uint8Array): readonly KeyUsage[] {
	return parseKeyUsageExtension(bytes);
}

/** @internal Decode the Extended Key Usage SEQUENCE OF OIDs. */
export function parseExtendedKeyUsage(bytes: Uint8Array): readonly ExtendedKeyUsage[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'extendedKeyUsage sequence',
	);
	return childrenOf(bytes, sequenceElement).map((element) =>
		parseExtendedKeyUsageOid(decodeObjectIdentifier(element.value)),
	);
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
	const noticeNumberElements = childrenOf(source, element);
	if (noticeNumberElements.length === 0) {
		throw new Error('noticeRef noticeNumbers must not be empty');
	}
	return noticeNumberElements.map((noticeNumberElement) =>
		decodeNonNegativeIntegerNumber(noticeNumberElement.value, 'noticeRef noticeNumber'),
	);
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

/** @internal Decode the Subject Alternative Names SEQUENCE OF GeneralName. */
export function parseSubjectAltNames(bytes: Uint8Array): readonly SubjectAltName[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'subjectAltName sequence',
	);
	return childrenOf(bytes, sequenceElement).map((element) => parseGeneralName(bytes, element));
}

/** @internal Decode the Authority Information Access extension value. */
export function parseAuthorityInfoAccess(bytes: Uint8Array): readonly AuthorityInformationAccess[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'authorityInfoAccess sequence',
	);
	return childrenOf(bytes, sequenceElement).map((element) => {
		const children = childrenOf(bytes, element);
		const method = requireElement(children[0], 'authorityInfoAccess method');
		const location = requireElement(children[1], 'authorityInfoAccess location');
		if (location.tag !== 0x86) {
			throw new Error(`Unsupported authorityInfoAccess location tag: ${location.tag}`);
		}
		return {
			method: parseAuthorityInfoAccessMethodOid(decodeObjectIdentifier(method.value)),
			uri: textDecoder.decode(location.value),
		};
	});
}

/** @internal Decode the CRL Distribution Points extension value. */
export function parseCrlDistributionPoints(bytes: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = requireElement(
		readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
		'CRLDistributionPoints sequence',
	);
	const points: ParsedDistributionPoint[] = [];
	for (const distributionPoint of childrenOf(bytes, sequenceElement)) {
		points.push(parseDistributionPoint(bytes, distributionPoint));
	}
	return points;
}

/** Decode a single DistributionPoint SEQUENCE. */
function parseDistributionPoint(source: Uint8Array, element: DerElement): ParsedDistributionPoint {
	let distributionPoint: ParsedDistributionPointName | undefined;
	let reasons: readonly DistributionPointReason[] | undefined;
	let crlIssuer: readonly GeneralName[] | undefined;
	for (const child of childrenOf(source, element)) {
		if (child.tag === 0xa0) {
			distributionPoint = parseDistributionPointName(source, child);
		} else if (child.tag === 0x81) {
			reasons = parseDistributionPointReasonFlagsContent(child.value);
		} else if (child.tag === 0xa2) {
			crlIssuer = parseGeneralNames(source, child);
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(reasons === undefined ? {} : { reasons }),
		...(crlIssuer === undefined ? {} : { crlIssuer }),
	};
}

/** Decode a DistributionPointName (fullName or relativeName). */
function parseDistributionPointName(
	source: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName {
	const distributionPointName = requireElement(
		childrenOf(source, element)[0],
		'distributionPointName',
	);
	if (distributionPointName.tag === 0xa0) {
		return {
			fullName: childrenOf(source, distributionPointName).map((name) =>
				parseGeneralName(source, name),
			),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		return { relativeName: parseRelativeDistinguishedName(source, distributionPointName) };
	}
	throw new Error(`Unsupported distributionPointName tag: ${distributionPointName.tag}`);
}

/** Decode a SEQUENCE OF GeneralName. */
function parseGeneralNames(source: Uint8Array, element: DerElement): readonly GeneralName[] {
	return childrenOf(source, element).map((name) => parseGeneralName(source, name));
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
			return { type: 'email' as const, value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns' as const, value: textDecoder.decode(element.value) };
		case 0x86:
			return { type: 'uri' as const, value: textDecoder.decode(element.value) };
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(rebuildDirectoryNameFromImplicit(element, source)),
			};
		default:
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
	}
}

/** Attempt to decode an otherName [0] as a known type (currently only SRV-ID). */
function parseOtherName(source: Uint8Array, element: DerElement): SubjectAltName | undefined {
	const otherNameSequence = requireElement(childrenOf(source, element)[0], 'otherName sequence');
	const otherNameChildren = childrenOf(source, otherNameSequence);
	const typeId = requireElement(otherNameChildren[0], 'otherName type-id');
	const valueElement = requireElement(otherNameChildren[1], 'otherName value');
	const typeIdOid = decodeObjectIdentifier(typeId.value);
	if (typeIdOid !== OIDS.idOnDnsSrv) {
		return undefined;
	}
	if (valueElement.tag !== 0xa0) {
		throw new Error('SRV-ID otherName value must use explicit [0]');
	}
	const srvNameElement = requireElement(childrenOf(source, valueElement)[0], 'SRV-ID IA5String');
	if (srvNameElement.tag !== 0x16) {
		throw new Error('SRV-ID otherName value must be an IA5String');
	}
	return { type: 'srv', value: decodeString(srvNameElement.tag, srvNameElement.value) };
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
	let permittedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
	let excludedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0xa0) {
			permittedSubtrees = parseGeneralSubtrees(bytes, child);
		} else if (child.tag === 0xa1) {
			excludedSubtrees = parseGeneralSubtrees(bytes, child);
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
	for (const subtreeElement of childrenOf(source, container)) {
		const children = childrenOf(source, subtreeElement);
		const baseElement = children[0];
		if (baseElement === undefined) {
			continue;
		}

		// RFC 5280 §4.2.1.10: minimum MUST be zero (default), maximum
		// MUST be absent. Reject non-standard values.
		for (let i = 1; i < children.length; i += 1) {
			const child = children[i];
			if (child === undefined) {
				continue;
			}
			if (child.tag === 0x80) {
				// minimum [0] INTEGER — must be 0
				if (child.value.length !== 1 || child.value[0] !== 0) {
					throw new Error('name constraints GeneralSubtree minimum must be 0');
				}
			} else if (child.tag === 0x81) {
				// maximum [1] INTEGER — must be absent
				throw new Error('name constraints GeneralSubtree maximum is not supported');
			}
		}

		const form = parseNameConstraintGeneralName(source, baseElement);
		if (form !== undefined) {
			subtrees.push({ base: form });
		}
	}
	return subtrees;
}

/** Decode a GeneralName for use in name constraints (IP carries address+mask). */
function parseNameConstraintGeneralName(
	source: Uint8Array,
	element: DerElement,
): ParsedNameConstraintForm | undefined {
	switch (element.tag) {
		case 0xa0:
			return { type: 'otherName', value: new Uint8Array(element.value) };
		case 0x81:
			return { type: 'email', value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns', value: textDecoder.decode(element.value) };
		case 0xa3:
			return { type: 'x400Address', value: new Uint8Array(element.value) };
		case 0x86:
			return { type: 'uri', value: textDecoder.decode(element.value) };
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
				derHex: toHex(rebuildDirectoryNameFromImplicit(element, source)),
			};
		case 0xa5:
			return { type: 'ediPartyName', value: new Uint8Array(element.value) };
		case 0x88:
			return { type: 'registeredID', value: decodeObjectIdentifier(element.value) };
	}
	return undefined;
}

/**
 * DirectoryName in GeneralName is IMPLICIT [4], meaning the outer tag
 * is 0xa4 but the content is a SEQUENCE of RDNs. We must reconstruct
 * the original SEQUENCE (tag 0x30) for DER hex comparison.
 */
function rebuildDirectoryNameFromImplicit(element: DerElement, source: Uint8Array): Uint8Array {
	const contentBytes = source.slice(element.start, element.end);
	const lengthEncoded = encodeLength(contentBytes.length);
	const result = new Uint8Array(1 + lengthEncoded.length + contentBytes.length);
	result[0] = 0x30;
	result.set(lengthEncoded, 1);
	result.set(contentBytes, 1 + lengthEncoded.length);
	return result;
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
export function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = requireElement(readElement(bytes, 0), 'authorityKeyIdentifier sequence');
	if (sequenceElement.end !== bytes.length) {
		throw new Error('Trailing data after DER element');
	}
	let offset = sequenceElement.start;
	while (offset < sequenceElement.end) {
		const child = readElement(bytes, offset);
		if (child.end > sequenceElement.end) {
			throw new Error('DER child exceeds parent length');
		}
		if (child.tag === 0x80) {
			return toHex(child.value);
		}
		offset = child.end;
	}
	if (offset !== sequenceElement.end) {
		throw new Error('Malformed DER sequence');
	}
	return undefined;
}
