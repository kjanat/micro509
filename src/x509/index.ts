/**
 * Canonical advanced X.509 domain surface.
 * Owns certificate, CSR, extension, name, and parse APIs behind one stable entrypoint.
 *
 * @module micro509/x509
 */

export type { SignatureProfileInput } from './certificate.ts';
export type {
	CertificateMaterial,
	CreateCertificateInput,
	CreateSelfSignedCertificateInput,
	SelfSignedCertificateResult,
	ValidityInput,
} from './certificate.ts';
export { createCertificate, createSelfSignedCertificate } from './certificate.ts';
export type { CreateCsrInput, CsrMaterial } from './csr.ts';
export { createCertificateSigningRequest } from './csr.ts';
export type {
	AuthorityInfoAccessMethod,
	AuthorityInformationAccess,
	BasicConstraints,
	CertificateExtensionsInput,
	CertificatePolicies,
	CpsPolicyQualifierInfo,
	CustomAuthorityInfoAccessMethod,
	CustomExtendedKeyUsage,
	CustomExtension,
	CustomPolicyQualifierInfo,
	DistributionPoint,
	DistributionPointName,
	DistributionPointReason,
	ExtendedKeyUsage,
	GeneralName,
	GeneralSubtree,
	InhibitAnyPolicy,
	KeyUsage,
	KnownAuthorityInfoAccessMethod,
	KnownExtendedKeyUsage,
	NameConstraintForm,
	NameConstraints,
	ParsedNameConstraintForm,
	PolicyConstraints,
	PolicyInformation,
	PolicyMapping,
	PolicyMappings,
	PolicyNoticeReference,
	PolicyQualifierInfo,
	SubjectAltName,
	UnsupportedNameConstraintForm,
	UserNoticePolicyQualifierInfo,
} from './extensions.ts';
export {
	buildCertificateExtensions,
	buildRequestedExtensions,
	encodeAuthorityInfoAccess,
	encodeBasicConstraints,
	encodeCertificatePolicies,
	encodeCrlDistributionPoints,
	encodeExtendedKeyUsage,
	encodeExtension,
	encodeInhibitAnyPolicy,
	encodeKeyUsage,
	encodeNameConstraints,
	encodePolicyConstraints,
	encodePolicyMappings,
	encodeSubjectAltName,
	getAuthorityInfoAccessMethodOid,
	getExtendedKeyUsageOid,
	parseAuthorityInfoAccessMethodOid,
	parseExtendedKeyUsageOid,
} from './extensions.ts';
export type {
	NameAttribute,
	NameFieldKey,
	NameInput,
	NameObject,
	RelativeDistinguishedNameInput,
} from './name.ts';
export { encodeName, encodeRelativeDistinguishedName } from './name.ts';
export type {
	DecodedExtensionMap,
	DecodedExtensionValue,
	ExtensionDecoder,
	ExtensionDecoderMap,
	ParseCertificateErrorCode,
	ParseCertificateFailure,
	ParseCertificateResult,
	ParseCertificateSigningRequestErrorCode,
	ParseCertificateSigningRequestFailure,
	ParseCertificateSigningRequestResult,
	ParsedBitFlags,
	ParsedCertificate,
	ParsedCertificateSigningRequest,
	ParsedDistributionPoint,
	ParsedDistributionPointName,
	ParsedExtension,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
	ParseOptions,
} from './parse.ts';
export {
	decodeExtension,
	decodeExtensionMap,
	decodeExtensions,
	defineExtensionDecoder,
	defineExtensionDecoderMap,
	findExtension,
	getSubjectPublicKey,
	getSubjectPublicKeyOrThrow,
	parseCertificateChainPem,
	parseCertificateDer,
	parseCertificateDerOrThrow,
	parseCertificatePem,
	parseCertificatePemOrThrow,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestDerOrThrow,
	parseCertificateSigningRequestPem,
	parseCertificateSigningRequestPemOrThrow,
} from './parse.ts';
