/**
 * Canonical advanced X.509 domain surface.
 * Owns certificate, CSR, extension, name, and parse APIs behind one stable entrypoint.
 *
 * DER/PEM parsing, encoding, extension decoding, and text rendering return
 * synchronously. Certificate/CSR creation and WebCrypto-backed hashing and key
 * operations return promises and must be awaited.
 *
 * @module micro509/x509
 */

export type {
	CertificateMaterial,
	CreateCertificateInput,
	CreateSelfSignedCertificateInput,
	SelfSignedCertificateResult,
	SignatureProfileInput,
	ValidityInput,
} from '#micro509/x509/certificate';
export { createCertificate, createSelfSignedCertificate } from '#micro509/x509/certificate';

export type { CreateCsrInput, CsrMaterial } from '#micro509/x509/csr';
export { createCertificateSigningRequest } from '#micro509/x509/csr';
export type {
	AuthorityInfoAccessMethod,
	AuthorityInformationAccess,
	AuthorityInformationAccessInput,
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
} from '#micro509/x509/extensions';
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
} from '#micro509/x509/extensions';
export type {
	CertificateFingerprint,
	CertificateFingerprintAlgorithm,
	CertificateFingerprintSource,
} from '#micro509/x509/fingerprint';
export { certificateFingerprint } from '#micro509/x509/fingerprint';

export type {
	NameAttribute,
	NameFieldKey,
	NameInput,
	NameObject,
	RelativeDistinguishedNameInput,
} from '#micro509/x509/name';
export { encodeName, encodeRelativeDistinguishedName } from '#micro509/x509/name';
export type { SubjectAltNameTextOptions } from '#micro509/x509/name-text';
export {
	distinguishedNameToString,
	relativeDistinguishedNameToString,
	subjectAltNameLabel,
	subjectAltNameToString,
} from '#micro509/x509/name-text';

export type {
	DecodedExtensionMap,
	DecodedExtensionValue,
	ExtensionDecoder,
	ExtensionDecoderMap,
	MatchCertificatePrivateKeyErrorCode,
	MatchCertificatePrivateKeyFailure,
	MatchCertificatePrivateKeyFailureResult,
	MatchCertificatePrivateKeyResult,
	MatchCertificatePrivateKeySuccess,
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
} from '#micro509/x509/parse';
export {
	certificateMatchesPrivateKey,
	decodeExtension,
	decodeExtensionMap,
	decodeExtensions,
	defineExtensionDecoder,
	defineExtensionDecoderMap,
	findExtension,
	getSubjectPublicKey,
	getSubjectPublicKeyOrThrow,
	matchCertificatePrivateKey,
	parseCertificateChainPem,
	parseCertificateDer,
	parseCertificateDerOrThrow,
	parseCertificatePem,
	parseCertificatePemOrThrow,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestDerOrThrow,
	parseCertificateSigningRequestPem,
	parseCertificateSigningRequestPemOrThrow,
} from '#micro509/x509/parse';
