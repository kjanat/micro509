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
	CreateCertificateErrorCode,
	CreateCertificateInput,
	CreateSelfSignedCertificateBase,
	CreateSelfSignedCertificateInput,
	SelfSignedCertificateResult,
	SelfSignedKeySource,
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
	ExtensionEncoderErrorCode,
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
	allOnesMaskForIpAddress,
	buildCertificateExtensions,
	buildRequestedExtensions,
	buildSubjectKeyIdentifier as subjectKeyIdentifier,
	decodeIpAddress,
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
	normalizeIpAddress,
	parseAuthorityInfoAccessMethodOid,
	parseExtendedKeyUsageOid,
	parseIpAddressToBytes,
} from '#micro509/x509/extensions';
export type {
	CertificateFingerprint,
	CertificateFingerprintAlgorithm,
	CertificateFingerprintSource,
} from '#micro509/x509/fingerprint';
export { certificateFingerprint } from '#micro509/x509/fingerprint';

export type {
	NameAttribute,
	NameEncoderErrorCode,
	NameFieldKey,
	NameInput,
	NameObject,
	RelativeDistinguishedNameInput,
} from '#micro509/x509/name';
export {
	canonicalDnKey,
	compareDistinguishedNames,
	encodeName,
	encodeRelativeDistinguishedName,
	isWithinDirectoryNameSubtree,
} from '#micro509/x509/name';
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
	ParseCertificateChainResult,
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
	parseAuthorityInfoAccess as decodeAuthorityInfoAccess,
	parseAuthorityKeyIdentifier as decodeAuthorityKeyIdentifier,
	parseBasicConstraints as decodeBasicConstraints,
	parseCertificateChainPem,
	parseCertificateChainPemOrThrow,
	parseCertificateDer,
	parseCertificateDerOrThrow,
	parseCertificateFromSource,
	parseCertificatePem,
	parseCertificatePemOrThrow,
	parseCertificatePolicies as decodeCertificatePolicies,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestDerOrThrow,
	parseCertificateSigningRequestPem,
	parseCertificateSigningRequestPemOrThrow,
	parseCertificatesFromSource,
	parseCrlDistributionPoints as decodeCrlDistributionPoints,
	parseDistinguishedNameDer,
	parseExtendedKeyUsage as decodeExtendedKeyUsage,
	parseInhibitAnyPolicy as decodeInhibitAnyPolicy,
	parseKeyUsage as decodeKeyUsage,
	parseNameConstraints as decodeNameConstraints,
	parsePolicyConstraints as decodePolicyConstraints,
	parsePolicyMappings as decodePolicyMappings,
	parseSubjectAltNames as decodeSubjectAltNames,
} from '#micro509/x509/parse';
