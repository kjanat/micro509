/**
 * Canonical advanced X.509 domain surface.
 * Owns certificate, CSR, extension, name, and parse APIs behind one stable entrypoint.
 * @module
 */

export type {
	CertificateMaterial,
	CreateCertificateInput,
	CreateSelfSignedCertificateInput,
	SelfSignedCertificateResult,
	ValidityInput,
} from '../certificate.ts';
export { createCertificate, createSelfSignedCertificate } from '../certificate.ts';
export type { CreateCsrInput, CsrMaterial } from '../csr.ts';
export { createCertificateSigningRequest } from '../csr.ts';
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
	IssuingDistributionPoint,
	IssuingDistributionPointBase,
	IssuingDistributionPointForAttributeCerts,
	IssuingDistributionPointForCaCerts,
	IssuingDistributionPointForUserCerts,
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
} from '../extensions.ts';
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
} from '../extensions.ts';
export type { SignatureProfileInput } from '../internal/crypto/signing.ts';
export type {
	NameAttribute,
	NameFieldKey,
	NameInput,
	NameObject,
	RelativeDistinguishedNameInput,
} from '../name.ts';
export { encodeName, encodeRelativeDistinguishedName } from '../name.ts';
export type {
	DecodedExtensionMap,
	DecodedExtensionValue,
	ExtensionDecoder,
	ExtensionDecoderMap,
	ParsedCertificate,
	ParsedCertificateSigningRequest,
	ParsedDistributionPoint,
	ParsedDistributionPointName,
	ParsedExtension,
	ParsedIssuingDistributionPoint,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
	ParseOptions,
} from '../parse.ts';
export {
	decodeExtension,
	decodeExtensionMap,
	decodeExtensions,
	defineExtensionDecoder,
	defineExtensionDecoderMap,
	findExtension,
	parseCertificateChainPem,
	parseCertificateDer,
	parseCertificatePem,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
} from '../parse.ts';
