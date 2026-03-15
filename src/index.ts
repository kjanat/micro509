/**
 * Stable root import for `micro509`.\
 * Re-exports the public X.509, CSR, CRL, OCSP, PKCS#7, PKCS#12/PFX, key, parsing, and
 * path-validation APIs from one package entrypoint.
 *
 * Reach for this module when you want the supported package surface without importing internal
 * files directly.
 *
 * The root export is organized around common PKI flows:
 *
 * - create certificates, CSRs, CRLs, OCSP responses, PKCS#7, and PFX artifacts
 * - parse DER or PEM inputs into typed certificate and request shapes
 * - verify certificate chains, service identities, CRLs, OCSP, and signed data
 * - import, export, generate, and encrypt key material with WebCrypto-safe algorithms
 * - build and inspect typed extension inputs, revocation evidence, and validation results
 *
 * @example
 * ```ts
 * import {
 * 	createSelfSignedCertificate,
 * 	parseCertificatePem,
 * 	verifyCertificateChain,
 * } from 'micro509';
 *
 * const { certificate } = await createSelfSignedCertificate({
 * 	subject: { commonName: 'example.com' },
 * 	algorithm: { kind: 'ecdsa', namedCurve: 'P-256' },
 * });
 *
 * const parsed = parseCertificatePem(certificate.pem);
 * // parsed.subject.values.commonName === 'example.com'
 *
 * const result = await verifyCertificateChain({
 * 	leaf: certificate.pem,
 * 	roots: [certificate.pem],
 * 	allowSelfSignedLeaf: true,
 * });
 * // result.ok === true
 * ```
 *
 * @example
 * ```ts
 * import {
 * 	generateKeyPair,
 * 	parseCertificateSigningRequestPem,
 * 	createCertificateSigningRequest,
 * } from 'micro509';
 *
 * const keyPair = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
 * const csr = await createCertificateSigningRequest({
 * 	subject: { commonName: 'example.com' },
 * 	publicKey: keyPair.publicKey,
 * 	signerPrivateKey: keyPair.privateKey,
 * });
 *
 * const parsed = parseCertificateSigningRequestPem(csr.pem);
 * // parsed.subject.values.commonName === 'example.com'
 * ```
 * @module
 */

export type {
	CertificateMaterial,
	CreateCertificateInput,
	CreateSelfSignedCertificateInput,
	SelfSignedCertificateResult,
	ValidityInput,
} from './certificate.ts';
export { createCertificate, createSelfSignedCertificate } from './certificate.ts';
export type {
	CertificateRevocationListMaterial,
	CheckCertificateRevocationAgainstCrlErrorCode,
	CheckCertificateRevocationAgainstCrlFailure,
	CheckCertificateRevocationAgainstCrlFailureDetails,
	CheckCertificateRevocationAgainstCrlGoodValue,
	CheckCertificateRevocationAgainstCrlInput,
	CheckCertificateRevocationAgainstCrlResult,
	CheckCertificateRevocationAgainstCrlRevokedValue,
	CheckCertificateRevocationAgainstCrlValue,
	CreateCertificateRevocationListInput,
	CrlApplicabilityFailureReason,
	CrlCertificateSource,
	CrlSource,
	ParsedCertificateRevocationList,
	ParsedRevokedCertificate,
	RevocationReason,
	RevokedCertificateInput,
	ValidateCertificateRevocationListFailure,
	ValidateCertificateRevocationListInput,
	ValidateCertificateRevocationListResult,
	VerifyCertificateRevocationListFailure,
	VerifyCertificateRevocationListResult,
} from './crl.ts';
export {
	checkCertificateRevocationAgainstCrl,
	createCertificateRevocationList,
	isCertificateRevoked,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	validateCertificateRevocationList,
	verifyCertificateRevocationList,
} from './crl.ts';
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
} from './extensions.ts';
export type {
	DnsServiceIdentityInput,
	IpServiceIdentityInput,
	MatchServiceIdentityErrorCode,
	MatchServiceIdentityEvaluation,
	MatchServiceIdentityFailure,
	MatchServiceIdentityFailureDetails,
	MatchServiceIdentityFailureResult,
	MatchServiceIdentityInput,
	MatchServiceIdentityResult,
	MatchServiceIdentitySuccess,
	ServiceIdentityInput,
	ServiceIdentityType,
	SrvServiceIdentityInput,
	UriServiceIdentityInput,
	VerifyServiceIdentityInput,
} from './identity.ts';
export { matchCertificateServiceIdentity, matchServiceIdentity } from './identity.ts';
export type {
	EcKeyAlgorithmInput,
	EcNamedCurve,
	Ed25519KeyAlgorithmInput,
	EncryptedPkcs8Options,
	ImportEcPublicKeyInput,
	ImportEd25519PublicKeyInput,
	ImportRsaPublicKeyInput,
	KeyAlgorithmInput,
	KeyPairMaterial,
	LegacyPemEncryptionOptions,
	Pbes2EncryptionOptions,
	Pbes2EncryptionScheme,
	Pbes2Prf,
	PrivateKeyImportInput,
	PublicKeyImportInput,
	RsaHash,
	RsaKeyAlgorithmInput,
	RsaScheme,
} from './keys.ts';
export {
	exportBinaryBase64,
	exportEncryptedPkcs1Pem,
	exportEncryptedPkcs8Der,
	exportEncryptedPkcs8Pem,
	exportEncryptedSec1Pem,
	exportPkcs1Der,
	exportPkcs1Pem,
	exportPkcs8Der,
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSec1Der,
	exportSec1Pem,
	exportSpkiDer,
	exportSpkiPem,
	generateKeyPair,
	importEncryptedPkcs1Pem,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8Pem,
	importEncryptedSec1Pem,
	importPkcs1Der,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Der,
	importPkcs8Pem,
	importPrivateJwk,
	importPublicJwk,
	importSec1Der,
	importSec1Pem,
	importSpkiBase64,
	importSpkiDer,
	importSpkiPem,
} from './keys.ts';
export type {
	NameAttribute,
	NameFieldKey,
	NameInput,
	NameObject,
	RelativeDistinguishedNameInput,
} from './name.ts';
export type { InitialNameConstraintsInput } from './name-constraints.ts';
export type {
	CreateOcspRequestInput,
	CreateOcspRequestItemInput,
	CreateOcspResponseInput,
	CreateOcspSingleResponseInput,
	OcspCertificateSource,
	OcspCertStatus,
	OcspHashAlgorithm,
	OcspRequestMaterial,
	OcspRequestSource,
	OcspResponseMaterial,
	OcspResponseStatus,
	ParsedOcspCertId,
	ParsedOcspRequest,
	ParsedOcspResponderId,
	ParsedOcspResponse,
	ParsedOcspSingleResponse,
	ValidateOcspResponseFailure,
	ValidateOcspResponseInput,
	ValidateOcspResponseResult,
	VerifyOcspResponseFailure,
	VerifyOcspResponseResult,
} from './ocsp.ts';
export {
	createOcspRequest,
	createOcspResponse,
	parseOcspRequestDer,
	parseOcspRequestPem,
	parseOcspResponseDer,
	parseOcspResponsePem,
	validateOcspResponse,
	verifyOcspResponse,
} from './ocsp.ts';
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
} from './parse.ts';
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
} from './parse.ts';
export type { CategorizedPemBlocks, PemBlock } from './pem.ts';
export { categorizePemBlocks, pemDecode, pemEncode, splitPemBlocks } from './pem.ts';
export type {
	CreatePfxInput,
	ParsedPfx,
	ParsedPfxAttribute,
	ParsedPfxBag,
	ParsedPfxBagAttributes,
	ParsePfxErrorCode,
	ParsePfxFailure,
	ParsePfxOptions,
	ParsePfxResult,
	PfxBagAttributesInput,
	PfxCertificateBagInput,
	PfxCertificateSource,
	PfxEncryptionOptions,
	PfxMaterial,
	PfxPrivateKeyBagInput,
	PfxPrivateKeySource,
} from './pfx.ts';
export { createPfx, parsePfxDer, parsePfxPem } from './pfx.ts';
export type {
	ParsedPkcs7SignedData,
	ParsedPkcs7SignerInfo,
	ParsePkcs7CertBagResult,
	ParsePkcs7ErrorCode,
	ParsePkcs7Failure,
	ParsePkcs7SignedDataResult,
	Pkcs7CertBag,
	Pkcs7CertificateSource,
	VerifyPkcs7SignedDataFailure,
	VerifyPkcs7SignedDataResult,
} from './pkcs7.ts';
export {
	createPkcs7CertBagDer,
	createPkcs7CertBagPem,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from './pkcs7.ts';
export type { ParsedPkcs12MacData, Pkcs12MacOptions } from './pkcs12-mac.ts';
export { createPkcs12MacData, parsePkcs12MacData } from './pkcs12-mac.ts';
export type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from './policy.ts';
export type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
	Result,
} from './result.ts';
export type {
	CheckCertificateRevocationErrorCode,
	CheckCertificateRevocationFailureDetails,
	CheckCertificateRevocationInput,
	CheckCertificateRevocationResult,
	CheckCertificateRevocationValue,
	ConfiguredOcspResponder,
	ConfiguredOcspResponderCertificate,
	OcspResponderCandidate,
	OcspResponderSource,
	ResolveOcspResponderCandidatesInput,
	RevocationCertificateSource,
	RevocationCheckGoodValue,
	RevocationCheckRevokedValue,
	RevocationCheckUnknownValue,
	RevocationCrlEvidenceInput,
	RevocationEvidenceInput,
	RevocationEvidenceKind,
	RevocationIndeterminateEvidence,
	RevocationIndeterminateReasonCode,
	RevocationOcspEvidenceInput,
	RevocationStatus,
} from './revocation.ts';
export {
	checkCertificateRevocation,
	getCertificateOcspResponderUris,
	resolveOcspResponderCandidates,
} from './revocation.ts';
export type { SignatureProfileInput } from './internal/crypto/signing.ts';
export type {
	BuildCandidatePathInput,
	BuildCandidatePathResult,
	CandidatePath,
	CertificateSource,
	CsrSource,
	EkuCheckFailure,
	EkuCheckPurpose,
	EkuCheckResult,
	TrustAnchor,
	ValidateCandidatePathInput,
	ValidateCandidatePathResult,
	ValidateCandidatePathSuccess,
	ValidateForCaInput,
	ValidateForCodeSigningInput,
	ValidateForTlsClientInput,
	ValidateForTlsServerInput,
	VerifiedCertificateChain,
	VerifyCertificateChainInput,
	VerifyChainFailure,
	VerifyChainResult,
	VerifyErrorCode,
	VerifyFailureDetails,
	VerifyPurpose,
	VerifyRequestFailure,
	VerifyRequestResult,
} from './verify.ts';
export {
	buildCandidatePath,
	checkExtendedKeyUsage,
	trustAnchorFromCertificate,
	validateCandidatePath,
	validateForCa,
	validateForCodeSigning,
	validateForTlsClient,
	validateForTlsServer,
	verifyCertificateChain,
	verifyCertificateSigningRequest,
} from './verify.ts';
