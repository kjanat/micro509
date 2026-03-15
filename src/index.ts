/**
 * Stable root import for `micro509`.\
 * Re-exports the common certificate, parsing, verification, revocation, key, and PKCS
 * workflows from one package entrypoint.
 *
 * Reach for this module when you want the default workflow-first package surface.
 * Use domain entrypoints such as `micro509/x509`, `micro509/verify`, and
 * `micro509/revocation` when you need exhaustive advanced types.
 *
 * The root export is organized around common PKI flows:
 *
 * - create certificates, CSRs, CRLs, OCSP responses, PKCS#7, and PFX artifacts
 * - parse DER or PEM inputs into typed certificate and request shapes
 * - verify certificate chains, service identities, CRLs, OCSP, and signed data
 * - import, export, generate, and encrypt key material with WebCrypto-safe algorithms
 * - work with the common extension inputs, revocation evidence, and validation results
 *
 * Advanced PKCS#12 MAC plumbing, signature profile tuning, and other domain-specific helper
 * types stay in their owner domains instead of being headlined here.
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
 * @module micro509
 */

// ── keys ─────────────────────────────────────────────────────────────
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
} from './keys/index.ts';
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
} from './keys/index.ts';

// ── pem ──────────────────────────────────────────────────────────────
export type { CategorizedPemBlocks, PemBlock } from './pem/index.ts';
export { categorizePemBlocks, pemDecode, pemEncode, splitPemBlocks } from './pem/index.ts';

// ── pkcs ─────────────────────────────────────────────────────────────
export type {
	CreatePfxInput,
	ParsedPfx,
	ParsedPfxAttribute,
	ParsedPfxBag,
	ParsedPfxBagAttributes,
	ParsedPkcs7SignedData,
	ParsedPkcs7SignerInfo,
	ParsePfxErrorCode,
	ParsePfxFailure,
	ParsePfxOptions,
	ParsePfxResult,
	ParsePkcs7CertBagResult,
	ParsePkcs7ErrorCode,
	ParsePkcs7Failure,
	ParsePkcs7SignedDataResult,
	PfxBagAttributesInput,
	PfxCertificateBagInput,
	PfxCertificateSource,
	PfxEncryptionOptions,
	PfxMaterial,
	PfxPrivateKeyBagInput,
	PfxPrivateKeySource,
	Pkcs7CertBag,
	Pkcs7CertificateSource,
	VerifyPkcs7SignedDataFailure,
	VerifyPkcs7SignedDataResult,
} from './pkcs/index.ts';
export {
	createPfx,
	createPkcs7CertBagDer,
	createPkcs7CertBagPem,
	parsePfxDer,
	parsePfxPem,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from './pkcs/index.ts';

// ── result ───────────────────────────────────────────────────────────
export type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
	Result,
} from './result/index.ts';

// ── revocation ───────────────────────────────────────────────────────
export type {
	CertificateRevocationListMaterial,
	CheckCertificateRevocationAgainstCrlInput,
	CheckCertificateRevocationAgainstCrlResult,
	CheckCertificateRevocationInput,
	CheckCertificateRevocationResult,
	ConfiguredOcspResponder,
	CreateCertificateRevocationListInput,
	CreateOcspRequestInput,
	CreateOcspRequestItemInput,
	CreateOcspResponseInput,
	CreateOcspSingleResponseInput,
	CrlCertificateSource,
	CrlSource,
	OcspCertificateSource,
	OcspCertStatus,
	OcspRequestMaterial,
	OcspRequestSource,
	OcspResponderCandidate,
	OcspResponderSource,
	OcspResponseMaterial,
	ParsedCertificateRevocationList,
	ParsedOcspCertId,
	ParsedOcspRequest,
	ParsedOcspResponderId,
	ParsedOcspResponse,
	ParsedOcspSingleResponse,
	ParsedRevokedCertificate,
	ResolveOcspResponderCandidatesInput,
	RevocationCertificateSource,
	RevocationCrlEvidenceInput,
	RevocationEvidenceInput,
	RevocationEvidenceKind,
	RevocationOcspEvidenceInput,
	RevocationReason,
	RevocationStatus,
	RevokedCertificateInput,
	ValidateCertificateRevocationListFailure,
	ValidateCertificateRevocationListInput,
	ValidateCertificateRevocationListResult,
	ValidateOcspResponseFailure,
	ValidateOcspResponseInput,
	ValidateOcspResponseResult,
	VerifyCertificateRevocationListFailure,
	VerifyCertificateRevocationListResult,
	VerifyOcspResponseFailure,
	VerifyOcspResponseResult,
} from './revocation/index.ts';
export {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	createCertificateRevocationList,
	createOcspRequest,
	createOcspResponse,
	getCertificateOcspResponderUris,
	isCertificateRevoked,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	parseOcspRequestDer,
	parseOcspRequestPem,
	parseOcspResponseDer,
	parseOcspResponsePem,
	resolveOcspResponderCandidates,
	validateCertificateRevocationList,
	validateOcspResponse,
	verifyCertificateRevocationList,
	verifyOcspResponse,
} from './revocation/index.ts';

// ── verify ───────────────────────────────────────────────────────────
export type {
	BuildCandidatePathInput,
	BuildCandidatePathResult,
	CandidatePath,
	CertificateSource,
	CsrSource,
	DnsServiceIdentityInput,
	EkuCheckFailure,
	EkuCheckPurpose,
	EkuCheckResult,
	InitialNameConstraintsInput,
	IpServiceIdentityInput,
	MatchServiceIdentityErrorCode,
	MatchServiceIdentityFailure,
	MatchServiceIdentityInput,
	MatchServiceIdentityResult,
	MatchServiceIdentitySuccess,
	PolicyValidationInput,
	ServiceIdentityInput,
	ServiceIdentityType,
	SrvServiceIdentityInput,
	TrustAnchor,
	UriServiceIdentityInput,
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
	VerifyServiceIdentityInput,
} from './verify/index.ts';
export {
	buildCandidatePath,
	checkExtendedKeyUsage,
	matchCertificateServiceIdentity,
	matchServiceIdentity,
	trustAnchorFromCertificate,
	validateCandidatePath,
	validateForCa,
	validateForCodeSigning,
	validateForTlsClient,
	validateForTlsServer,
	verifyCertificateChain,
	verifyCertificateSigningRequest,
} from './verify/index.ts';

// ── x509 ─────────────────────────────────────────────────────────────
export type {
	AuthorityInformationAccess,
	BasicConstraints,
	CertificateExtensionsInput,
	CertificateMaterial,
	CertificatePolicies,
	CreateCertificateInput,
	CreateCsrInput,
	CreateSelfSignedCertificateInput,
	CsrMaterial,
	DecodedExtensionMap,
	DecodedExtensionValue,
	DistributionPoint,
	DistributionPointName,
	ExtendedKeyUsage,
	ExtensionDecoder,
	ExtensionDecoderMap,
	GeneralName,
	GeneralSubtree,
	InhibitAnyPolicy,
	IssuingDistributionPoint,
	KeyUsage,
	NameAttribute,
	NameConstraintForm,
	NameConstraints,
	NameFieldKey,
	NameInput,
	NameObject,
	ParsedBitFlags,
	ParsedCertificate,
	ParsedCertificateSigningRequest,
	ParsedDistributionPoint,
	ParsedDistributionPointName,
	ParsedExtension,
	ParsedIssuingDistributionPoint,
	ParsedName,
	ParsedNameAttribute,
	ParsedNameConstraintForm,
	ParsedRelativeDistinguishedName,
	ParseOptions,
	PolicyConstraints,
	PolicyInformation,
	PolicyMapping,
	PolicyMappings,
	PolicyQualifierInfo,
	RelativeDistinguishedNameInput,
	SelfSignedCertificateResult,
	SubjectAltName,
	ValidityInput,
} from './x509/index.ts';
export {
	createCertificate,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
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
} from './x509/index.ts';
