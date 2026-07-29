/**
 * Canonical revocation domain surface.
 * Owns CRL, OCSP, and revocation orchestration APIs.
 *
 * @module micro509/revocation
 */

export type {
	CertificateRevocationStatus,
	CheckChainRevocationInput,
	CheckChainRevocationResult,
	CheckChainRevocationValue,
	OcspResponseSource,
	RevocationExecutionError,
	RevocationIndeterminateReason,
	RevocationPolicy,
	RevocationSource,
} from '#micro509/revocation/chain';
export { checkChainRevocation, REVOCATION_INDETERMINATE_REASONS } from '#micro509/revocation/chain';

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
	CrlEncoderErrorCode,
	CrlSource,
	ParseCertificateRevocationListErrorCode,
	ParseCertificateRevocationListFailure,
	ParseCertificateRevocationListResult,
	ParsedCertificateRevocationList,
	ParsedRevokedCertificate,
	RevocationReason,
	RevokedCertificateInput,
	ValidateCertificateRevocationListFailure,
	ValidateCertificateRevocationListInput,
	ValidateCertificateRevocationListResult,
	VerifyCertificateRevocationListSignatureFailure,
	VerifyCertificateRevocationListSignatureResult,
} from '#micro509/revocation/crl';
export {
	checkCertificateRevocationAgainstCrl,
	createCertificateRevocationList,
	isCertificateRevoked,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListDerOrThrow,
	parseCertificateRevocationListPem,
	parseCertificateRevocationListPemOrThrow,
	validateCertificateRevocationList,
	verifyCertificateRevocationListSignature,
} from '#micro509/revocation/crl';

export type {
	CreateOcspCertStatusInput,
	CreateOcspRequestInput,
	CreateOcspRequestItemInput,
	CreateOcspResponseInput,
	CreateOcspSingleResponseInput,
	OcspCertificateSource,
	OcspCertStatus,
	OcspEncoderErrorCode,
	OcspHashAlgorithm,
	OcspRequestMaterial,
	OcspRequestSource,
	OcspResponderRevocationPolicy,
	OcspResponseMaterial,
	OcspResponseStatus,
	ParsedOcspCertId,
	ParsedOcspCertStatus,
	ParsedOcspRequest,
	ParsedOcspResponderId,
	ParsedOcspResponse,
	ParsedOcspSingleResponse,
	ParseOcspRequestErrorCode,
	ParseOcspRequestFailure,
	ParseOcspRequestResult,
	ParseOcspResponseErrorCode,
	ParseOcspResponseFailure,
	ParseOcspResponseResult,
	ValidateOcspResponseErrorCode,
	ValidateOcspResponseFailure,
	ValidateOcspResponseInput,
	ValidateOcspResponseResult,
	VerifyOcspResponseSignatureFailure,
	VerifyOcspResponseSignatureResult,
} from '#micro509/revocation/ocsp';
export {
	createOcspRequest,
	createOcspResponse,
	hasOcspNoCheckExtension,
	parseOcspRequestDer,
	parseOcspRequestDerOrThrow,
	parseOcspRequestPem,
	parseOcspRequestPemOrThrow,
	parseOcspResponseDer,
	parseOcspResponseDerOrThrow,
	parseOcspResponsePem,
	parseOcspResponsePemOrThrow,
	validateOcspResponse,
	verifyOcspResponseSignature,
} from '#micro509/revocation/ocsp';

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
	RevocationCheckIndeterminateValue,
	RevocationCheckRevokedValue,
	RevocationCrlEvidenceInput,
	RevocationEvidenceInput,
	RevocationEvidenceKind,
	RevocationIndeterminateEvidence,
	RevocationIndeterminateReasonCode,
	RevocationOcspEvidenceInput,
	RevocationStatus,
} from '#micro509/revocation/revocation';
export {
	checkCertificateRevocation,
	getCertificateOcspResponderUris,
	REVOCATION_INDETERMINATE_REASON_CODES,
	resolveOcspResponderCandidates,
} from '#micro509/revocation/revocation';

export type {
	IssuingDistributionPoint,
	IssuingDistributionPointBase,
	IssuingDistributionPointForAttributeCerts,
	IssuingDistributionPointForCaCerts,
	IssuingDistributionPointForUserCerts,
} from '#micro509/x509/extensions';

export type {
	ParsedIssuingDistributionPoint,
	ParsedIssuingDistributionPointBase,
	ParsedIssuingDistributionPointScope,
} from '#micro509/x509/parse';
