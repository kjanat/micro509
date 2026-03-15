/**
 * Canonical advanced verification domain surface.
 * Owns chain validation, service identity, policy, and name-constraint APIs.
 * @module
 */

export type * from './identity.ts';
export type {
	DnsServiceIdentityInput,
	IpServiceIdentityInput,
	MatchableServiceIdentityInput,
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
export type * from './name-constraints.ts';
export type { InitialNameConstraintsInput } from './name-constraints.ts';
export type * from './policy.ts';
export type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from './policy.ts';
export type * from './verify.ts';
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
