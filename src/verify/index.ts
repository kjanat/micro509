/**
 * Canonical advanced verification domain surface.
 * Owns chain validation, service identity, policy, and name-constraint APIs.
 *
 * @module micro509/verify
 */

export type {
	DnsServiceIdentityInput,
	IpServiceIdentityInput,
	MatchServiceIdentityErrorCode,
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
} from '#micro509/verify/identity';
export { matchCertificateServiceIdentity, matchServiceIdentity } from '#micro509/verify/identity';

export type { InitialNameConstraintsInput } from '#micro509/verify/name-constraints';

export type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from '#micro509/verify/policy';

export type {
	BuildCandidatePathInput,
	BuildCandidatePathResult,
	CandidatePath,
	CertificateSource,
	ChainRevocationInput,
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
} from '#micro509/verify/verify';
export {
	buildCandidatePath,
	checkExtendedKeyUsage,
	isSelfIssuedCertificate,
	trustAnchorFromCertificate,
	VERIFY_ERROR_CODES,
	validateCandidatePath,
	validateForCa,
	validateForCodeSigning,
	validateForTlsClient,
	validateForTlsServer,
	verifyCertificateChain,
	verifyCertificateSigningRequest,
} from '#micro509/verify/verify';
