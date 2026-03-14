/**
 * Public certificate and CSR verification APIs.
 *
 * This module builds and validates certificate paths, purpose constraints, policy state,
 * name constraints, and optional identity checks.
 */

import type { ExtendedKeyUsage } from './extensions.ts';
import type { VerifyServiceIdentityInput } from './identity.ts';
import { matchServiceIdentity } from './identity.ts';
import type { InitialNameConstraintsInput } from './name-constraints.ts';
import {
	createNameConstraintValidationState,
	evaluateNameConstraints,
	type NameConstraintValidationState,
} from './name-constraints-engine.ts';
import { OIDS } from './oids.ts';
import type { ParsedCertificate, ParsedCertificateSigningRequest } from './parse.ts';
import { parseCertificateSigningRequestDer, parseCertificateSigningRequestPem } from './parse.ts';
import type { PolicyValidationInput, PolicyValidationOutcome } from './policy.ts';
import {
	createPolicyValidationState,
	evaluatePolicyChain,
	type PolicyValidationState,
} from './policy-engine.ts';
import type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
} from './result.ts';
import { errorResult, indexedErrorResult, indexedMicro509Error, micro509Error } from './result.ts';
import { verifySignedDataDetailed } from './sig-verify.ts';
import {
	buildChainInternal,
	countCaCertificatesBelowParsed,
	isSelfIssued,
	isWithinValidity,
	loadCertificates,
	loadSingleCertificate,
	verifyCertificateSignature,
} from './verify-path.ts';

// ---------------------------------------------------------------------------
// Source types
// ---------------------------------------------------------------------------

/**
 * Describes the accepted source forms for certificate inputs.
 */
export type CertificateSource = string | Uint8Array;
/**
 * Describes the accepted source forms for CSR inputs.
 */
export type CsrSource = string | Uint8Array;

// ---------------------------------------------------------------------------
// Purpose & EKU types
// ---------------------------------------------------------------------------

/**
 * Defines verify purpose.
 */
export type VerifyPurpose = 'serverAuth' | 'clientAuth' | 'ca';

/**
 * Defines EKU check purpose.
 */
export type EkuCheckPurpose =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

/**
 * Represents the result returned by EKU check operations.
 */
export type EkuCheckResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: undefined;
	  }
	| EkuCheckFailureResult;

/**
 * Represents a typed failure produced by EKU check operations.
 */
export interface EkuCheckFailure
	extends Micro509Error<'leaf_eku_missing' | 'intermediate_eku_constraint'> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the zero-based index associated with this value.
	 */
	readonly index: number;
}

/**
 * Represents the result returned by EKU check failure operations.
 */
type EkuCheckFailureResult = IndexedErrorResult<
	'leaf_eku_missing' | 'intermediate_eku_constraint',
	Record<never, never>,
	EkuCheckFailure
>;

// ---------------------------------------------------------------------------
// Trust anchor
// ---------------------------------------------------------------------------

/**
 * Describes trust anchor.
 */
export interface TrustAnchor {
	/**
	 * Carries the hexadecimal subject der.
	 */
	readonly subjectDerHex: string;
	/**
	 * Carries the DER-encoded subject public key info.
	 */
	readonly subjectPublicKeyInfoDer: Uint8Array;
	/**
	 * Carries the OID for public key algorithm.
	 */
	readonly publicKeyAlgorithmOid: string;
	/**
	 * Carries the OID for public key parameters.
	 */
	readonly publicKeyParametersOid?: string;
	/**
	 * Carries the subject key identifier value.
	 */
	readonly subjectKeyIdentifier?: string;
}

// ---------------------------------------------------------------------------
// Error & failure types
// ---------------------------------------------------------------------------

/**
 * Enumerates the error codes used by verify failures.
 */
export type VerifyErrorCode =
	| 'no_trusted_root'
	| 'issuer_not_found'
	| 'signature_invalid'
	| 'certificate_expired'
	| 'ca_required'
	| 'key_cert_sign_required'
	| 'path_length_exceeded'
	| 'authority_key_identifier_mismatch'
	| 'extended_key_usage_invalid'
	| 'subject_alt_name_mismatch'
	| 'common_name_fallback_suppressed'
	| 'self_signed_leaf_not_allowed'
	| 'unrecognized_critical_extension'
	| 'intermediate_eku_constraint'
	| 'policy_processing_not_implemented'
	| 'explicit_policy_required'
	| 'initial_policy_set_not_satisfied'
	| 'initial_name_constraints_not_implemented'
	| 'unsupported_name_constraints'
	| 'name_constraints_violated'
	| 'unsupported_signature_algorithm_parameters';

/**
 * Carries structured details for verify failures.
 */
export interface VerifyFailureDetails {
	/**
	 * Carries the subject common name value.
	 */
	readonly subjectCommonName?: string;
	/**
	 * Carries the issuer common name value.
	 */
	readonly issuerCommonName?: string;
	/**
	 * Carries the expected value.
	 */
	readonly expected?: string;
	/**
	 * Carries the actual value.
	 */
	readonly actual?: string;
	/**
	 * Carries the chain common names value.
	 */
	readonly chainCommonNames?: readonly string[];
	/**
	 * Carries the presented identifier types value.
	 */
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	/**
	 * Carries the common name fallback reason value.
	 */
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

/**
 * Represents a typed failure produced by verify chain operations.
 */
export interface VerifyChainFailure
	extends IndexedMicro509Error<VerifyErrorCode, VerifyFailureDetails> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents the result returned by verify failure operations.
 */
type VerifyFailureResult = IndexedErrorResult<
	VerifyErrorCode,
	VerifyFailureDetails,
	VerifyChainFailure
>;

// ---------------------------------------------------------------------------
// Build candidate path
// ---------------------------------------------------------------------------

/**
 * Describes the input shape for build candidate path operations.
 */
export interface BuildCandidatePathInput {
	/**
	 * Carries the leaf value.
	 */
	readonly leaf: CertificateSource;
	/**
	 * Carries the intermediates value.
	 */
	readonly intermediates?: readonly CertificateSource[];
	/**
	 * Carries the roots value.
	 */
	readonly roots: readonly CertificateSource[];
	/**
	 * Carries the trust anchors value.
	 */
	readonly trustAnchors?: readonly TrustAnchor[];
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
}

/**
 * Describes candidate path.
 */
export interface CandidatePath {
	/**
	 * Carries the leaf value.
	 */
	readonly leaf: ParsedCertificate;
	/**
	 * Carries the chain value.
	 */
	readonly chain: readonly ParsedCertificate[];
	/**
	 * Carries the root value.
	 */
	readonly root: ParsedCertificate;
}

/**
 * Represents the result returned by build candidate path operations.
 */
export type BuildCandidatePathResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: CandidatePath;
	  }
	| VerifyFailureResult;

// ---------------------------------------------------------------------------
// Validate candidate path
// ---------------------------------------------------------------------------

/**
 * Describes the input shape for validate candidate path operations.
 */
export interface ValidateCandidatePathInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/**
	 * Carries the chain value.
	 */
	readonly chain: readonly ParsedCertificate[];
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
	/**
	 * Carries the purpose value.
	 */
	readonly purpose?: VerifyPurpose;
	/**
	 * Indicates whether allow self signed leaf.
	 */
	readonly allowSelfSignedLeaf?: boolean;
}

/**
 * Represents a successful outcome produced by validate candidate path operations.
 */
export interface ValidateCandidatePathSuccess {
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

/**
 * Represents the result returned by validate candidate path success operations.
 */
interface ValidateCandidatePathSuccessResult {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: ValidateCandidatePathSuccess;
	/**
	 * Carries the policy validation value.
	 */
	readonly policyValidation: PolicyValidationOutcome;
}

/**
 * Represents the result returned by validate candidate path raw operations.
 */
type ValidateCandidatePathRawResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the policy validation value.
			 */
			readonly policyValidation: PolicyValidationOutcome;
	  }
	| VerifyChainFailure;

/**
 * Represents the result returned by validate candidate path operations.
 */
export type ValidateCandidatePathResult = ValidateCandidatePathSuccessResult | VerifyFailureResult;

// ---------------------------------------------------------------------------
// Verify chain (convenience composition)
// ---------------------------------------------------------------------------

/**
 * Describes the input shape for verify certificate chain operations.
 */
export interface VerifyCertificateChainInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/**
	 * Carries the leaf value.
	 */
	readonly leaf: CertificateSource;
	/**
	 * Carries the intermediates value.
	 */
	readonly intermediates?: readonly CertificateSource[];
	/**
	 * Carries the roots value.
	 */
	readonly roots: readonly CertificateSource[];
	/**
	 * Carries the trust anchors value.
	 */
	readonly trustAnchors?: readonly TrustAnchor[];
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
	/**
	 * Carries the purpose value.
	 */
	readonly purpose?: VerifyPurpose;
	/**
	 * Carries the service identity value.
	 */
	readonly serviceIdentity?: VerifyServiceIdentityInput;
	/**
	 * Indicates whether allow self signed leaf.
	 */
	readonly allowSelfSignedLeaf?: boolean;
}

/**
 * Describes verified certificate chain.
 */
export interface VerifiedCertificateChain {
	/**
	 * Carries the leaf value.
	 */
	readonly leaf: ParsedCertificate;
	/**
	 * Carries the chain value.
	 */
	readonly chain: readonly ParsedCertificate[];
	/**
	 * Carries the root value.
	 */
	readonly root: ParsedCertificate;
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

/**
 * Represents the result returned by verify chain operations.
 */
export type VerifyChainResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: VerifiedCertificateChain;
	  }
	| VerifyFailureResult;

// ---------------------------------------------------------------------------
// CSR verification
// ---------------------------------------------------------------------------

/**
 * Represents a typed failure produced by verify request operations.
 */
export interface VerifyRequestFailure
	extends Micro509Error<
		'signature_invalid' | 'unsupported_signature_algorithm_parameters',
		VerifyFailureDetails
	> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents the result returned by verify request failure operations.
 */
type VerifyRequestFailureResult = ErrorResult<
	'signature_invalid' | 'unsupported_signature_algorithm_parameters',
	VerifyFailureDetails,
	VerifyRequestFailure
>;

/**
 * Represents the result returned by verify request operations.
 */
export type VerifyRequestResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: ParsedCertificateSigningRequest;
	  }
	| VerifyRequestFailureResult;

// ---------------------------------------------------------------------------
// Validation profile inputs
// ---------------------------------------------------------------------------

/**
 * Describes the input shape for validate for TLS server operations.
 */
export interface ValidateForTlsServerInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/**
	 * Carries the leaf value.
	 */
	readonly leaf: CertificateSource;
	/**
	 * Carries the intermediates value.
	 */
	readonly intermediates?: readonly CertificateSource[];
	/**
	 * Carries the roots value.
	 */
	readonly roots: readonly CertificateSource[];
	/**
	 * Carries the trust anchors value.
	 */
	readonly trustAnchors?: readonly TrustAnchor[];
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
	/**
	 * Carries the service identity value.
	 */
	readonly serviceIdentity?: VerifyServiceIdentityInput;
}

/**
 * Describes the input shape for validate for TLS client operations.
 */
export interface ValidateForTlsClientInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
}
/**
 * Describes the input shape for validate for code signing operations.
 */
export interface ValidateForCodeSigningInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
}
/**
 * Describes the input shape for validate for CA operations.
 */
export interface ValidateForCaInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/**
 * OIDs of extensions this verifier processes during path validation.
 * Per RFC 5280 §6.1, certificates with unrecognized critical extensions
 * that are not in this set must be rejected.
 */
const PROCESSED_EXTENSION_OIDS: ReadonlySet<string> = new Set([
	OIDS.basicConstraints,
	OIDS.keyUsage,
	OIDS.extendedKeyUsage,
	OIDS.subjectAltName,
	OIDS.nameConstraints,
	OIDS.authorityKeyIdentifier,
	OIDS.subjectKeyIdentifier,
	OIDS.authorityInfoAccess,
	OIDS.cRLDistributionPoints,
	OIDS.certificatePolicies,
	OIDS.policyMappings,
	OIDS.policyConstraints,
	OIDS.inhibitAnyPolicy,
]);

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/**
 * Describes the input shape for verify failure details operations.
 */
interface VerifyFailureDetailsInput {
	/**
	 * Carries the subject common name value.
	 */
	readonly subjectCommonName?: string | undefined;
	/**
	 * Carries the issuer common name value.
	 */
	readonly issuerCommonName?: string | undefined;
	/**
	 * Carries the expected value.
	 */
	readonly expected?: string | undefined;
	/**
	 * Carries the actual value.
	 */
	readonly actual?: string | undefined;
	/**
	 * Carries the chain common names value.
	 */
	readonly chainCommonNames?: readonly string[] | undefined;
	/**
	 * Carries the presented identifier types value.
	 */
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[] | undefined;
	/**
	 * Carries the common name fallback reason value.
	 */
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch'
		| undefined;
}

/**
 * Tracks internal state for validation processing.
 */
interface ValidationState {
	/**
	 * Carries the policy value.
	 */
	readonly policy: PolicyValidationState;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints: NameConstraintValidationState;
}

/**
 * Describes nested validation inputs.
 */
interface NestedValidationInputs {
	/**
	 * Carries the policy value.
	 */
	readonly policy?: PolicyValidationInput;
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: InitialNameConstraintsInput;
}

/**
 * Represents the result returned by validation state operations.
 */
type ValidationStateResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: ValidationState;
	  }
	| VerifyChainFailure;

/**
 * Represents the result returned by validation check operations.
 */
type ValidationCheckResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
	  }
	| VerifyChainFailure;

// ---------------------------------------------------------------------------
// buildCandidatePath
// ---------------------------------------------------------------------------

/**
 * Discovers and signature-verifies a candidate certification path from a
 * leaf certificate to a trusted root or trust anchor. Does NOT validate
 * time, constraints, or leaf policy — use {@link validatECandidatePath}
 * for that, or {@link verifyCertificatEChain} for the all-in-one API.
 */
async function buildCandidatePathRaw(input: BuildCandidatePathInput): Promise<
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: CandidatePath;
	  }
	| VerifyChainFailure
> {
	const leaf = loadSingleCertificate(input.leaf);
	const intermediates = loadCertificates(input.intermediates ?? []);
	const roots = loadCertificates(input.roots);
	const anchors = input.trustAnchors ?? [];
	const at = input.at ?? new Date();
	const buildResult = await buildChainInternal(leaf, intermediates, roots, anchors, at, {
		failure,
		detail,
	});
	const chain = buildResult.chain;

	if (!buildResult.foundTrustedRoot) {
		if (buildResult.failure !== undefined) {
			return buildResult.failure;
		}
		if (buildResult.missingIssuerAt !== undefined) {
			return failure(
				'issuer_not_found',
				'issuer certificate not found',
				buildResult.missingIssuerAt,
				buildFailureDetails(chain, buildResult.missingIssuerAt),
			);
		}
		return failure(
			'no_trusted_root',
			'no trusted root found',
			undefined,
			detail({
				chainCommonNames: chain.map(
					(certificate) => certificate.subject.values.commonName ?? '<unnamed>',
				),
			}),
		);
	}

	const root = chain[chain.length - 1];
	if (root === undefined) {
		return failure('no_trusted_root', 'no trusted root found');
	}

	return {
		ok: true,
		value: {
			leaf,
			chain,
			root,
		},
	};
}

/**
 * Builds candidate path.
 *
 * @param input The typed input payload.
 * @returns The built candidate path.
 */
export async function buildCandidatePath(
	input: BuildCandidatePathInput,
): Promise<BuildCandidatePathResult> {
	const result = await buildCandidatePathRaw(input);
	return result.ok ? result : verifyFailureResult(result);
}

// ---------------------------------------------------------------------------
// validatECandidatePath
// ---------------------------------------------------------------------------

/**
 * Validates a pre-built candidate path (time, critical extensions,
 * signatures between chain members, CA/keyUsage/AKI constraints,
 * pathLength, and leaf purpose checks). The chain must be in
 * leaf-to-root order.
 *
 * For full signature verification, each certificate in the chain is
 * verified against its issuer (the next certificate). The root (last
 * entry) is assumed trusted and not re-verified.
 */
async function validateCandidatePathRaw(
	input: ValidateCandidatePathInput,
): Promise<ValidateCandidatePathRawResult> {
	const chain = input.chain;
	const at = input.at ?? new Date();
	const validationStateResult = buildValidationState(input, chain.length);
	if (!validationStateResult.ok) {
		return validationStateResult;
	}
	const leaf = chain[0];

	if (leaf === undefined) {
		return failure('issuer_not_found', 'chain is empty', 0);
	}

	if (chain.length === 1 && isSelfIssued(leaf)) {
		if (input.allowSelfSignedLeaf !== true) {
			return failure(
				'self_signed_leaf_not_allowed',
				'self-signed leaf not allowed',
				0,
				detail({
					subjectCommonName: leaf.subject.values.commonName,
				}),
			);
		}
	}

	for (let index = 0; index < chain.length; index += 1) {
		const current = chain[index];
		if (current === undefined) {
			return failure('issuer_not_found', 'chain element missing', index);
		}
		if (!isWithinValidity(current, at)) {
			return failure(
				'certificate_expired',
				'certificate not valid at requested time',
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					expected: at.toISOString(),
					actual: `${current.notBefore.toISOString()}..${current.notAfter.toISOString()}`,
				}),
			);
		}
		const unprocessedCritical = findUnprocessedCriticalExtension(current);
		if (unprocessedCritical !== undefined) {
			return failure(
				'unrecognized_critical_extension',
				`certificate contains unrecognized critical extension ${unprocessedCritical}`,
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					actual: unprocessedCritical,
				}),
			);
		}
		if (index === chain.length - 1) {
			continue;
		}
		const issuer = chain[index + 1];
		if (issuer === undefined) {
			return failure('issuer_not_found', 'issuer missing', index);
		}
		const signatureResult = await verifyCertificateSignature(current, issuer);
		if (!signatureResult.ok) {
			return failure(
				signatureResult.code,
				signatureResult.reason,
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					issuerCommonName: issuer.subject.values.commonName,
					actual: signatureResult.reason,
				}),
			);
		}
		if (!signatureResult.valid) {
			return failure(
				'signature_invalid',
				'certificate signature does not verify',
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					issuerCommonName: issuer.subject.values.commonName,
				}),
			);
		}
		if (issuer.basicConstraints?.ca !== true) {
			return failure(
				'ca_required',
				'issuer must be a CA certificate',
				index + 1,
				detail({
					subjectCommonName: issuer.subject.values.commonName,
				}),
			);
		}
		if (issuer.keyUsage !== undefined && !issuer.keyUsage.includes('keyCertSign')) {
			return failure(
				'key_cert_sign_required',
				'issuer missing keyCertSign',
				index + 1,
				detail({
					subjectCommonName: issuer.subject.values.commonName,
				}),
			);
		}
		if (
			current.authorityKeyIdentifier !== undefined &&
			issuer.subjectKeyIdentifier !== undefined &&
			current.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
		) {
			return failure(
				'authority_key_identifier_mismatch',
				'authorityKeyIdentifier does not match issuer subjectKeyIdentifier',
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					issuerCommonName: issuer.subject.values.commonName,
					expected: issuer.subjectKeyIdentifier,
					actual: current.authorityKeyIdentifier,
				}),
			);
		}
	}

	for (let index = 1; index < chain.length; index += 1) {
		const current = chain[index];
		if (current === undefined) {
			return failure('issuer_not_found', 'chain element missing', index);
		}
		const maxCaBelow = countCaCertificatesBelowParsed(chain, index);
		const pathLength = current.basicConstraints?.pathLength;
		if (pathLength !== undefined && maxCaBelow > pathLength) {
			return failure(
				'path_length_exceeded',
				'path length constraint exceeded',
				index,
				detail({
					subjectCommonName: current.subject.values.commonName,
					expected: String(pathLength),
					actual: String(maxCaBelow),
				}),
			);
		}
	}

	const policyResult = evaluatePolicyChain(chain, validationStateResult.value.policy);
	if (!policyResult.ok) {
		return failure(
			policyResult.error.code,
			policyResult.error.message,
			0,
			detail({
				expected: policyResult.error.details?.expected,
				actual: policyResult.error.details?.actual,
			}),
		);
	}

	const nameConstraintResult = evaluateNameConstraints(
		chain,
		validationStateResult.value.nameConstraints,
	);
	if (!nameConstraintResult.ok) {
		return nameConstraintResult;
	}

	return validateLeaf(leaf, input, policyResult.value);
}

/**
 * Validates candidate path.
 *
 * @param input The typed input payload.
 * @returns The validation result.
 */
export async function validateCandidatePath(
	input: ValidateCandidatePathInput,
): Promise<ValidateCandidatePathResult> {
	const result = await validateCandidatePathRaw(input);
	return result.ok
		? validateCandidatePathSuccessResult(result.policyValidation)
		: verifyFailureResult(result);
}

// ---------------------------------------------------------------------------
// verifyCertificateChain (convenience composition)
// ---------------------------------------------------------------------------

/**
 * All-in-one: builds a candidate path then validates it.
 * Equivalent to calling {@link buildCandidatePath} followed by
 * {@link validateCandidatePath}.
 */
export async function verifyCertificateChain(
	input: VerifyCertificateChainInput,
): Promise<VerifyChainResult> {
	const buildResult = await buildCandidatePath({
		leaf: input.leaf,
		roots: input.roots,
		...(input.intermediates !== undefined && {
			intermediates: input.intermediates,
		}),
		...(input.trustAnchors !== undefined && {
			trustAnchors: input.trustAnchors,
		}),
		...(input.at !== undefined && { at: input.at }),
	});
	if (!buildResult.ok) {
		return buildResult;
	}

	const validateResult = await validateCandidatePath({
		chain: buildResult.value.chain,
		...(input.at !== undefined && { at: input.at }),
		...(input.purpose !== undefined && { purpose: input.purpose }),
		...copyValidationInputs(input),
		...(input.allowSelfSignedLeaf !== undefined && {
			allowSelfSignedLeaf: input.allowSelfSignedLeaf,
		}),
	});
	if (!validateResult.ok) {
		return validateResult;
	}
	if (input.serviceIdentity !== undefined) {
		const serviceIdentityResult = validateServiceIdentity(
			buildResult.value.leaf,
			input.serviceIdentity,
		);
		if (!serviceIdentityResult.ok) {
			return verifyFailureResult(serviceIdentityResult);
		}
	}

	return {
		ok: true,
		value: {
			...buildResult.value,
			policyValidation: validateResult.value.policyValidation,
		},
	};
}

// ---------------------------------------------------------------------------
// verifyCertificateSigningRequest
// ---------------------------------------------------------------------------

/**
 * Verifies certificate signing request.
 *
 * @param input The typed input payload.
 * @returns The verification result.
 */
export async function verifyCertificateSigningRequest(
	input: CsrSource,
): Promise<VerifyRequestResult> {
	const parsed =
		typeof input === 'string'
			? parseCertificateSigningRequestPem(input)
			: parseCertificateSigningRequestDer(new Uint8Array(input));
	const signatureResult = await verifySignedDataDetailed(
		parsed.signatureAlgorithmOid,
		parsed.signatureAlgorithmParametersDer,
		parsed.publicKeyAlgorithmOid,
		parsed.publicKeyParametersOid,
		parsed.subjectPublicKeyInfoDer,
		parsed.signatureValue,
		parsed.certificationRequestInfoDer,
	);
	if (!signatureResult.ok) {
		return verifyRequestFailureResult(
			signatureResult.code,
			signatureResult.reason,
			detail({
				subjectCommonName: parsed.subject.values.commonName,
				actual: signatureResult.reason,
			}),
		);
	}
	if (!signatureResult.valid) {
		return verifyRequestFailureResult(
			'signature_invalid',
			'certificate request signature does not verify',
			detail({ subjectCommonName: parsed.subject.values.commonName }),
		);
	}
	return { ok: true, value: parsed };
}

// ---------------------------------------------------------------------------
// checkExtendedKeyUsage
// ---------------------------------------------------------------------------

/**
 * Standalone EKU check against a verified certificate chain.
 * Validates that the leaf has the requested purpose and that
 * intermediate CA EKU constraints (if present) permit it.
 */
export function checkExtendedKeyUsage(
	chain: readonly ParsedCertificate[],
	purpose: EkuCheckPurpose,
): EkuCheckResult {
	const leaf = chain[0];
	if (leaf === undefined) {
		return ekuCheckFailureResult('leaf_eku_missing', 'chain is empty', 0);
	}
	if (leaf.extendedKeyUsage !== undefined && !leaf.extendedKeyUsage.includes(purpose)) {
		return ekuCheckFailureResult(
			'leaf_eku_missing',
			`leaf certificate does not include EKU ${purpose}`,
			0,
		);
	}
	for (let index = 1; index < chain.length; index += 1) {
		const intermediate = chain[index];
		if (intermediate === undefined) {
			continue;
		}
		if (
			intermediate.extendedKeyUsage !== undefined &&
			!intermediate.extendedKeyUsage.includes(purpose)
		) {
			return ekuCheckFailureResult(
				'intermediate_eku_constraint',
				`intermediate CA at index ${String(index)} constrains EKU and does not include ${purpose}`,
				index,
			);
		}
	}
	return { ok: true, value: undefined };
}

// ---------------------------------------------------------------------------
// trustAnchorFromCertificate
// ---------------------------------------------------------------------------

/**
 * Trust anchor from certificate.
 *
 * @param certificate The certificate input.
 * @returns The computed value.
 */
export function trustAnchorFromCertificate(certificate: ParsedCertificate): TrustAnchor {
	return {
		subjectDerHex: certificate.subject.derHex,
		subjectPublicKeyInfoDer: certificate.subjectPublicKeyInfoDer,
		publicKeyAlgorithmOid: certificate.publicKeyAlgorithmOid,
		...(certificate.publicKeyParametersOid === undefined
			? {}
			: { publicKeyParametersOid: certificate.publicKeyParametersOid }),
		...(certificate.subjectKeyIdentifier === undefined
			? {}
			: { subjectKeyIdentifier: certificate.subjectKeyIdentifier }),
	};
}

// ---------------------------------------------------------------------------
// Validation profiles
// ---------------------------------------------------------------------------

/** Extracts defined optional fields from a base input for safe forwarding. */
function baseChainInput(
	input: BuildCandidatePathInput &
		PolicyValidationInput &
		InitialNameConstraintsInput &
		NestedValidationInputs,
): VerifyCertificateChainInput {
	return {
		leaf: input.leaf,
		roots: input.roots,
		...(input.intermediates !== undefined && {
			intermediates: input.intermediates,
		}),
		...(input.trustAnchors !== undefined && {
			trustAnchors: input.trustAnchors,
		}),
		...(input.at !== undefined && { at: input.at }),
		...copyValidationInputs(input),
	};
}

/**
 * Validates a certificate chain for TLS server use:
 * chain verification + `serverAuth` EKU (leaf + intermediate propagation)
 * + DNS/IP identity matching.
 */
export async function validateForTlsServer(
	input: ValidateForTlsServerInput,
): Promise<VerifyChainResult> {
	const result = await verifyChainForExtendedKeyUsageProfile(input, 'serverAuth');
	if (!result.ok) {
		return result;
	}
	if (input.serviceIdentity !== undefined) {
		const serviceIdentityResult = validateServiceIdentity(result.value.leaf, input.serviceIdentity);
		if (!serviceIdentityResult.ok) {
			return verifyFailureResult(serviceIdentityResult);
		}
	}
	return result;
}

/**
 * Validates a certificate chain for TLS client use:
 * chain verification + `clientAuth` EKU (leaf + intermediate propagation).
 */
export async function validateForTlsClient(
	input: ValidateForTlsClientInput,
): Promise<VerifyChainResult> {
	return verifyChainForExtendedKeyUsageProfile(input, 'clientAuth');
}

/**
 * Validates a certificate chain for code signing:
 * chain verification + `codeSigning` EKU (leaf + intermediate propagation).
 */
export async function validateForCodeSigning(
	input: ValidateForCodeSigningInput,
): Promise<VerifyChainResult> {
	return verifyChainForExtendedKeyUsageProfile(input, 'codeSigning');
}

/**
 * Validates a certificate chain for CA use:
 * chain verification + `basicConstraints.ca` check on the leaf.
 */
export async function validateForCa(input: ValidateForCaInput): Promise<VerifyChainResult> {
	return verifyCertificateChain({
		...baseChainInput(input),
		purpose: 'ca',
	});
}

// ---------------------------------------------------------------------------
// Private: leaf validation
// ---------------------------------------------------------------------------

/**
 * Validates leaf.
 *
 * @param leaf The leaf value.
 * @param input The typed input payload.
 * @param policyValidation The policy validation value.
 * @returns The validation result.
 */
function validateLeaf(
	leaf: ParsedCertificate,
	input: {
		/**
		 * Carries the purpose value.
		 */
		readonly purpose?: VerifyPurpose;
	},
	policyValidation: PolicyValidationOutcome,
): ValidateCandidatePathRawResult {
	const purpose = input.purpose;
	if (purpose !== undefined) {
		if (purpose === 'ca') {
			if (leaf.basicConstraints?.ca !== true) {
				return failure(
					'ca_required',
					'leaf is not a CA certificate',
					0,
					detail({
						subjectCommonName: leaf.subject.values.commonName,
					}),
				);
			}
		} else if (leaf.extendedKeyUsage !== undefined && !leaf.extendedKeyUsage.includes(purpose)) {
			return failure(
				'extended_key_usage_invalid',
				`leaf missing EKU ${purpose}`,
				0,
				detail({
					subjectCommonName: leaf.subject.values.commonName,
					expected: purpose,
					actual: leaf.extendedKeyUsage.map(formatEku).join(','),
				}),
			);
		}
	}
	return { ok: true, policyValidation };
}

/**
 * Validates service identity.
 *
 * @param leaf The leaf value.
 * @param serviceIdentity The service identity value.
 * @returns The validation result.
 */
function validateServiceIdentity(
	leaf: ParsedCertificate,
	serviceIdentity: VerifyServiceIdentityInput,
): ValidationCheckResult {
	const result = matchServiceIdentity({ certificate: leaf, serviceIdentity });
	if (result.ok) {
		return { ok: true };
	}
	const error = result.error;
	if (
		error.code !== 'subject_alt_name_mismatch' &&
		error.code !== 'common_name_fallback_suppressed'
	) {
		throw new Error('unreachable service identity type');
	}
	return {
		ok: false,
		code: error.code,
		message: error.message,
		index: 0,
		...(error.details === undefined ? {} : { details: error.details }),
	};
}

// ---------------------------------------------------------------------------
// Private: helpers
// ---------------------------------------------------------------------------

/**
 * Apply EKU check.
 *
 * @param result The result value.
 * @param purpose The purpose value.
 * @returns The computed value.
 */
function applyEkuCheck(
	result: {
		/**
		 * Indicates whether the operation succeeded.
		 */
		readonly ok: true;
		/**
		 * Carries the successful value payload.
		 */
		readonly value: VerifiedCertificateChain;
	},
	purpose: EkuCheckPurpose,
): VerifyChainResult {
	const ekuCheck = checkExtendedKeyUsage(result.value.chain, purpose);
	if (!ekuCheck.ok) {
		return verifyFailureResult(
			failure(
				ekuCheck.code === 'leaf_eku_missing'
					? 'extended_key_usage_invalid'
					: 'intermediate_eku_constraint',
				ekuCheck.message,
				ekuCheck.index,
			),
		);
	}
	return result;
}

/**
 * Verifies chain for extended key usage profile.
 *
 * @param input The typed input payload.
 * @param purpose The purpose value.
 * @returns The verification result.
 */
async function verifyChainForExtendedKeyUsageProfile(
	input: BuildCandidatePathInput & PolicyValidationInput & InitialNameConstraintsInput,
	purpose: EkuCheckPurpose,
): Promise<VerifyChainResult> {
	const result = await verifyCertificateChain(baseChainInput(input));
	if (!result.ok) {
		return result;
	}
	return applyEkuCheck(result, purpose);
}

/**
 * Finds unprocessed critical extension.
 *
 * @param certificate The certificate input.
 * @returns The matching unprocessed critical extension.
 */
function findUnprocessedCriticalExtension(certificate: ParsedCertificate): string | undefined {
	for (const extension of certificate.extensions) {
		if (extension.critical && !PROCESSED_EXTENSION_OIDS.has(extension.oid)) {
			return extension.oid;
		}
	}
	return undefined;
}

/**
 * Failure.
 *
 * @param code The code value.
 * @param message The message value.
 * @param index The index value.
 * @param details The structured details value.
 * @returns The computed value.
 */
function failure(
	code: VerifyErrorCode,
	message: string,
	index?: number,
	details?: VerifyFailureDetails,
): VerifyChainFailure {
	return {
		ok: false,
		...indexedMicro509Error(code, message, index, details),
	};
}

/**
 * Verifies failure result.
 *
 * @param error The error value.
 * @returns The verification result.
 */
function verifyFailureResult(error: VerifyChainFailure): VerifyFailureResult {
	return indexedErrorResult(error);
}

/**
 * Validates candidate path success result.
 *
 * @param policyValidation The policy validation value.
 * @returns The validation result.
 */
function validateCandidatePathSuccessResult(
	policyValidation: PolicyValidationOutcome,
): ValidateCandidatePathSuccessResult {
	return {
		ok: true,
		value: { policyValidation },
		policyValidation,
	};
}

/**
 * Verifies request failure result.
 *
 * @param code The code value.
 * @param message The message value.
 * @param details The structured details value.
 * @returns The verification result.
 */
function verifyRequestFailureResult(
	code: VerifyRequestFailure['code'],
	message: string,
	details?: VerifyFailureDetails,
): VerifyRequestFailureResult {
	const error: VerifyRequestFailure = {
		/**
		 * Indicates whether the operation succeeded.
		 */
		ok: false,
		...micro509Error(code, message, details),
	};
	return errorResult(error);
}

/**
 * EKU check failure result.
 *
 * @param code The code value.
 * @param message The message value.
 * @param index The index value.
 * @returns The computed value.
 */
function ekuCheckFailureResult(
	code: EkuCheckFailure['code'],
	message: string,
	index: number,
): EkuCheckFailureResult {
	const error: EkuCheckFailure = {
		/**
		 * Indicates whether the operation succeeded.
		 */
		ok: false,
		...indexedMicro509Error(code, message, index),
		/**
		 * Carries the zero-based index associated with this value.
		 */
		index,
	};
	return indexedErrorResult(error);
}

/**
 * Resolves policy validation input.
 *
 * @param input The typed input payload.
 * @returns The resolved policy validation input.
 */
function resolvePolicyValidationInput(
	input: NestedValidationInputs & PolicyValidationInput,
): PolicyValidationInput {
	return {
		...(input.initialPolicySet === undefined ? {} : { initialPolicySet: input.initialPolicySet }),
		...(input.requireExplicitPolicy === undefined
			? {}
			: { requireExplicitPolicy: input.requireExplicitPolicy }),
		...(input.inhibitPolicyMapping === undefined
			? {}
			: { inhibitPolicyMapping: input.inhibitPolicyMapping }),
		...(input.inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy: input.inhibitAnyPolicy }),
		...(input.policy?.initialPolicySet === undefined
			? {}
			: { initialPolicySet: input.policy.initialPolicySet }),
		...(input.policy?.requireExplicitPolicy === undefined
			? {}
			: { requireExplicitPolicy: input.policy.requireExplicitPolicy }),
		...(input.policy?.inhibitPolicyMapping === undefined
			? {}
			: { inhibitPolicyMapping: input.policy.inhibitPolicyMapping }),
		...(input.policy?.inhibitAnyPolicy === undefined
			? {}
			: { inhibitAnyPolicy: input.policy.inhibitAnyPolicy }),
	};
}

/**
 * Resolves initial name constraints input.
 *
 * @param input The typed input payload.
 * @returns The resolved initial name constraints input.
 */
function resolveInitialNameConstraintsInput(
	input: NestedValidationInputs & InitialNameConstraintsInput,
): InitialNameConstraintsInput {
	return {
		...(input.permittedSubtrees === undefined
			? {}
			: { permittedSubtrees: input.permittedSubtrees }),
		...(input.excludedSubtrees === undefined ? {} : { excludedSubtrees: input.excludedSubtrees }),
		...(input.nameConstraints?.permittedSubtrees === undefined
			? {}
			: { permittedSubtrees: input.nameConstraints.permittedSubtrees }),
		...(input.nameConstraints?.excludedSubtrees === undefined
			? {}
			: { excludedSubtrees: input.nameConstraints.excludedSubtrees }),
	};
}

/**
 * Copy validation inputs.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
function copyValidationInputs(
	input: NestedValidationInputs & PolicyValidationInput & InitialNameConstraintsInput,
): NestedValidationInputs {
	const policy = resolvePolicyValidationInput(input);
	const nameConstraints = resolveInitialNameConstraintsInput(input);
	return {
		...(hasPolicyValidationInput(policy) ? { policy } : {}),
		...(hasInitialNameConstraintsInput(nameConstraints) ? { nameConstraints } : {}),
	};
}

/**
 * Returns whether policy validation input.
 *
 * @param input The typed input payload.
 * @returns Whether the condition holds.
 */
function hasPolicyValidationInput(input: PolicyValidationInput): boolean {
	return (
		input.initialPolicySet !== undefined ||
		input.requireExplicitPolicy !== undefined ||
		input.inhibitPolicyMapping !== undefined ||
		input.inhibitAnyPolicy !== undefined
	);
}

/**
 * Returns whether initial name constraints input.
 *
 * @param input The typed input payload.
 * @returns Whether the condition holds.
 */
function hasInitialNameConstraintsInput(input: InitialNameConstraintsInput): boolean {
	return input.permittedSubtrees !== undefined || input.excludedSubtrees !== undefined;
}

/**
 * Builds failure details.
 *
 * @param chain The chain value.
 * @param index The index value.
 * @returns The built failure details.
 */
function buildFailureDetails(
	chain: readonly ParsedCertificate[],
	index: number,
): VerifyFailureDetails {
	const certificate = chain[index];
	return detail({
		subjectCommonName: certificate?.subject.values.commonName,
		issuerCommonName: certificate?.issuer.values.commonName,
		chainCommonNames: chain.map((entry) => entry.subject.values.commonName ?? '<unnamed>'),
	});
}

/**
 * Format EKU.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function formatEku(value: ExtendedKeyUsage): string {
	return typeof value === 'string' ? value : value.value;
}

/**
 * Detail.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
function detail(input: VerifyFailureDetailsInput): VerifyFailureDetails {
	return {
		...(input.subjectCommonName === undefined
			? {}
			: { subjectCommonName: input.subjectCommonName }),
		...(input.issuerCommonName === undefined ? {} : { issuerCommonName: input.issuerCommonName }),
		...(input.expected === undefined ? {} : { expected: input.expected }),
		...(input.actual === undefined ? {} : { actual: input.actual }),
		...(input.chainCommonNames === undefined ? {} : { chainCommonNames: input.chainCommonNames }),
		...(input.presentedIdentifierTypes === undefined
			? {}
			: { presentedIdentifierTypes: input.presentedIdentifierTypes }),
		...(input.commonNameFallbackReason === undefined
			? {}
			: { commonNameFallbackReason: input.commonNameFallbackReason }),
	};
}

/**
 * Builds validation state.
 *
 * @param input The typed input payload.
 * @param chainLength The chain length value.
 * @returns The built validation state.
 */
function buildValidationState(
	input: NestedValidationInputs & PolicyValidationInput & InitialNameConstraintsInput,
	chainLength: number,
): ValidationStateResult {
	const policy = createPolicyValidationState(resolvePolicyValidationInput(input), chainLength);
	const nameConstraints = createNameConstraintValidationState(
		resolveInitialNameConstraintsInput(input),
	);
	return {
		ok: true,
		value: {
			policy,
			nameConstraints,
		},
	};
}
