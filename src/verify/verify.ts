/**
 * Public certificate and CSR verification APIs.
 *
 * Builds and validates certificate paths per RFC 5280 §6, enforcing purpose
 * constraints, policy state, name constraints, and optional service identity
 * checks against a leaf certificate.
 *
 * Three levels of granularity:
 * - {@linkcode buildCandidatePath} — signature-verified path only
 * - {@linkcode validateCandidatePath} — time/constraint/policy validation on a pre-built path
 * - {@linkcode verifyCertificateChain} — all-in-one build + validate
 *
 * Purpose-scoped convenience wrappers: {@linkcode validateForTlsServer},
 * {@linkcode validateForTlsClient}, {@linkcode validateForCodeSigning}, {@linkcode validateForCa}.
 *
 * @module
 */

import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { verifySignedDataDetailed } from '#micro509/internal/crypto/sig-verify.ts';
import { parseIpAddressToBytes } from '#micro509/internal/shared/ip.ts';
import {
	createNameConstraintValidationState,
	evaluateNameConstraints,
	type NameConstraintValidationState,
} from '#micro509/internal/verify/name-constraints-engine.ts';
import {
	createPolicyValidationState,
	evaluatePolicyChain,
	type PolicyValidationState,
} from '#micro509/internal/verify/policy-engine.ts';
import {
	buildChainInternal,
	countCaCertificatesBelowParsed,
	isSelfIssued,
	isWithinValidity,
	loadCertificates,
	loadSingleCertificate,
	verifyCertificateSignature,
} from '#micro509/internal/verify/verify-path.ts';
import type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
} from '#micro509/result/result.ts';
import {
	errorResult,
	indexedErrorResult,
	indexedMicro509Error,
	micro509Error,
} from '#micro509/result/result.ts';
import type { ExtendedKeyUsage } from '#micro509/x509/extensions.ts';
import type {
	ParsedCertificate,
	ParsedCertificateSigningRequest,
	ParsedName,
} from '#micro509/x509/parse.ts';
import {
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
} from '#micro509/x509/parse.ts';
import type { VerifyServiceIdentityInput } from './identity.ts';
import { matchServiceIdentity } from './identity.ts';
import type { InitialNameConstraintsInput } from './name-constraints.ts';
import type { PolicyValidationInput, PolicyValidationOutcome } from './policy.ts';

export type * from './identity.ts';
export type * from './name-constraints.ts';
export type * from './policy.ts';

// ---------------------------------------------------------------------------
// Source types
// ---------------------------------------------------------------------------

/** PEM string or DER bytes for a certificate. PEM may contain multiple blocks. */
export type CertificateSource = string | Uint8Array;
/** PEM string or DER bytes for a certificate signing request. */
export type CsrSource = string | Uint8Array;

// ---------------------------------------------------------------------------
// Purpose & EKU types
// ---------------------------------------------------------------------------

/** High-level purpose applied during path validation to enforce leaf constraints. */
export type VerifyPurpose = 'serverAuth' | 'clientAuth' | 'ca';

/** Extended key usage purpose checked by {@linkcode checkExtendedKeyUsage}. */
export type EkuCheckPurpose =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

/** Result of {@linkcode checkExtendedKeyUsage}. Success carries no value; failure identifies the offending certificate. */
export type EkuCheckResult =
	| {
			readonly ok: true;
			readonly value: undefined;
	  }
	| IndexedErrorResult<
			'leaf_eku_missing' | 'intermediate_eku_constraint',
			Record<never, never>,
			EkuCheckFailure
	  >;

/** Failure from {@linkcode checkExtendedKeyUsage} with the chain index of the certificate that failed. */
export interface EkuCheckFailure
	extends Micro509Error<'leaf_eku_missing' | 'intermediate_eku_constraint'> {
	/** Always `false` for failures. */
	readonly ok: false;
	/** Zero-based index into the chain of the certificate that lacks the required EKU. */
	readonly index: number;
}

// ---------------------------------------------------------------------------
// Trust anchor
// ---------------------------------------------------------------------------

/**
 * Bare trust anchor — subject identity and public key material without a
 * full certificate. Used when the root CA certificate is unavailable but
 * its key is known. Build from a certificate with {@linkcode trustAnchorFromCertificate}.
 */
export interface TrustAnchor {
	/** Parsed subject distinguished name. Used for semantic issuer matching (RFC 5280 §7.1). */
	readonly subject: ParsedName;
	/** DER-encoded SubjectPublicKeyInfo used to verify signatures from this anchor. */
	readonly subjectPublicKeyInfoDer: Uint8Array;
	/** OID of the public key algorithm (e.g. `1.2.840.10045.2.1` for EC). */
	readonly publicKeyAlgorithmOid: string;
	/** OID of the key parameters, when algorithm-specific (e.g. named curve OID for EC). */
	readonly publicKeyParametersOid?: string;
	/** Hex-encoded subject key identifier for AKI matching. */
	readonly subjectKeyIdentifier?: string;
}

// ---------------------------------------------------------------------------
// Error & failure types
// ---------------------------------------------------------------------------

/**
 * Discriminant for every failure a verify operation can produce.
 *
 * - `no_trusted_root` — chain could not be anchored to any root or {@linkcode TrustAnchor}.
 * - `issuer_not_found` — an intermediate's issuer was not in the candidate set.
 * - `signature_invalid` — a certificate's signature failed cryptographic verification.
 * - `certificate_expired` — a certificate's notBefore/notAfter window excludes the validation time.
 * - `ca_required` — an issuer lacks `basicConstraints.ca = true`.
 * - `key_cert_sign_required` — an issuer has keyUsage but omits `keyCertSign`.
 * - `path_length_exceeded` — the number of CA certificates below an issuer exceeds its pathLength.
 * - `authority_key_identifier_mismatch` — a certificate's AKI does not match the issuer's SKI.
 * - `extended_key_usage_invalid` — the leaf certificate lacks the required EKU for the requested purpose.
 * - `subject_alt_name_mismatch` — no SAN entry matches the requested service identity.
 * - `common_name_fallback_suppressed` — CN fallback was attempted but suppressed (SAN present or disabled).
 * - `self_signed_leaf_not_allowed` — the leaf is self-signed and `allowSelfSignedLeaf` was not set.
 * - `unrecognized_critical_extension` — a certificate contains a critical extension the verifier cannot process.
 * - `intermediate_eku_constraint` — an intermediate CA's EKU set does not include the required purpose.
 * - `policy_processing_not_implemented` — policy processing encountered an unsupported construct.
 * - `explicit_policy_required` — `requireExplicitPolicy` was set but no acceptable policy was found.
 * - `initial_policy_set_not_satisfied` — the chain's policies do not intersect `initialPolicySet`.
 * - `initial_name_constraints_not_implemented` — caller-supplied initial name constraints are unsupported.
 * - `unsupported_name_constraints` — a certificate's nameConstraints use an unsupported form.
 * - `name_constraints_violated` — a subject name violates a permitted/excluded subtree.
 * - `unsupported_signature_algorithm_parameters` — the signature algorithm uses unrecognized parameters.
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

/** Diagnostic context attached to every {@linkcode VerifyChainFailure}. All fields are optional; presence depends on the error code. */
export interface VerifyFailureDetails {
	/** CN of the certificate that triggered the failure. */
	readonly subjectCommonName?: string;
	/** CN of the issuer of the offending certificate. */
	readonly issuerCommonName?: string;
	/** The value the verifier expected (e.g. a validity window bound or SKI). */
	readonly expected?: string;
	/** The value actually found. */
	readonly actual?: string;
	/** CNs of every certificate in the chain, leaf-first. Present on `no_trusted_root`. */
	readonly chainCommonNames?: readonly string[];
	/** SAN identifier types the leaf actually presents. Set on identity-match failures. */
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	/** Why the CN-fallback path was not taken. Set on `common_name_fallback_suppressed`. */
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

/** A chain verification failure with its error code, human message, chain index, and diagnostic details. */
export interface VerifyChainFailure
	extends IndexedMicro509Error<VerifyErrorCode, VerifyFailureDetails> {
	/** Always `false` for failures. */
	readonly ok: false;
}

// ---------------------------------------------------------------------------
// Build candidate path
// ---------------------------------------------------------------------------

/** Input for {@linkcode buildCandidatePath}. */
export interface BuildCandidatePathInput {
	/** End-entity certificate to verify. */
	readonly leaf: CertificateSource;
	/** Intermediate CA certificates available for path building. Order does not matter. */
	readonly intermediates?: readonly CertificateSource[];
	/** Trusted root CA certificates. At least one root or trust anchor must be supplied. */
	readonly roots: readonly CertificateSource[];
	/** Bare trust anchors to try when no root certificate matches. */
	readonly trustAnchors?: readonly TrustAnchor[];
	/** Validation time. Defaults to `new Date()`. */
	readonly at?: Date;
}

/** A signature-verified certification path from leaf to root, before constraint validation. */
export interface CandidatePath {
	/** Parsed end-entity certificate. */
	readonly leaf: ParsedCertificate;
	/** Full chain in leaf-to-root order (includes both leaf and root). */
	readonly chain: readonly ParsedCertificate[];
	/** Trusted root that terminates the path. */
	readonly root: ParsedCertificate;
}

/** Result of {@linkcode buildCandidatePath}. On success, contains the {@linkcode CandidatePath}. */
export type BuildCandidatePathResult =
	| {
			readonly ok: true;
			readonly value: CandidatePath;
	  }
	| IndexedErrorResult<VerifyErrorCode, VerifyFailureDetails, VerifyChainFailure>;

// ---------------------------------------------------------------------------
// Validate candidate path
// ---------------------------------------------------------------------------

/** Input for {@linkcode validateCandidatePath}. */
export interface ValidateCandidatePathInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides (takes precedence over flat fields). */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides (takes precedence over flat fields). */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/** Pre-built certificate chain in leaf-to-root order. */
	readonly chain: readonly ParsedCertificate[];
	/** Validation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Leaf purpose constraint to enforce. */
	readonly purpose?: VerifyPurpose;
	/** When `true`, allows a self-signed leaf that is also the root. Defaults to `false`. */
	readonly allowSelfSignedLeaf?: boolean;
}

/** Success payload from {@linkcode validateCandidatePath}. */
export interface ValidateCandidatePathSuccess {
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

/** Internal result from raw candidate-path validation before wrapping. */
type ValidateCandidatePathRawResult =
	| {
			readonly ok: true;
			readonly policyValidation: PolicyValidationOutcome;
	  }
	| VerifyChainFailure;

/** Result of {@linkcode validateCandidatePath}. */
export type ValidateCandidatePathResult =
	| {
			readonly ok: true;
			readonly value: ValidateCandidatePathSuccess;
			/** Shorthand duplicate of `value.policyValidation` for internal forwarding. */
			readonly policyValidation: PolicyValidationOutcome;
	  }
	| IndexedErrorResult<VerifyErrorCode, VerifyFailureDetails, VerifyChainFailure>;

// ---------------------------------------------------------------------------
// Verify chain (convenience composition)
// ---------------------------------------------------------------------------

/** Input for {@linkcode verifyCertificateChain}. Combines path-building, validation, and identity options. */
export interface VerifyCertificateChainInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides. */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides. */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/** End-entity certificate to verify. */
	readonly leaf: CertificateSource;
	/** Intermediate CA certificates available for path building. */
	readonly intermediates?: readonly CertificateSource[];
	/** Trusted root CA certificates. */
	readonly roots: readonly CertificateSource[];
	/** Bare trust anchors to try when no root certificate matches. */
	readonly trustAnchors?: readonly TrustAnchor[];
	/** Validation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Leaf purpose constraint to enforce during validation. */
	readonly purpose?: VerifyPurpose;
	/** DNS/IP/URI/SRV identity to match against the leaf's SAN. */
	readonly serviceIdentity?: VerifyServiceIdentityInput;
	/** When `true`, allows a self-signed leaf. Defaults to `false`. */
	readonly allowSelfSignedLeaf?: boolean;
}

/** Fully verified certificate chain returned on success from {@linkcode verifyCertificateChain}. */
export interface VerifiedCertificateChain {
	/** Parsed end-entity certificate. */
	readonly leaf: ParsedCertificate;
	/** Full chain in leaf-to-root order. */
	readonly chain: readonly ParsedCertificate[];
	/** Trusted root that terminates the path. */
	readonly root: ParsedCertificate;
	/** Final RFC 5280 §6 / RFC 9618 constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

/** Result of {@linkcode verifyCertificateChain}. On success, contains the {@linkcode VerifiedCertificateChain}. */
export type VerifyChainResult =
	| {
			readonly ok: true;
			readonly value: VerifiedCertificateChain;
	  }
	| IndexedErrorResult<VerifyErrorCode, VerifyFailureDetails, VerifyChainFailure>;

// ---------------------------------------------------------------------------
// CSR verification
// ---------------------------------------------------------------------------

/** Failure from {@linkcode verifyCertificateSigningRequest}. */
export interface VerifyRequestFailure
	extends Micro509Error<
		'signature_invalid' | 'unsupported_signature_algorithm_parameters',
		VerifyFailureDetails
	> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Result of {@linkcode verifyCertificateSigningRequest}. On success, contains the parsed CSR. */
export type VerifyRequestResult =
	| {
			readonly ok: true;
			readonly value: ParsedCertificateSigningRequest;
	  }
	| ErrorResult<
			'signature_invalid' | 'unsupported_signature_algorithm_parameters',
			VerifyFailureDetails,
			VerifyRequestFailure
	  >;

// ---------------------------------------------------------------------------
// Validation profile inputs
// ---------------------------------------------------------------------------

/** Input for {@linkcode validateForTlsServer}. Enforces `serverAuth` EKU and optional DNS/IP identity matching. */
export interface ValidateForTlsServerInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides. */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides. */
	readonly nameConstraints?: InitialNameConstraintsInput;
	/** End-entity certificate to verify. */
	readonly leaf: CertificateSource;
	/** Intermediate CA certificates. */
	readonly intermediates?: readonly CertificateSource[];
	/** Trusted root CA certificates. */
	readonly roots: readonly CertificateSource[];
	/** Bare trust anchors. */
	readonly trustAnchors?: readonly TrustAnchor[];
	/** Validation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** DNS/IP identity to match against the leaf's SAN. */
	readonly serviceIdentity?: VerifyServiceIdentityInput;
}

/** Input for {@linkcode validateForTlsClient}. Enforces `clientAuth` EKU. */
export interface ValidateForTlsClientInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides. */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides. */
	readonly nameConstraints?: InitialNameConstraintsInput;
}
/** Input for {@linkcode validateForCodeSigning}. Enforces `codeSigning` EKU. */
export interface ValidateForCodeSigningInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides. */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides. */
	readonly nameConstraints?: InitialNameConstraintsInput;
}
/** Input for {@linkcode validateForCa}. Enforces `basicConstraints.ca` on the leaf. */
export interface ValidateForCaInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	/** Nested policy validation overrides. */
	readonly policy?: PolicyValidationInput;
	/** Nested name constraint overrides. */
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

/** Loose input for building a {@linkcode VerifyFailureDetails} — accepts `undefined` values that get stripped. */
interface VerifyFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly issuerCommonName?: string | undefined;
	readonly expected?: string | undefined;
	readonly actual?: string | undefined;
	readonly chainCommonNames?: readonly string[] | undefined;
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[] | undefined;
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch'
		| undefined;
}

/** Mutable validation state accumulated during path walks. */
interface ValidationState {
	readonly policy: PolicyValidationState;
	readonly nameConstraints: NameConstraintValidationState;
}

/** Optional nested policy and name-constraint inputs extracted from public input types. */
interface NestedValidationInputs {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
}

/** Result of initializing validation state — may fail if constraints are unsupported. */
type ValidationStateResult =
	| {
			readonly ok: true;
			readonly value: ValidationState;
	  }
	| VerifyChainFailure;

/** Pass/fail result for a single validation check (carries no value on success). */
type ValidationCheckResult =
	| {
			readonly ok: true;
	  }
	| VerifyChainFailure;

// ---------------------------------------------------------------------------
// buildCandidatePath
// ---------------------------------------------------------------------------

/**
 * Discovers and signature-verifies a candidate certification path from a
 * leaf certificate to a trusted root or trust anchor. Does NOT validate
 * time, constraints, or leaf policy — use {@linkcode validateCandidatePath}
 * for that, or {@linkcode verifyCertificateChain} for the all-in-one API.
 */
async function buildCandidatePathRaw(input: BuildCandidatePathInput): Promise<
	| {
			readonly ok: true;
			readonly value: CandidatePath;
	  }
	| VerifyChainFailure
> {
	let leaf: ParsedCertificate;
	let intermediates: readonly ParsedCertificate[];
	let roots: readonly ParsedCertificate[];
	try {
		leaf = loadSingleCertificate(input.leaf);
		intermediates = loadCertificates(input.intermediates ?? []);
		roots = loadCertificates(input.roots);
	} catch (error) {
		return failure(
			'issuer_not_found',
			'certificate source is malformed or leaf source does not contain exactly one certificate',
			0,
			detail({
				actual: error instanceof Error ? error.message : 'certificate source is malformed',
			}),
		);
	}
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
 * Builds a signature-verified path from a leaf certificate to a trusted root.
 *
 * Parses the supplied certificates, walks the issuer chain, signature-checks
 * each link, and returns the first valid path. Does not enforce time, constraints,
 * or leaf purpose — call {@linkcode validateCandidatePath} or use the all-in-one
 * {@linkcode verifyCertificateChain} for full validation.
 *
 * @example
 * ```ts
 * import { buildCandidatePath } from 'micro509';
 *
 * const result = await buildCandidatePath({
 *   leaf: leafPem,
 *   intermediates: [intermediatePem],
 *   roots: [rootPem],
 * });
 * if (result.ok) {
 *   console.log('path length:', result.value.chain.length);
 * }
 * ```
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
 * Validates a pre-built candidate path: time window, critical extensions,
 * inter-certificate signatures, CA/keyUsage/AKI constraints, pathLength,
 * policy processing, name constraints, and leaf purpose checks.
 *
 * The chain must be in leaf-to-root order. The root (last entry) is
 * assumed trusted and not re-verified.
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
					expected: describeDateTime(at),
					actual: `${describeDateTime(current.notBefore)}..${describeDateTime(current.notAfter)}`,
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
		if (issuer.keyUsage !== undefined && !issuer.keyUsage.flags.includes('keyCertSign')) {
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
		if (isNonNegativeInteger(pathLength) && maxCaBelow > pathLength) {
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
 * Validates a pre-built certificate chain for time, constraints, policy, and
 * optionally leaf purpose. Wrap the result of {@linkcode buildCandidatePath}.
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
 * All-in-one certificate chain verification: builds a candidate path then
 * validates time, constraints, policy, purpose, and optional service identity.
 *
 * Equivalent to calling {@linkcode buildCandidatePath} followed by
 * {@linkcode validateCandidatePath} (plus identity matching when configured).
 *
 * @example
 * ```ts
 * import { verifyCertificateChain } from 'micro509';
 *
 * const result = await verifyCertificateChain({
 *   leaf: serverCertPem,
 *   intermediates: [intermediatePem],
 *   roots: [rootCaPem],
 *   purpose: 'serverAuth',
 *   serviceIdentity: { type: 'dns', value: 'example.com' },
 * });
 * if (!result.ok) {
 *   console.error(result.error.code, result.error.message);
 * }
 * ```
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
 * Verifies the self-signature of a PKCS#10 certificate signing request.
 *
 * Parses the CSR from PEM or DER, then checks that its signature is valid
 * against its own embedded public key.
 *
 * @example
 * ```ts
 * import { verifyCertificateSigningRequest } from 'micro509';
 *
 * const result = await verifyCertificateSigningRequest(csrPem);
 * if (result.ok) {
 *   console.log('subject:', result.value.subject.values.commonName);
 * }
 * ```
 */
export async function verifyCertificateSigningRequest(
	input: CsrSource,
): Promise<VerifyRequestResult> {
	let parsed: ParsedCertificateSigningRequest;
	try {
		parsed =
			typeof input === 'string'
				? parseCertificateSigningRequestPem(input)
				: parseCertificateSigningRequestDer(new Uint8Array(input));
	} catch (error) {
		return verifyRequestFailureResult(
			'signature_invalid',
			'certificate request input is malformed',
			detail({
				actual: error instanceof Error ? error.message : 'certificate request input is malformed',
			}),
		);
	}
	let signatureResult: Awaited<ReturnType<typeof verifySignedDataDetailed>>;
	try {
		signatureResult = await verifySignedDataDetailed(
			parsed.signatureAlgorithmOid,
			parsed.signatureAlgorithmParametersDer,
			parsed.publicKeyAlgorithmOid,
			parsed.publicKeyParametersOid,
			parsed.subjectPublicKeyInfoDer,
			parsed.signatureValue,
			parsed.certificationRequestInfoDer,
		);
	} catch (error) {
		return verifyRequestFailureResult(
			'signature_invalid',
			'certificate request input is malformed',
			detail({
				subjectCommonName: parsed.subject.values.commonName,
				actual: error instanceof Error ? error.message : 'certificate request input is malformed',
			}),
		);
	}
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
 *
 * @example
 * ```ts
 * import { checkExtendedKeyUsage } from 'micro509';
 *
 * const result = checkExtendedKeyUsage(chain, 'serverAuth');
 * if (!result.ok) {
 *   console.error(result.error.code, result.error.message);
 * }
 * ```
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

/** Extracts a {@linkcode TrustAnchor} from a parsed certificate, copying the subject, SPKI, and key identifiers. */
export function trustAnchorFromCertificate(certificate: ParsedCertificate): TrustAnchor {
	return {
		subject: certificate.subject,
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
 *
 * @example
 * ```ts
 * import { validateForTlsServer } from 'micro509';
 *
 * const result = await validateForTlsServer({
 *   leaf: serverCertPem,
 *   roots: [rootCaPem],
 *   serviceIdentity: { type: 'dns', value: 'example.com' },
 * });
 * if (result.ok) {
 *   console.log('valid for', result.value.leaf.subject.values.commonName);
 * }
 * ```
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
 *
 * @example
 * ```ts
 * import { validateForTlsClient } from 'micro509';
 *
 * const result = await validateForTlsClient({
 *   leaf: clientCertPem,
 *   roots: [rootCaPem],
 * });
 * ```
 */
export async function validateForTlsClient(
	input: ValidateForTlsClientInput,
): Promise<VerifyChainResult> {
	return verifyChainForExtendedKeyUsageProfile(input, 'clientAuth');
}

/**
 * Validates a certificate chain for code signing:
 * chain verification + `codeSigning` EKU (leaf + intermediate propagation).
 *
 * @example
 * ```ts
 * import { validateForCodeSigning } from 'micro509';
 *
 * const result = await validateForCodeSigning({
 *   leaf: codeSigningCertPem,
 *   roots: [rootCaPem],
 * });
 * ```
 */
export async function validateForCodeSigning(
	input: ValidateForCodeSigningInput,
): Promise<VerifyChainResult> {
	return verifyChainForExtendedKeyUsageProfile(input, 'codeSigning');
}

/**
 * Validates a certificate chain for CA use:
 * chain verification + `basicConstraints.ca` check on the leaf.
 *
 * @example
 * ```ts
 * import { validateForCa } from 'micro509';
 *
 * const result = await validateForCa({
 *   leaf: intermediateCertPem,
 *   roots: [rootCaPem],
 * });
 * ```
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

/** Enforces purpose-specific constraints on the leaf certificate (CA flag or EKU). */
function validateLeaf(
	leaf: ParsedCertificate,
	input: {
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

/** Matches the leaf's SAN against the requested service identity. */
function validateServiceIdentity(
	leaf: ParsedCertificate,
	serviceIdentity: VerifyServiceIdentityInput,
): ValidationCheckResult {
	const malformedInput = validateVerifyServiceIdentityInput(serviceIdentity);
	if (!malformedInput.ok) {
		return malformedInput;
	}
	const result = matchServiceIdentity({ certificate: leaf, serviceIdentity });
	if (result.ok) {
		return { ok: true };
	}
	const error = result.error;
	if (
		error.code !== 'subject_alt_name_mismatch' &&
		error.code !== 'common_name_fallback_suppressed'
	) {
		return failure(
			'subject_alt_name_mismatch',
			'service identity input is malformed',
			0,
			detail({ expected: serviceIdentity.value, actual: error.code }),
		);
	}
	return {
		ok: false,
		code: error.code,
		message: error.message,
		index: 0,
		...(error.details === undefined ? {} : { details: error.details }),
	};
}

function validateVerifyServiceIdentityInput(
	serviceIdentity: VerifyServiceIdentityInput,
): ValidationCheckResult {
	if (!isRecord(serviceIdentity)) {
		return failure('subject_alt_name_mismatch', 'service identity input is malformed', 0);
	}
	if (serviceIdentity.type !== 'dns' && serviceIdentity.type !== 'ip') {
		return failure(
			'subject_alt_name_mismatch',
			'service identity input is malformed',
			0,
			detail({ actual: String(serviceIdentity.type) }),
		);
	}
	if (typeof serviceIdentity.value !== 'string') {
		return failure(
			'subject_alt_name_mismatch',
			'service identity input is malformed',
			0,
			detail({ actual: serviceIdentity.type }),
		);
	}
	if (serviceIdentity.type === 'ip') {
		try {
			parseIpAddressToBytes(serviceIdentity.value);
		} catch {
			return failure(
				'subject_alt_name_mismatch',
				'service identity input is malformed',
				0,
				detail({ expected: serviceIdentity.value, actual: 'ip' }),
			);
		}
	}
	return { ok: true };
}

// ---------------------------------------------------------------------------
// Private: helpers
// ---------------------------------------------------------------------------

/** Applies an EKU check to a successfully verified chain and maps failures to verify error codes. */
function applyEkuCheck(
	result: {
		readonly ok: true;
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

/** Verifies a chain then checks that all certificates permit the given EKU purpose. */
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

/** Returns the OID of the first critical extension not in {@linkcode PROCESSED_EXTENSION_OIDS}, or `undefined`. */
function findUnprocessedCriticalExtension(certificate: ParsedCertificate): string | undefined {
	for (const extension of certificate.extensions) {
		if (extension.critical && !PROCESSED_EXTENSION_OIDS.has(extension.oid)) {
			return extension.oid;
		}
	}
	return undefined;
}

/** Constructs a {@linkcode VerifyChainFailure} with the given code, message, optional chain index, and details. */
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

/** Wraps a {@linkcode VerifyChainFailure} into the standard indexed error result shape. */
function verifyFailureResult(
	error: VerifyChainFailure,
): IndexedErrorResult<VerifyErrorCode, VerifyFailureDetails, VerifyChainFailure> {
	return indexedErrorResult(error);
}

/** Wraps a policy outcome into the validate-candidate-path success result shape. */
function validateCandidatePathSuccessResult(
	policyValidation: PolicyValidationOutcome,
): Extract<ValidateCandidatePathResult, { readonly ok: true }> {
	return {
		ok: true,
		value: { policyValidation },
		policyValidation,
	};
}

/** Describes a date in ISO format, or `'<invalid date>'` if invalid. */
function describeDateTime(value: Date): string {
	return Number.isNaN(value.getTime()) ? '<invalid date>' : value.toISOString();
}

/** Returns `true` if the value is a non-negative integer (including zero). */
function isNonNegativeInteger(value: number | undefined): value is number {
	return value !== undefined && Number.isInteger(value) && value >= 0;
}

/** Constructs a CSR verification failure result. */
function verifyRequestFailureResult(
	code: VerifyRequestFailure['code'],
	message: string,
	details?: VerifyFailureDetails,
): ErrorResult<
	'signature_invalid' | 'unsupported_signature_algorithm_parameters',
	VerifyFailureDetails,
	VerifyRequestFailure
> {
	const error: VerifyRequestFailure = {
		ok: false,
		...micro509Error(code, message, details),
	};
	return errorResult(error);
}

/** Constructs an EKU check failure result at the given chain index. */
function ekuCheckFailureResult(
	code: EkuCheckFailure['code'],
	message: string,
	index: number,
): IndexedErrorResult<
	'leaf_eku_missing' | 'intermediate_eku_constraint',
	Record<never, never>,
	EkuCheckFailure
> {
	const error: EkuCheckFailure = {
		ok: false,
		...indexedMicro509Error(code, message, index),
		index,
	};
	return indexedErrorResult(error);
}

/** Merges flat and nested policy fields, with nested taking precedence. */
function resolvePolicyValidationInput(
	input: NestedValidationInputs & PolicyValidationInput,
): PolicyValidationInput {
	const flatInitialPolicySet = normalizeInitialPolicySet(input.initialPolicySet);
	const nestedInitialPolicySet = normalizeInitialPolicySet(input.policy?.initialPolicySet);
	return {
		...(flatInitialPolicySet === undefined ? {} : { initialPolicySet: flatInitialPolicySet }),
		...(input.requireExplicitPolicy === undefined
			? {}
			: { requireExplicitPolicy: input.requireExplicitPolicy }),
		...(input.inhibitPolicyMapping === undefined
			? {}
			: { inhibitPolicyMapping: input.inhibitPolicyMapping }),
		...(input.inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy: input.inhibitAnyPolicy }),
		...(nestedInitialPolicySet === undefined ? {} : { initialPolicySet: nestedInitialPolicySet }),
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

/** Merges flat and nested name-constraint fields, with nested taking precedence. */
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

/** Extracts the resolved policy and name-constraint inputs for forwarding. */
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

/** Returns `true` if any policy validation field is defined. */
function hasPolicyValidationInput(input: PolicyValidationInput): boolean {
	return (
		input.initialPolicySet !== undefined ||
		input.requireExplicitPolicy !== undefined ||
		input.inhibitPolicyMapping !== undefined ||
		input.inhibitAnyPolicy !== undefined
	);
}

/** Returns `true` if any initial name constraint field is defined. */
function hasInitialNameConstraintsInput(input: InitialNameConstraintsInput): boolean {
	return input.permittedSubtrees !== undefined || input.excludedSubtrees !== undefined;
}

/** Constructs failure details with subject/issuer CNs and full chain CN list. */
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

/** Formats an EKU value as a human-readable string (name or raw OID). */
function formatEku(value: ExtendedKeyUsage): string {
	return typeof value === 'string' ? value : value.value;
}

/** Strips `undefined` values from a loose input to produce a clean {@linkcode VerifyFailureDetails}. */
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

/** Initializes policy and name-constraint validation state for a chain walk. */
function buildValidationState(
	input: NestedValidationInputs & PolicyValidationInput & InitialNameConstraintsInput,
	chainLength: number,
): ValidationStateResult {
	const policy = createPolicyValidationState(resolvePolicyValidationInput(input), chainLength);
	const initialNameConstraintsValidation = validateInitialNameConstraintsInput(
		resolveInitialNameConstraintsInput(input),
	);
	if (!initialNameConstraintsValidation.ok) {
		return initialNameConstraintsValidation;
	}
	const nameConstraints = createNameConstraintValidationState(
		initialNameConstraintsValidation.value,
	);
	return {
		ok: true,
		value: {
			policy,
			nameConstraints,
		},
	};
}

function normalizeInitialPolicySet(
	initialPolicySet: PolicyValidationInput['initialPolicySet'] | undefined,
): PolicyValidationInput['initialPolicySet'] | undefined {
	if (initialPolicySet === undefined || initialPolicySet === 'any') {
		return initialPolicySet;
	}
	if (!Array.isArray(initialPolicySet)) {
		return [];
	}
	return initialPolicySet.every((policyIdentifier) => typeof policyIdentifier === 'string')
		? initialPolicySet
		: [];
}

function validateInitialNameConstraintsInput(input: InitialNameConstraintsInput):
	| {
			readonly ok: true;
			readonly value: InitialNameConstraintsInput;
	  }
	| VerifyChainFailure {
	const permittedValidation = validateInitialNameConstraintSubtrees(
		input.permittedSubtrees,
		'permittedSubtrees',
	);
	if (!permittedValidation.ok) {
		return permittedValidation;
	}
	const excludedValidation = validateInitialNameConstraintSubtrees(
		input.excludedSubtrees,
		'excludedSubtrees',
	);
	if (!excludedValidation.ok) {
		return excludedValidation;
	}
	return { ok: true, value: input };
}

function validateInitialNameConstraintSubtrees(
	subtrees:
		| InitialNameConstraintsInput['permittedSubtrees']
		| InitialNameConstraintsInput['excludedSubtrees'],
	label: 'permittedSubtrees' | 'excludedSubtrees',
): { readonly ok: true } | VerifyChainFailure {
	if (subtrees === undefined) {
		return { ok: true };
	}
	if (!Array.isArray(subtrees)) {
		return invalidInitialNameConstraintsFailure(label);
	}
	for (const subtree of subtrees) {
		const invalidForm = describeInvalidInitialNameConstraintForm(subtree);
		if (invalidForm !== undefined) {
			return invalidInitialNameConstraintsFailure(invalidForm);
		}
	}
	return { ok: true };
}

function describeInvalidInitialNameConstraintForm(subtree: unknown): string | undefined {
	if (!isRecord(subtree)) {
		return 'invalid subtree';
	}
	const base = subtree.base;
	if (!isRecord(base) || typeof base.type !== 'string') {
		return 'invalid subtree';
	}
	switch (base.type) {
		case 'dns':
		case 'email':
		case 'uri':
			return typeof base.value === 'string' ? undefined : base.type;
		case 'directoryName':
			return typeof base.derHex === 'string' ? undefined : base.type;
		case 'ip':
			return base.addressBytes instanceof Uint8Array && base.maskBytes instanceof Uint8Array
				? undefined
				: base.type;
		case 'otherName':
		case 'x400Address':
		case 'ediPartyName':
		case 'registeredID':
			return base.type;
		default:
			return base.type;
	}
}

function invalidInitialNameConstraintsFailure(actual: string): VerifyChainFailure {
	return failure(
		'initial_name_constraints_not_implemented',
		'initial name constraints use unsupported or malformed forms',
		undefined,
		detail({ actual }),
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}
