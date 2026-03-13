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
import { verifySignedData } from './sig-verify.ts';
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

export type CertificateSource = string | Uint8Array;
export type CsrSource = string | Uint8Array;

// ---------------------------------------------------------------------------
// Purpose & EKU types
// ---------------------------------------------------------------------------

export type VerifyPurpose = 'serverAuth' | 'clientAuth' | 'ca';

export type EkuCheckPurpose =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

export type EkuCheckResult =
	| { readonly ok: true; readonly value: undefined }
	| EkuCheckFailureResult;

export interface EkuCheckFailure
	extends Micro509Error<'leaf_eku_missing' | 'intermediate_eku_constraint'> {
	readonly ok: false;
	readonly index: number;
}

type EkuCheckFailureResult = IndexedErrorResult<
	'leaf_eku_missing' | 'intermediate_eku_constraint',
	Record<never, never>,
	EkuCheckFailure
>;

// ---------------------------------------------------------------------------
// Trust anchor
// ---------------------------------------------------------------------------

export interface TrustAnchor {
	readonly subjectDerHex: string;
	readonly subjectPublicKeyInfoDer: Uint8Array;
	readonly publicKeyAlgorithmOid: string;
	readonly publicKeyParametersOid?: string;
	readonly subjectKeyIdentifier?: string;
}

// ---------------------------------------------------------------------------
// Error & failure types
// ---------------------------------------------------------------------------

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
	| 'name_constraints_violated';

export interface VerifyFailureDetails {
	readonly subjectCommonName?: string;
	readonly issuerCommonName?: string;
	readonly expected?: string;
	readonly actual?: string;
	readonly chainCommonNames?: readonly string[];
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

export interface VerifyChainFailure
	extends IndexedMicro509Error<VerifyErrorCode, VerifyFailureDetails> {
	readonly ok: false;
}

type VerifyFailureResult = IndexedErrorResult<
	VerifyErrorCode,
	VerifyFailureDetails,
	VerifyChainFailure
>;

// ---------------------------------------------------------------------------
// Build candidate path
// ---------------------------------------------------------------------------

export interface BuildCandidatePathInput {
	readonly leaf: CertificateSource;
	readonly intermediates?: readonly CertificateSource[];
	readonly roots: readonly CertificateSource[];
	readonly trustAnchors?: readonly TrustAnchor[];
	readonly at?: Date;
}

export interface CandidatePath {
	readonly leaf: ParsedCertificate;
	readonly chain: readonly ParsedCertificate[];
	readonly root: ParsedCertificate;
}

export type BuildCandidatePathResult =
	| { readonly ok: true; readonly value: CandidatePath }
	| VerifyFailureResult;

// ---------------------------------------------------------------------------
// Validate candidate path
// ---------------------------------------------------------------------------

export interface ValidateCandidatePathInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
	readonly chain: readonly ParsedCertificate[];
	readonly at?: Date;
	readonly purpose?: VerifyPurpose;
	readonly allowSelfSignedLeaf?: boolean;
}

export interface ValidateCandidatePathSuccess {
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

interface ValidateCandidatePathSuccessResult {
	readonly ok: true;
	readonly value: ValidateCandidatePathSuccess;
	readonly policyValidation: PolicyValidationOutcome;
}

type ValidateCandidatePathRawResult =
	| { readonly ok: true; readonly policyValidation: PolicyValidationOutcome }
	| VerifyChainFailure;

export type ValidateCandidatePathResult = ValidateCandidatePathSuccessResult | VerifyFailureResult;

// ---------------------------------------------------------------------------
// Verify chain (convenience composition)
// ---------------------------------------------------------------------------

export interface VerifyCertificateChainInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
	readonly leaf: CertificateSource;
	readonly intermediates?: readonly CertificateSource[];
	readonly roots: readonly CertificateSource[];
	readonly trustAnchors?: readonly TrustAnchor[];
	readonly at?: Date;
	readonly purpose?: VerifyPurpose;
	readonly serviceIdentity?: VerifyServiceIdentityInput;
	readonly allowSelfSignedLeaf?: boolean;
}

export interface VerifiedCertificateChain {
	readonly leaf: ParsedCertificate;
	readonly chain: readonly ParsedCertificate[];
	readonly root: ParsedCertificate;
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

export type VerifyChainResult =
	| { readonly ok: true; readonly value: VerifiedCertificateChain }
	| VerifyFailureResult;

// ---------------------------------------------------------------------------
// CSR verification
// ---------------------------------------------------------------------------

export interface VerifyRequestFailure
	extends Micro509Error<'signature_invalid', VerifyFailureDetails> {
	readonly ok: false;
}

type VerifyRequestFailureResult = ErrorResult<
	'signature_invalid',
	VerifyFailureDetails,
	VerifyRequestFailure
>;

export type VerifyRequestResult =
	| { readonly ok: true; readonly value: ParsedCertificateSigningRequest }
	| VerifyRequestFailureResult;

// ---------------------------------------------------------------------------
// Validation profile inputs
// ---------------------------------------------------------------------------

export interface ValidateForTlsServerInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
	readonly leaf: CertificateSource;
	readonly intermediates?: readonly CertificateSource[];
	readonly roots: readonly CertificateSource[];
	readonly trustAnchors?: readonly TrustAnchor[];
	readonly at?: Date;
	readonly serviceIdentity?: VerifyServiceIdentityInput;
}

export interface ValidateForTlsClientInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
}
export interface ValidateForCodeSigningInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
}
export interface ValidateForCaInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly policy?: PolicyValidationInput;
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

interface ValidationState {
	readonly policy: PolicyValidationState;
	readonly nameConstraints: NameConstraintValidationState;
}

interface NestedValidationInputs {
	readonly policy?: PolicyValidationInput;
	readonly nameConstraints?: InitialNameConstraintsInput;
}

type ValidationStateResult =
	| { readonly ok: true; readonly value: ValidationState }
	| VerifyChainFailure;

type ValidationCheckResult = { readonly ok: true } | VerifyChainFailure;

// ---------------------------------------------------------------------------
// buildCandidatePath
// ---------------------------------------------------------------------------

/**
 * Discovers and signature-verifies a candidate certification path from a
 * leaf certificate to a trusted root or trust anchor. Does NOT validate
 * time, constraints, or leaf policy — use {@link validateCandidatePath}
 * for that, or {@link verifyCertificateChain} for the all-in-one API.
 */
async function buildCandidatePathRaw(
	input: BuildCandidatePathInput,
): Promise<{ readonly ok: true; readonly value: CandidatePath } | VerifyChainFailure> {
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

export async function buildCandidatePath(
	input: BuildCandidatePathInput,
): Promise<BuildCandidatePathResult> {
	const result = await buildCandidatePathRaw(input);
	return result.ok ? result : verifyFailureResult(result);
}

// ---------------------------------------------------------------------------
// validateCandidatePath
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
		const signatureValid = await verifyCertificateSignature(current, issuer);
		if (!signatureValid) {
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

export async function verifyCertificateSigningRequest(
	input: CsrSource,
): Promise<VerifyRequestResult> {
	const parsed =
		typeof input === 'string'
			? parseCertificateSigningRequestPem(input)
			: parseCertificateSigningRequestDer(new Uint8Array(input));
	const signatureValid = await verifySignedData(
		parsed.signatureAlgorithmOid,
		parsed.publicKeyAlgorithmOid,
		parsed.publicKeyParametersOid,
		parsed.subjectPublicKeyInfoDer,
		parsed.signatureValue,
		parsed.certificationRequestInfoDer,
	);
	if (!signatureValid) {
		return verifyRequestFailureResult(
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

function applyEkuCheck(
	result: { readonly ok: true; readonly value: VerifiedCertificateChain },
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

function findUnprocessedCriticalExtension(certificate: ParsedCertificate): string | undefined {
	for (const extension of certificate.extensions) {
		if (extension.critical && !PROCESSED_EXTENSION_OIDS.has(extension.oid)) {
			return extension.oid;
		}
	}
	return undefined;
}

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

function verifyFailureResult(error: VerifyChainFailure): VerifyFailureResult {
	return indexedErrorResult(error);
}

function validateCandidatePathSuccessResult(
	policyValidation: PolicyValidationOutcome,
): ValidateCandidatePathSuccessResult {
	return {
		ok: true,
		value: { policyValidation },
		policyValidation,
	};
}

function verifyRequestFailureResult(
	message: string,
	details?: VerifyFailureDetails,
): VerifyRequestFailureResult {
	const error: VerifyRequestFailure = {
		ok: false,
		...micro509Error('signature_invalid', message, details),
	};
	return errorResult(error);
}

function ekuCheckFailureResult(
	code: EkuCheckFailure['code'],
	message: string,
	index: number,
): EkuCheckFailureResult {
	const error: EkuCheckFailure = {
		ok: false,
		...indexedMicro509Error(code, message, index),
		index,
	};
	return indexedErrorResult(error);
}

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

function hasPolicyValidationInput(input: PolicyValidationInput): boolean {
	return (
		input.initialPolicySet !== undefined ||
		input.requireExplicitPolicy !== undefined ||
		input.inhibitPolicyMapping !== undefined ||
		input.inhibitAnyPolicy !== undefined
	);
}

function hasInitialNameConstraintsInput(input: InitialNameConstraintsInput): boolean {
	return input.permittedSubtrees !== undefined || input.excludedSubtrees !== undefined;
}

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

function formatEku(value: ExtendedKeyUsage): string {
	return typeof value === 'string' ? value : value.value;
}

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
