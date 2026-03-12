import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	hexToBytes,
	requireElement,
	toHex,
} from './asn1.ts';
import type { IndexedMicro509Error } from './core/result.ts';
import { type DerElement, readElement } from './der.ts';
import type {
	ExtendedKeyUsage,
	NameConstraintForm,
	NameConstraints,
	ParsedNameConstraintForm,
	PolicyInformation,
	PolicyQualifierInfo,
} from './extensions.ts';
import { matchServiceIdentity } from './identity.ts';
import { allOnesMaskForIpAddress, decodeIpAddress, parseIpAddressToBytes } from './ip.ts';
import { nameFieldKeyFromOid } from './name.ts';
import { OIDS } from './oids.ts';
import type {
	ParsedCertificate,
	ParsedCertificateSigningRequest,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from './parse.ts';
import {
	parseCertificateDer,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
} from './parse.ts';
import { splitPemBlocks } from './pem.ts';
import { verifySignedData } from './sig-verify.ts';
import type {
	ConstrainedPolicy,
	InitialNameConstraintsInput,
	PolicyValidationInput,
	PolicyValidationOutcome,
	VerifyServiceIdentityInput,
} from './validation.ts';

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
	| { readonly ok: true }
	| {
			readonly ok: false;
			readonly code: 'leaf_eku_missing' | 'intermediate_eku_constraint';
			readonly message: string;
			readonly index: number;
	  };

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
	| VerifyChainFailure;

// ---------------------------------------------------------------------------
// Validate candidate path
// ---------------------------------------------------------------------------

export interface ValidateCandidatePathInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
	readonly chain: readonly ParsedCertificate[];
	readonly at?: Date;
	readonly purpose?: VerifyPurpose;
	readonly allowSelfSignedLeaf?: boolean;
}

export interface ValidateCandidatePathSuccess {
	readonly ok: true;
	/** Final RFC 9618-constrained policy outputs for this validated path. */
	readonly policyValidation: PolicyValidationOutcome;
}

export type ValidateCandidatePathResult = ValidateCandidatePathSuccess | VerifyChainFailure;

// ---------------------------------------------------------------------------
// Verify chain (convenience composition)
// ---------------------------------------------------------------------------

export interface VerifyCertificateChainInput
	extends PolicyValidationInput,
		InitialNameConstraintsInput {
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
	| VerifyChainFailure;

// ---------------------------------------------------------------------------
// CSR verification
// ---------------------------------------------------------------------------

export type VerifyRequestResult =
	| { readonly ok: true; readonly value: ParsedCertificateSigningRequest }
	| {
			readonly ok: false;
			readonly code: 'signature_invalid';
			readonly message: string;
			readonly details?: VerifyFailureDetails;
	  };

// ---------------------------------------------------------------------------
// Validation profile inputs
// ---------------------------------------------------------------------------

export interface ValidateForTlsServerInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {
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
		InitialNameConstraintsInput {}
export interface ValidateForCodeSigningInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {}
export interface ValidateForCaInput
	extends BuildCandidatePathInput,
		PolicyValidationInput,
		InitialNameConstraintsInput {}

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

interface InternalBuildResult {
	readonly chain: readonly ParsedCertificate[];
	readonly foundTrustedRoot: boolean;
	readonly missingIssuerAt?: number;
	readonly failure?: VerifyChainFailure;
}

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

interface PolicyValidationState {
	initialPolicySet: readonly string[] | 'any';
	explicitPolicy: number;
	inhibitPolicyMapping: number;
	inhibitAnyPolicy: number;
	validPolicyGraph: PolicyGraph | null;
}

interface PolicyGraphNode {
	depth: number;
	validPolicy: string;
	qualifierSet?: readonly PolicyQualifierInfo[];
	expectedPolicySet: Set<string>;
	parentKeys: Set<string>;
	childKeys: Set<string>;
}

interface PolicyGraph {
	nodesByDepth: Map<string, PolicyGraphNode>[];
}

interface NameConstraintValidationState {
	readonly initialPermittedSubtrees: readonly NameConstraintForm[];
	readonly initialExcludedSubtrees: readonly NameConstraintForm[];
}

interface ValidationState {
	readonly policy: PolicyValidationState;
	readonly nameConstraints: NameConstraintValidationState;
}

type ValidationStateResult =
	| { readonly ok: true; readonly value: ValidationState }
	| VerifyChainFailure;

type ValidationCheckResult = { readonly ok: true } | VerifyChainFailure;

type PolicyValidationResult =
	| { readonly ok: true; readonly value: PolicyValidationOutcome }
	| VerifyChainFailure;

// ---------------------------------------------------------------------------
// buildCandidatePath
// ---------------------------------------------------------------------------

/**
 * Discovers and signature-verifies a candidate certification path from a
 * leaf certificate to a trusted root or trust anchor. Does NOT validate
 * time, constraints, or leaf policy — use {@link validateCandidatePath}
 * for that, or {@link verifyCertificateChain} for the all-in-one API.
 */
export async function buildCandidatePath(
	input: BuildCandidatePathInput,
): Promise<BuildCandidatePathResult> {
	const leaf = loadSingleCertificate(input.leaf);
	const intermediates = loadCertificates(input.intermediates ?? []);
	const roots = loadCertificates(input.roots);
	const anchors = input.trustAnchors ?? [];
	const at = input.at ?? new Date();
	const buildResult = await buildChainInternal(leaf, intermediates, roots, anchors, at);
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
export async function validateCandidatePath(
	input: ValidateCandidatePathInput,
): Promise<ValidateCandidatePathResult> {
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

	processPolicyState(chain, validationStateResult.value.policy);
	const policyResult = validateProcessedPolicyState(chain, validationStateResult.value.policy);
	if (!policyResult.ok) {
		return policyResult;
	}

	const nameConstraintResult = checkNameConstraints(
		chain,
		validationStateResult.value.nameConstraints,
	);
	if (!nameConstraintResult.ok) {
		return nameConstraintResult;
	}

	return validateLeaf(leaf, input, policyResult.value);
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
			return serviceIdentityResult;
		}
	}

	return {
		ok: true,
		value: {
			...buildResult.value,
			policyValidation: validateResult.policyValidation,
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
		return {
			ok: false,
			code: 'signature_invalid',
			message: 'certificate request signature does not verify',
			details: detail({ subjectCommonName: parsed.subject.values.commonName }),
		};
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
		return {
			ok: false,
			code: 'leaf_eku_missing',
			message: 'chain is empty',
			index: 0,
		};
	}
	if (leaf.extendedKeyUsage !== undefined && !leaf.extendedKeyUsage.includes(purpose)) {
		return {
			ok: false,
			code: 'leaf_eku_missing',
			message: `leaf certificate does not include EKU ${purpose}`,
			index: 0,
		};
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
			return {
				ok: false,
				code: 'intermediate_eku_constraint',
				message: `intermediate CA at index ${String(index)} constrains EKU and does not include ${purpose}`,
				index,
			};
		}
	}
	return { ok: true };
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
	input: BuildCandidatePathInput & PolicyValidationInput & InitialNameConstraintsInput,
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

function copyValidationInputs(
	input: PolicyValidationInput & InitialNameConstraintsInput,
): PolicyValidationInput & InitialNameConstraintsInput {
	return {
		...(input.initialPolicySet === undefined ? {} : { initialPolicySet: input.initialPolicySet }),
		...(input.requireExplicitPolicy === undefined
			? {}
			: { requireExplicitPolicy: input.requireExplicitPolicy }),
		...(input.inhibitPolicyMapping === undefined
			? {}
			: { inhibitPolicyMapping: input.inhibitPolicyMapping }),
		...(input.inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy: input.inhibitAnyPolicy }),
		...(input.permittedSubtrees === undefined
			? {}
			: { permittedSubtrees: input.permittedSubtrees }),
		...(input.excludedSubtrees === undefined ? {} : { excludedSubtrees: input.excludedSubtrees }),
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
			return serviceIdentityResult;
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
): ValidateCandidatePathResult {
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
		return result;
	}
	if (
		result.code !== 'subject_alt_name_mismatch' &&
		result.code !== 'common_name_fallback_suppressed'
	) {
		throw new Error('unreachable service identity type');
	}
	return {
		ok: false,
		code: result.code,
		message: result.message,
		index: 0,
		...(result.details === undefined ? {} : { details: result.details }),
	};
}

// ---------------------------------------------------------------------------
// Private: chain building
// ---------------------------------------------------------------------------

async function buildChainInternal(
	leaf: ParsedCertificate,
	intermediates: readonly ParsedCertificate[],
	roots: readonly ParsedCertificate[],
	trustAnchors: readonly TrustAnchor[],
	at: Date,
): Promise<InternalBuildResult> {
	const candidates = [...intermediates, ...roots];
	const subjectIndex = new Map<string, ParsedCertificate[]>();
	const order = new Map<string, number>();
	const rootFingerprints = new Set(roots.map((candidate) => fingerprint(candidate)));
	const anchorIndex = new Map<string, TrustAnchor[]>();
	for (const anchor of trustAnchors) {
		const existing = anchorIndex.get(anchor.subjectDerHex);
		if (existing === undefined) {
			anchorIndex.set(anchor.subjectDerHex, [anchor]);
		} else {
			existing.push(anchor);
		}
	}
	let sawUntrustedAnchor = false;
	let deepestPath: readonly ParsedCertificate[] = [leaf];
	let deepestMissingIssuerAt: number | undefined;
	let preferredFailure: VerifyChainFailure | undefined;
	const deadEnds = new Set<string>();

	candidates.forEach((candidate, index) => {
		const key = candidate.subject.derHex;
		const existing = subjectIndex.get(key);
		if (existing === undefined) {
			subjectIndex.set(key, [candidate]);
		} else {
			existing.push(candidate);
		}
		order.set(fingerprint(candidate), index);
	});

	const maxDepth = candidates.length + 1;
	const startFingerprint = fingerprint(leaf);
	const success = await search(leaf, [leaf], new Set([startFingerprint]), 0);
	if (success !== undefined) {
		return { chain: success, foundTrustedRoot: true };
	}
	if (preferredFailure !== undefined) {
		return {
			chain: deepestPath,
			foundTrustedRoot: false,
			failure: preferredFailure,
		};
	}
	if (sawUntrustedAnchor) {
		return { chain: deepestPath, foundTrustedRoot: false };
	}
	return deepestMissingIssuerAt === undefined
		? { chain: deepestPath, foundTrustedRoot: false }
		: {
				chain: deepestPath,
				foundTrustedRoot: false,
				missingIssuerAt: deepestMissingIssuerAt,
			};

	async function search(
		current: ParsedCertificate,
		path: readonly ParsedCertificate[],
		visited: ReadonlySet<string>,
		caBelowCount: number,
	): Promise<readonly ParsedCertificate[] | undefined> {
		if (rootFingerprints.has(fingerprint(current))) {
			return path;
		}
		const matchedAnchor = await matchTrustAnchor(current, anchorIndex);
		if (matchedAnchor) {
			return path;
		}
		if (path.length > maxDepth) {
			return undefined;
		}
		const memoKey = `${fingerprint(current)}:${caBelowCount}`;
		if (deadEnds.has(memoKey)) {
			return undefined;
		}
		const issuers = rankIssuerCandidates(
			current,
			subjectIndex.get(current.issuer.derHex) ?? [],
			order,
			rootFingerprints,
		);
		if (issuers.length === 0) {
			updateDeepest(path);
			if (isSelfIssued(current)) {
				sawUntrustedAnchor = true;
			} else {
				deepestMissingIssuerAt = path.length - 1;
			}
			deadEnds.add(memoKey);
			return undefined;
		}

		for (const issuer of issuers) {
			const issuerFingerprint = fingerprint(issuer);
			if (visited.has(issuerFingerprint)) {
				continue;
			}
			if (!isWithinValidity(issuer, at)) {
				recordFailure(
					failure(
						'certificate_expired',
						'certificate not valid at requested time',
						path.length,
						detail({
							subjectCommonName: issuer.subject.values.commonName,
							expected: at.toISOString(),
							actual: `${issuer.notBefore.toISOString()}..${issuer.notAfter.toISOString()}`,
						}),
					),
					path,
				);
				continue;
			}
			if (issuer.basicConstraints?.ca !== true) {
				recordFailure(
					failure(
						'ca_required',
						'issuer must be a CA certificate',
						path.length,
						detail({
							subjectCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (issuer.keyUsage !== undefined && !issuer.keyUsage.includes('keyCertSign')) {
				recordFailure(
					failure(
						'key_cert_sign_required',
						'issuer missing keyCertSign',
						path.length,
						detail({
							subjectCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (
				current.authorityKeyIdentifier !== undefined &&
				issuer.subjectKeyIdentifier !== undefined &&
				current.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
			) {
				recordFailure(
					failure(
						'authority_key_identifier_mismatch',
						'authorityKeyIdentifier does not match issuer subjectKeyIdentifier',
						path.length - 1,
						detail({
							subjectCommonName: current.subject.values.commonName,
							issuerCommonName: issuer.subject.values.commonName,
							expected: issuer.subjectKeyIdentifier,
							actual: current.authorityKeyIdentifier,
						}),
					),
					path,
				);
				continue;
			}
			const nextCaBelowCount =
				caBelowCount + (current.basicConstraints?.ca === true && !isSelfIssued(current) ? 1 : 0);
			const pathLength = issuer.basicConstraints?.pathLength;
			if (pathLength !== undefined && nextCaBelowCount > pathLength) {
				recordFailure(
					failure(
						'path_length_exceeded',
						'path length constraint exceeded',
						path.length,
						detail({
							subjectCommonName: issuer.subject.values.commonName,
							expected: String(pathLength),
							actual: String(nextCaBelowCount),
						}),
					),
					path,
				);
				continue;
			}
			if (!(await verifyCertificateSignature(current, issuer))) {
				recordFailure(
					failure(
						'signature_invalid',
						'certificate signature does not verify',
						path.length - 1,
						detail({
							subjectCommonName: current.subject.values.commonName,
							issuerCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			const nextVisited = new Set(visited);
			nextVisited.add(issuerFingerprint);
			const nextPath = [...path, issuer];
			const result = await search(issuer, nextPath, nextVisited, nextCaBelowCount);
			if (result !== undefined) {
				return result;
			}
		}

		deadEnds.add(memoKey);
		updateDeepest(path);
		return undefined;
	}

	function updateDeepest(path: readonly ParsedCertificate[]): void {
		if (path.length > deepestPath.length) {
			deepestPath = path;
		}
	}

	function recordFailure(
		candidateFailure: VerifyChainFailure,
		path: readonly ParsedCertificate[],
	): void {
		if (preferredFailure === undefined || path.length >= deepestPath.length) {
			preferredFailure = candidateFailure;
		}
	}
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
		return failure(
			ekuCheck.code === 'leaf_eku_missing'
				? 'extended_key_usage_invalid'
				: 'intermediate_eku_constraint',
			ekuCheck.message,
			ekuCheck.index,
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

function rankIssuerCandidates(
	current: ParsedCertificate,
	candidates: readonly ParsedCertificate[],
	order: ReadonlyMap<string, number>,
	rootFingerprints: ReadonlySet<string>,
): readonly ParsedCertificate[] {
	const aki = current.authorityKeyIdentifier;
	return [...candidates]
		.filter((candidate) => isIssuerOf(candidate, current))
		.sort((left, right) => {
			const akiScore = compareBooleans(matchesAki(left, aki), matchesAki(right, aki));
			if (akiScore !== 0) {
				return akiScore;
			}
			const rootScore = compareBooleans(
				rootFingerprints.has(fingerprint(left)),
				rootFingerprints.has(fingerprint(right)),
			);
			if (rootScore !== 0) {
				return rootScore;
			}
			return (
				(order.get(fingerprint(left)) ?? Number.MAX_SAFE_INTEGER) -
				(order.get(fingerprint(right)) ?? Number.MAX_SAFE_INTEGER)
			);
		});
}

function matchesAki(candidate: ParsedCertificate, aki: string | undefined): boolean {
	return (
		aki !== undefined &&
		candidate.subjectKeyIdentifier !== undefined &&
		candidate.subjectKeyIdentifier === aki
	);
}

function compareBooleans(left: boolean, right: boolean): number {
	if (left === right) {
		return 0;
	}
	return left ? -1 : 1;
}

function isIssuerOf(issuer: ParsedCertificate, child: ParsedCertificate): boolean {
	return child.issuer.derHex === issuer.subject.derHex;
}

function findUnprocessedCriticalExtension(certificate: ParsedCertificate): string | undefined {
	for (const extension of certificate.extensions) {
		if (extension.critical && !PROCESSED_EXTENSION_OIDS.has(extension.oid)) {
			return extension.oid;
		}
	}
	return undefined;
}

function isWithinValidity(certificate: ParsedCertificate, at: Date): boolean {
	return (
		certificate.notBefore.getTime() <= at.getTime() &&
		at.getTime() <= certificate.notAfter.getTime()
	);
}

function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

function countCaCertificatesBelowParsed(
	chain: readonly ParsedCertificate[],
	index: number,
): number {
	let total = 0;
	for (let cursor = 0; cursor < index; cursor += 1) {
		const certificate = chain[cursor];
		if (certificate?.basicConstraints?.ca === true && !isSelfIssued(certificate)) {
			total += 1;
		}
	}
	return total;
}

function loadCertificates(sources: readonly CertificateSource[]): readonly ParsedCertificate[] {
	const loaded: ParsedCertificate[] = [];
	for (const source of sources) {
		loaded.push(...expandSource(source));
	}
	return loaded;
}

function loadSingleCertificate(source: CertificateSource): ParsedCertificate {
	const loaded = expandSource(source);
	const first = loaded[0];
	if (first === undefined) {
		throw new Error('No certificate found');
	}
	if (loaded.length !== 1) {
		throw new Error('Expected a single certificate source');
	}
	return first;
}

function expandSource(source: CertificateSource): readonly ParsedCertificate[] {
	if (typeof source === 'string') {
		return splitPemBlocks(source)
			.filter((block) => block.label === 'CERTIFICATE')
			.map((block) => parseCertificateDer(block.bytes));
	}
	return [parseCertificateDer(new Uint8Array(source))];
}

async function verifyCertificateSignature(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
): Promise<boolean> {
	return verifySignedData(
		certificate.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		certificate.signatureValue,
		certificate.tbsCertificateDer,
	);
}

async function matchTrustAnchor(
	certificate: ParsedCertificate,
	anchorIndex: ReadonlyMap<string, readonly TrustAnchor[]>,
): Promise<boolean> {
	const anchors = anchorIndex.get(certificate.issuer.derHex);
	if (anchors === undefined) {
		return false;
	}
	for (const anchor of anchors) {
		if (
			anchor.subjectKeyIdentifier !== undefined &&
			certificate.authorityKeyIdentifier !== undefined &&
			anchor.subjectKeyIdentifier !== certificate.authorityKeyIdentifier
		) {
			continue;
		}
		const verified = await verifySignedData(
			certificate.signatureAlgorithmOid,
			anchor.publicKeyAlgorithmOid,
			anchor.publicKeyParametersOid,
			anchor.subjectPublicKeyInfoDer,
			certificate.signatureValue,
			certificate.tbsCertificateDer,
		);
		if (verified) {
			return true;
		}
	}
	return false;
}

function fingerprint(certificate: ParsedCertificate): string {
	return toHex(certificate.der);
}

function failure(
	code: VerifyErrorCode,
	message: string,
	index?: number,
	details?: VerifyFailureDetails,
): VerifyChainFailure {
	return {
		ok: false,
		code,
		message,
		...(index === undefined ? {} : { index }),
		...(details === undefined ? {} : { details }),
	};
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
	input: PolicyValidationInput & InitialNameConstraintsInput,
	chainLength: number,
): ValidationStateResult {
	const policy = normalizePolicyValidationState(input, chainLength);
	const nameConstraints = normalizeNameConstraintValidationState(input);
	return {
		ok: true,
		value: {
			policy,
			nameConstraints,
		},
	};
}

function normalizePolicyValidationState(
	input: PolicyValidationInput,
	chainLength: number,
): PolicyValidationState {
	const disabledCounter = chainLength + 1;
	return {
		initialPolicySet: input.initialPolicySet ?? 'any',
		explicitPolicy: input.requireExplicitPolicy === true ? 0 : disabledCounter,
		inhibitPolicyMapping: input.inhibitPolicyMapping === true ? 0 : disabledCounter,
		inhibitAnyPolicy: input.inhibitAnyPolicy === true ? 0 : disabledCounter,
		validPolicyGraph: createInitialPolicyGraph(),
	};
}

function normalizeNameConstraintValidationState(
	input: InitialNameConstraintsInput,
): NameConstraintValidationState {
	return {
		initialPermittedSubtrees: input.permittedSubtrees?.map((subtree) => subtree.base) ?? [],
		initialExcludedSubtrees: input.excludedSubtrees?.map((subtree) => subtree.base) ?? [],
	};
}

function createInitialPolicyGraph(): PolicyGraph {
	const rootNode = createPolicyGraphNode(0, OIDS.anyPolicy, undefined, [OIDS.anyPolicy], []);
	return {
		nodesByDepth: [new Map([[policyNodeKey(0, OIDS.anyPolicy), rootNode]])],
	};
}

function createPolicyGraphNode(
	depth: number,
	validPolicy: string,
	qualifierSet: readonly PolicyQualifierInfo[] | undefined,
	expectedPolicySet: readonly string[],
	parentKeys: readonly string[],
): PolicyGraphNode {
	return {
		depth,
		validPolicy,
		...(qualifierSet === undefined ? {} : { qualifierSet }),
		expectedPolicySet: new Set(expectedPolicySet),
		parentKeys: new Set(parentKeys),
		childKeys: new Set<string>(),
	};
}

function policyNodeKey(depth: number, validPolicy: string): string {
	return `${String(depth)}:${validPolicy}`;
}

function processPolicyState(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): void {
	const leafDepth = chain.length - 1;
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const certificate = chain[index];
		if (certificate === undefined) {
			continue;
		}
		const depth = leafDepth - index;
		processPolicyCertificate(state, certificate, depth, depth === leafDepth);
	}
}

function validateProcessedPolicyState(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationResult {
	const outcome = derivePolicyValidationOutcome(chain, state);
	if (state.explicitPolicy === 0 && outcome.userConstrainedPolicies.length === 0) {
		return failure(
			'explicit_policy_required',
			'policy validation requires an explicit permitted policy',
			0,
			detail({
				expected:
					state.initialPolicySet === 'any' ? 'explicit policy' : state.initialPolicySet.join(','),
				actual: describeFinalPolicies(outcome.userConstrainedPolicies),
			}),
		);
	}
	if (state.initialPolicySet !== 'any' && outcome.userConstrainedPolicies.length === 0) {
		return failure(
			'initial_policy_set_not_satisfied',
			'certificate chain does not satisfy the requested initial policy set',
			0,
			detail({
				expected: state.initialPolicySet.join(','),
				actual: describeFinalPolicies(outcome.userConstrainedPolicies),
			}),
		);
	}
	return { ok: true, value: outcome };
}

function derivePolicyValidationOutcome(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationOutcome {
	const authorityConstrainedPolicies = collectAuthorityConstrainedPolicies(
		chain,
		state.validPolicyGraph,
	);
	const rootDomainPolicies = collectRootDomainPolicies(chain, state.validPolicyGraph);
	return {
		authorityConstrainedPolicies: [...authorityConstrainedPolicies.values()].sort(comparePolicies),
		userConstrainedPolicies: deriveUserConstrainedPolicies(
			authorityConstrainedPolicies,
			rootDomainPolicies,
			state.initialPolicySet,
		),
	};
}

function collectAuthorityConstrainedPolicies(
	chain: readonly ParsedCertificate[],
	graph: PolicyGraph | null,
): ReadonlyMap<string, ConstrainedPolicy> {
	if (graph === null) {
		return new Map<string, ConstrainedPolicy>();
	}
	const leafDepth = chain.length - 1;
	const finalDepth = graph.nodesByDepth[leafDepth];
	if (finalDepth === undefined) {
		return new Map<string, ConstrainedPolicy>();
	}
	const authorityPolicies = new Map<string, ConstrainedPolicy>();
	for (const [key, node] of finalDepth) {
		if (node.validPolicy === OIDS.anyPolicy) {
			authorityPolicies.set(
				OIDS.anyPolicy,
				buildConstrainedPolicy(OIDS.anyPolicy, node.qualifierSet),
			);
			continue;
		}
		if (reachesAuthorityRoot(graph, key)) {
			authorityPolicies.set(
				node.validPolicy,
				buildConstrainedPolicy(node.validPolicy, node.qualifierSet),
			);
		}
	}
	return authorityPolicies;
}

function reachesAuthorityRoot(graph: PolicyGraph, nodeKey: string): boolean {
	const pending = [nodeKey];
	const visited = new Set<string>();
	while (pending.length > 0) {
		const currentKey = pending.pop();
		if (currentKey === undefined || visited.has(currentKey)) {
			continue;
		}
		visited.add(currentKey);
		const node = getPolicyGraphNode(graph, currentKey);
		if (node === undefined) {
			continue;
		}
		for (const parentKey of node.parentKeys) {
			const parent = getPolicyGraphNode(graph, parentKey);
			if (parent === undefined) {
				continue;
			}
			if (parent.depth === 0 && parent.validPolicy === OIDS.anyPolicy) {
				return true;
			}
			pending.push(parentKey);
		}
	}
	return false;
}

function collectRootDomainPolicies(
	chain: readonly ParsedCertificate[],
	graph: PolicyGraph | null,
): ReadonlyMap<string, ConstrainedPolicy> {
	if (graph === null) {
		return new Map<string, ConstrainedPolicy>();
	}
	const leafDepth = chain.length - 1;
	const finalDepth = graph.nodesByDepth[leafDepth];
	if (finalDepth === undefined) {
		return new Map<string, ConstrainedPolicy>();
	}
	const rootPolicies = new Map<string, ConstrainedPolicy>();
	for (const [key, node] of finalDepth) {
		if (node.validPolicy === OIDS.anyPolicy) {
			rootPolicies.set(OIDS.anyPolicy, buildConstrainedPolicy(OIDS.anyPolicy, node.qualifierSet));
			continue;
		}
		collectAuthorityConstrainedPolicyRoots(graph, key, rootPolicies);
	}
	return rootPolicies;
}

function collectAuthorityConstrainedPolicyRoots(
	graph: PolicyGraph,
	nodeKey: string,
	authorityPolicies: Map<string, ConstrainedPolicy>,
): void {
	const pending = [nodeKey];
	const visited = new Set<string>();
	while (pending.length > 0) {
		const currentKey = pending.pop();
		if (currentKey === undefined || visited.has(currentKey)) {
			continue;
		}
		visited.add(currentKey);
		const node = getPolicyGraphNode(graph, currentKey);
		if (node === undefined) {
			continue;
		}
		for (const parentKey of node.parentKeys) {
			const parent = getPolicyGraphNode(graph, parentKey);
			if (parent === undefined) {
				continue;
			}
			if (parent.depth === 0 && parent.validPolicy === OIDS.anyPolicy) {
				if (node.validPolicy !== OIDS.anyPolicy) {
					authorityPolicies.set(
						node.validPolicy,
						buildConstrainedPolicy(
							node.validPolicy,
							currentKey === nodeKey ? node.qualifierSet : undefined,
						),
					);
				}
				continue;
			}
			pending.push(parentKey);
		}
	}
}

function deriveUserConstrainedPolicies(
	finalAuthorityConstrainedPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	rootDomainPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	initialPolicySet: readonly string[] | 'any',
): readonly ConstrainedPolicy[] {
	if (initialPolicySet === 'any') {
		return [...finalAuthorityConstrainedPolicies.values()].sort(comparePolicies);
	}
	const anyPolicy = rootDomainPolicies.get(OIDS.anyPolicy);
	const constrained = new Map<string, ConstrainedPolicy>();
	for (const policyIdentifier of initialPolicySet) {
		const direct = rootDomainPolicies.get(policyIdentifier);
		if (direct !== undefined) {
			constrained.set(policyIdentifier, direct);
			continue;
		}
		if (anyPolicy !== undefined) {
			constrained.set(
				policyIdentifier,
				buildConstrainedPolicy(policyIdentifier, anyPolicy.policyQualifiers),
			);
		}
	}
	return [...constrained.values()];
}

function buildConstrainedPolicy(
	policyIdentifier: string,
	policyQualifiers: readonly PolicyQualifierInfo[] | undefined,
): ConstrainedPolicy {
	return {
		policyIdentifier,
		...(policyQualifiers === undefined ? {} : { policyQualifiers }),
	};
}

function comparePolicies(left: ConstrainedPolicy, right: ConstrainedPolicy): number {
	return left.policyIdentifier.localeCompare(right.policyIdentifier);
}

function describeFinalPolicies(policies: readonly ConstrainedPolicy[]): string {
	return policies.length === 0
		? '<none>'
		: policies.map((policy) => policy.policyIdentifier).join(',');
}

function processPolicyCertificate(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
	depth: number,
	isLeaf: boolean,
): void {
	const certificatePolicies = normalizeCertificatePolicies(certificate.certificatePolicies);
	if (state.validPolicyGraph !== null && certificatePolicies === undefined) {
		state.validPolicyGraph = null;
	} else if (state.validPolicyGraph !== null && certificatePolicies !== undefined) {
		applyCertificatePolicyStep(
			state.validPolicyGraph,
			certificatePolicies,
			depth,
			state.inhibitAnyPolicy > 0 || (!isLeaf && isSelfIssued(certificate)),
		);
		if (certificate.policyMappings !== undefined) {
			applyPolicyMappingsStep(
				state.validPolicyGraph,
				depth,
				certificate.policyMappings,
				state.inhibitPolicyMapping > 0,
			);
		}
	}
	updatePolicyCounters(state, certificate, isLeaf);
}

function normalizeCertificatePolicies(
	policies: readonly PolicyInformation[] | undefined,
): Map<string, PolicyInformation> | undefined {
	if (policies === undefined) {
		return undefined;
	}
	const byOid = new Map<string, PolicyInformation>();
	for (const policy of policies) {
		if (!byOid.has(policy.policyIdentifier)) {
			byOid.set(policy.policyIdentifier, policy);
		}
	}
	return byOid;
}

function applyCertificatePolicyStep(
	graph: PolicyGraph,
	certificatePolicies: ReadonlyMap<string, PolicyInformation>,
	depth: number,
	allowAnyPolicyExpansion: boolean,
): void {
	const previousDepth = graph.nodesByDepth[depth - 1] ?? new Map<string, PolicyGraphNode>();
	const currentDepth = new Map<string, PolicyGraphNode>();
	graph.nodesByDepth[depth] = currentDepth;
	const anyPolicyInfo = certificatePolicies.get(OIDS.anyPolicy);
	const previousAnyPolicy = previousDepth.get(policyNodeKey(depth - 1, OIDS.anyPolicy));

	for (const policy of certificatePolicies.values()) {
		if (policy.policyIdentifier === OIDS.anyPolicy) {
			continue;
		}
		const matchingParents = collectParentsForExpectedPolicy(previousDepth, policy.policyIdentifier);
		if (matchingParents.length > 0) {
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				policy.policyIdentifier,
				policy.policyQualifiers,
				matchingParents,
				[policy.policyIdentifier],
			);
		}
	}

	if (previousAnyPolicy !== undefined) {
		const previousAnyPolicyKey = policyNodeKey(depth - 1, OIDS.anyPolicy);
		for (const policy of certificatePolicies.values()) {
			if (policy.policyIdentifier === OIDS.anyPolicy) {
				continue;
			}
			if (currentDepth.has(policyNodeKey(depth, policy.policyIdentifier))) {
				continue;
			}
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				policy.policyIdentifier,
				policy.policyQualifiers,
				[previousAnyPolicyKey],
				[policy.policyIdentifier],
			);
		}
	}

	if (anyPolicyInfo !== undefined && allowAnyPolicyExpansion) {
		for (const [validPolicy, parentKeys] of collectExpectedPolicyParents(previousDepth)) {
			if (currentDepth.has(policyNodeKey(depth, validPolicy))) {
				continue;
			}
			const expansionParents =
				validPolicy === OIDS.anyPolicy
					? previousAnyPolicy === undefined
						? []
						: [policyNodeKey(depth - 1, OIDS.anyPolicy)]
					: parentKeys;
			if (expansionParents.length === 0) {
				continue;
			}
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				validPolicy,
				anyPolicyInfo.policyQualifiers,
				expansionParents,
				[validPolicy],
			);
		}
	}

	prunePolicyGraph(graph, depth - 1);
}

function collectParentsForExpectedPolicy(
	nodes: ReadonlyMap<string, PolicyGraphNode>,
	policyIdentifier: string,
): string[] {
	const parents: string[] = [];
	for (const [key, node] of nodes) {
		if (node.expectedPolicySet.has(policyIdentifier)) {
			parents.push(key);
		}
	}
	return parents;
}

function collectExpectedPolicyParents(
	nodes: ReadonlyMap<string, PolicyGraphNode>,
): Map<string, string[]> {
	const parentsByPolicy = new Map<string, string[]>();
	for (const [key, node] of nodes) {
		for (const expectedPolicy of node.expectedPolicySet) {
			const parents = parentsByPolicy.get(expectedPolicy);
			if (parents === undefined) {
				parentsByPolicy.set(expectedPolicy, [key]);
				continue;
			}
			parents.push(key);
		}
	}
	return parentsByPolicy;
}

function addOrMergePolicyNode(
	graph: PolicyGraph,
	currentDepth: Map<string, PolicyGraphNode>,
	depth: number,
	validPolicy: string,
	qualifierSet: readonly PolicyQualifierInfo[] | undefined,
	parentKeys: readonly string[],
	expectedPolicySet: readonly string[],
): void {
	const key = policyNodeKey(depth, validPolicy);
	const existing = currentDepth.get(key);
	if (existing !== undefined) {
		for (const parentKey of parentKeys) {
			existing.parentKeys.add(parentKey);
			getPolicyGraphNode(graph, parentKey)?.childKeys.add(key);
		}
		for (const expectedPolicy of expectedPolicySet) {
			existing.expectedPolicySet.add(expectedPolicy);
		}
		if (existing.qualifierSet === undefined && qualifierSet !== undefined) {
			existing.qualifierSet = qualifierSet;
		}
		return;
	}
	const node = createPolicyGraphNode(
		depth,
		validPolicy,
		qualifierSet,
		expectedPolicySet,
		parentKeys,
	);
	currentDepth.set(key, node);
	for (const parentKey of parentKeys) {
		getPolicyGraphNode(graph, parentKey)?.childKeys.add(key);
	}
}

function getPolicyGraphNode(graph: PolicyGraph, key: string): PolicyGraphNode | undefined {
	const separator = key.indexOf(':');
	if (separator <= 0) {
		return undefined;
	}
	const depthString = key.slice(0, separator);
	const depth = Number.parseInt(depthString, 10);
	if (Number.isNaN(depth)) {
		return undefined;
	}
	return graph.nodesByDepth[depth]?.get(key);
}

function prunePolicyGraph(graph: PolicyGraph, maxDepth: number): void {
	for (let depth = maxDepth; depth >= 0; depth -= 1) {
		const nodes = graph.nodesByDepth[depth];
		if (nodes === undefined) {
			continue;
		}
		for (const key of [...nodes.keys()]) {
			const node = nodes.get(key);
			if (node === undefined || node.childKeys.size > 0) {
				continue;
			}
			deletePolicyGraphNode(graph, key);
		}
	}
}

function deletePolicyGraphNode(graph: PolicyGraph, key: string): void {
	const node = getPolicyGraphNode(graph, key);
	if (node === undefined) {
		return;
	}
	graph.nodesByDepth[node.depth]?.delete(key);
	for (const parentKey of node.parentKeys) {
		const parent = getPolicyGraphNode(graph, parentKey);
		if (parent === undefined) {
			continue;
		}
		parent.childKeys.delete(key);
		if (parent.childKeys.size === 0) {
			deletePolicyGraphNode(graph, parentKey);
		}
	}
}

function applyPolicyMappingsStep(
	graph: PolicyGraph,
	depth: number,
	mappings: readonly {
		readonly issuerDomainPolicy: string;
		readonly subjectDomainPolicy: string;
	}[],
	mappingAllowed: boolean,
): void {
	const currentDepth = graph.nodesByDepth[depth];
	if (currentDepth === undefined) {
		return;
	}
	const groupedMappings = new Map<string, string[]>();
	for (const mapping of mappings) {
		const subjectPolicies = groupedMappings.get(mapping.issuerDomainPolicy);
		if (subjectPolicies === undefined) {
			groupedMappings.set(mapping.issuerDomainPolicy, [mapping.subjectDomainPolicy]);
			continue;
		}
		subjectPolicies.push(mapping.subjectDomainPolicy);
	}
	const anyPolicyNode = currentDepth.get(policyNodeKey(depth, OIDS.anyPolicy));
	for (const [issuerDomainPolicy, subjectDomainPolicies] of groupedMappings) {
		const nodeKey = policyNodeKey(depth, issuerDomainPolicy);
		const node = currentDepth.get(nodeKey);
		if (mappingAllowed) {
			if (node !== undefined) {
				node.expectedPolicySet = new Set(subjectDomainPolicies);
				continue;
			}
			if (anyPolicyNode !== undefined) {
				addOrMergePolicyNode(
					graph,
					currentDepth,
					depth,
					issuerDomainPolicy,
					anyPolicyNode.qualifierSet,
					[...anyPolicyNode.parentKeys],
					subjectDomainPolicies,
				);
			}
			continue;
		}
		if (node !== undefined) {
			deletePolicyGraphNode(graph, nodeKey);
		}
	}
	prunePolicyGraph(graph, depth - 1);
}

function updatePolicyCounters(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
	isLeaf: boolean,
): void {
	if (isLeaf) {
		if (state.explicitPolicy > 0) {
			state.explicitPolicy -= 1;
		}
		if (certificate.policyConstraints?.requireExplicitPolicy === 0) {
			state.explicitPolicy = 0;
		}
		return;
	}
	if (!isSelfIssued(certificate)) {
		if (state.explicitPolicy > 0) {
			state.explicitPolicy -= 1;
		}
		if (state.inhibitPolicyMapping > 0) {
			state.inhibitPolicyMapping -= 1;
		}
		if (state.inhibitAnyPolicy > 0) {
			state.inhibitAnyPolicy -= 1;
		}
	}
	const policyConstraints = certificate.policyConstraints;
	if (
		policyConstraints?.requireExplicitPolicy !== undefined &&
		policyConstraints.requireExplicitPolicy < state.explicitPolicy
	) {
		state.explicitPolicy = policyConstraints.requireExplicitPolicy;
	}
	if (
		policyConstraints?.inhibitPolicyMapping !== undefined &&
		policyConstraints.inhibitPolicyMapping < state.inhibitPolicyMapping
	) {
		state.inhibitPolicyMapping = policyConstraints.inhibitPolicyMapping;
	}
	if (
		certificate.inhibitAnyPolicy !== undefined &&
		certificate.inhibitAnyPolicy.skipCerts < state.inhibitAnyPolicy
	) {
		state.inhibitAnyPolicy = certificate.inhibitAnyPolicy.skipCerts;
	}
}

// ---------------------------------------------------------------------------
// Private: name constraint validation (RFC 5280 §4.2.1.10 / §6.1)
// ---------------------------------------------------------------------------

/** Empty SEQUENCE DER hex — represents an empty subject DN. */
const EMPTY_SEQUENCE_HEX = '3000';

/**
 * Accumulated name constraint state during root-to-leaf traversal.
 * - `permittedLevels`: each entry is one CA's permittedSubtrees. A name
 *   must match at least one entry in *every* level (intersection semantics).
 * - `excluded`: flat list; a name must NOT match *any* entry.
 */
interface AccumulatedNameConstraints {
	readonly permittedLevels: readonly (readonly NameConstraintForm[])[];
	readonly excluded: readonly NameConstraintForm[];
}

/**
 * Walks the chain root-to-leaf, accumulating nameConstraints from CA
 * certificates and checking each non-self-issued certificate's names
 * against the accumulated constraints.
 *
 * RFC 5280 §6.1.3(b)–(c) for intermediates, §6.1.5(g) for the leaf.
 */

function checkNameConstraints(
	chain: readonly ParsedCertificate[],
	state: NameConstraintValidationState,
): ValidationCheckResult {
	let accumulated = seedInitialNameConstraints(state);

	// Seed constraints from the root (trust anchor). The root's own
	// names are not checked, but its nameConstraints apply to all
	// certificates below it in the chain.
	const root = chain[chain.length - 1];
	if (root?.nameConstraints !== undefined) {
		const unsupportedRoot = failOnUnsupportedNameConstraints(root, chain.length - 1);
		if (!unsupportedRoot.ok) {
			return unsupportedRoot;
		}
		accumulated = accumulateConstraints(accumulated, root.nameConstraints);
	}

	// Walk from just below root toward leaf.
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const current = chain[index];
		if (current === undefined) {
			continue;
		}

		// (b) If not self-issued, check names against accumulated constraints.
		// RFC 5280 §4.2.1.10: self-issued certificates are exempt UNLESS
		// they are the final certificate (leaf) in the path.
		if (!isSelfIssued(current) || index === 0) {
			const nameCheckResult = checkCertificateNames(current, accumulated, index);
			if (!nameCheckResult.ok) {
				return nameCheckResult;
			}
		}

		// (c) If this cert has nameConstraints, accumulate them.
		if (current.nameConstraints !== undefined) {
			const unsupportedCurrent = failOnUnsupportedNameConstraints(current, index);
			if (!unsupportedCurrent.ok) {
				return unsupportedCurrent;
			}
			accumulated = accumulateConstraints(accumulated, current.nameConstraints);
		}
	}

	return { ok: true };
}

function seedInitialNameConstraints(
	state: NameConstraintValidationState,
): AccumulatedNameConstraints {
	return {
		permittedLevels:
			state.initialPermittedSubtrees.length > 0 ? [state.initialPermittedSubtrees] : [],
		excluded: state.initialExcludedSubtrees,
	};
}

function accumulateConstraints(
	current: AccumulatedNameConstraints,
	constraints: NameConstraints<ParsedNameConstraintForm>,
): AccumulatedNameConstraints {
	const permittedLevels =
		constraints.permittedSubtrees !== undefined && constraints.permittedSubtrees.length > 0
			? [
					...current.permittedLevels,
					constraints.permittedSubtrees.flatMap((subtree) =>
						isSupportedNameConstraintForm(subtree.base) ? [subtree.base] : [],
					),
				]
			: current.permittedLevels;
	const excluded =
		constraints.excludedSubtrees !== undefined && constraints.excludedSubtrees.length > 0
			? [
					...current.excluded,
					...constraints.excludedSubtrees.flatMap((subtree) =>
						isSupportedNameConstraintForm(subtree.base) ? [subtree.base] : [],
					),
				]
			: current.excluded;
	return { permittedLevels, excluded };
}

function failOnUnsupportedNameConstraints(
	certificate: ParsedCertificate,
	index: number,
): { readonly ok: true } | VerifyChainFailure {
	if (certificate.nameConstraints === undefined) {
		return { ok: true };
	}
	const hasCriticalNameConstraintsExtension = certificate.extensions.some(
		(entry) => entry.oid === OIDS.nameConstraints && entry.critical,
	);
	if (!hasCriticalNameConstraintsExtension) {
		return { ok: true };
	}
	const unsupportedTypes = listUnsupportedNameConstraintTypes(certificate.nameConstraints);
	if (unsupportedTypes.length === 0) {
		return { ok: true };
	}
	return failure(
		'unsupported_name_constraints',
		'certificate contains unsupported critical name constraints',
		index,
		detail({
			subjectCommonName: certificate.subject.values.commonName,
			actual: unsupportedTypes.join(', '),
		}),
	);
}

function listUnsupportedNameConstraintTypes(
	constraints: NameConstraints<ParsedNameConstraintForm>,
): readonly string[] {
	const unsupportedTypes = new Set<string>();
	for (const subtree of constraints.permittedSubtrees ?? []) {
		if (!isSupportedNameConstraintForm(subtree.base)) {
			unsupportedTypes.add(subtree.base.type);
		}
	}
	for (const subtree of constraints.excludedSubtrees ?? []) {
		if (!isSupportedNameConstraintForm(subtree.base)) {
			unsupportedTypes.add(subtree.base.type);
		}
	}
	return [...unsupportedTypes];
}

function isSupportedNameConstraintForm(form: ParsedNameConstraintForm): form is NameConstraintForm {
	switch (form.type) {
		case 'dns':
		case 'email':
		case 'uri':
		case 'ip':
		case 'directoryName':
			return true;
		case 'otherName':
		case 'x400Address':
		case 'ediPartyName':
		case 'registeredID':
			return false;
		default: {
			const exhaustive: never = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
		}
	}
}

/**
 * Checks a certificate's subject DN and SANs against accumulated
 * name constraints. Returns a failure if any name violates constraints.
 */
function checkCertificateNames(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): ValidationCheckResult {
	// Check subject DN as directoryName (if non-empty).
	if (certificate.subject.derHex !== EMPTY_SEQUENCE_HEX) {
		const dnResult = isNamePermitted(
			{ type: 'directoryName', derHex: certificate.subject.derHex },
			accumulated,
		);
		if (!dnResult) {
			return failure(
				'name_constraints_violated',
				'subject distinguished name violates name constraints',
				index,
				detail({
					subjectCommonName: certificate.subject.values.commonName,
				}),
			);
		}
	}

	// Check each SAN.
	if (certificate.subjectAltNames !== undefined) {
		for (const san of certificate.subjectAltNames) {
			const checkable = sanToConstraintCheckable(san);
			if (checkable === undefined) {
				continue;
			}
			if (!isNamePermitted(checkable, accumulated)) {
				return failure(
					'name_constraints_violated',
					`SAN ${formatConstraintForm(checkable)} violates name constraints`,
					index,
					detail({
						subjectCommonName: certificate.subject.values.commonName,
						actual: formatConstraintForm(checkable),
					}),
				);
			}
		}
	}

	// RFC 5280 §4.2.1.10: When constraints are imposed on the rfc822Name
	// name form, but the certificate does not include a SAN email, the
	// constraint MUST be applied to the emailAddress attribute in the
	// subject DN.
	const hasEmailConstraints = accumulatedHasEmailConstraints(accumulated);
	if (hasEmailConstraints) {
		const hasSanEmail = certificate.subjectAltNames?.some((san) => san.type === 'email') ?? false;
		if (!hasSanEmail && certificate.subject.values.emailAddress !== undefined) {
			const emailForm: NameConstraintForm = {
				type: 'email',
				value: certificate.subject.values.emailAddress,
			};
			if (!isNamePermitted(emailForm, accumulated)) {
				return failure(
					'name_constraints_violated',
					`subject emailAddress ${certificate.subject.values.emailAddress} violates name constraints`,
					index,
					detail({
						subjectCommonName: certificate.subject.values.commonName,
						actual: certificate.subject.values.emailAddress,
					}),
				);
			}
		}
	}

	return { ok: true };
}

function accumulatedHasEmailConstraints(accumulated: AccumulatedNameConstraints): boolean {
	for (const level of accumulated.permittedLevels) {
		if (level.some((c) => c.type === 'email')) {
			return true;
		}
	}
	return accumulated.excluded.some((c) => c.type === 'email');
}

/**
 * Converts a SubjectAltName to a NameConstraintForm for checking.
 * Returns `undefined` for name forms that don't participate in
 * constraint checking (unknown tags).
 */
function sanToConstraintCheckable(
	san: import('./extensions.ts').SubjectAltName,
): NameConstraintForm | undefined {
	switch (san.type) {
		case 'dns':
			return { type: 'dns', value: san.value };
		case 'email':
			return { type: 'email', value: san.value };
		case 'uri':
			return { type: 'uri', value: san.value };
		case 'srv':
			return undefined;
		case 'ip':
			return {
				type: 'ip',
				addressBytes: parseIpAddressToBytes(san.value),
				maskBytes: allOnesMaskForIpAddress(san.value),
			};
		case 'directoryName':
			return { type: 'directoryName', derHex: san.derHex };
		case 'unknown':
			return undefined;
		default: {
			const exhaustive: never = san;
			throw new Error(`Unhandled SubjectAltName type: ${String(exhaustive)}`);
		}
	}
}

/**
 * Checks whether a name is permitted by the accumulated constraints.
 * A name is permitted if:
 * 1. It does NOT match any excluded constraint, AND
 * 2. For every permitted level that contains constraints of the same
 *    name form, it matches at least one.
 */
function isNamePermitted(
	name: NameConstraintForm,
	accumulated: AccumulatedNameConstraints,
): boolean {
	// Check excluded — if any match, reject.
	for (const constraint of accumulated.excluded) {
		if (nameMatchesConstraint(name, constraint)) {
			return false;
		}
	}
	// Check permitted — for each level with relevant constraints,
	// the name must match at least one.
	for (const level of accumulated.permittedLevels) {
		const relevant = level.filter((constraint) => constraint.type === name.type);
		if (relevant.length === 0) {
			continue;
		}
		if (!relevant.some((constraint) => nameMatchesConstraint(name, constraint))) {
			return false;
		}
	}
	return true;
}

function nameMatchesConstraint(name: NameConstraintForm, constraint: NameConstraintForm): boolean {
	if (name.type === 'dns' && constraint.type === 'dns') {
		return matchesDnsConstraint(name.value, constraint.value);
	}
	if (name.type === 'email' && constraint.type === 'email') {
		return matchesEmailConstraint(name.value, constraint.value);
	}
	if (name.type === 'uri' && constraint.type === 'uri') {
		return matchesUriConstraint(name.value, constraint.value);
	}
	if (name.type === 'ip' && constraint.type === 'ip') {
		return matchesIpConstraint(name.addressBytes, constraint.addressBytes, constraint.maskBytes);
	}
	if (name.type === 'directoryName' && constraint.type === 'directoryName') {
		return matchesDnConstraint(name.derHex, constraint.derHex);
	}
	return false;
}

/**
 * RFC 5280 §4.2.1.10: DNS name constraint matching.
 * Constraint "example.com" matches "example.com" and any subdomain.
 * Constraint ".example.com" matches only subdomains, not "example.com" itself.
 */
function matchesDnsConstraint(name: string, constraint: string): boolean {
	const lowerName = name.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.length === 0) {
		return true;
	}
	if (lowerConstraint.startsWith('.')) {
		return lowerName.endsWith(lowerConstraint);
	}
	return lowerName === lowerConstraint || lowerName.endsWith(`.${lowerConstraint}`);
}

/**
 * RFC 5280 §4.2.1.10: Email constraint matching.
 * - "user@example.com" matches only that exact address.
 * - "example.com" matches any address @example.com.
 * - ".example.com" matches any address @subdomain.example.com.
 */
function matchesEmailConstraint(name: string, constraint: string): boolean {
	const lowerName = name.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.includes('@')) {
		return lowerName === lowerConstraint;
	}
	const atIndex = lowerName.indexOf('@');
	if (atIndex < 0) {
		return false;
	}
	const host = lowerName.slice(atIndex + 1);
	if (lowerConstraint.startsWith('.')) {
		return host.endsWith(lowerConstraint);
	}
	return host === lowerConstraint;
}

/**
 * RFC 5280 §4.2.1.10: URI constraint matching.
 * Applied to the host part of the URI.
 * - Constraint ".example.com" matches subdomains only.
 * - Constraint "example.com" matches ONLY that exact host (no subdomain
 *   expansion, unlike DNS constraints).
 */
function matchesUriConstraint(uri: string, constraint: string): boolean {
	const host = extractUriHost(uri);
	if (host === undefined) {
		return false;
	}
	const lowerHost = host.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.length === 0) {
		return true;
	}
	if (lowerConstraint.startsWith('.')) {
		return lowerHost.endsWith(lowerConstraint);
	}
	// Non-period constraint: exact host match only (RFC 5280 §4.2.1.10).
	return lowerHost === lowerConstraint;
}

function extractUriHost(uri: string): string | undefined {
	const schemeEnd = uri.indexOf('://');
	if (schemeEnd < 0) {
		return undefined;
	}
	const afterScheme = uri.slice(schemeEnd + 3);
	const atSign = afterScheme.indexOf('@');
	const hostStart = atSign >= 0 ? atSign + 1 : 0;
	const rest = afterScheme.slice(hostStart);
	const pathStart = rest.indexOf('/');
	const portStart = rest.indexOf(':');
	const end =
		pathStart >= 0
			? portStart >= 0
				? Math.min(pathStart, portStart)
				: pathStart
			: portStart >= 0
				? portStart
				: rest.length;
	return rest.slice(0, end);
}

/**
 * RFC 5280 §4.2.1.10: IP constraint matching.
 * (nameIP & mask) == (constraintIP & mask)
 */
function matchesIpConstraint(
	nameBytes: Uint8Array,
	constraintAddr: Uint8Array,
	constraintMask: Uint8Array,
): boolean {
	if (nameBytes.length !== constraintAddr.length) {
		return false;
	}
	for (let i = 0; i < nameBytes.length; i += 1) {
		const nameByte = nameBytes[i] ?? 0;
		const addrByte = constraintAddr[i] ?? 0;
		const maskByte = constraintMask[i] ?? 0;
		if ((nameByte & maskByte) !== (addrByte & maskByte)) {
			return false;
		}
	}
	return true;
}

/**
 * RFC 5280 §4.2.1.10: DirectoryName constraint matching.
 * The subject DN must equal or be subordinate to the constraint DN,
 * using RFC 5280 section 7.1 name comparison semantics.
 */
function matchesDnConstraint(subjectDerHex: string, constraintDerHex: string): boolean {
	const subjectName = parseDirectoryNameDerHex(subjectDerHex);
	const constraintName = parseDirectoryNameDerHex(constraintDerHex);
	if (subjectName === undefined || constraintName === undefined) {
		return false;
	}
	return isWithinDirectoryNameSubtree(subjectName, constraintName);
}

function parseDirectoryNameDerHex(derHex: string): ParsedName | undefined {
	if (!/^(?:[0-9a-fA-F]{2})+$/.test(derHex)) {
		return undefined;
	}
	try {
		const bytes = hexToBytes(derHex);
		const element = readElement(bytes);
		if (element.tag !== 0x30) {
			return undefined;
		}
		const rdns: ParsedRelativeDistinguishedName[] = [];
		const attributes: ParsedNameAttribute[] = [];
		const values: ParsedName['values'] = {};
		for (const setElement of childrenOf(bytes, element)) {
			const rdn = parseDirectoryNameRdn(bytes, setElement);
			if (rdn === undefined) {
				return undefined;
			}
			rdns.push(rdn);
			for (const attribute of rdn.attributes) {
				attributes.push(attribute);
				if (attribute.key !== undefined && values[attribute.key] === undefined) {
					values[attribute.key] = attribute.value;
				}
			}
		}
		return {
			derHex: toHex(bytes),
			rdns,
			attributes,
			values,
		};
	} catch {
		return undefined;
	}
}

function parseDirectoryNameRdn(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName | undefined {
	const attributes: ParsedNameAttribute[] = [];
	const values: ParsedName['values'] = {};
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oidElement = parts[0];
		const valueElement = parts[1];
		if (oidElement === undefined || valueElement === undefined) {
			return undefined;
		}
		const oid = decodeObjectIdentifier(requireElement(oidElement, 'directoryName OID').value);
		let fieldValue: string;
		try {
			fieldValue = decodeString(
				valueElement.tag,
				requireElement(valueElement, 'directoryName value').value,
			);
		} catch {
			return undefined;
		}
		const fieldKey = nameFieldKeyFromOid(oid);
		const attribute: ParsedNameAttribute =
			fieldKey !== undefined
				? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
				: { oid, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
}

function isWithinDirectoryNameSubtree(subject: ParsedName, constraint: ParsedName): boolean {
	if (constraint.rdns.length > subject.rdns.length) {
		return false;
	}
	for (let index = 0; index < constraint.rdns.length; index += 1) {
		const subjectRdn = subject.rdns[index];
		const constraintRdn = constraint.rdns[index];
		if (subjectRdn === undefined || constraintRdn === undefined) {
			return false;
		}
		if (!compareRelativeDistinguishedNames(subjectRdn, constraintRdn)) {
			return false;
		}
	}
	return true;
}

function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = new Array(right.attributes.length).fill(false);
	for (const leftAttribute of left.attributes) {
		let found = false;
		for (let index = 0; index < right.attributes.length; index += 1) {
			const rightAttribute = right.attributes[index];
			if (rightAttribute === undefined || matched[index]) {
				continue;
			}
			if (!compareNameAttributeValue(leftAttribute, rightAttribute)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

function compareNameAttributeValue(left: ParsedNameAttribute, right: ParsedNameAttribute): boolean {
	if (left.oid !== right.oid) {
		return false;
	}
	if (isDirectoryStringTag(left.valueTag) && isDirectoryStringTag(right.valueTag)) {
		const preparedLeft = prepareNameCompareString(left.value);
		const preparedRight = prepareNameCompareString(right.value);
		if (preparedLeft === undefined || preparedRight === undefined) {
			return false;
		}
		return preparedLeft === preparedRight;
	}
	return left.valueTag === right.valueTag && left.value === right.value;
}

function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

function prepareNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

function formatConstraintForm(form: NameConstraintForm): string {
	switch (form.type) {
		case 'dns':
			return `dns:${form.value}`;
		case 'email':
			return `email:${form.value}`;
		case 'uri':
			return `uri:${form.value}`;
		case 'ip':
			return `ip:${decodeIpAddress(form.addressBytes)}`;
		case 'directoryName':
			return `dn:${form.derHex.slice(0, 20)}...`;
		default: {
			const exhaustive = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
		}
	}
}
