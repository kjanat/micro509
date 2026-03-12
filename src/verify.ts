import type {
	ExtendedKeyUsage,
	GeneralSubtree,
	NameConstraintForm,
	NameConstraints,
} from './extensions.ts';
import { OIDS } from './oids.ts';
import type { ParsedCertificate, ParsedCertificateSigningRequest } from './parse.ts';
import {
	parseCertificateDer,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
} from './parse.ts';
import { splitPemBlocks } from './pem.ts';
import { verifySignedData } from './sig-verify.ts';
import type {
	InitialNameConstraintsInput,
	PolicyValidationInput,
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
	| 'self_signed_leaf_not_allowed'
	| 'unrecognized_critical_extension'
	| 'intermediate_eku_constraint'
	| 'policy_processing_not_implemented'
	| 'initial_name_constraints_not_implemented'
	| 'name_constraints_violated';

export interface VerifyFailureDetails {
	readonly subjectCommonName?: string;
	readonly issuerCommonName?: string;
	readonly expected?: string;
	readonly actual?: string;
	readonly chainCommonNames?: readonly string[];
}

export interface VerifyChainFailure {
	readonly ok: false;
	readonly code: VerifyErrorCode;
	readonly message: string;
	readonly index?: number;
	readonly details?: VerifyFailureDetails;
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

export type ValidateCandidatePathResult = { readonly ok: true } | VerifyChainFailure;

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
}

interface PolicyValidationState {
	readonly initialPolicySet: readonly string[] | 'any';
	readonly explicitPolicy: number;
	readonly inhibitPolicyMapping: number;
	readonly inhibitAnyPolicy: number;
}

interface NameConstraintValidationState {
	readonly initialPermittedSubtrees: readonly GeneralSubtree[];
	readonly initialExcludedSubtrees: readonly GeneralSubtree[];
}

interface ValidationState {
	readonly policy: PolicyValidationState;
	readonly nameConstraints: NameConstraintValidationState;
}

type ValidationStateResult =
	| { readonly ok: true; readonly value: ValidationState }
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

	const nameConstraintResult = checkNameConstraints(
		chain,
		validationStateResult.value.nameConstraints,
	);
	if (!nameConstraintResult.ok) {
		return nameConstraintResult;
	}

	return validateLeaf(leaf, input);
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

	return { ok: true, value: buildResult.value };
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
	const result = await verifyCertificateChain({
		...baseChainInput(input),
		...(input.serviceIdentity !== undefined && {
			serviceIdentity: input.serviceIdentity,
		}),
	});
	if (!result.ok) {
		return result;
	}
	return applyEkuCheck(result, 'serverAuth');
}

/**
 * Validates a certificate chain for TLS client use:
 * chain verification + `clientAuth` EKU (leaf + intermediate propagation).
 */
export async function validateForTlsClient(
	input: ValidateForTlsClientInput,
): Promise<VerifyChainResult> {
	const result = await verifyCertificateChain(baseChainInput(input));
	if (!result.ok) {
		return result;
	}
	return applyEkuCheck(result, 'clientAuth');
}

/**
 * Validates a certificate chain for code signing:
 * chain verification + `codeSigning` EKU (leaf + intermediate propagation).
 */
export async function validateForCodeSigning(
	input: ValidateForCodeSigningInput,
): Promise<VerifyChainResult> {
	const result = await verifyCertificateChain(baseChainInput(input));
	if (!result.ok) {
		return result;
	}
	return applyEkuCheck(result, 'codeSigning');
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
	return { ok: true };
}

function validateServiceIdentity(
	leaf: ParsedCertificate,
	serviceIdentity: VerifyServiceIdentityInput,
): ValidateCandidatePathResult {
	switch (serviceIdentity.type) {
		case 'dns': {
			const expected = serviceIdentity.value;
			const sans = leaf.subjectAltNames?.filter((entry) => entry.type === 'dns') ?? [];
			if (sans.length > 0) {
				if (!sans.some((entry) => matchesDnsName(entry.value, expected))) {
					return failure(
						'subject_alt_name_mismatch',
						'DNS name not present in SAN',
						0,
						detail({
							subjectCommonName: leaf.subject.values.commonName,
							expected,
							actual: sans.map((entry) => entry.value).join(','),
						}),
					);
				}
				return { ok: true };
			}
			if (serviceIdentity.allowCommonNameFallback === true) {
				const commonName = leaf.subject.values.commonName;
				if (commonName === undefined || !matchesDnsName(commonName, expected)) {
					return failure(
						'subject_alt_name_mismatch',
						'DNS name not present in SAN or CN',
						0,
						detail({
							subjectCommonName: commonName,
							expected,
							actual: commonName ?? '',
						}),
					);
				}
				return { ok: true };
			}
			return failure(
				'subject_alt_name_mismatch',
				'DNS name not present in SAN',
				0,
				detail({
					subjectCommonName: leaf.subject.values.commonName,
					expected,
					actual: '',
				}),
			);
		}
		case 'ip': {
			const expected = normalizeIpAddress(serviceIdentity.value);
			const sans = leaf.subjectAltNames?.filter((entry) => entry.type === 'ip') ?? [];
			if (!sans.some((entry) => normalizeIpAddress(entry.value) === expected)) {
				return failure(
					'subject_alt_name_mismatch',
					'IP address not present in SAN',
					0,
					detail({
						subjectCommonName: leaf.subject.values.commonName,
						expected,
						actual: sans.map((entry) => normalizeIpAddress(entry.value)).join(','),
					}),
				);
			}
			return { ok: true };
		}
		default: {
			throw new Error('unreachable service identity type');
		}
	}
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
	return Array.from(certificate.der, (value) => value.toString(16).padStart(2, '0')).join('');
}

function matchesDnsName(pattern: string, actual: string): boolean {
	const lowerPattern = pattern.toLowerCase();
	const lowerActual = actual.toLowerCase();
	if (!lowerPattern.includes('*')) {
		return lowerPattern === lowerActual;
	}
	if (!lowerPattern.startsWith('*.')) {
		return false;
	}
	const suffix = lowerPattern.slice(1);
	if (!lowerActual.endsWith(suffix)) {
		return false;
	}
	const prefix = lowerActual.slice(0, lowerActual.length - suffix.length);
	return prefix.length > 0 && !prefix.includes('.');
}

function normalizeIpAddress(value: string): string {
	if (!value.includes(':')) {
		return value;
	}
	return expandIpv6(value)
		.map((segment) => segment.toLowerCase())
		.join(':');
}

function expandIpv6(value: string): readonly string[] {
	const pieces = value.toLowerCase().split('::');
	const head = pieces[0] ?? '';
	const tail = pieces[1];
	if (tail !== undefined && value.indexOf('::') !== value.lastIndexOf('::')) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const headParts = head.length > 0 ? head.split(':') : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(':') : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const zeroes = Array.from({ length: missing }, () => '0');
	return (tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts]).map((segment) =>
		segment.padStart(4, '0'),
	);
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
	};
}

function buildValidationState(
	input: PolicyValidationInput & InitialNameConstraintsInput,
	chainLength: number,
): ValidationStateResult {
	const policy = normalizePolicyValidationState(input, chainLength);
	if (hasNonDefaultPolicyInputs(policy)) {
		return failure(
			'policy_processing_not_implemented',
			'policy validation inputs are not implemented yet',
			undefined,
			detail({ actual: describePolicyState(policy) }),
		);
	}
	const nameConstraints = normalizeNameConstraintValidationState(input);
	if (
		nameConstraints.initialPermittedSubtrees.length > 0 ||
		nameConstraints.initialExcludedSubtrees.length > 0
	) {
		return failure(
			'initial_name_constraints_not_implemented',
			'initial name constraint inputs are not implemented yet',
			undefined,
			detail({ actual: describeInitialNameConstraintState(nameConstraints) }),
		);
	}
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
	};
}

function normalizeNameConstraintValidationState(
	input: InitialNameConstraintsInput,
): NameConstraintValidationState {
	return {
		initialPermittedSubtrees: input.permittedSubtrees ?? [],
		initialExcludedSubtrees: input.excludedSubtrees ?? [],
	};
}

function hasNonDefaultPolicyInputs(policy: PolicyValidationState): boolean {
	return (
		policy.initialPolicySet !== 'any' ||
		policy.explicitPolicy === 0 ||
		policy.inhibitPolicyMapping === 0 ||
		policy.inhibitAnyPolicy === 0
	);
}

function describePolicyState(policy: PolicyValidationState): string {
	const enabled: string[] = [];
	if (policy.initialPolicySet !== 'any') {
		enabled.push(`initialPolicySet=${policy.initialPolicySet.join(',')}`);
	}
	if (policy.explicitPolicy === 0) {
		enabled.push('requireExplicitPolicy');
	}
	if (policy.inhibitPolicyMapping === 0) {
		enabled.push('inhibitPolicyMapping');
	}
	if (policy.inhibitAnyPolicy === 0) {
		enabled.push('inhibitAnyPolicy');
	}
	return enabled.join(', ');
}

function describeInitialNameConstraintState(state: NameConstraintValidationState): string {
	const enabled: string[] = [];
	if (state.initialPermittedSubtrees.length > 0) {
		enabled.push(`permittedSubtrees=${String(state.initialPermittedSubtrees.length)}`);
	}
	if (state.initialExcludedSubtrees.length > 0) {
		enabled.push(`excludedSubtrees=${String(state.initialExcludedSubtrees.length)}`);
	}
	return enabled.join(', ');
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
	_state: NameConstraintValidationState,
): ValidateCandidatePathResult {
	let accumulated: AccumulatedNameConstraints = {
		permittedLevels: [],
		excluded: [],
	};

	// Seed constraints from the root (trust anchor). The root's own
	// names are not checked, but its nameConstraints apply to all
	// certificates below it in the chain.
	const root = chain[chain.length - 1];
	if (root?.nameConstraints !== undefined) {
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
			accumulated = accumulateConstraints(accumulated, current.nameConstraints);
		}
	}

	return { ok: true };
}

function accumulateConstraints(
	current: AccumulatedNameConstraints,
	constraints: NameConstraints,
): AccumulatedNameConstraints {
	const permittedLevels =
		constraints.permittedSubtrees !== undefined && constraints.permittedSubtrees.length > 0
			? [...current.permittedLevels, constraints.permittedSubtrees.map((subtree) => subtree.base)]
			: current.permittedLevels;
	const excluded =
		constraints.excludedSubtrees !== undefined && constraints.excludedSubtrees.length > 0
			? [...current.excluded, ...constraints.excludedSubtrees.map((subtree) => subtree.base)]
			: current.excluded;
	return { permittedLevels, excluded };
}

/**
 * Checks a certificate's subject DN and SANs against accumulated
 * name constraints. Returns a failure if any name violates constraints.
 */
function checkCertificateNames(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): ValidateCandidatePathResult {
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
		case 'ip':
			return {
				type: 'ip',
				addressBytes: parseIpAddressToBytes(san.value),
				maskBytes: allOnesMask(san.value),
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
 * The subject DN must equal or be subordinate to the constraint DN.
 * Subordinate means the constraint's DER is a prefix of the subject's
 * RDN sequence.
 *
 * NOTE: This uses byte-exact DER comparison, which is stricter than
 * RFC 5280 §7.1 (which allows string normalization). This avoids
 * false positives but may produce false negatives for DNs with
 * different string encodings (e.g. PrintableString vs UTF8String).
 */
function matchesDnConstraint(subjectDerHex: string, constraintDerHex: string): boolean {
	if (subjectDerHex === constraintDerHex) {
		return true;
	}
	// Check if constraint is a prefix: the subject's RDN sequence
	// starts with all RDNs from the constraint.
	// DER SEQUENCE: tag(0x30) + length + content
	// We compare the content (RDN SET elements) as a prefix.
	const subjectContent = extractSequenceContent(subjectDerHex);
	const constraintContent = extractSequenceContent(constraintDerHex);
	if (subjectContent === undefined || constraintContent === undefined) {
		return false;
	}
	return subjectContent.startsWith(constraintContent);
}

function extractSequenceContent(derHex: string): string | undefined {
	if (derHex.length < 4) {
		return undefined;
	}
	// Tag must be 0x30 (SEQUENCE)
	if (derHex.slice(0, 2) !== '30') {
		return undefined;
	}
	const firstLengthByte = Number.parseInt(derHex.slice(2, 4), 16);
	if (Number.isNaN(firstLengthByte)) {
		return undefined;
	}
	if (firstLengthByte < 128) {
		return derHex.slice(4);
	}
	const lengthOctets = firstLengthByte & 0x7f;
	return derHex.slice(4 + lengthOctets * 2);
}

function parseIpAddressToBytes(value: string): Uint8Array {
	if (value.includes(':')) {
		return parseIpv6ToBytes(value);
	}
	const segments = value.split('.');
	if (segments.length !== 4) {
		throw new Error(`Invalid IPv4 address: ${value}`);
	}
	return Uint8Array.from(
		segments.map((segment) => {
			const parsed = Number(segment);
			if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
				throw new Error(`Invalid IPv4 address: ${value}`);
			}
			return parsed;
		}),
	);
}

function parseIpv6ToBytes(value: string): Uint8Array {
	const expanded = expandIpv6(value);
	const bytes = new Uint8Array(16);
	expanded.forEach((segment, index) => {
		const parsed = Number.parseInt(segment, 16);
		bytes[index * 2] = parsed >> 8;
		bytes[index * 2 + 1] = parsed & 0xff;
	});
	return bytes;
}

function allOnesMask(ipValue: string): Uint8Array {
	const length = ipValue.includes(':') ? 16 : 4;
	const mask = new Uint8Array(length);
	mask.fill(0xff);
	return mask;
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
			return `ip:${formatIpBytes(form.addressBytes)}`;
		case 'directoryName':
			return `dn:${form.derHex.slice(0, 20)}...`;
		default: {
			const exhaustive = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
		}
	}
}

function formatIpBytes(bytes: Uint8Array): string {
	if (bytes.length === 4) {
		return Array.from(bytes, (value) => String(value)).join('.');
	}
	const groups: string[] = [];
	for (let index = 0; index < bytes.length; index += 2) {
		const left = bytes[index] ?? 0;
		const right = bytes[index + 1] ?? 0;
		groups.push(((left << 8) | right).toString(16));
	}
	return groups.join(':');
}
