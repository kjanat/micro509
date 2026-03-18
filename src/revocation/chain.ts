/**
 * Chain-level revocation orchestration.
 *
 * Evaluates CRL and OCSP evidence for an entire validated certificate chain,
 * implementing the revocation checking portion of RFC 5280 §6.3.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-6.3 | RFC 5280 §6.3 CRL Validation}
 * @module
 */

import type { ParsedCertificate } from '#micro509/x509/parse.ts';
import { parseCertificateFromSource } from '#micro509/x509/parse.ts';
import {
	checkCertificateRevocationAgainstCrl,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	type CrlSource,
	type ParsedCertificateRevocationList,
	type RevocationReason,
} from './crl.ts';

// ---------------------------------------------------------------------------
// Input Types
// ---------------------------------------------------------------------------

/**
 * Certificate in any supported format.
 *
 * Accepts PEM string, DER bytes, or an already-parsed {@linkcode ParsedCertificate}.
 * Used for {@linkcode CheckChainRevocationInput.extraCertificates}.
 */
export type CertificateSource = string | Uint8Array | ParsedCertificate;

/**
 * OCSP response in any supported format.
 *
 * Accepts PEM string or DER bytes. Reserved for future OCSP support in
 * {@linkcode CheckChainRevocationInput.ocspResponses}.
 */
export type OcspResponseSource = string | Uint8Array;

/**
 * Revocation checking policy for {@linkcode checkChainRevocation}.
 *
 * Controls how indeterminate results (missing evidence, expired CRLs) affect
 * the final {@linkcode CheckChainRevocationValue.decision | decision}.
 */
export interface RevocationPolicy {
	/**
	 * How to handle indeterminate status.
	 *
	 * - `'soft-fail'`: indeterminate certificates are allowed (default)
	 * - `'hard-fail'`: indeterminate certificates cause denial
	 */
	readonly mode?: 'soft-fail' | 'hard-fail';
	/**
	 * Evidence preference when multiple sources are available.
	 *
	 * - `'best-available'`: use whichever evidence is freshest (default)
	 * - `'ocsp'`: prefer OCSP over CRL
	 * - `'crl'`: prefer CRL over OCSP
	 */
	readonly prefer?: 'ocsp' | 'crl' | 'best-available';
}

/** Input for {@linkcode checkChainRevocation}. */
export interface CheckChainRevocationInput {
	/** Validated certificate chain (leaf first, root last). */
	readonly chain: readonly ParsedCertificate[];
	/** CRLs to evaluate. */
	readonly crls?: readonly CrlSource[];
	/** OCSP responses to evaluate. */
	readonly ocspResponses?: readonly OcspResponseSource[];
	/** Extra certs for indirect CRL issuers / delegated OCSP responders. */
	readonly extraCertificates?: readonly CertificateSource[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Revocation policy. */
	readonly policy?: RevocationPolicy;
}

// ---------------------------------------------------------------------------
// Output Types
// ---------------------------------------------------------------------------

/**
 * Granular reasons why revocation status could not be determined.
 *
 * Returned in {@linkcode CertificateRevocationStatus.indeterminateReasons} when
 * `status` is `'indeterminate'`. Grouped by category:
 *
 * - **Evidence not found**: `no_applicable_crl`, `no_applicable_ocsp`
 * - **Scope mismatch**: `distribution_point_mismatch`, `issuer_name_mismatch`,
 *   `reason_scope_mismatch`, `indirect_crl_scope_mismatch`, `reason_coverage_incomplete`
 * - **Signer trust**: `crl_signer_not_found`, `crl_signer_not_authorized`,
 *   `crl_signer_revoked`, `crl_signer_indeterminate`, and OCSP equivalents
 * - **Freshness**: `crl_expired`, `ocsp_response_expired`
 */
export type RevocationIndeterminateReason =
	// Evidence not found
	| 'no_applicable_crl'
	| 'no_applicable_ocsp'
	// Scope issues
	| 'distribution_point_mismatch'
	| 'issuer_name_mismatch'
	| 'reason_scope_mismatch'
	| 'indirect_crl_scope_mismatch'
	| 'reason_coverage_incomplete'
	// Signer trust issues
	| 'crl_signer_not_found'
	| 'crl_signer_not_authorized'
	| 'crl_signer_revoked'
	| 'crl_signer_indeterminate'
	| 'ocsp_responder_not_found'
	| 'ocsp_responder_not_authorized'
	| 'ocsp_responder_revoked'
	| 'ocsp_responder_indeterminate'
	// Freshness
	| 'crl_expired'
	| 'ocsp_response_expired'
	// OCSP specific
	| 'ocsp_status_unknown';

/**
 * Identifies the source of revocation evidence.
 *
 * Included in {@linkcode CertificateRevocationStatus.source} when status is
 * `'good'` or `'revoked'` to indicate which CRL or OCSP response provided the answer.
 */
export interface RevocationSource {
	/** Whether evidence came from a CRL or OCSP response. */
	readonly type: 'crl' | 'ocsp';
	/** Certificate that signed the evidence (CRL issuer or OCSP responder). */
	readonly signerCertificate?: ParsedCertificate;
	/** Identifier for debugging (e.g., CRL issuer DN or OCSP responder URL). */
	readonly evidenceIdentifier?: string;
}

/**
 * Revocation evaluation result for a single certificate.
 *
 * One entry per certificate in {@linkcode CheckChainRevocationValue.certificates}.
 * The trust anchor is excluded (never checked for revocation).
 */
export interface CertificateRevocationStatus {
	/** The certificate that was evaluated. */
	readonly certificate: ParsedCertificate;
	/**
	 * Revocation status determination.
	 *
	 * - `'good'`: evidence confirms certificate is not revoked
	 * - `'revoked'`: evidence confirms certificate is revoked
	 * - `'indeterminate'`: could not determine status (see {@linkcode indeterminateReasons})
	 */
	readonly status: 'good' | 'revoked' | 'indeterminate';
	/** Evidence source when status is `'good'` or `'revoked'`. */
	readonly source?: RevocationSource;
	/** Why status could not be determined. Present when `status` is `'indeterminate'`. */
	readonly indeterminateReasons?: readonly RevocationIndeterminateReason[];
	/** Revocation details. Present when `status` is `'revoked'`. */
	readonly revocationInfo?: {
		/** When the certificate was revoked. */
		readonly date: Date;
		/** RFC 5280 CRLReason code, if provided by the CRL/OCSP response. */
		readonly reason?: RevocationReason;
	};
}

/**
 * Errors encountered while processing revocation evidence.
 *
 * Distinct from {@linkcode RevocationIndeterminateReason}: execution errors are
 * code failures (malformed CRL, unsupported extension) rather than evaluation
 * outcomes (CRL doesn't cover this certificate).
 *
 * Collected in {@linkcode CheckChainRevocationValue.executionErrors}.
 */
export interface RevocationExecutionError {
	/** Error category. */
	readonly kind: 'parse_error' | 'unsupported_extension' | 'internal_error';
	/** Human-readable error description. */
	readonly message: string;
	/** Which evidence caused the error (e.g., CRL issuer DN). */
	readonly evidenceIdentifier?: string;
}

/**
 * Detailed revocation check results.
 *
 * Returned as {@linkcode CheckChainRevocationResult.value} from
 * {@linkcode checkChainRevocation}. Contains both the policy decision and
 * detailed per-certificate findings for debugging.
 */
export interface CheckChainRevocationValue {
	/**
	 * Final policy decision based on {@linkcode RevocationPolicy}.
	 *
	 * - `'allow'`: chain passes revocation check
	 * - `'deny'`: chain fails (revoked certificate or hard-fail on indeterminate)
	 */
	readonly decision: 'allow' | 'deny';
	/** Quick-access summary of problematic certificates. */
	readonly summary: {
		/** Certificates confirmed as revoked. */
		readonly revokedCertificates: readonly ParsedCertificate[];
		/** Certificates whose status could not be determined. */
		readonly indeterminateCertificates: readonly ParsedCertificate[];
	};
	/** Per-certificate evaluation results. See {@linkcode CertificateRevocationStatus}. */
	readonly certificates: readonly CertificateRevocationStatus[];
	/** Evidence that could not be processed. See {@linkcode RevocationExecutionError}. */
	readonly executionErrors?: readonly RevocationExecutionError[];
}

/** Result type for {@linkcode checkChainRevocation}. */
export type CheckChainRevocationResult = {
	readonly ok: true;
	readonly value: CheckChainRevocationValue;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parses a CRL from various source formats.
 */
function parseCrlFromSource(source: CrlSource): ParsedCertificateRevocationList {
	if (typeof source === 'object' && 'issuer' in source) {
		return source;
	}
	if (typeof source === 'string') {
		return parseCertificateRevocationListPem(source);
	}
	return parseCertificateRevocationListDer(source);
}

/**
 * Parses a certificate from various source formats, returning undefined on failure.
 */
function parseCertificateSafe(source: CertificateSource): ParsedCertificate | undefined {
	try {
		return parseCertificateFromSource(source);
	} catch {
		return undefined;
	}
}

/**
 * Compares two certificates by DER bytes for identity.
 * Reference equality fails when same cert is parsed from different sources.
 */
function sameCertificate(a: ParsedCertificate, b: ParsedCertificate): boolean {
	if (a.der.length !== b.der.length) return false;
	for (let i = 0; i < a.der.length; i++) {
		if (a.der[i] !== b.der[i]) return false;
	}
	return true;
}

/**
 * Searches for a certificate that could have signed the given CRL.
 * Matches by AKI/SKI or issuer/subject DN.
 */
function findIndirectCrlIssuer(
	crl: ParsedCertificateRevocationList,
	extraCertificates: readonly CertificateSource[],
	chain: readonly ParsedCertificate[],
): ParsedCertificate | undefined {
	// Combine extra certs with chain certs for searching
	// Chain certs are already parsed; extra certs may need parsing
	const parsedExtras: ParsedCertificate[] = [];
	for (const source of extraCertificates) {
		const parsed = parseCertificateSafe(source);
		if (parsed !== undefined) {
			parsedExtras.push(parsed);
		}
	}

	const candidates = [...parsedExtras, ...chain];

	// First pass: prefer AKI/SKI match (more specific)
	if (crl.authorityKeyIdentifier !== undefined) {
		for (const candidate of candidates) {
			if (
				candidate.subjectKeyIdentifier !== undefined &&
				normalizeHex(crl.authorityKeyIdentifier) === normalizeHex(candidate.subjectKeyIdentifier)
			) {
				return candidate;
			}
		}
	}

	// Second pass: fall back to DN match
	for (const candidate of candidates) {
		if (crl.issuer.derHex === candidate.subject.derHex) {
			return candidate;
		}
	}

	return undefined;
}

/** Lowercases a hex string for bytewise comparison. */
function normalizeHex(value: string): string {
	return value.toLowerCase();
}

// ---------------------------------------------------------------------------
// CRL Signer Validation (RFC 5280 §6.3.3)
// ---------------------------------------------------------------------------

/**
 * State machine for CRL signer validation with memoization.
 * - `visiting`: Currently being checked (cycle detection)
 * - `resolved-valid`: Signer is not revoked
 * - `resolved-revoked`: Signer is revoked
 * - `resolved-indeterminate`: Can't determine signer status
 */
type SignerValidationState =
	| 'visiting'
	| 'resolved-valid'
	| 'resolved-revoked'
	| 'resolved-indeterminate';

/** Context for CRL signer validation with memoization cache. */
interface SignerValidationContext {
	readonly cache: Map<string, SignerValidationState>;
	readonly chain: readonly ParsedCertificate[];
	readonly crls: readonly CrlSource[];
	readonly extraCertificates: readonly CertificateSource[];
	readonly at: Date;
}

/**
 * Builds a unique cache key for a certificate.
 * Uses issuer DN + serial number which uniquely identifies a cert.
 */
function certCacheKey(cert: ParsedCertificate): string {
	return `${cert.issuer.derHex}:${cert.serialNumberHex}`;
}

/**
 * Validates that a CRL signer certificate is not revoked.
 * Uses memoization to avoid redundant checks and detect cycles.
 */
async function validateCrlSigner(
	signer: ParsedCertificate,
	ctx: SignerValidationContext,
): Promise<SignerValidationState> {
	// Use issuer+serial as cache key (unique per certificate)
	const key = certCacheKey(signer);
	const cached = ctx.cache.get(key);

	// Cycle detection: if we're already visiting this signer, it's indeterminate
	if (cached === 'visiting') {
		return 'resolved-indeterminate';
	}

	// Return cached result if already resolved
	if (cached !== undefined) {
		return cached;
	}

	// Mark as visiting before recursive checks
	ctx.cache.set(key, 'visiting');

	// Trust anchor (last in chain) is trusted by definition
	const trustAnchor = ctx.chain[ctx.chain.length - 1];
	if (trustAnchor !== undefined && sameCertificate(signer, trustAnchor)) {
		ctx.cache.set(key, 'resolved-valid');
		return 'resolved-valid';
	}

	// If signer is in the validated chain, it's trusted
	// (Chain was already validated before revocation checking)
	const isInChain = ctx.chain.some((c) => sameCertificate(c, signer));
	if (isInChain) {
		ctx.cache.set(key, 'resolved-valid');
		return 'resolved-valid';
	}

	// Signer is not in chain — need to check its revocation status
	// Find signer's issuer to perform revocation check
	const signerIssuer = findSignerIssuer(signer, ctx);
	if (signerIssuer === undefined) {
		ctx.cache.set(key, 'resolved-indeterminate');
		return 'resolved-indeterminate';
	}

	// Check signer's revocation status (recursive)
	const signerRevocation = await checkSignerRevocation(signer, signerIssuer, ctx);
	ctx.cache.set(key, signerRevocation);
	return signerRevocation;
}

/**
 * Finds the issuer certificate for a CRL signer.
 * Searches the chain and extraCertificates by AKI/SKI or DN matching.
 */
function findSignerIssuer(
	signer: ParsedCertificate,
	ctx: SignerValidationContext,
): ParsedCertificate | undefined {
	// Parse extra certificates
	const parsedExtras: ParsedCertificate[] = [];
	for (const source of ctx.extraCertificates) {
		const parsed = parseCertificateSafe(source);
		if (parsed !== undefined) {
			parsedExtras.push(parsed);
		}
	}

	const candidates = [...ctx.chain, ...parsedExtras];

	for (const candidate of candidates) {
		// Match by AKI → SKI (preferred, more specific)
		if (
			signer.authorityKeyIdentifier !== undefined &&
			candidate.subjectKeyIdentifier !== undefined &&
			normalizeHex(signer.authorityKeyIdentifier) ===
				normalizeHex(candidate.subjectKeyIdentifier)
		) {
			return candidate;
		}

		// Match by issuer DN → subject DN
		if (signer.issuer.derHex === candidate.subject.derHex) {
			return candidate;
		}
	}

	return undefined;
}

/**
 * Checks if a CRL signer certificate is revoked by examining available CRLs.
 * Recursively validates the CRL signer of any CRL used to check revocation.
 */
async function checkSignerRevocation(
	signer: ParsedCertificate,
	issuer: ParsedCertificate,
	ctx: SignerValidationContext,
): Promise<SignerValidationState> {
	// If the signer's issuer is in the validated chain, the signer is trusted
	// by virtue of being issued by a trusted CA. We only need to check if
	// it's explicitly revoked, not prove "good" status.
	const issuerInChain = ctx.chain.some((c) => sameCertificate(c, issuer));

	// Try each CRL to check signer's revocation
	for (const crlSource of ctx.crls) {
		let crl: ParsedCertificateRevocationList;
		try {
			crl = parseCrlFromSource(crlSource);
		} catch {
			continue;
		}

		// Check if this CRL can provide revocation info for the signer
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: signer,
			issuerCertificate: issuer,
			crl,
			at: ctx.at,
		});

		if (result.ok) {
			if (result.value.status === 'revoked') {
				return 'resolved-revoked';
			}
			if (result.value.status === 'good') {
				// Before accepting this result, validate the CRL's signer
				// The CRL's signer is the issuer we just used
				const crlSignerStatus = await validateCrlSigner(issuer, ctx);
				if (crlSignerStatus === 'resolved-valid') {
					return 'resolved-valid';
				}
				// If CRL signer is revoked or indeterminate, can't trust this result
			}
		}
	}

	// If the signer's issuer is in the chain and we found no revocation,
	// trust the signer (issued by trusted CA, no evidence of revocation)
	if (issuerInChain) {
		return 'resolved-valid';
	}

	return 'resolved-indeterminate';
}

/** Builds a CertificateRevocationStatus for a CRL check result. */
function buildCrlStatus(
	cert: ParsedCertificate,
	signer: ParsedCertificate,
	status: 'good' | 'revoked',
	revocationDate?: Date,
	reasonCode?: RevocationReason,
): CertificateRevocationStatus {
	if (status === 'revoked' && revocationDate !== undefined) {
		return {
			certificate: cert,
			status: 'revoked',
			source: { type: 'crl', signerCertificate: signer },
			revocationInfo: {
				date: revocationDate,
				...(reasonCode !== undefined ? { reason: reasonCode } : {}),
			},
		};
	}
	return {
		certificate: cert,
		status: 'good',
		source: { type: 'crl', signerCertificate: signer },
	};
}

/**
 * Evaluates revocation status for a single certificate using available CRLs.
 * Returns both status and any execution errors encountered.
 *
 * Tries the chain issuer first; if that fails, searches extraCertificates
 * and chain for an indirect CRL issuer that matches the CRL's AKI or issuer DN.
 *
 * Also validates that CRL signers are not revoked (RFC 5280 §6.3.3).
 */
// RFC 5280 ReasonFlags — all possible revocation reasons that CRLs can cover.
const ALL_REASON_FLAGS: readonly string[] = [
	'keyCompromise',
	'cACompromise',
	'affiliationChanged',
	'superseded',
	'cessationOfOperation',
	'certificateHold',
	'privilegeWithdrawn',
	'aACompromise',
];

async function evaluateCertificateRevocation(
	cert: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
): Promise<{
	status: CertificateRevocationStatus;
	executionErrors: readonly RevocationExecutionError[];
}> {
	const { crls = [], extraCertificates = [], chain = [], at = new Date() } = input;
	const executionErrors: RevocationExecutionError[] = [];
	let sawCrlSignerRevoked = false;
	let sawCrlSignerIndeterminate = false;
	let sawGood = false;
	let lastGoodSigner: ParsedCertificate | undefined;
	const coveredReasons = new Set<string>();

	// Parse all CRLs and separate base CRLs from delta CRLs
	const parsedCrls: ParsedCertificateRevocationList[] = [];
	for (const crlSource of crls) {
		try {
			parsedCrls.push(parseCrlFromSource(crlSource));
		} catch (e) {
			executionErrors.push({
				kind: 'parse_error',
				message: e instanceof Error ? e.message : 'CRL parse failed',
			});
		}
	}

	const baseCrls = parsedCrls.filter((crl) => crl.baseCrlNumber === undefined);
	const deltaCrls = parsedCrls.filter((crl) => crl.baseCrlNumber !== undefined);

	// Helper to check CRL with given issuer and optional delta
	const checkWithIssuer = async (
		crl: ParsedCertificateRevocationList,
		deltaCrl: ParsedCertificateRevocationList | undefined,
		crlIssuer: ParsedCertificate,
	) => {
		return checkCertificateRevocationAgainstCrl({
			certificate: cert,
			issuerCertificate: crlIssuer,
			crl,
			...(deltaCrl !== undefined ? { deltaCrl } : {}),
			at,
		});
	};

	// Process base CRLs (optionally paired with delta CRLs)
	for (const baseCrl of baseCrls) {
		// Find applicable delta CRL for this base CRL (if any)
		// Delta CRL applies if it has the same issuer and crlNumber matches baseCrlNumber
		const applicableDelta = deltaCrls.find(
			(d) =>
				d.issuer.derHex === baseCrl.issuer.derHex &&
				d.baseCrlNumber !== undefined &&
				baseCrl.crlNumber !== undefined &&
				BigInt(d.baseCrlNumber) <= BigInt(baseCrl.crlNumber),
		);

		// Try chain issuer first
		let result = await checkWithIssuer(baseCrl, applicableDelta, issuer);
		let effectiveSigner = issuer;

		// Chain issuer failed — try to find indirect CRL issuer
		if (!result.ok) {
			const indirectIssuer = findIndirectCrlIssuer(baseCrl, extraCertificates, chain);
			if (indirectIssuer !== undefined && !sameCertificate(indirectIssuer, issuer)) {
				result = await checkWithIssuer(baseCrl, applicableDelta, indirectIssuer);
				effectiveSigner = indirectIssuer;
			}
		}

		if (!result.ok) {
			continue; // CRL doesn't apply to this certificate
		}

		// Validate CRL signer is not revoked before accepting result
		const signerStatus = await validateCrlSigner(effectiveSigner, signerCtx);
		if (signerStatus === 'resolved-revoked') {
			sawCrlSignerRevoked = true;
			continue; // CRL signer revoked — can't trust this CRL
		}
		if (signerStatus === 'resolved-indeterminate') {
			sawCrlSignerIndeterminate = true;
			continue; // CRL signer status unknown — try other CRLs
		}

		// CRL is valid — check result
		if (result.value.status === 'revoked') {
			// Immediately return revoked status
			return {
				status: buildCrlStatus(
					cert,
					effectiveSigner,
					'revoked',
					result.value.revocationDate,
					result.value.reasonCode,
				),
				executionErrors,
			};
		}

		// Status is 'good' — track which reasons this CRL covers
		sawGood = true;
		lastGoodSigner = effectiveSigner;
		const crlReasons = baseCrl.issuingDistributionPoint?.onlySomeReasons?.flags;
		if (crlReasons === undefined) {
			// CRL covers all reasons
			for (const reason of ALL_REASON_FLAGS) {
				coveredReasons.add(reason);
			}
		} else {
			// CRL only covers specific reasons
			for (const reason of crlReasons) {
				coveredReasons.add(reason);
			}
		}
	}

	// Return 'good' only if we saw at least one good result AND all reasons are covered
	if (sawGood) {
		const allReasonsCovered = ALL_REASON_FLAGS.every((r) => coveredReasons.has(r));
		if (allReasonsCovered) {
			return {
				status: {
					certificate: cert,
					status: 'good',
					source:
						lastGoodSigner !== undefined
							? { type: 'crl', signerCertificate: lastGoodSigner }
							: undefined,
				},
				executionErrors,
			};
		}
		// Not all reasons covered — indeterminate
		return {
			status: {
				certificate: cert,
				status: 'indeterminate',
				indeterminateReasons: ['reason_coverage_incomplete'],
			},
			executionErrors,
		};
	}

	// No applicable CRL found — determine most appropriate indeterminate reason
	const reasons: RevocationIndeterminateReason[] = [];
	if (sawCrlSignerRevoked) {
		reasons.push('crl_signer_revoked');
	} else if (sawCrlSignerIndeterminate) {
		reasons.push('crl_signer_indeterminate');
	} else if (crls.length === 0) {
		reasons.push('no_applicable_crl', 'no_applicable_ocsp');
	} else {
		reasons.push('no_applicable_crl');
	}

	return {
		status: {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons: reasons,
		},
		executionErrors,
	};
}

// ---------------------------------------------------------------------------
// Function
// ---------------------------------------------------------------------------

/**
 * Checks revocation status for all certificates in a validated chain.
 *
 * Evaluates CRL and OCSP evidence against each certificate (except the trust
 * anchor), applies the revocation policy, and returns a unified decision.
 *
 * @example
 * ```ts
 * const result = await checkChainRevocation({
 *   chain: validatedChain,
 *   crls: [crl1, crl2],
 *   policy: { mode: 'hard-fail' },
 * });
 * if (result.value.decision === 'deny') {
 *   console.log('Revocation check failed');
 * }
 * ```
 */
export async function checkChainRevocation(
	input: CheckChainRevocationInput,
): Promise<CheckChainRevocationResult> {
	const { chain, policy, crls = [], extraCertificates = [], at = new Date() } = input;
	const mode = policy?.mode ?? 'soft-fail';

	// Empty chain → allow
	if (chain.length === 0) {
		return {
			ok: true,
			value: {
				decision: 'allow',
				summary: { revokedCertificates: [], indeterminateCertificates: [] },
				certificates: [],
			},
		};
	}

	// Create signer validation context with memoization cache
	// This cache is shared across all certificate checks in this chain evaluation
	const signerCtx: SignerValidationContext = {
		cache: new Map(),
		chain,
		crls,
		extraCertificates,
		at,
	};

	// Skip trust anchor (last cert) — it's the trust base
	const certsToCheck = chain.slice(0, -1);
	const certificates: CertificateRevocationStatus[] = [];
	const revokedCertificates: ParsedCertificate[] = [];
	const indeterminateCertificates: ParsedCertificate[] = [];
	const allExecutionErrors: RevocationExecutionError[] = [];

	for (let i = 0; i < certsToCheck.length; i++) {
		const cert = certsToCheck[i];
		const issuer = chain[i + 1]; // Next cert in chain is the issuer
		if (cert === undefined || issuer === undefined) {
			continue; // Should never happen given loop bounds
		}

		const { status, executionErrors } = await evaluateCertificateRevocation(
			cert,
			issuer,
			input,
			signerCtx,
		);
		certificates.push(status);
		allExecutionErrors.push(...executionErrors);

		if (status.status === 'revoked') {
			revokedCertificates.push(cert);
		} else if (status.status === 'indeterminate') {
			indeterminateCertificates.push(cert);
		}
	}

	// Apply policy
	const hasRevoked = revokedCertificates.length > 0;
	const hasIndeterminate = indeterminateCertificates.length > 0;
	const decision: 'allow' | 'deny' =
		hasRevoked
			? 'deny'
			: hasIndeterminate && mode === 'hard-fail'
				? 'deny'
				: 'allow';

	return {
		ok: true,
		value: {
			decision,
			summary: { revokedCertificates, indeterminateCertificates },
			certificates,
			...(allExecutionErrors.length > 0
				? { executionErrors: allExecutionErrors }
				: {}),
		},
	};
}
