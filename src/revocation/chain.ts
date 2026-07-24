/**
 * Chain-level revocation orchestration.
 *
 * Evaluates CRL and OCSP evidence for an entire validated certificate chain,
 * implementing the revocation checking portion of RFC 5280 §6.3.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-6.3 | RFC 5280 §6.3 CRL Validation}
 * @module
 */

import type {
	CrlSource,
	ParsedCertificateRevocationList,
	RevocationReason,
} from '#micro509/revocation/crl';
import {
	ALL_DISTRIBUTION_POINT_REASONS,
	checkCertificateRevocationAgainstCrl,
	parseCertificateRevocationListDerOrThrow,
	parseCertificateRevocationListPemOrThrow,
	revocationReasonFromCode,
} from '#micro509/revocation/crl';
import type {
	OcspResponderRevocationPolicy,
	ParsedOcspResponse,
	ValidateOcspResponseFailure,
	ValidateOcspResponseResult,
} from '#micro509/revocation/ocsp';
import {
	parseOcspResponseDerOrThrow,
	parseOcspResponsePemOrThrow,
	validateOcspResponse,
} from '#micro509/revocation/ocsp';
import type { RevocationCertificateSource } from '#micro509/revocation/revocation';
import { verifyCertificateChain } from '#micro509/verify/verify';
import type { DistributionPointReason } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateFromSource } from '#micro509/x509/parse';

export type { CrlSource };

// Input Types

/**
 * OCSP response in any supported format.
 *
 * Accepts PEM string or DER bytes. Used for
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
	 * - `'hard-fail'`: indeterminate certificates cause denial (default)
	 * - `'soft-fail'`: indeterminate certificates are allowed — an explicit
	 *   availability/compatibility choice
	 *
	 * Revocation checking itself is opt-in: no check runs unless evidence is
	 * supplied. Once it is, indeterminate status denies by default.
	 */
	readonly mode?: 'soft-fail' | 'hard-fail';
	/**
	 * Evidence preference when multiple sources are available.
	 *
	 * Both evidence kinds are always evaluated, and a validated `revoked`
	 * verdict from either source wins regardless of preference (fail-closed).
	 * Preference only decides which source's `good` verdict is reported when
	 * both yield one.
	 *
	 * - `'best-available'`: the source with the fresher evidence — the later
	 *   `thisUpdate` on the validated OCSP entry or CRL — is reported; ties
	 *   favor OCSP (default)
	 * - `'ocsp'`: prefer OCSP over CRL
	 * - `'crl'`: prefer CRL over OCSP
	 */
	readonly prefer?: 'ocsp' | 'crl' | 'best-available';
	/**
	 * Revocation policy for delegated OCSP responder certificates
	 * (RFC 6960 §4.2.2.2.1). Supplied CRLs double as responder revocation
	 * evidence. Defaults to `'honor-nocheck'`.
	 */
	readonly ocspResponderRevocation?: OcspResponderRevocationPolicy;
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
	readonly extraCertificates?: readonly RevocationCertificateSource[];
	/**
	 * Explicitly trusted OCSP responder certificates (RFC 6960 §4.2.2.2
	 * criterion 1). A response signed by one of these is accepted without
	 * delegated-responder issuance, EKU, and revocation checks.
	 */
	readonly trustedOcspResponders?: readonly RevocationCertificateSource[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Revocation policy. */
	readonly policy?: RevocationPolicy;
}

// Output Types

/**
 * Granular reasons why revocation status could not be determined.
 *
 * Returned in {@linkcode CertificateRevocationStatus}'s `indeterminateReasons`
 * when `status` is `'indeterminate'`. Grouped by category:
 *
 * - **Evidence not found**: `no_applicable_crl`, `no_applicable_ocsp`
 * - **Scope mismatch**: `distribution_point_mismatch`, `issuer_name_mismatch`,
 *   `reason_scope_mismatch`, `indirect_crl_scope_mismatch`, `reason_coverage_incomplete`
 * - **Signer trust**: `crl_signer_not_found`, `crl_signer_not_authorized`,
 *   `crl_signer_revoked`, `crl_signer_indeterminate`, and OCSP equivalents
 * - **Freshness**: `crl_expired`, `ocsp_response_expired`
 */
export const REVOCATION_INDETERMINATE_REASONS = [
	// Evidence not found
	'no_applicable_crl',
	'no_applicable_ocsp',
	// Scope issues
	'distribution_point_mismatch',
	'issuer_name_mismatch',
	'reason_scope_mismatch',
	'indirect_crl_scope_mismatch',
	'reason_coverage_incomplete',
	// Signer trust issues
	'crl_signer_not_found',
	'crl_signer_not_authorized',
	'crl_signer_revoked',
	'crl_signer_indeterminate',
	'ocsp_responder_not_found',
	'ocsp_responder_not_authorized',
	'ocsp_responder_revoked',
	'ocsp_responder_indeterminate',
	// Freshness
	'crl_expired',
	'ocsp_response_expired',
	// OCSP specific
	'ocsp_status_unknown',
] as const;

/** See the doc comment above {@linkcode REVOCATION_INDETERMINATE_REASONS}. */
export type RevocationIndeterminateReason = (typeof REVOCATION_INDETERMINATE_REASONS)[number];

/**
 * Identifies the source of revocation evidence.
 *
 * Included in {@linkcode CertificateRevocationStatus}'s `source` when status is
 * `'good'` or `'revoked'` to indicate which CRL or OCSP response provided the answer.
 */
export interface RevocationSource {
	/** Whether evidence came from a CRL or OCSP response. */
	readonly kind: 'crl' | 'ocsp';
	/** Certificate that signed the evidence (CRL issuer or OCSP responder). */
	readonly signerCertificate?: ParsedCertificate;
	/** Identifier for debugging (e.g., CRL issuer DN or OCSP responder URL). */
	readonly evidenceIdentifier?: string;
	/**
	 * `thisUpdate` of the evidence backing the verdict — the OCSP single
	 * response entry or the freshest contributing CRL (an applied delta CRL
	 * supersedes its base). This is the timestamp `'best-available'` compares.
	 */
	readonly thisUpdate?: Date;
}

/**
 * Revocation evaluation result for a single certificate.
 *
 * One entry per certificate in {@linkcode CheckChainRevocationValue.certificates}.
 * The trust anchor is excluded (never checked for revocation).
 */
export type CertificateRevocationStatus =
	| {
			/** The certificate that was evaluated. */
			readonly certificate: ParsedCertificate;
			/** Evidence confirms the certificate is not revoked. */
			readonly status: 'good';
			/** Evidence that produced the verdict. */
			readonly source: RevocationSource;
			/** Never present on a `good` verdict. */
			readonly indeterminateReasons?: undefined;
			/** Never present on a `good` verdict. */
			readonly revocationInfo?: undefined;
	  }
	| {
			/** The certificate that was evaluated. */
			readonly certificate: ParsedCertificate;
			/** Evidence confirms the certificate is revoked. */
			readonly status: 'revoked';
			/** Evidence that produced the verdict. */
			readonly source: RevocationSource;
			/** Revocation details from the CRL entry or OCSP response. */
			readonly revocationInfo: {
				/** When the certificate was revoked. */
				readonly revocationDate: Date;
				/** RFC 5280 CRLReason code, if provided by the CRL/OCSP response. */
				readonly reason?: RevocationReason;
			};
			/** Never present on a `revoked` verdict. */
			readonly indeterminateReasons?: undefined;
	  }
	| {
			/** The certificate that was evaluated. */
			readonly certificate: ParsedCertificate;
			/** Revocation status could not be determined. */
			readonly status: 'indeterminate';
			/** Why status could not be determined. */
			readonly indeterminateReasons: readonly RevocationIndeterminateReason[];
			/** Never present on an `indeterminate` verdict. */
			readonly source?: undefined;
			/** Never present on an `indeterminate` verdict. */
			readonly revocationInfo?: undefined;
	  };

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

// Helpers

/**
 * Parses a CRL from various source formats.
 */
function parseCrlFromSource(source: CrlSource): ParsedCertificateRevocationList {
	if (typeof source === 'object' && 'issuer' in source) {
		return source;
	}
	if (typeof source === 'string') {
		return parseCertificateRevocationListPemOrThrow(source);
	}
	return parseCertificateRevocationListDerOrThrow(source);
}

/**
 * Parses a certificate from various source formats, returning undefined on failure.
 */
function parseCertificateSafe(source: RevocationCertificateSource): ParsedCertificate | undefined {
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
 * Yields every certificate that could have signed the given CRL, AKI/SKI
 * matches before DN matches. All candidates are returned so a certificate whose
 * subject DN collides with the genuine CRL issuer cannot shadow it: each is
 * tried against the CRL signature and its own path to the trust anchor.
 */
function findIndirectCrlIssuers(
	crl: ParsedCertificateRevocationList,
	extraCertificates: readonly RevocationCertificateSource[],
	chain: readonly ParsedCertificate[],
): readonly ParsedCertificate[] {
	const parsedExtras: ParsedCertificate[] = [];
	for (const source of extraCertificates) {
		const parsed = parseCertificateSafe(source);
		if (parsed !== undefined) {
			parsedExtras.push(parsed);
		}
	}

	const candidates = [...parsedExtras, ...chain];
	const matches: ParsedCertificate[] = [];
	const push = (candidate: ParsedCertificate): void => {
		if (!matches.some((existing) => sameCertificate(existing, candidate))) {
			matches.push(candidate);
		}
	};

	if (crl.authorityKeyIdentifier !== undefined) {
		for (const candidate of candidates) {
			if (
				candidate.subjectKeyIdentifier !== undefined &&
				normalizeHex(crl.authorityKeyIdentifier) === normalizeHex(candidate.subjectKeyIdentifier)
			) {
				push(candidate);
			}
		}
	}
	for (const candidate of candidates) {
		if (crl.issuer.derHex === candidate.subject.derHex) {
			push(candidate);
		}
	}

	return matches;
}

/** Lowercases a hex string for bytewise comparison. */
function normalizeHex(value: string): string {
	return value.toLowerCase();
}

/**
 * RFC 5280 §6.3.3(f): confirms the CRL issuer certificate has a valid
 * certification path to the same trust anchor as the certificate under test. A
 * signer already inside the validated chain is authorized by construction. The
 * path check runs without revocation to avoid unbounded recursion.
 */
async function crlSignerChainsToAnchor(
	signer: ParsedCertificate,
	chain: readonly ParsedCertificate[],
	extraCertificates: readonly RevocationCertificateSource[],
	at: Date,
): Promise<boolean> {
	if (chain.some((c) => sameCertificate(c, signer))) {
		return true;
	}
	const trustAnchor = chain[chain.length - 1];
	if (trustAnchor === undefined) {
		return false;
	}
	// The signer's issuer may be a validated chain certificate (a delegated
	// signer issued by an intermediate), so pool the non-anchor chain members
	// with the extras. Exclude the signer and the anchor.
	const pool: ParsedCertificate[] = [];
	const addCandidate = (parsed: ParsedCertificate): void => {
		if (sameCertificate(parsed, signer) || sameCertificate(parsed, trustAnchor)) {
			return;
		}
		if (!pool.some((existing) => sameCertificate(existing, parsed))) {
			pool.push(parsed);
		}
	};
	for (let index = 0; index < chain.length - 1; index += 1) {
		const certificate = chain[index];
		if (certificate !== undefined) {
			addCandidate(certificate);
		}
	}
	for (const source of extraCertificates) {
		const parsed = parseCertificateSafe(source);
		if (parsed !== undefined) {
			addCandidate(parsed);
		}
	}
	const result = await verifyCertificateChain({
		leaf: signer.der,
		intermediates: pool.map((certificate) => certificate.der),
		roots: [trustAnchor.der],
		at,
	});
	return result.ok;
}

// CRL Signer Validation (RFC 5280 §6.3.3)

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
	readonly extraCertificates: readonly RevocationCertificateSource[];
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
			normalizeHex(signer.authorityKeyIdentifier) === normalizeHex(candidate.subjectKeyIdentifier)
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

/** Builds the `revoked` CertificateRevocationStatus for a CRL hit. */
function buildCrlRevokedStatus(
	cert: ParsedCertificate,
	signer: ParsedCertificate,
	thisUpdate: Date,
	revocationDate: Date,
	reasonCode?: RevocationReason,
): CertificateRevocationStatus {
	return {
		certificate: cert,
		status: 'revoked',
		source: { kind: 'crl', signerCertificate: signer, thisUpdate },
		revocationInfo: {
			revocationDate,
			...(reasonCode !== undefined ? { reason: reasonCode } : {}),
		},
	};
}

// OCSP Evidence Evaluation (RFC 6960)

/** Per-certificate evidence evaluation outcome shared by the CRL and OCSP evaluators. */
interface EvidenceEvaluation {
	readonly status: CertificateRevocationStatus;
	readonly executionErrors: readonly RevocationExecutionError[];
}

/** Parses an OCSP response from PEM string or DER bytes. */
function parseOcspResponseFromSource(source: OcspResponseSource): ParsedOcspResponse {
	if (typeof source === 'string') {
		return parseOcspResponsePemOrThrow(source);
	}
	return parseOcspResponseDerOrThrow(source);
}

/** Maps a {@linkcode validateOcspResponse} failure code to an indeterminate reason. */
function ocspIndeterminateReasonFromFailure(
	code: ValidateOcspResponseFailure['code'],
): RevocationIndeterminateReason {
	switch (code) {
		case 'stale_response':
			return 'ocsp_response_expired';
		case 'responder_id_mismatch':
		case 'responder_chain_invalid':
		case 'ocsp_signing_missing':
			return 'ocsp_responder_not_authorized';
		case 'responder_revoked':
			return 'ocsp_responder_revoked';
		case 'signature_invalid':
		case 'responder_revocation_unknown':
			return 'ocsp_responder_indeterminate';
		case 'response_status_invalid':
		case 'issuer_mismatch':
		case 'nonce_mismatch':
		case 'request_mismatch':
			return 'no_applicable_ocsp';
	}
}

/** Validation failures worth retrying with an explicit responder certificate. */
const OCSP_RESPONDER_FAILURE_CODES: ReadonlySet<ValidateOcspResponseFailure['code']> = new Set([
	'signature_invalid',
	'responder_id_mismatch',
	'responder_chain_invalid',
	'ocsp_signing_missing',
]);

/**
 * Validates an OCSP response, retrying with caller-provided extra certificates
 * as explicit responder certificates when embedded discovery fails.
 */
async function validateOcspResponseWithResponderFallback(
	response: ParsedOcspResponse,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
	at: Date,
): Promise<ValidateOcspResponseResult> {
	const shared = {
		issuerCertificate: issuer,
		at,
		...(input.trustedOcspResponders !== undefined
			? { trustedOcspResponders: input.trustedOcspResponders }
			: {}),
		...(input.policy?.ocspResponderRevocation !== undefined
			? { responderRevocationPolicy: input.policy.ocspResponderRevocation }
			: {}),
		// Chain-level CRLs double as responder revocation evidence
		...(input.crls !== undefined ? { responderRevocationCrls: input.crls } : {}),
	};
	const primary = await validateOcspResponse({ response, ...shared });
	if (primary.ok || !OCSP_RESPONDER_FAILURE_CODES.has(primary.code)) {
		return primary;
	}
	for (const source of input.extraCertificates ?? []) {
		const responder = parseCertificateSafe(source);
		if (responder === undefined) {
			continue;
		}
		const retry = await validateOcspResponse({
			response,
			...shared,
			responderCertificate: responder,
		});
		if (retry.ok) {
			return retry;
		}
	}
	return primary;
}

/**
 * Evaluates OCSP evidence for a single certificate (RFC 6960).
 *
 * Every response is fully validated — signature, responder binding and
 * authorization, and freshness — via {@linkcode validateOcspResponse} before
 * its status entry is trusted. Issuer binding of each CertID is enforced by
 * the validator, so a serial-number match on a validated response is
 * sufficient to attribute the entry to `cert`.
 */
async function evaluateOcspEvidence(
	cert: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
): Promise<EvidenceEvaluation> {
	const { ocspResponses = [], at = new Date() } = input;
	const executionErrors: RevocationExecutionError[] = [];
	const reasons = new Set<RevocationIndeterminateReason>();

	for (const source of ocspResponses) {
		let parsed: ParsedOcspResponse;
		try {
			parsed = parseOcspResponseFromSource(source);
		} catch (e) {
			executionErrors.push({
				kind: 'parse_error',
				message: e instanceof Error ? e.message : 'OCSP response parse failed',
			});
			continue;
		}

		const entry = (parsed.responses ?? []).find(
			(single) =>
				normalizeHex(single.certId.serialNumberHex) === normalizeHex(cert.serialNumberHex),
		);
		if (entry === undefined) {
			continue; // Response does not cover this certificate
		}

		const validation = await validateOcspResponseWithResponderFallback(parsed, issuer, input, at);
		if (!validation.ok) {
			reasons.add(ocspIndeterminateReasonFromFailure(validation.code));
			continue;
		}

		if (entry.certStatus === 'revoked') {
			const reason = revocationReasonFromCode(entry.revocationReasonCode);
			return {
				status: {
					certificate: cert,
					status: 'revoked',
					source: { kind: 'ocsp', thisUpdate: entry.thisUpdate },
					revocationInfo: {
						revocationDate: entry.revokedAt ?? entry.thisUpdate,
						...(reason !== undefined ? { reason } : {}),
					},
				},
				executionErrors,
			};
		}
		if (entry.certStatus === 'good') {
			return {
				status: {
					certificate: cert,
					status: 'good',
					source: { kind: 'ocsp', thisUpdate: entry.thisUpdate },
				},
				executionErrors,
			};
		}
		reasons.add('ocsp_status_unknown');
	}

	if (reasons.size === 0) {
		reasons.add('no_applicable_ocsp');
	}
	return {
		status: {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons: [...reasons],
		},
		executionErrors,
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
interface CrlEvidenceState {
	readonly executionErrors: RevocationExecutionError[];
	readonly coveredReasons: Set<string>;
	sawCrlSignerRevoked: boolean;
	sawCrlSignerIndeterminate: boolean;
	sawCrlSignerNotAuthorized: boolean;
	sawGood: boolean;
	freshestGood?: { readonly signer: ParsedCertificate; readonly thisUpdate: Date };
}

/** Inputs for resolving one base CRL against its candidate signers. */
interface BaseCrlResolution {
	readonly cert: ParsedCertificate;
	readonly baseCrl: ParsedCertificateRevocationList;
	readonly applicableDelta: ParsedCertificateRevocationList | undefined;
	readonly crlThisUpdate: Date;
	readonly issuer: ParsedCertificate;
	readonly extraCertificates: readonly RevocationCertificateSource[];
	readonly chain: readonly ParsedCertificate[];
	readonly at: Date;
	readonly signerCtx: SignerValidationContext;
	readonly state: CrlEvidenceState;
}

/**
 * Runs each candidate signer through the full pipeline for one base CRL:
 * signature/applicability, RFC 5280 §6.3.3(f) path to the anchor, then signer
 * revocation. A candidate that verifies the signature but fails a later step
 * does not shadow a subsequent usable signer, so the search continues. Returns
 * a revoked status when one is found; otherwise records good or diagnostic
 * evidence into `state`.
 */
async function resolveBaseCrlAgainstSigners(
	params: BaseCrlResolution,
): Promise<ReturnType<typeof buildCrlRevokedStatus> | undefined> {
	const {
		cert,
		baseCrl,
		applicableDelta,
		crlThisUpdate,
		issuer,
		extraCertificates,
		chain,
		at,
		signerCtx,
		state,
	} = params;
	for (const candidate of collectCrlSignerCandidates(baseCrl, issuer, extraCertificates, chain)) {
		const checked = await checkCrlWithIssuer(cert, baseCrl, applicableDelta, candidate, at);
		if (!checked.ok) {
			continue;
		}
		if (!(await crlSignerChainsToAnchor(candidate, chain, extraCertificates, at))) {
			state.sawCrlSignerNotAuthorized = true;
			continue;
		}
		const signerStatus = await validateCrlSigner(candidate, signerCtx);
		if (signerStatus === 'resolved-revoked') {
			state.sawCrlSignerRevoked = true;
			continue;
		}
		if (signerStatus === 'resolved-indeterminate') {
			state.sawCrlSignerIndeterminate = true;
			continue;
		}
		if (checked.value.status === 'revoked') {
			return buildCrlRevokedStatus(
				cert,
				candidate,
				crlThisUpdate,
				checked.value.revocationDate,
				checked.value.reasonCode,
			);
		}
		recordGoodCrlEvidence(state, candidate, crlThisUpdate, checked.value.coveredReasons);
		return undefined;
	}
	return undefined;
}

async function evaluateCrlEvidence(
	cert: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
): Promise<EvidenceEvaluation> {
	const { crls = [], extraCertificates = [], chain = [], at = new Date() } = input;
	const state: CrlEvidenceState = {
		executionErrors: [],
		coveredReasons: new Set(),
		sawCrlSignerRevoked: false,
		sawCrlSignerIndeterminate: false,
		sawCrlSignerNotAuthorized: false,
		sawGood: false,
	};

	// Parse all CRLs and separate base CRLs from delta CRLs
	const parsedCrls = parseCrlEvidenceSources(crls, state.executionErrors);

	const baseCrls = parsedCrls.filter((crl) => crl.baseCrlNumber === undefined);
	const deltaCrls = parsedCrls.filter((crl) => crl.baseCrlNumber !== undefined);

	// Process base CRLs (optionally paired with delta CRLs)
	for (const baseCrl of baseCrls) {
		const applicableDelta = findApplicableDeltaCrl(baseCrl, deltaCrls);
		// Evidence freshness: an applied delta CRL supersedes its base
		const crlThisUpdate =
			applicableDelta !== undefined &&
			applicableDelta.thisUpdate.getTime() > baseCrl.thisUpdate.getTime()
				? applicableDelta.thisUpdate
				: baseCrl.thisUpdate;
		const revoked = await resolveBaseCrlAgainstSigners({
			cert,
			baseCrl,
			applicableDelta,
			crlThisUpdate,
			issuer,
			extraCertificates,
			chain,
			at,
			signerCtx,
			state,
		});
		if (revoked !== undefined) {
			return { status: revoked, executionErrors: state.executionErrors };
		}
	}

	// Return 'good' only if we saw at least one good result AND all reasons are covered
	if (state.sawGood && state.freshestGood !== undefined) {
		const allReasonsCovered = ALL_DISTRIBUTION_POINT_REASONS.every((r) =>
			state.coveredReasons.has(r),
		);
		if (allReasonsCovered) {
			return {
				status: {
					certificate: cert,
					status: 'good',
					source: {
						kind: 'crl',
						signerCertificate: state.freshestGood.signer,
						thisUpdate: state.freshestGood.thisUpdate,
					},
				},
				executionErrors: state.executionErrors,
			};
		}
		// Not all reasons covered — indeterminate
		return {
			status: {
				certificate: cert,
				status: 'indeterminate',
				indeterminateReasons: ['reason_coverage_incomplete'],
			},
			executionErrors: state.executionErrors,
		};
	}

	return {
		status: {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons: [crlUnavailableReason(state)],
		},
		executionErrors: state.executionErrors,
	};
}

/** Most specific indeterminate reason when no CRL yielded a usable verdict. */
function crlUnavailableReason(state: CrlEvidenceState): RevocationIndeterminateReason {
	if (state.sawCrlSignerRevoked) {
		return 'crl_signer_revoked';
	}
	if (state.sawCrlSignerNotAuthorized) {
		return 'crl_signer_not_authorized';
	}
	if (state.sawCrlSignerIndeterminate) {
		return 'crl_signer_indeterminate';
	}
	return 'no_applicable_crl';
}

/** Parses complete and delta CRL evidence while retaining source provenance. */
function parseCrlEvidenceSources(
	crls: readonly CrlSource[],
	executionErrors: RevocationExecutionError[],
): readonly ParsedCertificateRevocationList[] {
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
	return parsedCrls;
}

function findApplicableDeltaCrl(
	baseCrl: ParsedCertificateRevocationList,
	deltaCrls: readonly ParsedCertificateRevocationList[],
): ParsedCertificateRevocationList | undefined {
	return deltaCrls.find(
		(deltaCrl) =>
			deltaCrl.issuer.derHex === baseCrl.issuer.derHex &&
			deltaCrl.baseCrlNumber !== undefined &&
			baseCrl.crlNumber !== undefined &&
			BigInt(deltaCrl.baseCrlNumber) <= BigInt(baseCrl.crlNumber),
	);
}

/** The direct issuer first, then deduplicated indirect CRL-issuer candidates. */
function collectCrlSignerCandidates(
	baseCrl: ParsedCertificateRevocationList,
	issuer: ParsedCertificate,
	extraCertificates: readonly RevocationCertificateSource[],
	chain: readonly ParsedCertificate[],
): readonly ParsedCertificate[] {
	const candidates: ParsedCertificate[] = [issuer];
	for (const indirect of findIndirectCrlIssuers(baseCrl, extraCertificates, chain)) {
		if (!candidates.some((existing) => sameCertificate(existing, indirect))) {
			candidates.push(indirect);
		}
	}
	return candidates;
}

function checkCrlWithIssuer(
	cert: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	deltaCrl: ParsedCertificateRevocationList | undefined,
	crlIssuer: ParsedCertificate,
	at: Date,
): ReturnType<typeof checkCertificateRevocationAgainstCrl> {
	return checkCertificateRevocationAgainstCrl({
		certificate: cert,
		issuerCertificate: crlIssuer,
		crl,
		...(deltaCrl !== undefined ? { deltaCrl } : {}),
		at,
	});
}

function recordGoodCrlEvidence(
	state: CrlEvidenceState,
	signer: ParsedCertificate,
	thisUpdate: Date,
	coveredReasons: readonly DistributionPointReason[],
): void {
	state.sawGood = true;
	if (
		state.freshestGood === undefined ||
		thisUpdate.getTime() > state.freshestGood.thisUpdate.getTime()
	) {
		state.freshestGood = { signer, thisUpdate };
	}
	for (const reason of coveredReasons) {
		state.coveredReasons.add(reason);
	}
}

/**
 * Evaluates revocation status for a single certificate by combining OCSP and
 * CRL evidence.
 *
 * Both evidence kinds are always evaluated: a validated `revoked` verdict from
 * either source wins regardless of {@linkcode RevocationPolicy.prefer}
 * (fail-closed). Otherwise the preferred source's `good` verdict is reported —
 * for `'best-available'` the source with the later evidence `thisUpdate` wins,
 * ties favoring OCSP. If neither source is definitive, indeterminate reasons
 * from both are merged.
 */
async function evaluateCertificateRevocation(
	cert: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
): Promise<EvidenceEvaluation> {
	const prefer = input.policy?.prefer ?? 'best-available';
	const ocsp = await evaluateOcspEvidence(cert, issuer, input);
	const crl = await evaluateCrlEvidence(cert, issuer, input, signerCtx);
	const executionErrors = [...ocsp.executionErrors, ...crl.executionErrors];

	// 'best-available' ranks by evidence freshness; the sort is stable, so
	// equal (or absent) thisUpdate keeps OCSP first.
	const ordered =
		prefer === 'crl'
			? [crl, ocsp]
			: prefer === 'ocsp'
				? [ocsp, crl]
				: [ocsp, crl].sort(
						(a, b) =>
							(b.status.source?.thisUpdate?.getTime() ?? 0) -
							(a.status.source?.thisUpdate?.getTime() ?? 0),
					);
	const revoked = ordered.find((evaluation) => evaluation.status.status === 'revoked');
	if (revoked !== undefined) {
		return { status: revoked.status, executionErrors };
	}
	const good = ordered.find((evaluation) => evaluation.status.status === 'good');
	if (good !== undefined) {
		return { status: good.status, executionErrors };
	}

	const reasons = new Set<RevocationIndeterminateReason>();
	for (const evaluation of ordered) {
		for (const reason of evaluation.status.indeterminateReasons ?? []) {
			reasons.add(reason);
		}
	}
	return {
		status: {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons: [...reasons],
		},
		executionErrors,
	};
}

// Function

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
 *   ocspResponses: [ocspResponseDer],
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
	const mode = policy?.mode ?? 'hard-fail';

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
	const decision: 'allow' | 'deny' = hasRevoked
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
			...(allExecutionErrors.length > 0 ? { executionErrors: allExecutionErrors } : {}),
		},
	};
}
