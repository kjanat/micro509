/**
 * Chain-level revocation orchestration.
 * Evaluates CRL/OCSP evidence for an entire validated certificate chain.
 * @module
 */

import type { ParsedCertificate } from '#micro509/x509/parse.ts';
import type { CrlSource, RevocationReason } from './crl.ts';

// ---------------------------------------------------------------------------
// Input Types
// ---------------------------------------------------------------------------

/** PEM, DER, or parsed certificate. */
export type CertificateSource = string | Uint8Array | ParsedCertificate;

/** PEM or DER bytes of an OCSP response. */
export type OcspResponseSource = string | Uint8Array;

/** Revocation checking policy. */
export interface RevocationPolicy {
	/** 'soft-fail': indeterminate -> allow. 'hard-fail': indeterminate -> deny. Default: 'soft-fail'. */
	readonly mode?: 'soft-fail' | 'hard-fail';
	/** Evidence preference order. Default: 'best-available'. */
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

/** Granular reasons for indeterminate status. */
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

/** Where the revocation evidence came from. */
export interface RevocationSource {
	readonly type: 'crl' | 'ocsp';
	readonly signerCertificate?: ParsedCertificate;
	readonly evidenceIdentifier?: string;
}

/** Per-certificate revocation status. */
export interface CertificateRevocationStatus {
	readonly certificate: ParsedCertificate;
	readonly status: 'good' | 'revoked' | 'indeterminate';
	readonly source?: RevocationSource;
	readonly indeterminateReasons?: readonly RevocationIndeterminateReason[];
	readonly revocationInfo?: {
		readonly date: Date;
		readonly reason?: RevocationReason;
	};
}

/** Execution errors (code failures, not evaluation outcomes). */
export interface RevocationExecutionError {
	readonly kind: 'parse_error' | 'unsupported_extension' | 'internal_error';
	readonly message: string;
	readonly evidenceIdentifier?: string;
}

/** Successful result value. */
export interface CheckChainRevocationValue {
	/** Policy decision derived from findings. */
	readonly decision: 'allow' | 'deny';
	/** Summary for quick inspection. */
	readonly summary: {
		readonly revokedCertificates: readonly ParsedCertificate[];
		readonly indeterminateCertificates: readonly ParsedCertificate[];
	};
	/** Per-certificate detailed findings. */
	readonly certificates: readonly CertificateRevocationStatus[];
	/** Execution errors (evidence we couldn't evaluate). */
	readonly executionErrors?: readonly RevocationExecutionError[];
}

/** Result type for {@linkcode checkChainRevocation}. */
export type CheckChainRevocationResult = {
	readonly ok: true;
	readonly value: CheckChainRevocationValue;
};

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
	const { chain, policy } = input;
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

	// Skip trust anchor (last cert) — it's the trust base
	const certsToCheck = chain.slice(0, -1);
	const certificates: CertificateRevocationStatus[] = [];
	const revokedCertificates: ParsedCertificate[] = [];
	const indeterminateCertificates: ParsedCertificate[] = [];

	for (const cert of certsToCheck) {
		// TODO: Evaluate evidence (Task 2.2)
		// For now, return indeterminate since no evidence evaluation yet
		const status: CertificateRevocationStatus = {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons: ['no_applicable_crl', 'no_applicable_ocsp'],
		};
		certificates.push(status);
		indeterminateCertificates.push(cert);
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
		},
	};
}
