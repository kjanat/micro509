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
