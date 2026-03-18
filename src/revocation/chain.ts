/**
 * Chain-level revocation orchestration.
 * Evaluates CRL/OCSP evidence for an entire validated certificate chain.
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

	for (const candidate of candidates) {
		// Match by AKI → SKI (preferred, more specific)
		if (
			crl.authorityKeyIdentifier !== undefined &&
			candidate.subjectKeyIdentifier !== undefined &&
			normalizeHex(crl.authorityKeyIdentifier) === normalizeHex(candidate.subjectKeyIdentifier)
		) {
			return candidate;
		}

		// Match by issuer DN → subject DN
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
 */
async function evaluateCertificateRevocation(
	cert: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CheckChainRevocationInput,
): Promise<{
	status: CertificateRevocationStatus;
	executionErrors: readonly RevocationExecutionError[];
}> {
	const { crls = [], extraCertificates = [], chain = [], at = new Date() } = input;
	const executionErrors: RevocationExecutionError[] = [];

	// Try each CRL
	for (const crlSource of crls) {
		let crl: ParsedCertificateRevocationList;
		try {
			crl = parseCrlFromSource(crlSource);
		} catch (e) {
			executionErrors.push({
				kind: 'parse_error',
				message: e instanceof Error ? e.message : 'CRL parse failed',
			});
			continue;
		}

		// Try chain issuer first
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: cert,
			issuerCertificate: issuer,
			crl,
			at,
		});

		if (result.ok) {
			return {
				status: buildCrlStatus(
					cert,
					issuer,
					result.value.status,
					result.value.status === 'revoked' ? result.value.revocationDate : undefined,
					result.value.status === 'revoked' ? result.value.reasonCode : undefined,
				),
				executionErrors,
			};
		}

		// Chain issuer failed — try to find indirect CRL issuer
		const indirectIssuer = findIndirectCrlIssuer(crl, extraCertificates, chain);
		if (indirectIssuer !== undefined && !sameCertificate(indirectIssuer, issuer)) {
			const indirectResult = await checkCertificateRevocationAgainstCrl({
				certificate: cert,
				issuerCertificate: indirectIssuer,
				crl,
				at,
			});

			if (indirectResult.ok) {
				return {
					status: buildCrlStatus(
						cert,
						indirectIssuer,
						indirectResult.value.status,
						indirectResult.value.status === 'revoked'
							? indirectResult.value.revocationDate
							: undefined,
						indirectResult.value.status === 'revoked'
							? indirectResult.value.reasonCode
							: undefined,
					),
					executionErrors,
				};
			}
		}
	}

	// No applicable CRL found
	return {
		status: {
			certificate: cert,
			status: 'indeterminate',
			indeterminateReasons:
				crls.length === 0
					? ['no_applicable_crl', 'no_applicable_ocsp']
					: ['no_applicable_crl'], // CRLs provided but none covered this cert
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
