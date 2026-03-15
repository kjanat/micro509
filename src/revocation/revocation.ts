/**
 * Revocation orchestration: evaluates CRL and OCSP evidence to produce a
 * unified `good`/`revoked`/`unknown` status for a certificate.
 *
 * @module
 */

import type { CrlApplicabilityFailureReason, CrlSource, RevocationReason } from './crl.ts';
import { checkCertificateRevocationAgainstCrl } from './crl.ts';
import type { OcspCertificateSource, OcspRequestSource, ParsedOcspResponse } from './ocsp.ts';
import { validateOcspResponse } from './ocsp.ts';
import type { ParsedCertificate } from '../x509/parse.ts';
import { parseCertificateDer, parseCertificatePem } from '../x509/parse.ts';
import type { Result } from '../result/result.ts';

export type * from './crl.ts';
export type * from './ocsp.ts';
export type * from '../x509/parse.ts';
export type * from '../result/result.ts';

/** Unified revocation outcome across CRL and OCSP evidence. */
export type RevocationStatus = 'good' | 'revoked' | 'unknown';

/** Which revocation mechanism produced the evidence. */
export type RevocationEvidenceKind = 'crl' | 'ocsp';
/** PEM string, DER bytes, or already-parsed certificate. */
export type RevocationCertificateSource = string | Uint8Array | ParsedCertificate;
/** Where the OCSP responder URI came from. */
export type OcspResponderSource = 'configured' | 'authorityInfoAccess';
/** PEM or DER bytes of a pre-configured OCSP responder certificate. */
export type ConfiguredOcspResponderCertificate = string | Uint8Array;

/** A manually-configured OCSP responder endpoint. */
export interface ConfiguredOcspResponder {
	/** OCSP responder URI (typically `http://...`). */
	readonly uri: string;
	/** Known responder certificate — skips embedded-certificate discovery. */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/** One candidate OCSP responder resolved by {@linkcode resolveOcspResponderCandidates}. */
export interface OcspResponderCandidate {
	/** Whether this candidate came from configuration or the certificate's AIA extension. */
	readonly source: OcspResponderSource;
	/** OCSP responder URI. */
	readonly uri: string;
	/** Pre-known responder certificate, if available. */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/** Input for {@linkcode resolveOcspResponderCandidates}. */
export interface ResolveOcspResponderCandidatesInput {
	/** Certificate whose AIA extension will be inspected for OCSP URIs. */
	readonly certificate: RevocationCertificateSource;
	/** Manually-configured responders — checked before AIA-derived ones. */
	readonly configuredResponders?: readonly ConfiguredOcspResponder[];
}

/** CRL-based revocation evidence for {@linkcode CheckCertificateRevocationInput.evidence}. */
export interface RevocationCrlEvidenceInput {
	/** Discriminator for the CRL evidence variant. */
	readonly kind: 'crl';
	/** Complete (base) CRL. */
	readonly crl: CrlSource;
	/** Optional delta CRL for more recent revocation information. */
	readonly deltaCrl?: CrlSource;
}

/** OCSP-based revocation evidence for {@linkcode CheckCertificateRevocationInput.evidence}. */
export interface RevocationOcspEvidenceInput {
	/** Discriminator for the OCSP evidence variant. */
	readonly kind: 'ocsp';
	/** OCSP response to validate. */
	readonly response: string | Uint8Array | ParsedOcspResponse;
	/** Original OCSP request — enables nonce and coverage checks. */
	readonly request?: OcspRequestSource;
	/** Explicit responder certificate — overrides embedded certificate discovery. */
	readonly responderCertificate?: OcspCertificateSource;
}

/** Discriminated union of CRL and OCSP evidence inputs. */
export type RevocationEvidenceInput = RevocationCrlEvidenceInput | RevocationOcspEvidenceInput;

/** Input for {@linkcode checkCertificateRevocation}. */
export interface CheckCertificateRevocationInput {
	/** Certificate whose revocation status to determine. */
	readonly certificate: RevocationCertificateSource;
	/** Issuer of `certificate`. */
	readonly issuerCertificate: RevocationCertificateSource;
	/** CRL and/or OCSP evidence to evaluate. Returns `unknown` if empty. */
	readonly evidence?: readonly RevocationEvidenceInput[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Clock-skew tolerance in milliseconds. */
	readonly clockSkewMs?: number;
}

/** Error codes that {@linkcode checkCertificateRevocation} may surface inside an `unknown` result. */
export type CheckCertificateRevocationErrorCode =
	| 'revocation_evidence_missing'
	| 'revocation_status_unknown';

/** Why a particular piece of evidence could not produce a definitive `good`/`revoked` answer. */
export type RevocationIndeterminateReasonCode =
	| 'certificate_status_missing'
	| 'certificate_status_unknown'
	| 'crl_sign_not_permitted'
	| 'issuer_mismatch'
	| 'non_applicable'
	| 'nonce_mismatch'
	| 'ocsp_signing_missing'
	| 'request_mismatch'
	| 'responder_id_mismatch'
	| 'responder_chain_invalid'
	| 'response_status_invalid'
	| 'signature_invalid'
	| 'stale_crl'
	| 'stale_response';

/** One piece of evidence that failed to produce a definitive revocation answer. */
export interface RevocationIndeterminateEvidence {
	/** Whether this evidence was CRL or OCSP. */
	readonly source: RevocationEvidenceKind;
	/** Machine-readable reason code. */
	readonly code: RevocationIndeterminateReasonCode;
	/** Human-readable explanation. */
	readonly message: string;
	/** CRL-specific applicability failure reason, when `source` is `'crl'`. */
	readonly reason?: CrlApplicabilityFailureReason;
}

/** Diagnostic details attached to an `unknown` revocation result. */
export interface CheckCertificateRevocationFailureDetails {
	/** Which evidence kinds were attempted (`'crl'`, `'ocsp'`, or both). */
	readonly checkedSources: readonly RevocationEvidenceKind[];
	/** Per-evidence explanations of why no definitive answer was reached. */
	readonly indeterminateEvidence: readonly RevocationIndeterminateEvidence[];
}

/** Revocation status could not be determined from the provided evidence. */
export interface RevocationCheckUnknownValue {
	/** Status is indeterminate. */
	readonly status: Extract<RevocationStatus, 'unknown'>;
	/** Why revocation status is unknown. */
	readonly code: CheckCertificateRevocationErrorCode;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** What evidence was attempted and why each failed. */
	readonly details: CheckCertificateRevocationFailureDetails;
}

/** Certificate is not revoked according to the checked evidence. */
export interface RevocationCheckGoodValue {
	/** Certificate is not revoked. */
	readonly status: Extract<RevocationStatus, 'good'>;
	/** Which evidence kind confirmed the good status. */
	readonly source: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
}

/** Certificate is revoked according to the checked evidence. */
export interface RevocationCheckRevokedValue {
	/** Certificate is revoked. */
	readonly status: Extract<RevocationStatus, 'revoked'>;
	/** Which evidence kind reported the revocation. */
	readonly source: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** When the certificate was revoked (from CRL entry or OCSP response). */
	readonly revokedAt?: Date;
	/** CRL reason string (from CRL evidence). */
	readonly revocationReason?: RevocationReason;
	/** CRL reason integer code (from OCSP evidence). */
	readonly revocationReasonCode?: number;
}

/** Discriminated union of `good`, `revoked`, and `unknown` revocation outcomes. */
export type CheckCertificateRevocationValue =
	| RevocationCheckGoodValue
	| RevocationCheckRevokedValue
	| RevocationCheckUnknownValue;

/**
 * Result of {@linkcode checkCertificateRevocation}. Always succeeds (`ok: true`) —
 * the `value.status` discriminator carries the actual outcome.
 */
export type CheckCertificateRevocationResult = Result<CheckCertificateRevocationValue, never>;

/** Internal intermediate result from evaluating a single piece of revocation evidence. */
type RevocationEvidenceCheck =
	| { readonly status: 'good'; readonly result: RevocationCheckGoodValue }
	| { readonly status: 'revoked'; readonly result: RevocationCheckRevokedValue }
	| { readonly status: 'unknown'; readonly detail: RevocationIndeterminateEvidence };

/** Extracts OCSP responder URIs from the certificate's Authority Information Access extension. */
export function getCertificateOcspResponderUris(
	certificate: RevocationCertificateSource,
): readonly string[] {
	const parsedCertificate = normalizeCertificate(certificate);
	const uris: string[] = [];
	const seen = new Set<string>();
	for (const accessDescription of parsedCertificate.authorityInfoAccess ?? []) {
		if (accessDescription.method !== 'ocsp' || seen.has(accessDescription.uri)) {
			continue;
		}
		seen.add(accessDescription.uri);
		uris.push(accessDescription.uri);
	}
	return uris;
}

/**
 * Merges configured OCSP responders with those discovered from the certificate's
 * AIA extension. Configured responders take priority; duplicates are deduplicated by URI.
 */
export function resolveOcspResponderCandidates(
	input: ResolveOcspResponderCandidatesInput,
): readonly OcspResponderCandidate[] {
	const candidates: OcspResponderCandidate[] = [];
	const configuredByUri = new Map<string, ConfiguredOcspResponder>();
	for (const configuredResponder of input.configuredResponders ?? []) {
		const existing = configuredByUri.get(configuredResponder.uri);
		if (
			existing === undefined ||
			(existing.responderCertificate === undefined &&
				configuredResponder.responderCertificate !== undefined)
		) {
			configuredByUri.set(configuredResponder.uri, configuredResponder);
		}
	}
	const seen = new Set<string>();
	for (const configuredResponder of configuredByUri.values()) {
		seen.add(configuredResponder.uri);
		candidates.push({
			source: 'configured',
			uri: configuredResponder.uri,
			...(configuredResponder.responderCertificate === undefined
				? {}
				: { responderCertificate: configuredResponder.responderCertificate }),
		});
	}
	for (const uri of getCertificateOcspResponderUris(input.certificate)) {
		if (seen.has(uri)) {
			continue;
		}
		seen.add(uri);
		candidates.push({
			source: 'authorityInfoAccess',
			uri,
		});
	}
	return candidates;
}

/**
 * Evaluates all provided CRL and OCSP evidence to determine the certificate's
 * revocation status. Returns the first `revoked` if any, else the first `good`,
 * else `unknown` with diagnostic details about each indeterminate evidence.
 *
 * @example
 * ```ts
 * import { checkCertificateRevocation } from 'micro509';
 *
 * const result = await checkCertificateRevocation({
 *   certificate: leafPem,
 *   issuerCertificate: caPem,
 *   evidence: [{ kind: 'crl', crl: crlPem }],
 * });
 * if (result.ok && result.value.status === 'revoked') {
 *   console.log('revoked at', result.value.revokedAt);
 * }
 * ```
 */
export async function checkCertificateRevocation(
	input: CheckCertificateRevocationInput,
): Promise<CheckCertificateRevocationResult> {
	const evidence = input.evidence ?? [];
	const checkedSources = evidence.map((entry) => entry.kind);
	if (evidence.length === 0) {
		return revocationSuccess({
			status: 'unknown',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details: {
				checkedSources,
				indeterminateEvidence: [],
			},
		});
	}
	let goodResult: RevocationCheckGoodValue | undefined;
	const indeterminateEvidence: RevocationIndeterminateEvidence[] = [];
	for (const entry of evidence) {
		const result =
			entry.kind === 'crl'
				? await checkCertificateRevocationWithCrl(input, entry)
				: await checkCertificateRevocationWithOcsp(input, entry);
		if (result.status === 'revoked') {
			return revocationSuccess(result.result);
		}
		if (result.status === 'good') {
			goodResult ??= result.result;
			continue;
		}
		indeterminateEvidence.push(result.detail);
	}
	if (goodResult !== undefined) {
		return revocationSuccess(goodResult);
	}
	return revocationSuccess({
		status: 'unknown',
		code: 'revocation_status_unknown',
		message: 'No revocation evidence established certificate status',
		details: {
			checkedSources,
			indeterminateEvidence,
		},
	});
}

/** Evaluates a single CRL evidence entry via {@linkcode checkCertificateRevocationAgainstCrl}. */
async function checkCertificateRevocationWithCrl(
	input: CheckCertificateRevocationInput,
	evidence: RevocationCrlEvidenceInput,
): Promise<RevocationEvidenceCheck> {
	const result = await checkCertificateRevocationAgainstCrl({
		certificate: input.certificate,
		issuerCertificate: input.issuerCertificate,
		crl: evidence.crl,
		...(evidence.deltaCrl === undefined ? {} : { deltaCrl: evidence.deltaCrl }),
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
	});
	if (result.ok) {
		if (result.value.status === 'revoked') {
			return {
				status: 'revoked',
				result: {
					status: 'revoked',
					source: 'crl',
					message: 'Certificate is revoked according to CRL evidence',
					revokedAt: result.value.revocationDate,
					...(result.value.reasonCode === undefined
						? {}
						: { revocationReason: result.value.reasonCode }),
				},
			};
		}
		return {
			status: 'good',
			result: {
				status: 'good',
				source: 'crl',
				message: 'Certificate is not revoked according to CRL evidence',
			},
		};
	}
	return {
		status: 'unknown',
		detail: {
			source: 'crl',
			code: result.code,
			message: result.message,
			...(result.details?.reason === undefined ? {} : { reason: result.details.reason }),
		},
	};
}

/** Evaluates a single OCSP evidence entry via {@linkcode validateOcspResponse}. */
async function checkCertificateRevocationWithOcsp(
	input: CheckCertificateRevocationInput,
	evidence: RevocationOcspEvidenceInput,
): Promise<RevocationEvidenceCheck> {
	const response = await validateOcspResponse({
		response: evidence.response,
		issuerCertificate: input.issuerCertificate,
		...(evidence.request === undefined ? {} : { request: evidence.request }),
		...(evidence.responderCertificate === undefined
			? {}
			: { responderCertificate: evidence.responderCertificate }),
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
	});
	if (!response.ok) {
		return {
			status: 'unknown',
			detail: {
				source: 'ocsp',
				code: response.code,
				message: response.message,
			},
		};
	}
	const certificate = normalizeCertificate(input.certificate);
	const matchedResponse = response.value.responses?.find(
		(entry) =>
			normalizeHex(entry.certId.serialNumberHex) === normalizeHex(certificate.serialNumberHex),
	);
	if (matchedResponse === undefined) {
		return {
			status: 'unknown',
			detail: {
				source: 'ocsp',
				code: 'certificate_status_missing',
				message: 'OCSP response does not include certificate status for the target certificate',
			},
		};
	}
	if (matchedResponse.certStatus === 'revoked') {
		return {
			status: 'revoked',
			result: {
				status: 'revoked',
				source: 'ocsp',
				message: 'Certificate is revoked according to OCSP evidence',
				...(matchedResponse.revokedAt === undefined
					? {}
					: { revokedAt: matchedResponse.revokedAt }),
				...(matchedResponse.revocationReasonCode === undefined
					? {}
					: { revocationReasonCode: matchedResponse.revocationReasonCode }),
			},
		};
	}
	if (matchedResponse.certStatus === 'good') {
		return {
			status: 'good',
			result: {
				status: 'good',
				source: 'ocsp',
				message: 'Certificate is not revoked according to OCSP evidence',
			},
		};
	}
	return {
		status: 'unknown',
		detail: {
			source: 'ocsp',
			code: 'certificate_status_unknown',
			message: 'OCSP responder returned certificate status unknown',
		},
	};
}

/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(certificate: RevocationCertificateSource): ParsedCertificate {
	if (typeof certificate === 'string') {
		return parseCertificatePem(certificate);
	}
	if (certificate instanceof Uint8Array) {
		return parseCertificateDer(certificate);
	}
	return certificate;
}

/** Strips leading zeros and lowercases a hex string for comparison. */
function normalizeHex(value: string): string {
	const normalized = value.toLowerCase().replace(/^0+/, '');
	return normalized === '' ? '0' : normalized;
}

/** Wraps a value into a successful `CheckCertificateRevocationResult`. */
function revocationSuccess(
	value: CheckCertificateRevocationValue,
): CheckCertificateRevocationResult {
	return { ok: true, value };
}
