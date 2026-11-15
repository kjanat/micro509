/**
 * Revocation orchestration: evaluates CRL and OCSP evidence to produce a
 * unified `good`/`revoked`/`indeterminate` status for a certificate.
 *
 * @module
 */

import { DECODE_REFUSAL_CODES, decodeRefusalOf } from '#micro509/internal/asn1/decode-refusal';
import type { SignatureVerifiers } from '#micro509/internal/crypto/sig-verify';
import {
	callerVerification,
	resolveSignatureVerifiers,
} from '#micro509/internal/crypto/sig-verify';
import type { DecodeFailureCode, Result } from '#micro509/result/result';
import { rethrowIfInvariant } from '#micro509/result/result';
import type {
	CheckCertificateRevocationAgainstCrlResult,
	CrlApplicabilityFailureReason,
	CrlSource,
	DeltaCrlBudget,
	ParsedCertificateRevocationList,
	ParsedRevocationReason,
	UnrecognizedReasonCodePolicy,
} from '#micro509/revocation/crl';
import {
	assertClockSkew,
	assertCrlMaxAge,
	checkCertificateRevocationAgainstCrlsBy,
	coversAllDistributionPointReasons,
	DELTA_CRL_ATTEMPTS_PER_CALL,
	distinctSignedCrls,
	normalizeCrl,
	revocationReasonFromCode,
	signedCrlKey,
} from '#micro509/revocation/crl';
import type {
	OcspCertificateSource,
	OcspRequestSource,
	OcspResponderRevocationPolicy,
	ParsedOcspResponse,
	RevocationSkipReason,
	ValidateOcspResponseInput,
} from '#micro509/revocation/ocsp';
import { validateOcspResponseWith } from '#micro509/revocation/ocsp';
import type { DistributionPointReason } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateDerOrThrow, parseCertificateFromSource } from '#micro509/x509/parse';

export type * from '#micro509/revocation/crl';
export type * from '#micro509/revocation/ocsp';

/** Unified revocation outcome across CRL and OCSP evidence. */
export type RevocationStatus = 'good' | 'revoked' | 'indeterminate' | 'skipped';

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
	/** CRL and/or OCSP evidence to evaluate. Returns `indeterminate` if empty. */
	readonly evidence?: readonly RevocationEvidenceInput[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/**
	 * Clock-skew tolerance in milliseconds. It also widens `crlMaxAgeMs`.
	 * Throws `RangeError` when negative or not finite.
	 */
	readonly clockSkewMs?: number;
	/** Maximum age of each CRL's `thisUpdate` in milliseconds. Unbounded by default. See {@linkcode ValidateCertificateRevocationListInput.maxAgeMs}. */
	readonly crlMaxAgeMs?: number;
	/**
	 * OCSP client profile for every OCSP evidence entry. See
	 * {@linkcode ValidateOcspResponseInput.profile}. Defaults to `'rfc6960'`.
	 */
	readonly ocspProfile?: ValidateOcspResponseInput['profile'];
	/**
	 * Revocation policy for delegated OCSP responders. The CRLs in `evidence`,
	 * delta CRLs included, serve as their revocation evidence. See
	 * {@linkcode OcspResponderRevocationPolicy}. Defaults to
	 * `'nocheck-or-evidence'`.
	 */
	readonly ocspResponderRevocation?: OcspResponderRevocationPolicy;
	/**
	 * Treatment of CRL or OCSP evidence whose CRLReason is unrecognized. See
	 * {@linkcode UnrecognizedReasonCodePolicy}. `'reject'` turns that evidence
	 * into `reason_code_unrecognized`, which also keeps other evidence from
	 * settling the status as `good`. Defaults to `'revoked'`.
	 */
	readonly unrecognizedReasonCode?: UnrecognizedReasonCodePolicy;
	/**
	 * Caller verifiers for signature algorithms micro509 does not verify through
	 * WebCrypto, keyed by dotted-decimal signature algorithm OID, for the CRL and
	 * OCSP evidence. A key that micro509 verifies natively, a key that is no OID,
	 * or a value that is no function throws `RangeError`.
	 */
	readonly signatureVerifiers?: SignatureVerifiers;
}

/** Error codes that {@linkcode checkCertificateRevocation} may surface inside an `indeterminate` result. */
export type CheckCertificateRevocationErrorCode =
	| 'revocation_evidence_missing'
	| 'revocation_status_indeterminate'
	| DecodeFailureCode;

/** Every {@linkcode RevocationIndeterminateReasonCode}, as a runtime array. */
export const REVOCATION_INDETERMINATE_REASON_CODES = [
	'certificate_status_missing',
	'certificate_status_unknown',
	'crl_sign_not_permitted',
	'delta_crl_retry_limit_exceeded',
	'delta_crl_unusable',
	'issuer_mismatch',
	'malformed',
	'next_update_missing',
	'non_applicable',
	'nonce_mismatch',
	'ocsp_signing_missing',
	'reason_code_unrecognized',
	'reason_coverage_incomplete',
	'request_mismatch',
	'responder_id_mismatch',
	'responder_chain_invalid',
	'responder_revoked',
	'responder_revocation_unknown',
	'response_status_invalid',
	'signature_invalid',
	'stale_crl',
	'stale_response',
	'unsupported',
	'limit_exceeded',
] as const;

/** Why a particular piece of evidence could not produce a definitive `good`/`revoked` answer. */
export type RevocationIndeterminateReasonCode =
	(typeof REVOCATION_INDETERMINATE_REASON_CODES)[number];

/** One piece of evidence that failed to produce a definitive revocation answer. */
export interface RevocationIndeterminateEvidence {
	/** Whether this evidence was CRL or OCSP. */
	readonly kind: RevocationEvidenceKind;
	/** Machine-readable reason code. */
	readonly code: RevocationIndeterminateReasonCode;
	/** Human-readable explanation. */
	readonly message: string;
	/** CRL-specific applicability failure reason, when `kind` is `'crl'`. */
	readonly reason?: CrlApplicabilityFailureReason;
}

/** Diagnostic details attached to an `indeterminate` revocation result. */
export interface CheckCertificateRevocationFailureDetails {
	/** Which evidence kinds were attempted (`'crl'`, `'ocsp'`, or both). */
	readonly checkedSources: readonly RevocationEvidenceKind[];
	/** Per-evidence explanations of why no definitive answer was reached. */
	readonly indeterminateEvidence: readonly RevocationIndeterminateEvidence[];
}

/** Revocation status could not be determined from the provided evidence. */
export interface RevocationCheckIndeterminateValue {
	/** Status is indeterminate. */
	readonly status: Extract<RevocationStatus, 'indeterminate'>;
	/** Why revocation status is indeterminate. */
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
	readonly kind: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
}

/** Certificate is revoked according to the checked evidence. */
export interface RevocationCheckRevokedValue {
	/** Certificate is revoked. */
	readonly status: Extract<RevocationStatus, 'revoked'>;
	/** Which evidence kind reported the revocation. */
	readonly kind: RevocationEvidenceKind;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** When the certificate was revoked (from CRL entry or OCSP response). */
	readonly revokedAt?: Date;
	/** CRL reason (from CRL evidence). */
	readonly revocationReason?: ParsedRevocationReason;
	/** CRL reason code (from OCSP evidence). */
	readonly revocationReasonCode?: bigint;
}

/**
 * The certificate carries noRevAvail, so no evidence was consulted (RFC 9608
 * §4). A CRL never lists such a certificate (RFC 9608 §2), so its absence from
 * one shows nothing.
 */
export interface RevocationCheckSkippedValue {
	/** Status is skipped. */
	readonly status: Extract<RevocationStatus, 'skipped'>;
	/** The extension that exempts the certificate. */
	readonly skipReason: Extract<RevocationSkipReason, 'no_rev_avail'>;
	/** Human-readable diagnostic message. */
	readonly message: string;
}

/** Discriminated union of `good`, `revoked`, `indeterminate`, and `skipped` revocation outcomes. */
export type CheckCertificateRevocationValue =
	| RevocationCheckGoodValue
	| RevocationCheckRevokedValue
	| RevocationCheckIndeterminateValue
	| RevocationCheckSkippedValue;

/**
 * Result of {@linkcode checkCertificateRevocation}. Always succeeds (`ok: true`) —
 * the `value.status` discriminator carries the actual outcome.
 */
export type CheckCertificateRevocationResult = Result<CheckCertificateRevocationValue, never>;

/** Internal intermediate result from evaluating a single piece of revocation evidence. */
type RevocationEvidenceCheck =
	| {
			readonly status: 'good';
			readonly result: RevocationCheckGoodValue;
			/** RFC 5280 §6.3.3(d) reasons this CRL covered; absent for OCSP (which is definitive). */
			readonly coveredReasons?: readonly DistributionPointReason[];
	  }
	| { readonly status: 'revoked'; readonly result: RevocationCheckRevokedValue }
	| { readonly status: 'indeterminate'; readonly detail: RevocationIndeterminateEvidence };

/** Extracts OCSP responder URIs from the certificate's Authority Information Access extension. */
export function getCertificateOcspResponderUris(
	certificate: RevocationCertificateSource,
): readonly string[] {
	let parsedCertificate: ParsedCertificate;
	try {
		parsedCertificate = normalizeCertificate(certificate);
	} catch {
		return [];
	}
	const uris: string[] = [];
	const seen = new Set<string>();
	for (const accessDescription of parsedCertificate.authorityInfoAccess ?? []) {
		if (accessDescription.method !== 'ocsp' || accessDescription.location.type !== 'uri') {
			continue;
		}
		const uri = accessDescription.location.value;
		if (seen.has(uri)) {
			continue;
		}
		seen.add(uri);
		uris.push(uri);
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
 * revocation status. Returns the first `revoked` if any. Otherwise an OCSP
 * `good` settles the status, then a CRL `good` once the CRLs together cover
 * every revocation reason, else `indeterminate` with diagnostic details about
 * each indeterminate evidence.
 * Each CRL in `evidence` counts as a delta CRL when it carries the delta CRL
 * indicator and as a complete CRL otherwise, whichever field holds it. Each
 * distinct complete CRL is checked once, updated by the newest delta CRL
 * among them that applies to it, as `checkChainRevocation` does, within the
 * same attempt limits, which the CRL checks of delegated OCSP responders
 * share. A delta CRL
 * that cannot settle the status yields `delta_crl_unusable`, and a candidate
 * the limits leave unread that could change the status
 * `delta_crl_retry_limit_exceeded`; either keeps other
 * evidence from settling it as `good`.
 * A certificate carrying noRevAvail is `skipped` without consulting evidence
 * (RFC 9608 §4). One carrying id-pkix-ocsp-nocheck is still checked against
 * the evidence, which may list it as revoked.
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
	callerInput: CheckCertificateRevocationInput,
): Promise<CheckCertificateRevocationResult> {
	const input = { ...callerInput, at: callerInput.at ?? new Date() };
	assertCrlMaxAge(input.crlMaxAgeMs);
	assertClockSkew(input.clockSkewMs);
	resolveSignatureVerifiers(input.signatureVerifiers);
	const evidence = input.evidence ?? [];
	const checkedSources = evidence.map((entry) => entry.kind);
	if (carriesNoRevAvail(input.certificate)) {
		return revocationSuccess({
			status: 'skipped',
			skipReason: 'no_rev_avail',
			message: 'Certificate carries noRevAvail, so no revocation evidence applies',
		});
	}
	if (evidence.length === 0) {
		return revocationSuccess({
			status: 'indeterminate',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details: {
				checkedSources,
				indeterminateEvidence: [],
			},
		});
	}
	let normalizedCertificate: ParsedCertificate;
	try {
		normalizedCertificate = normalizeCertificate(input.certificate);
	} catch (error) {
		return undecodableCertificateResult(error, checkedSources);
	}
	let ocspGoodResult: RevocationCheckGoodValue | undefined;
	let crlGoodResult: RevocationCheckGoodValue | undefined;
	const crlCoveredReasons = new Set<string>();
	const indeterminateEvidence: RevocationIndeterminateEvidence[] = [];
	for (const result of await checkRevocationEvidence(input, evidence, normalizedCertificate)) {
		if (result.status === 'revoked') {
			return revocationSuccess(result.result);
		}
		if (result.status === 'good') {
			if (result.coveredReasons === undefined) {
				ocspGoodResult ??= result.result;
			} else {
				crlGoodResult ??= result.result;
				for (const reason of result.coveredReasons) {
					crlCoveredReasons.add(reason);
				}
			}
			continue;
		}
		indeterminateEvidence.push(result.detail);
	}
	return settleRevocationEvidence(
		ocspGoodResult,
		crlGoodResult,
		crlCoveredReasons,
		indeterminateEvidence,
		checkedSources,
	);
}

/** The result once no evidence revoked the certificate outright. */
function settleRevocationEvidence(
	ocspGoodResult: RevocationCheckGoodValue | undefined,
	crlGoodResult: RevocationCheckGoodValue | undefined,
	crlCoveredReasons: Set<string>,
	indeterminateEvidence: RevocationIndeterminateEvidence[],
	checkedSources: readonly RevocationEvidenceKind[],
): CheckCertificateRevocationResult {
	const unrecognizedReason = indeterminateEvidence.some(
		(entry) =>
			entry.code === 'reason_code_unrecognized' ||
			entry.code === 'delta_crl_unusable' ||
			entry.code === 'delta_crl_retry_limit_exceeded',
	);
	// An OCSP good is per-certificate and definitive. A CRL good is definitive
	// only once the applicable CRLs together cover every revocation reason.
	if (ocspGoodResult !== undefined && !unrecognizedReason) {
		return revocationSuccess(ocspGoodResult);
	}
	if (
		crlGoodResult !== undefined &&
		!unrecognizedReason &&
		coversAllDistributionPointReasons(crlCoveredReasons)
	) {
		return revocationSuccess(crlGoodResult);
	}
	if (crlGoodResult !== undefined && !coversAllDistributionPointReasons(crlCoveredReasons)) {
		indeterminateEvidence.push({
			kind: 'crl',
			code: 'reason_coverage_incomplete',
			message: 'CRL evidence covers only some revocation reasons',
		});
	}
	return revocationSuccess({
		status: 'indeterminate',
		code: 'revocation_status_indeterminate',
		message: 'No revocation evidence established certificate status',
		details: {
			checkedSources,
			indeterminateEvidence,
		},
	});
}

function undecodableCertificateResult(
	error: unknown,
	checkedSources: readonly RevocationEvidenceKind[],
): CheckCertificateRevocationResult {
	const refusal = decodeRefusalOf(error, DECODE_REFUSAL_CODES);
	return revocationSuccess({
		status: 'indeterminate',
		code: refusal?.code ?? 'malformed',
		message: refusal?.message ?? 'Certificate input is malformed',
		details: {
			checkedSources,
			indeterminateEvidence: [],
		},
	});
}

async function checkRevocationEvidence(
	input: CheckCertificateRevocationInput,
	evidence: readonly RevocationEvidenceInput[],
	certificate: ParsedCertificate,
): Promise<readonly RevocationEvidenceCheck[]> {
	const parsed = evidence.map((entry) =>
		entry.kind === 'crl' ? parseCrlEvidence(entry) : undefined,
	);
	const deltaCrls = distinctSignedCrls(
		parsed.flatMap((entry) =>
			[entry?.crl, entry?.deltaCrl].flatMap((crl) =>
				crl?.kind === 'parsed' && crl.crl.baseCrlNumber !== undefined ? [crl.crl] : [],
			),
		),
	);
	const budget: DeltaCrlBudget = { remaining: DELTA_CRL_ATTEMPTS_PER_CALL };
	const checkedCompleteCrls = new Set<string>();
	const checks: RevocationEvidenceCheck[] = [];
	for (const [index, entry] of evidence.entries()) {
		if (entry.kind === 'ocsp') {
			checks.push(
				await guardedEvidenceCheck('ocsp', () =>
					checkCertificateRevocationWithOcsp(input, entry, certificate, budget),
				),
			);
			continue;
		}
		const crlEntry = parsed[index];
		if (crlEntry === undefined) continue;
		for (const crl of [crlEntry.deltaCrl, crlEntry.crl]) {
			if (crl?.kind === 'indeterminate') checks.push(crl.check);
		}
		for (const completeCrl of completeCrlsOf(crlEntry)) {
			const key = signedCrlKey(completeCrl);
			if (checkedCompleteCrls.has(key)) continue;
			checkedCompleteCrls.add(key);
			checks.push(
				await guardedEvidenceCheck('crl', () =>
					checkCertificateRevocationWithCrl(input, completeCrl, deltaCrls, certificate, budget),
				),
			);
		}
	}
	return checks;
}

/**
 * The CRLs of one evidence entry to check as complete CRLs: its `crl`, and
 * its `deltaCrl` when that carries no delta CRL indicator. A delta CRL in
 * `crl` is still checked, which reports it as no complete CRL.
 */
function completeCrlsOf(
	entry: ReturnType<typeof parseCrlEvidence>,
): readonly ParsedCertificateRevocationList[] {
	return [
		...(entry.crl.kind === 'parsed' ? [entry.crl.crl] : []),
		...(entry.deltaCrl?.kind === 'parsed' && entry.deltaCrl.crl.baseCrlNumber === undefined
			? [entry.deltaCrl.crl]
			: []),
	];
}

/** One evidence check, with an undecodable input reported as indeterminate evidence. */
async function guardedEvidenceCheck(
	kind: RevocationEvidenceKind,
	check: () => Promise<RevocationEvidenceCheck>,
): Promise<RevocationEvidenceCheck> {
	try {
		return await check();
	} catch (error) {
		return undecodableEvidence(kind, error);
	}
}

function undecodableEvidence(
	kind: RevocationEvidenceKind,
	error: unknown,
): RevocationEvidenceCheck {
	rethrowIfInvariant(error);
	const refusal = decodeRefusalOf(error, DECODE_REFUSAL_CODES);
	return {
		status: 'indeterminate',
		detail: {
			kind,
			code: refusal?.code ?? 'malformed',
			message: refusal?.message ?? `${kind.toUpperCase()} evidence input is malformed`,
		},
	};
}

/** One CRL that decoded, or why it does not. */
type ParsedCrlEvidence =
	| { readonly kind: 'parsed'; readonly crl: ParsedCertificateRevocationList }
	| { readonly kind: 'indeterminate'; readonly check: RevocationEvidenceCheck };

/** A CRL evidence entry's complete and delta CRLs, each decoded on its own. */
function parseCrlEvidence(entry: RevocationCrlEvidenceInput): {
	readonly crl: ParsedCrlEvidence;
	readonly deltaCrl: ParsedCrlEvidence | undefined;
} {
	return {
		crl: parseOneCrl(entry.crl),
		deltaCrl: entry.deltaCrl === undefined ? undefined : parseOneCrl(entry.deltaCrl),
	};
}

function parseOneCrl(source: CrlSource): ParsedCrlEvidence {
	try {
		return { kind: 'parsed', crl: normalizeCrl(source) };
	} catch (error) {
		return { kind: 'indeterminate', check: undecodableEvidence('crl', error) };
	}
}

/**
 * Checks one complete CRL from `evidence`, updated by the newest delta CRL
 * among every delta CRL in `evidence` that applies to it, as chain revocation
 * does. A delta CRL that cannot settle the status yields `delta_crl_unusable`.
 */
async function checkCertificateRevocationWithCrl(
	input: CheckCertificateRevocationInput,
	completeCrl: ParsedCertificateRevocationList,
	deltaCrls: readonly ParsedCertificateRevocationList[],
	certificate: ParsedCertificate,
	budget: DeltaCrlBudget,
): Promise<RevocationEvidenceCheck> {
	const outcome = await checkCertificateRevocationAgainstCrlsBy(
		certificate,
		completeCrl,
		deltaCrls,
		{ kind: 'certificate', certificate: input.issuerCertificate },
		{
			...(input.at === undefined ? {} : { at: input.at }),
			...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
			...(input.crlMaxAgeMs === undefined ? {} : { maxAgeMs: input.crlMaxAgeMs }),
			...(input.unrecognizedReasonCode === undefined
				? {}
				: { unrecognizedReasonCode: input.unrecognizedReasonCode }),
		},
		callerVerification(input.signatureVerifiers),
		[budget],
	);
	if (outcome.kind === 'checked') return crlEvidenceCheck(outcome.result);
	return {
		status: 'indeterminate',
		detail:
			outcome.reason === 'retry_limit'
				? {
						kind: 'crl',
						code: 'delta_crl_retry_limit_exceeded',
						message:
							'A delta CRL candidate that could change the status remained after the attempt limit',
					}
				: {
						kind: 'crl',
						code: 'delta_crl_unusable',
						message: 'An applicable delta CRL could not settle the certificate status',
					},
	};
}

/** The evidence check for one CRL result. */
function crlEvidenceCheck(
	result: CheckCertificateRevocationAgainstCrlResult,
): RevocationEvidenceCheck {
	if (result.ok) {
		if (result.value.status === 'revoked') {
			return {
				status: 'revoked',
				result: {
					status: 'revoked',
					kind: 'crl',
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
				kind: 'crl',
				message: 'Certificate is not revoked according to CRL evidence',
			},
			coveredReasons: result.value.coveredReasons,
		};
	}
	return {
		status: 'indeterminate',
		detail: {
			kind: 'crl',
			code: result.code,
			message: result.message,
			...(result.details?.reason === undefined ? {} : { reason: result.details.reason }),
		},
	};
}

/** The {@linkcode validateOcspResponseWith} input for one OCSP evidence entry. */
function ocspEvidenceValidationInput(
	input: CheckCertificateRevocationInput,
	evidence: RevocationOcspEvidenceInput,
): ValidateOcspResponseInput {
	return {
		response: evidence.response,
		issuerCertificate: input.issuerCertificate,
		...(evidence.request === undefined ? {} : { request: evidence.request }),
		...(evidence.responderCertificate === undefined
			? {}
			: { responderCertificate: evidence.responderCertificate }),
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
		...(input.ocspProfile === undefined ? {} : { profile: input.ocspProfile }),
		...(input.ocspResponderRevocation === undefined
			? {}
			: { responderRevocationPolicy: input.ocspResponderRevocation }),
		responderRevocationCrls: (input.evidence ?? []).flatMap((entry) =>
			entry.kind !== 'crl'
				? []
				: entry.deltaCrl === undefined
					? [entry.crl]
					: [entry.crl, entry.deltaCrl],
		),
		...(input.crlMaxAgeMs === undefined
			? {}
			: { responderRevocationCrlMaxAgeMs: input.crlMaxAgeMs }),
		...(input.unrecognizedReasonCode === undefined
			? {}
			: { responderRevocationUnrecognizedReasonCode: input.unrecognizedReasonCode }),
		...(input.signatureVerifiers === undefined
			? {}
			: { signatureVerifiers: input.signatureVerifiers }),
	};
}

/**
 * Evaluates a single OCSP evidence entry via {@linkcode validateOcspResponseWith},
 * spending delta CRL checks of a delegated responder from `budget`.
 */
async function checkCertificateRevocationWithOcsp(
	input: CheckCertificateRevocationInput,
	evidence: RevocationOcspEvidenceInput,
	certificate: ParsedCertificate,
	budget: DeltaCrlBudget,
): Promise<RevocationEvidenceCheck> {
	const response = await validateOcspResponseWith(ocspEvidenceValidationInput(input, evidence), {
		verifiers: resolveSignatureVerifiers(input.signatureVerifiers),
		deltaBudget: budget,
	});
	if (!response.ok) {
		return {
			status: 'indeterminate',
			detail: {
				kind: 'ocsp',
				code: response.code,
				message: response.message,
			},
		};
	}
	const matchedResponse = response.value.responses?.find(
		(entry) =>
			normalizeHex(entry.certId.serialNumberHex) === normalizeHex(certificate.serialNumberHex),
	);
	if (matchedResponse === undefined) {
		return {
			status: 'indeterminate',
			detail: {
				kind: 'ocsp',
				code: 'certificate_status_missing',
				message: 'OCSP response does not include certificate status for the target certificate',
			},
		};
	}
	if (matchedResponse.certStatus === 'revoked') {
		if (
			input.unrecognizedReasonCode === 'reject' &&
			typeof revocationReasonFromCode(matchedResponse.revocationReasonCode) === 'object'
		) {
			return {
				status: 'indeterminate',
				detail: {
					kind: 'ocsp',
					code: 'reason_code_unrecognized',
					message: `OCSP response carries unrecognized reason code ${String(matchedResponse.revocationReasonCode)}`,
				},
			};
		}
		return {
			status: 'revoked',
			result: {
				status: 'revoked',
				kind: 'ocsp',
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
				kind: 'ocsp',
				message: 'Certificate is not revoked according to OCSP evidence',
			},
		};
	}
	return {
		status: 'indeterminate',
		detail: {
			kind: 'ocsp',
			code: 'certificate_status_unknown',
			message: 'OCSP responder returned certificate status unknown',
		},
	};
}

/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(certificate: RevocationCertificateSource): ParsedCertificate {
	return hasParsedCertificateShape(certificate)
		? parseCertificateDerOrThrow(new Uint8Array(certificate.der))
		: parseCertificateFromSource(certificate);
}

/** Whether `source` parses and carries noRevAvail in its signed DER. */
function carriesNoRevAvail(source: RevocationCertificateSource): boolean {
	try {
		return normalizeCertificate(source).noRevAvail === true;
	} catch (error) {
		rethrowIfInvariant(error);
		return false;
	}
}

function hasParsedCertificateShape(value: RevocationCertificateSource): value is ParsedCertificate {
	return typeof value !== 'string' && 'subjectPublicKeyInfoDer' in value;
}

/** Lowercases a hex string for bytewise serial-number comparison. */
function normalizeHex(value: string): string {
	return value.toLowerCase();
}

/** Wraps a value into a successful `CheckCertificateRevocationResult`. */
function revocationSuccess(
	value: CheckCertificateRevocationValue,
): CheckCertificateRevocationResult {
	return { ok: true, value };
}
