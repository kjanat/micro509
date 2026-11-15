/**
 * Chain-level revocation orchestration.
 *
 * Evaluates CRL and OCSP evidence for an entire validated certificate chain,
 * implementing the revocation checking portion of RFC 5280 §6.3.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-6.3 | RFC 5280 §6.3 CRL Validation}
 * @module
 */

import { toHex } from '#micro509/internal/asn1/asn1';
import { DECODE_REFUSAL_CODES, decodeRefusalOf } from '#micro509/internal/asn1/decode-refusal';
import type {
	CallerVerification,
	SignatureVerifier,
	SignatureVerifiers,
} from '#micro509/internal/crypto/sig-verify';
import { resolveSignatureVerifiers } from '#micro509/internal/crypto/sig-verify';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn';
import { createSpkiDistrustCheck } from '#micro509/internal/verify/spki-distrust';
import type { WorkingPublicKey } from '#micro509/internal/verify/verify-path';
import {
	anchorWorkingKey,
	carriesTrustAnchorKey,
	certificateWorkingKey,
	pathWorkingKey,
	workingParametersAt,
} from '#micro509/internal/verify/verify-path';
import type { DecodeFailureCode } from '#micro509/result/result';
import type {
	AuthenticatedCrlCheckOutcome,
	CrlCheckOptions,
	CrlSource,
	checkCertificateRevocationAgainstCrl,
	DeltaCrlBudget,
	ParsedCertificateRevocationList,
	ParsedRevocationReason,
	UnrecognizedReasonCodePolicy,
} from '#micro509/revocation/crl';
import {
	assertCrlMaxAge,
	authenticateCrl,
	checkCertificateRevocationAgainstCrlsBy,
	checkRevocationAgainstAuthenticatedCrl,
	coversAllDistributionPointReasons,
	DELTA_CRL_ATTEMPTS_PER_BASE,
	distinctSignedCrls,
	irremovableCrlRevocation,
	isCrlApplicableTo,
	normalizeCrl,
	rankApplicableDeltaCrls,
	revocationReasonFromCode,
} from '#micro509/revocation/crl';
import type {
	OcspResponderRevocationPolicy,
	ParsedOcspResponse,
	ParsedOcspSingleResponse,
	RevocationSkipReason,
	ValidateOcspResponseFailure,
	ValidateOcspResponseInput,
	ValidateOcspResponseResult,
} from '#micro509/revocation/ocsp';
import {
	parseOcspResponseDerOrThrow,
	parseOcspResponsePemOrThrow,
	revocationSkipReasonOf,
	validateOcspResponseBy,
} from '#micro509/revocation/ocsp';
import type { RevocationCertificateSource } from '#micro509/revocation/revocation';
import type { CandidatePath, TrustAnchor } from '#micro509/verify/verify';
import { verifyCertificateChain } from '#micro509/verify/verify';
import type { DistributionPointReason } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateDer, parseCertificateFromSource } from '#micro509/x509/parse';

export type { CrlSource };

// Input Types

/**
 * OCSP response in any supported format.
 *
 * Accepts PEM string or DER bytes. Used for
 * {@linkcode CheckChainRevocationInput.ocspResponses}.
 */
export type OcspResponseSource = string | Uint8Array;

/** A locally trusted OCSP responder bound to the CA scope it may serve. */
export interface TrustedOcspResponder {
	/** Certificate of the CA for whose certificates the responder is trusted. */
	readonly issuerCertificate: RevocationCertificateSource;
	/** Responder certificate trusted within that issuer's scope. */
	readonly responderCertificate: RevocationCertificateSource;
}

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
	 * evidence. Defaults to `'nocheck-or-evidence'`.
	 */
	readonly ocspResponderRevocation?: OcspResponderRevocationPolicy;
	/**
	 * Maximum age of a CRL's `thisUpdate` at the evaluation time, in
	 * milliseconds. An older CRL, or one without `nextUpdate` when this is
	 * unset, settles only a revocation other than certificateHold of an
	 * unexpired certificate (RFC 5280 §5.3.1). Applies to CRLs for chain
	 * certificates, CRL signers and delegated OCSP responders. Unbounded by
	 * default. RFC 5280 §3.3 leaves the required recency of revocation data to
	 * local policy.
	 */
	readonly crlMaxAgeMs?: number;
	/**
	 * Clock-skew tolerance in milliseconds for CRL and OCSP `thisUpdate`/
	 * `nextUpdate` checks. It also widens `crlMaxAgeMs` by the same amount.
	 * Defaults to `0`.
	 */
	readonly clockSkewMs?: number;
	/**
	 * OCSP client profile for every OCSP response. See
	 * {@linkcode ValidateOcspResponseInput.profile}. `'rfc9919'` turns a
	 * response without `nextUpdate` into `ocsp_next_update_missing`. Defaults
	 * to `'rfc6960'`.
	 */
	readonly ocspProfile?: ValidateOcspResponseInput['profile'];
	/**
	 * Treatment of CRL entries and OCSP responses whose CRLReason is
	 * unrecognized, including the CRLs for CRL signers and delegated OCSP
	 * responders. See {@linkcode UnrecognizedReasonCodePolicy}. `'reject'`
	 * makes that evidence yield `crl_reason_code_unrecognized` or
	 * `ocsp_reason_code_unrecognized`, which outranks a `good` verdict from
	 * other evidence. Defaults to `'revoked'`.
	 */
	readonly unrecognizedReasonCode?: UnrecognizedReasonCodePolicy;
	/**
	 * Whether a CRL that a delegated CRL signer signed may establish that
	 * signer's own status. RFC 5280 §6.3.3 (f) and X.509 (2019) §9.1.5 leave
	 * it open.
	 *
	 * - `'delegated'`: only when the signer's cRLDistributionPoints names the
	 *   signer as cRLIssuer, the delegation PKITS 4.14.30 validates (default)
	 * - `'any'`: any such CRL that covers the signer, such as one under its
	 *   issuer's name signed with the signer's separate CRL key
	 *
	 * A revocation of the signer in such a CRL counts under either value.
	 */
	readonly crlSignerSelfEvidence?: 'delegated' | 'any';
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
	 * criterion 1), each bound to the issuing CA for which it is authorized.
	 * A response signed by a matching responder is accepted without delegated-
	 * responder issuance, EKU, and revocation checks only in that issuer scope.
	 */
	readonly trustedOcspResponders?: readonly TrustedOcspResponder[];
	/** Evaluation time. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Revocation policy. */
	readonly policy?: RevocationPolicy;
	/**
	 * Caller verifiers for signature algorithms micro509 does not verify through
	 * WebCrypto, keyed by dotted-decimal signature algorithm OID, for CRL and OCSP
	 * signatures and the signer paths checked here. A CRL or OCSP signer inside
	 * `chain` verifies with the key parameters it inherits along `chain`
	 * (RFC 5280 §6.1.4 (e)). A key that micro509 verifies natively, a key that is
	 * no OID, or a value that is no function throws `RangeError`.
	 */
	readonly signatureVerifiers?: SignatureVerifiers;
	/**
	 * SHA-256 hashes of complete DER SubjectPublicKeyInfo values to distrust in
	 * the certification paths of CRL signers and delegated OCSP responders
	 * outside `chain`. Supply 64 hexadecimal characters per hash
	 * (case-insensitive, no separators). Defaults to an empty list. Malformed
	 * entries throw RangeError. A signer whose path carries one yields no
	 * evidence.
	 */
	readonly distrustedSpkiSha256?: readonly string[];
	/**
	 * The bare trust anchor that issued the last certificate of `chain`, when
	 * the path ends below one (RFC 5280 §6.1.1 (d)). The last certificate is
	 * then certificate 1 of the path and is checked too (RFC 5280 §6.1.3
	 * (a)(3)), with the anchor as its issuer: its key signs CRLs and OCSP
	 * responses and certifies delegated signers (X.509 (2019) §7.5). Omitted,
	 * the last certificate of `chain` is the trust anchor and is not checked. A
	 * chain that ends with the anchor's own certificate, or whose last
	 * certificate the anchor did not issue, throws `RangeError`.
	 */
	readonly trustAnchor?: TrustAnchor;
}

/**
 * The issuer of a certificate under check: the next certificate of the chain,
 * or the bare trust anchor above it.
 */
type RevocationIssuer =
	| { readonly kind: 'certificate'; readonly certificate: ParsedCertificate }
	| { readonly kind: 'trust_anchor'; readonly trustAnchor: TrustAnchor };

function sameIssuer(a: RevocationIssuer, b: RevocationIssuer): boolean {
	if (a.kind === 'certificate' && b.kind === 'certificate') {
		return sameCertificate(a.certificate, b.certificate);
	}
	return a.kind === 'trust_anchor' && b.kind === 'trust_anchor' && a.trustAnchor === b.trustAnchor;
}

/** `certificate` as an issuer: the bare trust anchor when it carries the anchor's name and key. */
function issuerOf(
	certificate: ParsedCertificate,
	trustAnchor: TrustAnchor | undefined,
): RevocationIssuer {
	return trustAnchor !== undefined && carriesTrustAnchorKey(certificate, trustAnchor)
		? { kind: 'trust_anchor', trustAnchor }
		: { kind: 'certificate', certificate };
}

/** The certificate that signed CRL or OCSP evidence, for its `source`. */
function signerCertificateOf(
	signer: RevocationIssuer,
): { readonly signerCertificate: ParsedCertificate } | Record<never, never> {
	return signer.kind === 'certificate' ? { signerCertificate: signer.certificate } : {};
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
 * - **Freshness**: `crl_expired`, `ocsp_response_expired`,
 *   `ocsp_next_update_missing`
 * - **Delta CRL**: `delta_crl_unusable` when an authenticated, current delta
 *   CRL cannot settle the status, `delta_crl_retry_limit_exceeded` when delta
 *   CRL candidates remain after the attempt limit. Either one outranks a
 *   `good` verdict from other evidence.
 * - **Reason code**: `crl_reason_code_unrecognized` and
 *   `ocsp_reason_code_unrecognized` when evidence revokes the certificate with
 *   an unrecognized CRLReason under `unrecognizedReasonCode: 'reject'`. Either
 *   one outranks a `good` verdict from other evidence.
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
	'ocsp_next_update_missing',
	// OCSP specific
	'ocsp_status_unknown',
	// Delta CRL
	'delta_crl_unusable',
	'delta_crl_retry_limit_exceeded',
	// Reason code
	'crl_reason_code_unrecognized',
	'ocsp_reason_code_unrecognized',
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
				readonly reason?: ParsedRevocationReason;
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
	  }
	| {
			/** The certificate that was evaluated. */
			readonly certificate: ParsedCertificate;
			/** Revocation checking does not apply to the certificate (RFC 9608 §4). */
			readonly status: 'skipped';
			/**
			 * The extension that exempts the certificate: `'no_rev_avail'` for
			 * noRevAvail (RFC 9608 §2) or `'ocsp_nocheck'` for id-pkix-ocsp-nocheck.
			 */
			readonly skipReason: RevocationSkipReason;
			/** Never present on a `skipped` verdict. */
			readonly source?: undefined;
			/** Never present on a `skipped` verdict. */
			readonly indeterminateReasons?: undefined;
			/** Never present on a `skipped` verdict. */
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
export type RevocationExecutionError = RevocationParseError | RevocationProcessingError;

/** Revocation evidence that did not parse. */
export interface RevocationParseError {
	/** Error category. */
	readonly kind: 'parse_error';
	/** `malformed`, or the refusal for evidence micro509 does not decode. */
	readonly code: DecodeFailureCode;
	/** Human-readable error description. */
	readonly message: string;
	/** Which evidence caused the error (e.g., CRL issuer DN). */
	readonly evidenceIdentifier?: string;
}

/** Revocation evidence that parsed but could not be processed. */
export interface RevocationProcessingError {
	/** Error category. */
	readonly kind: 'unsupported_extension' | 'internal_error';
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
	candidate: RevocationIssuer,
	chain: readonly ParsedCertificate[],
	extraCertificates: readonly RevocationCertificateSource[],
	at: Date,
	ctx: SignerValidationContext,
): Promise<boolean> {
	if (candidate.kind === 'trust_anchor') {
		return true;
	}
	const signer = candidate.certificate;
	if (chain.some((c) => sameCertificate(c, signer))) {
		return true;
	}
	if (ctx.trustAnchor !== undefined) {
		return await chainsToBareAnchor(signer, chain, extraCertificates, at, ctx.trustAnchor, ctx);
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
		...signerPathOptions(ctx),
	});
	if (result.ok) recordPathKeys(result.value, ctx);
	return result.ok;
}

/**
 * Remembers the working key (RFC 5280 §6.1.4 (e)) and the issuer that a
 * signer's validated path gives each of its certificates outside the checked
 * chain.
 */
function recordPathKeys(path: CandidatePath, ctx: SignerValidationContext): void {
	path.chain.forEach((certificate, index) => {
		if (ctx.chain.some((member) => sameCertificate(member, certificate))) return;
		const key = certCacheKey(certificate);
		ctx.pathKeys.set(key, pathWorkingKey(path, index));
		const issuer = path.chain[index + 1];
		if (issuer !== undefined) {
			ctx.pathIssuers.set(key, issuerOf(issuer, ctx.trustAnchor));
		} else if (!path.anchorCertificateInChain) {
			ctx.pathIssuers.set(key, { kind: 'trust_anchor', trustAnchor: path.trustAnchor });
		}
	});
}

/**
 * {@linkcode crlSignerChainsToAnchor} below a bare trust anchor: every chain
 * certificate is a candidate intermediate, and the anchor ends the path.
 */
async function chainsToBareAnchor(
	signer: ParsedCertificate,
	chain: readonly ParsedCertificate[],
	extraCertificates: readonly RevocationCertificateSource[],
	at: Date,
	trustAnchor: TrustAnchor,
	ctx: SignerValidationContext,
): Promise<boolean> {
	const pool: ParsedCertificate[] = [];
	for (const parsed of [...chain, ...extraCertificates.flatMap(parsedOrEmpty)]) {
		if (!sameCertificate(parsed, signer) && !pool.some((known) => sameCertificate(known, parsed))) {
			pool.push(parsed);
		}
	}
	const result = await verifyCertificateChain({
		leaf: signer.der,
		intermediates: pool.map((certificate) => certificate.der),
		roots: [],
		trustAnchors: [trustAnchor],
		at,
		...signerPathOptions(ctx),
	});
	if (result.ok) recordPathKeys(result.value, ctx);
	return result.ok;
}

/** The caller's verifiers and distrust for a signer's certification path. */
function signerPathOptions(ctx: SignerValidationContext): {
	readonly signatureVerifiers?: SignatureVerifiers;
	readonly distrustedSpkiSha256?: readonly string[];
} {
	return {
		...(ctx.signatureVerifiers !== undefined && { signatureVerifiers: ctx.signatureVerifiers }),
		...(ctx.distrustedSpkiSha256 !== undefined && {
			distrustedSpkiSha256: ctx.distrustedSpkiSha256,
		}),
	};
}

function parsedOrEmpty(source: RevocationCertificateSource): readonly ParsedCertificate[] {
	const parsed = parseCertificateSafe(source);
	return parsed === undefined ? [] : [parsed];
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
	readonly crlMaxAgeMs: number | undefined;
	readonly clockSkewMs: number | undefined;
	readonly unrecognizedReasonCode: UnrecognizedReasonCodePolicy;
	readonly crlSignerSelfEvidence: NonNullable<RevocationPolicy['crlSignerSelfEvidence']>;
	readonly signatureVerifiers: SignatureVerifiers | undefined;
	readonly distrustedSpkiSha256: readonly string[] | undefined;
	readonly verifiers: ReadonlyMap<string, SignatureVerifier>;
	/** Delta CRL checks left for the whole chain. */
	readonly deltaBudget: DeltaCrlBudget;
	/** The RFC 5280 §6.1 working key of a CRL or OCSP signer. */
	readonly workingKeyOf: (certificate: ParsedCertificate) => WorkingPublicKey;
	/** Working keys of signers outside the chain, from their validated paths. */
	readonly pathKeys: Map<string, WorkingPublicKey>;
	/** Issuers of signers outside the chain, from their validated paths. */
	readonly pathIssuers: Map<string, RevocationIssuer>;
	/** The bare trust anchor above the chain, when it ends below one. */
	readonly trustAnchor: TrustAnchor | undefined;
}

/** Caller verification for a signature by `signer`, with its working key parameters. */
function signerVerification(
	ctx: SignerValidationContext,
	signer: RevocationIssuer,
): CallerVerification {
	return {
		verifiers: ctx.verifiers,
		workingParameters: {
			parametersDer:
				signer.kind === 'trust_anchor'
					? anchorWorkingKey(signer.trustAnchor).parametersDer
					: ctx.workingKeyOf(signer.certificate).parametersDer,
		},
	};
}

/**
 * Working keys along `chain`: a member inherits key parameters from the members
 * above it (RFC 5280 §6.1.4 (e)); any other certificate keeps its own.
 */
function chainWorkingKeys(
	chain: readonly ParsedCertificate[],
	anchorKey: WorkingPublicKey | undefined,
): (certificate: ParsedCertificate) => WorkingPublicKey {
	const top = chain[chain.length - 1];
	return (certificate) => {
		const index = chain.findIndex((member) => sameCertificate(member, certificate));
		if (top === undefined || index < 0) return certificateWorkingKey(certificate);
		return {
			algorithmOid: certificate.publicKeyAlgorithmOid,
			parametersDer:
				anchorKey === undefined
					? workingParametersAt(chain, index, chain.length - 2, certificateWorkingKey(top))
					: workingParametersAt(chain, index, chain.length - 1, anchorKey),
		};
	};
}

/** A cache key for a certificate: its DER, so two certificates never share one. */
function certCacheKey(cert: ParsedCertificate): string {
	return toHex(cert.der);
}

/**
 * Validates that a CRL signer certificate is not revoked.
 * Uses memoization to avoid redundant checks and detect cycles.
 */
async function validateCrlSigner(
	candidate: RevocationIssuer,
	ctx: SignerValidationContext,
): Promise<SignerValidationState> {
	if (candidate.kind === 'trust_anchor') {
		return 'resolved-valid';
	}
	const signer = candidate.certificate;
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

	// If signer is in the validated chain, it's trusted
	// (Chain was already validated before revocation checking)
	const isInChain = ctx.chain.some((c) => sameCertificate(c, signer));
	if (isInChain) {
		ctx.cache.set(key, 'resolved-valid');
		return 'resolved-valid';
	}

	const signerIssuer = ctx.pathIssuers.get(key);
	if (signerIssuer === undefined) {
		ctx.cache.set(key, 'resolved-indeterminate');
		return 'resolved-indeterminate';
	}

	const signerRevocation =
		revocationSkipReason(signer) === undefined
			? await checkSignerRevocation(signer, signerIssuer, ctx)
			: 'resolved-valid';
	const status =
		signerRevocation === 'resolved-valid'
			? statusBelow(await validateCrlSigner(signerIssuer, ctx))
			: signerRevocation;
	ctx.cache.set(key, status);
	return status;
}

/**
 * A good or exempt signer's status once its issuer's is known: RFC 5280
 * §6.3.3 (f) validates the whole path of a CRL issuer, so an issuer that is
 * not known good leaves the signer indeterminate. RFC 9608 §4 exempts only the
 * certificate carrying noRevAvail or id-pkix-ocsp-nocheck.
 */
function statusBelow(issuerStatus: SignerValidationState): SignerValidationState {
	return issuerStatus === 'resolved-valid' ? 'resolved-valid' : 'resolved-indeterminate';
}

/**
 * Checks if a CRL signer certificate is revoked by examining available CRLs.
 * Recursively validates the CRL signer of any CRL used to check revocation.
 */
async function checkSignerRevocation(
	signer: ParsedCertificate,
	issuer: RevocationIssuer,
	ctx: SignerValidationContext,
): Promise<SignerValidationState> {
	// A `good` from one CRL does not end the search: a later CRL may report the
	// signer revoked, and a revoked verdict from any CRL wins.
	const coveredReasons = new Set<string>();
	let sawUnsettledEvidence = false;
	const crls = distinctSignedCrls(
		ctx.crls.flatMap((source) => {
			try {
				return [normalizeCrl(source)];
			} catch {
				return [];
			}
		}),
	);
	const deltaCrls = crls.filter((crl) => crl.baseCrlNumber !== undefined);
	for (const crl of crls) {
		if (crl.baseCrlNumber !== undefined) continue;
		const outcome = await checkSignerAgainstCrlAuthorities(signer, issuer, crl, deltaCrls, ctx);
		if (outcome.kind === 'revoked') {
			return 'resolved-revoked';
		}
		if (outcome.kind === 'unrecognized_reason' || outcome.kind === 'unsettled_delta') {
			sawUnsettledEvidence = true;
			continue;
		}
		for (const reason of outcome.reasons) {
			coveredReasons.add(reason);
		}
	}
	if (sawUnsettledEvidence) {
		return 'resolved-indeterminate';
	}
	return coversAllDistributionPointReasons(coveredReasons)
		? 'resolved-valid'
		: 'resolved-indeterminate';
}

/**
 * What one CRL settles about a signer: a revoked verdict, an entry
 * `unrecognizedReasonCode: 'reject'` refuses, a delta CRL that cannot settle
 * the status, or the reasons it covers.
 */
type SignerCrlOutcome =
	| { readonly kind: 'revoked' }
	| { readonly kind: 'unrecognized_reason' }
	| { readonly kind: 'unsettled_delta' }
	| { readonly kind: 'reasons'; readonly reasons: readonly DistributionPointReason[] };

const SIGNER_CRL_NO_EVIDENCE = {
	kind: 'reasons',
	reasons: [],
} as const satisfies SignerCrlOutcome;

/**
 * Evaluates one CRL against a signer with each key that may have signed it:
 * the signer's issuer, then an indirect CRL issuer whose path validates, the
 * signer itself included. The first key whose check yields evidence settles
 * the CRL.
 */
async function checkSignerAgainstCrlAuthorities(
	signer: ParsedCertificate,
	issuer: RevocationIssuer,
	crl: ParsedCertificateRevocationList,
	deltaCrls: readonly ParsedCertificateRevocationList[],
	ctx: SignerValidationContext,
): Promise<SignerCrlOutcome> {
	const baseBudget = { remaining: DELTA_CRL_ATTEMPTS_PER_BASE };
	for (const authority of collectCrlSignerCandidates(
		crl,
		issuer,
		ctx.extraCertificates,
		ctx.chain,
		ctx.trustAnchor,
	)) {
		if (
			!sameIssuer(authority, issuer) &&
			!(await crlSignerChainsToAnchor(authority, ctx.chain, ctx.extraCertificates, ctx.at, ctx))
		) {
			continue;
		}
		const outcome = await checkSignerAgainstCrl(signer, authority, crl, deltaCrls, ctx, [
			baseBudget,
			ctx.deltaBudget,
		]);
		if (outcome.kind !== 'reasons' || outcome.reasons.length > 0) return outcome;
	}
	return SIGNER_CRL_NO_EVIDENCE;
}

/**
 * Evaluates one CRL against a signer. A CRL that does not parse or does not
 * apply yields no evidence. Its `good` needs a CRL signer known good, and its
 * revocation one not known revoked. A CRL the signer itself signed vouches
 * for it as `crlSignerSelfEvidence` allows.
 */
async function checkSignerAgainstCrl(
	signer: ParsedCertificate,
	issuer: RevocationIssuer,
	crl: ParsedCertificateRevocationList,
	deltaCrls: readonly ParsedCertificateRevocationList[],
	ctx: SignerValidationContext,
	budgets: readonly DeltaCrlBudget[],
): Promise<SignerCrlOutcome> {
	const outcome = await checkCertificateRevocationAgainstCrlsBy(
		signer,
		crl,
		deltaCrls,
		issuer,
		{
			at: ctx.at,
			...(ctx.crlMaxAgeMs === undefined ? {} : { maxAgeMs: ctx.crlMaxAgeMs }),
			...(ctx.clockSkewMs === undefined ? {} : { clockSkewMs: ctx.clockSkewMs }),
			unrecognizedReasonCode: ctx.unrecognizedReasonCode,
		},
		signerVerification(ctx, issuer),
		budgets,
	);
	if (outcome.kind === 'unsettled') {
		return { kind: 'unsettled_delta' };
	}
	const result = outcome.result;
	if (!result.ok) {
		return result.code === 'reason_code_unrecognized'
			? { kind: 'unrecognized_reason' }
			: SIGNER_CRL_NO_EVIDENCE;
	}
	const selfSigned = issuer.kind === 'certificate' && sameCertificate(issuer.certificate, signer);
	if (selfSigned && ctx.crlSignerSelfEvidence === 'delegated' && !delegatesOwnStatus(signer)) {
		return result.value.status === 'revoked' ? { kind: 'revoked' } : SIGNER_CRL_NO_EVIDENCE;
	}
	const issuerStatus = selfSigned ? 'resolved-valid' : await validateCrlSigner(issuer, ctx);
	if (result.value.status === 'revoked') {
		return issuerStatus === 'resolved-revoked' ? SIGNER_CRL_NO_EVIDENCE : { kind: 'revoked' };
	}
	return issuerStatus === 'resolved-valid'
		? { kind: 'reasons', reasons: result.value.coveredReasons }
		: SIGNER_CRL_NO_EVIDENCE;
}

/** Whether `signer`'s cRLDistributionPoints names `signer` itself as cRLIssuer. */
function delegatesOwnStatus(signer: ParsedCertificate): boolean {
	const subject = signer.subject.derHex.toLowerCase();
	return (signer.crlDistributionPoints ?? []).some(
		(point) =>
			point.crlIssuer?.some(
				(name) => name.type === 'directoryName' && name.derHex.toLowerCase() === subject,
			) === true,
	);
}

/** Builds the `revoked` CertificateRevocationStatus for a CRL hit. */
function buildCrlRevokedStatus(
	cert: ParsedCertificate,
	signer: RevocationIssuer,
	thisUpdate: Date,
	revocationDate: Date,
	reasonCode?: ParsedRevocationReason,
): CertificateRevocationStatus {
	return {
		certificate: cert,
		status: 'revoked',
		source: { kind: 'crl', ...signerCertificateOf(signer), thisUpdate },
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

interface OcspHoldEvidence {
	readonly status: CertificateRevocationStatus;
	readonly thisUpdate: Date;
}

type ClassifiedOcspEvidence =
	| { readonly kind: 'good'; readonly thisUpdate: Date }
	| { readonly kind: 'hold'; readonly evidence: OcspHoldEvidence }
	| { readonly kind: 'revoked'; readonly status: CertificateRevocationStatus }
	| { readonly kind: 'unknown' }
	| { readonly kind: 'unrecognized_reason' };

type ApplicableOcspResponse =
	| {
			readonly kind: 'applicable';
			readonly parsed: ParsedOcspResponse;
			readonly entry: ParsedOcspSingleResponse;
	  }
	| { readonly kind: 'parse_error'; readonly error: RevocationParseError }
	| { readonly kind: 'not_applicable' };

/** Parses an OCSP response from PEM string or DER bytes. */
function parseOcspResponseFromSource(source: OcspResponseSource): ParsedOcspResponse {
	if (typeof source === 'string') {
		return parseOcspResponsePemOrThrow(source);
	}
	return parseOcspResponseDerOrThrow(source);
}

function evidenceParseError(error: unknown, fallbackMessage: string): RevocationParseError {
	return {
		kind: 'parse_error',
		code: decodeRefusalOf(error, DECODE_REFUSAL_CODES)?.code ?? 'malformed',
		message: error instanceof Error ? error.message : fallbackMessage,
	};
}

/** Parses one OCSP source and locates the entry for the certificate under evaluation. */
function findApplicableOcspResponse(
	source: OcspResponseSource,
	cert: ParsedCertificate,
): ApplicableOcspResponse {
	let parsed: ParsedOcspResponse;
	try {
		parsed = parseOcspResponseFromSource(source);
	} catch (error) {
		return { kind: 'parse_error', error: evidenceParseError(error, 'OCSP response parse failed') };
	}
	const entry = (parsed.responses ?? []).find(
		(single) => normalizeHex(single.certId.serialNumberHex) === normalizeHex(cert.serialNumberHex),
	);
	return entry === undefined ? { kind: 'not_applicable' } : { kind: 'applicable', parsed, entry };
}

/** Returns the later of two evidence timestamps, tolerating an empty accumulator. */
function laterEvidenceDate(current: Date | undefined, candidate: Date): Date {
	return current === undefined || candidate.getTime() > current.getTime() ? candidate : current;
}

/** Builds a definitive OCSP-revoked status from a validated response entry. */
function buildOcspRevokedStatus(
	cert: ParsedCertificate,
	thisUpdate: Date,
	revocationDate: Date,
	reason: ParsedRevocationReason | undefined,
): CertificateRevocationStatus {
	return {
		certificate: cert,
		status: 'revoked',
		source: { kind: 'ocsp', thisUpdate },
		revocationInfo: {
			revocationDate,
			...(reason !== undefined ? { reason } : {}),
		},
	};
}

/** Classifies one fully validated OCSP entry for aggregation. */
function classifyValidatedOcspEntry(
	cert: ParsedCertificate,
	entry: ParsedOcspSingleResponse,
	unrecognizedReasonCode: UnrecognizedReasonCodePolicy,
): ClassifiedOcspEvidence {
	if (entry.certStatus === 'good') {
		return { kind: 'good', thisUpdate: entry.thisUpdate };
	}
	if (entry.certStatus === 'unknown') {
		return { kind: 'unknown' };
	}
	const reason = revocationReasonFromCode(entry.revocationReasonCode);
	if (unrecognizedReasonCode === 'reject' && typeof reason === 'object') {
		return { kind: 'unrecognized_reason' };
	}
	const status = buildOcspRevokedStatus(cert, entry.thisUpdate, entry.revokedAt, reason);
	return reason === 'certificateHold'
		? { kind: 'hold', evidence: { status, thisUpdate: entry.thisUpdate } }
		: { kind: 'revoked', status };
}

/** Builds the definitive OCSP-good result or the accumulated indeterminate result. */
function finalizeOcspEvidence(
	cert: ParsedCertificate,
	freshestGoodThisUpdate: Date | undefined,
	reasons: Set<RevocationIndeterminateReason>,
	executionErrors: readonly RevocationExecutionError[],
): EvidenceEvaluation {
	if (freshestGoodThisUpdate !== undefined) {
		return {
			status: {
				certificate: cert,
				status: 'good',
				source: { kind: 'ocsp', thisUpdate: freshestGoodThisUpdate },
			},
			executionErrors,
		};
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

/** Maps a {@linkcode validateOcspResponse} failure code to an indeterminate reason. */
function ocspIndeterminateReasonFromFailure(
	code: ValidateOcspResponseFailure['code'],
): RevocationIndeterminateReason {
	switch (code) {
		case 'stale_response':
			return 'ocsp_response_expired';
		case 'next_update_missing':
			return 'ocsp_next_update_missing';
		case 'responder_id_mismatch':
		case 'responder_chain_invalid':
		case 'ocsp_signing_missing':
			return 'ocsp_responder_not_authorized';
		case 'responder_revoked':
			return 'ocsp_responder_revoked';
		case 'signature_invalid':
		case 'responder_revocation_unknown':
		case 'malformed':
		case 'unsupported':
		case 'limit_exceeded':
			return 'ocsp_responder_indeterminate';
		case 'response_status_invalid':
		case 'issuer_mismatch':
		case 'nonce_mismatch':
		case 'request_mismatch':
			return 'no_applicable_ocsp';
		default: {
			const _exhaustive: never = code;
			throw new Error(`Unhandled ValidateOcspResponse failure code: ${String(_exhaustive)}`);
		}
	}
}

/** Validation failures worth retrying with an explicit responder certificate. */
const OCSP_RESPONDER_FAILURE_CODES: ReadonlySet<ValidateOcspResponseFailure['code']> = new Set([
	'signature_invalid',
	'responder_id_mismatch',
	'responder_chain_invalid',
	'ocsp_signing_missing',
	'malformed',
	'unsupported',
	'limit_exceeded',
]);

/**
 * Validates an OCSP response, retrying with caller-provided extra certificates
 * as explicit responder certificates when embedded discovery fails.
 */
async function validateOcspResponseWithResponderFallback(
	response: ParsedOcspResponse,
	cert: ParsedCertificate,
	issuer: RevocationIssuer,
	input: CheckChainRevocationInput,
	at: Date,
	signerCtx: SignerValidationContext,
): Promise<ValidateOcspResponseResult> {
	const context = {
		verifiers: signerCtx.verifiers,
		issuerWorkingKey:
			issuer.kind === 'certificate'
				? signerCtx.workingKeyOf(issuer.certificate)
				: anchorWorkingKey(issuer.trustAnchor),
		deltaBudget: signerCtx.deltaBudget,
		...(signerCtx.distrustedSpkiSha256 !== undefined && {
			distrustedSpkiSha256: signerCtx.distrustedSpkiSha256,
		}),
	};
	const trustedOcspResponders = input.trustedOcspResponders
		?.filter((trusted) => {
			const trustedIssuer = parseCertificateSafe(trusted.issuerCertificate);
			if (trustedIssuer === undefined) return false;
			return issuer.kind === 'certificate'
				? sameCertificate(trustedIssuer, issuer.certificate)
				: carriesTrustAnchorKey(trustedIssuer, issuer.trustAnchor);
		})
		.map((trusted) => trusted.responderCertificate);
	const ocspIssuer =
		issuer.kind === 'certificate' ? issuer : { ...issuer, certificateIssuer: cert.issuer };
	const shared = {
		at,
		...(trustedOcspResponders !== undefined ? { trustedOcspResponders } : {}),
		...(input.policy?.ocspResponderRevocation !== undefined
			? { responderRevocationPolicy: input.policy.ocspResponderRevocation }
			: {}),
		// Chain-level CRLs double as responder revocation evidence
		...(input.crls !== undefined ? { responderRevocationCrls: input.crls } : {}),
		...(input.policy?.crlMaxAgeMs !== undefined
			? { responderRevocationCrlMaxAgeMs: input.policy.crlMaxAgeMs }
			: {}),
		...(input.policy?.clockSkewMs !== undefined ? { clockSkewMs: input.policy.clockSkewMs } : {}),
		...(input.policy?.ocspProfile !== undefined ? { profile: input.policy.ocspProfile } : {}),
		...(input.policy?.unrecognizedReasonCode !== undefined
			? { responderRevocationUnrecognizedReasonCode: input.policy.unrecognizedReasonCode }
			: {}),
		...(input.signatureVerifiers !== undefined
			? { signatureVerifiers: input.signatureVerifiers }
			: {}),
	};
	const primary = await validateOcspResponseBy({ response, ...shared }, ocspIssuer, context);
	if (primary.ok || !OCSP_RESPONDER_FAILURE_CODES.has(primary.code)) {
		return primary;
	}
	for (const source of input.extraCertificates ?? []) {
		const responder = parseCertificateSafe(source);
		if (responder === undefined) {
			continue;
		}
		const retry = await validateOcspResponseBy(
			{ response, ...shared, responderCertificate: responder },
			ocspIssuer,
			context,
		);
		if (retry.ok || !OCSP_RESPONDER_FAILURE_CODES.has(retry.code)) {
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
	issuer: RevocationIssuer,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
): Promise<EvidenceEvaluation> {
	const { ocspResponses = [], at = new Date() } = input;
	const executionErrors: RevocationExecutionError[] = [];
	const state: OcspEvidenceState = { reasons: new Set(), sawUnrecognizedReason: false };

	for (const source of ocspResponses) {
		const applicable = findApplicableOcspResponse(source, cert);
		if (applicable.kind === 'parse_error') {
			executionErrors.push(applicable.error);
			continue;
		}
		if (applicable.kind === 'not_applicable') {
			continue; // Response does not cover this certificate
		}

		const validation = await validateOcspResponseWithResponderFallback(
			applicable.parsed,
			cert,
			issuer,
			input,
			at,
			signerCtx,
		);
		if (!validation.ok) {
			state.reasons.add(ocspIndeterminateReasonFromFailure(validation.code));
			continue;
		}

		const evidence = classifyValidatedOcspEntry(
			cert,
			applicable.entry,
			input.policy?.unrecognizedReasonCode ?? 'revoked',
		);
		if (evidence.kind === 'revoked') {
			return {
				status: evidence.status,
				executionErrors,
			};
		}
		recordOcspEvidence(state, evidence);
	}

	return settleOcspEvidence(cert, state, executionErrors);
}

/** What the non-revoked OCSP entries for one certificate established. */
interface OcspEvidenceState {
	readonly reasons: Set<RevocationIndeterminateReason>;
	freshestGoodThisUpdate?: Date;
	freshestHold?: OcspHoldEvidence;
	sawUnrecognizedReason: boolean;
}

function recordOcspEvidence(
	state: OcspEvidenceState,
	evidence: Exclude<ClassifiedOcspEvidence, { readonly kind: 'revoked' }>,
): void {
	if (evidence.kind === 'good') {
		state.freshestGoodThisUpdate = laterEvidenceDate(
			state.freshestGoodThisUpdate,
			evidence.thisUpdate,
		);
		return;
	}
	if (evidence.kind === 'hold') {
		if (
			state.freshestHold === undefined ||
			evidence.evidence.thisUpdate.getTime() > state.freshestHold.thisUpdate.getTime()
		) {
			state.freshestHold = evidence.evidence;
		}
		return;
	}
	if (evidence.kind === 'unrecognized_reason') {
		state.sawUnrecognizedReason = true;
		return;
	}
	state.reasons.add('ocsp_status_unknown');
}

/** The OCSP verdict once no response revoked the certificate outright. */
function settleOcspEvidence(
	cert: ParsedCertificate,
	state: OcspEvidenceState,
	executionErrors: readonly RevocationExecutionError[],
): EvidenceEvaluation {
	if (state.sawUnrecognizedReason) {
		state.reasons.add('ocsp_reason_code_unrecognized');
		return finalizeOcspEvidence(cert, undefined, state.reasons, executionErrors);
	}
	const { freshestGoodThisUpdate, freshestHold } = state;
	if (
		freshestHold !== undefined &&
		(freshestGoodThisUpdate === undefined ||
			freshestGoodThisUpdate.getTime() <= freshestHold.thisUpdate.getTime())
	) {
		return { status: freshestHold.status, executionErrors };
	}
	return finalizeOcspEvidence(cert, freshestGoodThisUpdate, state.reasons, executionErrors);
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
	sawStaleCrl: boolean;
	sawDeltaCrlUnusable: boolean;
	sawDeltaCrlRetryLimit: boolean;
	sawUnrecognizedReasonCode: boolean;
	sawGood: boolean;
	freshestGood?: { readonly signer: RevocationIssuer; readonly thisUpdate: Date };
}

/** Inputs for resolving one base CRL against its candidate signers. */
interface BaseCrlResolution {
	readonly cert: ParsedCertificate;
	readonly baseCrl: ParsedCertificateRevocationList;
	readonly deltaCandidates: readonly ParsedCertificateRevocationList[];
	readonly issuer: RevocationIssuer;
	readonly extraCertificates: readonly RevocationCertificateSource[];
	readonly chain: readonly ParsedCertificate[];
	readonly at: Date;
	readonly crlMaxAgeMs: number | undefined;
	readonly clockSkewMs: number | undefined;
	readonly unrecognizedReasonCode: UnrecognizedReasonCodePolicy;
	readonly signerCtx: SignerValidationContext;
	readonly deltaBudget: DeltaCrlBudget;
	readonly state: CrlEvidenceState;
}

/**
 * Runs each candidate signer through the full pipeline for one base CRL:
 * signature/applicability, RFC 5280 §6.3.3(f) path to the anchor, then signer
 * revocation. A candidate that verifies the signature but fails a later step
 * does not shadow a subsequent usable signer, so the search continues. A
 * revocation stands from a signer whose own status is indeterminate, while
 * `good` needs a signer known good. Returns a revoked status when one is
 * found; otherwise records good or diagnostic evidence into `state`.
 */
async function resolveBaseCrlAgainstSigners(
	params: BaseCrlResolution,
): Promise<ReturnType<typeof buildCrlRevokedStatus> | undefined> {
	const {
		cert,
		baseCrl,
		deltaCandidates,
		issuer,
		extraCertificates,
		chain,
		at,
		crlMaxAgeMs,
		clockSkewMs,
		unrecognizedReasonCode,
		signerCtx,
		deltaBudget,
		state,
	} = params;
	const baseBudget = { remaining: DELTA_CRL_ATTEMPTS_PER_BASE };
	for (const candidate of collectCrlSignerCandidates(
		baseCrl,
		issuer,
		extraCertificates,
		chain,
		signerCtx.trustAnchor,
	)) {
		const authorized = await crlSignerChainsToAnchor(
			candidate,
			chain,
			extraCertificates,
			at,
			signerCtx,
		);
		const verification = signerVerification(signerCtx, candidate);
		if (!authorized) {
			state.sawCrlSignerNotAuthorized ||= (
				await authenticateCrl(baseCrl, candidate, verification)
			).ok;
			continue;
		}
		const resolved = await checkCrlAgainstDeltaCandidates({
			cert,
			baseCrl,
			deltaCandidates,
			candidate,
			at,
			crlMaxAgeMs,
			clockSkewMs,
			unrecognizedReasonCode,
			budgets: [baseBudget, deltaBudget],
			state,
			verification,
		});
		if (resolved.kind === 'unusable_base') {
			continue;
		}
		const verdict = settleCrlSignerCandidate(
			cert,
			candidate,
			resolved,
			await validateCrlSigner(candidate, signerCtx),
			state,
		);
		if (verdict.kind === 'done') return verdict.status;
	}
	return undefined;
}

/** Whether a base CRL's search ends with one signer candidate, and the revoked status it found. */
type CrlSignerCandidateVerdict =
	| { readonly kind: 'next' }
	| { readonly kind: 'done'; readonly status: CertificateRevocationStatus | undefined };

const NEXT_CRL_SIGNER_CANDIDATE = { kind: 'next' } as const satisfies CrlSignerCandidateVerdict;

/**
 * Settles one authorized signer candidate's outcome for a base CRL by the
 * signer's own status. A revocation stands from a signer whose status is
 * indeterminate, while `good` needs a signer known good.
 */
function settleCrlSignerCandidate(
	cert: ParsedCertificate,
	candidate: RevocationIssuer,
	resolved: Exclude<DeltaCandidateOutcome, { readonly kind: 'unusable_base' }>,
	signerStatus: SignerValidationState,
	state: CrlEvidenceState,
): CrlSignerCandidateVerdict {
	if (signerStatus === 'resolved-revoked') {
		state.sawCrlSignerRevoked = true;
		return NEXT_CRL_SIGNER_CANDIDATE;
	}
	const revoked = revokedCrlStatus(cert, candidate, resolved);
	if (signerStatus === 'resolved-indeterminate') {
		state.sawCrlSignerIndeterminate = true;
		return revoked === undefined ? NEXT_CRL_SIGNER_CANDIDATE : { kind: 'done', status: revoked };
	}
	if (resolved.kind === 'reason_code_unrecognized') {
		state.sawUnrecognizedReasonCode = true;
	} else if (resolved.kind === 'delta_unusable') {
		state.sawDeltaCrlUnusable = true;
	} else if (resolved.kind === 'retry_limit') {
		state.sawDeltaCrlRetryLimit = true;
	} else if (resolved.checked.value.status === 'good') {
		recordGoodCrlEvidence(
			state,
			candidate,
			resolved.crlThisUpdate,
			resolved.checked.value.coveredReasons,
		);
	}
	return { kind: 'done', status: revoked };
}

/** The revoked status `resolved` reports for `cert`, signed by `signer`. */
function revokedCrlStatus(
	cert: ParsedCertificate,
	signer: RevocationIssuer,
	resolved: DeltaCandidateOutcome,
): CertificateRevocationStatus | undefined {
	return resolved.kind === 'checked' && resolved.checked.value.status === 'revoked'
		? buildCrlRevokedStatus(
				cert,
				signer,
				resolved.crlThisUpdate,
				resolved.checked.value.revocationDate,
				resolved.checked.value.reasonCode,
			)
		: undefined;
}

async function evaluateCrlEvidence(
	cert: ParsedCertificate,
	issuer: RevocationIssuer,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
	deltaBudget: DeltaCrlBudget,
): Promise<EvidenceEvaluation> {
	const { crls = [], extraCertificates = [], chain = [], at = new Date() } = input;
	const state: CrlEvidenceState = {
		executionErrors: [],
		coveredReasons: new Set(),
		sawCrlSignerRevoked: false,
		sawCrlSignerIndeterminate: false,
		sawCrlSignerNotAuthorized: false,
		sawStaleCrl: false,
		sawDeltaCrlUnusable: false,
		sawDeltaCrlRetryLimit: false,
		sawUnrecognizedReasonCode: false,
		sawGood: false,
	};

	// Parse all CRLs and separate base CRLs from delta CRLs
	const parsedCrls = parseCrlEvidenceSources(crls, state.executionErrors);

	const baseCrls = distinctSignedCrls(
		parsedCrls.filter((crl) => crl.baseCrlNumber === undefined && isCrlApplicableTo(cert, crl)),
	);
	const deltaCrls = distinctSignedCrls(parsedCrls.filter((crl) => crl.baseCrlNumber !== undefined));

	// Process base CRLs (optionally paired with delta CRLs)
	const crlMaxAgeMs = input.policy?.crlMaxAgeMs;
	const clockSkewMs = input.policy?.clockSkewMs;
	for (const baseCrl of baseCrls) {
		const revoked = await resolveBaseCrlAgainstSigners({
			cert,
			baseCrl,
			deltaCandidates: rankApplicableDeltaCrls(
				baseCrl,
				deltaCrls,
				at,
				clockSkewMs ?? 0,
				crlMaxAgeMs,
			),
			issuer,
			extraCertificates,
			chain,
			at,
			crlMaxAgeMs,
			clockSkewMs,
			unrecognizedReasonCode: input.policy?.unrecognizedReasonCode ?? 'revoked',
			signerCtx,
			deltaBudget,
			state,
		});
		if (revoked !== undefined) {
			return { status: revoked, executionErrors: state.executionErrors };
		}
	}

	const blockingReasons = blockingCrlIndeterminateReasons(state);
	if (blockingReasons.length > 0) {
		return {
			status: { certificate: cert, status: 'indeterminate', indeterminateReasons: blockingReasons },
			executionErrors: state.executionErrors,
		};
	}

	// Return 'good' only if we saw at least one good result AND all reasons are covered
	if (state.sawGood && state.freshestGood !== undefined) {
		const allReasonsCovered = coversAllDistributionPointReasons(state.coveredReasons);
		if (allReasonsCovered) {
			return {
				status: {
					certificate: cert,
					status: 'good',
					source: {
						kind: 'crl',
						...signerCertificateOf(state.freshestGood.signer),
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

/** CRL conditions that keep the status indeterminate despite `good` evidence. */
function blockingCrlIndeterminateReasons(
	state: CrlEvidenceState,
): readonly RevocationIndeterminateReason[] {
	return [
		...(state.sawDeltaCrlUnusable ? (['delta_crl_unusable'] as const) : []),
		...(state.sawDeltaCrlRetryLimit ? (['delta_crl_retry_limit_exceeded'] as const) : []),
		...(state.sawUnrecognizedReasonCode ? (['crl_reason_code_unrecognized'] as const) : []),
	];
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
	if (state.sawStaleCrl) {
		return 'crl_expired';
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
			parsedCrls.push(normalizeCrl(crlSource));
		} catch (error) {
			executionErrors.push(evidenceParseError(error, 'CRL parse failed'));
		}
	}
	return parsedCrls;
}

const DELTA_CRL_ATTEMPTS_PER_CHAIN = 32;

interface DeltaCandidateCheck {
	readonly cert: ParsedCertificate;
	readonly baseCrl: ParsedCertificateRevocationList;
	readonly deltaCandidates: readonly ParsedCertificateRevocationList[];
	readonly candidate: RevocationIssuer;
	readonly at: Date;
	readonly crlMaxAgeMs: number | undefined;
	readonly clockSkewMs: number | undefined;
	readonly unrecognizedReasonCode: UnrecognizedReasonCodePolicy;
	readonly budgets: readonly DeltaCrlBudget[];
	readonly state: CrlEvidenceState;
	readonly verification: CallerVerification;
}

type DeltaCandidateOutcome =
	| {
			readonly kind: 'checked';
			readonly checked: Extract<
				Awaited<ReturnType<typeof checkCertificateRevocationAgainstCrl>>,
				{ readonly ok: true }
			>;
			readonly crlThisUpdate: Date;
	  }
	| { readonly kind: 'unusable_base' }
	| { readonly kind: 'reason_code_unrecognized' }
	| {
			readonly kind: 'delta_unusable';
			readonly complete: Awaited<ReturnType<typeof checkCertificateRevocationAgainstCrl>>;
	  }
	| { readonly kind: 'retry_limit' };

/**
 * Authenticates `baseCrl` with `candidate` once, then checks it with each
 * ranked delta CRL while the budgets last, and alone once every delta CRL is
 * rejected or a delta CRL past its `nextUpdate` leaves the status to it. A delta CRL that passes authentication, freshness, compatibility
 * and applicability ends the search.
 */
async function checkCrlAgainstDeltaCandidates(
	params: DeltaCandidateCheck,
): Promise<DeltaCandidateOutcome> {
	const {
		cert,
		baseCrl,
		deltaCandidates,
		candidate,
		at,
		crlMaxAgeMs,
		clockSkewMs,
		unrecognizedReasonCode,
		budgets,
		state,
		verification,
	} = params;
	const authenticated = await authenticateCrl(baseCrl, candidate, verification);
	if (!authenticated.ok) {
		return { kind: 'unusable_base' };
	}
	const input = {
		at,
		...(crlMaxAgeMs === undefined ? {} : { maxAgeMs: crlMaxAgeMs }),
		...(clockSkewMs === undefined ? {} : { clockSkewMs }),
		unrecognizedReasonCode,
	};
	for (const [index, deltaCrl] of deltaCandidates.entries()) {
		if (!takeDeltaCrlAttempt(budgets)) {
			return await retryLimitOutcome(params, authenticated.value, input);
		}
		const outcome = await checkRevocationAgainstAuthenticatedCrl(
			cert,
			authenticated.value,
			candidate,
			{ ...input, deltaCrl },
			verification,
		);
		if (outcome.kind === 'delta_stale') break;
		const settled = settleAuthenticatedCrlOutcome(
			outcome,
			laterEvidenceDate(baseCrl.thisUpdate, deltaCrl.thisUpdate),
			state,
		);
		if (settled === undefined) {
			continue;
		}
		if (settled.kind === 'delta_unusable') {
			return irremovableRevocation(cert, settled.complete, at, baseCrl.thisUpdate) ?? settled;
		}
		if (settled.kind !== 'checked' || settled.checked.value.status !== 'good') return settled;
		return (
			(await olderDeltaCrlRevocation(
				params,
				authenticated.value,
				input,
				deltaCandidates.slice(index + 1),
			)) ?? settled
		);
	}
	return (
		settleAuthenticatedCrlOutcome(
			await checkRevocationAgainstAuthenticatedCrl(
				cert,
				authenticated.value,
				candidate,
				input,
				verification,
			),
			baseCrl.thisUpdate,
			state,
		) ?? { kind: 'unusable_base' }
	);
}

/**
 * The outcome once the budgets end the delta CRL search: the base CRL's
 * revocation that no delta CRL could remove, otherwise `retry_limit`.
 */
async function retryLimitOutcome(
	params: DeltaCandidateCheck,
	completeCrl: ParsedCertificateRevocationList,
	input: CrlCheckOptions,
): Promise<DeltaCandidateOutcome> {
	const { cert, candidate, at, baseCrl, verification } = params;
	const alone = await checkRevocationAgainstAuthenticatedCrl(
		cert,
		completeCrl,
		candidate,
		input,
		verification,
	);
	return (
		(alone.kind === 'checked'
			? irremovableRevocation(cert, alone.result, at, baseCrl.thisUpdate)
			: undefined) ?? { kind: 'retry_limit' }
	);
}

/**
 * What the older delta CRLs in `older` change after a newer one settled the
 * status as good, read while the budgets last and until one past its
 * `nextUpdate` records nothing that stands (RFC 5280 §5.3.1, §3.3).
 */
async function olderDeltaCrlRevocation(
	params: DeltaCandidateCheck,
	completeCrl: ParsedCertificateRevocationList,
	input: CrlCheckOptions,
	older: readonly ParsedCertificateRevocationList[],
): Promise<DeltaCandidateOutcome | undefined> {
	const { cert, candidate, at, baseCrl, budgets, verification } = params;
	for (const deltaCrl of older) {
		if (!takeDeltaCrlAttempt(budgets)) return undefined;
		const outcome = await checkRevocationAgainstAuthenticatedCrl(
			cert,
			completeCrl,
			candidate,
			{ ...input, deltaCrl },
			verification,
		);
		if (outcome.kind === 'delta_stale') return undefined;
		const changed = olderDeltaCrlOutcome(
			cert,
			outcome,
			at,
			laterEvidenceDate(baseCrl.thisUpdate, deltaCrl.thisUpdate),
		);
		if (changed !== undefined) return changed;
	}
	return undefined;
}

/**
 * What one older delta CRL changes after a newer one settled the status as
 * good: a revocation no later CRL may drop, an entry
 * `unrecognizedReasonCode: 'reject'` refuses, or entries that cannot settle
 * the status.
 */
function olderDeltaCrlOutcome(
	cert: ParsedCertificate,
	outcome: AuthenticatedCrlCheckOutcome,
	at: Date,
	crlThisUpdate: Date,
): DeltaCandidateOutcome | undefined {
	if (outcome.kind === 'delta_unresolved') {
		return (
			irremovableRevocation(cert, outcome.complete, at, crlThisUpdate) ?? {
				kind: 'delta_unusable',
				complete: outcome.complete,
			}
		);
	}
	if (outcome.kind !== 'checked') return undefined;
	if (!outcome.result.ok) {
		return outcome.result.code === 'reason_code_unrecognized'
			? { kind: 'reason_code_unrecognized' }
			: undefined;
	}
	return irremovableRevocation(cert, outcome.result, at, crlThisUpdate);
}

/** The base CRL's revocation of `cert` in `complete` when no delta CRL could remove it at `at`. */
function irremovableRevocation(
	cert: ParsedCertificate,
	complete: Awaited<ReturnType<typeof checkCertificateRevocationAgainstCrl>>,
	at: Date,
	crlThisUpdate: Date,
): DeltaCandidateOutcome | undefined {
	const checked = irremovableCrlRevocation(cert, complete, at);
	return checked === undefined ? undefined : { kind: 'checked', checked, crlThisUpdate };
}

/** Spends one delta CRL check from every budget, or none when any is empty. */
function takeDeltaCrlAttempt(budgets: readonly DeltaCrlBudget[]): boolean {
	if (budgets.some((budget) => budget.remaining <= 0)) {
		return false;
	}
	for (const budget of budgets) {
		budget.remaining -= 1;
	}
	return true;
}

/** Maps one staged CRL check to the search outcome, or `undefined` to try the next delta CRL. */
function settleAuthenticatedCrlOutcome(
	outcome: AuthenticatedCrlCheckOutcome,
	crlThisUpdate: Date,
	state: CrlEvidenceState,
): DeltaCandidateOutcome | undefined {
	if (outcome.kind === 'delta_unresolved') {
		return { kind: 'delta_unusable', complete: outcome.complete };
	}
	if (outcome.kind === 'delta_rejected' || outcome.kind === 'delta_stale') {
		return undefined;
	}
	const result = outcome.result;
	if (!result.ok && result.code === 'stale_crl') {
		state.sawStaleCrl = true;
	}
	if (!result.ok && result.code === 'reason_code_unrecognized') {
		return { kind: 'reason_code_unrecognized' };
	}
	return result.ok
		? { kind: 'checked', checked: result, crlThisUpdate }
		: { kind: 'unusable_base' };
}

/** The direct issuer first, then deduplicated indirect CRL-issuer candidates. */
function collectCrlSignerCandidates(
	baseCrl: ParsedCertificateRevocationList,
	issuer: RevocationIssuer,
	extraCertificates: readonly RevocationCertificateSource[],
	chain: readonly ParsedCertificate[],
	trustAnchor: TrustAnchor | undefined,
): readonly RevocationIssuer[] {
	const candidates: RevocationIssuer[] = [issuer];
	const push = (candidate: RevocationIssuer): void => {
		if (!candidates.some((existing) => sameIssuer(existing, candidate))) {
			candidates.push(candidate);
		}
	};
	for (const indirect of findIndirectCrlIssuers(baseCrl, extraCertificates, chain)) {
		push(issuerOf(indirect, trustAnchor));
	}
	if (trustAnchor !== undefined && compareDistinguishedNames(baseCrl.issuer, trustAnchor.subject)) {
		push({ kind: 'trust_anchor', trustAnchor });
	}
	return candidates;
}

function recordGoodCrlEvidence(
	state: CrlEvidenceState,
	signer: RevocationIssuer,
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

/** Indeterminate reasons that keep other evidence from settling the status as `good`. */
const GOOD_BLOCKING_REASONS: ReadonlySet<RevocationIndeterminateReason> = new Set([
	'delta_crl_unusable',
	'delta_crl_retry_limit_exceeded',
	'crl_reason_code_unrecognized',
	'ocsp_reason_code_unrecognized',
]);

/**
 * Evaluates revocation status for a single certificate by combining OCSP and
 * CRL evidence.
 *
 * Both evidence kinds are always evaluated: a validated `revoked` verdict from
 * either source wins regardless of {@linkcode RevocationPolicy.prefer}
 * (fail-closed). Otherwise the preferred source's `good` verdict is reported —
 * for `'best-available'` the source with the later evidence `thisUpdate` wins,
 * ties favoring OCSP. An indeterminate reason in
 * {@linkcode GOOD_BLOCKING_REASONS} from either source outranks a `good`
 * verdict. If neither source is definitive, indeterminate reasons from both
 * are merged.
 */
async function evaluateCertificateRevocation(
	cert: ParsedCertificate,
	issuer: RevocationIssuer,
	input: CheckChainRevocationInput,
	signerCtx: SignerValidationContext,
	deltaBudget: DeltaCrlBudget,
): Promise<EvidenceEvaluation> {
	const prefer = input.policy?.prefer ?? 'best-available';
	const ocsp = await evaluateOcspEvidence(cert, issuer, input, signerCtx);
	const crl = await evaluateCrlEvidence(cert, issuer, input, signerCtx, deltaBudget);
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
	const blocked = [crl, ocsp].some((evaluation) =>
		evaluation.status.indeterminateReasons?.some((reason) => GOOD_BLOCKING_REASONS.has(reason)),
	);
	if (good !== undefined && !blocked) {
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

/**
 * @throws RangeError when `trustAnchor` did not issue the last certificate of
 * `chain`, or that certificate is the anchor's own.
 */
function assertIssuedByTrustAnchor(
	chain: readonly ParsedCertificate[],
	trustAnchor: TrustAnchor | undefined,
): void {
	const top = chain[chain.length - 1];
	if (trustAnchor === undefined || top === undefined) return;
	if (carriesTrustAnchorKey(top, trustAnchor)) {
		throw new RangeError('chain ends with the trust anchor certificate; omit it or trustAnchor');
	}
	if (!compareDistinguishedNames(top.issuer, trustAnchor.subject)) {
		throw new RangeError('trustAnchor does not name the issuer of the last chain certificate');
	}
}

/** The issuer of `chain[index]`: the next chain certificate, or the bare anchor above the last. */
function issuerAt(
	chain: readonly ParsedCertificate[],
	index: number,
	trustAnchor: TrustAnchor | undefined,
): RevocationIssuer | undefined {
	const next = chain[index + 1];
	if (next !== undefined) return { kind: 'certificate', certificate: next };
	return trustAnchor === undefined ? undefined : { kind: 'trust_anchor', trustAnchor };
}

/**
 * RFC 9608 §4: path validation skips RFC 5280 §6.1.3 step (a)(3) for a
 * certificate carrying noRevAvail or id-pkix-ocsp-nocheck, read from its
 * signed DER.
 */
function revocationSkipReason(certificate: ParsedCertificate): RevocationSkipReason | undefined {
	const signed = parseCertificateDer(certificate.der);
	return signed.ok ? revocationSkipReasonOf(signed.value) : undefined;
}

// Function

/**
 * Checks revocation status for all certificates in a validated chain.
 *
 * Evaluates CRL and OCSP evidence against each certificate (except the trust
 * anchor at the end of `chain`; with `trustAnchor`, every certificate), applies
 * the revocation policy, and returns a unified decision. A
 * certificate carrying noRevAvail or id-pkix-ocsp-nocheck is reported as
 * `skipped` without consulting evidence (RFC 9608 §4).
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
	return await checkChainRevocationAt({ ...input, at: input.at ?? new Date() });
}

/**
 * The signer validation state shared by every certificate check of one
 * {@linkcode checkChainRevocation} call, with its delta CRL budget and the
 * caller's distrust list as it stood when the call began.
 */
function signerValidationContext(
	input: CheckChainRevocationInput & { readonly at: Date },
	verifiers: ReadonlyMap<string, SignatureVerifier>,
): SignerValidationContext {
	const { chain, policy } = input;
	const pathKeys = new Map<string, WorkingPublicKey>();
	const chainKeys = chainWorkingKeys(
		chain,
		input.trustAnchor === undefined ? undefined : anchorWorkingKey(input.trustAnchor),
	);
	return {
		cache: new Map(),
		chain,
		crls: input.crls ?? [],
		extraCertificates: input.extraCertificates ?? [],
		at: input.at,
		crlMaxAgeMs: policy?.crlMaxAgeMs,
		clockSkewMs: policy?.clockSkewMs,
		unrecognizedReasonCode: policy?.unrecognizedReasonCode ?? 'revoked',
		crlSignerSelfEvidence: policy?.crlSignerSelfEvidence ?? 'delegated',
		signatureVerifiers: input.signatureVerifiers,
		distrustedSpkiSha256:
			input.distrustedSpkiSha256 === undefined ? undefined : [...input.distrustedSpkiSha256],
		verifiers,
		deltaBudget: { remaining: DELTA_CRL_ATTEMPTS_PER_CHAIN },
		workingKeyOf: (certificate) =>
			pathKeys.get(certCacheKey(certificate)) ?? chainKeys(certificate),
		pathKeys,
		pathIssuers: new Map(),
		trustAnchor: input.trustAnchor,
	};
}

/** {@linkcode checkChainRevocation} with its evaluation time resolved once for every check. */
async function checkChainRevocationAt(
	input: CheckChainRevocationInput & { readonly at: Date },
): Promise<CheckChainRevocationResult> {
	const { chain, policy } = input;
	assertCrlMaxAge(policy?.crlMaxAgeMs);
	const verifiers = resolveSignatureVerifiers(input.signatureVerifiers);
	createSpkiDistrustCheck(input.distrustedSpkiSha256);
	assertIssuedByTrustAnchor(chain, input.trustAnchor);
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

	const signerCtx = signerValidationContext(input, verifiers);
	const deltaBudget = signerCtx.deltaBudget;

	const certsToCheck = input.trustAnchor === undefined ? chain.slice(0, -1) : chain;
	const certificates: CertificateRevocationStatus[] = [];
	const revokedCertificates: ParsedCertificate[] = [];
	const indeterminateCertificates: ParsedCertificate[] = [];
	const allExecutionErrors: RevocationExecutionError[] = [];

	for (let i = 0; i < certsToCheck.length; i++) {
		const cert = certsToCheck[i];
		const issuer = issuerAt(chain, i, input.trustAnchor);
		if (cert === undefined || issuer === undefined) {
			continue;
		}

		const skipReason = revocationSkipReason(cert);
		if (skipReason !== undefined) {
			certificates.push({ certificate: cert, status: 'skipped', skipReason });
			continue;
		}

		const { status, executionErrors } = await evaluateCertificateRevocation(
			cert,
			issuer,
			input,
			signerCtx,
			deltaBudget,
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
