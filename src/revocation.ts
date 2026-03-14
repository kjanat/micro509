/**
 * Higher-level revocation orchestration helpers.
 *
 * This module combines CRL and OCSP evidence into one typed revocation result surface.
 */

import type { Result } from './core/result.ts';
import type { CrlApplicabilityFailureReason, CrlSource, RevocationReason } from './crl.ts';
import { checkCertificateRevocationAgainstCrl } from './crl.ts';
import type { OcspCertificateSource, OcspRequestSource, ParsedOcspResponse } from './ocsp.ts';
import { validateOcspResponse } from './ocsp.ts';
import type { ParsedCertificate } from './parse.ts';
import { parseCertificateDer, parseCertificatePem } from './parse.ts';

/**
 * Enumerates revocation values used by this module.
 */
export type RevocationStatus = 'good' | 'revoked' | 'unknown';

/**
 * Enumerates revocation evidence values used by this module.
 */
export type RevocationEvidenceKind = 'crl' | 'ocsp';
/**
 * Describes the accepted source forms for revocation certificate inputs.
 */
export type RevocationCertificateSource = string | Uint8Array | ParsedCertificate;
/**
 * Describes the accepted source forms for OCSP responder inputs.
 */
export type OcspResponderSource = 'configured' | 'authorityInfoAccess';
/**
 * Defines configured OCSP responder certificate.
 */
export type ConfiguredOcspResponderCertificate = string | Uint8Array;

/**
 * Describes configured OCSP responder.
 */
export interface ConfiguredOcspResponder {
	/**
	 * Carries the uri value.
	 */
	readonly uri: string;
	/**
	 * Carries the responder certificate value.
	 */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/**
 * Describes OCSP responder candidate.
 */
export interface OcspResponderCandidate {
	/**
	 * Carries the source value.
	 */
	readonly source: OcspResponderSource;
	/**
	 * Carries the uri value.
	 */
	readonly uri: string;
	/**
	 * Carries the responder certificate value.
	 */
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

/**
 * Describes the input shape for resolve OCSP responder candidates operations.
 */
export interface ResolveOcspResponderCandidatesInput {
	/**
	 * Carries the certificate value.
	 */
	readonly certificate: RevocationCertificateSource;
	/**
	 * Carries the configured responders value.
	 */
	readonly configuredResponders?: readonly ConfiguredOcspResponder[];
}

/**
 * Describes the input shape for revocation CRL evidence operations.
 */
export interface RevocationCrlEvidenceInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'crl';
	/**
	 * Carries the crl value.
	 */
	readonly crl: CrlSource;
	/**
	 * Carries the delta crl value.
	 */
	readonly deltaCrl?: CrlSource;
}

/**
 * Describes the input shape for revocation OCSP evidence operations.
 */
export interface RevocationOcspEvidenceInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'ocsp';
	/**
	 * Carries the response value.
	 */
	readonly response: string | Uint8Array | ParsedOcspResponse;
	/**
	 * Carries the request value.
	 */
	readonly request?: OcspRequestSource;
	/**
	 * Carries the responder certificate value.
	 */
	readonly responderCertificate?: OcspCertificateSource;
}

/**
 * Describes the input shape for revocation evidence operations.
 */
export type RevocationEvidenceInput = RevocationCrlEvidenceInput | RevocationOcspEvidenceInput;

/**
 * Describes the input shape for check certificate revocation operations.
 */
export interface CheckCertificateRevocationInput {
	/**
	 * Carries the certificate value.
	 */
	readonly certificate: RevocationCertificateSource;
	/**
	 * Carries the issuer certificate value.
	 */
	readonly issuerCertificate: RevocationCertificateSource;
	/**
	 * Carries the evidence value.
	 */
	readonly evidence?: readonly RevocationEvidenceInput[];
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
	/**
	 * Carries the clock skew ms value.
	 */
	readonly clockSkewMs?: number;
}

/**
 * Enumerates the error codes used by check certificate revocation failures.
 */
export type CheckCertificateRevocationErrorCode =
	| 'revocation_evidence_missing'
	| 'revocation_status_unknown';

/**
 * Enumerates the reason codes used by revocation indeterminate failures.
 */
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

/**
 * Describes revocation indeterminate evidence.
 */
export interface RevocationIndeterminateEvidence {
	/**
	 * Carries the source value.
	 */
	readonly source: RevocationEvidenceKind;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: RevocationIndeterminateReasonCode;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
	/**
	 * Carries the reason value.
	 */
	readonly reason?: CrlApplicabilityFailureReason;
}

/**
 * Carries structured details for check certificate revocation failures.
 */
export interface CheckCertificateRevocationFailureDetails {
	/**
	 * Carries the checked sources value.
	 */
	readonly checkedSources: readonly RevocationEvidenceKind[];
	/**
	 * Carries the indeterminate evidence value.
	 */
	readonly indeterminateEvidence: readonly RevocationIndeterminateEvidence[];
}

/**
 * Carries the value returned by revocation check unknown operations.
 */
export interface RevocationCheckUnknownValue {
	/**
	 * Identifies the status value.
	 */
	readonly status: Extract<RevocationStatus, 'unknown'>;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: CheckCertificateRevocationErrorCode;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
	/**
	 * Carries structured details for the current failure.
	 */
	readonly details: CheckCertificateRevocationFailureDetails;
}

/**
 * Carries the value returned by revocation check good operations.
 */
export interface RevocationCheckGoodValue {
	/**
	 * Identifies the status value.
	 */
	readonly status: Extract<RevocationStatus, 'good'>;
	/**
	 * Carries the source value.
	 */
	readonly source: RevocationEvidenceKind;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
}

/**
 * Carries the value returned by revocation check revoked operations.
 */
export interface RevocationCheckRevokedValue {
	/**
	 * Identifies the status value.
	 */
	readonly status: Extract<RevocationStatus, 'revoked'>;
	/**
	 * Carries the source value.
	 */
	readonly source: RevocationEvidenceKind;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
	/**
	 * Carries the revoked at value.
	 */
	readonly revokedAt?: Date;
	/**
	 * Carries the revocation reason value.
	 */
	readonly revocationReason?: RevocationReason;
	/**
	 * Carries the revocation reason code value.
	 */
	readonly revocationReasonCode?: number;
}

/**
 * Carries the value returned by check certificate revocation operations.
 */
export type CheckCertificateRevocationValue =
	| RevocationCheckGoodValue
	| RevocationCheckRevokedValue
	| RevocationCheckUnknownValue;

/**
 * Represents the result returned by check certificate revocation operations.
 */
export type CheckCertificateRevocationResult = Result<CheckCertificateRevocationValue, never>;

/**
 * Defines revocation evidence check.
 */
type RevocationEvidenceCheck =
	| {
			/**
			 * Identifies the status value.
			 */
			readonly status: 'good';
			/**
			 * Carries the result value.
			 */
			readonly result: RevocationCheckGoodValue;
	  }
	| {
			/**
			 * Identifies the status value.
			 */
			readonly status: 'revoked';
			/**
			 * Carries the result value.
			 */
			readonly result: RevocationCheckRevokedValue;
	  }
	| {
			/**
			 * Identifies the status value.
			 */
			readonly status: 'unknown';
			/**
			 * Carries the detail value.
			 */
			readonly detail: RevocationIndeterminateEvidence;
	  };

/**
 * Returns certificate OCSP responder uris.
 *
 * @param certificate The certificate input.
 * @returns The certificate OCSP responder uris.
 */
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
 * Resolves OCSP responder candidates.
 *
 * @param input The typed input payload.
 * @returns The resolved OCSP responder candidates.
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
 * Checks certificate revocation.
 *
 * @param input The typed input payload.
 * @returns The check result.
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

/**
 * Checks certificate revocation with CRL.
 *
 * @param input The typed input payload.
 * @param evidence The evidence value.
 * @returns The check result.
 */
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

/**
 * Checks certificate revocation with OCSP.
 *
 * @param input The typed input payload.
 * @param evidence The evidence value.
 * @returns The check result.
 */
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

/**
 * Normalizes certificate.
 *
 * @param certificate The certificate input.
 * @returns The computed value.
 */
function normalizeCertificate(certificate: RevocationCertificateSource): ParsedCertificate {
	if (typeof certificate === 'string') {
		return parseCertificatePem(certificate);
	}
	if (certificate instanceof Uint8Array) {
		return parseCertificateDer(certificate);
	}
	return certificate;
}

/**
 * Normalizes hex.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function normalizeHex(value: string): string {
	const normalized = value.toLowerCase().replace(/^0+/, '');
	return normalized === '' ? '0' : normalized;
}

/**
 * Revocation success.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function revocationSuccess(
	value: CheckCertificateRevocationValue,
): CheckCertificateRevocationResult {
	return { ok: true, value };
}
