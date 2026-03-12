import type { CrlApplicabilityFailureReason, CrlSource, RevocationReason } from './crl.ts';
import { checkCertificateRevocationAgainstCrl } from './crl.ts';
import type { OcspCertificateSource, OcspRequestSource, ParsedOcspResponse } from './ocsp.ts';
import { validateOcspResponse } from './ocsp.ts';
import type { ParsedCertificate } from './parse.ts';
import { parseCertificateDer, parseCertificatePem } from './parse.ts';
import type { RevocationStatus } from './validation.ts';

export type RevocationEvidenceKind = 'crl' | 'ocsp';
export type RevocationCertificateSource = string | Uint8Array | ParsedCertificate;
export type OcspResponderSource = 'configured' | 'authorityInfoAccess';
export type ConfiguredOcspResponderCertificate = string | Uint8Array;

export interface ConfiguredOcspResponder {
	readonly uri: string;
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

export interface OcspResponderCandidate {
	readonly source: OcspResponderSource;
	readonly uri: string;
	readonly responderCertificate?: ConfiguredOcspResponderCertificate;
}

export interface ResolveOcspResponderCandidatesInput {
	readonly certificate: RevocationCertificateSource;
	readonly configuredResponders?: readonly ConfiguredOcspResponder[];
}

export interface RevocationCrlEvidenceInput {
	readonly kind: 'crl';
	readonly crl: CrlSource;
	readonly deltaCrl?: CrlSource;
}

export interface RevocationOcspEvidenceInput {
	readonly kind: 'ocsp';
	readonly response: string | Uint8Array | ParsedOcspResponse;
	readonly request?: OcspRequestSource;
	readonly responderCertificate?: OcspCertificateSource;
}

export type RevocationEvidenceInput = RevocationCrlEvidenceInput | RevocationOcspEvidenceInput;

export interface CheckCertificateRevocationInput {
	readonly certificate: RevocationCertificateSource;
	readonly issuerCertificate: RevocationCertificateSource;
	readonly evidence?: readonly RevocationEvidenceInput[];
	readonly at?: Date;
	readonly clockSkewMs?: number;
}

export type CheckCertificateRevocationErrorCode =
	| 'revocation_evidence_missing'
	| 'revocation_status_unknown';

export type RevocationIndeterminateReasonCode =
	| 'certificate_status_missing'
	| 'certificate_status_unknown'
	| 'crl_sign_not_permitted'
	| 'issuer_mismatch'
	| 'non_applicable'
	| 'nonce_mismatch'
	| 'ocsp_signing_missing'
	| 'request_mismatch'
	| 'responder_chain_invalid'
	| 'response_status_invalid'
	| 'signature_invalid'
	| 'stale_crl'
	| 'stale_response';

export interface RevocationIndeterminateEvidence {
	readonly source: RevocationEvidenceKind;
	readonly code: RevocationIndeterminateReasonCode;
	readonly message: string;
	readonly reason?: CrlApplicabilityFailureReason;
}

export interface CheckCertificateRevocationFailureDetails {
	readonly checkedSources: readonly RevocationEvidenceKind[];
	readonly indeterminateEvidence: readonly RevocationIndeterminateEvidence[];
}

export interface RevocationCheckUnknownResult {
	readonly ok: false;
	readonly status: Extract<RevocationStatus, 'unknown'>;
	readonly code: CheckCertificateRevocationErrorCode;
	readonly message: string;
	readonly details: CheckCertificateRevocationFailureDetails;
}

export interface RevocationCheckGoodResult {
	readonly ok: true;
	readonly status: Extract<RevocationStatus, 'good'>;
	readonly source: RevocationEvidenceKind;
	readonly message: string;
}

export interface RevocationCheckRevokedResult {
	readonly ok: true;
	readonly status: Extract<RevocationStatus, 'revoked'>;
	readonly source: RevocationEvidenceKind;
	readonly message: string;
	readonly revokedAt?: Date;
	readonly revocationReason?: RevocationReason;
	readonly revocationReasonCode?: number;
}

export type CheckCertificateRevocationResult =
	| RevocationCheckGoodResult
	| RevocationCheckRevokedResult
	| RevocationCheckUnknownResult;

type RevocationEvidenceCheck =
	| {
			readonly status: 'good';
			readonly result: RevocationCheckGoodResult;
	  }
	| {
			readonly status: 'revoked';
			readonly result: RevocationCheckRevokedResult;
	  }
	| {
			readonly status: 'unknown';
			readonly detail: RevocationIndeterminateEvidence;
	  };

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

export async function checkCertificateRevocation(
	input: CheckCertificateRevocationInput,
): Promise<CheckCertificateRevocationResult> {
	const evidence = input.evidence ?? [];
	const checkedSources = evidence.map((entry) => entry.kind);
	if (evidence.length === 0) {
		return {
			ok: false,
			status: 'unknown',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details: {
				checkedSources,
				indeterminateEvidence: [],
			},
		};
	}
	let goodResult: RevocationCheckGoodResult | undefined;
	const indeterminateEvidence: RevocationIndeterminateEvidence[] = [];
	for (const entry of evidence) {
		const result =
			entry.kind === 'crl'
				? await checkCertificateRevocationWithCrl(input, entry)
				: await checkCertificateRevocationWithOcsp(input, entry);
		if (result.status === 'revoked') {
			return result.result;
		}
		if (result.status === 'good') {
			goodResult ??= result.result;
			continue;
		}
		indeterminateEvidence.push(result.detail);
	}
	if (goodResult !== undefined) {
		return goodResult;
	}
	return {
		ok: false,
		status: 'unknown',
		code: 'revocation_status_unknown',
		message: 'No revocation evidence established certificate status',
		details: {
			checkedSources,
			indeterminateEvidence,
		},
	};
}

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
		if (result.status === 'revoked') {
			return {
				status: 'revoked',
				result: {
					ok: true,
					status: 'revoked',
					source: 'crl',
					message: 'Certificate is revoked according to CRL evidence',
					revokedAt: result.revocationDate,
					...(result.reasonCode === undefined ? {} : { revocationReason: result.reasonCode }),
				},
			};
		}
		return {
			status: 'good',
			result: {
				ok: true,
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
				ok: true,
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
				ok: true,
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

function normalizeCertificate(certificate: RevocationCertificateSource): ParsedCertificate {
	if (typeof certificate === 'string') {
		return parseCertificatePem(certificate);
	}
	if (certificate instanceof Uint8Array) {
		return parseCertificateDer(certificate);
	}
	return certificate;
}

function normalizeHex(value: string): string {
	const normalized = value.toLowerCase().replace(/^0+/, '');
	return normalized === '' ? '0' : normalized;
}
