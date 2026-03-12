import type { CrlSource } from './crl.ts';
import type { OcspCertificateSource, OcspRequestSource, ParsedOcspResponse } from './ocsp.ts';
import type { ParsedCertificate } from './parse.ts';
import type { RevocationStatus } from './validation.ts';

export type RevocationEvidenceKind = 'crl' | 'ocsp';
export type RevocationCertificateSource = string | Uint8Array | ParsedCertificate;

export interface RevocationCrlEvidenceInput {
	readonly kind: 'crl';
	readonly crl: CrlSource;
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
	| 'revocation_not_implemented';

export interface CheckCertificateRevocationFailureDetails {
	readonly checkedSources: readonly RevocationEvidenceKind[];
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
	readonly revocationReasonCode?: number;
}

export type CheckCertificateRevocationResult =
	| RevocationCheckGoodResult
	| RevocationCheckRevokedResult
	| RevocationCheckUnknownResult;

export function checkCertificateRevocation(
	input: CheckCertificateRevocationInput,
): CheckCertificateRevocationResult {
	const evidence = input.evidence ?? [];
	const checkedSources = evidence.map((entry) => entry.kind);
	const details: CheckCertificateRevocationFailureDetails = {
		checkedSources,
	};
	if (evidence.length === 0) {
		return {
			ok: false,
			status: 'unknown',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details,
		};
	}
	return {
		ok: false,
		status: 'unknown',
		code: 'revocation_not_implemented',
		message: 'Revocation orchestration not implemented yet',
		details,
	};
}
