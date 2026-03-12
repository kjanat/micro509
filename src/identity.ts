import type { ParsedCertificate } from './parse.ts';
import type { MatchableServiceIdentityInput, ServiceIdentityInput } from './validation.ts';

export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'service_identity_type_unsupported';

export interface MatchServiceIdentityFailureDetails {
	readonly subjectCommonName?: string;
	readonly expected?: string;
	readonly actual?: string;
}

export type MatchServiceIdentityResult =
	| { readonly ok: true }
	| {
			readonly ok: false;
			readonly code: MatchServiceIdentityErrorCode;
			readonly message: string;
			readonly details?: MatchServiceIdentityFailureDetails;
	  };

export interface MatchServiceIdentityInput {
	readonly certificate: ParsedCertificate;
	readonly serviceIdentity: ServiceIdentityInput;
}

export function matchServiceIdentity(input: MatchServiceIdentityInput): MatchServiceIdentityResult {
	return matchCertificateServiceIdentity(input.certificate, input.serviceIdentity);
}

export function matchCertificateServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: MatchableServiceIdentityInput,
): MatchServiceIdentityResult {
	switch (serviceIdentity.type) {
		case 'dns': {
			const expected = serviceIdentity.value;
			const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'dns') ?? [];
			if (sans.length > 0) {
				if (!sans.some((entry) => matchesDnsName(entry.value, expected))) {
					return failure(
						'subject_alt_name_mismatch',
						'DNS name not present in SAN',
						details(
							certificate.subject.values.commonName,
							expected,
							sans.map((entry) => entry.value).join(','),
						),
					);
				}
				return { ok: true };
			}
			if (serviceIdentity.allowCommonNameFallback === true) {
				const commonName = certificate.subject.values.commonName;
				if (commonName === undefined || !matchesDnsName(commonName, expected)) {
					return failure(
						'subject_alt_name_mismatch',
						'DNS name not present in SAN or CN',
						details(commonName, expected, commonName ?? ''),
					);
				}
				return { ok: true };
			}
			return failure(
				'subject_alt_name_mismatch',
				'DNS name not present in SAN',
				details(certificate.subject.values.commonName, expected, ''),
			);
		}
		case 'ip': {
			const expected = normalizeIpAddress(serviceIdentity.value);
			const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'ip') ?? [];
			if (!sans.some((entry) => normalizeIpAddress(entry.value) === expected)) {
				return failure(
					'subject_alt_name_mismatch',
					'IP address not present in SAN',
					details(
						certificate.subject.values.commonName,
						expected,
						sans.map((entry) => normalizeIpAddress(entry.value)).join(','),
					),
				);
			}
			return { ok: true };
		}
		default: {
			return failure(
				'service_identity_type_unsupported',
				`${serviceIdentity.type} service identity matching not implemented yet`,
				{ expected: serviceIdentity.value },
			);
		}
	}
}

function matchesDnsName(pattern: string, actual: string): boolean {
	const lowerPattern = pattern.toLowerCase();
	const lowerActual = actual.toLowerCase();
	if (!lowerPattern.includes('*')) {
		return lowerPattern === lowerActual;
	}
	if (!lowerPattern.startsWith('*.')) {
		return false;
	}
	const suffix = lowerPattern.slice(1);
	if (!lowerActual.endsWith(suffix)) {
		return false;
	}
	const prefix = lowerActual.slice(0, lowerActual.length - suffix.length);
	return prefix.length > 0 && !prefix.includes('.');
}

function normalizeIpAddress(value: string): string {
	if (!value.includes(':')) {
		return value;
	}
	return expandIpv6(value)
		.map((segment) => segment.toLowerCase())
		.join(':');
}

function expandIpv6(value: string): readonly string[] {
	const pieces = value.toLowerCase().split('::');
	const head = pieces[0] ?? '';
	const tail = pieces[1];
	if (tail !== undefined && value.indexOf('::') !== value.lastIndexOf('::')) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const headParts = head.length > 0 ? head.split(':') : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(':') : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const zeroes = Array.from({ length: missing }, () => '0');
	return (tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts]).map((segment) =>
		segment.padStart(4, '0'),
	);
}

function failure(
	code: MatchServiceIdentityErrorCode,
	message: string,
	details?: MatchServiceIdentityFailureDetails,
): MatchServiceIdentityResult {
	return {
		ok: false,
		code,
		message,
		...(details === undefined ? {} : { details }),
	};
}

function details(
	subjectCommonName: string | undefined,
	expected: string,
	actual: string,
): MatchServiceIdentityFailureDetails {
	return {
		...(subjectCommonName === undefined ? {} : { subjectCommonName }),
		expected,
		actual,
	};
}
