import type { ParsedCertificate } from './parse.ts';
import type { MatchableServiceIdentityInput, ServiceIdentityInput } from './validation.ts';

export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'service_identity_service_mismatch'
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
		case 'uri': {
			const expected = parseUriServiceIdentity(serviceIdentity.value);
			const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'uri') ?? [];
			const matchingService = sans.flatMap((entry) => {
				const parsed = tryParseUriServiceIdentity(entry.value);
				if (parsed === undefined || parsed.serviceType !== expected.serviceType) {
					return [];
				}
				return [parsed];
			});
			if (matchingService.some((entry) => matchesDnsName(entry.domainName, expected.domainName))) {
				return { ok: true };
			}
			if (matchingService.length > 0) {
				return failure(
					'subject_alt_name_mismatch',
					'URI host not present in SAN',
					details(
						certificate.subject.values.commonName,
						expected.domainName,
						matchingService.map((entry) => entry.domainName).join(','),
					),
				);
			}
			if (sans.length > 0) {
				return failure(
					'service_identity_service_mismatch',
					'URI scheme not present in SAN',
					details(
						certificate.subject.values.commonName,
						expected.serviceType,
						sans
							.flatMap((entry) => {
								const parsed = tryParseUriServiceIdentity(entry.value);
								return parsed === undefined ? [] : [parsed.serviceType];
							})
							.join(','),
					),
				);
			}
			return failure(
				'subject_alt_name_mismatch',
				'URI-ID not present in SAN',
				details(certificate.subject.values.commonName, expected.domainName, ''),
			);
		}
		case 'srv': {
			const expected = parseSrvServiceIdentity(serviceIdentity.value);
			const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'srv') ?? [];
			const matchingService = sans.flatMap((entry) => {
				const parsed = tryParseSrvServiceIdentity(entry.value);
				if (parsed === undefined || parsed.serviceType !== expected.serviceType) {
					return [];
				}
				return [parsed];
			});
			if (matchingService.some((entry) => matchesDnsName(entry.domainName, expected.domainName))) {
				return { ok: true };
			}
			if (matchingService.length > 0) {
				return failure(
					'subject_alt_name_mismatch',
					'SRV domain not present in SAN',
					details(
						certificate.subject.values.commonName,
						expected.domainName,
						matchingService.map((entry) => entry.domainName).join(','),
					),
				);
			}
			if (sans.length > 0) {
				return failure(
					'service_identity_service_mismatch',
					'SRV service not present in SAN',
					details(
						certificate.subject.values.commonName,
						expected.serviceType,
						sans
							.flatMap((entry) => {
								const parsed = tryParseSrvServiceIdentity(entry.value);
								return parsed === undefined ? [] : [parsed.serviceType];
							})
							.join(','),
					),
				);
			}
			return failure(
				'subject_alt_name_mismatch',
				'SRV-ID not present in SAN',
				details(certificate.subject.values.commonName, expected.domainName, ''),
			);
		}
		default: {
			const _exhaustive: never = serviceIdentity;
			throw new Error(`Unhandled service identity type: ${String(_exhaustive)}`);
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

interface ServiceScopedIdentity {
	readonly serviceType: string;
	readonly domainName: string;
}

function parseUriServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseUriServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid URI service identity: ${value}`);
	}
	return parsed;
}

function tryParseUriServiceIdentity(value: string): ServiceScopedIdentity | undefined {
	const schemeEnd = value.indexOf(':');
	if (schemeEnd <= 0) {
		return undefined;
	}
	const serviceType = value.slice(0, schemeEnd).toLowerCase();
	const domainName = extractUriRegName(value);
	if (domainName === undefined) {
		return undefined;
	}
	return { serviceType, domainName: domainName.toLowerCase() };
}

function extractUriRegName(value: string): string | undefined {
	const schemeEnd = value.indexOf(':');
	if (schemeEnd <= 0) {
		return undefined;
	}
	const schemeSpecific = value.slice(schemeEnd + 1);
	let authority = cutAtFirstDelimiter(
		schemeSpecific.startsWith('//') ? schemeSpecific.slice(2) : schemeSpecific,
		['/', '?', '#'],
	);
	const userInfoSeparator = authority.lastIndexOf('@');
	if (userInfoSeparator >= 0) {
		authority = authority.slice(userInfoSeparator + 1);
	}
	if (authority.startsWith('[')) {
		return undefined;
	}
	const host = cutAtFirstDelimiter(authority, [':', ';']);
	if (host.length === 0 || host.includes('[') || host.includes(']')) {
		return undefined;
	}
	return host;
}

function cutAtFirstDelimiter(value: string, delimiters: readonly string[]): string {
	let end = value.length;
	for (const delimiter of delimiters) {
		const index = value.indexOf(delimiter);
		if (index >= 0 && index < end) {
			end = index;
		}
	}
	return value.slice(0, end);
}

function parseSrvServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseSrvServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid SRV service identity: ${value}`);
	}
	return parsed;
}

function tryParseSrvServiceIdentity(value: string): ServiceScopedIdentity | undefined {
	if (!value.startsWith('_')) {
		return undefined;
	}
	const dotIndex = value.indexOf('.');
	if (dotIndex <= 1 || dotIndex === value.length - 1) {
		return undefined;
	}
	return {
		serviceType: value.slice(1, dotIndex).toLowerCase(),
		domainName: value.slice(dotIndex + 1).toLowerCase(),
	};
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
