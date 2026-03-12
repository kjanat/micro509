import type { Micro509Error, Result } from './core/result.ts';
import { normalizeIpAddress } from './ip.ts';
import type { ParsedCertificate } from './parse.ts';
import type { MatchableServiceIdentityInput, ServiceIdentityInput } from './validation.ts';

export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'common_name_fallback_suppressed'
	| 'service_identity_service_mismatch'
	| 'service_identity_type_unsupported';

export interface MatchServiceIdentityFailureDetails {
	readonly subjectCommonName?: string;
	readonly expected?: string;
	readonly actual?: string;
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

export interface MatchServiceIdentityFailure
	extends Micro509Error<MatchServiceIdentityErrorCode, MatchServiceIdentityFailureDetails> {
	readonly ok: false;
}

export type MatchServiceIdentityResult = { readonly ok: true } | MatchServiceIdentityFailure;

export type MatchServiceIdentityEvaluation = Result<void, MatchServiceIdentityFailure>;

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
			if (sans.some((entry) => matchesDnsName(entry.value, expected))) {
				return { ok: true };
			}
			const presentedIdentifierTypes = presentedDnsIdentifierTypes(certificate);
			if (serviceIdentity.allowCommonNameFallback === true && presentedIdentifierTypes.length > 0) {
				return failure(
					'common_name_fallback_suppressed',
					'DNS name not present in SAN; CN fallback suppressed because supported SAN identifiers exist',
					details(
						certificate.subject.values.commonName,
						expected,
						sans.map((entry) => entry.value).join(','),
						{
							presentedIdentifierTypes,
							commonNameFallbackReason: 'suppressed_by_presented_identifier',
						},
					),
				);
			}
			if (sans.length > 0) {
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
			if (serviceIdentity.allowCommonNameFallback === true) {
				const commonName = certificate.subject.values.commonName;
				if (commonName === undefined || !matchesDnsName(commonName, expected)) {
					return failure(
						'subject_alt_name_mismatch',
						'DNS name not present in SAN or CN',
						details(commonName, expected, commonName ?? '', {
							commonNameFallbackReason:
								commonName === undefined ? 'common_name_missing' : 'common_name_mismatch',
						}),
					);
				}
				return { ok: true };
			}
			return failure(
				'subject_alt_name_mismatch',
				'DNS name not present in SAN',
				details(certificate.subject.values.commonName, expected, '', {
					commonNameFallbackReason: 'disabled',
				}),
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
	const lowerPattern = normalizeDnsPattern(pattern);
	const lowerActual = normalizeDnsName(actual);
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

function normalizeDnsPattern(value: string): string {
	if (!value.startsWith('*.')) {
		return normalizeDnsName(value);
	}
	return `*.${normalizeDnsName(value.slice(2))}`;
}

function normalizeDnsName(value: string): string {
	const normalized = tryNormalizeDnsName(value);
	return normalized ?? value.toLowerCase();
}

function tryNormalizeDnsName(value: string): string | undefined {
	if (value.length === 0) {
		return undefined;
	}
	for (const forbidden of ['/', ':', '?', '#', '@', '[', ']']) {
		if (value.includes(forbidden)) {
			return undefined;
		}
	}
	try {
		return new URL(`https://${value}`).hostname.toLowerCase();
	} catch {
		return undefined;
	}
}

interface ServiceScopedIdentity {
	readonly serviceType: string;
	readonly domainName: string;
}

function presentedDnsIdentifierTypes(
	certificate: ParsedCertificate,
): readonly ('dns' | 'uri' | 'srv')[] {
	const sans = certificate.subjectAltNames ?? [];
	const types: ('dns' | 'uri' | 'srv')[] = [];
	for (const type of ['dns', 'uri', 'srv'] as const) {
		if (sans.some((entry) => entry.type === type)) {
			types.push(type);
		}
	}
	return types;
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
	return { serviceType, domainName: normalizeDnsName(domainName) };
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
		domainName: normalizeDnsName(value.slice(dotIndex + 1)),
	};
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
	extra?: Pick<
		MatchServiceIdentityFailureDetails,
		'presentedIdentifierTypes' | 'commonNameFallbackReason'
	>,
): MatchServiceIdentityFailureDetails {
	return {
		...(subjectCommonName === undefined ? {} : { subjectCommonName }),
		expected,
		actual,
		...(extra?.presentedIdentifierTypes === undefined
			? {}
			: { presentedIdentifierTypes: extra.presentedIdentifierTypes }),
		...(extra?.commonNameFallbackReason === undefined
			? {}
			: { commonNameFallbackReason: extra.commonNameFallbackReason }),
	};
}
