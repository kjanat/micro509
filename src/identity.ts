/**
 * Service-identity matching helpers.
 *
 * This module implements DNS, IP, URI, and SRV identifier comparison for certificate
 * consumers.
 */

import { normalizeIpAddress } from './ip.ts';
import type { ParsedCertificate } from './parse.ts';
import type { ErrorResult, Micro509Error, Result } from './result.ts';
import { errorResult, micro509Error, successResult } from './result.ts';

/**
 * Describes the input shape for DNS service identity operations.
 */
export interface DnsServiceIdentityInput {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'dns';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
	/**
	 * Indicates whether allow common name fallback.
	 */
	readonly allowCommonNameFallback?: boolean;
}

/**
 * Describes the input shape for IP service identity operations.
 */
export interface IpServiceIdentityInput {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'ip';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Describes the input shape for URI service identity operations.
 */
export interface UriServiceIdentityInput {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'uri';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Describes the input shape for SRV service identity operations.
 */
export interface SrvServiceIdentityInput {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'srv';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Describes the input shape for service identity operations.
 */
export type ServiceIdentityInput =
	| DnsServiceIdentityInput
	| IpServiceIdentityInput
	| UriServiceIdentityInput
	| SrvServiceIdentityInput;

/**
 * Defines service identity type.
 */
export type ServiceIdentityType = ServiceIdentityInput['type'];
/**
 * Describes the input shape for matchable service identity operations.
 */
export type MatchableServiceIdentityInput = ServiceIdentityInput;
/**
 * Describes the input shape for verify service identity operations.
 */
export type VerifyServiceIdentityInput = DnsServiceIdentityInput | IpServiceIdentityInput;

/**
 * Enumerates the error codes used by match service identity failures.
 */
export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'common_name_fallback_suppressed'
	| 'service_identity_service_mismatch'
	| 'service_identity_type_unsupported';

/**
 * Carries structured details for match service identity failures.
 */
export interface MatchServiceIdentityFailureDetails {
	/**
	 * Carries the subject common name value.
	 */
	readonly subjectCommonName?: string;
	/**
	 * Carries the expected value.
	 */
	readonly expected?: string;
	/**
	 * Carries the actual value.
	 */
	readonly actual?: string;
	/**
	 * Carries the presented identifier types value.
	 */
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	/**
	 * Carries the common name fallback reason value.
	 */
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

/**
 * Represents a typed failure produced by match service identity operations.
 */
export interface MatchServiceIdentityFailure
	extends Micro509Error<MatchServiceIdentityErrorCode, MatchServiceIdentityFailureDetails> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents a successful outcome produced by match service identity operations.
 */
export interface MatchServiceIdentitySuccess {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: undefined;
}

/**
 * Represents the result returned by match service identity failure operations.
 */
export type MatchServiceIdentityFailureResult = ErrorResult<
	MatchServiceIdentityErrorCode,
	MatchServiceIdentityFailureDetails,
	MatchServiceIdentityFailure
>;

/**
 * Represents the result returned by match service identity operations.
 */
export type MatchServiceIdentityResult =
	| MatchServiceIdentitySuccess
	| MatchServiceIdentityFailureResult;

/**
 * Defines match service identity evaluation.
 */
export type MatchServiceIdentityEvaluation = Result<void, MatchServiceIdentityFailure>;

/**
 * Describes the input shape for match service identity operations.
 */
export interface MatchServiceIdentityInput {
	/**
	 * Carries the certificate value.
	 */
	readonly certificate: ParsedCertificate;
	/**
	 * Carries the service identity value.
	 */
	readonly serviceIdentity: ServiceIdentityInput;
}

/**
 * Matches service identity.
 *
 * @param input The typed input payload.
 * @returns The matching result.
 */
export function matchServiceIdentity(input: MatchServiceIdentityInput): MatchServiceIdentityResult {
	return matchCertificateServiceIdentity(input.certificate, input.serviceIdentity);
}

/**
 * Matches certificate service identity.
 *
 * @param certificate The certificate input.
 * @param serviceIdentity The service identity value.
 * @returns The matching result.
 */
export function matchCertificateServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: MatchableServiceIdentityInput,
): MatchServiceIdentityResult {
	switch (serviceIdentity.type) {
		case 'dns': {
			const expected = serviceIdentity.value;
			const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'dns') ?? [];
			if (sans.some((entry) => matchesDnsName(entry.value, expected))) {
				return success();
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
				return success();
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
			return success();
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
				return success();
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
				return success();
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

/**
 * Matches es DNS name.
 *
 * @param pattern The pattern value.
 * @param actual The actual value.
 * @returns The computed value.
 */
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

/**
 * Normalizes DNS pattern.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function normalizeDnsPattern(value: string): string {
	if (!value.startsWith('*.')) {
		return normalizeDnsName(value);
	}
	return `*.${normalizeDnsName(value.slice(2))}`;
}

/**
 * Normalizes DNS name.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function normalizeDnsName(value: string): string {
	const normalized = tryNormalizeDnsName(value);
	return normalized ?? value.toLowerCase();
}

/**
 * Try normalize DNS name.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
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

/**
 * Describes service scoped identity.
 */
interface ServiceScopedIdentity {
	/**
	 * Carries the service type value.
	 */
	readonly serviceType: string;
	/**
	 * Carries the domain name value.
	 */
	readonly domainName: string;
}

/**
 * Presented DNS identifier types.
 *
 * @param certificate The certificate input.
 * @returns The computed value.
 */
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

/**
 * Parses URI service identity.
 *
 * @param value The value to process.
 * @returns The parsed URI service identity.
 */
function parseUriServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseUriServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid URI service identity: ${value}`);
	}
	return parsed;
}

/**
 * Try parse URI service identity.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
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

/**
 * Extract URI reg name.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
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

/**
 * Cut at first delimiter.
 *
 * @param value The value to process.
 * @param delimiters The delimiters value.
 * @returns The computed value.
 */
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

/**
 * Parses SRV service identity.
 *
 * @param value The value to process.
 * @returns The parsed SRV service identity.
 */
function parseSrvServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseSrvServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid SRV service identity: ${value}`);
	}
	return parsed;
}

/**
 * Try parse SRV service identity.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
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

/**
 * Failure.
 *
 * @param code The code value.
 * @param message The message value.
 * @param details The structured details value.
 * @returns The computed value.
 */
function failure(
	code: MatchServiceIdentityErrorCode,
	message: string,
	details?: MatchServiceIdentityFailureDetails,
): MatchServiceIdentityResult {
	const error: MatchServiceIdentityFailure = {
		/**
		 * Indicates whether the operation succeeded.
		 */
		ok: false,
		...micro509Error(code, message, details),
	};
	return errorResult(error);
}

/**
 * Success.
 *
 * @returns The computed value.
 */
function success(): MatchServiceIdentitySuccess {
	return successResult(undefined);
}

/**
 * Details.
 *
 * @param subjectCommonName The subject common name value.
 * @param expected The expected value.
 * @param actual The actual value.
 * @param extra The extra value.
 * @returns The computed value.
 */
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
