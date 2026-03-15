/**
 * Service-identity matching (RFC 6125 / RFC 9525).
 *
 * Compares a reference identifier (hostname, IP, URI, SRV name) against the
 * presented identifiers in a certificate's SAN extension, with optional
 * common-name fallback for DNS names.
 *
 * @module
 */

import { normalizeIpAddress } from '#micro509/internal/shared/ip.ts';
import type { ErrorResult, Micro509Error, Result } from '#micro509/result/result.ts';
import { errorResult, micro509Error, successResult } from '#micro509/result/result.ts';
import type { ParsedCertificate } from '#micro509/x509/parse.ts';

/** DNS hostname reference identifier. */
export interface DnsServiceIdentityInput {
	/** Discriminant for DNS hostname matching. */
	readonly type: 'dns';
	/** The hostname to match (e.g. `"mail.example.com"`). Wildcard labels in the certificate are handled internally. */
	readonly value: string;
	/**
	 * When `true`, falls back to the subject CN if the SAN extension has no
	 * dns/uri/srv entries. Suppressed when any supported SAN type is present.
	 * Default: `false`.
	 */
	readonly allowCommonNameFallback?: boolean;
}

/** IP address reference identifier. */
export interface IpServiceIdentityInput {
	/** Discriminant for IP address matching. */
	readonly type: 'ip';
	/** IPv4 or IPv6 address string. Normalized before comparison. */
	readonly value: string;
}

/** URI-ID reference identifier (RFC 6125 §6.5). Scheme and host are matched. */
export interface UriServiceIdentityInput {
	/** Discriminant for URI-ID matching. */
	readonly type: 'uri';
	/** Full URI whose scheme and reg-name will be compared. */
	readonly value: string;
}

/** SRV-ID reference identifier (RFC 4985). */
export interface SrvServiceIdentityInput {
	/** Discriminant for SRV-ID matching. */
	readonly type: 'srv';
	/** SRV name in `_service.domain` form (e.g. `"_imap.example.com"`). */
	readonly value: string;
}

/** Discriminated union of all supported reference identifier types. */
export type ServiceIdentityInput =
	| DnsServiceIdentityInput
	| IpServiceIdentityInput
	| UriServiceIdentityInput
	| SrvServiceIdentityInput;

/** The `type` discriminant values of {@linkcode ServiceIdentityInput}. */
export type ServiceIdentityType = ServiceIdentityInput['type'];
/** Alias for the full identity union accepted by matching functions. */
export type MatchableServiceIdentityInput = ServiceIdentityInput;
/** Subset of identities usable for TLS server verification (DNS and IP only). */
export type VerifyServiceIdentityInput = DnsServiceIdentityInput | IpServiceIdentityInput;

/** Discriminant codes for identity-matching failures. */
export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'common_name_fallback_suppressed'
	| 'service_identity_service_mismatch'
	| 'service_identity_type_unsupported';

/** Diagnostic context attached to an identity-matching failure. */
export interface MatchServiceIdentityFailureDetails {
	/** CN of the certificate that was being matched, if present. */
	readonly subjectCommonName?: string;
	/** The reference identifier the caller asked to verify. */
	readonly expected?: string;
	/** Comma-joined presented identifiers (from SAN) that were compared. */
	readonly actual?: string;
	/** SAN types that were present, relevant to CN-fallback suppression logic. */
	readonly presentedIdentifierTypes?: readonly ('dns' | 'uri' | 'srv')[];
	/** Explains why CN fallback was not used or failed. */
	readonly commonNameFallbackReason?:
		| 'disabled'
		| 'suppressed_by_presented_identifier'
		| 'common_name_missing'
		| 'common_name_mismatch';
}

/** A failed identity-matching attempt. */
export interface MatchServiceIdentityFailure
	extends Micro509Error<MatchServiceIdentityErrorCode, MatchServiceIdentityFailureDetails> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** A successful identity match (the certificate covers the requested name). */
export interface MatchServiceIdentitySuccess {
	/** Always `true` for success. */
	readonly ok: true;
	/** No payload on success — the match itself is the signal. */
	readonly value: undefined;
}

/** Failure branch of {@linkcode MatchServiceIdentityResult} with structured error details. */
export type MatchServiceIdentityFailureResult = ErrorResult<
	MatchServiceIdentityErrorCode,
	MatchServiceIdentityFailureDetails,
	MatchServiceIdentityFailure
>;

/** Result of matching a reference identifier against a certificate's presented identifiers. */
export type MatchServiceIdentityResult =
	| MatchServiceIdentitySuccess
	| ErrorResult<
			MatchServiceIdentityErrorCode,
			MatchServiceIdentityFailureDetails,
			MatchServiceIdentityFailure
	  >;

/** Void-valued result type used internally during identity evaluation. */
export type MatchServiceIdentityEvaluation = Result<void, MatchServiceIdentityFailure>;

/** Input for {@linkcode matchServiceIdentity}. */
export interface MatchServiceIdentityInput {
	/** The parsed leaf certificate to check. */
	readonly certificate: ParsedCertificate;
	/** The reference identifier the client wants to verify. */
	readonly serviceIdentity: ServiceIdentityInput;
}

/**
 * Checks whether a certificate covers the requested service identity.
 *
 * Delegates to {@linkcode matchCertificateServiceIdentity} — this overload
 * accepts a single options object.
 *
 * @example
 * ```ts
 * const result = matchServiceIdentity({
 *   certificate: parsed,
 *   serviceIdentity: { type: 'dns', value: 'example.com' },
 * });
 * if (!result.ok) console.error(result.error.message);
 * ```
 */
export function matchServiceIdentity(input: MatchServiceIdentityInput): MatchServiceIdentityResult {
	return matchCertificateServiceIdentity(input.certificate, input.serviceIdentity);
}

/**
 * Compares a reference identifier against a certificate's SAN entries.
 *
 * Supports DNS (with wildcard matching), IP, URI-ID, and SRV-ID.
 * For DNS, optionally falls back to subject CN when no SAN of a supported
 * type is present.
 *
 * @example
 * ```ts
 * const result = matchCertificateServiceIdentity(parsed, {
 *   type: 'ip',
 *   value: '192.168.1.1',
 * });
 * ```
 *
 * @example
 * ```ts
 * const result = matchCertificateServiceIdentity(parsed, {
 *   type: 'dns',
 *   value: 'mail.example.com',
 *   allowCommonNameFallback: true,
 * });
 * ```
 */
export function matchCertificateServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: ServiceIdentityInput,
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

/** Compares a presented DNS identifier (possibly wildcarded) against a reference name. */
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

/** Lowercases a DNS pattern, preserving the `*.` wildcard prefix if present. */
function normalizeDnsPattern(value: string): string {
	if (!value.startsWith('*.')) {
		return normalizeDnsName(value);
	}
	return `*.${normalizeDnsName(value.slice(2))}`;
}

/** Lowercases and IDNA-normalizes a DNS name via the URL parser. */
function normalizeDnsName(value: string): string {
	const normalized = tryNormalizeDnsName(value);
	return normalized ?? value.toLowerCase();
}

/** Attempts IDNA normalization via URL constructor. Returns `undefined` for invalid names. */
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

/** Decomposed URI-ID or SRV-ID: a service type discriminant plus a domain. */
interface ServiceScopedIdentity {
	/** URI scheme (e.g. `"https"`) or SRV service label (e.g. `"imap"`). */
	readonly serviceType: string;
	/** Normalized domain name portion for DNS comparison. */
	readonly domainName: string;
}

/** Returns which SAN types (dns, uri, srv) the certificate presents, used for CN-fallback suppression. */
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

/** Parses a URI into scheme + host. Throws on malformed input. */
function parseUriServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseUriServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid URI service identity: ${value}`);
	}
	return parsed;
}

/** Attempts to split a URI into scheme + reg-name. Returns `undefined` on failure. */
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

/** Extracts the reg-name host from a URI, stripping scheme, userinfo, port, and path components. */
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

/** Returns the substring before the first occurrence of any delimiter character. */
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

/** Parses an SRV name (`_service.domain`) into parts. Throws on malformed input. */
function parseSrvServiceIdentity(value: string): ServiceScopedIdentity {
	const parsed = tryParseSrvServiceIdentity(value);
	if (parsed === undefined) {
		throw new Error(`Invalid SRV service identity: ${value}`);
	}
	return parsed;
}

/** Attempts to split `_service.domain` into parts. Returns `undefined` on failure. */
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

/** Constructs a failure result with the given error code and diagnostic details. */
function failure(
	code: MatchServiceIdentityErrorCode,
	message: string,
	details?: MatchServiceIdentityFailureDetails,
): MatchServiceIdentityResult {
	const error: MatchServiceIdentityFailure = {
		ok: false,
		...micro509Error(code, message, details),
	};
	return errorResult(error);
}

/** Constructs a success result indicating the identity matched. */
function success(): MatchServiceIdentitySuccess {
	return successResult(undefined);
}

/** Assembles failure detail fields, merging optional CN-fallback and identifier-type info. */
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
