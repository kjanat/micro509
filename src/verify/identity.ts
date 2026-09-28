/**
 * Service-identity matching (RFC 9525), with opt-in CN fallback from the
 * obsoleted RFC 6125 §6.4.4.
 *
 * Compares a reference identifier (hostname, IP, URI, SRV name) against the
 * presented identifiers in a certificate's SAN extension, with optional
 * common-name fallback for DNS names.
 *
 * @module
 */

import { DECODE_REFUSAL_CODES, decodeRefusalOf } from '#micro509/internal/asn1/decode-refusal';
import { presentedDomainToAscii, referenceDomainToAscii } from '#micro509/internal/shared/idna';
import { decodeIpAddress, parseIpAddressToBytes } from '#micro509/internal/shared/ip';
import type { UriHost, UriHostSource } from '#micro509/internal/shared/uri-host';
import { hostportHost, uriAuthorityHost } from '#micro509/internal/shared/uri-host';
import { parsePresentedSrvName } from '#micro509/internal/x509/general-name-profile';
import type { DecodeRefusalCode, ErrorResult, Micro509Error } from '#micro509/result/result';
import { errorResult, micro509Error, successResult } from '#micro509/result/result';
import type { SubjectAltName } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateDerOrThrow } from '#micro509/x509/parse';

/** DNS hostname reference identifier. */
export interface DnsServiceIdentityInput {
	/** Discriminant for DNS hostname matching. */
	readonly type: 'dns';
	/** The hostname to match (e.g. `"mail.example.com"`). Wildcard labels in the certificate are handled internally. */
	readonly value: string;
	/**
	 * When `true`, falls back to the subject CN if the SAN extension has no
	 * dns/uri/srv entries. Suppressed when any supported SAN type is present.
	 * RFC 9525 §4.1 forbids identifying a service by the Common Name RDN.
	 * @default false
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

/** URI-ID reference identifier (RFC 9525 §§6.2-6.5). Scheme and host are matched. */
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
/** Discriminant codes for identity-matching failures. */
export type MatchServiceIdentityErrorCode =
	| 'subject_alt_name_mismatch'
	| 'common_name_fallback_suppressed'
	| 'service_identity_mismatch'
	| 'unsupported_service_identity_type'
	| DecodeRefusalCode;

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
	| MatchServiceIdentityFailureResult;

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
 * For DNS, optionally falls back to subject CN when no SAN of a supported type is present.
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
	rawCertificate: ParsedCertificate,
	serviceIdentity: ServiceIdentityInput,
): MatchServiceIdentityResult {
	let certificate: ParsedCertificate;
	try {
		certificate = parseCertificateDerOrThrow(new Uint8Array(rawCertificate.der));
	} catch (error) {
		const refusal = decodeRefusalOf(error, DECODE_REFUSAL_CODES);
		return refusal === undefined
			? failure('subject_alt_name_mismatch', 'certificate input is malformed')
			: failure(refusal.code, refusal.message);
	}
	switch (serviceIdentity.type) {
		case 'dns':
			return matchDnsServiceIdentity(certificate, serviceIdentity);
		case 'ip':
			return matchIpServiceIdentity(certificate, serviceIdentity);
		case 'uri':
			return matchScopedServiceIdentity(certificate, serviceIdentity, {
				parse: tryParseUriServiceIdentity,
				sanType: 'uri',
				missingMessage: 'URI-ID not present in SAN',
				serviceMismatchMessage: 'URI scheme not present in SAN',
				domainMismatchMessage: 'URI host not present in SAN',
			});
		case 'srv':
			return matchScopedServiceIdentity(certificate, serviceIdentity, {
				parse: tryParseSrvServiceIdentity,
				sanType: 'srv',
				missingMessage: 'SRV-ID not present in SAN',
				serviceMismatchMessage: 'SRV service not present in SAN',
				domainMismatchMessage: 'SRV domain not present in SAN',
			});
		default: {
			return failure('unsupported_service_identity_type', 'Unsupported service identity type');
		}
	}
}

/** Matches a DNS service identity against SANs and the explicitly enabled CN fallback. */
function matchDnsServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: DnsServiceIdentityInput,
): MatchServiceIdentityResult {
	if (typeof serviceIdentity.value !== 'string') {
		return malformedServiceIdentityFailure(certificate, 'dns', serviceIdentity.value);
	}
	const expected = serviceIdentity.value;
	const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'dns') ?? [];
	if (sans.some((entry) => matchesDnsName(entry.value, expected))) {
		return success();
	}
	return matchDnsFallback(
		certificate,
		expected,
		sans,
		serviceIdentity.allowCommonNameFallback === true,
	);
}

function matchDnsFallback(
	certificate: ParsedCertificate,
	expected: string,
	sans: readonly { readonly value: string }[],
	allowCommonNameFallback: boolean,
): MatchServiceIdentityResult {
	const presentedIdentifierTypes = presentedDnsIdentifierTypes(certificate);
	if (allowCommonNameFallback && presentedIdentifierTypes.length > 0) {
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
	if (!allowCommonNameFallback) {
		return failure(
			'subject_alt_name_mismatch',
			'DNS name not present in SAN',
			details(certificate.subject.values.commonName, expected, '', {
				commonNameFallbackReason: 'disabled',
			}),
		);
	}
	return matchCommonNameFallback(certificate, expected);
}

function matchCommonNameFallback(
	certificate: ParsedCertificate,
	expected: string,
): MatchServiceIdentityResult {
	const commonName = certificate.subject.values.commonName;
	if (commonName !== undefined && matchesDnsName(commonName, expected)) {
		return success();
	}
	return failure(
		'subject_alt_name_mismatch',
		'DNS name not present in SAN or CN',
		details(commonName, expected, commonName ?? '', {
			commonNameFallbackReason:
				commonName === undefined ? 'common_name_missing' : 'common_name_mismatch',
		}),
	);
}

function matchIpServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: IpServiceIdentityInput,
): MatchServiceIdentityResult {
	if (typeof serviceIdentity.value !== 'string') {
		return malformedServiceIdentityFailure(certificate, 'ip', serviceIdentity.value);
	}
	const expectedBytes = tryParsePresentedIpAddress(serviceIdentity.value);
	if (expectedBytes === undefined) {
		return malformedServiceIdentityFailure(certificate, 'ip', serviceIdentity.value);
	}
	return matchParsedIpServiceIdentity(certificate, expectedBytes);
}

function matchParsedIpServiceIdentity(
	certificate: ParsedCertificate,
	expectedBytes: Uint8Array,
): MatchServiceIdentityResult {
	const expected = decodeIpAddress(expectedBytes);
	const sans = certificate.subjectAltNames?.filter((entry) => entry.type === 'ip') ?? [];
	const presentedAddresses: string[] = [];
	for (const entry of sans) {
		const presentedBytes = tryParsePresentedIpAddress(entry.value);
		if (presentedBytes === undefined) {
			return failure(
				'subject_alt_name_mismatch',
				'IP address SAN is malformed',
				details(certificate.subject.values.commonName, expected, `ip:${entry.value}`),
			);
		}
		presentedAddresses.push(decodeIpAddress(presentedBytes));
		if (sameIpAddressBytes(presentedBytes, expectedBytes)) {
			return success();
		}
	}
	return failure(
		'subject_alt_name_mismatch',
		'IP address not present in SAN',
		details(certificate.subject.values.commonName, expected, presentedAddresses.join(',')),
	);
}

interface ScopedServiceIdentityOptions {
	readonly parse: (value: string, source: UriHostSource) => ServiceScopedIdentity | undefined;
	readonly sanType: 'uri' | 'srv';
	readonly missingMessage: string;
	readonly serviceMismatchMessage: string;
	readonly domainMismatchMessage: string;
}

type ScopedSubjectAltName =
	| Extract<SubjectAltName, { readonly type: 'uri' }>
	| Extract<SubjectAltName, { readonly type: 'srv' }>;

function matchScopedServiceIdentity(
	certificate: ParsedCertificate,
	serviceIdentity: UriServiceIdentityInput | SrvServiceIdentityInput,
	options: ScopedServiceIdentityOptions,
): MatchServiceIdentityResult {
	if (typeof serviceIdentity.value !== 'string') {
		return malformedServiceIdentityFailure(
			certificate,
			serviceIdentity.type,
			serviceIdentity.value,
		);
	}
	const expected = options.parse(serviceIdentity.value, 'reference');
	if (expected === undefined) {
		return malformedServiceIdentityFailure(
			certificate,
			serviceIdentity.type,
			serviceIdentity.value,
		);
	}
	const sans =
		certificate.subjectAltNames?.filter((entry) =>
			isScopedSubjectAltName(entry, options.sanType),
		) ?? [];
	const matchingService = sans.flatMap((entry) => {
		const parsed = options.parse(entry.value, 'presented');
		return parsed === undefined || parsed.serviceType !== expected.serviceType ? [] : [parsed];
	});
	if (matchingService.some((entry) => matchesServiceHost(entry.host, expected.host))) {
		return success();
	}
	return scopedServiceIdentityFailure(certificate, expected, sans, matchingService, options);
}

function isScopedSubjectAltName(
	entry: SubjectAltName,
	sanType: 'uri' | 'srv',
): entry is ScopedSubjectAltName {
	return entry.type === sanType;
}

function scopedServiceIdentityFailure(
	certificate: ParsedCertificate,
	expected: ServiceScopedIdentity,
	sans: readonly { readonly value: string }[],
	matchingService: readonly ServiceScopedIdentity[],
	options: ScopedServiceIdentityOptions,
): MatchServiceIdentityResult {
	if (matchingService.length > 0) {
		return failure(
			'subject_alt_name_mismatch',
			options.domainMismatchMessage,
			details(
				certificate.subject.values.commonName,
				serviceHostText(expected.host),
				matchingService.map((entry) => serviceHostText(entry.host)).join(','),
			),
		);
	}
	if (sans.length > 0) {
		return failure(
			'service_identity_mismatch',
			options.serviceMismatchMessage,
			details(
				certificate.subject.values.commonName,
				expected.serviceType,
				sans.flatMap((entry) => serviceTypeFromSanValue(entry.value, options.parse)).join(','),
			),
		);
	}
	return failure(
		'subject_alt_name_mismatch',
		options.missingMessage,
		details(certificate.subject.values.commonName, serviceHostText(expected.host), ''),
	);
}

function serviceTypeFromSanValue(
	value: string,
	parse: ScopedServiceIdentityOptions['parse'],
): readonly string[] {
	const parsed = parse(value, 'presented');
	return parsed === undefined ? [] : [parsed.serviceType];
}

/** Compares a presented DNS identifier (possibly wildcarded) against a reference name. */
function matchesDnsName(pattern: string, actual: string): boolean {
	const lowerPattern = normalizeDnsPattern(pattern);
	const lowerActual = tryNormalizeDnsName(actual);
	if (lowerActual === undefined) {
		return false;
	}
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
 * Lowercases the ASCII letters of a presented DNS identifier and nothing else:
 * RFC 9549 §2.3 compares DNS names by a case-insensitive exact match, so no
 * percent-decoding, IPv4 parsing or IDNA mapping applies to what the
 * certificate presents.
 */
function normalizeDnsPattern(value: string): string {
	return value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}

/**
 * RFC 9525 §6.3: a reference domain name in A-labels, lowercased. Returns
 * `undefined` for a name with URI delimiters or one that is not valid IDNA2008.
 */
function tryNormalizeDnsName(value: string): string | undefined {
	if (value.length === 0 || /[/:?#@[\]]/.test(value)) {
		return undefined;
	}
	return referenceDomainToAscii(value);
}

/** Decomposed URI-ID or SRV-ID: a service type discriminant plus a host. */
interface ServiceScopedIdentity {
	/** URI scheme (e.g. `"https"`) or SRV service label (e.g. `"imap"`). */
	readonly serviceType: string;
	/** Domain name in A-labels, which a presented identifier may wildcard, or an IP address. */
	readonly host: ServiceHost;
}

type ServiceHost =
	| { readonly type: 'dns'; readonly name: string }
	| { readonly type: 'ip'; readonly bytes: Uint8Array };

/** RFC 9525 §6.3 compares domain names and §6.4 compares IP addresses by their octets. */
function matchesServiceHost(presented: ServiceHost, reference: ServiceHost): boolean {
	return presented.type === 'ip'
		? reference.type === 'ip' && sameIpAddressBytes(presented.bytes, reference.bytes)
		: reference.type === 'dns' && matchesDnsName(presented.name, reference.name);
}

function serviceHostText(host: ServiceHost): string {
	return host.type === 'ip' ? decodeIpAddress(host.bytes) : host.name;
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

/** RFC 9525 §6.2: a URI-ID's scheme and the host of its authority, or of a SIP URI. */
function tryParseUriServiceIdentity(
	value: string,
	source: UriHostSource,
): ServiceScopedIdentity | undefined {
	const schemeEnd = value.indexOf(':');
	if (schemeEnd <= 0 || !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(value.slice(0, schemeEnd))) {
		return undefined;
	}
	const serviceType = value.slice(0, schemeEnd).toLowerCase();
	const sip = serviceType === 'sip' || serviceType === 'sips';
	const host =
		sip && !value.startsWith('//', schemeEnd + 1)
			? sipUriHost(value.slice(schemeEnd + 1), source)
			: uriAuthorityHost(value, source);
	const serviceHost = uriServiceHost(host, source === 'presented' && !sip);
	return serviceHost === undefined ? undefined : { serviceType, host: serviceHost };
}

/** RFC 3261 §25.1 userinfo without its "@": a non-empty user and an optional password. */
const SIP_USERINFO =
	/^(?:[A-Za-z0-9\-_.!~*'()&=+$,;?/]|%[0-9A-Fa-f]{2})+(?::(?:[A-Za-z0-9\-_.!~*'()&=+$,]|%[0-9A-Fa-f]{2})*)?$/;

/**
 * RFC 3261 §25.1: the only "@" a SIP URI may hold ends its userinfo, and the
 * hostport after it ends at its parameters or headers, holds no escaped
 * octets, and gives a port at least one digit.
 */
function sipUriHost(schemeSpecific: string, source: UriHostSource): UriHost {
	const at = schemeSpecific.indexOf('@');
	const afterUserinfo = schemeSpecific.slice(at + 1);
	const hostport = afterUserinfo.split(/[;?]/, 1)[0] ?? '';
	return (at >= 0 && !SIP_USERINFO.test(schemeSpecific.slice(0, at))) ||
		afterUserinfo.includes('@') ||
		hostport.includes('%') ||
		hostport.endsWith(':')
		? { type: 'invalid' }
		: hostportHost(hostport, source);
}

/**
 * RFC 9525 §6.3: a presented wildcard is the whole left-most label of the
 * domain name. RFC 5922 §7.2 prohibits wildcards for SIP domains.
 */
function uriServiceHost(host: UriHost, wildcardAllowed: boolean): ServiceHost | undefined {
	switch (host.type) {
		case 'dns':
		case 'ip':
			return host;
		case 'regName': {
			const parent =
				wildcardAllowed && host.value.startsWith('*.')
					? presentedDomainToAscii(host.value.slice(2))
					: undefined;
			return parent === undefined ? undefined : { type: 'dns', name: `*.${parent}` };
		}
		case 'absent':
		case 'invalid':
			return undefined;
		default: {
			const _exhaustive: never = host;
			throw new Error(`Unhandled UriHost type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * RFC 4985 §2 `_Service.Name`. RFC 9525 §6.3 lets a presented Name open with
 * a `*` label.
 */
function tryParseSrvServiceIdentity(
	value: string,
	source: UriHostSource,
): ServiceScopedIdentity | undefined {
	if (!value.startsWith('_')) {
		return undefined;
	}
	const dotIndex = value.indexOf('.');
	if (dotIndex <= 1 || dotIndex === value.length - 1) {
		return undefined;
	}
	const domain = value.slice(dotIndex + 1);
	const wildcard = source === 'presented' && domain.startsWith('*.');
	const domainName = tryNormalizeDnsName(wildcard ? domain.slice(2) : domain);
	const parts =
		domainName === undefined
			? undefined
			: parsePresentedSrvName(`${value.slice(0, dotIndex).toLowerCase()}.${domainName}`);
	return parts === undefined
		? undefined
		: {
				serviceType: parts.service.slice(1),
				host: { type: 'dns', name: wildcard ? `*.${parts.name}` : parts.name },
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

function malformedServiceIdentityFailure(
	certificate: ParsedCertificate,
	type: ServiceIdentityType,
	value: unknown,
): MatchServiceIdentityResult {
	const renderedValue = typeof value === 'string' ? value : '<malformed>';
	return failure(
		'subject_alt_name_mismatch',
		'service identity input is malformed',
		details(certificate.subject.values.commonName, `${type}:${renderedValue}`, type),
	);
}

function tryParsePresentedIpAddress(value: string): Uint8Array | undefined {
	try {
		return parseIpAddressToBytes(value);
	} catch {
		return undefined;
	}
}

function sameIpAddressBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
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
