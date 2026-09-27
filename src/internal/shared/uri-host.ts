/**
 * RFC 3986 §3.2.2 host of a URI, read once for name constraints and service
 * identity alike.
 *
 * @module
 */

import { presentedDomainToAscii, referenceDomainToAscii } from '#micro509/internal/shared/idna';
import { parseIpAddressToBytes } from '#micro509/internal/shared/ip';

/**
 * A URI host: a domain name in A-labels, an IP address, a reg-name that is not
 * a domain name, no host at all, or text outside the RFC 3986 grammar.
 */
export type UriHost =
	| { readonly type: 'dns'; readonly name: string }
	| { readonly type: 'ip'; readonly bytes: Uint8Array }
	| { readonly type: 'regName'; readonly value: string }
	| { readonly type: 'absent' }
	| { readonly type: 'invalid' };

/** A URI taken from a certificate, or a reference URI that may be an RFC 3987 IRI. */
export type UriHostSource = 'presented' | 'reference';

const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const REG_NAME = /^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$/;
const IREG_NAME = /^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2}|[^\0-\x7f])*$/u;
const IPV4_ADDRESS =
	/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const PORT = /^(?::\d*)?$/;
const DOMAIN_CHARACTERS = /^(?:[A-Za-z0-9._-]|[^\0-\x7f])+$/u;

/** RFC 3986 §3.2.2 IPv4address, dotted decimal without leading zeros. */
export function isIpv4Address(host: string): boolean {
	return IPV4_ADDRESS.test(host);
}

const ABSENT: UriHost = { type: 'absent' };
const INVALID: UriHost = { type: 'invalid' };

/** RFC 3986 §3.2: the host of the authority that `//` opens, or `absent` without one. */
export function uriAuthorityHost(uri: string, source: UriHostSource): UriHost {
	const scheme = SCHEME.exec(uri);
	if (scheme === null) return INVALID;
	const rest = uri.slice(scheme[0].length);
	if (!rest.startsWith('//')) return ABSENT;
	const authority = rest.slice(2).split(/[/?#]/, 1)[0] ?? '';
	return hostportHost(authority.slice(authority.indexOf('@') + 1), source);
}

/** RFC 3986 §3.2.2 and §3.2.3: the host of `host [ ":" port ]`. */
export function hostportHost(hostport: string, source: UriHostSource): UriHost {
	if (hostport.startsWith('[')) {
		const close = hostport.indexOf(']');
		return close < 0 || !PORT.test(hostport.slice(close + 1))
			? INVALID
			: ipLiteralHost(hostport.slice(1, close));
	}
	const colon = hostport.indexOf(':');
	const host = colon < 0 ? hostport : hostport.slice(0, colon);
	if (!PORT.test(hostport.slice(host.length))) return INVALID;
	return host.length === 0 ? ABSENT : regNameHost(host, source);
}

/** RFC 3986 §3.2.2 IP-literal, of which only IPv6address is read. */
function ipLiteralHost(literal: string): UriHost {
	if (!literal.includes(':') || /^v/i.test(literal)) return INVALID;
	try {
		return { type: 'ip', bytes: parseIpAddressToBytes(literal) };
	} catch {
		return INVALID;
	}
}

/**
 * RFC 3986 §3.2.2 IPv4address or reg-name, with the single "." that may follow
 * the rightmost label dropped.
 */
function regNameHost(host: string, source: UriHostSource): UriHost {
	if (!(source === 'reference' ? IREG_NAME : REG_NAME).test(host)) return INVALID;
	const decoded = source === 'reference' ? decodeUtf8(host) : decodeUnreserved(host);
	if (decoded === undefined) return INVALID;
	if (isIpv4Address(decoded)) return { type: 'ip', bytes: parseIpAddressToBytes(decoded) };
	const value = decoded.endsWith('.') ? decoded.slice(0, -1) : decoded;
	const name = !DOMAIN_CHARACTERS.test(value)
		? undefined
		: source === 'reference'
			? referenceDomainToAscii(value)
			: presentedDomainToAscii(value);
	return name === undefined || name.endsWith('.')
		? { type: 'regName', value }
		: { type: 'dns', name };
}

/** RFC 3986 §6.2.2.2: only a percent-encoded unreserved character decodes. */
function decodeUnreserved(host: string): string {
	return host.replace(/%([0-9A-Fa-f]{2})/g, (encoded, hex: string) => {
		const character = String.fromCharCode(Number.parseInt(hex, 16));
		return /^[A-Za-z0-9._~-]$/.test(character) ? character : encoded;
	});
}

/** RFC 3986 §3.2.2: a reference host's percent-encoded octets decode as UTF-8. */
function decodeUtf8(host: string): string | undefined {
	try {
		return decodeURIComponent(host);
	} catch {
		return undefined;
	}
}
