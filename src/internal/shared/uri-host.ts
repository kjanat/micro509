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
const UNRESERVED = 'A-Za-z0-9._~\\-';
const SUB_DELIMS = "!$&'()*+,;=";
/** RFC 3987 §2.2 ucschar, without the bidirectional formatting characters §4.1 forbids. */
const UCSCHAR =
	'\\u{a0}-\\u{200d}\\u{2010}-\\u{2029}\\u{202f}-\\u{d7ff}\\u{f900}-\\u{fdcf}\\u{fdf0}-\\u{ffef}\\u{10000}-\\u{1fffd}\\u{20000}-\\u{2fffd}\\u{30000}-\\u{3fffd}\\u{40000}-\\u{4fffd}\\u{50000}-\\u{5fffd}\\u{60000}-\\u{6fffd}\\u{70000}-\\u{7fffd}\\u{80000}-\\u{8fffd}\\u{90000}-\\u{9fffd}\\u{a0000}-\\u{afffd}\\u{b0000}-\\u{bfffd}\\u{c0000}-\\u{cfffd}\\u{d0000}-\\u{dfffd}\\u{e1000}-\\u{efffd}';
/** RFC 3987 §2.2 iprivate. */
const IPRIVATE = '\\u{e000}-\\u{f8ff}\\u{f0000}-\\u{ffffd}\\u{100000}-\\u{10fffd}';

/** The userinfo, reg-name, and text after the authority of an RFC 3986 URI or RFC 3987 IRI. */
interface UriGrammar {
	readonly userinfo: RegExp;
	readonly regName: RegExp;
	readonly afterAuthority: RegExp;
}

function uriGrammar(extra: string, queryExtra: string): UriGrammar {
	const run = (characters: string): string => `(?:[${characters}]|%[0-9A-Fa-f]{2})*`;
	const pchar = `${UNRESERVED}${SUB_DELIMS}:@${extra}`;
	return {
		userinfo: new RegExp(`^${run(`${UNRESERVED}${SUB_DELIMS}:${extra}`)}$`, 'u'),
		regName: new RegExp(`^${run(`${UNRESERVED}${SUB_DELIMS}${extra}`)}$`, 'u'),
		afterAuthority: new RegExp(
			`^(?:/${run(pchar)})*(?:\\?${run(`${pchar}/?${queryExtra}`)})?(?:#${run(`${pchar}/?`)})?$`,
			'u',
		),
	};
}

const URI_GRAMMAR = uriGrammar('', '');
const IRI_GRAMMAR = uriGrammar(UCSCHAR, IPRIVATE);

function grammarOf(source: UriHostSource): UriGrammar {
	return source === 'reference' ? IRI_GRAMMAR : URI_GRAMMAR;
}

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

/**
 * RFC 3986 §3.2: the host of the authority that `//` opens, or `absent`
 * without an authority. The userinfo, and the path, query and fragment after
 * the authority, must follow RFC 3986 §3.2.1 and §3.3 to §3.5, or RFC 3987 §2.2
 * for a reference identifier.
 */
export function uriAuthorityHost(uri: string, source: UriHostSource): UriHost {
	const scheme = SCHEME.exec(uri);
	if (scheme === null) return INVALID;
	const rest = uri.slice(scheme[0].length);
	if (!rest.startsWith('//')) return ABSENT;
	const grammar = grammarOf(source);
	const authority = rest.slice(2).split(/[/?#]/, 1)[0] ?? '';
	const at = authority.indexOf('@');
	return grammar.afterAuthority.test(rest.slice(2 + authority.length)) &&
		(at < 0 || grammar.userinfo.test(authority.slice(0, at)))
		? hostportHost(authority.slice(at + 1), source)
		: INVALID;
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
	if (!grammarOf(source).regName.test(host)) return INVALID;
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
