/**
 * RFC 9598 SmtpUTF8Mailbox syntax: the RFC 6531 §3.3 Local-part and a domain of
 * NR-LDH labels and A-labels.
 *
 * @module
 */

import type { IdnaMode } from '#micro509/internal/shared/idna';
import { domainToAscii } from '#micro509/internal/shared/idna';

const MAX_DOMAIN_OCTETS = 253;

/** RFC 5321 §4.1.2 Dot-string with RFC 6531 §3.3 `atext =/ UTF8-non-ascii`, C1 controls excluded (RFC 6530 §10.1). */
const SMTP_UTF8_DOT_STRING =
	/^[\w!#$%&'*+\-/=?^`{|}~\u{a0}-\u{d7ff}\u{e000}-\u{10ffff}]+(?:\.[\w!#$%&'*+\-/=?^`{|}~\u{a0}-\u{d7ff}\u{e000}-\u{10ffff}]+)*$/u;

/** RFC 5321 §4.1.2 Quoted-string with RFC 6531 §3.3 `qtextSMTP =/ UTF8-non-ascii`, C1 controls excluded (RFC 6530 §10.1). */
const SMTP_UTF8_QUOTED_STRING = /^"(?:[^"\\\p{Cc}\p{Cs}]|\\[ -~])*"$/u;

/** An RFC 6531 §3.3 Local-part: a Dot-string or a Quoted-string. */
export function isSmtpUtf8LocalPart(localPart: string): boolean {
	return SMTP_UTF8_DOT_STRING.test(localPart) || SMTP_UTF8_QUOTED_STRING.test(localPart);
}

/**
 * RFC 9598 §3: a mailbox domain of lowercase NR-LDH labels and A-labels that
 * passes {@linkcode domainToAscii} in `mode`, the RFC 5893 Bidi rule included.
 */
export function isMailboxDomain(domain: string, mode: IdnaMode): boolean {
	return (
		domain.length > 0 &&
		domain.length <= MAX_DOMAIN_OCTETS &&
		domain
			.split('.')
			.every(
				(label) =>
					/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) &&
					(label.slice(2, 4) !== '--' || label.startsWith('xn--')),
			) &&
		domainToAscii(domain, mode).ok
	);
}
