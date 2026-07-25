/**
 * Human-readable text for parsed names.
 *
 * Renders a {@linkcode ParsedName} or {@linkcode SubjectAltName} as a display string,
 * covering every variant of the union without the caller narrowing it by hand.
 *
 * @module micro509/x509/name-text
 */

import { hexToBytes, toHex } from '#micro509/internal/asn1/asn1';
import { DN_ATTRIBUTE_KEYWORDS } from '#micro509/internal/x509/name-fields';
import type { SubjectAltName } from '#micro509/x509/extensions';
import type {
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse';
import { parseDistinguishedNameDer } from '#micro509/x509/parse';

/** Options for {@linkcode subjectAltNameToString}. */
export interface SubjectAltNameTextOptions {
	/** Prepend `{@linkcode subjectAltNameLabel}:` to the value, as `openssl x509 -text` does. Defaults to `false`. */
	readonly prefix?: boolean;
}

/**
 * Renders one {@linkcode SubjectAltName} as text.
 *
 * | variant | rendering |
 * | --- | --- |
 * | `dns`, `ip`, `email`, `uri`, `srv` | the value itself |
 * | `directoryName` | {@linkcode distinguishedNameToString} of the embedded name, or the DER hex if it does not decode |
 * | `unknown` | lowercase hex of the raw content bytes |
 *
 * @example Render every SAN of a parsed certificate
 * ```ts
 * const names = (parsed.subjectAltNames ?? []).map((name) => subjectAltNameToString(name));
 * // ['example.com', '192.0.2.1', 'CN=Example CA,C=US']
 *
 * subjectAltNameToString({ type: 'dns', value: 'example.com' }, { prefix: true }); // 'DNS:example.com'
 * ```
 */
export function subjectAltNameToString(
	name: SubjectAltName,
	options?: SubjectAltNameTextOptions,
): string {
	const text = subjectAltNameText(name);
	return options?.prefix === true ? `${subjectAltNameLabel(name)}:${text}` : text;
}

/**
 * The `openssl x509 -text` label for a {@linkcode SubjectAltName} variant —
 * `DNS`, `IP Address`, `email`, `URI`, `SRV`, `DirName`, or `[tag <n>]` for an unrecognized tag.
 */
export function subjectAltNameLabel(name: SubjectAltName): string {
	switch (name.type) {
		case 'dns':
			return 'DNS';
		case 'ip':
			return 'IP Address';
		case 'email':
			return 'email';
		case 'uri':
			return 'URI';
		case 'srv':
			return 'SRV';
		case 'directoryName':
			return 'DirName';
		case 'unknown':
			return `[tag ${String(name.tag)}]`;
		default: {
			const _exhaustive: never = name;
			throw new Error(`Unhandled SubjectAltName type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * Renders a {@linkcode ParsedName} as an RFC 4514 distinguished name string, e.g. `CN=Example CA,O=Acme,C=US`.
 *
 * RDNs are emitted in reverse encoding order and multi-valued RDNs are joined with `+`,
 * both per RFC 4514 [§2](https://datatracker.ietf.org/doc/html/rfc4514#section-2).
 * Attribute types outside the RFC 4514 [§3](https://datatracker.ietf.org/doc/html/rfc4514#section-3)
 * keyword table use the short names `openssl` prints, falling back to the dotted OID.
 *
 * @example
 * ```ts
 * distinguishedNameToString(parsed.subject); // 'CN=example.com,O=Acme\\, Inc.,C=US'
 * ```
 */
export function distinguishedNameToString(name: ParsedName): string {
	return [...name.rdns]
		.reverse()
		.map((rdn) => relativeDistinguishedNameToString(rdn))
		.join(',');
}

/** Renders one {@linkcode ParsedRelativeDistinguishedName}, joining a multi-valued RDN's attributes with `+`. */
export function relativeDistinguishedNameToString(rdn: ParsedRelativeDistinguishedName): string {
	return rdn.attributes.map((attribute) => attributeToString(attribute)).join('+');
}

/** Characters RFC 4514 [§2.4](https://datatracker.ietf.org/doc/html/rfc4514#section-2.4) escapes wherever they appear. */
const ESCAPED_CHARACTERS = new Set(['"', '+', ',', ';', '<', '>', '\\']);

function attributeToString(attribute: ParsedNameAttribute): string {
	const keyword = DN_ATTRIBUTE_KEYWORDS[attribute.oid] ?? attribute.oid;
	return `${keyword}=${escapeAttributeValue(attribute.value)}`;
}

function escapeAttributeValue(value: string): string {
	const characters = [...value];
	return characters
		.map((character, index) => {
			if (ESCAPED_CHARACTERS.has(character)) {
				return `\\${character}`;
			}
			const code = character.codePointAt(0) ?? 0;
			if (code < 0x20 || code === 0x7f) {
				return `\\${code.toString(16).padStart(2, '0')}`;
			}
			if (character === ' ' && (index === 0 || index === characters.length - 1)) {
				return '\\ ';
			}
			return character === '#' && index === 0 ? '\\#' : character;
		})
		.join('');
}

function subjectAltNameText(name: SubjectAltName): string {
	switch (name.type) {
		case 'dns':
		case 'ip':
		case 'email':
		case 'uri':
		case 'srv':
			return name.value;
		case 'directoryName':
			return directoryNameText(name.derHex);
		case 'unknown':
			return toHex(name.value);
		default: {
			const _exhaustive: never = name;
			throw new Error(`Unhandled SubjectAltName type: ${String(_exhaustive)}`);
		}
	}
}

function directoryNameText(derHex: string): string {
	try {
		return distinguishedNameToString(parseDistinguishedNameDer(hexToBytes(derHex)));
	} catch {
		return derHex;
	}
}
