/**
 * The canonical RFC 5280 §4.2.1.6 GeneralName decoder, shared by certificate
 * and CRL parsing so both layers agree on the representation of every
 * alternative.
 *
 * @module
 */

import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	toHex,
} from '#micro509/internal/asn1/asn1';
import { DECODE_REFUSAL_CODES, rethrowDecodeRefusal } from '#micro509/internal/asn1/decode-refusal';
import type { DerElement } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { decodeIpAddress } from '#micro509/internal/shared/ip';
import { readDirectoryNameTlv } from '#micro509/internal/x509/directory-name';
import type { GeneralName, SubjectAltName } from '#micro509/x509/extensions';

/** Decode a SEQUENCE OF GeneralName. */
export function parseGeneralNames(source: Uint8Array, element: DerElement): readonly GeneralName[] {
	const names = childrenOf(source, element);
	if (names.length === 0) {
		throw new Error('GeneralNames must not be empty');
	}
	for (const name of names) {
		if ((name.tag & 0xc0) !== 0x80) {
			throw new Error('GeneralNames must contain GeneralName entries');
		}
	}
	return names.map((name) => parseGeneralName(source, name));
}

/**
 * Decode an IA5String GeneralName alternative, rejecting a zero-length value.
 *
 * RFC 5280 §4.2.1.6 forbids empty GeneralName fields, and a certificate carrying
 * one presents no usable identity.
 */
function requireNonEmptyIa5(element: DerElement, alternative: string): string {
	if (element.value.length === 0) {
		throw new Error(`GeneralName ${alternative} must not be empty`);
	}
	return decodeString(0x16, element.value);
}

/** Decode a single GeneralName from its implicit context tag. */
export function parseGeneralName(source: Uint8Array, element: DerElement): GeneralName {
	switch (element.tag) {
		case 0xa0:
			return parseOtherName(source, element);
		case 0x81:
			return { type: 'email' as const, value: requireNonEmptyIa5(element, 'rfc822Name') };
		case 0x82:
			return { type: 'dns' as const, value: requireNonEmptyIa5(element, 'dNSName') };
		case 0x86:
			return {
				type: 'uri' as const,
				value: requireNonEmptyIa5(element, 'uniformResourceIdentifier'),
			};
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa3:
			return { type: 'x400Address' as const, value: source.slice(element.start, element.end) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(readDirectoryNameTlv(element)),
			};
		case 0xa5:
			return { type: 'ediPartyName' as const, value: source.slice(element.start, element.end) };
		case 0x88:
			return { type: 'registeredID' as const, value: decodeObjectIdentifier(element.value) };
		default:
			throw new Error(`Invalid GeneralName tag: ${element.tag}`);
	}
}

/** The type-id and single value element of an otherName [0]. */
export interface OtherNameParts {
	readonly typeId: string;
	readonly value: DerElement;
}

/**
 * Read the envelope of an otherName [0], throwing when it is malformed.
 *
 * `otherName [0] OtherName` is in the IMPLICIT-TAGS module, so the [0] tag
 * replaces OtherName's SEQUENCE tag: the type-id and `value [0] EXPLICIT` are
 * the direct children, with no inner SEQUENCE.
 */
export function readOtherName(source: Uint8Array, element: DerElement): OtherNameParts {
	const children = childrenOf(source, element);
	const typeId = children[0];
	const valueElement = children[1];
	if (
		children.length !== 2 ||
		typeId === undefined ||
		valueElement === undefined ||
		typeId.tag !== 0x06 ||
		valueElement.tag !== 0xa0
	) {
		throw new Error('Malformed otherName');
	}
	const valueChildren = childrenOf(source, valueElement);
	const value = valueChildren[0];
	if (valueChildren.length !== 1 || value === undefined) {
		throw new Error('otherName value [0] must wrap exactly one element');
	}
	return { typeId: decodeObjectIdentifier(typeId.value), value };
}

/** RFC 4985 §2: `SRVName ::= IA5String (SIZE (1..MAX))`. */
export function decodeSrvName(value: DerElement): string {
	if (value.tag !== 0x16 || value.value.length === 0) {
		throw new Error('SRV-ID otherName must wrap a non-empty IA5String');
	}
	return decodeString(value.tag, value.value);
}

/** The DER of an otherName value element. */
export function otherNameValueDer(source: Uint8Array, value: DerElement): Uint8Array {
	return source.slice(value.start - value.headerLength, value.end);
}

/** [MS-WCCE] §2.2.2.7.5: a user principal name is a UTF8String. */
function decodeUpn(value: DerElement): SubjectAltName | undefined {
	if (value.tag !== 0x0c || value.value.length === 0) {
		return undefined;
	}
	try {
		return { type: 'upn', value: decodeString(value.tag, value.value) };
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_REFUSAL_CODES);
		return undefined;
	}
}

/**
 * RFC 4120 §5.2.1: a KerberosString is a GeneralString holding IA5String
 * characters only. The code-extension controls of X.690 §8.23.9 are left out,
 * since a GeneralString reads them as escape sequences.
 */
function decodeKerberosString(element: DerElement | undefined): string | undefined {
	if (
		element?.tag !== 0x1b ||
		element.value.some(
			(octet) => octet > 0x7f || octet === 0x0e || octet === 0x0f || octet === 0x1b,
		)
	) {
		return undefined;
	}
	return String.fromCharCode(...element.value);
}

/** RFC 4120 §5.2.4: `Int32 ::= INTEGER (-2147483648..2147483647)`, DER-minimal. */
function decodeInt32(element: DerElement | undefined): number | undefined {
	const contents = element?.tag === 0x02 ? element.value : undefined;
	const [first, second] = contents ?? [];
	if (
		contents === undefined ||
		first === undefined ||
		contents.length > 4 ||
		(second !== undefined &&
			((first === 0x00 && second < 0x80) || (first === 0xff && second >= 0x80)))
	) {
		return undefined;
	}
	return contents
		.slice(1)
		.reduce((value, octet) => value * 256 + octet, first >= 0x80 ? first - 256 : first);
}

/** The single element under an EXPLICIT context tag. */
function explicitChild(
	source: Uint8Array,
	element: DerElement | undefined,
	tag: number,
): DerElement | undefined {
	if (element?.tag !== tag) {
		return undefined;
	}
	const children = childrenOf(source, element);
	return children.length === 1 ? children[0] : undefined;
}

/**
 * RFC 4556 §3.2.2 KRB5PrincipalName with RFC 4120's PrincipalName, Realm and
 * KerberosString, all EXPLICIT-tagged. A realm holds no NUL (RFC 4120 §5.2.2).
 */
function decodeKrb5PrincipalName(
	source: Uint8Array,
	value: DerElement,
): SubjectAltName | undefined {
	const fields = value.tag === 0x30 ? childrenOf(source, value) : [];
	const realm = decodeKerberosString(explicitChild(source, fields[0], 0xa0));
	const principal = explicitChild(source, fields[1], 0xa1);
	const principalFields = principal?.tag === 0x30 ? childrenOf(source, principal) : [];
	const nameType = decodeInt32(explicitChild(source, principalFields[0], 0xa0));
	const names = explicitChild(source, principalFields[1], 0xa1);
	const nameString =
		names?.tag === 0x30 ? childrenOf(source, names).map(decodeKerberosString) : [undefined];
	if (
		fields.length !== 2 ||
		principalFields.length !== 2 ||
		realm === undefined ||
		realm.includes('\0') ||
		nameType === undefined
	) {
		return undefined;
	}
	const components = nameString.filter((component) => component !== undefined);
	return components.length === nameString.length
		? { type: 'krb5PrincipalName', realm, nameType, nameString: components }
		: undefined;
}

/**
 * The typed {@linkcode SubjectAltName} variant of a UPN or KRB5PrincipalName
 * otherName, or `undefined` when the value does not fit that variant's type
 * and stays a plain `otherName`.
 */
export function typedOtherName(
	typeId: string,
	source: Uint8Array,
	value: DerElement,
): SubjectAltName | undefined {
	switch (typeId) {
		case OIDS.ntPrincipalName:
			return decodeUpn(value);
		case OIDS.idPkinitSan:
			return decodeKrb5PrincipalName(source, value);
		default:
			return undefined;
	}
}

/**
 * Decode an otherName [0], typing SRV-ID (RFC 4985), SmtpUTF8Mailbox
 * (RFC 9598), UPN ([MS-WCCE]) and KRB5PrincipalName (RFC 4556) and keeping any
 * other type-id with its value element. A malformed SRV-ID or SmtpUTF8Mailbox
 * payload throws.
 */
function parseOtherName(source: Uint8Array, element: DerElement): SubjectAltName {
	const { typeId, value } = readOtherName(source, element);
	switch (typeId) {
		case OIDS.idOnDnsSrv:
			return { type: 'srv', value: decodeSrvName(value) };
		case OIDS.idOnSmtpUtf8Mailbox:
			if (value.tag !== 0x0c || value.value.length === 0) {
				throw new Error('SmtpUTF8Mailbox otherName must wrap a non-empty UTF8String');
			}
			return { type: 'smtpUtf8Mailbox', value: decodeString(value.tag, value.value) };
		default:
			return (
				typedOtherName(typeId, source, value) ?? {
					type: 'otherName',
					typeId,
					value: otherNameValueDer(source, value),
				}
			);
	}
}
