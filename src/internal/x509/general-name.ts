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
import type { DerElement } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { decodeIpAddress } from '#micro509/internal/shared/ip';
import { readDirectoryNameTlv } from '#micro509/internal/x509/directory-name';
import type { GeneralName, SubjectAltName } from '#micro509/x509/extensions';

/** Keeps a leading U+FEFF, which RFC 9598 §3 forbids and the builder must be able to see. */
const SMTP_UTF8_MAILBOX_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

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

/** A SRVName restriction's `_Service` label and Name, one of them possibly empty. */
export interface SrvNameRestriction {
	readonly service: string;
	readonly name: string;
}

/**
 * RFC 4985 §4: split `_Service.Name`, `_Service`, or `Name`, the leading
 * underscore marking the service (§2). The `_Service` label and each Name label
 * are DNS labels of at most 63 octets, and the Name is at most 253 octets.
 */
export function splitSrvNameRestriction(value: string): SrvNameRestriction | undefined {
	const dot = value.indexOf('.');
	const service = value.startsWith('_') ? value.slice(0, dot < 0 ? value.length : dot) : '';
	const name = service.length === 0 ? value : value.slice(service.length + 1);
	if (service.length > 0 && !/^_[A-Za-z0-9-]{1,62}$/.test(service)) return undefined;
	if (service.length > 0 && dot < 0) return { service, name: '' };
	return name.length <= 253 && name.split('.').every((label) => /^[A-Za-z0-9_-]{1,63}$/.test(label))
		? { service, name }
		: undefined;
}

/** The DER of an otherName value element. */
export function otherNameValueDer(source: Uint8Array, value: DerElement): Uint8Array {
	return source.slice(value.start - value.headerLength, value.end);
}

/**
 * Decode an otherName [0], typing SRV-ID (RFC 4985) and SmtpUTF8Mailbox
 * (RFC 9598) and keeping any other type-id with its value element. A malformed
 * payload of a recognised type-id throws.
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
			return { type: 'smtpUtf8Mailbox', value: SMTP_UTF8_MAILBOX_DECODER.decode(value.value) };
		default:
			return { type: 'otherName', typeId, value: otherNameValueDer(source, value) };
	}
}
