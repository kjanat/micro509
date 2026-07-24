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
import { GENERAL_NAME_WIRE_TAGS } from '#micro509/internal/x509/general-name-tags';
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

/** Decode a single GeneralName from its implicit context tag. */
export function parseGeneralName(source: Uint8Array, element: DerElement): GeneralName {
	switch (element.tag) {
		case 0xa0: {
			const otherName = parseOtherName(source, element);
			if (otherName !== undefined) {
				return otherName;
			}
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
		}
		case 0x81:
			return { type: 'email' as const, value: decodeString(0x16, element.value) };
		case 0x82:
			return { type: 'dns' as const, value: decodeString(0x16, element.value) };
		case 0x86:
			return { type: 'uri' as const, value: decodeString(0x16, element.value) };
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(readDirectoryNameTlv(element)),
			};
		default:
			// x400Address [3], ediPartyName [5], and registeredID [8] are valid but
			// unsupported; any other tag/class/constructedness is not a GeneralName.
			if (!GENERAL_NAME_WIRE_TAGS.has(element.tag)) {
				throw new Error(`Invalid GeneralName tag: ${element.tag}`);
			}
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
	}
}

/**
 * Decode an otherName [0] as a known type (currently only SRV-ID).
 *
 * `otherName [0] OtherName` is in the IMPLICIT-TAGS module, so the [0] tag
 * replaces OtherName's SEQUENCE tag: the type-id and `value [0] EXPLICIT` are
 * the direct children, with no inner SEQUENCE. A malformed envelope, or a
 * malformed payload of a recognised OID, throws. A structurally valid OtherName
 * with an unsupported OID returns `undefined`, so the caller preserves it as
 * `{ type: 'unknown' }`.
 */
function parseOtherName(source: Uint8Array, element: DerElement): SubjectAltName | undefined {
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
	if (decodeObjectIdentifier(typeId.value) !== OIDS.idOnDnsSrv) {
		return undefined;
	}
	if (value.tag !== 0x16 || value.value.length === 0) {
		throw new Error('SRV-ID otherName must wrap a non-empty IA5String');
	}
	return { type: 'srv', value: decodeString(value.tag, value.value) };
}
