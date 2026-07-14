/**
 * Distinguished-name field metadata.
 *
 * Maps friendly {@linkcode NameFieldKey} names to their ASN.1 OIDs and string-encoding functions.
 * @module
 */

import { ia5String, printableString, utf8String } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import type { NameFieldKey } from '#micro509/x509/name';

/**
 * OID and ASN.1 string encoder for one distinguished-name attribute type.
 */
export interface NameFieldDefinition {
	/** Dotted-decimal OID (e.g. `"2.5.4.3"` for commonName). */
	readonly oid: string;
	/** Encodes the attribute value to the correct ASN.1 string type (UTF8, PrintableString, IA5). */
	readonly encode: (value: string) => Uint8Array;
}

/**
 * Registry mapping every {@linkcode NameFieldKey} to its OID and ASN.1 encoder.
 *
 * Country and serialNumber use PrintableString; emailAddress uses IA5String;
 * all others use UTF8String.
 */
export const NAME_FIELD_DEFINITIONS: Record<NameFieldKey, NameFieldDefinition> = {
	commonName: { oid: OIDS.commonName, encode: utf8String },
	surname: { oid: OIDS.surname, encode: utf8String },
	serialNumber: { oid: OIDS.serialNumber, encode: printableString },
	country: { oid: OIDS.countryName, encode: printableString },
	locality: { oid: OIDS.localityName, encode: utf8String },
	state: { oid: OIDS.stateOrProvinceName, encode: utf8String },
	street: { oid: OIDS.streetAddress, encode: utf8String },
	organization: { oid: OIDS.organizationName, encode: utf8String },
	organizationalUnit: { oid: OIDS.organizationalUnitName, encode: utf8String },
	title: { oid: OIDS.title, encode: utf8String },
	givenName: { oid: OIDS.givenName, encode: utf8String },
	emailAddress: { oid: OIDS.emailAddress, encode: ia5String },
};

/**
 * Canonical emission order when converting a {@linkcode NameObject} to RDN attributes.
 *
 * Follows the conventional `C/ST/L/STREET/O/OU/CN/…` ordering.
 */
export const NAME_OBJECT_ORDER: readonly NameFieldKey[] = [
	'country',
	'state',
	'locality',
	'street',
	'organization',
	'organizationalUnit',
	'commonName',
	'givenName',
	'surname',
	'title',
	'serialNumber',
	'emailAddress',
];

/**
 * Display keyword for a DN attribute type, keyed by OID.
 *
 * RFC 4514 [§3](https://datatracker.ietf.org/doc/html/rfc4514#section-3) defines
 * `CN`, `L`, `ST`, `O`, `OU`, `C`, `STREET`, `DC`, and `UID`; the rest are the short
 * names `openssl` prints for attribute types the RFC leaves to the dotted OID.
 */
export const DN_ATTRIBUTE_KEYWORDS: Readonly<Record<string, string>> = {
	[OIDS.commonName]: 'CN',
	[OIDS.surname]: 'SN',
	[OIDS.serialNumber]: 'serialNumber',
	[OIDS.countryName]: 'C',
	[OIDS.localityName]: 'L',
	[OIDS.stateOrProvinceName]: 'ST',
	[OIDS.streetAddress]: 'STREET',
	[OIDS.organizationName]: 'O',
	[OIDS.organizationalUnitName]: 'OU',
	[OIDS.title]: 'title',
	[OIDS.givenName]: 'GN',
	[OIDS.emailAddress]: 'emailAddress',
	[OIDS.userId]: 'UID',
	[OIDS.domainComponent]: 'DC',
};

/** Reverse lookup table: OID string → friendly {@linkcode NameFieldKey}. */
const NAME_FIELD_KEYS_BY_OID = new Map<string, NameFieldKey>();
for (const key of NAME_OBJECT_ORDER) {
	NAME_FIELD_KEYS_BY_OID.set(NAME_FIELD_DEFINITIONS[key].oid, key);
}

/** Resolves a dotted-decimal OID to its {@linkcode NameFieldKey}, or `undefined` if unknown. */
export function nameFieldKeyFromOid(oid: string): NameFieldKey | undefined {
	return NAME_FIELD_KEYS_BY_OID.get(oid);
}
