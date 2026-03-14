/**
 * Distinguished-name field metadata.
 *
 * This module defines the supported attribute mapping between friendly field keys and
 * ASN.1 object identifiers.
 */

import { ia5String, printableString, utf8String } from './der.ts';
import type { NameFieldKey } from './name.ts';
import { OIDS } from './oids.ts';

/**
 * Describes the registry definition used for name field handling.
 */
export interface NameFieldDefinition {
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the encode value.
	 */
	readonly encode: (value: string) => Uint8Array;
}

/**
 * Defines the name field definitions used by this module.
 */
export const NAME_FIELD_DEFINITIONS: Record<NameFieldKey, NameFieldDefinition> = {
	/**
	 * Carries the common name value.
	 */
	commonName: { oid: OIDS.commonName, encode: utf8String },
	/**
	 * Carries the surname value.
	 */
	surname: { oid: OIDS.surname, encode: utf8String },
	/**
	 * Carries the serial number value.
	 */
	serialNumber: { oid: OIDS.serialNumber, encode: printableString },
	/**
	 * Carries the country value.
	 */
	country: { oid: OIDS.countryName, encode: printableString },
	/**
	 * Carries the locality value.
	 */
	locality: { oid: OIDS.localityName, encode: utf8String },
	/**
	 * Carries the state value.
	 */
	state: { oid: OIDS.stateOrProvinceName, encode: utf8String },
	/**
	 * Carries the street value.
	 */
	street: { oid: OIDS.streetAddress, encode: utf8String },
	/**
	 * Carries the organization value.
	 */
	organization: { oid: OIDS.organizationName, encode: utf8String },
	/**
	 * Carries the organizational unit value.
	 */
	organizationalUnit: { oid: OIDS.organizationalUnitName, encode: utf8String },
	/**
	 * Carries the title value.
	 */
	title: { oid: OIDS.title, encode: utf8String },
	/**
	 * Carries the given name value.
	 */
	givenName: { oid: OIDS.givenName, encode: utf8String },
	/**
	 * Carries the email address value.
	 */
	emailAddress: { oid: OIDS.emailAddress, encode: ia5String },
};

/**
 * Defines the name object order used by this module.
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
 * Defines the name field keys by oid used by this module.
 */
const NAME_FIELD_KEYS_BY_OID = new Map<string, NameFieldKey>();
for (const key of NAME_OBJECT_ORDER) {
	NAME_FIELD_KEYS_BY_OID.set(NAME_FIELD_DEFINITIONS[key].oid, key);
}

/**
 * Name field key from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
export function nameFieldKeyFromOid(oid: string): NameFieldKey | undefined {
	return NAME_FIELD_KEYS_BY_OID.get(oid);
}
