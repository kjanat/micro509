import { ia5String, printableString, utf8String } from './der.ts';
import type { NameFieldKey } from './name.ts';
import { OIDS } from './oids.ts';

export interface NameFieldDefinition {
	readonly oid: string;
	readonly encode: (value: string) => Uint8Array;
}

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

const NAME_FIELD_KEYS_BY_OID = new Map<string, NameFieldKey>();
for (const key of NAME_OBJECT_ORDER) {
	NAME_FIELD_KEYS_BY_OID.set(NAME_FIELD_DEFINITIONS[key].oid, key);
}

export function nameFieldKeyFromOid(oid: string): NameFieldKey | undefined {
	return NAME_FIELD_KEYS_BY_OID.get(oid);
}
