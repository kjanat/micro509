import { ia5String, objectIdentifier, printableString, sequence, setOf, utf8String } from "./der.ts";
import { OIDS } from "./oids.ts";

export type NameFieldKey =
	| "commonName"
	| "surname"
	| "serialNumber"
	| "country"
	| "locality"
	| "state"
	| "street"
	| "organization"
	| "organizationalUnit"
	| "title"
	| "givenName"
	| "emailAddress";

export interface NameObject {
	readonly commonName?: string;
	readonly surname?: string;
	readonly serialNumber?: string;
	readonly country?: string;
	readonly locality?: string;
	readonly state?: string;
	readonly street?: string;
	readonly organization?: string;
	readonly organizationalUnit?: string;
	readonly title?: string;
	readonly givenName?: string;
	readonly emailAddress?: string;
}

export interface NameAttribute {
	readonly type: NameFieldKey;
	readonly value: string;
}

export type NameInput = NameObject | readonly NameAttribute[];

interface NameFieldDefinition {
	readonly oid: string;
	readonly encode: (value: string) => Uint8Array;
}

const NAME_FIELD_DEFINITIONS: Record<NameFieldKey, NameFieldDefinition> = {
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

const NAME_OBJECT_ORDER: readonly NameFieldKey[] = [
	"country",
	"state",
	"locality",
	"street",
	"organization",
	"organizationalUnit",
	"commonName",
	"givenName",
	"surname",
	"title",
	"serialNumber",
	"emailAddress",
];

export function encodeName(input: NameInput): Uint8Array {
	const attributes = isNameAttributes(input) ? input : nameObjectToAttributes(input);
	if (attributes.length === 0) {
		throw new Error("Name must contain at least one attribute");
	}

	return sequence(
		attributes.map((attribute) => {
			const definition = NAME_FIELD_DEFINITIONS[attribute.type];
			if (definition === undefined) {
				throw new Error(`Unsupported name field: ${attribute.type}`);
			}
			if (attribute.type === "country" && attribute.value.length !== 2) {
				throw new Error("Country must be a 2-character code");
			}

			return setOf([
				sequence([objectIdentifier(definition.oid), definition.encode(attribute.value)]),
			]);
		}),
	);
}

function isNameAttributes(input: NameInput): input is readonly NameAttribute[] {
	return Array.isArray(input);
}

function nameObjectToAttributes(input: NameObject): readonly NameAttribute[] {
	const attributes: NameAttribute[] = [];
	for (const key of NAME_OBJECT_ORDER) {
		const value = input[key];
		if (typeof value === "string" && value.length > 0) {
			attributes.push({ type: key, value });
		}
	}
	return attributes;
}
