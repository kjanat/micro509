import { objectIdentifier, sequence, setOf } from './der.ts';
import { NAME_FIELD_DEFINITIONS, NAME_OBJECT_ORDER } from './name-fields.ts';

export type NameFieldKey =
	| 'commonName'
	| 'surname'
	| 'serialNumber'
	| 'country'
	| 'locality'
	| 'state'
	| 'street'
	| 'organization'
	| 'organizationalUnit'
	| 'title'
	| 'givenName'
	| 'emailAddress';

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
export type RelativeDistinguishedNameInput = readonly NameAttribute[];

export { nameFieldKeyFromOid } from './name-fields.ts';

export function encodeName(input: NameInput): Uint8Array {
	const attributes = isNameAttributes(input) ? input : nameObjectToAttributes(input);
	if (attributes.length === 0) {
		throw new Error('Name must contain at least one attribute');
	}

	return sequence(attributes.map(encodeNameAttributeAsSet));
}

export function encodeRelativeDistinguishedName(
	attributes: RelativeDistinguishedNameInput,
): Uint8Array {
	if (attributes.length === 0) {
		throw new Error('Relative distinguished name must contain at least one attribute');
	}
	return setOf(attributes.map(encodeNameAttribute));
}

function isNameAttributes(input: NameInput): input is readonly NameAttribute[] {
	return Array.isArray(input);
}

function encodeNameAttributeAsSet(attribute: NameAttribute): Uint8Array {
	return setOf([encodeNameAttribute(attribute)]);
}

function encodeNameAttribute(attribute: NameAttribute): Uint8Array {
	const definition = NAME_FIELD_DEFINITIONS[attribute.type];
	if (definition === undefined) {
		throw new Error(`Unsupported name field: ${attribute.type}`);
	}
	if (attribute.type === 'country' && attribute.value.length !== 2) {
		throw new Error('Country must be a 2-character code');
	}
	return sequence([objectIdentifier(definition.oid), definition.encode(attribute.value)]);
}

function nameObjectToAttributes(input: NameObject): readonly NameAttribute[] {
	const attributes: NameAttribute[] = [];
	for (const key of NAME_OBJECT_ORDER) {
		const value = input[key];
		if (typeof value === 'string' && value.length > 0) {
			attributes.push({ type: key, value });
		}
	}
	return attributes;
}
