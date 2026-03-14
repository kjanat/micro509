/**
 * Distinguished-name input and encoding helpers.
 *
 * This module turns typed name inputs into DER-encoded X.509 Name structures.
 */

import { objectIdentifier, sequence, setOf } from './der.ts';
import { NAME_FIELD_DEFINITIONS, NAME_OBJECT_ORDER } from './name-fields.ts';

/**
 * Defines name field key.
 */
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

/**
 * Describes name object.
 */
export interface NameObject {
	/**
	 * Carries the common name value.
	 */
	readonly commonName?: string;
	/**
	 * Carries the surname value.
	 */
	readonly surname?: string;
	/**
	 * Carries the serial number value.
	 */
	readonly serialNumber?: string;
	/**
	 * Carries the country value.
	 */
	readonly country?: string;
	/**
	 * Carries the locality value.
	 */
	readonly locality?: string;
	/**
	 * Carries the state value.
	 */
	readonly state?: string;
	/**
	 * Carries the street value.
	 */
	readonly street?: string;
	/**
	 * Carries the organization value.
	 */
	readonly organization?: string;
	/**
	 * Carries the organizational unit value.
	 */
	readonly organizationalUnit?: string;
	/**
	 * Carries the title value.
	 */
	readonly title?: string;
	/**
	 * Carries the given name value.
	 */
	readonly givenName?: string;
	/**
	 * Carries the email address value.
	 */
	readonly emailAddress?: string;
}

/**
 * Describes name attribute.
 */
export interface NameAttribute {
	/**
	 * Identifies the type value.
	 */
	readonly type: NameFieldKey;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Describes the input shape for name operations.
 */
export type NameInput = NameObject | readonly NameAttribute[];
/**
 * Describes the input shape for relative distinguished name operations.
 */
export type RelativeDistinguishedNameInput = readonly NameAttribute[];

export { nameFieldKeyFromOid } from './name-fields.ts';

/**
 * Encodes name.
 *
 * @param input The typed input payload.
 * @returns The encoded name.
 */
export function encodeName(input: NameInput): Uint8Array {
	const attributes = isNameAttributes(input) ? input : nameObjectToAttributes(input);
	if (attributes.length === 0) {
		throw new Error('Name must contain at least one attribute');
	}

	return sequence(attributes.map(encodeNameAttributeAsSet));
}

/**
 * Encodes relative distinguished name.
 *
 * @param attributes The attributes value.
 * @returns The encoded relative distinguished name.
 */
export function encodeRelativeDistinguishedName(
	attributes: RelativeDistinguishedNameInput,
): Uint8Array {
	if (attributes.length === 0) {
		throw new Error('Relative distinguished name must contain at least one attribute');
	}
	return setOf(attributes.map(encodeNameAttribute));
}

/**
 * Returns whether name attributes.
 *
 * @param input The typed input payload.
 * @returns Whether the condition holds.
 */
function isNameAttributes(input: NameInput): input is readonly NameAttribute[] {
	return Array.isArray(input);
}

/**
 * Encodes name attribute as set.
 *
 * @param attribute The attribute value.
 * @returns The encoded name attribute as set.
 */
function encodeNameAttributeAsSet(attribute: NameAttribute): Uint8Array {
	return setOf([encodeNameAttribute(attribute)]);
}

/**
 * Encodes name attribute.
 *
 * @param attribute The attribute value.
 * @returns The encoded name attribute.
 */
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

/**
 * Name object to attributes.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
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
