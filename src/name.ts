/**
 * Distinguished-name input and encoding helpers.
 *
 * Turns typed name inputs into DER-encoded X.509 Name structures
 * (RFC 5280 §4.1.2.4).
 *
 * @module
 */

import { objectIdentifier, sequence, setOf } from './der.ts';
import { NAME_FIELD_DEFINITIONS, NAME_OBJECT_ORDER } from './name-fields.ts';

/**
 * Union of recognized X.501 attribute type shorthand names.
 *
 * Each key maps to an OID + ASN.1 string encoding in {@linkcode NAME_FIELD_DEFINITIONS}.
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
 * Bag-of-fields form of an X.501 distinguished name.
 *
 * Fields are emitted into the DER Name in the order defined by
 * {@linkcode NAME_OBJECT_ORDER}. For full control over RDN ordering, pass a
 * {@linkcode NameAttribute} array instead.
 */
export interface NameObject {
	/** Subject or issuer common name (CN). */
	readonly commonName?: string;
	/** Subject surname (SN). */
	readonly surname?: string;
	/** Device or entity serial number — not the certificate serial. */
	readonly serialNumber?: string;
	/** ISO 3166 two-letter country code (C). Must be exactly 2 characters. */
	readonly country?: string;
	/** City or locality (L). */
	readonly locality?: string;
	/** State or province (ST). */
	readonly state?: string;
	/** Street address. */
	readonly street?: string;
	/** Organization name (O). */
	readonly organization?: string;
	/** Organizational unit (OU). Deprecated in modern CA practice. */
	readonly organizationalUnit?: string;
	/** Job title or functional designation. */
	readonly title?: string;
	/** First / given name (GN). */
	readonly givenName?: string;
	/** RFC 822 email address. Encoded as IA5String, not UTF-8. */
	readonly emailAddress?: string;
}

/**
 * Single attribute type–value pair within a distinguished name.
 *
 * Use an array of these when you need explicit RDN ordering that
 * {@linkcode NameObject} cannot express.
 */
export interface NameAttribute {
	/** Which attribute type this pair represents. */
	readonly type: NameFieldKey;
	/** The string value for this attribute (encoding chosen per field definition). */
	readonly value: string;
}

/**
 * Input for {@linkcode encodeName}. Either a {@linkcode NameObject} bag-of-fields or
 * an ordered array of {@linkcode NameAttribute} pairs.
 */
export type NameInput = NameObject | readonly NameAttribute[];
/**
 * Input for {@linkcode encodeRelativeDistinguishedName}. Each attribute becomes
 * one element in the SET OF.
 */
export type RelativeDistinguishedNameInput = readonly NameAttribute[];

export { nameFieldKeyFromOid } from './name-fields.ts';

/**
 * DER-encodes an X.509 Name (SEQUENCE OF SET OF AttributeTypeAndValue).
 *
 * Throws if the input produces zero attributes.
 *
 * @example
 * ```ts
 * const der = encodeName({ country: 'US', commonName: 'example.com' });
 * ```
 *
 * @example
 * ```ts
 * const der = encodeName([
 *   { type: 'country', value: 'US' },
 *   { type: 'commonName', value: 'example.com' },
 * ]);
 * ```
 */
export function encodeName(input: NameInput): Uint8Array {
	const attributes = isNameAttributes(input) ? input : nameObjectToAttributes(input);
	if (attributes.length === 0) {
		throw new Error('Name must contain at least one attribute');
	}

	return sequence(attributes.map(encodeNameAttributeAsSet));
}

/**
 * DER-encodes a single RelativeDistinguishedName (SET OF AttributeTypeAndValue).
 *
 * Throws if the attribute list is empty.
 */
export function encodeRelativeDistinguishedName(
	attributes: RelativeDistinguishedNameInput,
): Uint8Array {
	if (attributes.length === 0) {
		throw new Error('Relative distinguished name must contain at least one attribute');
	}
	return setOf(attributes.map(encodeNameAttribute));
}

/** Narrows a {@linkcode NameInput} to the ordered-attribute-array form. */
function isNameAttributes(input: NameInput): input is readonly NameAttribute[] {
	return Array.isArray(input);
}

/** Wraps a single attribute in a SET OF for the Name SEQUENCE. */
function encodeNameAttributeAsSet(attribute: NameAttribute): Uint8Array {
	return setOf([encodeNameAttribute(attribute)]);
}

/**
 * DER-encodes one AttributeTypeAndValue SEQUENCE.
 *
 * Throws for unsupported field keys and invalid country codes.
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

/** Converts a {@linkcode NameObject} to ordered attributes per {@linkcode NAME_OBJECT_ORDER}. */
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
