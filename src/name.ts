/**
 * Distinguished-name input and DER encoding helpers.
 *
 * Encodes X.509 `Name` values used for certificate subjects, issuers,
 * and CSR subjects.\
 * A `Name` is a DER `SEQUENCE` of RelativeDistinguishedNames (RDNs), and each
 * RDN is a `SET OF` one or more name attributes.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 *
 * Use {@linkcode encodeName} for the common case where each attribute occupies
 * its own RDN.\
 * Use {@linkcode encodeRelativeDistinguishedName} when you need one
 * multi-valued RDN.
 *
 * `NameObject` favors convenience: populated fields are emitted in the
 * canonical order from {@linkcode NAME_OBJECT_ORDER}.\
 * `NameAttribute` arrays favor control: caller order is preserved, but each
 * entry still becomes its own single-attribute RDN.
 *
 * Attribute OIDs and ASN.1 string encodings come from
 * {@linkcode NAME_FIELD_DEFINITIONS}.
 *
 * @example
 * ```ts
 * import { encodeName } from 'micro509/name';
 *
 * const subjectDer = encodeName({
 * 	country: 'US',
 * 	organization: 'ACME Inc',
 * 	commonName: 'example.com',
 * });
 *
 * // DER for: C=US, O=ACME Inc, CN=example.com
 * ```
 *
 * @example
 * ```ts
 * import { encodeName } from 'micro509/name';
 *
 * const subjectDer = encodeName([
 * 	{ type: 'commonName', value: 'example.com' },
 * 	{ type: 'organization', value: 'ACME Inc' },
 * 	{ type: 'country', value: 'US' },
 * ]);
 *
 * // preserves caller-supplied attribute order
 * ```
 *
 * @example
 * ```ts
 * import { encodeRelativeDistinguishedName } from 'micro509/name';
 *
 * const rdnDer = encodeRelativeDistinguishedName([
 * 	{ type: 'commonName', value: 'example.com' },
 * 	{ type: 'serialNumber', value: 'device-7' },
 * ]);
 *
 * // one multi-valued RDN containing CN + serialNumber
 * ```
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
 * Convenience object form of an X.501 distinguished name.
 *
 * Populated fields are emitted in the order defined by
 * {@linkcode NAME_OBJECT_ORDER}.\
 * Each populated field becomes its own single-attribute RDN.
 *
 * For caller-controlled ordering, pass a {@linkcode NameAttribute} array to {@linkcode encodeName}.\
 * For multi-valued RDNs, use {@linkcode encodeRelativeDistinguishedName}.
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
 * Single name attribute within a distinguished name.
 *
 * RFC 5280 / X.501 call this structure an `AttributeTypeAndValue`.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 * {@linkcode encodeName} places each attribute in its own single-attribute RDN.\
 * {@linkcode encodeRelativeDistinguishedName} packs several attributes into one RDN.
 */
export interface NameAttribute {
	/** Which attribute type this pair represents. */
	readonly type: NameFieldKey;
	/** The string value for this attribute (encoding chosen per field definition). */
	readonly value: string;
}

/**
 * Input for {@linkcode encodeName}.
 *
 * Accepts either a {@linkcode NameObject} convenience shape or an ordered array of {@linkcode NameAttribute} pairs.\
 * Both forms encode one attribute per RDN.
 */
export type NameInput = NameObject | readonly NameAttribute[];

/**
 * Input for {@linkcode encodeRelativeDistinguishedName}.
 *
 * Each entry becomes one name attribute inside the RDN's `SET OF`.\
 * Use this shape for multi-valued RDNs.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 */
export type RelativeDistinguishedNameInput = readonly NameAttribute[];

export { nameFieldKeyFromOid } from './name-fields.ts';

/**
 * DER-encodes an X.509 `Name`.
 *
 * Returns a DER `SEQUENCE` of RelativeDistinguishedNames (RDNs).\
 * Each RDN emitted by this helper contains exactly one name attribute.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 *
 * {@linkcode NameObject} input emits populated fields in the canonical order from {@linkcode NAME_OBJECT_ORDER}.\
 * {@linkcode NameAttribute} array input preserves caller-supplied ordering,
 * but each entry still becomes its own single-attribute RDN.
 *
 * Attribute OIDs and ASN.1 string encodings come from {@linkcode NAME_FIELD_DEFINITIONS}.\
 * Empty strings and `undefined` fields are ignored when the input is a {@linkcode NameObject}.
 *
 * @example
 * ```ts
 * const der = encodeName({ country: 'US', commonName: 'example.com' });
 *
 * // emits two single-attribute RDNs: C=US, then CN=example.com
 * ```
 *
 * @example
 * ```ts
 * const der = encodeName([
 * 	{ type: 'country', value: 'US' },
 * 	{ type: 'commonName', value: 'example.com' },
 * ]);
 *
 * // preserves caller order: C first, then CN
 * ```
 *
 * @param input Name fields in convenience-object form or caller-ordered attribute form.
 * @returns DER-encoded X.509 `Name` bytes.
 * @throws {Error} If the input produces no attributes, contains an unsupported field key, or uses an invalid country code.
 */
export function encodeName(input: NameInput): Uint8Array {
	const attributes = isNameAttributes(input) ? input : nameObjectToAttributes(input);
	if (attributes.length === 0) {
		throw new Error('Name must contain at least one attribute');
	}

	return sequence(attributes.map(encodeNameAttributeAsSet));
}

/**
 * DER-encodes a single RelativeDistinguishedName (RDN).
 *
 * Returns a DER `SET OF` name attributes for one X.509 name segment.\
 * Use this when you need a multi-valued RDN.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1 RFC 5280 Appendix A.1}
 *
 * Attribute OIDs and ASN.1 string encodings come from
 * {@linkcode NAME_FIELD_DEFINITIONS}.
 *
 * @example
 * ```ts
 * const rdn = encodeRelativeDistinguishedName([
 * 	{ type: 'commonName', value: 'example.com' },
 * 	{ type: 'serialNumber', value: 'device-7' },
 * ]);
 *
 * // emits one RDN with both attributes in the same SET
 * ```
 *
 * @param attributes Attribute list to encode inside one RDN.
 * @returns DER-encoded RelativeDistinguishedName bytes.
 * @throws {Error} If the attribute list is empty, contains an unsupported field key, or uses an invalid country code.
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
 * DER-encodes one name attribute SEQUENCE.
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
