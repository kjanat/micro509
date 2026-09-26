/**
 * RFC 5280 Appendix A.1 ORAddress schema validation for x400Address builder
 * input. The module is `DEFINITIONS EXPLICIT TAGS`, so only the fields marked
 * IMPLICIT replace their underlying tag.
 *
 * @module
 */

import { childrenOf, decodeIntegerNumber, decodeString } from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import type { GeneralNameContentCheck } from '#micro509/internal/x509/general-name-profile';

const VALID: GeneralNameContentCheck = { ok: true };
const MALFORMED: GeneralNameContentCheck = { ok: false, reason: 'malformed' };
const UNSUPPORTED: GeneralNameContentCheck = { ok: false, reason: 'unsupported' };

const NUMERIC_STRING = 0x12;
const PRINTABLE_STRING = 0x13;
const SEQUENCE = 0x30;
const SET = 0x31;

/** A string bound in characters, inclusive. */
interface Bounds {
	readonly min: number;
	readonly max: number;
}

function bounds(min: number, max: number): Bounds {
	return { min, max };
}

function check(valid: boolean): GeneralNameContentCheck {
	return valid ? VALID : MALFORMED;
}

function firstFailure(checks: readonly GeneralNameContentCheck[]): GeneralNameContentCheck {
	return checks.find((result) => !result.ok) ?? VALID;
}

/** X.680 Table 9: NumericString holds digits and space. */
function isNumericString(value: Uint8Array, size: Bounds): boolean {
	return (
		value.length >= size.min &&
		value.length <= size.max &&
		value.every((octet) => octet === 0x20 || (octet >= 0x30 && octet <= 0x39))
	);
}

function isPrintableString(value: Uint8Array, size: Bounds): boolean {
	if (value.length < size.min || value.length > size.max) {
		return false;
	}
	try {
		decodeString(PRINTABLE_STRING, value);
		return true;
	} catch {
		return false;
	}
}

/** A universal NumericString or PrintableString element within its CHOICE bounds. */
function isNumericOrPrintable(element: DerElement, numeric: Bounds, printable: Bounds): boolean {
	return element.tag === NUMERIC_STRING
		? isNumericString(element.value, numeric)
		: element.tag === PRINTABLE_STRING && isPrintableString(element.value, printable);
}

/** The single element an explicit tag wraps, or `undefined`. */
function explicitInner(source: Uint8Array, element: DerElement): DerElement | undefined {
	const children = childrenOf(source, element);
	return children.length === 1 ? children[0] : undefined;
}

/** DER orders SET components by ascending tag and SET OF members by ascending encoding. */
function isAscending(values: readonly number[]): boolean {
	return values.every((value, index) => index === 0 || (values[index - 1] ?? value) < value);
}

function compareEncodings(left: Uint8Array, right: Uint8Array): number {
	const length = Math.min(left.length, right.length);
	for (let index = 0; index < length; index += 1) {
		const difference = (left[index] ?? 0) - (right[index] ?? 0);
		if (difference !== 0) return difference;
	}
	return left.length - right.length;
}

function encodingOf(source: Uint8Array, element: DerElement): Uint8Array {
	return source.subarray(element.start - element.headerLength, element.end);
}

/** RFC 5280 A.1: `CountryName ::= [APPLICATION 1] CHOICE`, also the physical-delivery-country-name CHOICE. */
function checkCountryName(element: DerElement | undefined): GeneralNameContentCheck {
	return check(element !== undefined && isNumericOrPrintable(element, bounds(3, 3), bounds(2, 2)));
}

type FieldCheck = (source: Uint8Array, element: DerElement) => GeneralNameContentCheck;

/** BuiltInStandardAttributes fields in schema order, keyed by their encoded tag. */
const BUILT_IN_STANDARD_ATTRIBUTES: ReadonlyMap<number, FieldCheck> = new Map<number, FieldCheck>([
	[0x61, (source, element) => checkCountryName(explicitInner(source, element))],
	[
		0x62,
		(source, element) => {
			const inner = explicitInner(source, element);
			return check(
				inner !== undefined && isNumericOrPrintable(inner, bounds(0, 16), bounds(0, 16)),
			);
		},
	],
	[0x80, (_source, element) => check(isNumericString(element.value, bounds(1, 16)))],
	[0x81, (_source, element) => check(isPrintableString(element.value, bounds(1, 24)))],
	[
		0xa2,
		(source, element) => {
			const inner = explicitInner(source, element);
			return check(
				inner !== undefined && isNumericOrPrintable(inner, bounds(1, 16), bounds(1, 16)),
			);
		},
	],
	[0x83, (_source, element) => check(isPrintableString(element.value, bounds(1, 64)))],
	[0x84, (_source, element) => check(isNumericString(element.value, bounds(1, 32)))],
	[0xa5, checkPersonalName],
	[0xa6, checkOrganizationalUnitNames],
]);

const BUILT_IN_STANDARD_ORDER: readonly number[] = [...BUILT_IN_STANDARD_ATTRIBUTES.keys()];

/**
 * `PersonalName ::= SET { surname [0], given-name [1] OPTIONAL, initials [2]
 * OPTIONAL, generation-qualifier [3] OPTIONAL }`, each an IMPLICIT
 * PrintableString of 1 to 40, 16, 5 and 3 characters.
 */
function checkPersonalName(source: Uint8Array, element: DerElement): GeneralNameContentCheck {
	const fields = childrenOf(source, element);
	const limits = new Map([
		[0x80, 40],
		[0x81, 16],
		[0x82, 5],
		[0x83, 3],
	]);
	return check(
		fields[0]?.tag === 0x80 &&
			isAscending(fields.map((field) => field.tag)) &&
			fields.every((field) => {
				const max = limits.get(field.tag);
				return max !== undefined && isPrintableString(field.value, bounds(1, max));
			}),
	);
}

/** `OrganizationalUnitNames ::= SEQUENCE SIZE (1..4) OF PrintableString (SIZE (1..32))`. */
function checkOrganizationalUnitNames(
	source: Uint8Array,
	element: DerElement,
): GeneralNameContentCheck {
	const names = childrenOf(source, element);
	return check(
		names.length >= 1 &&
			names.length <= 4 &&
			names.every(
				(name) => name.tag === PRINTABLE_STRING && isPrintableString(name.value, bounds(1, 32)),
			),
	);
}

function checkBuiltInStandardAttributes(
	source: Uint8Array,
	element: DerElement,
): GeneralNameContentCheck {
	const fields = childrenOf(source, element);
	const positions = fields.map((field) => BUILT_IN_STANDARD_ORDER.indexOf(field.tag));
	if (positions.some((position) => position < 0) || !isAscending(positions)) {
		return MALFORMED;
	}
	return firstFailure(
		fields.map(
			(field) => BUILT_IN_STANDARD_ATTRIBUTES.get(field.tag)?.(source, field) ?? MALFORMED,
		),
	);
}

/**
 * `BuiltInDomainDefinedAttributes ::= SEQUENCE SIZE (1..4) OF SEQUENCE { type
 * PrintableString (SIZE (1..8)), value PrintableString (SIZE (1..128)) }`.
 */
function checkBuiltInDomainDefinedAttributes(
	source: Uint8Array,
	element: DerElement,
): GeneralNameContentCheck {
	const attributes = childrenOf(source, element);
	return check(
		attributes.length >= 1 &&
			attributes.length <= 4 &&
			attributes.every((attribute) => {
				const [type, value, ...rest] =
					attribute.tag === SEQUENCE ? childrenOf(source, attribute) : [];
				return (
					rest.length === 0 &&
					type?.tag === PRINTABLE_STRING &&
					value?.tag === PRINTABLE_STRING &&
					isPrintableString(type.value, bounds(1, 8)) &&
					isPrintableString(value.value, bounds(1, 128))
				);
			}),
	);
}

/**
 * `PDSParameter ::= SET { printable-string PrintableString (SIZE (1..30))
 * OPTIONAL, teletex-string TeletexString OPTIONAL }`. A TeletexString
 * component is unsupported.
 */
function checkPdsParameter(source: Uint8Array, value: DerElement): GeneralNameContentCheck {
	if (value.tag !== SET) return MALFORMED;
	const components = childrenOf(source, value);
	if (components.some((component) => component.tag === 0x14)) return UNSUPPORTED;
	return check(
		components.length <= 1 &&
			components.every(
				(component) =>
					component.tag === PRINTABLE_STRING && isPrintableString(component.value, bounds(1, 30)),
			),
	);
}

/**
 * `UnformattedPostalAddress ::= SET { printable-address SEQUENCE SIZE (1..6) OF
 * PrintableString (SIZE (1..30)) OPTIONAL, teletex-string TeletexString
 * OPTIONAL }`. A TeletexString component is unsupported.
 */
function checkUnformattedPostalAddress(
	source: Uint8Array,
	value: DerElement,
): GeneralNameContentCheck {
	if (value.tag !== SET) return MALFORMED;
	const components = childrenOf(source, value);
	if (components.some((component) => component.tag === 0x14)) return UNSUPPORTED;
	const lines = components[0] === undefined ? [] : childrenOf(source, components[0]);
	return check(
		components.length <= 1 &&
			(components[0] === undefined ||
				(components[0].tag === SEQUENCE &&
					lines.length >= 1 &&
					lines.length <= 6 &&
					lines.every(
						(line) => line.tag === PRINTABLE_STRING && isPrintableString(line.value, bounds(1, 30)),
					))),
	);
}

/** `TerminalType ::= INTEGER (0..ub-integer-options)`, with ub-integer-options 256. */
function checkTerminalType(_source: Uint8Array, value: DerElement): GeneralNameContentCheck {
	if (value.tag !== 0x02) return MALFORMED;
	try {
		const terminalType = decodeIntegerNumber(value.value);
		return check(terminalType >= 0 && terminalType <= 256);
	} catch {
		return MALFORMED;
	}
}

/**
 * Extension-attribute value schemas by `extension-attribute-type`. Types 2 to 6
 * are TeletexString forms and type 22 is extended-network-address; they and
 * any type RFC 5280 does not define are unsupported.
 */
const EXTENSION_ATTRIBUTE_VALUES: ReadonlyMap<number, FieldCheck> = new Map<number, FieldCheck>([
	[
		1,
		(_source, value) =>
			check(value.tag === PRINTABLE_STRING && isPrintableString(value.value, bounds(1, 64))),
	],
	[
		7,
		(_source, value) =>
			check(value.tag === PRINTABLE_STRING && isPrintableString(value.value, bounds(1, 16))),
	],
	[8, (_source, value) => checkCountryName(value)],
	[9, (_source, value) => check(isNumericOrPrintable(value, bounds(1, 16), bounds(1, 16)))],
	...[10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21].map((type): [number, FieldCheck] => [
		type,
		checkPdsParameter,
	]),
	[16, checkUnformattedPostalAddress],
	[23, checkTerminalType],
]);

/**
 * `ExtensionAttribute ::= SEQUENCE { extension-attribute-type [0] IMPLICIT
 * INTEGER (0..256), extension-attribute-value [1] ANY DEFINED BY
 * extension-attribute-type }`.
 */
function checkExtensionAttribute(source: Uint8Array, element: DerElement): GeneralNameContentCheck {
	const [type, wrapped, ...rest] = element.tag === SEQUENCE ? childrenOf(source, element) : [];
	if (type?.tag !== 0x80 || wrapped?.tag !== 0xa1 || rest.length > 0) return MALFORMED;
	let typeNumber: number;
	try {
		typeNumber = decodeIntegerNumber(type.value);
	} catch {
		return MALFORMED;
	}
	const value = explicitInner(source, wrapped);
	if (typeNumber < 0 || typeNumber > 256 || value === undefined) return MALFORMED;
	return EXTENSION_ATTRIBUTE_VALUES.get(typeNumber)?.(source, value) ?? UNSUPPORTED;
}

/** `ExtensionAttributes ::= SET SIZE (1..256) OF ExtensionAttribute`, DER-sorted. */
function checkExtensionAttributes(
	source: Uint8Array,
	element: DerElement,
): GeneralNameContentCheck {
	const attributes = childrenOf(source, element);
	const sorted = attributes.every(
		(attribute, index) =>
			index === 0 ||
			compareEncodings(
				encodingOf(source, attributes[index - 1] ?? attribute),
				encodingOf(source, attribute),
			) <= 0,
	);
	if (attributes.length < 1 || attributes.length > 256 || !sorted) return MALFORMED;
	return firstFailure(attributes.map((attribute) => checkExtensionAttribute(source, attribute)));
}

/**
 * `ORAddress ::= SEQUENCE { built-in-standard-attributes, built-in-domain-defined-attributes
 * OPTIONAL, extension-attributes OPTIONAL }`, given the children of the x400Address element.
 */
export function checkOrAddressFields(
	children: readonly DerElement[],
	source: Uint8Array,
): GeneralNameContentCheck {
	const [standard, ...optional] = children;
	const domainDefined = optional[0]?.tag === SEQUENCE ? optional[0] : undefined;
	const extensions = optional.slice(domainDefined === undefined ? 0 : 1);
	const [extensionAttributes, ...extra] = extensions;
	if (
		standard?.tag !== SEQUENCE ||
		extra.length > 0 ||
		(extensionAttributes !== undefined && extensionAttributes.tag !== SET)
	) {
		return MALFORMED;
	}
	return firstFailure([
		checkBuiltInStandardAttributes(source, standard),
		domainDefined === undefined
			? VALID
			: checkBuiltInDomainDefinedAttributes(source, domainDefined),
		extensionAttributes === undefined
			? VALID
			: checkExtensionAttributes(source, extensionAttributes),
	]);
}
