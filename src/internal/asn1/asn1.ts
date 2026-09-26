/**
 * ASN.1 decoding helpers used by the higher-level DER, parse, and crypto modules.
 *
 * These utilities stay intentionally small and strict so malformed input fails early and
 * higher-level modules can build on one consistent decoding layer.
 *
 * @module
 */

import type { DerElement } from '#micro509/internal/asn1/der';
import {
	DEFAULT_MAX_DER_DEPTH,
	objectIdentifier,
	readElement,
	walkDerTree,
} from '#micro509/internal/asn1/der';

/** Shared UTF-8 text decoder for ASN.1 string types. */
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const PRINTABLE_STRING_PATTERN = /^[A-Za-z0-9 '()+,\-./:=?]*$/u;

/**
 * Decodes a DER-encoded OBJECT IDENTIFIER value into its dotted-decimal string form.
 *
 * @example "1.2.840.113549.1.1.1"
 * @throws on empty input, truncated multi-byte sub-identifiers, or incomplete continuation octets.
 */
export function decodeObjectIdentifier(bytes: Uint8Array): string {
	if (bytes.length === 0) {
		throw new Error('OID is empty');
	}
	const firstSubidentifier = decodeOidSubidentifier(bytes, 0);
	let offset = firstSubidentifier.nextOffset;
	const values =
		firstSubidentifier.value < 40
			? [0, firstSubidentifier.value]
			: firstSubidentifier.value < 80
				? [1, firstSubidentifier.value - 40]
				: [2, firstSubidentifier.value - 80];
	while (offset < bytes.length) {
		const subidentifier = decodeOidSubidentifier(bytes, offset);
		values.push(subidentifier.value);
		offset = subidentifier.nextOffset;
	}
	return values.join('.');
}

/**
 * Reduces an OID to the dotted-decimal form its DER encoding decodes back to, so
 * that spellings differing only by redundant leading zeros in an arc resolve to
 * one identity.
 *
 * @example `canonicalizeOid('2.5.029.17')` returns `'2.5.29.17'`
 * @throws if the OID has a non-numeric segment or violates the X.660 arc constraints.
 */
export function canonicalizeOid(oid: string): string {
	return decodeObjectIdentifier(readElement(objectIdentifier(oid), 0).value);
}

/** Converts raw bytes to a lowercase hex string with no separator. */
export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

/**
 * Copies a {@linkcode Uint8Array} into a standalone {@linkcode ArrayBuffer} suitable for
 * Web Crypto operations that require a non-shared backing buffer.
 */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}

/**
 * Iterates through all direct child TLV elements inside a constructed {@linkcode DerElement}
 * (SEQUENCE, SET, or context-tagged container).
 *
 * @throws if any child overflows the parent boundary or if there is leftover data between the last child and the parent end offset.
 */
export function childrenOf(source: Uint8Array, parent: DerElement): DerElement[] {
	const children: DerElement[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		if (child.end > parent.end) {
			throw new Error('DER child exceeds parent length');
		}
		children.push(child);
		offset = child.end;
	}
	if (offset !== parent.end) {
		throw new Error('Malformed DER container');
	}
	return children;
}

/**
 * Asserts that a value is not `undefined`, returning it narrowed.\
 * Used to enforce the presence of mandatory ASN.1 fields during parsing.
 *
 * @param label Human-readable field name included in the error message on failure.
 */
export function requireElement<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

/**
 * Strips the leading "unused bits" octet from a BIT STRING element, returning just the payload bytes.
 *
 * Used to extract signature values and public keys from their BIT STRING wrapper.
 *
 * @throws if the tag is not `0x03`.
 */
export function extractBitStringValue(element: DerElement): Uint8Array {
	if (element.tag !== 0x03) {
		throw new Error('Expected BIT STRING');
	}
	const unusedBits = element.value[0];
	if (unusedBits === undefined || unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	if (unusedBits !== 0) {
		throw new Error('BIT STRING must have zero unused bits');
	}
	return element.value.slice(1);
}

/** A BIT STRING payload and the number of unused trailing bits in its final byte. */
export interface DerBitString {
	/** Payload bytes, excluding the leading unused-bit count octet. */
	readonly bytes: Uint8Array;
	/** Unused trailing bits in the final byte, 0 through 7. */
	readonly unusedBits: number;
	/** `true` when the original encoding had non-zero padding bits (DER violation). */
	readonly nonZeroPadding: boolean;
}

/**
 * Decodes a BIT STRING element into its payload and unused-bit count.
 *
 * Accepts a non-zero unused-bit count, so it reads flag strings such as {@linkcode KeyUsage},
 * which {@linkcode extractBitStringValue} rejects.
 *
 * Padding bits that {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §11.2.1} requires to be zero are reported through
 * {@linkcode DerBitString.nonZeroPadding} rather than rejected, so a caller can decide.
 */
export function decodeBitString(element: DerElement): DerBitString {
	if (element.tag !== 0x03) {
		throw new Error('Expected BIT STRING');
	}
	const unusedBits = element.value[0];
	if (unusedBits === undefined || unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	const bytes = element.value.slice(1);
	if (bytes.length === 0 && unusedBits !== 0) {
		throw new Error('Invalid BIT STRING');
	}
	const paddingMask = (1 << unusedBits) - 1;
	const nonZeroPadding =
		unusedBits > 0 && bytes.length > 0 && ((bytes[bytes.length - 1] ?? 0) & paddingMask) !== 0;
	return { bytes, unusedBits, nonZeroPadding };
}

/**
 * Parses a {@linkcode DerElement} with tag UTCTime (`0x17`) or GeneralizedTime (`0x18`) into a {@linkcode Date}.
 *
 * For UTCTime, the two-digit year is interpreted per RFC 5280:
 * - values >= 50 map to 19xx,
 * - values < 50 map to 20xx.
 *
 * @throws on unrecognized time tags.
 */
export function parseTime(element: DerElement): Date {
	if (element.tag === 0x17) {
		const value = decodeUtf8Text(element.value, 'UTCTime');
		const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
		if (match === null) {
			throw new Error('Invalid UTCTime');
		}
		const yearText = requireElement(match[1], 'UTCTime year');
		const monthText = requireElement(match[2], 'UTCTime month');
		const dayText = requireElement(match[3], 'UTCTime day');
		const hourText = requireElement(match[4], 'UTCTime hour');
		const minuteText = requireElement(match[5], 'UTCTime minute');
		const secondText = requireElement(match[6], 'UTCTime second');
		const year = Number.parseInt(yearText, 10);
		return buildStrictUtcDate(
			year >= 50 ? 1900 + year : 2000 + year,
			monthText,
			dayText,
			hourText,
			minuteText,
			secondText,
			'UTCTime',
		);
	}
	if (element.tag === 0x18) {
		const value = decodeUtf8Text(element.value, 'GeneralizedTime');
		const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
		if (match === null) {
			throw new Error('Invalid GeneralizedTime');
		}
		const yearText = requireElement(match[1], 'GeneralizedTime year');
		const monthText = requireElement(match[2], 'GeneralizedTime month');
		const dayText = requireElement(match[3], 'GeneralizedTime day');
		const hourText = requireElement(match[4], 'GeneralizedTime hour');
		const minuteText = requireElement(match[5], 'GeneralizedTime minute');
		const secondText = requireElement(match[6], 'GeneralizedTime second');
		return buildStrictUtcDate(
			Number.parseInt(yearText, 10),
			monthText,
			dayText,
			hourText,
			minuteText,
			secondText,
			'GeneralizedTime',
		);
	}
	throw new Error(`Unsupported time tag: ${element.tag}`);
}

/**
 * Decodes DER INTEGER content octets holding a non-negative value into a JavaScript `number`.
 *
 * @throws if the value is empty, negative, non-minimally encoded, or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
 */
export function decodeIntegerNumber(bytes: Uint8Array): number {
	const magnitude = decodeIntegerMagnitude(bytes);
	if (magnitude.type === 'unsafe') {
		throw new Error(`Integer too large for safe number (${bytes.length} bytes)`);
	}
	return magnitude.value;
}

/** A non-negative INTEGER value as a `number`, or `unsafe` once it exceeds {@linkcode Number.MAX_SAFE_INTEGER}. */
export type IntegerMagnitude =
	| { readonly type: 'safe'; readonly value: number }
	| { readonly type: 'unsafe' };

/**
 * Decodes DER INTEGER content octets holding a non-negative value, stopping at the first octet past {@linkcode Number.MAX_SAFE_INTEGER}.
 *
 * @param bytes DER INTEGER content octets to decode.
 * @param label Field name for error messages (defaults to `"INTEGER"`).
 * @throws if the value is empty, negative, or non-minimally encoded.
 */
export function decodeIntegerMagnitude(bytes: Uint8Array, label = 'INTEGER'): IntegerMagnitude {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error(`${label} is empty`);
	}
	if ((first & 0x80) !== 0) {
		throw new Error(`${label} must be non-negative`);
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error(`${label} must use minimal encoding`);
	}
	let value = 0;
	for (const byte of bytes) {
		if (value > Math.floor((Number.MAX_SAFE_INTEGER - byte) / 256)) {
			return { type: 'unsafe' };
		}
		value = value * 256 + byte;
	}
	return { type: 'safe', value };
}

/**
 * Like {@linkcode decodeIntegerNumber}, but optionally rewrites thrown error messages with a caller-specific field label.
 *
 * @param bytes DER INTEGER content octets to decode.
 * @param label Field name for error messages (defaults to `"INTEGER"`).
 * @throws if the value is empty, negative, non-minimally encoded, or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
 */
export function decodeNonNegativeIntegerNumber(bytes: Uint8Array, label = 'INTEGER'): number {
	if (label === 'INTEGER') {
		return decodeIntegerNumber(bytes);
	}
	try {
		return decodeIntegerNumber(bytes);
	} catch (error) {
		if (!(error instanceof Error)) {
			throw error;
		}
		switch (error.message) {
			case 'INTEGER is empty':
				throw new Error(`${label} is empty`);
			case 'INTEGER must be non-negative':
				throw new Error(`${label} must be non-negative`);
			case 'INTEGER must use minimal encoding':
				throw new Error(`${label} must use minimal encoding`);
			default:
				if (error.message.startsWith('Integer too large for safe number')) {
					throw new Error(`${label} too large for safe number (${bytes.length} bytes)`);
				}
				throw error;
		}
	}
}

/**
 * Converts a hex string (even or odd length) to a {@linkcode Uint8Array}.
 * Odd-length strings are left-padded with a zero nibble.
 */
export function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const out = new Uint8Array(normalized.length / 2);
	for (let index = 0; index < out.length; index += 1) {
		const chunk = normalized.slice(index * 2, index * 2 + 2);
		if (!/^[0-9a-fA-F]{2}$/.test(chunk)) {
			throw new Error(`Invalid hex byte: ${chunk}`);
		}
		const parsed = Number.parseInt(chunk, 16);
		out[index] = parsed;
	}
	return out;
}

/** Decodes a DER BOOLEAN value. X.690 clause 11.1 restricts TRUE to an all-ones octet, so only `0xff` and `0x00` are accepted. */
export function decodeBoolean(bytes: Uint8Array): boolean {
	if (bytes.length !== 1) {
		throw new Error('BOOLEAN must contain exactly one octet');
	}
	const value = bytes[0];
	if (value !== 0x00 && value !== 0xff) {
		throw new Error('BOOLEAN must use DER encoding');
	}
	return value === 0xff;
}

function buildStrictUtcDate(
	year: number,
	monthText: string,
	dayText: string,
	hourText: string,
	minuteText: string,
	secondText: string,
	label: 'UTCTime' | 'GeneralizedTime',
): Date {
	const month = Number.parseInt(monthText, 10);
	const day = Number.parseInt(dayText, 10);
	const hour = Number.parseInt(hourText, 10);
	const minute = Number.parseInt(minuteText, 10);
	const second = Number.parseInt(secondText, 10);
	const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
	if (
		Number.isNaN(date.getTime()) ||
		date.getUTCFullYear() !== year ||
		date.getUTCMonth() !== month - 1 ||
		date.getUTCDate() !== day ||
		date.getUTCHours() !== hour ||
		date.getUTCMinutes() !== minute ||
		date.getUTCSeconds() !== second
	) {
		throw new Error(`Invalid ${label}`);
	}
	return date;
}

function decodeOidSubidentifier(
	bytes: Uint8Array,
	start: number,
): {
	readonly value: number;
	readonly nextOffset: number;
} {
	const first = bytes[start];
	if (first === undefined) {
		throw new Error('Malformed OID');
	}
	if (first === 0x80) {
		throw new Error('Malformed OID: non-minimal base-128 encoding');
	}
	let value = 0;
	let offset = start;
	for (; offset < bytes.length; offset += 1) {
		const next = bytes[offset];
		if (next === undefined) {
			throw new Error('Malformed OID');
		}
		const digit = next & 0x7f;
		if (value > Math.floor((Number.MAX_SAFE_INTEGER - digit) / 128)) {
			throw new Error('Malformed OID: overflow/non-minimal or too-large subidentifier');
		}
		value = value * 128 + digit;
		if ((next & 0x80) === 0) {
			return {
				value,
				nextOffset: offset + 1,
			};
		}
	}
	throw new Error('Malformed OID: incomplete continuation');
}

/**
 * Decodes a DER string element by tag.
 *
 * Supports:
 * - UTF8String (`0x0c`),
 * - PrintableString (`0x13`),
 * - IA5String (`0x16`),
 * - UniversalString (`0x1c`), and
 * - BMPString (`0x1e`).
 *
 * @throws on unsupported string tags.
 */
export function decodeString(tag: number, bytes: Uint8Array): string {
	switch (tag) {
		case 0x0c:
			return decodeUtf8Text(bytes, 'UTF8String');
		case 0x13:
			return decodePrintableString(bytes);
		case 0x16:
			return decodeIa5String(bytes);
		case 0x14:
			throw new Error('Unsupported string tag: 20 (TeletexString)');
		case 0x1c:
			return decodeUniversalString(bytes);
		case 0x1e:
			return decodeBmpString(bytes);
		default:
			throw new Error(`Unsupported string tag: ${tag}`);
	}
}

function decodeUtf8Text(
	bytes: Uint8Array,
	label: 'GeneralizedTime' | 'UTCTime' | 'UTF8String',
): string {
	try {
		return textDecoder.decode(bytes);
	} catch (error) {
		if (error instanceof Error) {
			throw new Error(`Invalid ${label}: invalid UTF-8`, { cause: error });
		}
		throw error;
	}
}

function decodeAsciiString(bytes: Uint8Array, label: 'IA5String' | 'PrintableString'): string {
	let value = '';
	for (const byte of bytes) {
		if (byte > 0x7f) {
			throw new Error(`Invalid ${label}: contains non-ASCII bytes`);
		}
		value += String.fromCharCode(byte);
	}
	return value;
}

function decodeIa5String(bytes: Uint8Array): string {
	return decodeAsciiString(bytes, 'IA5String');
}

function decodePrintableString(bytes: Uint8Array): string {
	const value = decodeAsciiString(bytes, 'PrintableString');
	if (!PRINTABLE_STRING_PATTERN.test(value)) {
		throw new Error('Invalid PrintableString: contains characters outside the allowed set');
	}
	return value;
}

function decodeBmpString(bytes: Uint8Array): string {
	if (bytes.length % 2 !== 0) {
		throw new Error('Invalid BMPString length');
	}
	let value = '';
	for (let index = 0; index < bytes.length; index += 2) {
		const left = bytes[index];
		const right = bytes[index + 1];
		if (left === undefined || right === undefined) {
			throw new Error('Invalid BMPString content');
		}
		const codeUnit = (left << 8) | right;
		if (codeUnit >= 0xd800 && codeUnit <= 0xdfff) {
			throw new Error('Invalid BMPString code point');
		}
		value += String.fromCharCode(codeUnit);
	}
	return value;
}

function decodeUniversalString(bytes: Uint8Array): string {
	if (bytes.length % 4 !== 0) {
		throw new Error('Invalid UniversalString length');
	}
	let value = '';
	for (let index = 0; index < bytes.length; index += 4) {
		const first = bytes[index];
		const second = bytes[index + 1];
		const third = bytes[index + 2];
		const fourth = bytes[index + 3];
		if (
			first === undefined ||
			second === undefined ||
			third === undefined ||
			fourth === undefined
		) {
			throw new Error('Invalid UniversalString content');
		}
		const codePoint = ((first * 256 + second) * 256 + third) * 256 + fourth;
		if (codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
			throw new Error('Invalid UniversalString code point');
		}
		value += String.fromCodePoint(codePoint);
	}
	return value;
}

/** The verdict of {@linkcode checkStrictDer} on an encoding. */
export type StrictDerVerdict = 'valid' | 'malformed' | 'unsupported';

/**
 * Walks {@linkcode bytes} as one DER element and checks each universal-class
 * element against the X.690 rules its tag fixes: the identifier form, the
 * contents, and the DER restrictions of clauses 10 and 11.
 *
 * Where those rules rest on ISO/IEC 2022, ISO 8601 or an implicitly tagged
 * schema, the element is `unsupported`: TeletexString, VideotexString, TIME,
 * EXTERNAL, EMBEDDED PDV, CHARACTER STRING, a REAL with a long-form exponent, a
 * GeneralizedTime at second 60, and text holding an escape sequence or a
 * code-extension control. Context-specific, application and private elements
 * get framing checks only, as do the rules that depend on a schema: SET
 * component order, DEFAULT omission and NamedBitList trailing bits.
 */
export function checkStrictDer(
	bytes: Uint8Array,
	maxDepth: number = DEFAULT_MAX_DER_DEPTH,
): StrictDerVerdict {
	let unsupported = false;
	try {
		walkDerTree(bytes, maxDepth, undefined, (element) => {
			const verdict = checkUniversalElement(element);
			if (verdict === 'malformed') {
				throw new Error('DER element breaks the rules of its universal type');
			}
			unsupported ||= verdict === 'unsupported';
		});
	} catch {
		return 'malformed';
	}
	return unsupported ? 'unsupported' : 'valid';
}

type UniversalElementCheck = (element: DerElement) => StrictDerVerdict;

function verdictOf(valid: boolean): StrictDerVerdict {
	return valid ? 'valid' : 'malformed';
}

function decodes(decode: () => unknown): StrictDerVerdict {
	try {
		decode();
		return 'valid';
	} catch {
		return 'malformed';
	}
}

function asciiText(contents: Uint8Array): string | undefined {
	try {
		return decodeIa5String(contents);
	} catch {
		return undefined;
	}
}

const ESCAPE = 0x1b;

/** X.690 §8.23.10 and Table 3: UTF8String and IA5String carry no escape sequence. */
const ESCAPE_CONTROLS: ReadonlySet<number> = new Set([ESCAPE]);

/** X.690 §8.23.9: SHIFT OUT, SHIFT IN, ESCAPE, SINGLE-SHIFT TWO and THREE, and CONTROL SEQUENCE INTRODUCER. */
const CODE_EXTENSION_CONTROLS: ReadonlySet<number> = new Set([
	0x0e,
	0x0f,
	ESCAPE,
	0x8e,
	0x8f,
	0x9b,
]);

/** The verdict on text {@linkcode decode} validates, `unsupported` when it holds one of {@linkcode controls}. */
function checkText(decode: () => string, controls: ReadonlySet<number>): StrictDerVerdict {
	let text: string;
	try {
		text = decode();
	} catch {
		return 'malformed';
	}
	for (const character of text) {
		if (controls.has(character.codePointAt(0) ?? 0)) {
			return 'unsupported';
		}
	}
	return 'valid';
}

/** X.690 Table 3: GraphicString and ObjectDescriptor open with register entry 6 as G0 and no C0 or C1 set. */
function checkGraphicString(element: DerElement): StrictDerVerdict {
	if (element.value.includes(ESCAPE)) {
		return 'unsupported';
	}
	return verdictOf(element.value.every((octet) => octet >= 0x20 && octet <= 0x7e));
}

/** X.690 Table 3: GeneralString opens with register entry 6 as G0 and entry 1 as C0, beside SPACE and DELETE. */
function checkGeneralString(element: DerElement): StrictDerVerdict {
	if (element.value.some((octet) => octet === ESCAPE || octet === 0x0e || octet === 0x0f)) {
		return 'unsupported';
	}
	return verdictOf(element.value.every((octet) => octet <= 0x7f));
}

/** X.690 §8.3.2: the first nine bits of a multi-octet INTEGER are neither all ones nor all zeros. */
function isMinimalInteger(contents: Uint8Array): boolean {
	const [first, second] = contents;
	if (first === undefined) {
		return false;
	}
	return (
		second === undefined ||
		((first !== 0x00 || second >= 0x80) && (first !== 0xff || second < 0x80))
	);
}

/** X.690 §8.19.2: every subidentifier ends on an octet with bit 8 clear and never opens with 0x80. */
function isSubidentifierList(contents: Uint8Array): boolean {
	let opensSubidentifier = true;
	for (const octet of contents) {
		if (opensSubidentifier && octet === 0x80) {
			return false;
		}
		opensSubidentifier = (octet & 0x80) === 0;
	}
	return opensSubidentifier;
}

function checkBitString(element: DerElement): StrictDerVerdict {
	try {
		return verdictOf(!decodeBitString(element).nonZeroPadding);
	} catch {
		return 'malformed';
	}
}

/** X.680 Table 9: NumericString holds the digits and SPACE. */
export function isNumericStringContents(contents: Uint8Array): boolean {
	return contents.every((octet) => octet === 0x20 || (octet >= 0x30 && octet <= 0x39));
}

function isLeapYear(year: number): boolean {
	return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

const DAYS_IN_MONTH: readonly number[] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

interface TimeSyntax {
	readonly pattern: RegExp;
	readonly century: number;
	readonly leapSecond: StrictDerVerdict;
}

/** X.690 §11.8 and X.680 §47.3: `YYMMDDhhmmssZ`, the year as its two low-order digits and seconds 00 to 59. */
const UTC_TIME: TimeSyntax = {
	pattern: /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/,
	century: 2000,
	leapSecond: 'malformed',
};

/** X.690 §11.7: seconds present, `.` before a fraction with no trailing zero, and `Z`; ISO 8601 governs second 60. */
const GENERALIZED_TIME: TimeSyntax = {
	pattern: /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d*[1-9])?Z$/,
	century: 0,
	leapSecond: 'unsupported',
};

function checkTime(element: DerElement, syntax: TimeSyntax): StrictDerVerdict {
	const fields = syntax.pattern
		.exec(asciiText(element.value) ?? '')
		?.slice(1)
		.map(Number);
	if (fields === undefined) {
		return 'malformed';
	}
	const [year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0] = fields;
	const monthDays =
		(DAYS_IN_MONTH[month - 1] ?? 0) + (month === 2 && isLeapYear(syntax.century + year) ? 1 : 0);
	if (day < 1 || day > monthDays || hour > 23 || minute > 59 || second > 60) {
		return 'malformed';
	}
	return second === 60 ? syntax.leapSecond : 'valid';
}

/**
 * X.690 §11.3.2: NR3 without SPACE, a MINUS SIGN only on a negative value, a
 * mantissa that neither opens nor closes with 0 followed by `.E`, and an
 * exponent written `+0` or with no leading 0 and no PLUS SIGN.
 */
const DER_NR3 = /^-?[1-9](?:\d*[1-9])?\.E(?:\+0|-?[1-9]\d*)$/;

/**
 * X.690 §8.5 and §11.3: an empty plus zero, a one-octet special value, a
 * base-2 binary form with F = 0, the fewest exponent octets and an odd
 * mantissa with no leading zero octet, or a decimal NR3 form. X.690 §8.5.7.4
 * d) leaves the length of a long-form exponent ambiguous.
 */
function checkReal(element: DerElement): StrictDerVerdict {
	const [first] = element.value;
	const rest = element.value.subarray(1);
	if (first === undefined) {
		return 'valid';
	}
	if ((first & 0x80) === 0) {
		return (first & 0x40) === 0
			? verdictOf(first === 0x03 && DER_NR3.test(asciiText(rest) ?? ''))
			: verdictOf(rest.length === 0 && first <= 0x43);
	}
	const format = first & 0x03;
	if ((first & 0x3c) !== 0) {
		return 'malformed';
	}
	if (format === 0x03) {
		return 'unsupported';
	}
	const exponent = rest.subarray(0, format + 1);
	const mantissa = rest.subarray(format + 1);
	return verdictOf(
		exponent.length === format + 1 &&
			isMinimalInteger(exponent) &&
			(mantissa[0] ?? 0) !== 0 &&
			((mantissa.at(-1) ?? 0) & 0x01) === 1,
	);
}

/**
 * The identifier octet DER uses for each universal type, mapped to the check
 * of its contents. A universal identifier missing here is a reserved tag
 * number or a form DER forbids.
 */
const UNIVERSAL_ELEMENTS: ReadonlyMap<number, UniversalElementCheck> = new Map<
	number,
	UniversalElementCheck
>([
	[0x01, (element) => decodes(() => decodeBoolean(element.value))],
	[0x02, (element) => verdictOf(isMinimalInteger(element.value))],
	[0x03, checkBitString],
	[0x04, () => 'valid'],
	[0x05, (element) => verdictOf(element.value.length === 0)],
	[0x06, (element) => verdictOf(element.value.length > 0 && isSubidentifierList(element.value))],
	[0x07, checkGraphicString],
	[0x09, checkReal],
	[0x0a, (element) => verdictOf(isMinimalInteger(element.value))],
	[
		0x0c,
		(element) => checkText(() => decodeUtf8Text(element.value, 'UTF8String'), ESCAPE_CONTROLS),
	],
	[0x0d, (element) => verdictOf(element.value.length > 0 && isSubidentifierList(element.value))],
	[0x0e, () => 'unsupported'],
	[0x12, (element) => verdictOf(isNumericStringContents(element.value))],
	[0x13, (element) => decodes(() => decodePrintableString(element.value))],
	[0x14, () => 'unsupported'],
	[0x15, () => 'unsupported'],
	[0x16, (element) => checkText(() => decodeIa5String(element.value), ESCAPE_CONTROLS)],
	[0x17, (element) => checkTime(element, UTC_TIME)],
	[0x18, (element) => checkTime(element, GENERALIZED_TIME)],
	[0x19, checkGraphicString],
	[0x1a, (element) => verdictOf(element.value.every((octet) => octet >= 0x20 && octet <= 0x7e))],
	[0x1b, checkGeneralString],
	[
		0x1c,
		(element) => checkText(() => decodeUniversalString(element.value), CODE_EXTENSION_CONTROLS),
	],
	[0x1e, (element) => checkText(() => decodeBmpString(element.value), CODE_EXTENSION_CONTROLS)],
	[0x28, () => 'unsupported'],
	[0x2b, () => 'unsupported'],
	[0x30, () => 'valid'],
	[0x31, () => 'valid'],
	[0x3d, () => 'unsupported'],
]);

function checkUniversalElement(element: DerElement): StrictDerVerdict {
	if ((element.tag & 0xc0) !== 0) {
		return 'valid';
	}
	return UNIVERSAL_ELEMENTS.get(element.tag)?.(element) ?? 'malformed';
}
