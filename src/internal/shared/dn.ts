/**
 * Distinguished name comparison utilities implementing RFC 5280 §7.1, which
 * defers string preparation to the RFC 4518 LDAP profile.
 *
 * {@linkcode prepareNameCompareString} runs the RFC 4518 Map, Normalize,
 * Prohibit, and Insignificant Space steps with RFC 3454 Appendix B.2 case
 * folding. The Prohibit step rejects code points unassigned in the running
 * Unicode version; RFC 3454 Table A.1 pins that set to Unicode 3.2.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4518 | RFC 4518}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-7.1 | RFC 5280 §7.1}
 * @module
 */

import { OIDS } from '#micro509/internal/asn1/oids';
import {
	A1_UNASSIGNED_RANGES,
	B2_CASE_FOLD,
	type CodePointRange,
	NFKC_3_2_CORRECTIONS,
} from '#micro509/internal/shared/rfc3454-tables';
import type {
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse';

// Public API

/** RFC 5280 [§7.1](https://datatracker.ietf.org/doc/html/rfc5280#section-7.1) semantic equality: same RDN count, each pair matches attribute-by-attribute. */
export function compareDistinguishedNames(left: ParsedName, right: ParsedName): boolean {
	if (left.rdns.length !== right.rdns.length) {
		return false;
	}
	for (let index = 0; index < left.rdns.length; index += 1) {
		const leftRdn = left.rdns[index];
		const rightRdn = right.rdns[index];
		if (leftRdn === undefined || rightRdn === undefined) {
			return false;
		}
		if (!compareRelativeDistinguishedNames(leftRdn, rightRdn)) {
			return false;
		}
	}
	return true;
}

/**
 * Produces a deterministic string key for a parsed DN, suitable as a Map key.
 * Semantically equal DNs (per RFC 5280 [§7.1](https://datatracker.ietf.org/doc/html/rfc5280#section-7.1)) produce identical keys.
 *
 * Format: RDNs joined by `,`, attributes within each RDN sorted by OID then by prepared value, joined by `+`.
 */
export function canonicalDnKey(name: ParsedName): string {
	return name.rdns.map(canonicalRdnKey).join(',');
}

/** True when `subject` equals or is subordinate to `constraint` (RDN prefix match). */
export function isWithinDirectoryNameSubtree(subject: ParsedName, constraint: ParsedName): boolean {
	if (constraint.rdns.length > subject.rdns.length) {
		return false;
	}
	for (let index = 0; index < constraint.rdns.length; index += 1) {
		const subjectRdn = subject.rdns[index];
		const constraintRdn = constraint.rdns[index];
		if (subjectRdn === undefined || constraintRdn === undefined) {
			return false;
		}
		if (!compareRelativeDistinguishedNames(subjectRdn, constraintRdn)) {
			return false;
		}
	}
	return true;
}

// RDN / attribute comparison

/** Order-independent RDN equality: same attribute count, each pair matched exactly once. */
export function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = Array.from({ length: right.attributes.length }, () => false);
	for (const leftAttribute of left.attributes) {
		let found = false;
		for (let index = 0; index < right.attributes.length; index += 1) {
			const rightAttribute = right.attributes[index];
			if (rightAttribute === undefined || matched[index]) {
				continue;
			}
			if (!compareNameAttributeValue(leftAttribute, rightAttribute)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/** Compares two AttributeTypeAndValue pairs using RFC 5280 [§7.1](https://datatracker.ietf.org/doc/html/rfc5280#section-7.1) string-prep for DirectoryString tags. */
export function compareNameAttributeValue(
	left: ParsedNameAttribute,
	right: ParsedNameAttribute,
): boolean {
	if (left.oid !== right.oid) {
		return false;
	}
	if (left.oid === OIDS.domainComponent) {
		// RFC 5280 §7.3 / RFC 4519 caseIgnoreIA5Match: domainComponent is
		// IA5String, prepared and compared case-insensitively with insignificant
		// spaces collapsed.
		return compareIa5AttributeValue(left, right, (leftValue, rightValue) => {
			const prepared = prepareNameCompareString(leftValue);
			return prepared !== undefined && prepared === prepareNameCompareString(rightValue);
		});
	}
	// RFC 5280 §4.1.2.6 and RFC 2985 §6.1 pkcs9CaseIgnoreMatch: emailAddress is
	// IA5String, matched character by character without regard to case and
	// without the RFC 4518 space collapsing a DirectoryString attribute gets.
	// Under any other tag the value falls through to the general comparison.
	if (
		left.oid === OIDS.emailAddress &&
		compareIa5AttributeValue(
			left,
			right,
			(leftValue, rightValue) => leftValue.toLowerCase() === rightValue.toLowerCase(),
		)
	) {
		return true;
	}
	if (isDirectoryStringTag(left.valueTag) && isDirectoryStringTag(right.valueTag)) {
		const preparedLeft = prepareNameCompareString(left.value);
		const preparedRight = prepareNameCompareString(right.value);
		if (preparedLeft === undefined || preparedRight === undefined) {
			return false;
		}
		return preparedLeft === preparedRight;
	}
	return left.valueTag === right.valueTag && left.value === right.value;
}

// Helpers

/**
 * Applies `matches` to two IA5String attribute values. A value under any other
 * tag, or a non-ASCII value, is malformed and does not match.
 */
function compareIa5AttributeValue(
	left: ParsedNameAttribute,
	right: ParsedNameAttribute,
	matches: (left: string, right: string) => boolean,
): boolean {
	if (left.valueTag !== 0x16 || right.valueTag !== 0x16) {
		return false;
	}
	if (!isAscii(left.value) || !isAscii(right.value)) {
		return false;
	}
	return matches(left.value, right.value);
}

/**
 * True for the DirectoryString encodings the parser decodes to a comparable
 * string: UTF8String (0x0C), PrintableString (0x13), UniversalString (0x1C),
 * and BMPString (0x1E). TeletexString (0x14) is rejected at parse time, so it
 * never reaches comparison.
 */
export function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13 || tag === 0x1c || tag === 0x1e;
}

/** RFC 4518 §2.2: code points deleted (Cc/Cf controls, joiners, ignorables). */
const MAP_TO_NOTHING: readonly CodePointRange[] = [
	[0x0000, 0x0008], // C0 controls NUL..BS
	[0x000e, 0x001f], // C0 controls SO..US
	[0x007f, 0x0084], // DEL, C1 controls
	[0x0086, 0x009f], // C1 controls
	[0x00ad, 0x00ad], // SOFT HYPHEN
	[0x034f, 0x034f], // COMBINING GRAPHEME JOINER
	[0x06dd, 0x06dd], // ARABIC END OF AYAH
	[0x070f, 0x070f], // SYRIAC ABBREVIATION MARK
	[0x1806, 0x1806], // MONGOLIAN TODO SOFT HYPHEN
	[0x180b, 0x180e], // variation selectors, MONGOLIAN VOWEL SEPARATOR
	[0x200b, 0x200f], // ZWSP, ZWNJ, ZWJ, LRM, RLM
	[0x202a, 0x202e], // bidi embedding/override controls
	[0x2060, 0x2063], // WORD JOINER, invisible operators
	[0x206a, 0x206f], // deprecated format controls
	[0xfe00, 0xfe0f], // variation selectors
	[0xfeff, 0xfeff], // ZERO WIDTH NO-BREAK SPACE (BOM)
	[0xfff9, 0xfffc], // interlinear annotations, OBJECT REPLACEMENT CHARACTER
	[0x1d173, 0x1d17a], // musical symbol format controls
	[0xe0001, 0xe0001], // LANGUAGE TAG
	[0xe0020, 0xe007f], // tag characters
];

/** RFC 4518 §2.2: code points mapped to SPACE (control whitespace and Zs/Zl/Zp). */
const MAP_TO_SPACE: readonly CodePointRange[] = [
	[0x0009, 0x000d], // TAB, LF, VT, FF, CR
	[0x0085, 0x0085], // NEL
	[0x00a0, 0x00a0], // NO-BREAK SPACE
	[0x1680, 0x1680], // OGHAM SPACE MARK
	[0x2000, 0x200a], // EN QUAD .. HAIR SPACE
	[0x2028, 0x2029], // LINE SEPARATOR, PARAGRAPH SEPARATOR
	[0x202f, 0x202f], // NARROW NO-BREAK SPACE
	[0x205f, 0x205f], // MEDIUM MATHEMATICAL SPACE
	[0x3000, 0x3000], // IDEOGRAPHIC SPACE
];

/** True when `codePoint` falls in one of the inclusive `ranges`. */
function inRanges(codePoint: number, ranges: readonly CodePointRange[]): boolean {
	return ranges.some(([first, last]) => codePoint >= first && codePoint <= last);
}

/** True when every code point in `value` is ASCII. */
function isAscii(value: string): boolean {
	for (const ch of value) {
		const codePoint = ch.codePointAt(0);
		if (codePoint === undefined || codePoint > 0x7f) {
			return false;
		}
	}
	return true;
}

/**
 * RFC 4518 §2.4 Prohibit against the frozen Unicode 3.2 repertoire: code points
 * unassigned in 3.2 (RFC 3454 Table A.1), private use, surrogate, non-character,
 * and the replacement character. `\p{Cn}` is avoided because it tracks the
 * running Unicode version rather than 3.2.
 */
function isProhibited(codePoint: number): boolean {
	return (
		inRanges(codePoint, A1_UNASSIGNED_RANGES) ||
		(codePoint >= 0xe000 && codePoint <= 0xf8ff) ||
		(codePoint >= 0xf0000 && codePoint <= 0xffffd) ||
		(codePoint >= 0x100000 && codePoint <= 0x10fffd) ||
		(codePoint >= 0xd800 && codePoint <= 0xdfff) ||
		(codePoint >= 0xfdd0 && codePoint <= 0xfdef) ||
		(codePoint & 0xffff) >= 0xfffe ||
		codePoint === 0xfffd
	);
}

/**
 * RFC 4518 §2.2 Map against the Unicode 3.2 repertoire: delete ignorable code
 * points, fold separators to SPACE, reject any code point prohibited in 3.2
 * before the host NFKC can reinterpret it, and freeze the CJK compatibility
 * ideographs whose NFKC decomposition Unicode 4.0 later corrected. Returns
 * `undefined` when a prohibited code point is present.
 */
function mapAndProhibitSource(value: string): string | undefined {
	let mapped = '';
	for (const ch of value) {
		const codePoint = ch.codePointAt(0);
		if (codePoint === undefined || inRanges(codePoint, MAP_TO_NOTHING)) {
			continue;
		}
		if (inRanges(codePoint, MAP_TO_SPACE)) {
			mapped += ' ';
			continue;
		}
		if (isProhibited(codePoint)) {
			return undefined;
		}
		mapped += NFKC_3_2_CORRECTIONS.get(ch) ?? ch;
	}
	return mapped;
}

/** RFC 3454 Appendix B.2 case fold, applied per code point with identity fallback. */
function caseFold(value: string): string {
	let out = '';
	for (const ch of value) {
		out += B2_CASE_FOLD.get(ch) ?? ch;
	}
	return out;
}

/**
 * RFC 4518 §2.6.1: collapses insignificant SPACE runs. A U+0020 followed by a
 * combining mark is significant (the base of a combining sequence) and stays.
 */
function collapseInsignificantSpaces(value: string): string {
	return value
		.replace(/ +(?!\p{M})/gu, ' ')
		.replace(/^ (?!\p{M})/u, '')
		.replace(/ $/u, '');
}

/**
 * Prepares a DirectoryString value for RFC 5280 §7.1 comparison through the RFC
 * 4518 Map, Normalize, Prohibit, and Insignificant Space steps against the
 * Unicode 3.2 repertoire. B.2 case folds first, the host NFKC runs once, and
 * the Prohibit set is rechecked on the output. Returns `undefined` when a
 * prohibited code point is present.
 */
export function prepareNameCompareString(value: string): string | undefined {
	const mapped = mapAndProhibitSource(value);
	if (mapped === undefined) {
		return undefined;
	}
	const normalized = caseFold(mapped).normalize('NFKC');
	for (const ch of normalized) {
		const codePoint = ch.codePointAt(0);
		if (codePoint !== undefined && isProhibited(codePoint)) {
			return undefined;
		}
	}
	return collapseInsignificantSpaces(normalized);
}

/** Canonical string for a single RDN: attributes sorted, values prepared. */
function canonicalRdnKey(rdn: ParsedRelativeDistinguishedName): string {
	return rdn.attributes
		.map((attr) => {
			const val = canonicalAttributeValue(attr);
			return `${attr.oid}=${escapeCanonicalDnValue(val)}`;
		})
		.sort()
		.join('+');
}

/** Tag-independent canonical value for one attribute, matching {@linkcode compareNameAttributeValue}. */
function canonicalAttributeValue(attr: ParsedNameAttribute): string {
	if (attr.oid === OIDS.domainComponent && attr.valueTag === 0x16 && isAscii(attr.value)) {
		return `[dc]${prepareNameCompareString(attr.value) ?? attr.value.toLowerCase()}`;
	}
	if (attr.oid === OIDS.emailAddress && attr.valueTag === 0x16 && isAscii(attr.value)) {
		return `[email]${attr.value.toLowerCase()}`;
	}
	if (isDirectoryStringTag(attr.valueTag)) {
		return prepareNameCompareString(attr.value) ?? `[raw:${attr.valueTag}]${attr.value}`;
	}
	return `[${String(attr.valueTag)}]${attr.value}`;
}

function escapeCanonicalDnValue(value: string): string {
	return value
		.replaceAll('\\', '\\\\')
		.replaceAll(',', '\\,')
		.replaceAll('+', '\\+')
		.replaceAll('=', '\\=');
}
