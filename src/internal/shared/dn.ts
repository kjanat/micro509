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
		return left.value.toLowerCase() === right.value.toLowerCase();
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

/** True for UTF8String (0x0C) and PrintableString (0x13), the DirectoryString tags prepared for comparison. */
export function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/** Inclusive `[first, last]` code-point ranges. */
type CodePointRange = readonly [number, number];

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

/**
 * RFC 4518 §2.4 Prohibit: unassigned (`\p{Cn}`, which also covers
 * non-characters), private use (`\p{Co}`), surrogate (`\p{Cs}`), the
 * replacement character U+FFFD. The deprecated tone marks U+0340/U+0341 that
 * \u00a72.4 also prohibits are decomposed away by the preceding NFKC step.
 */
const PROHIBITED = /[\p{Cn}\p{Co}\p{Cs}\ufffd]/u;

/**
 * RFC 3454 Appendix B.2 case-fold entries whose result differs from a plain
 * lowercase, keyed by the source code point. Every other character folds through
 * {@linkcode String.prototype.toLowerCase}. Trailing comments render `source -> result`.
 */
const B2_FOLD = new Map<string, string>([
	['\u00df', 'ss'], // ß -> ss
	['\u0149', '\u02bcn'], // ŉ -> ʼn
	['\u01f0', 'j\u030c'], // ǰ -> ǰ
	['\u0345', '\u03b9'], // ͅ -> ι
	['\u0390', '\u03b9\u0308\u0301'], // ΐ -> ΐ
	['\u03b0', '\u03c5\u0308\u0301'], // ΰ -> ΰ
	['\u03c2', '\u03c3'], // ς -> σ
	['\u03d0', '\u03b2'], // ϐ -> β
	['\u03d1', '\u03b8'], // ϑ -> θ
	['\u03d5', '\u03c6'], // ϕ -> φ
	['\u03d6', '\u03c0'], // ϖ -> π
	['\u03f0', '\u03ba'], // ϰ -> κ
	['\u03f1', '\u03c1'], // ϱ -> ρ
	['\u0587', '\u0565\u0582'], // և -> եւ
	['\u1e96', 'h\u0331'], // ẖ -> ẖ
	['\u1e97', 't\u0308'], // ẗ -> ẗ
	['\u1e98', 'w\u030a'], // ẘ -> ẘ
	['\u1e99', 'y\u030a'], // ẙ -> ẙ
	['\u1e9a', 'a\u02be'], // ẚ -> aʾ
	['\u1f50', '\u03c5\u0313'], // ὐ -> ὐ
	['\u1f52', '\u03c5\u0313\u0300'], // ὒ -> ὒ
	['\u1f54', '\u03c5\u0313\u0301'], // ὔ -> ὔ
	['\u1f56', '\u03c5\u0313\u0342'], // ὖ -> ὖ
	['\u1fbe', '\u03b9'], // ι -> ι
	['\ufb00', 'ff'], // ﬀ -> ff
	['\ufb01', 'fi'], // ﬁ -> fi
	['\ufb02', 'fl'], // ﬂ -> fl
	['\ufb03', 'ffi'], // ﬃ -> ffi
	['\ufb04', 'ffl'], // ﬄ -> ffl
	['\ufb05', 'st'], // ﬅ -> st
	['\ufb06', 'st'], // ﬆ -> st
	['\ufb13', '\u0574\u0576'], // ﬓ -> մն
	['\ufb14', '\u0574\u0565'], // ﬔ -> մե
	['\ufb15', '\u0574\u056b'], // ﬕ -> մի
	['\ufb16', '\u057e\u0576'], // ﬖ -> վն
	['\ufb17', '\u0574\u056d'], // ﬗ -> մխ
]);

/**
 * RFC 4518 §2.2 Map plus B.2 case fold: delete ignorable code points and fold
 * separators to SPACE, then lowercase, then apply the B.2 table. Lowercasing
 * before the table matters because {@linkcode String.prototype.toLowerCase}
 * emits a final sigma (U+03C2) that B.2 folds to U+03C3.
 */
function mapAndFold(value: string): string {
	let mapped = '';
	for (const ch of value) {
		const codePoint = ch.codePointAt(0);
		if (codePoint === undefined || inRanges(codePoint, MAP_TO_NOTHING)) {
			continue;
		}
		mapped += inRanges(codePoint, MAP_TO_SPACE) ? ' ' : ch;
	}
	let out = '';
	for (const ch of mapped.toLowerCase()) {
		out += B2_FOLD.get(ch) ?? ch;
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
 * 4518 Map, Normalize, Prohibit, and Insignificant Space steps. Returns
 * `undefined` when the Prohibit step rejects the value.
 */
export function prepareNameCompareString(value: string): string | undefined {
	const normalized = mapAndFold(value).normalize('NFKC');
	if (PROHIBITED.test(normalized)) {
		return undefined;
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
	if (attr.oid === OIDS.domainComponent) {
		return `[dc]${attr.value.toLowerCase()}`;
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
