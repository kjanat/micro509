/**
 * IDNA2008 (RFC 5890, RFC 5891, RFC 5892, RFC 5893) over the frozen Unicode
 * 12.0.0 tables in `idna-tables.ts`.
 *
 * `'registration'` applies the RFC 5891 §4 tests a certificate issuer owes a
 * label it places in a certificate. `'lookup'` applies the RFC 5891 §5 tests an
 * application owes a reference identifier before comparing it.
 *
 * @module
 */

import {
	BIDI_AL_RANGES,
	BIDI_AN_RANGES,
	BIDI_BN_RANGES,
	BIDI_CS_RANGES,
	BIDI_EN_RANGES,
	BIDI_ES_RANGES,
	BIDI_ET_RANGES,
	BIDI_L_RANGES,
	BIDI_NSM_RANGES,
	BIDI_ON_RANGES,
	BIDI_R_RANGES,
	CONTEXTJ_RANGES,
	CONTEXTO_RANGES,
	JOINING_D_RANGES,
	JOINING_L_RANGES,
	JOINING_R_RANGES,
	JOINING_T_RANGES,
	MARK_RANGES,
	PVALID_RANGES,
	SCRIPT_GREEK_RANGES,
	SCRIPT_HAN_RANGES,
	SCRIPT_HEBREW_RANGES,
	SCRIPT_HIRAGANA_RANGES,
	SCRIPT_KATAKANA_RANGES,
	VIRAMA_RANGES,
} from '#micro509/internal/shared/idna-tables';
import { punycodeDecode, punycodeEncode } from '#micro509/internal/shared/punycode';

/** Which set of RFC 5891 tests to apply: §4 registration or §5 lookup. */
export type IdnaMode = 'registration' | 'lookup';

/** Why a label or domain name is not valid IDNA2008. */
export type IdnaFailure =
	| 'empty_label'
	| 'label_too_long'
	| 'domain_too_long'
	| 'invalid_a_label'
	| 'not_nfc'
	| 'hyphen'
	| 'leading_combining_mark'
	| 'disallowed_code_point'
	| 'context_rule'
	| 'bidi_rule';

/** A converted domain name, or the first reason it is not valid IDNA2008. */
export type IdnaResult =
	| { readonly ok: true; readonly value: string }
	| { readonly ok: false; readonly reason: IdnaFailure };

type BidiClass =
	| 'L'
	| 'R'
	| 'AL'
	| 'AN'
	| 'EN'
	| 'ES'
	| 'CS'
	| 'ET'
	| 'ON'
	| 'BN'
	| 'NSM'
	| 'other';

const BIDI_TABLES: readonly (readonly [Exclude<BidiClass, 'other'>, readonly number[]])[] = [
	['L', BIDI_L_RANGES],
	['R', BIDI_R_RANGES],
	['AL', BIDI_AL_RANGES],
	['AN', BIDI_AN_RANGES],
	['EN', BIDI_EN_RANGES],
	['ES', BIDI_ES_RANGES],
	['CS', BIDI_CS_RANGES],
	['ET', BIDI_ET_RANGES],
	['ON', BIDI_ON_RANGES],
	['BN', BIDI_BN_RANGES],
	['NSM', BIDI_NSM_RANGES],
];

type JoiningType = 'D' | 'L' | 'R' | 'T' | 'U';

const ACE_PREFIX = 'xn--';
const MAX_LABEL_OCTETS = 63;
const MAX_DOMAIN_OCTETS = 253;

/** Whether `codePoint` falls in a flat `[first, last, first, last, …]` range list. */
export function inRanges(ranges: readonly number[], codePoint: number): boolean {
	let low = 0;
	let high = ranges.length / 2 - 1;
	while (low <= high) {
		const middle = (low + high) >> 1;
		const first = ranges[middle * 2] ?? 0;
		const last = ranges[middle * 2 + 1] ?? 0;
		if (codePoint < first) high = middle - 1;
		else if (codePoint > last) low = middle + 1;
		else return true;
	}
	return false;
}

function bidiClass(codePoint: number): BidiClass {
	return BIDI_TABLES.find(([, ranges]) => inRanges(ranges, codePoint))?.[0] ?? 'other';
}

function joiningType(codePoint: number): JoiningType {
	if (inRanges(JOINING_D_RANGES, codePoint)) return 'D';
	if (inRanges(JOINING_L_RANGES, codePoint)) return 'L';
	if (inRanges(JOINING_R_RANGES, codePoint)) return 'R';
	if (inRanges(JOINING_T_RANGES, codePoint)) return 'T';
	return 'U';
}

function codePointsOf(label: string): number[] {
	return Array.from(label, (character) => character.codePointAt(0) ?? 0);
}

function isAscii(value: string): boolean {
	return codePointsOf(value).every((codePoint) => codePoint < 0x80);
}

function asciiLowercase(value: string): string {
	return value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}

/**
 * RFC 5892 Appendix A as updated by RFC 8753 §6: the rule of the contextual
 * code point at `index`, evaluated for that one occurrence.
 */
function contextRuleHolds(codePoints: readonly number[], index: number): boolean {
	const codePoint = codePoints[index] ?? 0;
	const before = codePoints[index - 1];
	const after = codePoints[index + 1];
	switch (codePoint) {
		case 0x200c:
			return (
				(before !== undefined && inRanges(VIRAMA_RANGES, before)) ||
				zeroWidthNonJoinerJoins(codePoints, index)
			);
		case 0x200d:
			return before !== undefined && inRanges(VIRAMA_RANGES, before);
		case 0x00b7:
			return before === 0x6c && after === 0x6c;
		case 0x0375:
			return after !== undefined && inRanges(SCRIPT_GREEK_RANGES, after);
		case 0x05f3:
		case 0x05f4:
			return before !== undefined && inRanges(SCRIPT_HEBREW_RANGES, before);
		case 0x30fb:
			return codePoints.some(
				(other) =>
					inRanges(SCRIPT_HIRAGANA_RANGES, other) ||
					inRanges(SCRIPT_KATAKANA_RANGES, other) ||
					inRanges(SCRIPT_HAN_RANGES, other),
			);
		default:
			if (codePoint >= 0x0660 && codePoint <= 0x0669) {
				return !codePoints.some((other) => other >= 0x06f0 && other <= 0x06f9);
			}
			if (codePoint >= 0x06f0 && codePoint <= 0x06f9) {
				return !codePoints.some((other) => other >= 0x0660 && other <= 0x0669);
			}
			return false;
	}
}

/** RFC 8753 §6 rule C1 regular expression: (L|D) T* ZWNJ T* (R|D). */
function zeroWidthNonJoinerJoins(codePoints: readonly number[], index: number): boolean {
	let left = index - 1;
	while (left >= 0 && joiningType(codePoints[left] ?? 0) === 'T') left -= 1;
	let right = index + 1;
	while (right < codePoints.length && joiningType(codePoints[right] ?? 0) === 'T') right += 1;
	const leftType = left >= 0 ? joiningType(codePoints[left] ?? 0) : 'U';
	const rightType = right < codePoints.length ? joiningType(codePoints[right] ?? 0) : 'U';
	return (leftType === 'L' || leftType === 'D') && (rightType === 'R' || rightType === 'D');
}

/**
 * RFC 5891 §4.2 (registration) or §5.4 (lookup) tests on a U-label. Bidi is
 * checked per domain name by {@linkcode checkBidiDomain}.
 */
export function checkULabel(label: string, mode: IdnaMode): IdnaFailure | undefined {
	if (label.length === 0) return 'empty_label';
	if (label.normalize('NFC') !== label) return 'not_nfc';
	const codePoints = codePointsOf(label);
	if (codePoints[2] === 0x2d && codePoints[3] === 0x2d) return 'hyphen';
	if (mode === 'registration' && (codePoints[0] === 0x2d || codePoints.at(-1) === 0x2d)) {
		return 'hyphen';
	}
	if (inRanges(MARK_RANGES, codePoints[0] ?? 0)) return 'leading_combining_mark';
	for (let index = 0; index < codePoints.length; index += 1) {
		const codePoint = codePoints[index] ?? 0;
		if (inRanges(PVALID_RANGES, codePoint)) continue;
		if (!inRanges(CONTEXTJ_RANGES, codePoint) && !inRanges(CONTEXTO_RANGES, codePoint)) {
			return 'disallowed_code_point';
		}
		if (!contextRuleHolds(codePoints, index)) return 'context_rule';
	}
	return undefined;
}

/** RFC 5893 §1.4: a label with an R, AL or AN character is an RTL label. */
function isRtlLabel(label: string): boolean {
	return codePointsOf(label).some((codePoint) => {
		const found = bidiClass(codePoint);
		return found === 'R' || found === 'AL' || found === 'AN';
	});
}

/** RFC 5893 §2: the six conditions, for one label of a Bidi domain name. */
function satisfiesBidiRule(label: string): boolean {
	const classes = codePointsOf(label).map(bidiClass);
	const first = classes[0];
	if (first !== 'L' && first !== 'R' && first !== 'AL') return false;
	let end = classes.length - 1;
	while (end >= 0 && classes[end] === 'NSM') end -= 1;
	const last = classes[end];
	if (first === 'L') {
		const allowed = new Set<BidiClass>(['L', 'EN', 'ES', 'CS', 'ET', 'ON', 'BN', 'NSM']);
		return classes.every((found) => allowed.has(found)) && (last === 'L' || last === 'EN');
	}
	const allowed = new Set<BidiClass>(['R', 'AL', 'AN', 'EN', 'ES', 'CS', 'ET', 'ON', 'BN', 'NSM']);
	return (
		classes.every((found) => allowed.has(found)) &&
		(last === 'R' || last === 'AL' || last === 'EN' || last === 'AN') &&
		!(classes.includes('EN') && classes.includes('AN'))
	);
}

/**
 * RFC 5893 §2 applies to every label of a Bidi domain name, one with at least
 * one RTL label, ASCII labels included.
 */
export function checkBidiDomain(uLabels: readonly string[]): IdnaFailure | undefined {
	if (!uLabels.some(isRtlLabel)) return undefined;
	return uLabels.every(satisfiesBidiRule) ? undefined : 'bidi_rule';
}

/** The A-label for a U-label: `xn--` and its RFC 3492 Punycode. */
export function toALabel(uLabel: string): string {
	return `${ACE_PREFIX}${punycodeEncode(uLabel)}`;
}

/**
 * RFC 5891 §4.2.1 / §5.3: an `xn--` label is an A-label only when it decodes to
 * a valid U-label that encodes back to the same A-label. Registration requires
 * it in lowercase; lookup lowercases it first. Returns the U-label.
 */
export function checkALabel(
	label: string,
	mode: IdnaMode,
):
	| { readonly ok: true; readonly uLabel: string }
	| { readonly ok: false; readonly reason: IdnaFailure } {
	const lower = asciiLowercase(label);
	if ((mode === 'registration' && lower !== label) || !lower.startsWith(ACE_PREFIX)) {
		return { ok: false, reason: 'invalid_a_label' };
	}
	if (lower.length > MAX_LABEL_OCTETS || !isLdhLabel(lower)) {
		return { ok: false, reason: 'invalid_a_label' };
	}
	let uLabel: string;
	try {
		uLabel = punycodeDecode(lower.slice(ACE_PREFIX.length));
	} catch {
		return { ok: false, reason: 'invalid_a_label' };
	}
	if (isAscii(uLabel) || checkULabel(uLabel, mode) !== undefined || toALabel(uLabel) !== lower) {
		return { ok: false, reason: 'invalid_a_label' };
	}
	return { ok: true, uLabel };
}

function isLdhLabel(label: string): boolean {
	return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label);
}

function isIdnLabel(label: string): boolean {
	return !isAscii(label) || asciiLowercase(label).startsWith(ACE_PREFIX);
}

/** The A-label of a U-label that passes {@linkcode checkULabel} and fits 63 octets. */
function uLabelToALabel(label: string, mode: IdnaMode): IdnaResult {
	if (codePointsOf(label).length > MAX_LABEL_OCTETS - ACE_PREFIX.length) {
		return { ok: false, reason: 'label_too_long' };
	}
	const failure = checkULabel(label, mode);
	if (failure !== undefined) return { ok: false, reason: failure };
	const aLabel = toALabel(label);
	return aLabel.length > MAX_LABEL_OCTETS
		? { ok: false, reason: 'label_too_long' }
		: { ok: true, value: aLabel };
}

/**
 * Converts each U-label of `domain` to its A-label and checks each `xn--`
 * label, under the RFC 5891 §4 (registration) or §5 (lookup) tests, then
 * applies the RFC 5893 Bidi rule across the name. Other ASCII labels are
 * returned as given.
 */
export function domainToAscii(domain: string, mode: IdnaMode): IdnaResult {
	const labels = domain.split('.');
	if (!labels.some(isIdnLabel)) return { ok: true, value: domain };
	const ascii: string[] = [];
	const uLabels: string[] = [];
	for (const label of labels) {
		if (!isAscii(label)) {
			const converted = uLabelToALabel(label, mode);
			if (!converted.ok) return converted;
			ascii.push(converted.value);
			uLabels.push(label);
		} else if (isIdnLabel(label)) {
			const checked = checkALabel(label, mode);
			if (!checked.ok) return checked;
			ascii.push(asciiLowercase(label));
			uLabels.push(checked.uLabel);
		} else {
			ascii.push(label);
			uLabels.push(label);
		}
	}
	const bidi = checkBidiDomain(uLabels);
	if (bidi !== undefined) return { ok: false, reason: bidi };
	const value = ascii.join('.');
	return value.length > MAX_DOMAIN_OCTETS
		? { ok: false, reason: 'domain_too_long' }
		: { ok: true, value };
}

/**
 * RFC 5895 §2 mapping of a user-supplied name: lowercase, fullwidth and
 * halfwidth forms to their standard characters, the ideographic full stops to
 * ".", and NFC.
 */
function mapForLookup(domain: string): string {
	return Array.from(domain.toLowerCase(), (character) => {
		const codePoint = character.codePointAt(0) ?? 0;
		if (codePoint === 0x3002 || codePoint === 0xff0e || codePoint === 0xff61) return '.';
		return codePoint >= 0xff01 && codePoint <= 0xffef ? character.normalize('NFKC') : character;
	})
		.join('')
		.normalize('NFC');
}

/**
 * RFC 9525 §6.3 A-label form of a reference identifier's domain name, after
 * RFC 5895 mapping and the RFC 5891 §5 lookup tests. Every ASCII label must be
 * 1 to 63 letters, digits, hyphens or underscores. Returns `undefined` when the
 * name fails either test.
 */
export function referenceDomainToAscii(domain: string): string | undefined {
	const mapped = mapForLookup(domain);
	const asciiLabelsValid = mapped
		.split('.')
		.every((label) => !isAscii(label) || /^[a-z0-9_-]{1,63}$/.test(label));
	if (!asciiLabelsValid) return undefined;
	const converted = domainToAscii(mapped, 'lookup');
	return converted.ok ? converted.value : undefined;
}
