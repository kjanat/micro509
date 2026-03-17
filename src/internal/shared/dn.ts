/**
 * RFC 5280 §7.1 distinguished name comparison utilities.
 *
 * Provides semantic DN equality (case-folding, NFKC normalization,
 * whitespace collapse) and a canonical string key for O(1) Map lookups.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-7.1 | RFC 5280 §7.1}.  Internationalized Names in Distinguished Names
 * @module
 */

import type {
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse.ts';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** RFC 5280 §7.1 semantic equality: same RDN count, each pair matches attribute-by-attribute. */
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
 * Semantically equal DNs (per RFC 5280 §7.1) produce identical keys.
 *
 * Format: RDNs joined by `,`, attributes within each RDN sorted by OID then
 * by prepared value, joined by `+`.
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

// ---------------------------------------------------------------------------
// RDN / attribute comparison
// ---------------------------------------------------------------------------

/** Order-independent RDN equality: same attribute count, each pair matched exactly once. */
export function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = new Array<boolean>(right.attributes.length).fill(false);
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

/** Compares two AttributeTypeAndValue pairs using RFC 5280 §7.1 string-prep for DirectoryString tags. */
export function compareNameAttributeValue(
	left: ParsedNameAttribute,
	right: ParsedNameAttribute,
): boolean {
	if (left.oid !== right.oid) {
		return false;
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** True for UTF8String (0x0C) and PrintableString (0x13) — the DirectoryString types we normalize. */
export function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/** NFKC-normalizes, lowercases, trims, and collapses whitespace for RFC 5280 §7.1 comparison. */
export function prepareNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

/** Canonical string for a single RDN: attributes sorted, values prepared. */
function canonicalRdnKey(rdn: ParsedRelativeDistinguishedName): string {
	return rdn.attributes
		.map((attr) => {
			const val = isDirectoryStringTag(attr.valueTag)
				? (prepareNameCompareString(attr.value) ?? `[raw:${attr.valueTag}]${attr.value}`)
				: `[${String(attr.valueTag)}]${attr.value}`;
			return `${attr.oid}=${escapeCanonicalDnValue(val)}`;
		})
		.sort()
		.join('+');
}

function escapeCanonicalDnValue(value: string): string {
	return value
		.replaceAll('\\', '\\\\')
		.replaceAll(',', '\\,')
		.replaceAll('+', '\\+')
		.replaceAll('=', '\\=');
}
