/**
 * Profile validation for GeneralName alternatives whose content micro509
 * checks beyond DER framing: SRVName (RFC 4985, RFC 6335), DirectoryString,
 * EDIPartyName, and ORAddress (RFC 5280).
 *
 * @module
 */

import { checkStrictDer, childrenOf, decodeString } from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import { readRootElement } from '#micro509/internal/asn1/der';
import { domainToAscii } from '#micro509/internal/shared/idna';
import { checkOrAddressFields } from '#micro509/internal/x509/or-address';

/** A SRVName's `_Service` label and Name, either possibly empty in a restriction. */
export interface SrvNameParts {
	readonly service: string;
	readonly name: string;
}

/** U+3002, U+FF0E and U+FF61, the label separators RFC 4985 §3 stores as U+002E. */
const IDEOGRAPHIC_LABEL_SEPARATORS = /[。．｡]/g;

/** Replaces each RFC 4985 §3 label separator with U+002E. */
export function normalizeLabelSeparators(value: string): string {
	return value.replace(IDEOGRAPHIC_LABEL_SEPARATORS, '.');
}

/**
 * RFC 6335 §5.1 service name behind the underscore of a `_Service` label: 1 to
 * 15 letters, digits, and hyphens, at least one letter, and no hyphen at either
 * end or beside another hyphen.
 */
function isServiceLabel(label: string): boolean {
	const name = label.slice(1);
	return (
		label.startsWith('_') &&
		/^[A-Za-z0-9-]{1,15}$/.test(name) &&
		/[A-Za-z]/.test(name) &&
		!name.startsWith('-') &&
		!name.endsWith('-') &&
		!name.includes('--')
	);
}

/**
 * RFC 4985 §3 Name under `UseSTD3ASCIIRules`: at most 253 octets of LDH labels
 * of 1 to 63 octets that start and end with a letter or digit, with every
 * `xn--` label an IDNA2008 A-label.
 */
function isSrvDomainName(name: string): boolean {
	return (
		name.length <= 253 &&
		name
			.split('.')
			.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)) &&
		domainToAscii(name, 'lookup').ok
	);
}

function splitSrvName(value: string): SrvNameParts {
	if (!value.startsWith('_')) {
		return { service: '', name: value };
	}
	const dot = value.indexOf('.');
	return dot < 0
		? { service: value, name: '' }
		: { service: value.slice(0, dot), name: value.slice(dot + 1) };
}

/** RFC 4985 §4: a restriction is `_Service.Name`, `_Service`, or `Name`. */
export function parseSrvNameRestriction(value: string): SrvNameParts | undefined {
	const parts = splitSrvName(value);
	const serviceOk = parts.service.length === 0 || isServiceLabel(parts.service);
	const nameOk = (parts.service.length > 0 && !value.includes('.')) || isSrvDomainName(parts.name);
	return serviceOk && nameOk ? parts : undefined;
}

/** RFC 4985 §2: a presented SRVName is `_Service.Name`. */
export function parsePresentedSrvName(value: string): SrvNameParts | undefined {
	const parts = splitSrvName(value);
	return isServiceLabel(parts.service) && isSrvDomainName(parts.name) ? parts : undefined;
}

/** Why a structured GeneralName value failed its profile. */
export type GeneralNameContentFailure = 'malformed' | 'unsupported';

export type GeneralNameContentCheck =
	| { readonly ok: true }
	| { readonly ok: false; readonly reason: GeneralNameContentFailure };

const VALID: GeneralNameContentCheck = { ok: true };
const MALFORMED: GeneralNameContentCheck = { ok: false, reason: 'malformed' };
const UNSUPPORTED: GeneralNameContentCheck = { ok: false, reason: 'unsupported' };

const TELETEX_STRING = 0x14;

/** DirectoryString alternatives other than TeletexString: PrintableString, UniversalString, UTF8String, BMPString. */
const DECODABLE_DIRECTORY_STRING_TAGS: ReadonlySet<number> = new Set([0x13, 0x1c, 0x0c, 0x1e]);

/**
 * RFC 5280 DirectoryString, each alternative `SIZE (1..MAX)`. TeletexString has
 * no repertoire micro509 validates, so it is unsupported rather than accepted
 * unchecked.
 */
export function checkDirectoryString(element: DerElement): GeneralNameContentCheck {
	if (element.tag === TELETEX_STRING) {
		return UNSUPPORTED;
	}
	if (!DECODABLE_DIRECTORY_STRING_TAGS.has(element.tag) || element.value.length === 0) {
		return MALFORMED;
	}
	try {
		decodeString(element.tag, element.value);
		return VALID;
	} catch {
		return MALFORMED;
	}
}

/**
 * RFC 5280 §4.2.1.6: `EDIPartyName ::= SEQUENCE { nameAssigner [0]
 * DirectoryString OPTIONAL, partyName [1] DirectoryString }`, each tag
 * explicit around its CHOICE.
 */
export function checkEdiPartyName(element: Uint8Array): GeneralNameContentCheck {
	return checkStructuredGeneralName(element, (children, source) => {
		const partyName = children.at(-1);
		if (
			partyName?.tag !== 0xa1 ||
			!(children.length === 1 || (children.length === 2 && children[0]?.tag === 0xa0))
		) {
			return MALFORMED;
		}
		return firstFailure(
			children.map((child) => {
				const inner = childrenOf(source, child);
				const directoryString = inner[0];
				return inner.length === 1 && directoryString !== undefined
					? checkDirectoryString(directoryString)
					: MALFORMED;
			}),
		);
	});
}

/** RFC 5280 Appendix A.1 ORAddress, with its fields checked against their schema. */
export function checkOrAddress(element: Uint8Array): GeneralNameContentCheck {
	return checkStructuredGeneralName(element, checkOrAddressFields);
}

function checkStructuredGeneralName(
	element: Uint8Array,
	check: (children: readonly DerElement[], source: Uint8Array) => GeneralNameContentCheck,
): GeneralNameContentCheck {
	const encoding = checkStrictDer(element);
	if (encoding === 'malformed') {
		return MALFORMED;
	}
	try {
		const profile = check(childrenOf(element, readRootElement(element)), element);
		return profile.ok && encoding === 'unsupported' ? UNSUPPORTED : profile;
	} catch {
		return MALFORMED;
	}
}

function firstFailure(checks: readonly GeneralNameContentCheck[]): GeneralNameContentCheck {
	return checks.find((check) => !check.ok) ?? VALID;
}
