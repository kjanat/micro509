/**
 * Internal name-constraints evaluation engine.
 *
 * Accumulates and evaluates the shipped RFC 5280 §4.2.1.10 / §6.1
 * name-constraint subset during certificate path validation.
 *
 * @module
 */

import type {
	NameConstraintForm,
	NameConstraints,
	ParsedNameConstraintForm,
	SubjectAltName,
} from '../../x509/extensions.ts';
import { nameFieldKeyFromOid } from '../../x509/name.ts';
import type { InitialNameConstraintsInput } from '../../verify/name-constraints.ts';
import type {
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '../../x509/parse.ts';
import type { Micro509Error } from '../../result/result.ts';
import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	hexToBytes,
	requireElement,
	toHex,
} from '../asn1/asn1.ts';
import { DEFAULT_MAX_DER_DEPTH, type DerElement, readRootElement } from '../asn1/der.ts';
import { OIDS } from '../asn1/oids.ts';
import { allOnesMaskForIpAddress, decodeIpAddress, parseIpAddressToBytes } from '../shared/ip.ts';

/**
 * Opaque state seeded from {@linkcode InitialNameConstraintsInput} and consumed
 * by {@linkcode evaluateNameConstraints}.
 */
export interface NameConstraintValidationState {
	/** Caller-supplied permitted subtree bases (pre-chain). */
	readonly initialPermittedSubtrees: readonly NameConstraintForm[];
	/** Caller-supplied excluded subtree bases (pre-chain). */
	readonly initialExcludedSubtrees: readonly NameConstraintForm[];
}

/** Discriminant codes for name-constraint validation failures. */
export type NameConstraintValidationFailureCode =
	| 'name_constraints_violated'
	| 'unsupported_name_constraints';

/** Diagnostic context attached to a name-constraint validation failure. */
export interface NameConstraintValidationFailureDetails {
	/** CN of the certificate whose name violated constraints, if available. */
	readonly subjectCommonName?: string;
	/** The name or constraint-type string that caused the violation. */
	readonly actual?: string;
}

/** A name-constraint check that failed, with the offending certificate's chain index. */
export interface NameConstraintValidationFailure
	extends Micro509Error<
		NameConstraintValidationFailureCode,
		NameConstraintValidationFailureDetails
	> {
	/** Always `false` for failures. */
	readonly ok: false;
	/** Zero-based index into the chain of the certificate that violated constraints. */
	readonly index: number;
}

/** Success or failure outcome of name-constraint evaluation across a chain. */
export type NameConstraintValidationResult =
	| {
			/** All names in the chain satisfy accumulated constraints. */
			readonly ok: true;
	  }
	| NameConstraintValidationFailure;

/** Builder input for assembling optional failure detail fields. */
interface NameConstraintValidationFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly actual?: string | undefined;
}

/** Constructs a {@linkcode NameConstraintValidationFailure} with optional details. */
function nameConstraintFailure(
	code: NameConstraintValidationFailureCode,
	message: string,
	index: number,
	details?: NameConstraintValidationFailureDetails,
): NameConstraintValidationFailure {
	return {
		ok: false,
		code,
		message,
		index,
		...(details === undefined ? {} : { details }),
	};
}

/** Strips undefined fields and returns `undefined` when all fields are empty. */
function nameConstraintDetails(
	input: NameConstraintValidationFailureDetailsInput,
): NameConstraintValidationFailureDetails | undefined {
	const details: NameConstraintValidationFailureDetails = {
		...(input.subjectCommonName === undefined
			? {}
			: { subjectCommonName: input.subjectCommonName }),
		...(input.actual === undefined ? {} : { actual: input.actual }),
	};
	return Object.keys(details).length === 0 ? undefined : details;
}

/** A certificate is self-issued when subject and issuer DER match exactly. */
function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

/**
 * Initializes validation state from caller-supplied initial constraints.
 *
 * Call once before {@linkcode evaluateNameConstraints}.
 */
export function createNameConstraintValidationState(
	input: InitialNameConstraintsInput,
): NameConstraintValidationState {
	return {
		initialPermittedSubtrees: input.permittedSubtrees?.map((subtree) => subtree.base) ?? [],
		initialExcludedSubtrees: input.excludedSubtrees?.map((subtree) => subtree.base) ?? [],
	};
}

// ---------------------------------------------------------------------------
// Private: name constraint validation (RFC 5280 §4.2.1.10 / §6.1)
// ---------------------------------------------------------------------------

/** Empty SEQUENCE DER hex — represents an empty subject DN. */
const EMPTY_SEQUENCE_HEX = '3000';

/**
 * Accumulated name constraint state during root-to-leaf traversal.
 * - `permittedLevels`: each entry is one CA's permittedSubtrees. A name
 *   must match at least one entry in *every* level (intersection semantics).
 * - `excluded`: flat list; a name must NOT match *any* entry.
 */
interface AccumulatedNameConstraints {
	/** One entry per CA that asserted permittedSubtrees; intersection semantics. */
	readonly permittedLevels: readonly (readonly NameConstraintForm[])[];
	/** Flat union of all excludedSubtrees seen so far. */
	readonly excluded: readonly NameConstraintForm[];
}

/**
 * Walks the chain root-to-leaf, accumulating namEConstraints from CA
 * certificates and checking each non-self-issued certificate's names
 * against the accumulated constraints.
 *
 * RFC 5280 §6.1.3(b)–(c) for intermediates, §6.1.5(g) for the leaf.
 */

export function evaluateNameConstraints(
	chain: readonly ParsedCertificate[],
	state: NameConstraintValidationState,
): NameConstraintValidationResult {
	let accumulated = seedInitialNameConstraints(state);

	// Seed constraints from the root (trust anchor). The root's own
	// names are not checked, but its namEConstraints apply to all
	// certificates below it in the chain.
	const root = chain[chain.length - 1];
	if (root?.nameConstraints !== undefined) {
		const unsupportedRoot = failOnUnsupportedNameConstraints(root, chain.length - 1);
		if (!unsupportedRoot.ok) {
			return unsupportedRoot;
		}
		accumulated = accumulateConstraints(accumulated, root.nameConstraints);
	}

	// Walk from just below root toward leaf.
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const current = chain[index];
		if (current === undefined) {
			continue;
		}

		// (b) If not self-issued, check names against accumulated constraints.
		// RFC 5280 §4.2.1.10: self-issued certificates are exempt UNLESS
		// they are the final certificate (leaf) in the path.
		if (!isSelfIssued(current) || index === 0) {
			const nameCheckResult = checkCertificateNames(current, accumulated, index);
			if (!nameCheckResult.ok) {
				return nameCheckResult;
			}
		}

		// (c) If this cert has namEConstraints, accumulate them.
		if (current.nameConstraints !== undefined) {
			const unsupportedCurrent = failOnUnsupportedNameConstraints(current, index);
			if (!unsupportedCurrent.ok) {
				return unsupportedCurrent;
			}
			accumulated = accumulateConstraints(accumulated, current.nameConstraints);
		}
	}

	return { ok: true };
}

/** Converts initial state into the starting accumulated-constraints snapshot. */
function seedInitialNameConstraints(
	state: NameConstraintValidationState,
): AccumulatedNameConstraints {
	return {
		permittedLevels:
			state.initialPermittedSubtrees.length > 0 ? [state.initialPermittedSubtrees] : [],
		excluded: state.initialExcludedSubtrees,
	};
}

/** Merges one certificate's nameConstraints extension into the running totals. */
function accumulateConstraints(
	current: AccumulatedNameConstraints,
	constraints: NameConstraints<ParsedNameConstraintForm>,
): AccumulatedNameConstraints {
	const permittedLevels =
		constraints.permittedSubtrees !== undefined && constraints.permittedSubtrees.length > 0
			? [
					...current.permittedLevels,
					constraints.permittedSubtrees.flatMap((subtree) =>
						isSupportedNameConstraintForm(subtree.base) ? [subtree.base] : [],
					),
				]
			: current.permittedLevels;
	const excluded =
		constraints.excludedSubtrees !== undefined && constraints.excludedSubtrees.length > 0
			? [
					...current.excluded,
					...constraints.excludedSubtrees.flatMap((subtree) =>
						isSupportedNameConstraintForm(subtree.base) ? [subtree.base] : [],
					),
				]
			: current.excluded;
	return { permittedLevels, excluded };
}

/** Rejects the chain if a critical nameConstraints extension uses unsupported name forms. */
function failOnUnsupportedNameConstraints(
	certificate: ParsedCertificate,
	index: number,
): NameConstraintValidationResult {
	if (certificate.nameConstraints === undefined) {
		return { ok: true };
	}
	const hasCriticalNameConstraintsExtension = certificate.extensions.some(
		(entry) => entry.oid === OIDS.nameConstraints && entry.critical,
	);
	if (!hasCriticalNameConstraintsExtension) {
		return { ok: true };
	}
	const unsupportedTypes = listUnsupportedNameConstraintTypes(certificate.nameConstraints);
	if (unsupportedTypes.length === 0) {
		return { ok: true };
	}
	return nameConstraintFailure(
		'unsupported_name_constraints',
		'certificate contains unsupported critical name constraints',
		index,
		nameConstraintDetails({
			subjectCommonName: certificate.subject.values.commonName,
			actual: unsupportedTypes.join(', '),
		}),
	);
}

/** Collects the distinct unsupported GeneralName type strings from a nameConstraints extension. */
function listUnsupportedNameConstraintTypes(
	constraints: NameConstraints<ParsedNameConstraintForm>,
): readonly string[] {
	const unsupportedTypes = new Set<string>();
	for (const subtree of constraints.permittedSubtrees ?? []) {
		if (!isSupportedNameConstraintForm(subtree.base)) {
			unsupportedTypes.add(subtree.base.type);
		}
	}
	for (const subtree of constraints.excludedSubtrees ?? []) {
		if (!isSupportedNameConstraintForm(subtree.base)) {
			unsupportedTypes.add(subtree.base.type);
		}
	}
	return [...unsupportedTypes];
}

/** True for name forms this engine can evaluate: dns, email, uri, ip, directoryName. */
function isSupportedNameConstraintForm(form: ParsedNameConstraintForm): form is NameConstraintForm {
	switch (form.type) {
		case 'dns':
		case 'email':
		case 'uri':
		case 'ip':
		case 'directoryName':
			return true;
		case 'otherName':
		case 'x400Address':
		case 'ediPartyName':
		case 'registeredID':
			return false;
		default: {
			const exhaustive: never = form;
			throw new Error(`Unhandled NamEConstraintForm type: ${String(exhaustive)}`);
		}
	}
}

/**
 * Checks a certificate's subject DN and SANs against accumulated
 * name constraints. Returns a failure if any name violates constraints.
 */
function checkCertificateNames(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): NameConstraintValidationResult {
	// Check subject DN as directoryName (if non-empty).
	if (certificate.subject.derHex !== EMPTY_SEQUENCE_HEX) {
		const dnResult = isNamePermitted(
			{ type: 'directoryName', derHex: certificate.subject.derHex },
			accumulated,
		);
		if (!dnResult) {
			return nameConstraintFailure(
				'name_constraints_violated',
				'subject distinguished name violates name constraints',
				index,
				nameConstraintDetails({
					subjectCommonName: certificate.subject.values.commonName,
				}),
			);
		}
	}

	// Check each SAN.
	if (certificate.subjectAltNames !== undefined) {
		for (const san of certificate.subjectAltNames) {
			const checkable = sanToConstraintCheckable(san);
			if (checkable === undefined) {
				continue;
			}
			if (!isNamePermitted(checkable, accumulated)) {
				return nameConstraintFailure(
					'name_constraints_violated',
					`SAN ${formatConstraintForm(checkable)} violates name constraints`,
					index,
					nameConstraintDetails({
						subjectCommonName: certificate.subject.values.commonName,
						actual: formatConstraintForm(checkable),
					}),
				);
			}
		}
	}

	// RFC 5280 §4.2.1.10: When constraints are imposed on the rfc822Name
	// name form, but the certificate does not include a SAN email, the
	// constraint MUST be applied to the emailAddress attribute in the
	// subject DN.
	const hasEmailConstraints = accumulatedHasEmailConstraints(accumulated);
	if (hasEmailConstraints) {
		const hasSanEmail = certificate.subjectAltNames?.some((san) => san.type === 'email') ?? false;
		if (!hasSanEmail && certificate.subject.values.emailAddress !== undefined) {
			const emailForm: NameConstraintForm = {
				type: 'email',
				value: certificate.subject.values.emailAddress,
			};
			if (!isNamePermitted(emailForm, accumulated)) {
				return nameConstraintFailure(
					'name_constraints_violated',
					`subject emailAddress ${certificate.subject.values.emailAddress} violates name constraints`,
					index,
					nameConstraintDetails({
						subjectCommonName: certificate.subject.values.commonName,
						actual: certificate.subject.values.emailAddress,
					}),
				);
			}
		}
	}

	return { ok: true };
}

/** True when any level of accumulated constraints addresses the email name form. */
function accumulatedHasEmailConstraints(accumulated: AccumulatedNameConstraints): boolean {
	for (const level of accumulated.permittedLevels) {
		if (level.some((c) => c.type === 'email')) {
			return true;
		}
	}
	return accumulated.excluded.some((c) => c.type === 'email');
}

/**
 * Converts a SubjectAltName to a NameConstraintForm for checking.
 * Returns `undefined` for name forms that don't participate in
 * constraint checking (unknown tags).
 */
function sanToConstraintCheckable(san: SubjectAltName): NameConstraintForm | undefined {
	switch (san.type) {
		case 'dns':
			return { type: 'dns', value: san.value };
		case 'email':
			return { type: 'email', value: san.value };
		case 'uri':
			return { type: 'uri', value: san.value };
		case 'srv':
			return undefined;
		case 'ip':
			return {
				type: 'ip',
				addressBytes: parseIpAddressToBytes(san.value),
				maskBytes: allOnesMaskForIpAddress(san.value),
			};
		case 'directoryName':
			return { type: 'directoryName', derHex: san.derHex };
		case 'unknown':
			return undefined;
		default: {
			const exhaustive: never = san;
			throw new Error(`Unhandled SubjectAltName type: ${String(exhaustive)}`);
		}
	}
}

/**
 * Checks whether a name is permitted by the accumulated constraints.
 * A name is permitted if:
 * 1. It does NOT match any excluded constraint, AND
 * 2. For every permitted level that contains constraints of the same
 *    name form, it matches at least one.
 */
function isNamePermitted(
	name: NameConstraintForm,
	accumulated: AccumulatedNameConstraints,
): boolean {
	// Check excluded — if any match, reject.
	for (const constraint of accumulated.excluded) {
		if (nameMatchesConstraint(name, constraint)) {
			return false;
		}
	}
	// Check permitted — for each level with relevant constraints,
	// the name must match at least one.
	for (const level of accumulated.permittedLevels) {
		const relevant = level.filter((constraint) => constraint.type === name.type);
		if (relevant.length === 0) {
			continue;
		}
		if (!relevant.some((constraint) => nameMatchesConstraint(name, constraint))) {
			return false;
		}
	}
	return true;
}

/** Dispatches to the type-specific matching function for the name form. */
function nameMatchesConstraint(name: NameConstraintForm, constraint: NameConstraintForm): boolean {
	if (name.type === 'dns' && constraint.type === 'dns') {
		return matchesDnsConstraint(name.value, constraint.value);
	}
	if (name.type === 'email' && constraint.type === 'email') {
		return matchesEmailConstraint(name.value, constraint.value);
	}
	if (name.type === 'uri' && constraint.type === 'uri') {
		return matchesUriConstraint(name.value, constraint.value);
	}
	if (name.type === 'ip' && constraint.type === 'ip') {
		return matchesIpConstraint(name.addressBytes, constraint.addressBytes, constraint.maskBytes);
	}
	if (name.type === 'directoryName' && constraint.type === 'directoryName') {
		return matchesDnConstraint(name.derHex, constraint.derHex);
	}
	return false;
}

/**
 * RFC 5280 §4.2.1.10: DNS name constraint matching.
 * Constraint "example.com" matches "example.com" and any subdomain.
 * Constraint ".example.com" matches only subdomains, not "example.com" itself.
 */
function matchesDnsConstraint(name: string, constraint: string): boolean {
	const lowerName = name.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.length === 0) {
		return true;
	}
	if (lowerConstraint.startsWith('.')) {
		return lowerName.endsWith(lowerConstraint);
	}
	return lowerName === lowerConstraint || lowerName.endsWith(`.${lowerConstraint}`);
}

/**
 * RFC 5280 §4.2.1.10: Email constraint matching.
 * - "user@example.com" matches only that exact address.
 * - "example.com" matches any address @example.com.
 * - ".example.com" matches any address @subdomain.example.com.
 */
function matchesEmailConstraint(name: string, constraint: string): boolean {
	const lowerName = name.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.includes('@')) {
		return lowerName === lowerConstraint;
	}
	const atIndex = lowerName.indexOf('@');
	if (atIndex < 0) {
		return false;
	}
	const host = lowerName.slice(atIndex + 1);
	if (lowerConstraint.startsWith('.')) {
		return host.endsWith(lowerConstraint);
	}
	return host === lowerConstraint;
}

/**
 * RFC 5280 §4.2.1.10: URI constraint matching.
 * Applied to the host part of the URI.
 * - Constraint ".example.com" matches subdomains only.
 * - Constraint "example.com" matches ONLY that exact host (no subdomain
 *   expansion, unlike DNS constraints).
 */
function matchesUriConstraint(uri: string, constraint: string): boolean {
	const host = extractUriHost(uri);
	if (host === undefined) {
		return false;
	}
	const lowerHost = host.toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
	if (lowerConstraint.length === 0) {
		return true;
	}
	if (lowerConstraint.startsWith('.')) {
		return lowerHost.endsWith(lowerConstraint);
	}
	// Non-period constraint: exact host match only (RFC 5280 §4.2.1.10).
	return lowerHost === lowerConstraint;
}

/** Extracts the host (reg-name) portion of a URI, stripping scheme, userinfo, port, and path. */
function extractUriHost(uri: string): string | undefined {
	const schemeEnd = uri.indexOf('://');
	if (schemeEnd < 0) {
		return undefined;
	}
	const afterScheme = uri.slice(schemeEnd + 3);
	const atSign = afterScheme.indexOf('@');
	const hostStart = atSign >= 0 ? atSign + 1 : 0;
	const rest = afterScheme.slice(hostStart);
	const pathStart = rest.indexOf('/');
	const portStart = rest.indexOf(':');
	const end =
		pathStart >= 0
			? portStart >= 0
				? Math.min(pathStart, portStart)
				: pathStart
			: portStart >= 0
				? portStart
				: rest.length;
	return rest.slice(0, end);
}

/**
 * RFC 5280 §4.2.1.10: IP constraint matching.
 * (nameiP & mask) == (constraintiP & mask)
 */
function matchesIpConstraint(
	nameBytes: Uint8Array,
	constraintAddr: Uint8Array,
	constraintMask: Uint8Array,
): boolean {
	if (nameBytes.length !== constraintAddr.length) {
		return false;
	}
	for (let i = 0; i < nameBytes.length; i += 1) {
		const nameByte = nameBytes[i] ?? 0;
		const addrByte = constraintAddr[i] ?? 0;
		const maskByte = constraintMask[i] ?? 0;
		if ((nameByte & maskByte) !== (addrByte & maskByte)) {
			return false;
		}
	}
	return true;
}

/**
 * RFC 5280 §4.2.1.10: DirectoryName constraint matching.
 * The subject DN must equal or be subordinate to the constraint DN,
 * using RFC 5280 section 7.1 name comparison semantics.
 */
function matchesDnConstraint(subjectDerHex: string, constraintDerHex: string): boolean {
	const subjectName = parseDirectoryNameDerHex(subjectDerHex);
	const constraintName = parseDirectoryNameDerHex(constraintDerHex);
	if (subjectName === undefined || constraintName === undefined) {
		return false;
	}
	return isWithinDirectoryNameSubtree(subjectName, constraintName);
}

/** Re-parses a hex-encoded DER Name for RDN-by-RDN comparison. Returns `undefined` on malformed input. */
function parseDirectoryNameDerHex(derHex: string): ParsedName | undefined {
	if (!/^(?:[0-9a-fA-F]{2})+$/.test(derHex)) {
		return undefined;
	}
	try {
		const bytes = hexToBytes(derHex);
		const element = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		if (element.tag !== 0x30) {
			return undefined;
		}
		const rdns: ParsedRelativeDistinguishedName[] = [];
		const attributes: ParsedNameAttribute[] = [];
		const values: ParsedName['values'] = {};
		for (const setElement of childrenOf(bytes, element)) {
			const rdn = parseDirectoryNameRdn(bytes, setElement);
			if (rdn === undefined) {
				return undefined;
			}
			rdns.push(rdn);
			for (const attribute of rdn.attributes) {
				attributes.push(attribute);
				if (attribute.key !== undefined && values[attribute.key] === undefined) {
					values[attribute.key] = attribute.value;
				}
			}
		}
		return {
			derHex: toHex(bytes),
			rdns,
			attributes,
			values,
		};
	} catch {
		return undefined;
	}
}

/** Parses one SET element (a single RDN) from the DER Name SEQUENCE. */
function parseDirectoryNameRdn(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName | undefined {
	const attributes: ParsedNameAttribute[] = [];
	const values: ParsedName['values'] = {};
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oidElement = parts[0];
		const valueElement = parts[1];
		if (oidElement === undefined || valueElement === undefined) {
			return undefined;
		}
		const oid = decodeObjectIdentifier(requireElement(oidElement, 'directoryName OID').value);
		let fieldValue: string;
		try {
			fieldValue = decodeString(
				valueElement.tag,
				requireElement(valueElement, 'directoryName value').value,
			);
		} catch {
			return undefined;
		}
		const fieldKey = nameFieldKeyFromOid(oid);
		const attribute: ParsedNameAttribute =
			fieldKey !== undefined
				? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
				: { oid, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
}

/** True when `subject` equals or is subordinate to `constraint` (RDN prefix match). */
function isWithinDirectoryNameSubtree(subject: ParsedName, constraint: ParsedName): boolean {
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

/** Order-independent RDN equality: same attribute count, each pair matched exactly once. */
function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = new Array(right.attributes.length).fill(false);
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
function compareNameAttributeValue(left: ParsedNameAttribute, right: ParsedNameAttribute): boolean {
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

/** True for UTF8String (0x0C) and PrintableString (0x13) — the DirectoryString types we normalize. */
function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/** NFKC-normalizes, lowercases, trims, and collapses whitespace for RFC 5280 §7.1 comparison. */
function prepareNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

/** Human-readable label for a constraint form, used in error messages. */
function formatConstraintForm(form: NameConstraintForm): string {
	switch (form.type) {
		case 'dns':
			return `dns:${form.value}`;
		case 'email':
			return `email:${form.value}`;
		case 'uri':
			return `uri:${form.value}`;
		case 'ip':
			return `ip:${decodeIpAddress(form.addressBytes)}`;
		case 'directoryName':
			return `dn:${form.derHex.slice(0, 20)}...`;
		default: {
			const exhaustive = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
		}
	}
}
