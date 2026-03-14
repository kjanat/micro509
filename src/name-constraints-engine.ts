/**
 * Internal name-constraints evaluation engine.
 *
 * This module accumulates and evaluates the shipped RFC 5280 name-constraint subset during
 * path validation.
 */

import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	hexToBytes,
	requireElement,
	toHex,
} from './asn1.ts';
import type { Micro509Error } from './core/result.ts';
import { DEFAULT_MAX_DER_DEPTH, type DerElement, readRootElement } from './der.ts';
import type {
	NameConstraintForm,
	NameConstraints,
	ParsedNameConstraintForm,
	SubjectAltName,
} from './extensions.ts';
import { allOnesMaskForIpAddress, decodeIpAddress, parseIpAddressToBytes } from './ip.ts';
import { nameFieldKeyFromOid } from './name.ts';
import type { InitialNameConstraintsInput } from './name-constraints.ts';
import { OIDS } from './oids.ts';
import type {
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from './parse.ts';

/**
 * Tracks internal state for name constraint validation processing.
 */
export interface NameConstraintValidationState {
	/**
	 * Carries the initial permitted subtrees value.
	 */
	readonly initialPermittedSubtrees: readonly NameConstraintForm[];
	/**
	 * Carries the initial excluded subtrees value.
	 */
	readonly initialExcludedSubtrees: readonly NameConstraintForm[];
}

/**
 * Defines name constraint validation failure code.
 */
export type NameConstraintValidationFailureCode =
	| 'name_constraints_violated'
	| 'unsupported_name_constraints';

/**
 * Carries structured details for name constraint validation failures.
 */
export interface NameConstraintValidationFailureDetails {
	/**
	 * Carries the subject common name value.
	 */
	readonly subjectCommonName?: string;
	/**
	 * Carries the actual value.
	 */
	readonly actual?: string;
}

/**
 * Represents a typed failure produced by name constraint validation operations.
 */
export interface NameConstraintValidationFailure
	extends Micro509Error<
		NameConstraintValidationFailureCode,
		NameConstraintValidationFailureDetails
	> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the zero-based index associated with this value.
	 */
	readonly index: number;
}

/**
 * Represents the result returned by name constraint validation operations.
 */
export type NameConstraintValidationResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
	  }
	| NameConstraintValidationFailure;

/**
 * Describes the input shape for name constraint validation failure details operations.
 */
interface NameConstraintValidationFailureDetailsInput {
	/**
	 * Carries the subject common name value.
	 */
	readonly subjectCommonName?: string | undefined;
	/**
	 * Carries the actual value.
	 */
	readonly actual?: string | undefined;
}

/**
 * Name constraint failure.
 *
 * @param code The code value.
 * @param message The message value.
 * @param index The index value.
 * @param details The structured details value.
 * @returns The computed value.
 */
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

/**
 * Name constraint details.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
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

/**
 * Returns whether self issued.
 *
 * @param certificate The certificate input.
 * @returns Whether the condition holds.
 */
function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

/**
 * Creates name constraint validation state.
 *
 * @param input The typed input payload.
 * @returns The created name constraint validation state.
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
	/**
	 * Carries the permitted levels value.
	 */
	readonly permittedLevels: readonly (readonly NameConstraintForm[])[];
	/**
	 * Carries the excluded value.
	 */
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

/**
 * Seeds initial name constraints.
 *
 * @param state The current state value.
 * @returns The computed value.
 */
function seedInitialNameConstraints(
	state: NameConstraintValidationState,
): AccumulatedNameConstraints {
	return {
		permittedLevels:
			state.initialPermittedSubtrees.length > 0 ? [state.initialPermittedSubtrees] : [],
		excluded: state.initialExcludedSubtrees,
	};
}

/**
 * Accumulates constraints.
 *
 * @param current The current value.
 * @param constraints The constraints value.
 * @returns The computed value.
 */
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

/**
 * Fail on unsupported name constraints.
 *
 * @param certificate The certificate input.
 * @param index The index value.
 * @returns The computed value.
 */
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

/**
 * List unsupported name constraint types.
 *
 * @param constraints The constraints value.
 * @returns The computed value.
 */
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

/**
 * Returns whether supported name constraint form.
 *
 * @param form The form value.
 * @returns Whether the condition holds.
 */
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
				/**
				 * Identifies the type value.
				 */
				type: 'email',
				/**
				 * Carries the successful value payload.
				 */
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

/**
 * Accumulates d has email constraints.
 *
 * @param accumulated The accumulated value.
 * @returns The computed value.
 */
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

/**
 * Name matches constraint.
 *
 * @param name The name value.
 * @param constraint The constraint value.
 * @returns The computed value.
 */
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

/**
 * Extract URI host.
 *
 * @param uri The URI value.
 * @returns The computed value.
 */
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

/**
 * Parses directory name DER hex.
 *
 * @param derHex The DER hex value.
 * @returns The parsed directory name DER hex.
 */
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

/**
 * Parses directory name RDN.
 *
 * @param source The source value to process.
 * @param setElement The set element value.
 * @returns The parsed directory name RDN.
 */
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

/**
 * Returns whether within directory name subtree.
 *
 * @param subject The subject value.
 * @param constraint The constraint value.
 * @returns Whether the condition holds.
 */
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

/**
 * Compares relative distinguished names.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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

/**
 * Compares name attribute value.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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

/**
 * Returns whether directory string tag.
 *
 * @param tag The tag value.
 * @returns Whether the condition holds.
 */
function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/**
 * Prepare name compare string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function prepareNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

/**
 * Format constraint form.
 *
 * @param form The form value.
 * @returns The computed value.
 */
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
