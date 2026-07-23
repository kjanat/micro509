/**
 * Internal name-constraints evaluation engine.
 *
 * Accumulates and evaluates the shipped RFC 5280
 * [§4.2.1.10](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10) / [§6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)
 * name-constraint subset during certificate path validation.
 *
 * @module
 */

import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	hexToBytes,
	requireElement,
	toHex,
} from '#micro509/internal/asn1/asn1';
import {
	DEFAULT_MAX_DER_DEPTH,
	type DerElement,
	readRootElement,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	compareDistinguishedNames,
	isWithinDirectoryNameSubtree,
} from '#micro509/internal/shared/dn';
import {
	allOnesMaskForIpAddress,
	decodeIpAddress,
	parseIpAddressToBytes,
} from '#micro509/internal/shared/ip';
import type { Micro509Error } from '#micro509/result/result';
import type { InitialNameConstraintsInput } from '#micro509/verify/name-constraints';
import type {
	NameConstraintForm,
	NameConstraints,
	ParsedNameConstraintForm,
	SubjectAltName,
	UnsupportedNameConstraintForm,
} from '#micro509/x509/extensions';
import { nameFieldKeyFromOid } from '#micro509/x509/name';
import type {
	NameFieldKey,
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse';

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

type SubjectAltNameCheckableResult =
	| {
			readonly ok: true;
			readonly value: NameConstraintForm | undefined;
	  }
	| {
			readonly ok: false;
			readonly actual: string;
	  };

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

/** A certificate is self-issued when subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
function isSelfIssued(certificate: ParsedCertificate): boolean {
	return compareDistinguishedNames(certificate.subject, certificate.issuer);
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

// Private: name constraint validation (RFC 5280 §4.2.1.10 / §6.1)

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
	/**
	 * Name forms this engine cannot evaluate that were imposed by a
	 * **critical** nameConstraints extension above. RFC 5280 §4.2.1.10:
	 * a subsequent certificate carrying a name of such a form MUST be
	 * rejected; certificates without one stay acceptable.
	 */
	readonly unsupportedCriticalForms: ReadonlySet<UnsupportedNameConstraintForm['type']>;
}

/**
 * Walks the chain root-to-leaf, accumulating nameConstraints from CA
 * certificates and checking each non-self-issued certificate's names
 * against the accumulated constraints.
 *
 * RFC 5280 §6.1.3(b)-(c) for name checks, §6.1.4(g) for constraint accumulation.
 */

export function evaluateNameConstraints(
	chain: readonly ParsedCertificate[],
	state: NameConstraintValidationState,
): NameConstraintValidationResult {
	let accumulated = seedInitialNameConstraints(state);

	// Seed constraints from the root (trust anchor). The root's own
	// names are not checked, but its nameConstraints apply to all
	// certificates below it in the chain.
	const root = chain[chain.length - 1];
	if (root?.nameConstraints !== undefined) {
		accumulated = accumulateConstraints(
			accumulated,
			root.nameConstraints,
			hasCriticalNameConstraintsExtension(root),
		);
	}

	// Walk from just below root toward leaf.
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const current = chain[index];
		if (current === undefined) {
			throw new Error(`Certificate chain contains undefined at index ${String(index)}`);
		}

		// RFC 5280 §6.1.3(b)-(c): check names against accumulated permitted (b)
		// and excluded (c) constraints. §4.2.1.10 exempts self-issued
		// certificates unless the certificate is the leaf.
		if (!isSelfIssued(current) || index === 0) {
			const nameCheckResult = checkCertificateNames(current, accumulated, index);
			if (!nameCheckResult.ok) {
				return nameCheckResult;
			}
		}

		// RFC 5280 §6.1.4(g): accumulate this certificate's nameConstraints,
		// intersecting permitted subtrees and unioning excluded subtrees.
		if (current.nameConstraints !== undefined) {
			accumulated = accumulateConstraints(
				accumulated,
				current.nameConstraints,
				hasCriticalNameConstraintsExtension(current),
			);
		}
	}

	return { ok: true };
}

/** True when the certificate carries a critical nameConstraints extension. */
function hasCriticalNameConstraintsExtension(certificate: ParsedCertificate): boolean {
	return certificate.extensions.some(
		(entry) => entry.oid === OIDS.nameConstraints && entry.critical,
	);
}

/** Converts initial state into the starting accumulated-constraints snapshot. */
function seedInitialNameConstraints(
	state: NameConstraintValidationState,
): AccumulatedNameConstraints {
	return {
		permittedLevels:
			state.initialPermittedSubtrees.length > 0 ? [state.initialPermittedSubtrees] : [],
		excluded: state.initialExcludedSubtrees,
		unsupportedCriticalForms: new Set(),
	};
}

/**
 * Merges one certificate's nameConstraints extension into the running totals.
 *
 * Unsupported constraint forms from a critical extension are recorded so
 * subsequent certificates carrying a name of that form fail closed
 * (RFC 5280 §4.2.1.10). Unsupported forms in a non-critical extension are
 * dropped — the RFC's rejection requirement is scoped to critical
 * extensions (conforming CAs MUST mark nameConstraints critical anyway).
 */
function accumulateConstraints(
	current: AccumulatedNameConstraints,
	constraints: NameConstraints<ParsedNameConstraintForm>,
	critical: boolean,
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
	const newUnsupported = critical ? listUnsupportedNameConstraintTypes(constraints) : [];
	const unsupportedCriticalForms =
		newUnsupported.length > 0
			? new Set([...current.unsupportedCriticalForms, ...newUnsupported])
			: current.unsupportedCriticalForms;
	return { permittedLevels, excluded, unsupportedCriticalForms };
}

/** Collects the distinct unsupported GeneralName form types from a nameConstraints extension. */
function listUnsupportedNameConstraintTypes(
	constraints: NameConstraints<ParsedNameConstraintForm>,
): readonly UnsupportedNameConstraintForm['type'][] {
	const unsupportedTypes = new Set<UnsupportedNameConstraintForm['type']>();
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
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
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
	const subjectResult = checkCertificateSubjectName(certificate, accumulated, index);
	if (!subjectResult.ok) return subjectResult;
	const sanResult = checkCertificateSubjectAltNames(certificate, accumulated, index);
	if (!sanResult.ok) return sanResult;
	const subjectEmailResult = checkCertificateSubjectEmailFallback(certificate, accumulated, index);
	if (!subjectEmailResult.ok) return subjectEmailResult;
	return { ok: true };
}

/** Checks a certificate subject DN against the accumulated directory-name constraints. */
function checkCertificateSubjectName(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): NameConstraintValidationResult {
	if (certificate.subject.derHex === EMPTY_SEQUENCE_HEX) return { ok: true };
	const dnResult = isNamePermitted(
		{ type: 'directoryName', derHex: certificate.subject.derHex },
		accumulated,
	);
	return dnResult
		? { ok: true }
		: nameConstraintFailure(
				'name_constraints_violated',
				'subject distinguished name violates name constraints',
				index,
				nameConstraintDetails({ subjectCommonName: certificate.subject.values.commonName }),
			);
}

function checkCertificateSubjectAltNames(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): NameConstraintValidationResult {
	for (const san of certificate.subjectAltNames ?? []) {
		const result = checkCertificateSubjectAltName(certificate, accumulated, san, index);
		if (!result.ok) return result;
	}
	return { ok: true };
}

function checkCertificateSubjectAltName(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	san: SubjectAltName,
	index: number,
): NameConstraintValidationResult {
	const unsupportedForm = sanUnsupportedFormType(san);
	if (unsupportedForm !== undefined && accumulated.unsupportedCriticalForms.has(unsupportedForm)) {
		return nameConstraintFailure(
			'unsupported_name_constraints',
			`critical name constraints impose ${unsupportedForm} constraints that cannot be processed, and the certificate contains a ${unsupportedForm} subject alternative name`,
			index,
			nameConstraintDetails({
				subjectCommonName: certificate.subject.values.commonName,
				actual: unsupportedForm,
			}),
		);
	}
	const checkableResult = sanToConstraintCheckable(san);
	if (!checkableResult.ok) {
		return nameConstraintFailure(
			'name_constraints_violated',
			`SAN ${checkableResult.actual} is malformed and cannot be checked against name constraints`,
			index,
			nameConstraintDetails({
				subjectCommonName: certificate.subject.values.commonName,
				actual: checkableResult.actual,
			}),
		);
	}
	const checkable = checkableResult.value;
	if (
		checkable?.type === 'uri' &&
		accumulatedHasUriConstraints(accumulated) &&
		uriAuthorityLacksFqdn(checkable.value)
	) {
		return nameConstraintFailure(
			'name_constraints_violated',
			`SAN uri:${checkable.value} has no FQDN authority and cannot be evaluated against URI name constraints`,
			index,
			nameConstraintDetails({
				subjectCommonName: certificate.subject.values.commonName,
				actual: `uri:${checkable.value}`,
			}),
		);
	}
	if (checkable === undefined || isNamePermitted(checkable, accumulated)) return { ok: true };
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

function checkCertificateSubjectEmailFallback(
	certificate: ParsedCertificate,
	accumulated: AccumulatedNameConstraints,
	index: number,
): NameConstraintValidationResult {
	// RFC 5280 §4.2.1.10 applies rfc822Name constraints to the subject DN
	// emailAddress when the certificate has no subjectAltName extension. This
	// implementation applies it whenever the SAN carries no rfc822Name.
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

/** True when any level of accumulated constraints addresses the URI name form. */
function accumulatedHasUriConstraints(accumulated: AccumulatedNameConstraints): boolean {
	for (const level of accumulated.permittedLevels) {
		if (level.some((c) => c.type === 'uri')) {
			return true;
		}
	}
	return accumulated.excluded.some((c) => c.type === 'uri');
}

/**
 * Maps a SAN to the unsupported constraint form it instantiates, if any.
 *
 * SRV-ID SANs are otherName [0] instances. Unknown SANs carry the full DER
 * tag byte: 0xa0 otherName [0], 0xa3 x400Address [3], 0xa5 ediPartyName [5],
 * 0x88 registeredID [8].
 */
function sanUnsupportedFormType(
	san: SubjectAltName,
): UnsupportedNameConstraintForm['type'] | undefined {
	if (san.type === 'srv') {
		return 'otherName';
	}
	if (san.type !== 'unknown') {
		return undefined;
	}
	switch (san.tag) {
		case 0xa0:
			return 'otherName';
		case 0xa3:
			return 'x400Address';
		case 0xa5:
			return 'ediPartyName';
		case 0x88:
			return 'registeredID';
		default:
			return undefined;
	}
}

/**
 * Converts a SubjectAltName to a NameConstraintForm for checking.
 * Returns `undefined` for name forms that don't participate in
 * constraint checking (unknown tags).
 */
function sanToConstraintCheckable(san: SubjectAltName): SubjectAltNameCheckableResult {
	switch (san.type) {
		case 'dns':
			return { ok: true, value: { type: 'dns', value: san.value } };
		case 'email':
			return { ok: true, value: { type: 'email', value: san.value } };
		case 'uri':
			return { ok: true, value: { type: 'uri', value: san.value } };
		case 'srv':
			return { ok: true, value: undefined };
		case 'ip':
			try {
				return {
					ok: true,
					value: {
						type: 'ip',
						addressBytes: parseIpAddressToBytes(san.value),
						maskBytes: allOnesMaskForIpAddress(san.value),
					},
				};
			} catch {
				return {
					ok: false,
					actual: `ip:${san.value}`,
				};
			}
		case 'directoryName':
			return { ok: true, value: { type: 'directoryName', derHex: san.derHex } };
		case 'unknown':
			return { ok: true, value: undefined };
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
 * DNS name constraint matching. RFC 5280 §4.2.1.10 adds zero or more labels on
 * the left; §7.2 compares label by label case-insensitively. Constraint
 * "example.com" matches "example.com" and any subdomain. The leading-period
 * form ".example.com" restricts to subdomains, following the convention shared
 * by OpenSSL, Go and NSS rather than the RFC.
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
 * RFC 5280 §4.2.1.10 email constraint matching, deferring to §7.5 (as
 * replaced by RFC 9549 §7.5.1): the local part matches exactly, the host part
 * case-insensitively.
 * - "user@example.com" constrains the local part exactly and the host case-insensitively.
 * - "example.com" matches any address whose host is example.com.
 * - ".example.com" matches any address under a subdomain of example.com.
 */
function matchesEmailConstraint(name: string, constraint: string): boolean {
	if (constraint.includes('@')) {
		const nameAt = name.lastIndexOf('@');
		const constraintAt = constraint.lastIndexOf('@');
		if (nameAt < 0 || constraintAt < 0) {
			return false;
		}
		if (name.slice(0, nameAt) !== constraint.slice(0, constraintAt)) {
			return false;
		}
		return (
			name.slice(nameAt + 1).toLowerCase() === constraint.slice(constraintAt + 1).toLowerCase()
		);
	}
	const atIndex = name.lastIndexOf('@');
	if (atIndex < 0) {
		return false;
	}
	const host = name.slice(atIndex + 1).toLowerCase();
	const lowerConstraint = constraint.toLowerCase();
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
	try {
		const url = new URL(uri);
		return url.hostname;
	} catch {
		return undefined;
	}
}

/**
 * RFC 5280 §4.2.1.10: a URI subject to a uniformResourceIdentifier constraint
 * MUST be rejected when its authority component has no FQDN host. True for a
 * missing or empty authority, a bracketed IPv6 literal, an IPv4 literal, or a
 * single-label host such as `localhost` (an FQDN has at least two labels).
 */
function uriAuthorityLacksFqdn(uri: string): boolean {
	const host = extractUriHost(uri);
	if (host === undefined || host.length === 0 || host.startsWith('[')) {
		return true;
	}
	if (isIpLiteral(host)) {
		return true;
	}
	const labels = host.split('.').filter((label) => label.length > 0);
	return labels.length < 2;
}

/** True when `host` parses as an IPv4 or IPv6 literal. */
function isIpLiteral(host: string): boolean {
	try {
		parseIpAddressToBytes(host);
		return true;
	} catch {
		return false;
	}
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
		const root = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		const element = unwrapDirectoryNameElement(bytes, root);
		if (element.tag !== 0x30) {
			return undefined;
		}
		const rdns: ParsedRelativeDistinguishedName[] = [];
		const attributes: ParsedNameAttribute[] = [];
		const values: Partial<Record<NameFieldKey, string>> = {};
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
 * Unwraps doubly-nested directoryName SEQUENCE encoding.
 *
 * Some encoders produce `[4] { SEQ { SEQ { SET... } } }` instead of `[4] { SEQ { SET... } }`.
 * A single SEQUENCE child indicates the extra wrapper (valid Names have SET children).
 */
function unwrapDirectoryNameElement(source: Uint8Array, element: DerElement): DerElement {
	if (element.tag !== 0x30) {
		return element;
	}
	const children = childrenOf(source, element);
	const child = children[0];
	if (children.length === 1 && child?.tag === 0x30) {
		return child;
	}
	return element;
}

/** Parses one SET element (a single RDN) from the DER Name SEQUENCE. */
function parseDirectoryNameRdn(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName | undefined {
	if (setElement.tag !== 0x31) {
		return undefined;
	}
	const children = childrenOf(source, setElement);
	if (children.length === 0) {
		return undefined;
	}
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of children) {
		if (attributeSequence.tag !== 0x30) {
			return undefined;
		}
		const parts = childrenOf(source, attributeSequence);
		const oidElement = parts[0];
		const valueElement = parts[1];
		if (oidElement === undefined || valueElement === undefined || parts.length !== 2) {
			return undefined;
		}
		if (oidElement.tag !== 0x06) {
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
	if (attributes.length === 0) {
		return undefined;
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
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
			return `dn:${form.derHex.slice(0, 20)}${form.derHex.length > 20 ? '...' : ''}`;
		default: {
			const exhaustive = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(exhaustive)}`);
		}
	}
}
