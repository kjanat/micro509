/**
 * Certificate policy validation types (RFC 5280 §6.1 / RFC 9618).
 *
 * Caller-facing knobs for controlling policy processing and the constrained
 * policy sets returned by successful path validation.
 *
 * @module
 */

import type { PolicyQualifierInfo } from '#micro509/x509/extensions';

/**
 * Input for the policy-validation engine.
 *
 * All fields are optional — omitted values produce the most permissive
 * behavior (accept any policy, allow mappings, allow anyPolicy).
 */
export interface PolicyValidationInput {
	/**
	 * OIDs the relying party considers acceptable, or `'any'` to accept
	 * whatever the chain asserts. Default: `'any'`.
	 */
	readonly initialPolicySet?: readonly string[] | 'any';
	/** When `true`, the chain must assert at least one acceptable policy. Default: `false`. */
	readonly requireExplicitPolicy?: boolean;
	/** When `true`, policy mappings in CA certificates are ignored. Default: `false`. */
	readonly inhibitPolicyMapping?: boolean;
	/** When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`. */
	readonly inhibitAnyPolicy?: boolean;
}

/** One policy OID that survives RFC 5280 / RFC 9618 processing. */
export interface ConstrainedPolicy {
	/** Dotted-decimal OID of the surviving policy. */
	readonly policyIdentifier: string;
	/** Qualifier info (CPS URIs, user notices) attached to this policy, if any. */
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

/** Final policy outputs exposed by successful path-validation APIs. */
export interface PolicyValidationOutcome {
	/** Policies valid under the authority's (CA chain) constraints alone. */
	readonly authorityConstrainedPolicies: readonly ConstrainedPolicy[];
	/**
	 * Policies from {@linkcode PolicyValidationInput.initialPolicySet} the chain
	 * establishes, per RFC 9618 §5.5 step (g)(5)-(6). Includes OIDs covered only
	 * by an authority-constrained anyPolicy, so this is not necessarily a subset
	 * of {@linkcode authorityConstrainedPolicies}.
	 */
	readonly userConstrainedPolicies: readonly ConstrainedPolicy[];
}
