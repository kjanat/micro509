/**
 * Public policy-validation input and output types.
 *
 * These types describe the caller-facing policy knobs and the constrained policy results
 * exposed by verification APIs.
 */

import type { PolicyQualifierInfo } from './extensions.ts';

/**
 * Describes the input shape for policy validation operations.
 */
export interface PolicyValidationInput {
	/**
	 * Carries the initial policy set value.
	 */
	readonly initialPolicySet?: readonly string[] | 'any';
	/**
	 * Indicates whether require explicit policy.
	 */
	readonly requireExplicitPolicy?: boolean;
	/**
	 * Indicates whether inhibit policy mapping.
	 */
	readonly inhibitPolicyMapping?: boolean;
	/**
	 * Indicates whether inhibit any policy.
	 */
	readonly inhibitAnyPolicy?: boolean;
}

/** One policy OID that survives RFC 5280 / RFC 9618 processing. */
export interface ConstrainedPolicy {
	/**
	 * Carries the policy identifier value.
	 */
	readonly policyIdentifier: string;
	/**
	 * Carries the policy qualifiers value.
	 */
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

/** Final policy outputs exposed by successful path-validation APIs. */
export interface PolicyValidationOutcome {
	/**
	 * Carries the authority constrained policies value.
	 */
	readonly authorityConstrainedPolicies: readonly ConstrainedPolicy[];
	/**
	 * Carries the user constrained policies value.
	 */
	readonly userConstrainedPolicies: readonly ConstrainedPolicy[];
}
