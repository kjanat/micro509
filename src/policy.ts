import type { PolicyQualifierInfo } from './extensions.ts';

export interface PolicyValidationInput {
	readonly initialPolicySet?: readonly string[] | 'any';
	readonly requireExplicitPolicy?: boolean;
	readonly inhibitPolicyMapping?: boolean;
	readonly inhibitAnyPolicy?: boolean;
}

/** One policy OID that survives RFC 5280 / RFC 9618 processing. */
export interface ConstrainedPolicy {
	readonly policyIdentifier: string;
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

/** Final policy outputs exposed by successful path-validation APIs. */
export interface PolicyValidationOutcome {
	readonly authorityConstrainedPolicies: readonly ConstrainedPolicy[];
	readonly userConstrainedPolicies: readonly ConstrainedPolicy[];
}
