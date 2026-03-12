import type { GeneralSubtree, PolicyQualifierInfo } from './extensions.ts';

/**
 * Shared boundary types for validation domains.
 *
 * - `verify.ts` owns path building and raw path validation.
 * - `identity.ts` will own service identity matching.
 * - `revocation.ts` will own CRL/OCSP orchestration.
 */

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

export interface InitialNameConstraintsInput {
	readonly permittedSubtrees?: readonly GeneralSubtree[];
	readonly excludedSubtrees?: readonly GeneralSubtree[];
}

export interface DnsServiceIdentityInput {
	readonly type: 'dns';
	readonly value: string;
	readonly allowCommonNameFallback?: boolean;
}

export interface IpServiceIdentityInput {
	readonly type: 'ip';
	readonly value: string;
}

export interface UriServiceIdentityInput {
	readonly type: 'uri';
	readonly value: string;
}

export interface SrvServiceIdentityInput {
	readonly type: 'srv';
	readonly value: string;
}

export type ServiceIdentityInput =
	| DnsServiceIdentityInput
	| IpServiceIdentityInput
	| UriServiceIdentityInput
	| SrvServiceIdentityInput;

export type ServiceIdentityType = ServiceIdentityInput['type'];
export type MatchableServiceIdentityInput = ServiceIdentityInput;
export type VerifyServiceIdentityInput = DnsServiceIdentityInput | IpServiceIdentityInput;

export type RevocationStatus = 'good' | 'revoked' | 'unknown';
