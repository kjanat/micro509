/**
 * Cross-domain validation types shared by the public validation surfaces.
 *
 * This module keeps shared validation structures in one place so verify, identity, and
 * revocation APIs stay aligned.
 */

export type {
	DnsServiceIdentityInput,
	IpServiceIdentityInput,
	MatchableServiceIdentityInput,
	ServiceIdentityInput,
	ServiceIdentityType,
	SrvServiceIdentityInput,
	UriServiceIdentityInput,
	VerifyServiceIdentityInput,
} from './identity.ts';
export type { InitialNameConstraintsInput } from './name-constraints.ts';
export type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from './policy.ts';
export type { RevocationStatus } from './revocation.ts';
