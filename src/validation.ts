/**
 * Cross-domain validation types shared by the public validation surfaces.
 *
 * Re-exports identity, name-constraint, policy, and revocation types so that
 * downstream consumers can import a single validation namespace without
 * reaching into internal modules.
 *
 * @module
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
