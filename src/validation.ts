/**
 * Temporary compatibility shim for pre-1.0 type moves.
 *
 * Import new types from their owning domain modules instead:
 * - `./policy.ts`
 * - `./name-constraints.ts`
 * - `./identity.ts`
 * - `./revocation.ts`
 *
 * Remove this file once internal and external callers finish migrating.
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
