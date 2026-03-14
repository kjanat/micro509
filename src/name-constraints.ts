/**
 * Caller-supplied initial name constraints for path validation.
 *
 * These types let callers seed the permitted/excluded subtree state
 * before RFC 5280 §6.1 certificate path processing begins.
 *
 * @module
 */

import type { GeneralSubtree } from './extensions.ts';

/**
 * Input for {@link createNameConstraintValidationState}.
 *
 * Seeds the name-constraint engine with trust-anchor-level subtree
 * restrictions that apply before any certificate in the chain is processed.
 */
export interface InitialNameConstraintsInput {
	/** Subtrees within which all subsequent subject names must fall. Default: unconstrained. */
	readonly permittedSubtrees?: readonly GeneralSubtree[];
	/** Subtrees that no subsequent subject name may fall within. Default: none. */
	readonly excludedSubtrees?: readonly GeneralSubtree[];
}
