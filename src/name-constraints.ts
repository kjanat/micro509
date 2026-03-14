/**
 * Public input types for caller-supplied initial name constraints.
 *
 * These types let callers seed name-constraint state before certificate path processing
 * begins.
 */

import type { GeneralSubtree } from './extensions.ts';

/**
 * Describes the input shape for initial name constraints operations.
 */
export interface InitialNameConstraintsInput {
	/**
	 * Carries the permitted subtrees value.
	 */
	readonly permittedSubtrees?: readonly GeneralSubtree[];
	/**
	 * Carries the excluded subtrees value.
	 */
	readonly excludedSubtrees?: readonly GeneralSubtree[];
}
