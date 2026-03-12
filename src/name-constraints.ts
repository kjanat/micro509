import type { GeneralSubtree } from './extensions.ts';

export interface InitialNameConstraintsInput {
	readonly permittedSubtrees?: readonly GeneralSubtree[];
	readonly excludedSubtrees?: readonly GeneralSubtree[];
}
