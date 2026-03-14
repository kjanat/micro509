/**
 * Internal RFC 9618 policy-validation engine.
 *
 * This module tracks policy state, updates it per certificate, and derives the public
 * policy-validation outcome.
 */

import type { Micro509Error, Result } from './core/result.ts';
import type { PolicyInformation, PolicyQualifierInfo } from './extensions.ts';
import { OIDS } from './oids.ts';
import type { ParsedCertificate } from './parse.ts';
import type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from './policy.ts';

/**
 * Tracks internal state for policy validation processing.
 */
export interface PolicyValidationState {
	/**
	 * Carries the initial policy set value.
	 */
	initialPolicySet: readonly string[] | 'any';
	/**
	 * Carries the explicit policy value.
	 */
	explicitPolicy: number;
	/**
	 * Carries the inhibit policy mapping value.
	 */
	inhibitPolicyMapping: number;
	/**
	 * Carries the inhibit any policy value.
	 */
	inhibitAnyPolicy: number;
	/**
	 * Carries the valid policy graph value.
	 */
	validPolicyGraph: PolicyGraph | null;
}

/**
 * Defines policy validation failure code.
 */
export type PolicyValidationFailureCode =
	| 'explicit_policy_required'
	| 'initial_policy_set_not_satisfied';

/**
 * Carries structured details for policy validation failures.
 */
export interface PolicyValidationFailureDetails {
	/**
	 * Carries the expected value.
	 */
	readonly expected: string;
	/**
	 * Carries the actual value.
	 */
	readonly actual: string;
}

/**
 * Represents a typed failure produced by policy validation operations.
 */
export interface PolicyValidationFailure
	extends Micro509Error<PolicyValidationFailureCode, PolicyValidationFailureDetails> {}

/**
 * Represents the result returned by policy validation operations.
 */
export type PolicyValidationResult = Result<PolicyValidationOutcome, PolicyValidationFailure>;

/**
 * Describes policy graph node.
 */
interface PolicyGraphNode {
	/**
	 * Carries the depth value.
	 */
	depth: number;
	/**
	 * Carries the valid policy value.
	 */
	validPolicy: string;
	/**
	 * Carries the qualifier set value.
	 */
	qualifierSet?: readonly PolicyQualifierInfo[];
	/**
	 * Carries the expected policy set value.
	 */
	expectedPolicySet: Set<string>;
	/**
	 * Carries the parent keys value.
	 */
	parentKeys: Set<string>;
	/**
	 * Carries the child keys value.
	 */
	childKeys: Set<string>;
}

/**
 * Describes policy graph.
 */
interface PolicyGraph {
	/**
	 * Carries the nodes by depth value.
	 */
	nodesByDepth: Map<string, PolicyGraphNode>[];
}

/**
 * Creates policy validation state.
 *
 * @param input The typed input payload.
 * @param chainLength The chain length value.
 * @returns The created policy validation state.
 */
export function createPolicyValidationState(
	input: PolicyValidationInput,
	chainLength: number,
): PolicyValidationState {
	const disabledCounter = chainLength + 1;
	return {
		initialPolicySet: input.initialPolicySet ?? 'any',
		explicitPolicy: input.requireExplicitPolicy === true ? 0 : disabledCounter,
		inhibitPolicyMapping: input.inhibitPolicyMapping === true ? 0 : disabledCounter,
		inhibitAnyPolicy: input.inhibitAnyPolicy === true ? 0 : disabledCounter,
		validPolicyGraph: createInitialPolicyGraph(),
	};
}

/**
 * Evaluates policy chain.
 *
 * @param chain The chain value.
 * @param state The current state value.
 * @returns The computed value.
 */
export function evaluatePolicyChain(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationResult {
	processPolicyState(chain, state);
	const outcome = derivePolicyValidationOutcome(chain, state);
	if (state.explicitPolicy === 0 && outcome.userConstrainedPolicies.length === 0) {
		return {
			ok: false,
			error: {
				code: 'explicit_policy_required',
				message: 'policy validation requires an explicit permitted policy',
				details: {
					expected:
						state.initialPolicySet === 'any' ? 'explicit policy' : state.initialPolicySet.join(','),
					actual: describeFinalPolicies(outcome.userConstrainedPolicies),
				},
			},
		};
	}
	if (state.initialPolicySet !== 'any' && outcome.userConstrainedPolicies.length === 0) {
		return {
			ok: false,
			error: {
				code: 'initial_policy_set_not_satisfied',
				message: 'certificate chain does not satisfy the requested initial policy set',
				details: {
					expected: state.initialPolicySet.join(','),
					actual: describeFinalPolicies(outcome.userConstrainedPolicies),
				},
			},
		};
	}
	return { ok: true, value: outcome };
}

/**
 * Creates initial policy graph.
 *
 * @returns The created initial policy graph.
 */
function createInitialPolicyGraph(): PolicyGraph {
	const rootNode = createPolicyGraphNode(0, OIDS.anyPolicy, undefined, [OIDS.anyPolicy], []);
	return {
		nodesByDepth: [new Map([[policyNodeKey(0, OIDS.anyPolicy), rootNode]])],
	};
}

/**
 * Creates policy graph node.
 *
 * @param depth The depth value.
 * @param validPolicy The valid policy value.
 * @param qualifierSet The qualifier set value.
 * @param expectedPolicySet The expected policy set value.
 * @param parentKeys The parent keys value.
 * @returns The created policy graph node.
 */
function createPolicyGraphNode(
	depth: number,
	validPolicy: string,
	qualifierSet: readonly PolicyQualifierInfo[] | undefined,
	expectedPolicySet: readonly string[],
	parentKeys: readonly string[],
): PolicyGraphNode {
	return {
		depth,
		validPolicy,
		...(qualifierSet === undefined ? {} : { qualifierSet }),
		expectedPolicySet: new Set(expectedPolicySet),
		parentKeys: new Set(parentKeys),
		childKeys: new Set<string>(),
	};
}

/**
 * Policy node key.
 *
 * @param depth The depth value.
 * @param validPolicy The valid policy value.
 * @returns The computed value.
 */
function policyNodeKey(depth: number, validPolicy: string): string {
	return `${String(depth)}:${validPolicy}`;
}

/**
 * Process policy state.
 *
 * @param chain The chain value.
 * @param state The current state value.
 */
function processPolicyState(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): void {
	const leafDepth = chain.length - 1;
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const certificate = chain[index];
		if (certificate === undefined) {
			continue;
		}
		const depth = leafDepth - index;
		processPolicyCertificate(state, certificate, depth, depth === leafDepth);
	}
}

/**
 * Derives policy validation outcome.
 *
 * @param chain The chain value.
 * @param state The current state value.
 * @returns The derived policy validation outcome.
 */
function derivePolicyValidationOutcome(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationOutcome {
	const authorityConstrainedPolicies = collectAuthorityConstrainedPolicies(
		chain,
		state.validPolicyGraph,
	);
	const rootDomainPolicies = collectRootDomainPolicies(chain, state.validPolicyGraph);
	return {
		authorityConstrainedPolicies: [...authorityConstrainedPolicies.values()].sort(comparePolicies),
		userConstrainedPolicies: deriveUserConstrainedPolicies(
			authorityConstrainedPolicies,
			rootDomainPolicies,
			state.initialPolicySet,
		),
	};
}

/**
 * Collects authority constrained policies.
 *
 * @param chain The chain value.
 * @param graph The graph value.
 * @returns The collected authority constrained policies.
 */
function collectAuthorityConstrainedPolicies(
	chain: readonly ParsedCertificate[],
	graph: PolicyGraph | null,
): ReadonlyMap<string, ConstrainedPolicy> {
	if (graph === null) {
		return new Map<string, ConstrainedPolicy>();
	}
	const leafDepth = chain.length - 1;
	const finalDepth = graph.nodesByDepth[leafDepth];
	if (finalDepth === undefined) {
		return new Map<string, ConstrainedPolicy>();
	}
	const authorityPolicies = new Map<string, ConstrainedPolicy>();
	for (const [key, node] of finalDepth) {
		if (node.validPolicy === OIDS.anyPolicy) {
			authorityPolicies.set(
				OIDS.anyPolicy,
				buildConstrainedPolicy(OIDS.anyPolicy, node.qualifierSet),
			);
			continue;
		}
		if (reachesAuthorityRoot(graph, key)) {
			authorityPolicies.set(
				node.validPolicy,
				buildConstrainedPolicy(node.validPolicy, node.qualifierSet),
			);
		}
	}
	return authorityPolicies;
}

/**
 * Reaches authority root.
 *
 * @param graph The graph value.
 * @param nodeKey The node key value.
 * @returns The computed value.
 */
function reachesAuthorityRoot(graph: PolicyGraph, nodeKey: string): boolean {
	const pending = [nodeKey];
	const visited = new Set<string>();
	while (pending.length > 0) {
		const currentKey = pending.pop();
		if (currentKey === undefined || visited.has(currentKey)) {
			continue;
		}
		visited.add(currentKey);
		const node = getPolicyGraphNode(graph, currentKey);
		if (node === undefined) {
			continue;
		}
		for (const parentKey of node.parentKeys) {
			const parent = getPolicyGraphNode(graph, parentKey);
			if (parent === undefined) {
				continue;
			}
			if (parent.depth === 0 && parent.validPolicy === OIDS.anyPolicy) {
				return true;
			}
			pending.push(parentKey);
		}
	}
	return false;
}

/**
 * Collects root domain policies.
 *
 * @param chain The chain value.
 * @param graph The graph value.
 * @returns The collected root domain policies.
 */
function collectRootDomainPolicies(
	chain: readonly ParsedCertificate[],
	graph: PolicyGraph | null,
): ReadonlyMap<string, ConstrainedPolicy> {
	if (graph === null) {
		return new Map<string, ConstrainedPolicy>();
	}
	const leafDepth = chain.length - 1;
	const finalDepth = graph.nodesByDepth[leafDepth];
	if (finalDepth === undefined) {
		return new Map<string, ConstrainedPolicy>();
	}
	const rootPolicies = new Map<string, ConstrainedPolicy>();
	for (const [key, node] of finalDepth) {
		if (node.validPolicy === OIDS.anyPolicy) {
			rootPolicies.set(OIDS.anyPolicy, buildConstrainedPolicy(OIDS.anyPolicy, node.qualifierSet));
			continue;
		}
		collectAuthorityConstrainedPolicyRoots(graph, key, rootPolicies);
	}
	return rootPolicies;
}

/**
 * Collects authority constrained policy roots.
 *
 * @param graph The graph value.
 * @param nodeKey The node key value.
 * @param authorityPolicies The authority policies value.
 */
function collectAuthorityConstrainedPolicyRoots(
	graph: PolicyGraph,
	nodeKey: string,
	authorityPolicies: Map<string, ConstrainedPolicy>,
): void {
	const pending = [nodeKey];
	const visited = new Set<string>();
	while (pending.length > 0) {
		const currentKey = pending.pop();
		if (currentKey === undefined || visited.has(currentKey)) {
			continue;
		}
		visited.add(currentKey);
		const node = getPolicyGraphNode(graph, currentKey);
		if (node === undefined) {
			continue;
		}
		for (const parentKey of node.parentKeys) {
			const parent = getPolicyGraphNode(graph, parentKey);
			if (parent === undefined) {
				continue;
			}
			if (parent.depth === 0 && parent.validPolicy === OIDS.anyPolicy) {
				if (node.validPolicy !== OIDS.anyPolicy) {
					authorityPolicies.set(
						node.validPolicy,
						buildConstrainedPolicy(
							node.validPolicy,
							currentKey === nodeKey ? node.qualifierSet : undefined,
						),
					);
				}
				continue;
			}
			pending.push(parentKey);
		}
	}
}

/**
 * Derives user constrained policies.
 *
 * @param finalAuthorityConstrainedPolicies The final authority constrained policies value.
 * @param rootDomainPolicies The root domain policies value.
 * @param initialPolicySet The initial policy set value.
 * @returns The derived user constrained policies.
 */
function deriveUserConstrainedPolicies(
	finalAuthorityConstrainedPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	rootDomainPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	initialPolicySet: readonly string[] | 'any',
): readonly ConstrainedPolicy[] {
	if (initialPolicySet === 'any') {
		return [...finalAuthorityConstrainedPolicies.values()].sort(comparePolicies);
	}
	const anyPolicy = rootDomainPolicies.get(OIDS.anyPolicy);
	const constrained = new Map<string, ConstrainedPolicy>();
	for (const policyIdentifier of initialPolicySet) {
		const direct = rootDomainPolicies.get(policyIdentifier);
		if (direct !== undefined) {
			constrained.set(policyIdentifier, direct);
			continue;
		}
		if (anyPolicy !== undefined) {
			constrained.set(
				policyIdentifier,
				buildConstrainedPolicy(policyIdentifier, anyPolicy.policyQualifiers),
			);
		}
	}
	return [...constrained.values()];
}

/**
 * Builds constrained policy.
 *
 * @param policyIdentifier The policy identifier value.
 * @param policyQualifiers The policy qualifiers value.
 * @returns The built constrained policy.
 */
function buildConstrainedPolicy(
	policyIdentifier: string,
	policyQualifiers: readonly PolicyQualifierInfo[] | undefined,
): ConstrainedPolicy {
	return {
		policyIdentifier,
		...(policyQualifiers === undefined ? {} : { policyQualifiers }),
	};
}

/**
 * Compares policies.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
function comparePolicies(left: ConstrainedPolicy, right: ConstrainedPolicy): number {
	return left.policyIdentifier.localeCompare(right.policyIdentifier);
}

/**
 * Describe final policies.
 *
 * @param policies The policies value.
 * @returns The computed value.
 */
function describeFinalPolicies(policies: readonly ConstrainedPolicy[]): string {
	return policies.length === 0
		? '<none>'
		: policies.map((policy) => policy.policyIdentifier).join(',');
}

/**
 * Process policy certificate.
 *
 * @param state The current state value.
 * @param certificate The certificate input.
 * @param depth The depth value.
 * @param isLeaf The is leaf value.
 */
function processPolicyCertificate(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
	depth: number,
	isLeaf: boolean,
): void {
	const certificatePolicies = normalizeCertificatePolicies(certificate.certificatePolicies);
	if (state.validPolicyGraph !== null && certificatePolicies === undefined) {
		state.validPolicyGraph = null;
	} else if (state.validPolicyGraph !== null && certificatePolicies !== undefined) {
		applyCertificatePolicyStep(
			state.validPolicyGraph,
			certificatePolicies,
			depth,
			state.inhibitAnyPolicy > 0 || (!isLeaf && isSelfIssued(certificate)),
		);
		if (certificate.policyMappings !== undefined) {
			applyPolicyMappingsStep(
				state.validPolicyGraph,
				depth,
				certificate.policyMappings,
				state.inhibitPolicyMapping > 0,
			);
		}
	}
	updatePolicyCounters(state, certificate, isLeaf);
}

/**
 * Normalizes certificate policies.
 *
 * @param policies The policies value.
 * @returns The computed value.
 */
function normalizeCertificatePolicies(
	policies: readonly PolicyInformation[] | undefined,
): Map<string, PolicyInformation> | undefined {
	if (policies === undefined) {
		return undefined;
	}
	const byOid = new Map<string, PolicyInformation>();
	for (const policy of policies) {
		if (!byOid.has(policy.policyIdentifier)) {
			byOid.set(policy.policyIdentifier, policy);
		}
	}
	return byOid;
}

/**
 * Apply certificate policy step.
 *
 * @param graph The graph value.
 * @param certificatePolicies The certificate policies value.
 * @param depth The depth value.
 * @param allowAnyPolicyExpansion The allow any policy expansion value.
 */
function applyCertificatePolicyStep(
	graph: PolicyGraph,
	certificatePolicies: ReadonlyMap<string, PolicyInformation>,
	depth: number,
	allowAnyPolicyExpansion: boolean,
): void {
	const previousDepth = graph.nodesByDepth[depth - 1] ?? new Map<string, PolicyGraphNode>();
	const currentDepth = new Map<string, PolicyGraphNode>();
	graph.nodesByDepth[depth] = currentDepth;
	const anyPolicyInfo = certificatePolicies.get(OIDS.anyPolicy);
	const previousAnyPolicy = previousDepth.get(policyNodeKey(depth - 1, OIDS.anyPolicy));

	for (const policy of certificatePolicies.values()) {
		if (policy.policyIdentifier === OIDS.anyPolicy) {
			continue;
		}
		const matchingParents = collectParentsForExpectedPolicy(previousDepth, policy.policyIdentifier);
		if (matchingParents.length > 0) {
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				policy.policyIdentifier,
				policy.policyQualifiers,
				matchingParents,
				[policy.policyIdentifier],
			);
		}
	}

	if (previousAnyPolicy !== undefined) {
		const previousAnyPolicyKey = policyNodeKey(depth - 1, OIDS.anyPolicy);
		for (const policy of certificatePolicies.values()) {
			if (policy.policyIdentifier === OIDS.anyPolicy) {
				continue;
			}
			if (currentDepth.has(policyNodeKey(depth, policy.policyIdentifier))) {
				continue;
			}
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				policy.policyIdentifier,
				policy.policyQualifiers,
				[previousAnyPolicyKey],
				[policy.policyIdentifier],
			);
		}
	}

	if (anyPolicyInfo !== undefined && allowAnyPolicyExpansion) {
		for (const [validPolicy, parentKeys] of collectExpectedPolicyParents(previousDepth)) {
			if (currentDepth.has(policyNodeKey(depth, validPolicy))) {
				continue;
			}
			const expansionParents =
				validPolicy === OIDS.anyPolicy
					? previousAnyPolicy === undefined
						? []
						: [policyNodeKey(depth - 1, OIDS.anyPolicy)]
					: parentKeys;
			if (expansionParents.length === 0) {
				continue;
			}
			addOrMergePolicyNode(
				graph,
				currentDepth,
				depth,
				validPolicy,
				anyPolicyInfo.policyQualifiers,
				expansionParents,
				[validPolicy],
			);
		}
	}

	prunePolicyGraph(graph, depth - 1);
}

/**
 * Collects parents for expected policy.
 *
 * @param nodes The nodes value.
 * @param policyIdentifier The policy identifier value.
 * @returns The collected parents for expected policy.
 */
function collectParentsForExpectedPolicy(
	nodes: ReadonlyMap<string, PolicyGraphNode>,
	policyIdentifier: string,
): string[] {
	const parents: string[] = [];
	for (const [key, node] of nodes) {
		if (node.expectedPolicySet.has(policyIdentifier)) {
			parents.push(key);
		}
	}
	return parents;
}

/**
 * Collects expected policy parents.
 *
 * @param nodes The nodes value.
 * @returns The collected expected policy parents.
 */
function collectExpectedPolicyParents(
	nodes: ReadonlyMap<string, PolicyGraphNode>,
): Map<string, string[]> {
	const parentsByPolicy = new Map<string, string[]>();
	for (const [key, node] of nodes) {
		for (const expectedPolicy of node.expectedPolicySet) {
			const parents = parentsByPolicy.get(expectedPolicy);
			if (parents === undefined) {
				parentsByPolicy.set(expectedPolicy, [key]);
				continue;
			}
			parents.push(key);
		}
	}
	return parentsByPolicy;
}

/**
 * Adds or merge policy node.
 *
 * @param graph The graph value.
 * @param currentDepth The current depth value.
 * @param depth The depth value.
 * @param validPolicy The valid policy value.
 * @param qualifierSet The qualifier set value.
 * @param parentKeys The parent keys value.
 * @param expectedPolicySet The expected policy set value.
 */
function addOrMergePolicyNode(
	graph: PolicyGraph,
	currentDepth: Map<string, PolicyGraphNode>,
	depth: number,
	validPolicy: string,
	qualifierSet: readonly PolicyQualifierInfo[] | undefined,
	parentKeys: readonly string[],
	expectedPolicySet: readonly string[],
): void {
	const key = policyNodeKey(depth, validPolicy);
	const existing = currentDepth.get(key);
	if (existing !== undefined) {
		for (const parentKey of parentKeys) {
			existing.parentKeys.add(parentKey);
			getPolicyGraphNode(graph, parentKey)?.childKeys.add(key);
		}
		for (const expectedPolicy of expectedPolicySet) {
			existing.expectedPolicySet.add(expectedPolicy);
		}
		if (existing.qualifierSet === undefined && qualifierSet !== undefined) {
			existing.qualifierSet = qualifierSet;
		}
		return;
	}
	const node = createPolicyGraphNode(
		depth,
		validPolicy,
		qualifierSet,
		expectedPolicySet,
		parentKeys,
	);
	currentDepth.set(key, node);
	for (const parentKey of parentKeys) {
		getPolicyGraphNode(graph, parentKey)?.childKeys.add(key);
	}
}

/**
 * Returns policy graph node.
 *
 * @param graph The graph value.
 * @param key The key value.
 * @returns The policy graph node.
 */
function getPolicyGraphNode(graph: PolicyGraph, key: string): PolicyGraphNode | undefined {
	const separator = key.indexOf(':');
	if (separator <= 0) {
		return undefined;
	}
	const depthString = key.slice(0, separator);
	const depth = Number.parseInt(depthString, 10);
	if (Number.isNaN(depth)) {
		return undefined;
	}
	return graph.nodesByDepth[depth]?.get(key);
}

/**
 * Prune policy graph.
 *
 * @param graph The graph value.
 * @param maxDepth The max depth value.
 */
function prunePolicyGraph(graph: PolicyGraph, maxDepth: number): void {
	for (let depth = maxDepth; depth >= 0; depth -= 1) {
		const nodes = graph.nodesByDepth[depth];
		if (nodes === undefined) {
			continue;
		}
		for (const key of [...nodes.keys()]) {
			const node = nodes.get(key);
			if (node === undefined || node.childKeys.size > 0) {
				continue;
			}
			deletePolicyGraphNode(graph, key);
		}
	}
}

/**
 * Delete policy graph node.
 *
 * @param graph The graph value.
 * @param key The key value.
 */
function deletePolicyGraphNode(graph: PolicyGraph, key: string): void {
	const node = getPolicyGraphNode(graph, key);
	if (node === undefined) {
		return;
	}
	graph.nodesByDepth[node.depth]?.delete(key);
	for (const parentKey of node.parentKeys) {
		const parent = getPolicyGraphNode(graph, parentKey);
		if (parent === undefined) {
			continue;
		}
		parent.childKeys.delete(key);
		if (parent.childKeys.size === 0) {
			deletePolicyGraphNode(graph, parentKey);
		}
	}
}

/**
 * Apply policy mappings step.
 *
 * @param graph The graph value.
 * @param depth The depth value.
 * @param mappings The mappings value.
 * @param mappingAllowed The mapping allowed value.
 */
function applyPolicyMappingsStep(
	graph: PolicyGraph,
	depth: number,
	mappings: readonly {
		/**
		 * Carries the issuer domain policy value.
		 */
		readonly issuerDomainPolicy: string;
		/**
		 * Carries the subject domain policy value.
		 */
		readonly subjectDomainPolicy: string;
	}[],
	mappingAllowed: boolean,
): void {
	const currentDepth = graph.nodesByDepth[depth];
	if (currentDepth === undefined) {
		return;
	}
	const groupedMappings = new Map<string, string[]>();
	for (const mapping of mappings) {
		const subjectPolicies = groupedMappings.get(mapping.issuerDomainPolicy);
		if (subjectPolicies === undefined) {
			groupedMappings.set(mapping.issuerDomainPolicy, [mapping.subjectDomainPolicy]);
			continue;
		}
		subjectPolicies.push(mapping.subjectDomainPolicy);
	}
	const anyPolicyNode = currentDepth.get(policyNodeKey(depth, OIDS.anyPolicy));
	for (const [issuerDomainPolicy, subjectDomainPolicies] of groupedMappings) {
		const nodeKey = policyNodeKey(depth, issuerDomainPolicy);
		const node = currentDepth.get(nodeKey);
		if (mappingAllowed) {
			if (node !== undefined) {
				node.expectedPolicySet = new Set(subjectDomainPolicies);
				continue;
			}
			if (anyPolicyNode !== undefined) {
				addOrMergePolicyNode(
					graph,
					currentDepth,
					depth,
					issuerDomainPolicy,
					anyPolicyNode.qualifierSet,
					[...anyPolicyNode.parentKeys],
					subjectDomainPolicies,
				);
			}
			continue;
		}
		if (node !== undefined) {
			deletePolicyGraphNode(graph, nodeKey);
		}
	}
	prunePolicyGraph(graph, depth - 1);
}

/**
 * Update policy counters.
 *
 * @param state The current state value.
 * @param certificate The certificate input.
 * @param isLeaf The is leaf value.
 */
function updatePolicyCounters(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
	isLeaf: boolean,
): void {
	if (isLeaf) {
		if (state.explicitPolicy > 0) {
			state.explicitPolicy -= 1;
		}
		if (certificate.policyConstraints?.requireExplicitPolicy === 0) {
			state.explicitPolicy = 0;
		}
		return;
	}
	if (!isSelfIssued(certificate)) {
		if (state.explicitPolicy > 0) {
			state.explicitPolicy -= 1;
		}
		if (state.inhibitPolicyMapping > 0) {
			state.inhibitPolicyMapping -= 1;
		}
		if (state.inhibitAnyPolicy > 0) {
			state.inhibitAnyPolicy -= 1;
		}
	}
	const policyConstraints = certificate.policyConstraints;
	if (
		policyConstraints?.requireExplicitPolicy !== undefined &&
		policyConstraints.requireExplicitPolicy < state.explicitPolicy
	) {
		state.explicitPolicy = policyConstraints.requireExplicitPolicy;
	}
	if (
		policyConstraints?.inhibitPolicyMapping !== undefined &&
		policyConstraints.inhibitPolicyMapping < state.inhibitPolicyMapping
	) {
		state.inhibitPolicyMapping = policyConstraints.inhibitPolicyMapping;
	}
	if (
		certificate.inhibitAnyPolicy !== undefined &&
		certificate.inhibitAnyPolicy.skipCerts < state.inhibitAnyPolicy
	) {
		state.inhibitAnyPolicy = certificate.inhibitAnyPolicy.skipCerts;
	}
}

/**
 * Returns whether self issued.
 *
 * @param certificate The certificate input.
 * @returns Whether the condition holds.
 */
function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}
