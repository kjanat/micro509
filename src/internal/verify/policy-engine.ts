/**
 * Internal RFC 9618 policy-validation engine.
 *
 * Tracks the policy graph and counter state through each certificate in a
 * chain, then derives the {@linkcode PolicyValidationOutcome}.
 *
 * @module
 */

import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn.ts';
import type { Micro509Error, Result } from '#micro509/result/result.ts';
import type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from '#micro509/verify/policy.ts';
import type { PolicyInformation, PolicyQualifierInfo } from '#micro509/x509/extensions.ts';
import type { ParsedCertificate } from '#micro509/x509/parse.ts';

/**
 * Mutable state threaded through each step of the policy-validation walk.
 *
 * Created by {@linkcode createPolicyValidationState}, consumed by
 * {@linkcode evaluatePolicyChain}.
 */
export interface PolicyValidationState {
	/** Caller-requested acceptable policies, or `'any'`. */
	initialPolicySet: readonly string[] | 'any';
	/** Remaining certificates before explicit-policy enforcement kicks in. */
	explicitPolicy: number;
	/** Remaining certificates before policy mappings are disallowed. */
	inhibitPolicyMapping: number;
	/** Remaining certificates before anyPolicy expansion stops. */
	inhibitAnyPolicy: number;
	/** The RFC 9618 policy graph; `null` when the graph has been emptied. */
	validPolicyGraph: PolicyGraph | null;
}

/** Discriminant codes for policy-validation failures. */
export type PolicyValidationFailureCode =
	| 'explicit_policy_required'
	| 'initial_policy_set_not_satisfied';

/** Diagnostic context for a policy-validation failure. */
export interface PolicyValidationFailureDetails {
	/** Description of the policies the caller expected. */
	readonly expected: string;
	/** Comma-joined OIDs (or `"<none>"`) that actually survived processing. */
	readonly actual: string;
}

/** A policy-validation failure with structured diagnostic details. */
export interface PolicyValidationFailure
	extends Micro509Error<PolicyValidationFailureCode, PolicyValidationFailureDetails> {}

/** Success with {@linkcode PolicyValidationOutcome}, or a {@linkcode PolicyValidationFailure}. */
export type PolicyValidationResult = Result<PolicyValidationOutcome, PolicyValidationFailure>;

/** One node in the RFC 9618 policy graph, keyed by `depth:policyOID`. */
interface PolicyGraphNode {
	/** Graph depth (0 = root anyPolicy node). */
	depth: number;
	/** The policy OID this node represents at its depth. */
	validPolicy: string;
	/** Policy qualifiers inherited from the certificate that created this node. */
	qualifierSet?: readonly PolicyQualifierInfo[];
	/** OIDs this node expects to see in the next certificate's policies. */
	expectedPolicySet: Set<string>;
	/** Keys of parent nodes in the previous depth level. */
	parentKeys: Set<string>;
	/** Keys of child nodes in the next depth level. */
	childKeys: Set<string>;
}

/** The full RFC 9618 valid-policy graph, indexed by depth level. */
interface PolicyGraph {
	/** Each index `i` holds the nodes at depth `i`, keyed by `"depth:oid"`. */
	nodesByDepth: Map<string, PolicyGraphNode>[];
}

/**
 * Initializes mutable policy state from caller options.
 *
 * Counter values default to `chainLength + 1` (effectively disabled) unless
 * the corresponding input flag is `true`.
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
 * Walks the chain root-to-leaf, updating policy state per certificate,
 * then checks whether the resulting policy set satisfies caller requirements.
 */
export function evaluatePolicyChain(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationResult {
	if (chain.length === 0) {
		throw new RangeError('policy validation requires at least one certificate');
	}
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

/** Builds the depth-0 graph with a single anyPolicy root node. */
function createInitialPolicyGraph(): PolicyGraph {
	const rootNode = createPolicyGraphNode(0, OIDS.anyPolicy, undefined, [OIDS.anyPolicy], []);
	return {
		nodesByDepth: [new Map([[policyNodeKey(0, OIDS.anyPolicy), rootNode]])],
	};
}

/** Constructs a new {@linkcode PolicyGraphNode} with empty child-key set. */
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

/** Canonical map key for a graph node: `"depth:policyOID"`. */
function policyNodeKey(depth: number, validPolicy: string): string {
	return `${String(depth)}:${validPolicy}`;
}

/** Iterates root-to-leaf (skipping root), applying each certificate's policies to the state. */
function processPolicyState(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): void {
	const leafDepth = chain.length - 1;
	for (let index = chain.length - 2; index >= 0; index -= 1) {
		const certificate = chain[index];
		if (certificate === undefined) {
			throw new Error(
				`missing certificate at chain index ${String(index)} (chain length ${String(chain.length)})`,
			);
		}
		const depth = leafDepth - index;
		processPolicyCertificate(state, certificate, depth, depth === leafDepth);
	}
}

/** Extracts the final authority- and user-constrained policy sets from the completed graph. */
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

/** Collects leaf-depth policies whose graph paths trace back to the anyPolicy root. */
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

/** DFS upward through parent links to check if the node ultimately connects to the depth-0 anyPolicy root. */
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

/** Like authority-constrained, but records the OID at the depth-1 node that connects to root. */
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

/** Walks parent links upward, collecting the depth-1 OID that first connects to the root anyPolicy. */
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
				// Record the depth-1 policy that connects to root
				// If the depth-1 node is anyPolicy itself, record anyPolicy so it can satisfy
				// any policy in the initial-policy-set via deriveUserConstrainedPolicies
				authorityPolicies.set(
					node.validPolicy,
					buildConstrainedPolicy(
						node.validPolicy,
						currentKey === nodeKey ? node.qualifierSet : undefined,
					),
				);
				continue;
			}
			pending.push(parentKey);
		}
	}
}

/** Intersects root-domain policies with the caller's initial-policy-set. */
function deriveUserConstrainedPolicies(
	finalAuthorityConstrainedPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	rootDomainPolicies: ReadonlyMap<string, ConstrainedPolicy>,
	initialPolicySet: readonly string[] | 'any',
): readonly ConstrainedPolicy[] {
	if (initialPolicySet === 'any') {
		return [...finalAuthorityConstrainedPolicies.values()].sort(comparePolicies);
	}
	const anyPolicy = rootDomainPolicies.get(OIDS.anyPolicy);
	// If the EE asserts anyPolicy, it satisfies any policy in initial-policy-set
	const eeHasAnyPolicy = finalAuthorityConstrainedPolicies.has(OIDS.anyPolicy);
	const constrained = new Map<string, ConstrainedPolicy>();
	for (const policyIdentifier of initialPolicySet) {
		const direct = rootDomainPolicies.get(policyIdentifier);
		if (direct !== undefined) {
			constrained.set(policyIdentifier, direct);
			continue;
		}
		// anyPolicy can satisfy a requested policy if:
		// 1. The EE asserts the specific policy (finalAuthorityConstrainedPolicies.has), OR
		// 2. The EE itself asserts anyPolicy (eeHasAnyPolicy)
		if (
			anyPolicy !== undefined &&
			(finalAuthorityConstrainedPolicies.has(policyIdentifier) || eeHasAnyPolicy)
		) {
			constrained.set(
				policyIdentifier,
				buildConstrainedPolicy(policyIdentifier, anyPolicy.policyQualifiers),
			);
		}
	}
	return [...constrained.values()];
}

/** Constructs a {@linkcode ConstrainedPolicy}, omitting qualifiers when absent. */
function buildConstrainedPolicy(
	policyIdentifier: string,
	policyQualifiers: readonly PolicyQualifierInfo[] | undefined,
): ConstrainedPolicy {
	return {
		policyIdentifier,
		...(policyQualifiers === undefined ? {} : { policyQualifiers }),
	};
}

/** Lexicographic comparator for sorting policies by OID string. */
function comparePolicies(left: ConstrainedPolicy, right: ConstrainedPolicy): number {
	return left.policyIdentifier.localeCompare(right.policyIdentifier);
}

/** Human-readable comma-joined OID list for error messages; `"<none>"` when empty. */
function describeFinalPolicies(policies: readonly ConstrainedPolicy[]): string {
	return policies.length === 0
		? '<none>'
		: policies.map((policy) => policy.policyIdentifier).join(',');
}

/** Applies one certificate's policies, mappings, and constraints to the running state. */
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

/** Deduplicates certificate policies by OID, keeping the first occurrence. */
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

/** Extends the policy graph by one depth level using a certificate's policy extension. */
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

/** Finds all previous-depth nodes whose expectedPolicySet contains the given OID. */
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

/** Groups all previous-depth nodes by each OID in their expectedPolicySet. */
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

/** Inserts a node at the current depth, or merges parents/expected-policies into an existing one. */
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

/** Looks up a node by its `"depth:oid"` key, parsing the depth prefix. */
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

/** Removes childless leaf nodes bottom-up, cascading deletions through parent links. */
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

/** Removes a node and recursively prunes its parents if they become childless. */
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

/** Applies issuer→subject policy mappings at the current depth, or deletes mapped nodes when disallowed. */
function applyPolicyMappingsStep(
	graph: PolicyGraph,
	depth: number,
	mappings: readonly {
		readonly issuerDomainPolicy: string;
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
		if (
			mapping.issuerDomainPolicy === OIDS.anyPolicy ||
			mapping.subjectDomainPolicy === OIDS.anyPolicy
		) {
			continue;
		}
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

/** Decrements explicitPolicy / inhibitPolicyMapping / inhibitAnyPolicy and applies policyConstraints overrides. */
function updatePolicyCounters(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
	isLeaf: boolean,
): void {
	if (isLeaf) {
		if (state.explicitPolicy > 0) {
			state.explicitPolicy -= 1;
		}
		if (isNonNegativeInteger(certificate.policyConstraints?.requireExplicitPolicy)) {
			if (certificate.policyConstraints.requireExplicitPolicy === 0) {
				state.explicitPolicy = 0;
			}
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
		isNonNegativeInteger(policyConstraints?.requireExplicitPolicy) &&
		policyConstraints.requireExplicitPolicy < state.explicitPolicy
	) {
		state.explicitPolicy = policyConstraints.requireExplicitPolicy;
	}
	if (
		isNonNegativeInteger(policyConstraints?.inhibitPolicyMapping) &&
		policyConstraints.inhibitPolicyMapping < state.inhibitPolicyMapping
	) {
		state.inhibitPolicyMapping = policyConstraints.inhibitPolicyMapping;
	}
	if (
		isNonNegativeInteger(certificate.inhibitAnyPolicy?.skipCerts) &&
		certificate.inhibitAnyPolicy.skipCerts < state.inhibitAnyPolicy
	) {
		state.inhibitAnyPolicy = certificate.inhibitAnyPolicy.skipCerts;
	}
}

function isNonNegativeInteger(value: number | undefined): value is number {
	return value !== undefined && Number.isInteger(value) && value >= 0;
}

/** A certificate is self-issued when subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
function isSelfIssued(certificate: ParsedCertificate): boolean {
	return compareDistinguishedNames(certificate.subject, certificate.issuer);
}
