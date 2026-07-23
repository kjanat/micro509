/**
 * Internal RFC 9618 policy-validation engine.
 *
 * Tracks the policy graph and counter state through each certificate in a
 * chain, then derives the {@linkcode PolicyValidationOutcome}.
 *
 * @module
 */

import { OIDS } from '#micro509/internal/asn1/oids';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn';
import type { Micro509Error, Result } from '#micro509/result/result';
import type {
	ConstrainedPolicy,
	PolicyValidationInput,
	PolicyValidationOutcome,
} from '#micro509/verify/policy';
import type { PolicyInformation, PolicyQualifierInfo } from '#micro509/x509/extensions';
import type { ParsedCertificate } from '#micro509/x509/parse';

/**
 * Mutable state threaded through each step of the policy-validation walk.
 *
 * Created by {@linkcode createPolicyValidationState}, consumed by
 * {@linkcode evaluatePolicyChain}.
 */
export interface PolicyValidationState {
	/** Caller-requested acceptable policies, or `'any'`. */
	readonly initialPolicySet: readonly string[] | 'any';
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
export interface PolicyGraphNode {
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
export interface PolicyGraph {
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
	if (chain.length === 1) {
		const certificate = chain[0];
		if (certificate === undefined) {
			throw new Error(
				`missing certificate at chain index 0 (chain length ${String(chain.length)})`,
			);
		}
		processPolicyCertificate(state, certificate, 1, true);
		return;
	}
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

/** Extracts the authority- and user-constrained policy sets from the completed graph (RFC 9618 §5.5 step (g)). */
function derivePolicyValidationOutcome(
	chain: readonly ParsedCertificate[],
	state: PolicyValidationState,
): PolicyValidationOutcome {
	const authority = collectAuthorityConstrainedPolicies(chain, state.validPolicyGraph);
	return {
		authorityConstrainedPolicies: [...authority.values()].sort(comparePolicies),
		userConstrainedPolicies: deriveUserConstrainedPolicies(authority, state.initialPolicySet),
	};
}

/**
 * RFC 9618 §5.5 (g)(2)-(4) authority_constrained_policy_set. The
 * valid_policy_node_set is every graph node, at any depth, whose valid_policy is
 * not anyPolicy and whose single parent is an anyPolicy node, plus a depth-n
 * anyPolicy node when present. Pruning has already removed nodes with no path to
 * the leaf, so the whole graph is the final tree.
 */
function collectAuthorityConstrainedPolicies(
	chain: readonly ParsedCertificate[],
	graph: PolicyGraph | null,
): ReadonlyMap<string, ConstrainedPolicy> {
	const authority = new Map<string, ConstrainedPolicy>();
	if (graph === null) {
		return authority;
	}
	for (const depthNodes of graph.nodesByDepth) {
		for (const node of depthNodes.values()) {
			if (node.validPolicy === OIDS.anyPolicy || node.parentKeys.size !== 1) {
				continue;
			}
			if (getSingleParent(graph, node)?.validPolicy === OIDS.anyPolicy) {
				authority.set(
					node.validPolicy,
					buildConstrainedPolicy(node.validPolicy, node.qualifierSet),
				);
			}
		}
	}
	const leafDepth = Math.max(1, chain.length - 1);
	const leafAnyPolicy = graph.nodesByDepth[leafDepth]?.get(
		policyNodeKey(leafDepth, OIDS.anyPolicy),
	);
	if (leafAnyPolicy !== undefined) {
		authority.set(
			OIDS.anyPolicy,
			buildConstrainedPolicy(OIDS.anyPolicy, leafAnyPolicy.qualifierSet),
		);
	}
	return authority;
}

/** Returns the sole parent of a node whose parent list has exactly one entry. */
function getSingleParent(graph: PolicyGraph, node: PolicyGraphNode): PolicyGraphNode | undefined {
	const parentKey = [...node.parentKeys][0];
	return parentKey === undefined ? undefined : getPolicyGraphNode(graph, parentKey);
}

/**
 * RFC 9618 §5.5 (g)(5)-(6) user_constrained_policy_set. It equals the
 * authority-constrained set when the initial-policy-set is anyPolicy. Otherwise
 * it keeps the members named in the initial-policy-set, and, when the authority
 * set holds anyPolicy, adds the remaining requested OIDs with anyPolicy's
 * qualifiers.
 */
function deriveUserConstrainedPolicies(
	authority: ReadonlyMap<string, ConstrainedPolicy>,
	initialPolicySet: readonly string[] | 'any',
): readonly ConstrainedPolicy[] {
	if (initialPolicySet === 'any') {
		return [...authority.values()].sort(comparePolicies);
	}
	const constrained = new Map<string, ConstrainedPolicy>();
	for (const [policyIdentifier, policy] of authority) {
		if (initialPolicySet.includes(policyIdentifier)) {
			constrained.set(policyIdentifier, policy);
		}
	}
	const anyPolicy = authority.get(OIDS.anyPolicy);
	if (anyPolicy !== undefined) {
		for (const policyIdentifier of initialPolicySet) {
			if (!constrained.has(policyIdentifier)) {
				constrained.set(
					policyIdentifier,
					buildConstrainedPolicy(policyIdentifier, anyPolicy.policyQualifiers),
				);
			}
		}
	}
	return [...constrained.values()].sort(comparePolicies);
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
	const previousAnyPolicyKey = policyNodeKey(depth - 1, OIDS.anyPolicy);

	addPolicyNodesFromExpectedParents(graph, currentDepth, previousDepth, certificatePolicies, depth);

	if (previousAnyPolicy !== undefined) {
		addPolicyNodesFromPreviousAnyPolicy(
			graph,
			currentDepth,
			certificatePolicies,
			depth,
			previousAnyPolicyKey,
		);
	}

	if (anyPolicyInfo !== undefined && allowAnyPolicyExpansion) {
		addAnyPolicyExpansionNodes(
			graph,
			currentDepth,
			previousDepth,
			depth,
			anyPolicyInfo,
			previousAnyPolicyKey,
			previousAnyPolicy !== undefined,
		);
	}

	prunePolicyGraph(graph, depth - 1);
}

/** Adds explicit certificate-policy nodes whose expected policies match parent nodes. */
function addPolicyNodesFromExpectedParents(
	graph: PolicyGraph,
	currentDepth: Map<string, PolicyGraphNode>,
	previousDepth: ReadonlyMap<string, PolicyGraphNode>,
	certificatePolicies: ReadonlyMap<string, PolicyInformation>,
	depth: number,
): void {
	for (const policy of certificatePolicies.values()) {
		if (policy.policyIdentifier === OIDS.anyPolicy) {
			continue;
		}
		const matchingParents = collectParentsForExpectedPolicy(previousDepth, policy.policyIdentifier);
		if (matchingParents.length === 0) {
			continue;
		}
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

function addPolicyNodesFromPreviousAnyPolicy(
	graph: PolicyGraph,
	currentDepth: Map<string, PolicyGraphNode>,
	certificatePolicies: ReadonlyMap<string, PolicyInformation>,
	depth: number,
	previousAnyPolicyKey: string,
): void {
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

/** Expands an accepted anyPolicy entry into the policies expected by the previous depth. */
function addAnyPolicyExpansionNodes(
	graph: PolicyGraph,
	currentDepth: Map<string, PolicyGraphNode>,
	previousDepth: ReadonlyMap<string, PolicyGraphNode>,
	depth: number,
	anyPolicyInfo: PolicyInformation,
	previousAnyPolicyKey: string,
	hasPreviousAnyPolicy: boolean,
): void {
	for (const [validPolicy, parentKeys] of collectExpectedPolicyParents(previousDepth)) {
		if (currentDepth.has(policyNodeKey(depth, validPolicy))) {
			continue;
		}
		const expansionParents = collectAnyPolicyExpansionParents(
			validPolicy,
			parentKeys,
			previousAnyPolicyKey,
			hasPreviousAnyPolicy,
		);
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

function collectAnyPolicyExpansionParents(
	validPolicy: string,
	parentKeys: readonly string[],
	previousAnyPolicyKey: string,
	hasPreviousAnyPolicy: boolean,
): readonly string[] {
	if (validPolicy !== OIDS.anyPolicy) {
		return parentKeys;
	}
	return hasPreviousAnyPolicy ? [previousAnyPolicyKey] : [];
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
		for (const key of nodes.keys()) {
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
		updateLeafPolicyCounter(state, certificate);
		return;
	}
	if (!isSelfIssued(certificate)) {
		decrementPolicyCounters(state);
	}
	applyPolicyCounterOverrides(state, certificate);
}

function updateLeafPolicyCounter(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
): void {
	decrementPositiveCounter(state, 'explicitPolicy');
	if (certificate.policyConstraints?.requireExplicitPolicy === 0) {
		state.explicitPolicy = 0;
	}
}

function decrementPolicyCounters(state: PolicyValidationState): void {
	decrementPositiveCounter(state, 'explicitPolicy');
	decrementPositiveCounter(state, 'inhibitPolicyMapping');
	decrementPositiveCounter(state, 'inhibitAnyPolicy');
}

function decrementPositiveCounter(
	state: PolicyValidationState,
	key: 'explicitPolicy' | 'inhibitPolicyMapping' | 'inhibitAnyPolicy',
): void {
	if (state[key] > 0) {
		state[key] -= 1;
	}
}

function applyPolicyCounterOverrides(
	state: PolicyValidationState,
	certificate: ParsedCertificate,
): void {
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
