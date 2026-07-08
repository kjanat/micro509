/**
 * Centralized ASN.1 object identifier registry referenced by create, parse,
 * verify, and container modules.
 *
 * All OIDs are dotted-decimal string constants keyed by their common short name.
 *
 * @module
 */

import OID_GROUP_SPECS from './oids.json' with { type: 'json' };

type OidLeaves = { readonly [name: string]: string };
type OidNode = {
	readonly arc: string;
	readonly oids?: OidLeaves;
	readonly children?: OidTree;
};
type OidTree = { readonly [name: string]: OidNode };
type OidMap = { readonly [name: string]: string };
type MutableOidMap = { [name: string]: string };
declare const oidNameBrand: unique symbol;
type OidValue<Name extends string, Value extends string> = Value & {
	readonly [oidNameBrand]?: Name;
};
type JoinOidPrefix<Base extends string, Arc extends string> = Base extends ''
	? Arc
	: `${Base}.${Arc}`;
type OidsFromLeaves<Prefix extends string, Leaves extends OidLeaves> = {
	readonly [Name in keyof Leaves]: OidValue<Name & string, `${Prefix}.${Leaves[Name]}`>;
};
type UnionToIntersection<Union> = (Union extends unknown ? (value: Union) => void : never) extends (
	value: infer Intersection,
) => void
	? Intersection
	: never;
type OidsFromNode<Node extends OidNode, Base extends string = ''> = Node extends {
	readonly arc: infer Arc extends string;
}
	? (Node extends { readonly oids: infer Leaves extends OidLeaves }
			? OidsFromLeaves<JoinOidPrefix<Base, Arc>, Leaves>
			: unknown) &
			(Node extends { readonly children: infer Children extends OidTree }
				? OidsFromTree<Children, JoinOidPrefix<Base, Arc>>
				: unknown)
	: never;
type OidsFromTree<Tree extends OidTree, Base extends string = ''> = UnionToIntersection<
	OidsFromNode<Tree[keyof Tree], Base>
>;
type OidDocumentRoots<Document> = Omit<Document, '$schema'>;
type OidRegistry = OidsFromTree<OidDocumentRoots<typeof OID_GROUP_SPECS>>;

function joinOidPrefix(basePrefix: string, arc: string): string {
	if (basePrefix === '') {
		return arc;
	}

	return `${basePrefix}.${arc}`;
}

function isOidNode(value: unknown): value is OidNode {
	return typeof value === 'object' && value !== null && 'arc' in value;
}

function hasOidName(oids: OidMap, name: string): boolean {
	return Object.hasOwn(oids, name);
}

function addOidNode(oids: MutableOidMap, node: OidNode, basePrefix: string): void {
	const prefix = joinOidPrefix(basePrefix, node.arc);

	if (node.oids !== undefined) {
		for (const [name, arc] of Object.entries(node.oids)) {
			const path = joinOidPrefix(prefix, arc);
			if (hasOidName(oids, name)) {
				const existingPath = oids[name];
				throw new TypeError(
					`Duplicate OID name "${name}" at ${path}; already assigned to ${existingPath}`,
				);
			}
			oids[name] = path;
		}
	}

	if (node.children !== undefined) {
		addOidTree(oids, node.children, prefix);
	}
}

function addOidTree(oids: MutableOidMap, tree: OidTree, basePrefix: string): void {
	for (const node of Object.values(tree)) {
		addOidNode(oids, node, basePrefix);
	}
}

function addOidDocument(oids: MutableOidMap, document: typeof OID_GROUP_SPECS): void {
	for (const value of Object.values(document)) {
		if (isOidNode(value)) {
			addOidNode(oids, value, '');
		}
	}
}

function collectOidNamesFromNode(names: Set<string>, node: OidNode): void {
	if (node.oids !== undefined) {
		for (const name of Object.keys(node.oids)) {
			names.add(name);
		}
	}

	if (node.children !== undefined) {
		for (const child of Object.values(node.children)) {
			collectOidNamesFromNode(names, child);
		}
	}
}

function collectOidNamesFromDocument(document: typeof OID_GROUP_SPECS): readonly string[] {
	const names = new Set<string>();
	for (const value of Object.values(document)) {
		if (isOidNode(value)) {
			collectOidNamesFromNode(names, value);
		}
	}
	return [...names];
}

function isOidRegistry(oids: OidMap, names: readonly string[]): oids is OidRegistry {
	for (const name of names) {
		if (!hasOidName(oids, name)) {
			return false;
		}
	}
	return true;
}

function flattenOidTree(tree: typeof OID_GROUP_SPECS): OidRegistry {
	const oids: MutableOidMap = Object.create(null);
	addOidDocument(oids, tree);
	const names = collectOidNamesFromDocument(tree);
	if (!isOidRegistry(oids, names)) {
		const missingNames = names.filter((name) => !hasOidName(oids, name));
		throw new TypeError(`Incomplete OID registry; missing ${missingNames.join(', ')}`);
	}
	return oids;
}

/**
 * Dotted-decimal OID constants for X.500 attributes, PKCS algorithms,
 * X.509v3 extensions, EKU purposes, hash algorithms, and PKIX access methods.
 */
const OIDS: OidRegistry = flattenOidTree(OID_GROUP_SPECS);

export { OIDS, OID_GROUP_SPECS };
