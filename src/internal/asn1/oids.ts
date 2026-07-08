/**
 * Centralized ASN.1 object identifier registry referenced by create, parse,
 * verify, and container modules.
 *
 * All OIDs are dotted-decimal string constants keyed by their common short name.
 *
 * @module
 */

import OID_GROUP_SPECS from '#micro509/internal/asn1/oidsJson' with { type: 'json' };

type OidLeaves = { readonly [name: string]: string };
type OidNode = {
	readonly arc: string;
	readonly oids?: OidLeaves;
	readonly children?: OidTree;
};
type OidTree = { readonly [name: string]: OidNode };
type OidMap = { readonly [name: string]: string };
type JoinOidPrefix<Base extends string, Arc extends string> = Base extends ''
	? Arc
	: `${Base}.${Arc}`;
type OidFromArcs<Arcs extends readonly string[]> = Arcs extends readonly [
	infer Head extends string,
	...infer Tail extends string[],
]
	? Tail extends []
		? Head
		: `${Head}.${OidFromArcs<Tail>}`
	: never;
type IsoMemberBodyUs<Rest extends readonly string[]> = OidFromArcs<['1', '2', '840', ...Rest]>;
type RsaDsi<Rest extends readonly string[]> = IsoMemberBodyUs<['113549', ...Rest]>;
type Pkcs<Rest extends readonly string[]> = RsaDsi<['1', ...Rest]>;
type IdentifiedOrganization<Rest extends readonly string[]> = OidFromArcs<['1', '3', ...Rest]>;
type Pkix<Rest extends readonly string[]> = IdentifiedOrganization<
	['6', '1', '5', '5', '7', ...Rest]
>;
type JointIsoItuT<Rest extends readonly string[]> = OidFromArcs<['2', ...Rest]>;
type DirectoryServices<Rest extends readonly string[]> = JointIsoItuT<['5', ...Rest]>;
type NistAlgorithm<Rest extends readonly string[]> = JointIsoItuT<
	['16', '840', '1', '101', '3', '4', ...Rest]
>;
type OidsFromLeaves<Prefix extends string, Leaves extends OidLeaves> = {
	readonly [Name in keyof Leaves]: `${Prefix}.${Leaves[Name]}`;
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

type OidRegistry = {
	readonly commonName: DirectoryServices<['4', '3']>;
	readonly surname: DirectoryServices<['4', '4']>;
	readonly serialNumber: DirectoryServices<['4', '5']>;
	readonly countryName: DirectoryServices<['4', '6']>;
	readonly localityName: DirectoryServices<['4', '7']>;
	readonly stateOrProvinceName: DirectoryServices<['4', '8']>;
	readonly streetAddress: DirectoryServices<['4', '9']>;
	readonly organizationName: DirectoryServices<['4', '10']>;
	readonly organizationalUnitName: DirectoryServices<['4', '11']>;
	readonly title: DirectoryServices<['4', '12']>;
	readonly givenName: DirectoryServices<['4', '42']>;
	readonly emailAddress: Pkcs<['9', '1']>;
	readonly cmsContentType: Pkcs<['9', '3']>;
	readonly cmsMessageDigest: Pkcs<['9', '4']>;
	readonly extensionRequest: Pkcs<['9', '14']>;
	readonly pkcs7Data: Pkcs<['7', '1']>;
	readonly pkcs7SignedData: Pkcs<['7', '2']>;
	readonly pkcs7EncryptedData: Pkcs<['7', '6']>;
	readonly pkcs12KeyBag: Pkcs<['12', '10', '1', '1']>;
	readonly pkcs12CertBag: Pkcs<['12', '10', '1', '3']>;
	readonly x509CertificateBagType: Pkcs<['9', '22', '1']>;
	readonly friendlyName: Pkcs<['9', '20']>;
	readonly localKeyId: Pkcs<['9', '21']>;
	readonly pbes2: Pkcs<['5', '13']>;
	readonly pbkdf2: Pkcs<['5', '12']>;
	readonly mgf1: Pkcs<['1', '8']>;
	readonly hmacWithSHA1: RsaDsi<['2', '7']>;
	readonly hmacWithSHA256: RsaDsi<['2', '9']>;
	readonly aes128Cbc: NistAlgorithm<['1', '2']>;
	readonly aes192Cbc: NistAlgorithm<['1', '22']>;
	readonly aes256Cbc: NistAlgorithm<['1', '42']>;
	readonly rsaEncryption: Pkcs<['1', '1']>;
	readonly sha1WithRSAEncryption: Pkcs<['1', '5']>;
	readonly rsassaPss: Pkcs<['1', '10']>;
	readonly sha256WithRSAEncryption: Pkcs<['1', '11']>;
	readonly sha384WithRSAEncryption: Pkcs<['1', '12']>;
	readonly sha512WithRSAEncryption: Pkcs<['1', '13']>;
	readonly ecPublicKey: IsoMemberBodyUs<['10045', '2', '1']>;
	readonly ecdsaWithSHA1: IsoMemberBodyUs<['10045', '4', '1']>;
	readonly ecdsaWithSHA224: IsoMemberBodyUs<['10045', '4', '3', '1']>;
	readonly ecdsaWithSHA256: IsoMemberBodyUs<['10045', '4', '3', '2']>;
	readonly ecdsaWithSHA384: IsoMemberBodyUs<['10045', '4', '3', '3']>;
	readonly ecdsaWithSHA512: IsoMemberBodyUs<['10045', '4', '3', '4']>;
	readonly prime256v1: IsoMemberBodyUs<['10045', '3', '1', '7']>;
	readonly secp384r1: IdentifiedOrganization<['132', '0', '34']>;
	readonly secp521r1: IdentifiedOrganization<['132', '0', '35']>;
	readonly ed25519: IdentifiedOrganization<['101', '112']>;
	readonly subjectKeyIdentifier: DirectoryServices<['29', '14']>;
	readonly keyUsage: DirectoryServices<['29', '15']>;
	readonly subjectAltName: DirectoryServices<['29', '17']>;
	readonly nameConstraints: DirectoryServices<['29', '30']>;
	readonly certificatePolicies: DirectoryServices<['29', '32']>;
	readonly policyMappings: DirectoryServices<['29', '33']>;
	readonly cRLNumber: DirectoryServices<['29', '20']>;
	readonly cRLReason: DirectoryServices<['29', '21']>;
	readonly invalidityDate: DirectoryServices<['29', '24']>;
	readonly certificateIssuer: DirectoryServices<['29', '29']>;
	readonly issuingDistributionPoint: DirectoryServices<['29', '28']>;
	readonly deltaCRLIndicator: DirectoryServices<['29', '27']>;
	readonly basicConstraints: DirectoryServices<['29', '19']>;
	readonly policyConstraints: DirectoryServices<['29', '36']>;
	readonly cRLDistributionPoints: DirectoryServices<['29', '31']>;
	readonly freshestCRL: DirectoryServices<['29', '46']>;
	readonly inhibitAnyPolicy: DirectoryServices<['29', '54']>;
	readonly extendedKeyUsage: DirectoryServices<['29', '37']>;
	readonly authorityKeyIdentifier: DirectoryServices<['29', '35']>;
	readonly anyPolicy: DirectoryServices<['29', '32', '0']>;
	readonly authorityInfoAccess: Pkix<['1', '1']>;
	readonly idOnDnsSrv: Pkix<['8', '7']>;
	readonly cpsPolicyQualifier: Pkix<['2', '1']>;
	readonly userNoticePolicyQualifier: Pkix<['2', '2']>;
	readonly ocspAccessMethod: Pkix<['48', '1']>;
	readonly caIssuersAccessMethod: Pkix<['48', '2']>;
	readonly ocspBasicResponse: Pkix<['48', '1', '1']>;
	readonly ocspNonce: Pkix<['48', '1', '2']>;
	readonly ocspNoCheck: Pkix<['48', '1', '5']>;
	readonly sha1: IdentifiedOrganization<['14', '3', '2', '26']>;
	readonly sha256: NistAlgorithm<['2', '1']>;
	readonly sha384: NistAlgorithm<['2', '2']>;
	readonly sha512: NistAlgorithm<['2', '3']>;
	readonly serverAuth: Pkix<['3', '1']>;
	readonly clientAuth: Pkix<['3', '2']>;
	readonly codeSigning: Pkix<['3', '3']>;
	readonly emailProtection: Pkix<['3', '4']>;
	readonly timeStamping: Pkix<['3', '8']>;
	readonly ocspSigning: Pkix<['3', '9']>;
};

function joinOidPrefix(basePrefix: string, arc: string): string {
	if (basePrefix === '') {
		return arc;
	}

	return `${basePrefix}.${arc}`;
}

function addOidNode(oids: Record<string, string>, node: OidNode, basePrefix: string): void {
	const prefix = joinOidPrefix(basePrefix, node.arc);

	if (node.oids !== undefined) {
		for (const [name, arc] of Object.entries(node.oids)) {
			oids[name] = joinOidPrefix(prefix, arc);
		}
	}

	if (node.children !== undefined) {
		addOidTree(oids, node.children, prefix);
	}
}

function addOidTree(oids: Record<string, string>, tree: OidTree, basePrefix: string): void {
	for (const node of Object.values(tree)) {
		addOidNode(oids, node, basePrefix);
	}
}

function addOidDocument(oids: Record<string, string>, document: typeof OID_GROUP_SPECS): void {
	addOidNode(oids, document.iso, '');
	addOidNode(oids, document.jointIsoItuT, '');
}

function flattenOidTree(tree: typeof OID_GROUP_SPECS): OidRegistry;
function flattenOidTree(tree: typeof OID_GROUP_SPECS): OidMap {
	const oids: Record<string, string> = {};
	addOidDocument(oids, tree);
	return oids;
}

/**
 * Dotted-decimal OID constants for X.500 attributes, PKCS algorithms,
 * X.509v3 extensions, EKU purposes, hash algorithms, and PKIX access methods.
 */
const OIDS: OidRegistry = flattenOidTree(OID_GROUP_SPECS);

export { OIDS, OID_GROUP_SPECS };
