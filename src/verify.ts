import type { ExtendedKeyUsage } from "./extensions.ts";
import { OIDS } from "./oids.ts";
import {
	parseCertificateDer,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
	type ParsedCertificate,
	type ParsedCertificateSigningRequest,
} from "./parse.ts";
import { splitPemBlocks } from "./pem.ts";
import { verifySignedData } from "./sig-verify.ts";

export type CertificateSource = string | Uint8Array;
export type CsrSource = string | Uint8Array;

export type VerifyPurpose = "serverAuth" | "clientAuth" | "ca";

export type EkuCheckPurpose =
	| "serverAuth"
	| "clientAuth"
	| "codeSigning"
	| "emailProtection"
	| "timeStamping"
	| "ocspSigning";

export type EkuCheckResult =
	| { readonly ok: true }
	| {
		readonly ok: false;
		readonly code: "leaf_eku_missing" | "intermediate_eku_constraint";
		readonly message: string;
		readonly index: number;
	};

export interface TrustAnchor {
	readonly subjectDerHex: string;
	readonly subjectPublicKeyInfoDer: Uint8Array;
	readonly publicKeyAlgorithmOid: string;
	readonly publicKeyParametersOid?: string;
	readonly subjectKeyIdentifier?: string;
}

export interface VerifyCertificateChainInput {
	readonly leaf: CertificateSource;
	readonly intermediates?: readonly CertificateSource[];
	readonly roots: readonly CertificateSource[];
	readonly trustAnchors?: readonly TrustAnchor[];
	readonly at?: Date;
	readonly purpose?: VerifyPurpose;
	readonly dnsName?: string;
	readonly ipAddress?: string;
	readonly allowSelfSignedLeaf?: boolean;
}

export type VerifyErrorCode =
	| "no_trusted_root"
	| "issuer_not_found"
	| "signature_invalid"
	| "certificate_expired"
	| "ca_required"
	| "key_cert_sign_required"
	| "path_length_exceeded"
	| "authority_key_identifier_mismatch"
	| "extended_key_usage_invalid"
	| "subject_alt_name_mismatch"
	| "self_signed_leaf_not_allowed"
	| "unrecognized_critical_extension";

export interface VerifiedCertificateChain {
	readonly leaf: ParsedCertificate;
	readonly chain: readonly ParsedCertificate[];
	readonly root: ParsedCertificate;
}

export interface VerifyFailureDetails {
	readonly subjectCommonName?: string;
	readonly issuerCommonName?: string;
	readonly expected?: string;
	readonly actual?: string;
	readonly chainCommonNames?: readonly string[];
}

export type VerifyRequestResult =
	| { readonly ok: true; readonly value: ParsedCertificateSigningRequest }
	| {
		readonly ok: false;
		readonly code: "signature_invalid";
		readonly message: string;
		readonly details?: VerifyFailureDetails;
	};

export interface VerifyChainFailure {
	readonly ok: false;
	readonly code: VerifyErrorCode;
	readonly message: string;
	readonly index?: number;
	readonly details?: VerifyFailureDetails;
}

export type VerifyChainResult =
	| { readonly ok: true; readonly value: VerifiedCertificateChain }
	| VerifyChainFailure;

/**
 * OIDs of extensions this verifier processes during path validation.
 * Per RFC 5280 §6.1, certificates with unrecognized critical extensions
 * that are not in this set must be rejected.
 */
const PROCESSED_EXTENSION_OIDS: ReadonlySet<string> = new Set([
	OIDS.basicConstraints,
	OIDS.keyUsage,
	OIDS.extendedKeyUsage,
	OIDS.subjectAltName,
	OIDS.authorityKeyIdentifier,
	OIDS.subjectKeyIdentifier,
	OIDS.authorityInfoAccess,
	OIDS.cRLDistributionPoints,
]);

interface LoadedCertificate {
	readonly der: Uint8Array;
	readonly parsed: ParsedCertificate;
}

interface BuildChainResult {
	readonly chain: readonly LoadedCertificate[];
	readonly foundTrustedRoot: boolean;
	readonly missingIssuerAt?: number;
	readonly failure?: VerifyChainFailure;
}

interface VerifyFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly issuerCommonName?: string | undefined;
	readonly expected?: string | undefined;
	readonly actual?: string | undefined;
	readonly chainCommonNames?: readonly string[] | undefined;
}

export async function verifyCertificateChain(
	input: VerifyCertificateChainInput,
): Promise<VerifyChainResult> {
	const leaf = loadSingleCertificate(input.leaf);
	const intermediates = loadCertificates(input.intermediates ?? []);
	const roots = loadCertificates(input.roots);
	const anchors = input.trustAnchors ?? [];
	const at = input.at ?? new Date();
	const buildResult = await buildChain(leaf, intermediates, roots, anchors, at);
	const chain = buildResult.chain;

	if (chain.length === 1 && isSelfIssued(leaf.parsed)) {
		if (!input.allowSelfSignedLeaf) {
			return failure(
				"self_signed_leaf_not_allowed",
				"self-signed leaf not allowed",
				0,
				detail({
					subjectCommonName: leaf.parsed.subject.values.commonName,
				}),
			);
		}
	}

	if (!buildResult.foundTrustedRoot) {
		if (buildResult.failure !== undefined) {
			return buildResult.failure;
		}
		if (buildResult.missingIssuerAt !== undefined) {
			return failure(
				"issuer_not_found",
				"issuer certificate not found",
				buildResult.missingIssuerAt,
				buildFailureDetails(chain, buildResult.missingIssuerAt),
			);
		}
		return failure(
			"no_trusted_root",
			"no trusted root found",
			undefined,
			detail({
				chainCommonNames: chain.map(
					(certificate) => certificate.parsed.subject.values.commonName ?? "<unnamed>",
				),
			}),
		);
	}

	for (let index = 0; index < chain.length; index += 1) {
		const current = chain[index];
		if (current === undefined) {
			return failure("issuer_not_found", "chain element missing", index);
		}
		if (!isWithinValidity(current.parsed, at)) {
			return failure(
				"certificate_expired",
				"certificate not valid at requested time",
				index,
				detail({
					subjectCommonName: current.parsed.subject.values.commonName,
					expected: at.toISOString(),
					actual: `${current.parsed.notBefore.toISOString()}..${current.parsed.notAfter.toISOString()}`,
				}),
			);
		}
		const unprocessedCritical = findUnprocessedCriticalExtension(
			current.parsed,
		);
		if (unprocessedCritical !== undefined) {
			return failure(
				"unrecognized_critical_extension",
				`certificate contains unrecognized critical extension ${unprocessedCritical}`,
				index,
				detail({
					subjectCommonName: current.parsed.subject.values.commonName,
					actual: unprocessedCritical,
				}),
			);
		}
		if (index === chain.length - 1) {
			continue;
		}
		const issuer = chain[index + 1];
		if (issuer === undefined) {
			return failure("issuer_not_found", "issuer missing", index);
		}
		const signatureValid = await verifyCertificateSignature(
			current.parsed,
			issuer.parsed,
		);
		if (!signatureValid) {
			return failure(
				"signature_invalid",
				"certificate signature does not verify",
				index,
				detail({
					subjectCommonName: current.parsed.subject.values.commonName,
					issuerCommonName: issuer.parsed.subject.values.commonName,
				}),
			);
		}
		if (issuer.parsed.basicConstraints?.ca !== true) {
			return failure(
				"ca_required",
				"issuer must be a CA certificate",
				index + 1,
				detail({
					subjectCommonName: issuer.parsed.subject.values.commonName,
				}),
			);
		}
		if (
			issuer.parsed.keyUsage !== undefined
			&& !issuer.parsed.keyUsage.includes("keyCertSign")
		) {
			return failure(
				"key_cert_sign_required",
				"issuer missing keyCertSign",
				index + 1,
				detail({
					subjectCommonName: issuer.parsed.subject.values.commonName,
				}),
			);
		}
		if (
			current.parsed.authorityKeyIdentifier !== undefined
			&& issuer.parsed.subjectKeyIdentifier !== undefined
			&& current.parsed.authorityKeyIdentifier
				!== issuer.parsed.subjectKeyIdentifier
		) {
			return failure(
				"authority_key_identifier_mismatch",
				"authorityKeyIdentifier does not match issuer subjectKeyIdentifier",
				index,
				detail({
					subjectCommonName: current.parsed.subject.values.commonName,
					issuerCommonName: issuer.parsed.subject.values.commonName,
					expected: issuer.parsed.subjectKeyIdentifier,
					actual: current.parsed.authorityKeyIdentifier,
				}),
			);
		}
	}

	for (let index = 1; index < chain.length; index += 1) {
		const current = chain[index];
		if (current === undefined) {
			return failure("issuer_not_found", "chain element missing", index);
		}
		const maxCaBelow = countCaCertificatesBelow(chain, index);
		const pathLength = current.parsed.basicConstraints?.pathLength;
		if (pathLength !== undefined && maxCaBelow > pathLength) {
			return failure(
				"path_length_exceeded",
				"path length constraint exceeded",
				index,
				detail({
					subjectCommonName: current.parsed.subject.values.commonName,
					expected: String(pathLength),
					actual: String(maxCaBelow),
				}),
			);
		}
	}

	const leafValidation = validateLeaf(chain[0], input);
	if (!leafValidation.ok) {
		return leafValidation;
	}

	const root = chain[chain.length - 1];
	if (root === undefined) {
		return failure("no_trusted_root", "no trusted root found");
	}

	return {
		ok: true,
		value: {
			leaf: leaf.parsed,
			chain: chain.map((certificate) => certificate.parsed),
			root: root.parsed,
		},
	};
}

export async function verifyCertificateSigningRequest(
	input: CsrSource,
): Promise<VerifyRequestResult> {
	const parsed = typeof input === "string"
		? parseCertificateSigningRequestPem(input)
		: parseCertificateSigningRequestDer(new Uint8Array(input));
	const signatureValid = await verifySignedData(
		parsed.signatureAlgorithmOid,
		parsed.publicKeyAlgorithmOid,
		parsed.publicKeyParametersOid,
		parsed.subjectPublicKeyInfoDer,
		parsed.signatureValue,
		parsed.certificationRequestInfoDer,
	);
	if (!signatureValid) {
		return {
			ok: false,
			code: "signature_invalid",
			message: "certificate request signature does not verify",
			details: detail({ subjectCommonName: parsed.subject.values.commonName }),
		};
	}
	return { ok: true, value: parsed };
}

/**
 * Standalone EKU check against a verified certificate chain.
 * Validates that the leaf has the requested purpose and that
 * intermediate CA EKU constraints (if present) permit it.
 */
export function checkExtendedKeyUsage(
	chain: readonly ParsedCertificate[],
	purpose: EkuCheckPurpose,
): EkuCheckResult {
	const leaf = chain[0];
	if (leaf === undefined) {
		return {
			ok: false,
			code: "leaf_eku_missing",
			message: "chain is empty",
			index: 0,
		};
	}
	if (
		leaf.extendedKeyUsage !== undefined
		&& !leaf.extendedKeyUsage.includes(purpose)
	) {
		return {
			ok: false,
			code: "leaf_eku_missing",
			message: `leaf certificate does not include EKU ${purpose}`,
			index: 0,
		};
	}
	for (let index = 1; index < chain.length; index += 1) {
		const intermediate = chain[index];
		if (intermediate === undefined) {
			continue;
		}
		if (
			intermediate.extendedKeyUsage !== undefined
			&& !intermediate.extendedKeyUsage.includes(purpose)
		) {
			return {
				ok: false,
				code: "intermediate_eku_constraint",
				message: `intermediate CA at index ${String(index)} constrains EKU and does not include ${purpose}`,
				index,
			};
		}
	}
	return { ok: true };
}

export function trustAnchorFromCertificate(
	certificate: ParsedCertificate,
): TrustAnchor {
	return {
		subjectDerHex: certificate.subject.derHex,
		subjectPublicKeyInfoDer: certificate.subjectPublicKeyInfoDer,
		publicKeyAlgorithmOid: certificate.publicKeyAlgorithmOid,
		...(certificate.publicKeyParametersOid === undefined
			? {}
			: { publicKeyParametersOid: certificate.publicKeyParametersOid }),
		...(certificate.subjectKeyIdentifier === undefined
			? {}
			: { subjectKeyIdentifier: certificate.subjectKeyIdentifier }),
	};
}

function validateLeaf(
	leaf: LoadedCertificate | undefined,
	input: VerifyCertificateChainInput,
): VerifyChainResult | { readonly ok: true } {
	if (leaf === undefined) {
		return failure("issuer_not_found", "leaf missing", 0);
	}
	const purpose = input.purpose;
	if (purpose !== undefined) {
		if (purpose === "ca") {
			if (leaf.parsed.basicConstraints?.ca !== true) {
				return failure(
					"ca_required",
					"leaf is not a CA certificate",
					0,
					detail({
						subjectCommonName: leaf.parsed.subject.values.commonName,
					}),
				);
			}
		} else if (
			leaf.parsed.extendedKeyUsage !== undefined
			&& !leaf.parsed.extendedKeyUsage.includes(purpose)
		) {
			return failure(
				"extended_key_usage_invalid",
				`leaf missing EKU ${purpose}`,
				0,
				detail({
					subjectCommonName: leaf.parsed.subject.values.commonName,
					expected: purpose,
					actual: leaf.parsed.extendedKeyUsage.map(formatEku).join(","),
				}),
			);
		}
	}
	if (input.dnsName !== undefined) {
		const sans = leaf.parsed.subjectAltNames?.filter((entry) => entry.type === "dns")
			?? [];
		if (
			!sans.some((entry) => matchesDnsName(entry.value, input.dnsName ?? ""))
		) {
			return failure(
				"subject_alt_name_mismatch",
				"DNS name not present in SAN",
				0,
				detail({
					subjectCommonName: leaf.parsed.subject.values.commonName,
					expected: input.dnsName,
					actual: sans.map((entry) => entry.value).join(","),
				}),
			);
		}
	}
	if (input.ipAddress !== undefined) {
		const expected = normalizeIpAddress(input.ipAddress);
		const sans = leaf.parsed.subjectAltNames?.filter((entry) => entry.type === "ip") ?? [];
		if (!sans.some((entry) => normalizeIpAddress(entry.value) === expected)) {
			return failure(
				"subject_alt_name_mismatch",
				"IP address not present in SAN",
				0,
				detail({
					subjectCommonName: leaf.parsed.subject.values.commonName,
					expected,
					actual: sans
						.map((entry) => normalizeIpAddress(entry.value))
						.join(","),
				}),
			);
		}
	}
	return { ok: true };
}

async function buildChain(
	leaf: LoadedCertificate,
	intermediates: readonly LoadedCertificate[],
	roots: readonly LoadedCertificate[],
	trustAnchors: readonly TrustAnchor[],
	at: Date,
): Promise<BuildChainResult> {
	const candidates = [...intermediates, ...roots];
	const subjectIndex = new Map<string, LoadedCertificate[]>();
	const order = new Map<string, number>();
	const rootFingerprints = new Set(
		roots.map((candidate) => fingerprint(candidate)),
	);
	const anchorIndex = new Map<string, TrustAnchor[]>();
	for (const anchor of trustAnchors) {
		const existing = anchorIndex.get(anchor.subjectDerHex);
		if (existing === undefined) {
			anchorIndex.set(anchor.subjectDerHex, [anchor]);
		} else {
			existing.push(anchor);
		}
	}
	let sawUntrustedAnchor = false;
	let deepestPath: readonly LoadedCertificate[] = [leaf];
	let deepestMissingIssuerAt: number | undefined;
	let preferredFailure: VerifyChainFailure | undefined;
	const deadEnds = new Set<string>();

	candidates.forEach((candidate, index) => {
		const key = candidate.parsed.subject.derHex;
		const existing = subjectIndex.get(key);
		if (existing === undefined) {
			subjectIndex.set(key, [candidate]);
		} else {
			existing.push(candidate);
		}
		order.set(fingerprint(candidate), index);
	});

	const maxDepth = candidates.length + 1;
	const startFingerprint = fingerprint(leaf);
	const success = await search(leaf, [leaf], new Set([startFingerprint]), 0);
	if (success !== undefined) {
		return { chain: success, foundTrustedRoot: true };
	}
	if (preferredFailure !== undefined) {
		return {
			chain: deepestPath,
			foundTrustedRoot: false,
			failure: preferredFailure,
		};
	}
	if (sawUntrustedAnchor) {
		return { chain: deepestPath, foundTrustedRoot: false };
	}
	return deepestMissingIssuerAt === undefined
		? { chain: deepestPath, foundTrustedRoot: false }
		: {
			chain: deepestPath,
			foundTrustedRoot: false,
			missingIssuerAt: deepestMissingIssuerAt,
		};

	async function search(
		current: LoadedCertificate,
		path: readonly LoadedCertificate[],
		visited: ReadonlySet<string>,
		caBelowCount: number,
	): Promise<readonly LoadedCertificate[] | undefined> {
		if (rootFingerprints.has(fingerprint(current))) {
			return path;
		}
		const matchedAnchor = await matchTrustAnchor(current, anchorIndex);
		if (matchedAnchor) {
			return path;
		}
		if (path.length > maxDepth) {
			return undefined;
		}
		const memoKey = `${fingerprint(current)}:${caBelowCount}`;
		if (deadEnds.has(memoKey)) {
			return undefined;
		}
		const issuers = rankIssuerCandidates(
			current,
			subjectIndex.get(current.parsed.issuer.derHex) ?? [],
			order,
			rootFingerprints,
		);
		if (issuers.length === 0) {
			updateDeepest(path);
			if (isSelfIssued(current.parsed)) {
				sawUntrustedAnchor = true;
			} else {
				deepestMissingIssuerAt = path.length - 1;
			}
			deadEnds.add(memoKey);
			return undefined;
		}

		for (const issuer of issuers) {
			const issuerFingerprint = fingerprint(issuer);
			if (visited.has(issuerFingerprint)) {
				continue;
			}
			if (!isWithinValidity(issuer.parsed, at)) {
				recordFailure(
					failure(
						"certificate_expired",
						"certificate not valid at requested time",
						path.length,
						detail({
							subjectCommonName: issuer.parsed.subject.values.commonName,
							expected: at.toISOString(),
							actual: `${issuer.parsed.notBefore.toISOString()}..${issuer.parsed.notAfter.toISOString()}`,
						}),
					),
					path,
				);
				continue;
			}
			if (issuer.parsed.basicConstraints?.ca !== true) {
				recordFailure(
					failure(
						"ca_required",
						"issuer must be a CA certificate",
						path.length,
						detail({
							subjectCommonName: issuer.parsed.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (
				issuer.parsed.keyUsage !== undefined
				&& !issuer.parsed.keyUsage.includes("keyCertSign")
			) {
				recordFailure(
					failure(
						"key_cert_sign_required",
						"issuer missing keyCertSign",
						path.length,
						detail({
							subjectCommonName: issuer.parsed.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (
				current.parsed.authorityKeyIdentifier !== undefined
				&& issuer.parsed.subjectKeyIdentifier !== undefined
				&& current.parsed.authorityKeyIdentifier
					!== issuer.parsed.subjectKeyIdentifier
			) {
				recordFailure(
					failure(
						"authority_key_identifier_mismatch",
						"authorityKeyIdentifier does not match issuer subjectKeyIdentifier",
						path.length - 1,
						detail({
							subjectCommonName: current.parsed.subject.values.commonName,
							issuerCommonName: issuer.parsed.subject.values.commonName,
							expected: issuer.parsed.subjectKeyIdentifier,
							actual: current.parsed.authorityKeyIdentifier,
						}),
					),
					path,
				);
				continue;
			}
			const nextCaBelowCount = caBelowCount
				+ (current.parsed.basicConstraints?.ca === true
						&& !isSelfIssued(current.parsed)
					? 1
					: 0);
			const pathLength = issuer.parsed.basicConstraints?.pathLength;
			if (pathLength !== undefined && nextCaBelowCount > pathLength) {
				recordFailure(
					failure(
						"path_length_exceeded",
						"path length constraint exceeded",
						path.length,
						detail({
							subjectCommonName: issuer.parsed.subject.values.commonName,
							expected: String(pathLength),
							actual: String(nextCaBelowCount),
						}),
					),
					path,
				);
				continue;
			}
			if (!(await verifyCertificateSignature(current.parsed, issuer.parsed))) {
				recordFailure(
					failure(
						"signature_invalid",
						"certificate signature does not verify",
						path.length - 1,
						detail({
							subjectCommonName: current.parsed.subject.values.commonName,
							issuerCommonName: issuer.parsed.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			const nextVisited = new Set(visited);
			nextVisited.add(issuerFingerprint);
			const nextPath = [...path, issuer];
			const result = await search(
				issuer,
				nextPath,
				nextVisited,
				nextCaBelowCount,
			);
			if (result !== undefined) {
				return result;
			}
		}

		deadEnds.add(memoKey);
		updateDeepest(path);
		return undefined;
	}

	function updateDeepest(path: readonly LoadedCertificate[]): void {
		if (path.length > deepestPath.length) {
			deepestPath = path;
		}
	}

	function recordFailure(
		candidateFailure: VerifyChainFailure,
		path: readonly LoadedCertificate[],
	): void {
		if (preferredFailure === undefined || path.length >= deepestPath.length) {
			preferredFailure = candidateFailure;
		}
	}
}

function rankIssuerCandidates(
	current: LoadedCertificate,
	candidates: readonly LoadedCertificate[],
	order: ReadonlyMap<string, number>,
	rootFingerprints: ReadonlySet<string>,
): readonly LoadedCertificate[] {
	const aki = current.parsed.authorityKeyIdentifier;
	return [...candidates]
		.filter((candidate) => isIssuerOf(candidate, current))
		.sort((left, right) => {
			const akiScore = compareBooleans(
				matchesAki(left, aki),
				matchesAki(right, aki),
			);
			if (akiScore !== 0) {
				return akiScore;
			}
			const rootScore = compareBooleans(
				rootFingerprints.has(fingerprint(left)),
				rootFingerprints.has(fingerprint(right)),
			);
			if (rootScore !== 0) {
				return rootScore;
			}
			return (
				(order.get(fingerprint(left)) ?? Number.MAX_SAFE_INTEGER)
				- (order.get(fingerprint(right)) ?? Number.MAX_SAFE_INTEGER)
			);
		});
}

function matchesAki(
	candidate: LoadedCertificate,
	aki: string | undefined,
): boolean {
	return (
		aki !== undefined
		&& candidate.parsed.subjectKeyIdentifier !== undefined
		&& candidate.parsed.subjectKeyIdentifier === aki
	);
}

function compareBooleans(left: boolean, right: boolean): number {
	if (left === right) {
		return 0;
	}
	return left ? -1 : 1;
}

function isIssuerOf(
	issuer: LoadedCertificate,
	child: LoadedCertificate,
): boolean {
	return child.parsed.issuer.derHex === issuer.parsed.subject.derHex;
}

function findUnprocessedCriticalExtension(
	certificate: ParsedCertificate,
): string | undefined {
	for (const extension of certificate.extensions) {
		if (extension.critical && !PROCESSED_EXTENSION_OIDS.has(extension.oid)) {
			return extension.oid;
		}
	}
	return undefined;
}

function isWithinValidity(certificate: ParsedCertificate, at: Date): boolean {
	return (
		certificate.notBefore.getTime() <= at.getTime()
		&& at.getTime() <= certificate.notAfter.getTime()
	);
}

function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

function countCaCertificatesBelow(
	chain: readonly LoadedCertificate[],
	index: number,
): number {
	let total = 0;
	for (let cursor = 0; cursor < index; cursor += 1) {
		const certificate = chain[cursor];
		if (
			certificate?.parsed.basicConstraints?.ca === true
			&& !isSelfIssued(certificate.parsed)
		) {
			total += 1;
		}
	}
	return total;
}

function loadCertificates(
	sources: readonly CertificateSource[],
): readonly LoadedCertificate[] {
	const loaded: LoadedCertificate[] = [];
	for (const source of sources) {
		loaded.push(...expandSource(source));
	}
	return loaded;
}

function loadSingleCertificate(source: CertificateSource): LoadedCertificate {
	const loaded = expandSource(source);
	const first = loaded[0];
	if (first === undefined) {
		throw new Error("No certificate found");
	}
	if (loaded.length !== 1) {
		throw new Error("Expected a single certificate source");
	}
	return first;
}

function expandSource(source: CertificateSource): readonly LoadedCertificate[] {
	if (typeof source === "string") {
		return splitPemBlocks(source)
			.filter((block) => block.label === "CERTIFICATE")
			.map((block) => ({
				der: block.bytes,
				parsed: parseCertificateDer(block.bytes),
			}));
	}
	return [loadDerCertificate(source)];
}

function loadDerCertificate(der: Uint8Array): LoadedCertificate {
	const bytes = new Uint8Array(der);
	return {
		der: bytes,
		parsed: parseCertificateDer(bytes),
	};
}

async function verifyCertificateSignature(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
): Promise<boolean> {
	return verifySignedData(
		certificate.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		certificate.signatureValue,
		certificate.tbsCertificateDer,
	);
}

function isSameCertificate(
	left: LoadedCertificate,
	right: LoadedCertificate,
): boolean {
	if (left.der.length !== right.der.length) {
		return false;
	}
	for (let index = 0; index < left.der.length; index += 1) {
		if (left.der[index] !== right.der[index]) {
			return false;
		}
	}
	return true;
}

async function matchTrustAnchor(
	certificate: LoadedCertificate,
	anchorIndex: ReadonlyMap<string, readonly TrustAnchor[]>,
): Promise<boolean> {
	const anchors = anchorIndex.get(certificate.parsed.issuer.derHex);
	if (anchors === undefined) {
		return false;
	}
	for (const anchor of anchors) {
		if (
			anchor.subjectKeyIdentifier !== undefined
			&& certificate.parsed.authorityKeyIdentifier !== undefined
			&& anchor.subjectKeyIdentifier !== certificate.parsed.authorityKeyIdentifier
		) {
			continue;
		}
		const verified = await verifySignedData(
			certificate.parsed.signatureAlgorithmOid,
			anchor.publicKeyAlgorithmOid,
			anchor.publicKeyParametersOid,
			anchor.subjectPublicKeyInfoDer,
			certificate.parsed.signatureValue,
			certificate.parsed.tbsCertificateDer,
		);
		if (verified) {
			return true;
		}
	}
	return false;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

function fingerprint(certificate: LoadedCertificate): string {
	return Array.from(certificate.der, (value) => value.toString(16).padStart(2, "0")).join("");
}

function isTrustedSelfSignedRoot(
	certificate: LoadedCertificate,
	roots: readonly LoadedCertificate[],
): boolean {
	return (
		isSelfIssued(certificate.parsed)
		&& roots.some((candidate) => isSameCertificate(candidate, certificate))
	);
}

function matchesDnsName(pattern: string, actual: string): boolean {
	const lowerPattern = pattern.toLowerCase();
	const lowerActual = actual.toLowerCase();
	if (!lowerPattern.includes("*")) {
		return lowerPattern === lowerActual;
	}
	if (!lowerPattern.startsWith("*.")) {
		return false;
	}
	const suffix = lowerPattern.slice(1);
	if (!lowerActual.endsWith(suffix)) {
		return false;
	}
	const prefix = lowerActual.slice(0, lowerActual.length - suffix.length);
	return prefix.length > 0 && !prefix.includes(".");
}

function normalizeIpAddress(value: string): string {
	if (!value.includes(":")) {
		return value;
	}
	return expandIpv6(value)
		.map((segment) => segment.toLowerCase())
		.join(":");
}

function expandIpv6(value: string): readonly string[] {
	const pieces = value.toLowerCase().split("::");
	const head = pieces[0] ?? "";
	const tail = pieces[1];
	if (tail !== undefined && value.indexOf("::") !== value.lastIndexOf("::")) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const headParts = head.length > 0 ? head.split(":") : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(":") : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const zeroes = Array.from({ length: missing }, () => "0");
	return (
		tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts]
	).map((segment) => segment.padStart(4, "0"));
}

function failure(
	code: VerifyErrorCode,
	message: string,
	index?: number,
	details?: VerifyFailureDetails,
): VerifyChainFailure {
	return {
		ok: false,
		code,
		message,
		...(index === undefined ? {} : { index }),
		...(details === undefined ? {} : { details }),
	};
}

function buildFailureDetails(
	chain: readonly LoadedCertificate[],
	index: number,
): VerifyFailureDetails {
	const certificate = chain[index];
	return detail({
		subjectCommonName: certificate?.parsed.subject.values.commonName,
		issuerCommonName: certificate?.parsed.issuer.values.commonName,
		chainCommonNames: chain.map(
			(entry) => entry.parsed.subject.values.commonName ?? "<unnamed>",
		),
	});
}

function formatEku(value: ExtendedKeyUsage): string {
	return typeof value === "string" ? value : value.value;
}

function detail(input: VerifyFailureDetailsInput): VerifyFailureDetails {
	return {
		...(input.subjectCommonName === undefined
			? {}
			: { subjectCommonName: input.subjectCommonName }),
		...(input.issuerCommonName === undefined
			? {}
			: { issuerCommonName: input.issuerCommonName }),
		...(input.expected === undefined ? {} : { expected: input.expected }),
		...(input.actual === undefined ? {} : { actual: input.actual }),
		...(input.chainCommonNames === undefined
			? {}
			: { chainCommonNames: input.chainCommonNames }),
	};
}
