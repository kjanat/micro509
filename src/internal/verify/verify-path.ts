/**
 * Internal certificate path-building and signature-check helpers.
 *
 * Loads and parses candidate certificates, ranks issuer candidates by AKI/root
 * affinity, matches against bare {@linkcode TrustAnchor}s, and performs the
 * depth-first chain search used by the public verify APIs in `verify.ts`.
 *
 * @module
 */

import { toHex } from '#micro509/internal/asn1/asn1.ts';
import {
	type VerifySignedDataResult,
	verifySignedDataDetailed,
} from '#micro509/internal/crypto/sig-verify.ts';
import { canonicalDnKey, compareDistinguishedNames } from '#micro509/internal/shared/dn.ts';
import { splitPemBlocks } from '#micro509/pem/pem.ts';
import type {
	CertificateSource,
	TrustAnchor,
	VerifyChainFailure,
	VerifyErrorCode,
	VerifyFailureDetails,
} from '#micro509/verify/verify.ts';
import type { ParsedCertificate } from '#micro509/x509/parse.ts';
import { parseCertificateDer } from '#micro509/x509/parse.ts';

/** Result of the internal chain-building search. */
export interface InternalBuildResult {
	/** Deepest chain found (leaf-to-root order), may be partial if no root was reached. */
	readonly chain: readonly ParsedCertificate[];
	/** `true` when the chain terminates at a trusted root or anchor. */
	readonly foundTrustedRoot: boolean;
	/** Chain index where no issuer candidate existed, when the search dead-ended. */
	readonly missingIssuerAt?: number;
	/** Best failure encountered during the search, for diagnostic reporting. */
	readonly failure?: VerifyChainFailure;
}

/** Result of attempting to match a certificate against bare trust anchors. */
interface TrustAnchorMatchResult {
	/** `true` if a trust anchor verified the certificate's signature. */
	readonly matched: boolean;
	/** Failure to report when matching was attempted but signature verification failed. */
	readonly failure?: VerifyChainFailure;
}

/** Loose input for constructing failure detail objects during path building. */
interface VerifyPathFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly issuerCommonName?: string | undefined;
	readonly expected?: string | undefined;
	readonly actual?: string | undefined;
	readonly chainCommonNames?: readonly string[] | undefined;
}

/** Callbacks injected by the caller to construct failure objects during path building. */
export interface VerifyPathCallbacks {
	/** Constructs a {@linkcode VerifyChainFailure} from a code, message, chain index, and details. */
	readonly failure: (
		code: VerifyErrorCode,
		message: string,
		index?: number,
		details?: VerifyFailureDetails,
	) => VerifyChainFailure;
	/** Constructs a {@linkcode VerifyFailureDetails} from loose inputs. */
	readonly detail: (input: VerifyPathFailureDetailsInput) => VerifyFailureDetails;
}

/** Returns `true` if `at` falls within the certificate's notBefore/notAfter window (inclusive). */
export function isWithinValidity(certificate: ParsedCertificate, at: Date): boolean {
	return (
		certificate.notBefore.getTime() <= at.getTime() &&
		at.getTime() <= certificate.notAfter.getTime()
	);
}

/** Returns `true` if the certificate's subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
export function isSelfIssued(certificate: ParsedCertificate): boolean {
	return compareDistinguishedNames(certificate.subject, certificate.issuer);
}

/** Counts non-self-issued CA certificates in positions 0..(index-1) for pathLength checking. */
export function countCaCertificatesBelowParsed(
	chain: readonly ParsedCertificate[],
	index: number,
): number {
	let total = 0;
	for (let cursor = 0; cursor < index; cursor += 1) {
		const certificate = chain[cursor];
		if (certificate?.basicConstraints?.ca === true && !isSelfIssued(certificate)) {
			total += 1;
		}
	}
	return total;
}

/** Parses an array of PEM/DER sources into parsed certificates, expanding multi-block PEM. */
export function loadCertificates(
	sources: readonly CertificateSource[],
): readonly ParsedCertificate[] {
	const loaded: ParsedCertificate[] = [];
	for (const source of sources) {
		loaded.push(...expandSource(source));
	}
	return loaded;
}

/** Parses exactly one certificate from a PEM/DER source. Throws if the source contains zero or multiple certificates. */
export function loadSingleCertificate(source: CertificateSource): ParsedCertificate {
	const loaded = expandSource(source);
	const first = loaded[0];
	if (first === undefined) {
		throw new Error('No certificate found');
	}
	if (loaded.length !== 1) {
		throw new Error('Expected a single certificate source');
	}
	return first;
}

/** Verifies that `certificate` was signed by `issuer`'s public key. */
export async function verifyCertificateSignature(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
): Promise<VerifySignedDataResult> {
	return verifySignedDataDetailed(
		certificate.signatureAlgorithmOid,
		certificate.signatureAlgorithmParametersDer,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		certificate.signatureValue,
		certificate.tbsCertificateDer,
	);
}

/**
 * Depth-first chain search from leaf to root. Tries all issuer candidates,
 * checking validity, CA constraints, AKI, pathLength, and signatures at each
 * step. Returns the first fully anchored path or the deepest partial path
 * with the best failure encountered.
 */
export async function buildChainInternal(
	leaf: ParsedCertificate,
	intermediates: readonly ParsedCertificate[],
	roots: readonly ParsedCertificate[],
	trustAnchors: readonly TrustAnchor[],
	at: Date,
	callbacks: VerifyPathCallbacks,
): Promise<InternalBuildResult> {
	const candidates = [...intermediates, ...roots];
	const subjectIndex = new Map<string, ParsedCertificate[]>();
	const order = new Map<string, number>();
	const rootFingerprints = new Set(roots.map((candidate) => fingerprint(candidate)));
	const anchorIndex = new Map<string, TrustAnchor[]>();
	for (const anchor of trustAnchors) {
		const key = canonicalDnKey(anchor.subject);
		const existing = anchorIndex.get(key);
		if (existing === undefined) {
			anchorIndex.set(key, [anchor]);
		} else {
			existing.push(anchor);
		}
	}
	let sawUntrustedAnchor = false;
	let deepestPath: readonly ParsedCertificate[] = [leaf];
	let deepestMissingIssuerAt: number | undefined;
	let preferredFailure: VerifyChainFailure | undefined;
	const deadEnds = new Set<string>();

	candidates.forEach((candidate, index) => {
		const key = canonicalDnKey(candidate.subject);
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
		current: ParsedCertificate,
		path: readonly ParsedCertificate[],
		visited: ReadonlySet<string>,
		caBelowCount: number,
	): Promise<readonly ParsedCertificate[] | undefined> {
		if (rootFingerprints.has(fingerprint(current))) {
			return path;
		}
		const matchedAnchor = await matchTrustAnchor(current, anchorIndex, callbacks, path.length - 1);
		if (matchedAnchor.failure !== undefined) {
			recordFailure(matchedAnchor.failure, path);
		}
		if (matchedAnchor.matched) {
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
			subjectIndex.get(canonicalDnKey(current.issuer)) ?? [],
			order,
			rootFingerprints,
		);
		if (issuers.length === 0) {
			const wasDeepest = path.length > deepestPath.length;
			updateDeepest(path);
			if (isSelfIssued(current)) {
				sawUntrustedAnchor = true;
			} else if (wasDeepest) {
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
			if (!isWithinValidity(issuer, at)) {
				recordFailure(
					callbacks.failure(
						'certificate_expired',
						'certificate not valid at requested time',
						path.length,
						callbacks.detail({
							subjectCommonName: issuer.subject.values.commonName,
							expected: at.toISOString(),
							actual: `${issuer.notBefore.toISOString()}..${issuer.notAfter.toISOString()}`,
						}),
					),
					path,
				);
				continue;
			}
			if (issuer.basicConstraints?.ca !== true) {
				recordFailure(
					callbacks.failure(
						'ca_required',
						'issuer must be a CA certificate',
						path.length,
						callbacks.detail({
							subjectCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (issuer.keyUsage !== undefined && !issuer.keyUsage.includes('keyCertSign')) {
				recordFailure(
					callbacks.failure(
						'key_cert_sign_required',
						'issuer missing keyCertSign',
						path.length,
						callbacks.detail({
							subjectCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			if (
				current.authorityKeyIdentifier !== undefined &&
				issuer.subjectKeyIdentifier !== undefined &&
				current.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
			) {
				recordFailure(
					callbacks.failure(
						'authority_key_identifier_mismatch',
						'authorityKeyIdentifier does not match issuer subjectKeyIdentifier',
						path.length - 1,
						callbacks.detail({
							subjectCommonName: current.subject.values.commonName,
							issuerCommonName: issuer.subject.values.commonName,
							expected: issuer.subjectKeyIdentifier,
							actual: current.authorityKeyIdentifier,
						}),
					),
					path,
				);
				continue;
			}
			const nextCaBelowCount =
				caBelowCount + (current.basicConstraints?.ca === true && !isSelfIssued(current) ? 1 : 0);
			const pathLength = issuer.basicConstraints?.pathLength;
			if (pathLength !== undefined && nextCaBelowCount > pathLength) {
				recordFailure(
					callbacks.failure(
						'path_length_exceeded',
						'path length constraint exceeded',
						path.length,
						callbacks.detail({
							subjectCommonName: issuer.subject.values.commonName,
							expected: String(pathLength),
							actual: String(nextCaBelowCount),
						}),
					),
					path,
				);
				continue;
			}
			const signatureResult = await verifyCertificateSignature(current, issuer);
			if (!signatureResult.ok) {
				recordFailure(
					callbacks.failure(
						signatureResult.code,
						signatureResult.reason,
						path.length - 1,
						callbacks.detail({
							subjectCommonName: current.subject.values.commonName,
							issuerCommonName: issuer.subject.values.commonName,
							actual: signatureResult.reason,
						}),
					),
					path,
				);
				continue;
			}
			if (!signatureResult.valid) {
				recordFailure(
					callbacks.failure(
						'signature_invalid',
						'certificate signature does not verify',
						path.length - 1,
						callbacks.detail({
							subjectCommonName: current.subject.values.commonName,
							issuerCommonName: issuer.subject.values.commonName,
						}),
					),
					path,
				);
				continue;
			}
			const nextVisited = new Set(visited);
			nextVisited.add(issuerFingerprint);
			const nextPath = [...path, issuer];
			const result = await search(issuer, nextPath, nextVisited, nextCaBelowCount);
			if (result !== undefined) {
				return result;
			}
		}

		deadEnds.add(memoKey);
		updateDeepest(path);
		return undefined;
	}

	function updateDeepest(path: readonly ParsedCertificate[]): boolean {
		if (path.length > deepestPath.length) {
			deepestPath = path;
			return true;
		}
		return false;
	}

	function recordFailure(
		candidateFailure: VerifyChainFailure,
		path: readonly ParsedCertificate[],
	): void {
		if (preferredFailure === undefined || path.length >= deepestPath.length) {
			preferredFailure = candidateFailure;
		}
	}
}

/** Expands a PEM (possibly multi-block) or DER source into parsed certificates. */
function expandSource(source: CertificateSource): readonly ParsedCertificate[] {
	if (typeof source === 'string') {
		return splitPemBlocks(source)
			.filter((block) => block.label === 'CERTIFICATE')
			.map((block) => parseCertificateDer(block.bytes));
	}
	return [parseCertificateDer(new Uint8Array(source))];
}

/** Filters and sorts issuer candidates: AKI match first, then roots, then input order. */
function rankIssuerCandidates(
	current: ParsedCertificate,
	candidates: readonly ParsedCertificate[],
	order: ReadonlyMap<string, number>,
	rootFingerprints: ReadonlySet<string>,
): readonly ParsedCertificate[] {
	const aki = current.authorityKeyIdentifier;
	const filtered = [...candidates].filter((candidate) => isIssuerOf(candidate, current));
	const fps = new Map<ParsedCertificate, string>();
	for (const candidate of filtered) {
		fps.set(candidate, fingerprint(candidate));
	}
	return filtered.sort((left, right) => {
		const akiScore = compareBooleans(matchesAki(left, aki), matchesAki(right, aki));
		if (akiScore !== 0) {
			return akiScore;
		}
		const leftFp = fps.get(left) ?? '';
		const rightFp = fps.get(right) ?? '';
		const rootScore = compareBooleans(rootFingerprints.has(leftFp), rootFingerprints.has(rightFp));
		if (rootScore !== 0) {
			return rootScore;
		}
		return (
			(order.get(leftFp) ?? Number.MAX_SAFE_INTEGER) -
			(order.get(rightFp) ?? Number.MAX_SAFE_INTEGER)
		);
	});
}

/** Returns `true` if the candidate's SKI matches the given authority key identifier. */
function matchesAki(candidate: ParsedCertificate, aki: string | undefined): boolean {
	return (
		aki !== undefined &&
		candidate.subjectKeyIdentifier !== undefined &&
		candidate.subjectKeyIdentifier === aki
	);
}

/** Sort comparator: `true` sorts before `false`. Returns -1, 0, or 1. */
function compareBooleans(left: boolean, right: boolean): number {
	if (left === right) {
		return 0;
	}
	return left ? -1 : 1;
}

/** Returns `true` if `issuer`'s subject DN semantically matches `child`'s issuer DN (RFC 5280 §7.1). */
function isIssuerOf(issuer: ParsedCertificate, child: ParsedCertificate): boolean {
	return compareDistinguishedNames(child.issuer, issuer.subject);
}

/** Attempts to verify `certificate` against each bare trust anchor whose subject DN matches. */
async function matchTrustAnchor(
	certificate: ParsedCertificate,
	anchorIndex: ReadonlyMap<string, readonly TrustAnchor[]>,
	callbacks: VerifyPathCallbacks,
	index: number,
): Promise<TrustAnchorMatchResult> {
	const anchors = anchorIndex.get(canonicalDnKey(certificate.issuer));
	if (anchors === undefined) {
		return { matched: false };
	}
	let firstFailure: VerifyChainFailure | undefined;
	for (const anchor of anchors) {
		if (
			anchor.subjectKeyIdentifier !== undefined &&
			certificate.authorityKeyIdentifier !== undefined &&
			anchor.subjectKeyIdentifier !== certificate.authorityKeyIdentifier
		) {
			continue;
		}
		const verified = await verifySignedDataDetailed(
			certificate.signatureAlgorithmOid,
			certificate.signatureAlgorithmParametersDer,
			anchor.publicKeyAlgorithmOid,
			anchor.publicKeyParametersOid,
			anchor.subjectPublicKeyInfoDer,
			certificate.signatureValue,
			certificate.tbsCertificateDer,
		);
		if (!verified.ok) {
			// Capture the first failure but continue trying other anchors
			if (firstFailure === undefined) {
				firstFailure = callbacks.failure(
					verified.code,
					verified.reason,
					index,
					callbacks.detail({
						subjectCommonName: certificate.subject.values.commonName,
						actual: verified.reason,
					}),
				);
			}
			continue;
		}
		if (verified.valid) {
			return { matched: true };
		}
	}
	return firstFailure !== undefined
		? { matched: false, failure: firstFailure }
		: { matched: false };
}

/** Returns a hex fingerprint of the certificate's raw DER, used for cycle detection and dedup. */
function fingerprint(certificate: ParsedCertificate): string {
	return toHex(certificate.der);
}
