import { toHex } from './asn1.ts';
import type { ParsedCertificate } from './parse.ts';
import { parseCertificateDer } from './parse.ts';
import { splitPemBlocks } from './pem.ts';
import { type VerifySignedDataResult, verifySignedDataDetailed } from './sig-verify.ts';
import type {
	CertificateSource,
	TrustAnchor,
	VerifyChainFailure,
	VerifyErrorCode,
	VerifyFailureDetails,
} from './verify.ts';

export interface InternalBuildResult {
	readonly chain: readonly ParsedCertificate[];
	readonly foundTrustedRoot: boolean;
	readonly missingIssuerAt?: number;
	readonly failure?: VerifyChainFailure;
}

interface TrustAnchorMatchResult {
	readonly matched: boolean;
	readonly failure?: VerifyChainFailure;
}

interface VerifyPathFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly issuerCommonName?: string | undefined;
	readonly expected?: string | undefined;
	readonly actual?: string | undefined;
	readonly chainCommonNames?: readonly string[] | undefined;
}

export interface VerifyPathCallbacks {
	readonly failure: (
		code: VerifyErrorCode,
		message: string,
		index?: number,
		details?: VerifyFailureDetails,
	) => VerifyChainFailure;
	readonly detail: (input: VerifyPathFailureDetailsInput) => VerifyFailureDetails;
}

export function isWithinValidity(certificate: ParsedCertificate, at: Date): boolean {
	return (
		certificate.notBefore.getTime() <= at.getTime() &&
		at.getTime() <= certificate.notAfter.getTime()
	);
}

export function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

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

export function loadCertificates(
	sources: readonly CertificateSource[],
): readonly ParsedCertificate[] {
	const loaded: ParsedCertificate[] = [];
	for (const source of sources) {
		loaded.push(...expandSource(source));
	}
	return loaded;
}

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
		const existing = anchorIndex.get(anchor.subjectDerHex);
		if (existing === undefined) {
			anchorIndex.set(anchor.subjectDerHex, [anchor]);
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
		const key = candidate.subject.derHex;
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
			subjectIndex.get(current.issuer.derHex) ?? [],
			order,
			rootFingerprints,
		);
		if (issuers.length === 0) {
			updateDeepest(path);
			if (isSelfIssued(current)) {
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

	function updateDeepest(path: readonly ParsedCertificate[]): void {
		if (path.length > deepestPath.length) {
			deepestPath = path;
		}
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

function expandSource(source: CertificateSource): readonly ParsedCertificate[] {
	if (typeof source === 'string') {
		return splitPemBlocks(source)
			.filter((block) => block.label === 'CERTIFICATE')
			.map((block) => parseCertificateDer(block.bytes));
	}
	return [parseCertificateDer(new Uint8Array(source))];
}

function rankIssuerCandidates(
	current: ParsedCertificate,
	candidates: readonly ParsedCertificate[],
	order: ReadonlyMap<string, number>,
	rootFingerprints: ReadonlySet<string>,
): readonly ParsedCertificate[] {
	const aki = current.authorityKeyIdentifier;
	return [...candidates]
		.filter((candidate) => isIssuerOf(candidate, current))
		.sort((left, right) => {
			const akiScore = compareBooleans(matchesAki(left, aki), matchesAki(right, aki));
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
				(order.get(fingerprint(left)) ?? Number.MAX_SAFE_INTEGER) -
				(order.get(fingerprint(right)) ?? Number.MAX_SAFE_INTEGER)
			);
		});
}

function matchesAki(candidate: ParsedCertificate, aki: string | undefined): boolean {
	return (
		aki !== undefined &&
		candidate.subjectKeyIdentifier !== undefined &&
		candidate.subjectKeyIdentifier === aki
	);
}

function compareBooleans(left: boolean, right: boolean): number {
	if (left === right) {
		return 0;
	}
	return left ? -1 : 1;
}

function isIssuerOf(issuer: ParsedCertificate, child: ParsedCertificate): boolean {
	return child.issuer.derHex === issuer.subject.derHex;
}

async function matchTrustAnchor(
	certificate: ParsedCertificate,
	anchorIndex: ReadonlyMap<string, readonly TrustAnchor[]>,
	callbacks: VerifyPathCallbacks,
	index: number,
): Promise<TrustAnchorMatchResult> {
	const anchors = anchorIndex.get(certificate.issuer.derHex);
	if (anchors === undefined) {
		return { matched: false };
	}
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
			return {
				matched: false,
				failure: callbacks.failure(
					verified.code,
					verified.reason,
					index,
					callbacks.detail({
						subjectCommonName: certificate.subject.values.commonName,
						actual: verified.reason,
					}),
				),
			};
		}
		if (verified.valid) {
			return { matched: true };
		}
	}
	return { matched: false };
}

function fingerprint(certificate: ParsedCertificate): string {
	return toHex(certificate.der);
}
