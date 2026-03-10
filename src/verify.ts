import { Buffer } from "node:buffer";
import { X509Certificate } from "node:crypto";
import { parseCertificateChainPem, parseCertificateDer, parseCertificatePem, type ParsedCertificate } from "./parse.ts";

export type CertificateSource = string | Uint8Array;

export type VerifyPurpose = "serverAuth" | "clientAuth" | "ca";

export interface VerifyCertificateChainInput {
	readonly leaf: CertificateSource;
	readonly intermediates?: readonly CertificateSource[];
	readonly roots: readonly CertificateSource[];
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
	| "self_signed_leaf_not_allowed";

export interface VerifiedCertificateChain {
	readonly leaf: ParsedCertificate;
	readonly chain: readonly ParsedCertificate[];
	readonly root: ParsedCertificate;
}

export type VerifyChainResult =
	| { readonly ok: true; readonly value: VerifiedCertificateChain }
	| {
		readonly ok: false;
		readonly code: VerifyErrorCode;
		readonly message: string;
		readonly index?: number;
	};

interface LoadedCertificate {
	readonly der: Uint8Array;
	readonly parsed: ParsedCertificate;
	readonly x509: X509Certificate;
}

interface BuildChainResult {
	readonly chain: readonly LoadedCertificate[];
	readonly foundTrustedRoot: boolean;
	readonly missingIssuerAt?: number;
}

export function verifyCertificateChain(input: VerifyCertificateChainInput): VerifyChainResult {
	const leaf = loadSingleCertificate(input.leaf);
	const intermediates = loadCertificates(input.intermediates ?? []);
	const roots = loadCertificates(input.roots);
	const at = input.at ?? new Date();
	const buildResult = buildChain(leaf, intermediates, roots);
	const chain = buildResult.chain;

	if (chain.length === 1 && isSelfIssued(leaf.parsed)) {
		if (!input.allowSelfSignedLeaf) {
			return failure("self_signed_leaf_not_allowed", "self-signed leaf not allowed", 0);
		}
	}

	if (!buildResult.foundTrustedRoot) {
		if (buildResult.missingIssuerAt !== undefined) {
			return failure("issuer_not_found", "issuer certificate not found", buildResult.missingIssuerAt);
		}
		return failure("no_trusted_root", "no trusted root found");
	}

	for (let index = 0; index < chain.length; index += 1) {
		const current = chain[index];
		if (current === undefined) {
			return failure("issuer_not_found", "chain element missing", index);
		}
		if (!isWithinValidity(current.parsed, at)) {
			return failure("certificate_expired", "certificate not valid at requested time", index);
		}
		if (index === chain.length - 1) {
			continue;
		}
		const issuer = chain[index + 1];
		if (issuer === undefined) {
			return failure("issuer_not_found", "issuer missing", index);
		}
		if (!current.x509.verify(issuer.x509.publicKey)) {
			return failure("signature_invalid", "certificate signature does not verify", index);
		}
		if (issuer.parsed.basicConstraints?.ca !== true) {
			return failure("ca_required", "issuer must be a CA certificate", index + 1);
		}
		if (
			issuer.parsed.keyUsage !== undefined
			&& !issuer.parsed.keyUsage.includes("keyCertSign")
		) {
			return failure("key_cert_sign_required", "issuer missing keyCertSign", index + 1);
		}
		if (
			current.parsed.authorityKeyIdentifier !== undefined
			&& issuer.parsed.subjectKeyIdentifier !== undefined
			&& current.parsed.authorityKeyIdentifier !== issuer.parsed.subjectKeyIdentifier
		) {
			return failure(
				"authority_key_identifier_mismatch",
				"authorityKeyIdentifier does not match issuer subjectKeyIdentifier",
				index,
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
			return failure("path_length_exceeded", "path length constraint exceeded", index);
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
				return failure("ca_required", "leaf is not a CA certificate", 0);
			}
		} else if (
			leaf.parsed.extendedKeyUsage !== undefined
			&& !leaf.parsed.extendedKeyUsage.includes(purpose)
		) {
			return failure("extended_key_usage_invalid", `leaf missing EKU ${purpose}`, 0);
		}
	}
	if (input.dnsName !== undefined) {
		const sans = leaf.parsed.subjectAltNames?.filter((entry) => entry.type === "dns") ?? [];
		if (!sans.some((entry) => matchesDnsName(entry.value, input.dnsName ?? ""))) {
			return failure("subject_alt_name_mismatch", "DNS name not present in SAN", 0);
		}
	}
	if (input.ipAddress !== undefined) {
		const expected = normalizeIpAddress(input.ipAddress);
		const sans = leaf.parsed.subjectAltNames?.filter((entry) => entry.type === "ip") ?? [];
		if (!sans.some((entry) => normalizeIpAddress(entry.value) === expected)) {
			return failure("subject_alt_name_mismatch", "IP address not present in SAN", 0);
		}
	}
	return { ok: true };
}

function buildChain(
	leaf: LoadedCertificate,
	intermediates: readonly LoadedCertificate[],
	roots: readonly LoadedCertificate[],
): BuildChainResult {
	const chain: LoadedCertificate[] = [leaf];
	const remainingIntermediates = [...intermediates];
	while (true) {
		const current = chain[chain.length - 1];
		if (current === undefined) {
			break;
		}
		const trustedRoot = findIssuer(current, roots);
		if (trustedRoot !== undefined) {
			if (!isSameCertificate(current, trustedRoot)) {
				chain.push(trustedRoot);
			}
			return { chain, foundTrustedRoot: true };
		}
		if (isTrustedSelfSignedRoot(current, roots)) {
			return { chain, foundTrustedRoot: true };
		}
		const issuerIndex = remainingIntermediates.findIndex((candidate) => isIssuerOf(candidate, current));
		if (issuerIndex === -1) {
			return isSelfIssued(current.parsed)
				? { chain, foundTrustedRoot: false }
				: { chain, foundTrustedRoot: false, missingIssuerAt: chain.length - 1 };
		}
		const issuer = remainingIntermediates[issuerIndex];
		if (issuer === undefined) {
			return { chain, foundTrustedRoot: false, missingIssuerAt: chain.length - 1 };
		}
		chain.push(issuer);
		remainingIntermediates.splice(issuerIndex, 1);
	}
	return { chain, foundTrustedRoot: false };
}

function findIssuer(
	certificate: LoadedCertificate,
	candidates: readonly LoadedCertificate[],
): LoadedCertificate | undefined {
	const aki = certificate.parsed.authorityKeyIdentifier;
	if (aki !== undefined) {
		for (const candidate of candidates) {
			if (
				isIssuerOf(candidate, certificate)
				&& candidate.parsed.subjectKeyIdentifier !== undefined
				&& candidate.parsed.subjectKeyIdentifier === aki
			) {
				return candidate;
			}
		}
	}
	return candidates.find((candidate) => isIssuerOf(candidate, certificate));
}

function isIssuerOf(issuer: LoadedCertificate, child: LoadedCertificate): boolean {
	return child.parsed.issuer.derHex === issuer.parsed.subject.derHex;
}

function isWithinValidity(certificate: ParsedCertificate, at: Date): boolean {
	return certificate.notBefore.getTime() <= at.getTime() && at.getTime() <= certificate.notAfter.getTime();
}

function isSelfIssued(certificate: ParsedCertificate): boolean {
	return certificate.subject.derHex === certificate.issuer.derHex;
}

function countCaCertificatesBelow(chain: readonly LoadedCertificate[], index: number): number {
	let total = 0;
	for (let cursor = 0; cursor < index; cursor += 1) {
		const certificate = chain[cursor];
		if (certificate?.parsed.basicConstraints?.ca === true) {
			total += 1;
		}
	}
	return total;
}

function loadCertificates(sources: readonly CertificateSource[]): readonly LoadedCertificate[] {
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
		const pemCertificates = parseCertificateChainPem(source);
		if (pemCertificates.length > 0) {
			const blocks = splitPemCertificates(source);
			return pemCertificates.map((parsed, index) => {
				const pem = blocks[index];
				if (pem === undefined) {
					throw new Error("PEM parse mismatch");
				}
				return {
					der: extractDerFromX509(new X509Certificate(pem)),
					parsed,
					x509: new X509Certificate(pem),
				};
			});
		}
		throw new Error("Certificate PEM required");
	}
	return [loadDerCertificate(source)];
}

function loadDerCertificate(der: Uint8Array): LoadedCertificate {
	const bytes = new Uint8Array(der);
	return {
		der: bytes,
		parsed: parseCertificateDer(bytes),
		x509: new X509Certificate(Buffer.from(bytes)),
	};
}

function splitPemCertificates(pemBundle: string): readonly string[] {
	const normalized = pemBundle.replace(/\r/g, "");
	return Array.from(
		normalized.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g),
		(match) => match[0],
	);
}

function extractDerFromX509(certificate: X509Certificate): Uint8Array {
	return new Uint8Array(certificate.raw);
}

function isSameCertificate(left: LoadedCertificate, right: LoadedCertificate): boolean {
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

function isTrustedSelfSignedRoot(
	certificate: LoadedCertificate,
	roots: readonly LoadedCertificate[],
): boolean {
	return isSelfIssued(certificate.parsed) && roots.some((candidate) => isSameCertificate(candidate, certificate));
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
	return (tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts]).map((segment) =>
		segment.padStart(4, "0")
	);
}

function failure(code: VerifyErrorCode, message: string, index?: number): VerifyChainResult {
	return index === undefined ? { ok: false, code, message } : { ok: false, code, message, index };
}
