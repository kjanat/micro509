import { readSequenceChildren } from "./der.ts";
import { type ExtendedKeyUsage } from "./extensions.ts";
import { getCrypto, importSpkiDer, type PublicKeyImportInput } from "./keys.ts";
import { OIDS } from "./oids.ts";
import {
	parseCertificateDer,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
	type ParsedCertificate,
	type ParsedCertificateSigningRequest,
} from "./parse.ts";
import { splitPemBlocks } from "./pem.ts";

export type CertificateSource = string | Uint8Array;
export type CsrSource = string | Uint8Array;

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

export type VerifyChainResult =
	| { readonly ok: true; readonly value: VerifiedCertificateChain }
	| {
		readonly ok: false;
		readonly code: VerifyErrorCode;
		readonly message: string;
		readonly index?: number;
		readonly details?: VerifyFailureDetails;
	};

interface LoadedCertificate {
	readonly der: Uint8Array;
	readonly parsed: ParsedCertificate;
}

interface BuildChainResult {
	readonly chain: readonly LoadedCertificate[];
	readonly foundTrustedRoot: boolean;
	readonly missingIssuerAt?: number;
}

interface VerifyFailureDetailsInput {
	readonly subjectCommonName?: string | undefined;
	readonly issuerCommonName?: string | undefined;
	readonly expected?: string | undefined;
	readonly actual?: string | undefined;
	readonly chainCommonNames?: readonly string[] | undefined;
}

interface VerifySignatureConfig {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
}

export async function verifyCertificateChain(
	input: VerifyCertificateChainInput,
): Promise<VerifyChainResult> {
	const leaf = loadSingleCertificate(input.leaf);
	const intermediates = loadCertificates(input.intermediates ?? []);
	const roots = loadCertificates(input.roots);
	const at = input.at ?? new Date();
	const buildResult = buildChain(leaf, intermediates, roots);
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
				chainCommonNames: chain.map((certificate) => certificate.parsed.subject.values.commonName ?? "<unnamed>"),
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
		if (index === chain.length - 1) {
			continue;
		}
		const issuer = chain[index + 1];
		if (issuer === undefined) {
			return failure("issuer_not_found", "issuer missing", index);
		}
		const signatureValid = await verifyCertificateSignature(current.parsed, issuer.parsed);
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
			&& current.parsed.authorityKeyIdentifier !== issuer.parsed.subjectKeyIdentifier
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
		const sans = leaf.parsed.subjectAltNames?.filter((entry) => entry.type === "dns") ?? [];
		if (!sans.some((entry) => matchesDnsName(entry.value, input.dnsName ?? ""))) {
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
					actual: sans.map((entry) => normalizeIpAddress(entry.value)).join(","),
				}),
			);
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

async function verifySignedData(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	spkiDer: Uint8Array,
	signatureValue: Uint8Array,
	data: Uint8Array,
): Promise<boolean> {
	const config = getVerifySignatureConfig(
		signatureAlgorithmOid,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
	);
	const issuerKey = await importSpkiDer(spkiDer, config.importAlgorithm);
	const subtle = getCrypto().subtle;
	const signatureView = new Uint8Array(signatureValue);
	const dataView = new Uint8Array(data);
	if (await subtle.verify(config.verifyParams, issuerKey, signatureView, dataView)) {
		return true;
	}
	if (config.ecdsaRawSignatureBytes !== undefined && signatureValue[0] === 0x30) {
		const raw = new Uint8Array(derEcdsaSignatureToRaw(
			signatureValue,
			config.ecdsaRawSignatureBytes / 2,
		));
		return subtle.verify(config.verifyParams, issuerKey, raw, dataView);
	}
	return false;
}

function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): VerifySignatureConfig {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(publicKeyAlgorithmOid, "SHA-256"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha384WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(publicKeyAlgorithmOid, "SHA-384"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha512WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(publicKeyAlgorithmOid, "SHA-512"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.ecdsaWithSHA256:
			return {
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid),
				verifyParams: { name: "ECDSA", hash: "SHA-256" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA384:
			return {
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid),
				verifyParams: { name: "ECDSA", hash: "SHA-384" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error("Ed25519 signature requires Ed25519 issuer public key");
			}
			return {
				importAlgorithm: { kind: "ed25519" },
				verifyParams: { name: "Ed25519" },
			};
		default:
			throw new Error(`Unsupported signature algorithm OID: ${signatureAlgorithmOid}`);
	}
}

function requireRsaPublicKey(
	publicKeyAlgorithmOid: string,
	hash: "SHA-256" | "SHA-384" | "SHA-512",
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.rsaEncryption) {
		throw new Error("RSA signature requires RSA issuer public key");
	}
	return { kind: "rsa", hash };
}

function requireEcPublicKey(
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.ecPublicKey) {
		throw new Error("ECDSA signature requires EC issuer public key");
	}
	switch (publicKeyParametersOid) {
		case OIDS.prime256v1:
			return { kind: "ecdsa", namedCurve: "P-256" };
		case OIDS.secp384r1:
			return { kind: "ecdsa", namedCurve: "P-384" };
		default:
			throw new Error(`Unsupported EC curve OID: ${publicKeyParametersOid ?? "missing"}`);
	}
}

function curveBytes(parametersOid: string | undefined): number {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		default:
			throw new Error(`Unsupported EC curve OID: ${parametersOid ?? "missing"}`);
	}
}

function derEcdsaSignatureToRaw(signature: Uint8Array, partLength: number): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error("Malformed ECDSA DER signature");
	}
	return concatFixedWidth(trimLeadingZero(r.value), trimLeadingZero(s.value), partLength);
}

function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}

function concatFixedWidth(left: Uint8Array, right: Uint8Array, partLength: number): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error("ECDSA signature integer too large");
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
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

function failure(
	code: VerifyErrorCode,
	message: string,
	index?: number,
	details?: VerifyFailureDetails,
): VerifyChainResult {
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
		chainCommonNames: chain.map((entry) => entry.parsed.subject.values.commonName ?? "<unnamed>"),
	});
}

function formatEku(value: ExtendedKeyUsage): string {
	return typeof value === "string" ? value : value.value;
}

function detail(input: VerifyFailureDetailsInput): VerifyFailureDetails {
	return {
		...(input.subjectCommonName === undefined ? {} : { subjectCommonName: input.subjectCommonName }),
		...(input.issuerCommonName === undefined ? {} : { issuerCommonName: input.issuerCommonName }),
		...(input.expected === undefined ? {} : { expected: input.expected }),
		...(input.actual === undefined ? {} : { actual: input.actual }),
		...(input.chainCommonNames === undefined ? {} : { chainCommonNames: input.chainCommonNames }),
	};
}
