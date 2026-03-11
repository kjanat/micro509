import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	requireElement,
	toArrayBuffer,
	toHex,
} from "./asn1.ts";
import {
	concatBytes,
	type DerElement,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from "./der.ts";
import { getCrypto } from "./keys.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemEncode, splitPemBlocks } from "./pem.ts";
import { verifySignedData } from "./sig-verify.ts";

export type Pkcs7CertificateSource = string | Uint8Array;

export interface Pkcs7CertBag {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface ParsedPkcs7SignerInfo {
	readonly version: number;
	readonly issuerDerHex?: string;
	readonly serialNumberHex?: string;
	readonly digestAlgorithmOid: string;
	readonly signatureAlgorithmOid: string;
	readonly signatureHex: string;
	readonly signature: Uint8Array;
	readonly hasSignedAttrs: boolean;
	/** Raw DER of signedAttrs with original IMPLICIT [0] tag (0xa0). Present only when hasSignedAttrs is true. */
	readonly signedAttrsDer?: Uint8Array;
}

export interface ParsedPkcs7SignedData {
	readonly contentTypeOid: string;
	readonly version: number;
	readonly digestAlgorithmOids: readonly string[];
	readonly encapsulatedContentTypeOid: string;
	readonly encapsulatedContent?: Uint8Array;
	readonly certificates: readonly ParsedCertificate[];
	readonly signerInfos: readonly ParsedPkcs7SignerInfo[];
}

// ---------------------------------------------------------------------------
// Result types for PKCS#7 parsing
// ---------------------------------------------------------------------------

export type ParsePkcs7ErrorCode = "malformed" | "not_signed_data";

export type ParsePkcs7SignedDataResult =
	| { readonly ok: true; readonly value: ParsedPkcs7SignedData }
	| {
		readonly ok: false;
		readonly code: ParsePkcs7ErrorCode;
		readonly message: string;
	};

export type ParsePkcs7CertBagResult =
	| { readonly ok: true; readonly value: readonly ParsedCertificate[] }
	| {
		readonly ok: false;
		readonly code: ParsePkcs7ErrorCode;
		readonly message: string;
	};

export type VerifyPkcs7SignedDataResult =
	| { readonly ok: true; readonly value: ParsedPkcs7SignedData }
	| {
		readonly ok: false;
		readonly code:
			| "signer_not_found"
			| "signature_invalid"
			| "message_digest_mismatch"
			| "content_missing"
			| ParsePkcs7ErrorCode;
		readonly message: string;
	};

// ---------------------------------------------------------------------------
// createPkcs7CertBag
// ---------------------------------------------------------------------------

export function createPkcs7CertBagDer(
	certificates: readonly Pkcs7CertificateSource[],
): Uint8Array {
	const certificateDers = certificates.flatMap(normalizeCertificateSource);
	const signedData = sequence([
		integerFromNumber(1),
		setOf([]),
		sequence([objectIdentifier(OIDS.pkcs7Data)]),
		explicitContext(0, concatBytes(certificateDers)),
		setOf([]),
	]);
	return sequence([
		objectIdentifier(OIDS.pkcs7SignedData),
		explicitContext(0, signedData),
	]);
}

export function createPkcs7CertBagPem(
	certificates: readonly Pkcs7CertificateSource[],
): Pkcs7CertBag {
	const der = createPkcs7CertBagDer(certificates);
	return {
		der,
		pem: pemEncode("PKCS7", der),
		base64: base64Encode(der),
	};
}

// ---------------------------------------------------------------------------
// parsePkcs7CertBag — Result-returning
// ---------------------------------------------------------------------------

export function parsePkcs7CertBagDer(der: Uint8Array): ParsePkcs7CertBagResult {
	const result = parsePkcs7SignedDataDer(der);
	if (!result.ok) {
		return result;
	}
	return { ok: true, value: result.value.certificates };
}

export function parsePkcs7CertBagPem(pem: string): ParsePkcs7CertBagResult {
	const blocks = splitPemBlocks(pem).filter((block) => block.label === "PKCS7");
	if (blocks.length !== 1) {
		return pkcs7Failure("malformed", "Expected exactly one PKCS7 PEM block");
	}
	const block = blocks[0];
	if (block === undefined) {
		return pkcs7Failure("malformed", "Missing PKCS7 block");
	}
	return parsePkcs7CertBagDer(block.bytes);
}

// ---------------------------------------------------------------------------
// parsePkcs7SignedData — Result-returning
// ---------------------------------------------------------------------------

export function parsePkcs7SignedDataDer(
	der: Uint8Array,
): ParsePkcs7SignedDataResult {
	try {
		const contentInfo = readSequenceChildren(der);
		const contentType = contentInfo[0];
		const content = contentInfo[1];
		if (contentType === undefined || content === undefined) {
			return pkcs7Failure("malformed", "Malformed PKCS#7 content info");
		}
		const contentTypeOid = decodeObjectIdentifier(contentType.value);
		if (contentTypeOid !== OIDS.pkcs7SignedData) {
			return pkcs7Failure(
				"not_signed_data",
				"PKCS#7 content is not signedData",
			);
		}
		const signedData = childAt(der, content, 0, "signedData");
		const signedDataChildren = childrenOf(der, signedData);
		const version = signedDataChildren[0];
		const digestAlgorithms = signedDataChildren[1];
		const encapContentInfo = signedDataChildren[2];
		const certificates = signedDataChildren[3];
		const signerInfos = signedDataChildren[signedDataChildren.length - 1];
		if (
			version === undefined
			|| digestAlgorithms === undefined
			|| encapContentInfo === undefined
			|| signerInfos === undefined
		) {
			return pkcs7Failure("malformed", "Malformed SignedData");
		}
		const encapDer = der.slice(
			encapContentInfo.start - encapContentInfo.headerLength,
			encapContentInfo.end,
		);
		const encapChildren = readSequenceChildren(encapDer);
		const encapType = encapChildren[0];
		const encapContent = encapChildren[1];
		if (encapType === undefined) {
			return pkcs7Failure("malformed", "Malformed EncapsulatedContentInfo");
		}
		return {
			ok: true,
			value: {
				contentTypeOid,
				version: decodeIntegerNumber(version.value),
				digestAlgorithmOids: parseDigestAlgorithms(der, digestAlgorithms),
				encapsulatedContentTypeOid: decodeObjectIdentifier(encapType.value),
				...(encapContent === undefined
					? {}
					: {
						encapsulatedContent: extractEncapsulatedContent(
							encapDer,
							encapContent,
						),
					}),
				certificates: parseCertificateSet(der, certificates),
				signerInfos: parseSignerInfos(der, signerInfos),
			},
		};
	} catch {
		return pkcs7Failure("malformed", "Malformed PKCS#7 structure");
	}
}

export function parsePkcs7SignedDataPem(
	pem: string,
): ParsePkcs7SignedDataResult {
	const blocks = splitPemBlocks(pem).filter((block) => block.label === "PKCS7");
	const block = blocks[0];
	if (block === undefined || blocks.length !== 1) {
		return pkcs7Failure("malformed", "Expected exactly one PKCS7 PEM block");
	}
	return parsePkcs7SignedDataDer(block.bytes);
}

// ---------------------------------------------------------------------------
// verifyPkcs7SignedData
// ---------------------------------------------------------------------------

export async function verifyPkcs7SignedData(
	input: string | Uint8Array | ParsedPkcs7SignedData,
): Promise<VerifyPkcs7SignedDataResult> {
	let parsed: ParsedPkcs7SignedData;
	if (typeof input === "string") {
		const result = parsePkcs7SignedDataPem(input);
		if (!result.ok) {
			return result;
		}
		parsed = result.value;
	} else if (input instanceof Uint8Array) {
		const result = parsePkcs7SignedDataDer(input);
		if (!result.ok) {
			return result;
		}
		parsed = result.value;
	} else {
		parsed = input;
	}
	if (parsed.encapsulatedContent === undefined) {
		return {
			ok: false,
			code: "content_missing",
			message: "SignedData encapsulated content is missing",
		};
	}
	for (const signerInfo of parsed.signerInfos) {
		const signer = parsed.certificates.find(
			(certificate) =>
				signerInfo.serialNumberHex !== undefined
				&& signerInfo.issuerDerHex !== undefined
				&& certificate.serialNumberHex === signerInfo.serialNumberHex
				&& certificate.issuer.derHex === signerInfo.issuerDerHex,
		);
		if (signer === undefined) {
			return {
				ok: false,
				code: "signer_not_found",
				message: "Signer certificate not found in SignedData certificates",
			};
		}
		if (signerInfo.hasSignedAttrs) {
			const attrsResult = await verifySignedAttrs(
				signerInfo,
				signer,
				parsed.encapsulatedContent,
			);
			if (!attrsResult.ok) {
				return attrsResult;
			}
			continue;
		}
		const verified = await verifySignedData(
			signerInfo.signatureAlgorithmOid,
			signer.publicKeyAlgorithmOid,
			signer.publicKeyParametersOid,
			signer.subjectPublicKeyInfoDer,
			signerInfo.signature,
			parsed.encapsulatedContent,
		);
		if (!verified) {
			return {
				ok: false,
				code: "signature_invalid",
				message: "SignedData signature does not verify",
			};
		}
	}
	return { ok: true, value: parsed };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function pkcs7Failure(
	code: ParsePkcs7ErrorCode,
	message: string,
): {
	readonly ok: false;
	readonly code: ParsePkcs7ErrorCode;
	readonly message: string;
} {
	return { ok: false, code, message };
}

function normalizeCertificateSource(
	source: Pkcs7CertificateSource,
): readonly Uint8Array[] {
	if (typeof source === "string") {
		return splitPemBlocks(source)
			.filter((block) => block.label === "CERTIFICATE")
			.map((block) => new Uint8Array(block.bytes));
	}
	return [new Uint8Array(source)];
}

function parseCertificateSet(
	source: Uint8Array,
	certificates: ReturnType<typeof readElement> | undefined,
): readonly ParsedCertificate[] {
	if (certificates === undefined || certificates.tag !== 0xa0) {
		return [];
	}
	const parsed: ParsedCertificate[] = [];
	let offset = certificates.start;
	while (offset < certificates.end) {
		const element = readElement(source, offset);
		parsed.push(parseCertificateDer(source.slice(offset, element.end)));
		offset = element.end;
	}
	return parsed;
}

function parseDigestAlgorithms(
	source: Uint8Array,
	element: ReturnType<typeof readElement>,
): readonly string[] {
	const digests: string[] = [];
	for (const child of childrenOf(source, element)) {
		const childDer = source.slice(child.start - child.headerLength, child.end);
		const parts = readSequenceChildren(childDer);
		const oid = parts[0];
		if (oid !== undefined) {
			digests.push(decodeObjectIdentifier(oid.value));
		}
	}
	return digests;
}

function parseSignerInfos(
	source: Uint8Array,
	element: ReturnType<typeof readElement>,
): readonly ParsedPkcs7SignerInfo[] {
	const signers: ParsedPkcs7SignerInfo[] = [];
	for (const signerInfo of childrenOf(source, element)) {
		const signerDer = source.slice(
			signerInfo.start - signerInfo.headerLength,
			signerInfo.end,
		);
		const parts = readSequenceChildren(signerDer);
		const version = parts[0];
		const sid = parts[1];
		const digestAlgorithm = parts[2];
		let index = 3;
		const signedAttrsElement = parts[index]?.tag === 0xa0 ? parts[index] : undefined;
		const hasSignedAttrs = signedAttrsElement !== undefined;
		if (hasSignedAttrs) {
			index += 1;
		}
		const signatureAlgorithm = parts[index];
		const signature = parts[index + 1];
		if (
			version === undefined
			|| sid === undefined
			|| digestAlgorithm === undefined
			|| signatureAlgorithm === undefined
			|| signature === undefined
			|| signature.tag !== 0x04
		) {
			throw new Error("Malformed SignerInfo");
		}
		const digestAlgorithmDer = signerDer.slice(
			digestAlgorithm.start - digestAlgorithm.headerLength,
			digestAlgorithm.end,
		);
		const digestAlgorithmOid = decodeObjectIdentifier(
			requireElement(
				readSequenceChildren(digestAlgorithmDer)[0],
				"digest algorithm OID",
			).value,
		);
		const signatureAlgorithmDer = signerDer.slice(
			signatureAlgorithm.start - signatureAlgorithm.headerLength,
			signatureAlgorithm.end,
		);
		const signatureAlgorithmOid = decodeObjectIdentifier(
			requireElement(
				readSequenceChildren(signatureAlgorithmDer)[0],
				"signature algorithm OID",
			).value,
		);
		const parsedSid = parseSignerIdentifier(
			signerDer.slice(sid.start - sid.headerLength, sid.end),
		);
		signers.push({
			version: decodeIntegerNumber(version.value),
			...(parsedSid.issuerDerHex === undefined
				? {}
				: { issuerDerHex: parsedSid.issuerDerHex }),
			...(parsedSid.serialNumberHex === undefined
				? {}
				: { serialNumberHex: parsedSid.serialNumberHex }),
			digestAlgorithmOid,
			signatureAlgorithmOid,
			signatureHex: toHex(signature.value),
			signature: new Uint8Array(signature.value),
			hasSignedAttrs,
			...(signedAttrsElement === undefined
				? {}
				: {
					signedAttrsDer: new Uint8Array(
						signerDer.slice(
							signedAttrsElement.start - signedAttrsElement.headerLength,
							signedAttrsElement.end,
						),
					),
				}),
		});
	}
	return signers;
}

function extractEncapsulatedContent(
	encapDer: Uint8Array,
	element: ReturnType<typeof readElement>,
): Uint8Array {
	if (element.tag !== 0xa0) {
		throw new Error("Unexpected encapsulated content tag");
	}
	const inner = readElement(encapDer, element.start);
	if (inner.tag !== 0x04) {
		throw new Error("Expected encapsulated OCTET STRING");
	}
	return inner.value;
}

function parseSignerIdentifier(der: Uint8Array): {
	readonly issuerDerHex?: string;
	readonly serialNumberHex?: string;
} {
	const top = readSequenceChildren(der);
	const issuer = top[0];
	const serial = top[1];
	if (issuer === undefined || serial === undefined) {
		return {};
	}
	return {
		issuerDerHex: toHex(
			der.slice(issuer.start - issuer.headerLength, issuer.end),
		),
		serialNumberHex: toHex(serial.value),
	};
}

function childAt(
	source: Uint8Array,
	parent: DerElement,
	index: number,
	label: string,
): DerElement {
	let offset = parent.start;
	let currentIndex = 0;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		if (currentIndex === index) {
			return child;
		}
		offset = child.end;
		currentIndex += 1;
	}
	throw new Error(`Missing ${label}`);
}

// ---------------------------------------------------------------------------
// CMS signed attributes verification (RFC 5652 Section 5.4)
// ---------------------------------------------------------------------------

function digestAlgorithmHash(
	digestAlgorithmOid: string,
): "SHA-256" | "SHA-384" | "SHA-512" {
	switch (digestAlgorithmOid) {
		case OIDS.sha256:
			return "SHA-256";
		case OIDS.sha384:
			return "SHA-384";
		case OIDS.sha512:
			return "SHA-512";
		default:
			throw new Error(
				`Unsupported digest algorithm OID: ${digestAlgorithmOid}`,
			);
	}
}

function extractMessageDigest(
	signedAttrsDer: Uint8Array,
): Uint8Array | undefined {
	// signedAttrs is IMPLICIT [0] — parse children (each is a SEQUENCE of {OID, SET OF values})
	const outer = readElement(signedAttrsDer);
	for (const attr of childrenOf(signedAttrsDer, outer)) {
		const attrDer = signedAttrsDer.slice(
			attr.start - attr.headerLength,
			attr.end,
		);
		const parts = readSequenceChildren(attrDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined) {
			continue;
		}
		if (decodeObjectIdentifier(oid.value) === OIDS.cmsMessageDigest) {
			// values is SET OF, first child is the OCTET STRING digest
			const digestElement = readElement(attrDer, values.start);
			if (digestElement.tag !== 0x04) {
				return undefined;
			}
			return digestElement.value;
		}
	}
	return undefined;
}

function retagSignedAttrsAsSet(signedAttrsDer: Uint8Array): Uint8Array {
	// Replace IMPLICIT [0] tag (0xa0) with SET OF tag (0x31) per RFC 5652 Section 5.4
	const copy = new Uint8Array(signedAttrsDer);
	copy[0] = 0x31;
	return copy;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let diff = 0;
	for (let index = 0; index < a.length; index += 1) {
		diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
	}
	return diff === 0;
}

async function verifySignedAttrs(
	signerInfo: ParsedPkcs7SignerInfo,
	signer: ParsedCertificate,
	encapsulatedContent: Uint8Array,
): Promise<
	| { readonly ok: true }
	| {
		readonly ok: false;
		readonly code:
			| "message_digest_mismatch"
			| "signature_invalid"
			| "malformed";
		readonly message: string;
	}
> {
	if (signerInfo.signedAttrsDer === undefined) {
		return { ok: false, code: "malformed", message: "Missing signedAttrs DER" };
	}
	// Step 1: Extract messageDigest attribute from signedAttrs
	const expectedDigest = extractMessageDigest(signerInfo.signedAttrsDer);
	if (expectedDigest === undefined) {
		return {
			ok: false,
			code: "malformed",
			message: "Missing messageDigest attribute in signedAttrs",
		};
	}
	// Step 2: Compute digest of encapsulated content
	const hash = digestAlgorithmHash(signerInfo.digestAlgorithmOid);
	const actualDigest = new Uint8Array(
		await getCrypto().subtle.digest(hash, toArrayBuffer(encapsulatedContent)),
	);
	// Step 3: Compare digests (constant-time)
	if (!constantTimeEqual(actualDigest, expectedDigest)) {
		return {
			ok: false,
			code: "message_digest_mismatch",
			message: "Content digest does not match messageDigest attribute",
		};
	}
	// Step 4: Verify signature over re-tagged signedAttrs (0xa0 → 0x31 SET OF)
	const signedData = retagSignedAttrsAsSet(signerInfo.signedAttrsDer);
	const verified = await verifySignedData(
		signerInfo.signatureAlgorithmOid,
		signer.publicKeyAlgorithmOid,
		signer.publicKeyParametersOid,
		signer.subjectPublicKeyInfoDer,
		signerInfo.signature,
		signedData,
	);
	if (!verified) {
		return {
			ok: false,
			code: "signature_invalid",
			message: "SignedData signature over signedAttrs does not verify",
		};
	}
	return { ok: true };
}
