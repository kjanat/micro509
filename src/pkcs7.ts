import { childrenOf, decodeIntegerNumber, decodeObjectIdentifier, requireElement, toHex } from "./asn1.ts";
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

export type VerifyPkcs7SignedDataResult =
	| { readonly ok: true; readonly value: ParsedPkcs7SignedData }
	| {
		readonly ok: false;
		readonly code:
			| "signer_not_found"
			| "signature_invalid"
			| "content_missing";
		readonly message: string;
	};

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

export function parsePkcs7CertBagDer(
	der: Uint8Array,
): readonly ParsedCertificate[] {
	return parsePkcs7SignedDataDer(der).certificates;
}

export function parsePkcs7CertBagPem(
	pem: string,
): readonly ParsedCertificate[] {
	const blocks = splitPemBlocks(pem).filter((block) => block.label === "PKCS7");
	if (blocks.length !== 1) {
		throw new Error("Expected exactly one PKCS7 block");
	}
	const block = blocks[0];
	if (block === undefined) {
		throw new Error("Missing PKCS7 block");
	}
	return parsePkcs7CertBagDer(block.bytes);
}

export function parsePkcs7SignedDataDer(
	der: Uint8Array,
): ParsedPkcs7SignedData {
	const contentInfo = readSequenceChildren(der);
	const contentType = contentInfo[0];
	const content = contentInfo[1];
	if (contentType === undefined || content === undefined) {
		throw new Error("Malformed PKCS#7 content info");
	}
	const contentTypeOid = decodeObjectIdentifier(contentType.value);
	if (contentTypeOid !== OIDS.pkcs7SignedData) {
		throw new Error("PKCS#7 content is not signedData");
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
		throw new Error("Malformed SignedData");
	}
	const encapDer = der.slice(
		encapContentInfo.start - encapContentInfo.headerLength,
		encapContentInfo.end,
	);
	const encapChildren = readSequenceChildren(encapDer);
	const encapType = encapChildren[0];
	const encapContent = encapChildren[1];
	if (encapType === undefined) {
		throw new Error("Malformed EncapsulatedContentInfo");
	}
	return {
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
	};
}

export function parsePkcs7SignedDataPem(pem: string): ParsedPkcs7SignedData {
	const blocks = splitPemBlocks(pem).filter((block) => block.label === "PKCS7");
	const block = blocks[0];
	if (block === undefined || blocks.length !== 1) {
		throw new Error("Expected exactly one PKCS7 block");
	}
	return parsePkcs7SignedDataDer(block.bytes);
}

export async function verifyPkcs7SignedData(
	input: string | Uint8Array | ParsedPkcs7SignedData,
): Promise<VerifyPkcs7SignedDataResult> {
	const parsed = typeof input === "string"
		? parsePkcs7SignedDataPem(input)
		: input instanceof Uint8Array
		? parsePkcs7SignedDataDer(input)
		: input;
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
		if (parts[index]?.tag === 0xa0) {
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
