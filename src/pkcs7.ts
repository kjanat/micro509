import {
	concatBytes,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from "./der.ts";
import { getCrypto, importSpkiDer, type PublicKeyImportInput } from "./keys.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemEncode, splitPemBlocks } from "./pem.ts";

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
	const signedDataChildren = childrenOfElements(der, signedData);
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
		version: decodeInteger(version.value),
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
	const key = await importSpkiDer(spkiDer, config.importAlgorithm);
	const subtle = getCrypto().subtle;
	const signatureView = toArrayBuffer(signatureValue);
	const dataView = toArrayBuffer(data);
	if (await subtle.verify(config.verifyParams, key, signatureView, dataView)) {
		return true;
	}
	if (config.ecdsaRawSignatureBytes !== undefined) {
		const alternate = alternateEcdsaSignatureEncoding(
			signatureValue,
			config.ecdsaRawSignatureBytes / 2,
		);
		if (alternate !== undefined) {
			return subtle.verify(
				config.verifyParams,
				key,
				toArrayBuffer(alternate),
				dataView,
			);
		}
	}
	return false;
}

function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
} {
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
				importAlgorithm: requireEcPublicKey(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-256" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA384:
			return {
				importAlgorithm: requireEcPublicKey(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-384" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error("Ed25519 signature requires Ed25519 signer public key");
			}
			return {
				importAlgorithm: { kind: "ed25519" },
				verifyParams: { name: "Ed25519" },
			};
		default:
			throw new Error(
				`Unsupported signature algorithm OID: ${signatureAlgorithmOid}`,
			);
	}
}

function requireRsaPublicKey(
	publicKeyAlgorithmOid: string,
	hash: "SHA-256" | "SHA-384" | "SHA-512",
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.rsaEncryption) {
		throw new Error("RSA signature requires RSA signer public key");
	}
	return { kind: "rsa", hash };
}

function requireEcPublicKey(
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.ecPublicKey) {
		throw new Error("ECDSA signature requires EC signer public key");
	}
	switch (publicKeyParametersOid) {
		case OIDS.prime256v1:
			return { kind: "ecdsa", namedCurve: "P-256" };
		case OIDS.secp384r1:
			return { kind: "ecdsa", namedCurve: "P-384" };
		default:
			throw new Error(
				`Unsupported EC curve OID: ${publicKeyParametersOid ?? "missing"}`,
			);
	}
}

function curveBytes(parametersOid: string | undefined): number {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		default:
			throw new Error(
				`Unsupported EC curve OID: ${parametersOid ?? "missing"}`,
			);
	}
}

function alternateEcdsaSignatureEncoding(
	signature: Uint8Array,
	partLength: number,
): Uint8Array | undefined {
	try {
		if (signature[0] === 0x30) {
			return derEcdsaSignatureToRaw(signature, partLength);
		}
		return rawEcdsaSignatureToDer(signature, partLength);
	} catch {
		return undefined;
	}
}

function derEcdsaSignatureToRaw(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error("Malformed ECDSA DER signature");
	}
	return concatFixedWidth(
		trimLeadingZero(r.value),
		trimLeadingZero(s.value),
		partLength,
	);
}

function rawEcdsaSignatureToDer(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error("Unexpected ECDSA raw signature length");
	}
	return sequence([
		integerFromBytes(signature.slice(0, partLength)),
		integerFromBytes(signature.slice(partLength)),
	]);
}

function integerFromBytes(bytes: Uint8Array): Uint8Array {
	if ((bytes[0] ?? 0) >= 0x80) {
		const out = new Uint8Array(bytes.length + 1);
		out[0] = 0;
		out.set(bytes, 1);
		return tlv(0x02, out);
	}
	return tlv(0x02, bytes);
}

function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}

function concatFixedWidth(
	left: Uint8Array,
	right: Uint8Array,
	partLength: number,
): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error("ECDSA signature integer too large");
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
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
	for (const child of childrenOfElements(source, element)) {
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
	for (const signerInfo of childrenOfElements(source, element)) {
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
			requireDefined(
				readSequenceChildren(digestAlgorithmDer)[0],
				"digest algorithm OID",
			).value,
		);
		const signatureAlgorithmDer = signerDer.slice(
			signatureAlgorithm.start - signatureAlgorithm.headerLength,
			signatureAlgorithm.end,
		);
		const signatureAlgorithmOid = decodeObjectIdentifier(
			requireDefined(
				readSequenceChildren(signatureAlgorithmDer)[0],
				"signature algorithm OID",
			).value,
		);
		const parsedSid = parseSignerIdentifier(
			signerDer.slice(sid.start - sid.headerLength, sid.end),
		);
		signers.push({
			version: decodeInteger(version.value),
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

function childrenOfElements(
	source: Uint8Array,
	parent: { readonly start: number; readonly end: number },
): ReturnType<typeof readElement>[] {
	const children: ReturnType<typeof readElement>[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		children.push(child);
		offset = child.end;
	}
	return children;
}

function decodeInteger(bytes: Uint8Array): number {
	let value = 0;
	for (const byte of bytes) {
		value = (value << 8) | byte;
	}
	return value;
}

function requireDefined<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
		"",
	);
}

function childAt(
	source: Uint8Array,
	parent: { readonly start: number; readonly end: number },
	index: number,
	label: string,
): { readonly start: number; readonly end: number } {
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

function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error("OID is empty");
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error("Malformed OID");
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join(".");
}
