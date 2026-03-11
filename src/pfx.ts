import {
	type DerElement,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from "./der.ts";
import { exportPkcs8Der } from "./keys.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemEncode, splitPemBlocks } from "./pem.ts";

export type PfxCertificateSource = string | Uint8Array;
export type PfxPrivateKeySource = CryptoKey | Uint8Array;

export interface PfxBagAttributesInput {
	readonly friendlyName?: string;
	readonly localKeyId?: Uint8Array;
}

export interface PfxCertificateBagInput {
	readonly certificate: PfxCertificateSource;
	readonly attributes?: PfxBagAttributesInput;
}

export interface PfxPrivateKeyBagInput {
	readonly privateKey: PfxPrivateKeySource;
	readonly attributes?: PfxBagAttributesInput;
}

export interface CreatePfxInput {
	readonly certificates?: readonly PfxCertificateBagInput[];
	readonly privateKeys?: readonly PfxPrivateKeyBagInput[];
}

export interface PfxMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface ParsedPfxAttribute {
	readonly oid: string;
	readonly valuesHex: readonly string[];
}

export interface ParsedPfxBagAttributes {
	readonly entries: readonly ParsedPfxAttribute[];
	readonly friendlyName?: string;
	readonly localKeyId?: string;
}

export type ParsedPfxBag =
	| {
		readonly kind: "certificate";
		readonly bagId: string;
		readonly attributes: ParsedPfxBagAttributes;
		readonly certificate: ParsedCertificate;
	}
	| {
		readonly kind: "privateKey";
		readonly bagId: string;
		readonly attributes: ParsedPfxBagAttributes;
		readonly pkcs8Der: Uint8Array;
	}
	| {
		readonly kind: "unknown";
		readonly bagId: string;
		readonly attributes: ParsedPfxBagAttributes;
		readonly valueDer: Uint8Array;
	};

export interface ParsedPfx {
	readonly bags: readonly ParsedPfxBag[];
	readonly certificates: readonly ParsedCertificate[];
	readonly privateKeys: readonly Uint8Array[];
}

export async function createPfx(input: CreatePfxInput): Promise<PfxMaterial> {
	const bagContents: Uint8Array[] = [];
	for (const certificate of input.certificates ?? []) {
		bagContents.push(createCertificateBag(await normalizeCertificate(certificate.certificate), certificate.attributes));
	}
	for (const privateKey of input.privateKeys ?? []) {
		bagContents.push(createPrivateKeyBag(await normalizePrivateKey(privateKey.privateKey), privateKey.attributes));
	}
	const safeContents = sequence(bagContents);
	const authenticatedSafe = sequence([
		sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(safeContents)),
		]),
	]);
	const der = sequence([
		integerFromNumber(3),
		sequence([
			objectIdentifier(OIDS.pkcs7Data),
			explicitContext(0, octetString(authenticatedSafe)),
		]),
	]);
	return {
		der,
		pem: pemEncode("PKCS12", der),
		base64: base64Encode(der),
	};
}

export function parsePfxDer(der: Uint8Array): ParsedPfx {
	const topLevel = readSequenceChildren(der);
	const authSafe = topLevel[1];
	if (authSafe === undefined) {
		throw new Error("Malformed PFX");
	}
	const authSafeDer = der.slice(authSafe.start - authSafe.headerLength, authSafe.end);
	const authenticatedSafeOctets = extractContentInfoData(authSafeDer);
	const authenticatedSafe = readSequenceChildren(authenticatedSafeOctets);
	const bags: ParsedPfxBag[] = [];
	for (const contentInfo of authenticatedSafe) {
		const contentInfoDer = authenticatedSafeOctets.slice(contentInfo.start - contentInfo.headerLength, contentInfo.end);
		const safeContents = extractContentInfoData(contentInfoDer);
		for (const bag of readSequenceChildren(safeContents)) {
			const bagDer = safeContents.slice(bag.start - bag.headerLength, bag.end);
			bags.push(parseSafeBag(bagDer));
		}
	}
	return {
		bags,
		certificates: bags.flatMap((bag) => bag.kind === "certificate" ? [bag.certificate] : []),
		privateKeys: bags.flatMap((bag) => bag.kind === "privateKey" ? [bag.pkcs8Der] : []),
	};
}

function extractContentInfoData(contentInfoDer: Uint8Array): Uint8Array {
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const contentType = contentInfoChildren[0];
	const content = contentInfoChildren[1];
	if (contentType === undefined || content === undefined) {
		throw new Error("Malformed ContentInfo");
	}
	if (decodeObjectIdentifier(contentType.value) !== OIDS.pkcs7Data) {
		throw new Error("Only passwordless data ContentInfo is supported");
	}
	return extractContextOctetString(contentInfoDer, content);
}

export function parsePfxPem(pem: string): ParsedPfx {
	const blocks = splitPemBlocks(pem).filter((block) => block.label === "PKCS12");
	const block = blocks[0];
	if (block === undefined || blocks.length !== 1) {
		throw new Error("Expected exactly one PKCS12 block");
	}
	return parsePfxDer(block.bytes);
}

function createCertificateBag(certificateDer: Uint8Array, attributes: PfxBagAttributesInput | undefined): Uint8Array {
	const certBag = sequence([
		objectIdentifier(OIDS.x509CertificateBagType),
		explicitContext(0, octetString(certificateDer)),
	]);
	return sequence([
		objectIdentifier(OIDS.pkcs12CertBag),
		explicitContext(0, certBag),
		...encodeBagAttributes(attributes),
	]);
}

function createPrivateKeyBag(pkcs8Der: Uint8Array, attributes: PfxBagAttributesInput | undefined): Uint8Array {
	return sequence([
		objectIdentifier(OIDS.pkcs12KeyBag),
		explicitContext(0, pkcs8Der),
		...encodeBagAttributes(attributes),
	]);
}

function encodeBagAttributes(attributes: PfxBagAttributesInput | undefined): readonly Uint8Array[] {
	if (attributes === undefined) {
		return [];
	}
	const out: Uint8Array[] = [];
	if (attributes.friendlyName !== undefined) {
		out.push(sequence([
			objectIdentifier(OIDS.friendlyName),
			setOf([bmpString(attributes.friendlyName)]),
		]));
	}
	if (attributes.localKeyId !== undefined) {
		out.push(sequence([
			objectIdentifier(OIDS.localKeyId),
			setOf([octetString(attributes.localKeyId)]),
		]));
	}
	return out.length === 0 ? [] : [setOf(out)];
}

function parseSafeBag(der: Uint8Array): ParsedPfxBag {
	const children = readSequenceChildren(der);
	const bagId = children[0];
	const bagValue = children[1];
	const attributeSet = children[2];
	if (bagId === undefined || bagValue === undefined) {
		throw new Error("Malformed SafeBag");
	}
	const bagOid = decodeObjectIdentifier(bagId.value);
	const attributes = parseBagAttributes(der, attributeSet);
	if (bagOid === OIDS.pkcs12CertBag) {
		const certBag = extractContextChild(der, bagValue);
		const certBagDer = der.slice(certBag.start - certBag.headerLength, certBag.end);
		const certBagChildren = readSequenceChildren(certBagDer);
		const certValue = certBagChildren[1];
		if (certValue === undefined) {
			throw new Error("Malformed certBag");
		}
		const certificateDer = extractContextOctetString(certBagDer, certValue);
		return {
			kind: "certificate",
			bagId: bagOid,
			attributes,
			certificate: parseCertificateDer(certificateDer),
		};
	}
	if (bagOid === OIDS.pkcs12KeyBag) {
		const pkcs8 = extractContextChild(der, bagValue);
		return {
			kind: "privateKey",
			bagId: bagOid,
			attributes,
			pkcs8Der: der.slice(pkcs8.start - pkcs8.headerLength, pkcs8.end),
		};
	}
	const value = extractContextChild(der, bagValue);
	return {
		kind: "unknown",
		bagId: bagOid,
		attributes,
		valueDer: der.slice(value.start - value.headerLength, value.end),
	};
}

function parseBagAttributes(source: Uint8Array, attributeSet: DerElement | undefined): ParsedPfxBagAttributes {
	if (attributeSet === undefined) {
		return { entries: [] };
	}
	const entries: ParsedPfxAttribute[] = [];
	let friendlyName: string | undefined;
	let localKeyId: string | undefined;
	for (const attribute of childrenOf(source, attributeSet)) {
		const attributeDer = source.slice(attribute.start - attribute.headerLength, attribute.end);
		const parts = readSequenceChildren(attributeDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined) {
			throw new Error("Malformed PFX bag attribute");
		}
		const attrOid = decodeObjectIdentifier(oid.value);
		const rawValues = childrenOf(attributeDer, values).map((value) =>
			attributeDer.slice(value.start - value.headerLength, value.end)
		);
		entries.push({ oid: attrOid, valuesHex: rawValues.map((value) => toHex(value)) });
		const firstValue = rawValues[0];
		if (firstValue === undefined) {
			continue;
		}
		if (attrOid === OIDS.friendlyName) {
			friendlyName = decodeBmpString(firstValue);
		}
		if (attrOid === OIDS.localKeyId) {
			localKeyId = toHex(readElement(firstValue).value);
		}
	}
	return {
		entries,
		...(friendlyName === undefined ? {} : { friendlyName }),
		...(localKeyId === undefined ? {} : { localKeyId }),
	};
}

async function normalizePrivateKey(source: PfxPrivateKeySource): Promise<Uint8Array> {
	if (source instanceof CryptoKey) {
		return exportPkcs8Der(source);
	}
	return new Uint8Array(source);
}

async function normalizeCertificate(source: PfxCertificateSource): Promise<Uint8Array> {
	if (typeof source === "string") {
		const block = splitPemBlocks(source).find((candidate) => candidate.label === "CERTIFICATE");
		if (block === undefined) {
			throw new Error("Certificate PEM required");
		}
		return new Uint8Array(block.bytes);
	}
	return new Uint8Array(source);
}

function extractContextOctetString(source: Uint8Array, element: DerElement): Uint8Array {
	const child = extractContextChild(source, element);
	if (child.tag !== 0x04) {
		throw new Error("Expected OCTET STRING in context value");
	}
	return child.value;
}

function extractContextChild(source: Uint8Array, element: DerElement): DerElement {
	if ((element.tag & 0xe0) !== 0xa0) {
		throw new Error("Expected context-specific constructed value");
	}
	return readElement(source, element.start);
}

function childrenOf(source: Uint8Array, parent: DerElement): DerElement[] {
	const children: DerElement[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		children.push(child);
		offset = child.end;
	}
	return children;
}

function bmpString(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length * 2);
	for (let index = 0; index < value.length; index += 1) {
		const codePoint = value.charCodeAt(index);
		bytes[index * 2] = codePoint >> 8;
		bytes[index * 2 + 1] = codePoint & 0xff;
	}
	return tlv(0x1e, bytes);
}

function decodeBmpString(der: Uint8Array): string {
	const element = readElement(der);
	if (element.tag !== 0x1e) {
		throw new Error("Expected BMPString");
	}
	let value = "";
	for (let index = 0; index < element.value.length; index += 2) {
		const left = element.value[index] ?? 0;
		const right = element.value[index + 1] ?? 0;
		value += String.fromCharCode((left << 8) | right);
	}
	return value;
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

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}
