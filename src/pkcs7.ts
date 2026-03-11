import {
	concatBytes,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
} from "./der.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemEncode, splitPemBlocks } from "./pem.ts";

export type Pkcs7CertificateSource = string | Uint8Array;

export interface Pkcs7CertBag {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

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

export function parsePkcs7CertBagDer(der: Uint8Array): readonly ParsedCertificate[] {
	const contentInfo = readSequenceChildren(der);
	const contentType = contentInfo[0];
	const content = contentInfo[1];
	if (contentType === undefined || content === undefined) {
		throw new Error("Malformed PKCS#7 content info");
	}
	if (decodeObjectIdentifier(contentType.value) !== OIDS.pkcs7SignedData) {
		throw new Error("PKCS#7 content is not signedData");
	}
	const signedData = childAt(der, content, 0, "signedData");
	const signedDataChildren = childrenOfElements(der, signedData);
	const certificates = signedDataChildren[3];
	if (certificates === undefined || certificates.tag !== 0xa0) {
		return [];
	}
	const parsed: ParsedCertificate[] = [];
	let offset = certificates.start;
	while (offset < certificates.end) {
		const element = readElement(der, offset);
		parsed.push(parseCertificateDer(der.slice(offset, element.end)));
		offset = element.end;
	}
	return parsed;
}

export function parsePkcs7CertBagPem(pem: string): readonly ParsedCertificate[] {
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

function normalizeCertificateSource(source: Pkcs7CertificateSource): readonly Uint8Array[] {
	if (typeof source === "string") {
		return splitPemBlocks(source)
			.filter((block) => block.label === "CERTIFICATE")
			.map((block) => new Uint8Array(block.bytes));
	}
	return [new Uint8Array(source)];
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
