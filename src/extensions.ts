import { createHash } from "node:crypto";
import {
	bitString,
	bool,
	implicitPrimitiveContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from "./der.js";
import { OIDS } from "./oids.js";

export type KeyUsage =
	| "digitalSignature"
	| "nonRepudiation"
	| "keyEncipherment"
	| "dataEncipherment"
	| "keyAgreement"
	| "keyCertSign"
	| "cRLSign"
	| "encipherOnly"
	| "decipherOnly";

export type SubjectAltName =
	| { readonly type: "dns"; readonly value: string }
	| { readonly type: "ip"; readonly value: string }
	| { readonly type: "email"; readonly value: string }
	| { readonly type: "uri"; readonly value: string };

export interface BasicConstraints {
	readonly ca: boolean;
	readonly pathLength?: number;
}

export interface CertificateExtensionsInput {
	readonly subjectAltNames?: readonly SubjectAltName[];
	readonly keyUsage?: readonly KeyUsage[];
	readonly basicConstraints?: BasicConstraints;
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
}

export type ExtendedKeyUsage =
	| "serverAuth"
	| "clientAuth"
	| "codeSigning"
	| "emailProtection"
	| "timeStamping"
	| "ocspSigning";

const EXTENDED_KEY_USAGE_OIDS: Record<ExtendedKeyUsage, string> = {
	serverAuth: OIDS.serverAuth,
	clientAuth: OIDS.clientAuth,
	codeSigning: OIDS.codeSigning,
	emailProtection: OIDS.emailProtection,
	timeStamping: OIDS.timeStamping,
	ocspSigning: OIDS.ocspSigning,
};

const KEY_USAGE_BITS: Record<KeyUsage, number> = {
	digitalSignature: 0,
	nonRepudiation: 1,
	keyEncipherment: 2,
	dataEncipherment: 3,
	keyAgreement: 4,
	keyCertSign: 5,
	cRLSign: 6,
	encipherOnly: 7,
	decipherOnly: 8,
};

export function buildCertificateExtensions(
	subjectPublicKeyInfo: Uint8Array,
	issuerPublicKeyInfo: Uint8Array | undefined,
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	const basicConstraints = input?.basicConstraints ?? { ca: false };
	extensions.push(
		encodeExtension(OIDS.basicConstraints, encodeBasicConstraints(basicConstraints), true),
	);
	extensions.push(
		encodeExtension(OIDS.subjectKeyIdentifier, octetString(buildSubjectKeyIdentifier(subjectPublicKeyInfo))),
	);
	if (issuerPublicKeyInfo !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.authorityKeyIdentifier,
				sequence([implicitPrimitiveContext(0, buildSubjectKeyIdentifier(issuerPublicKeyInfo))]),
			),
		);
	}
	if (input?.keyUsage !== undefined && input.keyUsage.length > 0) {
		extensions.push(encodeExtension(OIDS.keyUsage, encodeKeyUsage(input.keyUsage), true));
	}
	if (input?.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		extensions.push(
			encodeExtension(OIDS.subjectAltName, sequence(input.subjectAltNames.map(encodeSubjectAltName))),
		);
	}
	if (input?.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		extensions.push(
			encodeExtension(OIDS.extendedKeyUsage, encodeExtendedKeyUsage(input.extendedKeyUsage)),
		);
	}
	return extensions;
}

export function buildRequestedExtensions(
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	if (input?.basicConstraints !== undefined) {
		extensions.push(
			encodeExtension(OIDS.basicConstraints, encodeBasicConstraints(input.basicConstraints), true),
		);
	}
	if (input?.keyUsage !== undefined && input.keyUsage.length > 0) {
		extensions.push(encodeExtension(OIDS.keyUsage, encodeKeyUsage(input.keyUsage), true));
	}
	if (input?.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		extensions.push(
			encodeExtension(OIDS.subjectAltName, sequence(input.subjectAltNames.map(encodeSubjectAltName))),
		);
	}
	if (input?.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		extensions.push(
			encodeExtension(OIDS.extendedKeyUsage, encodeExtendedKeyUsage(input.extendedKeyUsage)),
		);
	}
	return extensions;
}

export function encodeExtension(oid: string, extnValue: Uint8Array, critical = false): Uint8Array {
	const fields = [objectIdentifier(oid)];
	if (critical) {
		fields.push(bool(true));
	}
	fields.push(octetString(extnValue));
	return sequence(fields);
}

export function encodeBasicConstraints(input: BasicConstraints): Uint8Array {
	const fields: Uint8Array[] = [];
	if (input.ca) {
		fields.push(bool(true));
	}
	if (input.pathLength !== undefined) {
		if (!input.ca) {
			throw new Error("pathLength requires ca=true");
		}
		fields.push(integerFromNumber(input.pathLength));
	}
	return sequence(fields);
}

export function encodeKeyUsage(usages: readonly KeyUsage[]): Uint8Array {
	let highestBit = 0;
	for (const usage of usages) {
		const index = KEY_USAGE_BITS[usage];
		if (index > highestBit) {
			highestBit = index;
		}
	}
	const byteLength = Math.floor(highestBit / 8) + 1;
	const bytes = new Uint8Array(byteLength);
	for (const usage of usages) {
		const index = KEY_USAGE_BITS[usage];
		const byteIndex = Math.floor(index / 8);
		const bitIndex = index % 8;
		const current = bytes[byteIndex] ?? 0;
		bytes[byteIndex] = current | (1 << (7 - bitIndex));
	}
	const unusedBits = (8 - ((highestBit + 1) % 8)) % 8;
	return bitString(bytes, unusedBits);
}

export function encodeSubjectAltName(value: SubjectAltName): Uint8Array {
	switch (value.type) {
		case "dns":
			return implicitPrimitiveContext(2, new TextEncoder().encode(value.value));
		case "email":
			return implicitPrimitiveContext(1, new TextEncoder().encode(value.value));
		case "uri":
			return implicitPrimitiveContext(6, new TextEncoder().encode(value.value));
		case "ip":
			return implicitPrimitiveContext(7, encodeIpAddress(value.value));
	}
}

export function encodeExtendedKeyUsage(usages: readonly ExtendedKeyUsage[]): Uint8Array {
	return sequence(usages.map((usage) => objectIdentifier(EXTENDED_KEY_USAGE_OIDS[usage])));
}

function encodeIpAddress(input: string): Uint8Array {
	if (input.includes(":")) {
		return encodeIpv6Address(input);
	}
	const segments = input.split(".");
	if (segments.length !== 4) {
		throw new Error(`Invalid IPv4 address: ${input}`);
	}
	return Uint8Array.from(
		segments.map((segment) => {
			const parsed = Number(segment);
			if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
				throw new Error(`Invalid IPv4 address: ${input}`);
			}
			return parsed;
		}),
	);
}

function encodeIpv6Address(input: string): Uint8Array {
	const pieces = input.split("::");
	const head = pieces[0] ?? "";
	const tail = pieces[1];
	if (tail !== undefined && input.indexOf("::") !== input.lastIndexOf("::")) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const headParts = head.length > 0 ? head.split(":") : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(":") : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const zeroes = Array.from({ length: missing }, () => "0");
	const parts = tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts];
	if (parts.length !== 8) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const out = new Uint8Array(16);
	parts.forEach((part, index) => {
		const parsed = Number.parseInt(part, 16);
		if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffff) {
			throw new Error(`Invalid IPv6 address: ${input}`);
		}
		out[index * 2] = parsed >> 8;
		out[index * 2 + 1] = parsed & 0xff;
	});
	return out;
}

function buildSubjectKeyIdentifier(subjectPublicKeyInfo: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(subjectPublicKeyInfo);
	const subjectPublicKey = topLevel[1];
	if (subjectPublicKey === undefined || subjectPublicKey.tag !== 0x03) {
		throw new Error("SPKI missing subject public key bit string");
	}
	const publicKeyBytes = subjectPublicKey.value.slice(1);
	return new Uint8Array(createHash("sha1").update(publicKeyBytes).digest());
}
