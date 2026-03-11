import { Buffer } from "node:buffer";

export interface PemBlock {
	readonly label: string;
	readonly bytes: Uint8Array;
	readonly pem: string;
}

export interface CategorizedPemBlocks {
	readonly certificates: readonly PemBlock[];
	readonly certificateRequests: readonly PemBlock[];
	readonly privateKeys: readonly PemBlock[];
	readonly publicKeys: readonly PemBlock[];
	readonly others: readonly PemBlock[];
}

export function pemEncode(label: string, der: Uint8Array): string {
	const body = Buffer.from(der).toString("base64");
	const lines = body.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export function base64Encode(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64");
}

export function pemDecode(label: string, pem: string): Uint8Array {
	const normalized = pem.replace(/\r/g, "").trim();
	const begin = `-----BEGIN ${label}-----`;
	const end = `-----END ${label}-----`;
	if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
		throw new Error(`Invalid PEM for ${label}`);
	}
	const body = normalized.slice(begin.length, normalized.length - end.length).replace(/\n/g, "").trim();
	return new Uint8Array(Buffer.from(body, "base64"));
}

export function base64Decode(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "base64"));
}

export function splitPemBlocks(input: string): readonly PemBlock[] {
	const normalized = input.replace(/\r/g, "");
	return Array.from(
		normalized.matchAll(/-----BEGIN ([^-]+)-----[\s\S]*?-----END \1-----/g),
		(match) => {
			const pem = match[0];
			const label = match[1];
			if (pem === undefined || label === undefined) {
				throw new Error("Invalid PEM block match");
			}
			return {
				label,
				bytes: pemDecode(label, pem),
				pem,
			};
		},
	);
}

export function categorizePemBlocks(input: string | readonly PemBlock[]): CategorizedPemBlocks {
	const blocks = typeof input === "string" ? splitPemBlocks(input) : input;
	const certificates: PemBlock[] = [];
	const certificateRequests: PemBlock[] = [];
	const privateKeys: PemBlock[] = [];
	const publicKeys: PemBlock[] = [];
	const others: PemBlock[] = [];

	for (const block of blocks) {
		switch (block.label) {
			case "CERTIFICATE":
				certificates.push(block);
				break;
			case "CERTIFICATE REQUEST":
				certificateRequests.push(block);
				break;
			case "PRIVATE KEY":
			case "RSA PRIVATE KEY":
			case "EC PRIVATE KEY":
				privateKeys.push(block);
				break;
			case "PUBLIC KEY":
				publicKeys.push(block);
				break;
			default:
				others.push(block);
		}
	}

	return { certificates, certificateRequests, privateKeys, publicKeys, others };
}
