import { Buffer } from "node:buffer";

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
