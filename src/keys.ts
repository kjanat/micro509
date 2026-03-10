import { webcrypto } from "node:crypto";
import { base64Decode, base64Encode, pemDecode, pemEncode } from "./pem.ts";

export type RsaHash = "SHA-256" | "SHA-384" | "SHA-512";

export interface RsaKeyAlgorithmInput {
	readonly kind: "rsa";
	readonly modulusLength?: 2048 | 3072 | 4096;
	readonly hash?: RsaHash;
}

export interface EcKeyAlgorithmInput {
	readonly kind: "ecdsa";
	readonly namedCurve?: "P-256" | "P-384";
}

export interface Ed25519KeyAlgorithmInput {
	readonly kind: "ed25519";
}

export type KeyAlgorithmInput =
	| RsaKeyAlgorithmInput
	| EcKeyAlgorithmInput
	| Ed25519KeyAlgorithmInput;

export interface KeyPairMaterial {
	readonly publicKey: CryptoKey;
	readonly privateKey: CryptoKey;
	exportSpkiDer(): Promise<Uint8Array>;
	exportSpkiPem(): Promise<string>;
	exportPkcs8Der(): Promise<Uint8Array>;
	exportPkcs8Pem(): Promise<string>;
	exportPublicJwk(): Promise<JsonWebKey>;
	exportPrivateJwk(): Promise<JsonWebKey>;
}

export interface ImportRsaPublicKeyInput {
	readonly kind: "rsa";
	readonly hash?: RsaHash;
}

export interface ImportEcPublicKeyInput {
	readonly kind: "ecdsa";
	readonly namedCurve: "P-256" | "P-384";
}

export interface ImportEd25519PublicKeyInput {
	readonly kind: "ed25519";
}

export type PublicKeyImportInput =
	| ImportRsaPublicKeyInput
	| ImportEcPublicKeyInput
	| ImportEd25519PublicKeyInput;

export type PrivateKeyImportInput = PublicKeyImportInput;

export function getCrypto(): Crypto {
	const candidate = globalThis.crypto ?? webcrypto;
	if (candidate?.subtle === undefined) {
		throw new Error("WebCrypto subtle API is required");
	}
	return candidate;
}

export async function generateKeyPair(
	algorithm: KeyAlgorithmInput = { kind: "ecdsa", namedCurve: "P-256" },
): Promise<KeyPairMaterial> {
	const subtle = getCrypto().subtle;
	const generated = await subtle.generateKey(
		toGenerateKeyAlgorithm(algorithm),
		true,
		["sign", "verify"],
	);

	if (!("publicKey" in generated) || !("privateKey" in generated)) {
		throw new Error("Expected an asymmetric key pair");
	}

	return wrapKeyPair(generated.publicKey, generated.privateKey);
}

export function wrapKeyPair(publicKey: CryptoKey, privateKey: CryptoKey): KeyPairMaterial {
	return {
		publicKey,
		privateKey,
		async exportSpkiDer() {
			return new Uint8Array(await getCrypto().subtle.exportKey("spki", publicKey));
		},
		async exportSpkiPem() {
			return pemEncode("PUBLIC KEY", await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(await getCrypto().subtle.exportKey("pkcs8", privateKey));
		},
		async exportPkcs8Pem() {
			return pemEncode("PRIVATE KEY", await this.exportPkcs8Der());
		},
		async exportPublicJwk() {
			return getCrypto().subtle.exportKey("jwk", publicKey);
		},
		async exportPrivateJwk() {
			return getCrypto().subtle.exportKey("jwk", privateKey);
		},
	};
}

export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey("spki", publicKey));
}

export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey("pkcs8", privateKey));
}

export async function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey("jwk", publicKey);
}

export async function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey("jwk", privateKey);
}

export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode("PRIVATE KEY", await exportPkcs8Der(privateKey));
}

export async function exportSpkiPem(publicKey: CryptoKey): Promise<string> {
	return pemEncode("PUBLIC KEY", await exportSpkiDer(publicKey));
}

export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === "public") {
		return base64Encode(await exportSpkiDer(key));
	}
	return base64Encode(await exportPkcs8Der(key));
}

export async function importSpkiDer(
	der: Uint8Array,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		"spki",
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		["verify"],
	);
}

export async function importSpkiPem(
	pem: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(pemDecode("PUBLIC KEY", pem), algorithm);
}

export async function importSpkiBase64(
	base64: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(base64Decode(base64), algorithm);
}

export async function importPkcs8Der(
	der: Uint8Array,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		"pkcs8",
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		["sign"],
	);
}

export async function importPkcs8Pem(
	pem: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(pemDecode("PRIVATE KEY", pem), algorithm);
}

export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(base64Decode(base64), algorithm);
}

export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey("jwk", jwk, toImportAlgorithm(algorithm), true, ["verify"]);
}

export async function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey("jwk", jwk, toImportAlgorithm(algorithm), true, ["sign"]);
}

function toGenerateKeyAlgorithm(
	algorithm: KeyAlgorithmInput,
): EcKeyGenParams | RsaHashedKeyGenParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case "rsa":
			return {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: algorithm.modulusLength ?? 2048,
				publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
				hash: algorithm.hash ?? "SHA-256",
			};
		case "ecdsa":
			return {
				name: "ECDSA",
				namedCurve: algorithm.namedCurve ?? "P-256",
			};
		case "ed25519":
			return { name: "Ed25519" };
	}
}

function toImportAlgorithm(
	algorithm: PublicKeyImportInput,
): EcKeyImportParams | RsaHashedImportParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case "rsa":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: algorithm.hash ?? "SHA-256",
			};
		case "ecdsa":
			return {
				name: "ECDSA",
				namedCurve: algorithm.namedCurve,
			};
		case "ed25519":
			return { name: "Ed25519" };
	}
}
