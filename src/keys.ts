import { webcrypto } from "node:crypto";
import { nullValue, objectIdentifier, octetString, readElement, readSequenceChildren, sequence } from "./der.ts";
import { OIDS } from "./oids.ts";
import { decryptPbes2, encryptPbes2, type Pbes2EncryptionOptions } from "./pbes2.ts";
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

export type EncryptedPkcs8Options = Pbes2EncryptionOptions;

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

export function wrapKeyPair(
	publicKey: CryptoKey,
	privateKey: CryptoKey,
): KeyPairMaterial {
	return {
		publicKey,
		privateKey,
		async exportSpkiDer() {
			return new Uint8Array(
				await getCrypto().subtle.exportKey("spki", publicKey),
			);
		},
		async exportSpkiPem() {
			return pemEncode("PUBLIC KEY", await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(
				await getCrypto().subtle.exportKey("pkcs8", privateKey),
			);
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

export async function exportPkcs8Der(
	privateKey: CryptoKey,
): Promise<Uint8Array> {
	return new Uint8Array(
		await getCrypto().subtle.exportKey("pkcs8", privateKey),
	);
}

export async function exportPublicJwk(
	publicKey: CryptoKey,
): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey("jwk", publicKey);
}

export async function exportPrivateJwk(
	privateKey: CryptoKey,
): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey("jwk", privateKey);
}

export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode("PRIVATE KEY", await exportPkcs8Der(privateKey));
}

export async function exportEncryptedPkcs8Der(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const encryption = await encryptPbes2(pkcs8, options);
	return sequence([
		encryption.algorithmIdentifierDer,
		octetString(encryption.encryptedData),
	]);
}

export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode(
		"ENCRYPTED PRIVATE KEY",
		await exportEncryptedPkcs8Der(privateKey, options),
	);
}

export async function exportPkcs1Der(
	privateKey: CryptoKey,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.rsaEncryption) {
		throw new Error("PKCS#1 export requires an RSA private key");
	}
	return parsed.privateKeyDer;
}

export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode("RSA PRIVATE KEY", await exportPkcs1Der(privateKey));
}

export async function exportSec1Der(
	privateKey: CryptoKey,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.ecPublicKey) {
		throw new Error("SEC1 export requires an EC private key");
	}
	return parsed.privateKeyDer;
}

export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode("EC PRIVATE KEY", await exportSec1Der(privateKey));
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

export async function importEncryptedPkcs8Der(
	der: Uint8Array,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	const children = readSequenceChildren(der);
	const algorithmIdentifier = children[0];
	const encryptedData = children[1];
	if (
		algorithmIdentifier === undefined
		|| encryptedData === undefined
		|| encryptedData.tag !== 0x04
	) {
		throw new Error("Malformed EncryptedPrivateKeyInfo");
	}
	const decrypted = await decryptPbes2(
		der.slice(
			algorithmIdentifier.start - algorithmIdentifier.headerLength,
			algorithmIdentifier.end,
		),
		encryptedData.value,
		password,
	);
	return importPkcs8Der(decrypted, algorithm);
}

export async function importEncryptedPkcs8Pem(
	pem: string,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importEncryptedPkcs8Der(
		pemDecode("ENCRYPTED PRIVATE KEY", pem),
		password,
		algorithm,
	);
}

export async function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaPublicKeyInput = { kind: "rsa" },
): Promise<CryptoKey> {
	return importPkcs8Der(wrapPkcs1InPkcs8(der), algorithm);
}

export async function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaPublicKeyInput = { kind: "rsa" },
): Promise<CryptoKey> {
	return importPkcs1Der(pemDecode("RSA PRIVATE KEY", pem), algorithm);
}

export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(base64Decode(base64), algorithm);
}

export async function importSec1Der(
	der: Uint8Array,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importPkcs8Der(wrapSec1InPkcs8(der, algorithm.namedCurve), algorithm);
}

export async function importSec1Pem(
	pem: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importSec1Der(pemDecode("EC PRIVATE KEY", pem), algorithm);
}

export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		"jwk",
		jwk,
		toImportAlgorithm(algorithm),
		true,
		["verify"],
	);
}

export async function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		"jwk",
		jwk,
		toImportAlgorithm(algorithm),
		true,
		["sign"],
	);
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

function parsePkcs8PrivateKey(der: Uint8Array): {
	readonly algorithmOid: string;
	readonly parametersOid?: string;
	readonly privateKeyDer: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const algorithm = children[1];
	const privateKey = children[2];
	if (algorithm === undefined || privateKey === undefined) {
		throw new Error("Malformed PKCS#8 private key");
	}
	const algorithmChildren = readSequenceChildren(
		der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
	);
	const algorithmOid = algorithmChildren[0];
	if (algorithmOid === undefined) {
		throw new Error("PKCS#8 algorithm OID missing");
	}
	const parameters = algorithmChildren[1];
	return {
		algorithmOid: decodeObjectIdentifier(algorithmOid.value),
		...(parameters?.tag === 0x06
			? { parametersOid: decodeObjectIdentifier(parameters.value) }
			: {}),
		privateKeyDer: privateKey.value,
	};
}

function wrapPkcs1InPkcs8(der: Uint8Array): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(der)),
	]);
}

function wrapSec1InPkcs8(
	der: Uint8Array,
	namedCurve: ImportEcPublicKeyInput["namedCurve"],
): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([
			objectIdentifier(OIDS.ecPublicKey),
			objectIdentifier(namedCurveToOid(namedCurve)),
		]),
		octetString(new Uint8Array(der)),
	]);
}

function namedCurveToOid(
	namedCurve: ImportEcPublicKeyInput["namedCurve"],
): string {
	switch (namedCurve) {
		case "P-256":
			return OIDS.prime256v1;
		case "P-384":
			return OIDS.secp384r1;
	}
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
