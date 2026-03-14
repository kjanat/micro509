/**
 * WebCrypto key generation plus import and export helpers.
 *
 * This module owns the library's public key-material boundary and its key-container
 * interoperability logic.
 */

import { decodeObjectIdentifier, hexToBytes, toArrayBuffer, toHex } from './asn1.ts';
import { nullValue, objectIdentifier, octetString, readSequenceChildren, sequence } from './der.ts';
import { md5 } from './hash.ts';
import { OIDS } from './oids.ts';
import { decryptPbes2, encryptPbes2, type Pbes2EncryptionOptions } from './pbes2.ts';
import { base64Decode, base64Encode, pemDecode, pemEncode } from './pem.ts';

/**
 * Enumerates the supported RSA hash values.
 */
export type RsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Enumerates the supported RSA schemes.
 */
export type RsaScheme = 'pkcs1-v1_5' | 'pss';

/**
 * Defines EC named curve.
 */
export type EcNamedCurve = 'P-256' | 'P-384' | 'P-521';

/**
 * Describes the input shape for RSA key algorithm operations.
 */
export interface RsaKeyAlgorithmInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'rsa';
	/**
	 * Carries the modulus length value.
	 */
	readonly modulusLength?: 2048 | 3072 | 4096;
	/**
	 * Carries the hash value.
	 */
	readonly hash?: RsaHash;
	/**
	 * Carries the scheme value.
	 */
	readonly scheme?: RsaScheme;
}

/**
 * Describes the input shape for EC key algorithm operations.
 */
export interface EcKeyAlgorithmInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'ecdsa';
	/**
	 * Carries the named curve value.
	 */
	readonly namedCurve?: EcNamedCurve;
}

/**
 * Describes the input shape for Ed25519 key algorithm operations.
 */
export interface Ed25519KeyAlgorithmInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'ed25519';
}

/**
 * Describes the input shape for key algorithm operations.
 */
export type KeyAlgorithmInput =
	| RsaKeyAlgorithmInput
	| EcKeyAlgorithmInput
	| Ed25519KeyAlgorithmInput;

/**
 * Bundles the encoded artifacts produced by key pair operations.
 */
export interface KeyPairMaterial {
	/**
	 * Carries the public key value.
	 */
	readonly publicKey: CryptoKey;
	/**
	 * Carries the private key value.
	 */
	readonly privateKey: CryptoKey;
	/**
	 * Exports spki der.
	 *
	 * @returns The exported spki der.
	 */
	exportSpkiDer(): Promise<Uint8Array>;
	/**
	 * Exports spk i pem.
	 *
	 * @returns The exported spk i pem.
	 */
	exportSpkiPem(): Promise<string>;
	/**
	 * Exports pkcs#8 der.
	 *
	 * @returns The exported pkcs#8 der.
	 */
	exportPkcs8Der(): Promise<Uint8Array>;
	/**
	 * Exports pkcs#8 pem.
	 *
	 * @returns The exported pkcs#8 pem.
	 */
	exportPkcs8Pem(): Promise<string>;
	/**
	 * Exports public jwk.
	 *
	 * @returns The exported public jwk.
	 */
	exportPublicJwk(): Promise<JsonWebKey>;
	/**
	 * Exports private jwk.
	 *
	 * @returns The exported private jwk.
	 */
	exportPrivateJwk(): Promise<JsonWebKey>;
}

/**
 * Describes the input shape for import RSA public key operations.
 */
export interface ImportRsaPublicKeyInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'rsa';
	/**
	 * Carries the hash value.
	 */
	readonly hash?: RsaHash;
	/**
	 * Carries the scheme value.
	 */
	readonly scheme?: RsaScheme;
}

/**
 * Describes the input shape for import EC public key operations.
 */
export interface ImportEcPublicKeyInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'ecdsa';
	/**
	 * Carries the named curve value.
	 */
	readonly namedCurve: EcNamedCurve;
}

/**
 * Describes the input shape for import Ed25519 public key operations.
 */
export interface ImportEd25519PublicKeyInput {
	/**
	 * Identifies the kind value.
	 */
	readonly kind: 'ed25519';
}

/**
 * Describes the input shape for public key import operations.
 */
export type PublicKeyImportInput =
	| ImportRsaPublicKeyInput
	| ImportEcPublicKeyInput
	| ImportEd25519PublicKeyInput;

/**
 * Describes the input shape for private key import operations.
 */
export type PrivateKeyImportInput = PublicKeyImportInput;

/**
 * Configures encrypted PKCS#8 operations.
 */
export type EncryptedPkcs8Options = Pbes2EncryptionOptions;

/**
 * Configures legacy PEM encryption operations.
 */
export interface LegacyPemEncryptionOptions {
	/**
	 * Carries the password value.
	 */
	readonly password: string;
	/**
	 * Carries the iv value.
	 */
	readonly iv?: Uint8Array;
	/**
	 * Carries the cipher value.
	 */
	readonly cipher?: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';
}

/**
 * Returns crypto.
 *
 * @returns The crypto.
 */
export function getCrypto(): Crypto {
	const c = globalThis.crypto;
	if (c?.subtle === undefined) {
		throw new Error('WebCrypto subtle API is required');
	}
	return c;
}

/**
 * Generates key pair.
 *
 * @param algorithm The algorithm configuration.
 * @returns The generated key pair.
 */
export async function generateKeyPair(
	algorithm: KeyAlgorithmInput = { kind: 'ecdsa', namedCurve: 'P-256' },
): Promise<KeyPairMaterial> {
	const subtle = getCrypto().subtle;
	const generated = await subtle.generateKey(toGenerateKeyAlgorithm(algorithm), true, [
		'sign',
		'verify',
	]);

	if (!('publicKey' in generated) || !('privateKey' in generated)) {
		throw new Error('Expected an asymmetric key pair');
	}

	return wrapKeyPair(generated.publicKey, generated.privateKey);
}

/**
 * Wrap key pair.
 *
 * @param publicKey The public key to use.
 * @param privateKey The private key to use.
 * @returns The computed value.
 */
export function wrapKeyPair(publicKey: CryptoKey, privateKey: CryptoKey): KeyPairMaterial {
	return {
		publicKey,
		privateKey,
		async exportSpkiDer() {
			return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
		},
		async exportSpkiPem() {
			return pemEncode('PUBLIC KEY', await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
		},
		async exportPkcs8Pem() {
			return pemEncode('PRIVATE KEY', await this.exportPkcs8Der());
		},
		async exportPublicJwk() {
			return getCrypto().subtle.exportKey('jwk', publicKey);
		},
		async exportPrivateJwk() {
			return getCrypto().subtle.exportKey('jwk', privateKey);
		},
	};
}

/**
 * Exports SPKI DER.
 *
 * @param publicKey The public key to use.
 * @returns The exported SPKI DER.
 */
export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
}

/**
 * Exports PKCS#8 DER.
 *
 * @param privateKey The private key to use.
 * @returns The exported PKCS#8 DER.
 */
export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
}

/**
 * Exports public JWK.
 *
 * @param publicKey The public key to use.
 * @returns The exported public JWK.
 */
export async function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', publicKey);
}

/**
 * Exports private JWK.
 *
 * @param privateKey The private key to use.
 * @returns The exported private JWK.
 */
export async function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', privateKey);
}

/**
 * Exports PKCS#8 PEM.
 *
 * @param privateKey The private key to use.
 * @returns The exported PKCS#8 PEM.
 */
export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('PRIVATE KEY', await exportPkcs8Der(privateKey));
}

/**
 * Exports encrypted PKCS#8 DER.
 *
 * @param privateKey The private key to use.
 * @param options The options that control the operation.
 * @returns The exported encrypted PKCS#8 DER.
 */
export async function exportEncryptedPkcs8Der(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const encryption = await encryptPbes2(pkcs8, options);
	return sequence([encryption.algorithmIdentifierDer, octetString(encryption.encryptedData)]);
}

/**
 * Exports encrypted PKCS#8 PEM.
 *
 * @param privateKey The private key to use.
 * @param options The options that control the operation.
 * @returns The exported encrypted PKCS#8 PEM.
 */
export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode('ENCRYPTED PRIVATE KEY', await exportEncryptedPkcs8Der(privateKey, options));
}

/**
 * Exports PKCS#1 DER.
 *
 * @param privateKey The private key to use.
 * @returns The exported PKCS#1 DER.
 */
export async function exportPkcs1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.rsaEncryption) {
		throw new Error('PKCS#1 export requires an RSA private key');
	}
	return parsed.privateKeyDer;
}

/**
 * Exports PKCS#1 PEM.
 *
 * @param privateKey The private key to use.
 * @returns The exported PKCS#1 PEM.
 */
export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('RSA PRIVATE KEY', await exportPkcs1Der(privateKey));
}

/**
 * Exports encrypted PKCS#1 PEM.
 *
 * @param privateKey The private key to use.
 * @param options The options that control the operation.
 * @returns The exported encrypted PKCS#1 PEM.
 */
export async function exportEncryptedPkcs1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('RSA PRIVATE KEY', await exportPkcs1Der(privateKey), options);
}

/**
 * Exports SEC1 DER.
 *
 * @param privateKey The private key to use.
 * @returns The exported SEC1 DER.
 */
export async function exportSec1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.ecPublicKey) {
		throw new Error('SEC1 export requires an EC private key');
	}
	return parsed.privateKeyDer;
}

/**
 * Exports SEC1 PEM.
 *
 * @param privateKey The private key to use.
 * @returns The exported SEC1 PEM.
 */
export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('EC PRIVATE KEY', await exportSec1Der(privateKey));
}

/**
 * Exports encrypted SEC1 PEM.
 *
 * @param privateKey The private key to use.
 * @param options The options that control the operation.
 * @returns The exported encrypted SEC1 PEM.
 */
export async function exportEncryptedSec1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('EC PRIVATE KEY', await exportSec1Der(privateKey), options);
}

/**
 * Exports SPKI PEM.
 *
 * @param publicKey The public key to use.
 * @returns The exported SPKI PEM.
 */
export async function exportSpkiPem(publicKey: CryptoKey): Promise<string> {
	return pemEncode('PUBLIC KEY', await exportSpkiDer(publicKey));
}

/**
 * Exports binary base64.
 *
 * @param key The key value.
 * @returns The exported binary base64.
 */
export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === 'public') {
		return base64Encode(await exportSpkiDer(key));
	}
	return base64Encode(await exportPkcs8Der(key));
}

/**
 * Imports SPKI DER.
 *
 * @param der The DER-encoded bytes.
 * @param algorithm The algorithm configuration.
 * @returns The imported SPKI DER.
 */
export async function importSpkiDer(
	der: Uint8Array,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		'spki',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['verify'],
	);
}

/**
 * Imports SPKI PEM.
 *
 * @param pem The PEM-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported SPKI PEM.
 */
export async function importSpkiPem(
	pem: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(pemDecode('PUBLIC KEY', pem), algorithm);
}

/**
 * Imports SPKI base64.
 *
 * @param base64 The base64-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported SPKI base64.
 */
export async function importSpkiBase64(
	base64: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(base64Decode(base64), algorithm);
}

/**
 * Imports PKCS#8 DER.
 *
 * @param der The DER-encoded bytes.
 * @param algorithm The algorithm configuration.
 * @returns The imported PKCS#8 DER.
 */
export async function importPkcs8Der(
	der: Uint8Array,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		'pkcs8',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['sign'],
	);
}

/**
 * Imports PKCS#8 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported PKCS#8 PEM.
 */
export async function importPkcs8Pem(
	pem: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(pemDecode('PRIVATE KEY', pem), algorithm);
}

/**
 * Imports encrypted PKCS#8 DER.
 *
 * @param der The DER-encoded bytes.
 * @param password The password used to protect or unlock the data.
 * @param algorithm The algorithm configuration.
 * @returns The imported encrypted PKCS#8 DER.
 */
export async function importEncryptedPkcs8Der(
	der: Uint8Array,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	const children = readSequenceChildren(der);
	const algorithmIdentifier = children[0];
	const encryptedData = children[1];
	if (
		algorithmIdentifier === undefined ||
		encryptedData === undefined ||
		encryptedData.tag !== 0x04
	) {
		throw new Error('Malformed EncryptedPrivateKeyInfo');
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

/**
 * Imports encrypted PKCS#8 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param password The password used to protect or unlock the data.
 * @param algorithm The algorithm configuration.
 * @returns The imported encrypted PKCS#8 PEM.
 */
export async function importEncryptedPkcs8Pem(
	pem: string,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importEncryptedPkcs8Der(pemDecode('ENCRYPTED PRIVATE KEY', pem), password, algorithm);
}

/**
 * Imports PKCS#1 DER.
 *
 * @param der The DER-encoded bytes.
 * @param algorithm The algorithm configuration.
 * @returns The imported PKCS#1 DER.
 */
export async function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs8Der(wrapPkcs1InPkcs8(der), algorithm);
}

/**
 * Imports PKCS#1 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported PKCS#1 PEM.
 */
export async function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs1Der(pemDecode('RSA PRIVATE KEY', pem), algorithm);
}

/**
 * Imports encrypted PKCS#1 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param password The password used to protect or unlock the data.
 * @param algorithm The algorithm configuration.
 * @returns The imported encrypted PKCS#1 PEM.
 */
export async function importEncryptedPkcs1Pem(
	pem: string,
	password: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('RSA PRIVATE KEY', pem, password);
	try {
		return importPkcs1Der(decrypted, algorithm);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

/**
 * Imports PKCS#8 base64.
 *
 * @param base64 The base64-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported PKCS#8 base64.
 */
export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(base64Decode(base64), algorithm);
}

/**
 * Imports SEC1 DER.
 *
 * @param der The DER-encoded bytes.
 * @param algorithm The algorithm configuration.
 * @returns The imported SEC1 DER.
 */
export async function importSec1Der(
	der: Uint8Array,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importPkcs8Der(wrapSec1InPkcs8(der, algorithm.namedCurve), algorithm);
}

/**
 * Imports SEC1 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param algorithm The algorithm configuration.
 * @returns The imported SEC1 PEM.
 */
export async function importSec1Pem(
	pem: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importSec1Der(pemDecode('EC PRIVATE KEY', pem), algorithm);
}

/**
 * Imports encrypted SEC1 PEM.
 *
 * @param pem The PEM-encoded text.
 * @param password The password used to protect or unlock the data.
 * @param algorithm The algorithm configuration.
 * @returns The imported encrypted SEC1 PEM.
 */
export async function importEncryptedSec1Pem(
	pem: string,
	password: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('EC PRIVATE KEY', pem, password);
	try {
		return importSec1Der(decrypted, algorithm);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

/**
 * Imports public JWK.
 *
 * @param jwk The JWK value.
 * @param algorithm The algorithm configuration.
 * @returns The imported public JWK.
 */
export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['verify']);
}

/**
 * Imports private JWK.
 *
 * @param jwk The JWK value.
 * @param algorithm The algorithm configuration.
 * @returns The imported private JWK.
 */
export async function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['sign']);
}

/**
 * To generate key algorithm.
 *
 * @param algorithm The algorithm configuration.
 * @returns The computed value.
 */
function toGenerateKeyAlgorithm(
	algorithm: KeyAlgorithmInput,
): EcKeyGenParams | RsaHashedKeyGenParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				modulusLength: algorithm.modulusLength ?? 2048,
				publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.namedCurve ?? 'P-256',
			};
		case 'ed25519':
			return { name: 'Ed25519' };
	}
}

/**
 * To import algorithm.
 *
 * @param algorithm The algorithm configuration.
 * @returns The computed value.
 */
function toImportAlgorithm(
	algorithm: PublicKeyImportInput,
): EcKeyImportParams | RsaHashedImportParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.namedCurve,
			};
		case 'ed25519':
			return { name: 'Ed25519' };
	}
}

/**
 * Parses PKCS#8 private key.
 *
 * @param der The DER-encoded bytes.
 * @returns The parsed PKCS#8 private key.
 */
function parsePkcs8PrivateKey(der: Uint8Array): {
	/**
	 * Carries the OID for algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * Carries the OID for parameters.
	 */
	readonly parametersOid?: string;
	/**
	 * Carries the DER-encoded private key.
	 */
	readonly privateKeyDer: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const algorithm = children[1];
	const privateKey = children[2];
	if (algorithm === undefined || privateKey === undefined) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const algorithmChildren = readSequenceChildren(
		der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
	);
	const algorithmOid = algorithmChildren[0];
	if (algorithmOid === undefined) {
		throw new Error('PKCS#8 algorithm OID missing');
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

/**
 * Wrap PKCS#1 in PKCS#8.
 *
 * @param der The DER-encoded bytes.
 * @returns The computed value.
 */
function wrapPkcs1InPkcs8(der: Uint8Array): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(der)),
	]);
}

/**
 * Wrap SEC1 in PKCS#8.
 *
 * @param der The DER-encoded bytes.
 * @param namedCurve The named curve value.
 * @returns The computed value.
 */
function wrapSec1InPkcs8(
	der: Uint8Array,
	namedCurve: ImportEcPublicKeyInput['namedCurve'],
): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.ecPublicKey), objectIdentifier(namedCurveToOid(namedCurve))]),
		octetString(new Uint8Array(der)),
	]);
}

/**
 * Named curve to OID.
 *
 * @param namedCurve The named curve value.
 * @returns The computed value.
 */
function namedCurveToOid(namedCurve: ImportEcPublicKeyInput['namedCurve']): string {
	switch (namedCurve) {
		case 'P-256':
			return OIDS.prime256v1;
		case 'P-384':
			return OIDS.secp384r1;
		case 'P-521':
			return OIDS.secp521r1;
	}
}

/**
 * RSA scheme to web crypto algorithm name.
 *
 * @param scheme The scheme value.
 * @returns The computed value.
 */
function rsaSchemeToWebCryptoAlgorithmName(
	scheme: RsaScheme | undefined,
): 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' {
	if (scheme === 'pss') {
		return 'RSA-PSS';
	}
	return 'RSASSA-PKCS1-v1_5';
}

/**
 * Encrypt traditional PEM.
 *
 * @param label The label value.
 * @param der The DER-encoded bytes.
 * @param options The options that control the operation.
 * @returns The computed value.
 */
async function encryptTraditionalPem(
	label: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	der: Uint8Array,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	if (iv.length !== 16) {
		throw new Error('Traditional PEM encryption requires a 16-byte IV');
	}
	const cipher = options.cipher ?? 'AES-256-CBC';
	const key = await importTraditionalPemAesKey(options.password, iv.slice(0, 8), cipher, [
		'encrypt',
	]);
	const encrypted = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(der),
		),
	);
	const body =
		base64Encode(encrypted)
			.match(/.{1,64}/g)
			?.join('\n') ?? '';
	return [
		`-----BEGIN ${label}-----`,
		'Proc-Type: 4,ENCRYPTED',
		`DEK-Info: ${cipher},${toHex(iv).toUpperCase()}`,
		'',
		body,
		`-----END ${label}-----`,
	].join('\n');
}

/**
 * Decrypt traditional PEM.
 *
 * @param expectedLabel The expected label value.
 * @param pem The PEM-encoded text.
 * @param password The password used to protect or unlock the data.
 * @returns The computed value.
 */
async function decryptTraditionalPem(
	expectedLabel: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	pem: string,
	password: string,
): Promise<Uint8Array> {
	const parsed = parseTraditionalPem(pem);
	if (parsed.label !== expectedLabel) {
		throw new Error(`Expected ${expectedLabel} PEM block`);
	}
	const dekInfo = parsed.headers.get('DEK-Info');
	if (parsed.headers.get('Proc-Type') !== '4,ENCRYPTED' || dekInfo === undefined) {
		throw new Error('Traditional PEM encryption headers missing');
	}
	const [cipher, ivHex] = dekInfo.split(',');
	if (!isTraditionalPemCipher(cipher) || ivHex === undefined) {
		throw new Error(
			'Only AES-128-CBC, AES-192-CBC, and AES-256-CBC traditional PEM encryption is supported',
		);
	}
	const iv = hexToBytes(ivHex);
	const key = await importTraditionalPemAesKey(password, iv.slice(0, 8), cipher, ['decrypt']);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
				key,
				toArrayBuffer(base64Decode(parsed.base64Body)),
			),
		);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

/**
 * Imports traditional PEM aes key.
 *
 * @param password The password used to protect or unlock the data.
 * @param salt The salt value.
 * @param cipher The cipher value.
 * @param usages The usages value.
 * @returns The imported traditional PEM aes key.
 */
async function importTraditionalPemAesKey(
	password: string,
	salt: Uint8Array,
	cipher: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC',
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const keyLength = traditionalPemCipherKeyLength(cipher);
	const keyBytes = opensslBytesToKey(password, salt, keyLength / 8);
	return getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'AES-CBC', length: keyLength },
		false,
		usages,
	);
}

/**
 * Returns whether traditional PEM cipher.
 *
 * @param cipher The cipher value.
 * @returns Whether the condition holds.
 */
function isTraditionalPemCipher(
	cipher: string | undefined,
): cipher is 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC' {
	return cipher === 'AES-128-CBC' || cipher === 'AES-192-CBC' || cipher === 'AES-256-CBC';
}

/**
 * Traditional PEM cipher key length.
 *
 * @param cipher The cipher value.
 * @returns The computed value.
 */
function traditionalPemCipherKeyLength(
	cipher: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC',
): 128 | 192 | 256 {
	switch (cipher) {
		case 'AES-128-CBC':
			return 128;
		case 'AES-192-CBC':
			return 192;
		case 'AES-256-CBC':
			return 256;
	}
}

/**
 * Openssl bytes to key.
 *
 * @param password The password used to protect or unlock the data.
 * @param salt The salt value.
 * @param length The length value.
 * @returns The computed value.
 */
function opensslBytesToKey(password: string, salt: Uint8Array, length: number): Uint8Array {
	const passwordBytes = new TextEncoder().encode(password);
	const chunks: Uint8Array[] = [];
	let previous = new Uint8Array();
	let total = 0;
	while (total < length) {
		const input = new Uint8Array(previous.length + passwordBytes.length + salt.length);
		input.set(previous, 0);
		input.set(passwordBytes, previous.length);
		input.set(salt, previous.length + passwordBytes.length);
		previous = md5(input);
		chunks.push(previous);
		total += previous.length;
	}
	const out = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		const slice = chunk.slice(0, Math.min(chunk.length, length - offset));
		out.set(slice, offset);
		offset += slice.length;
		if (offset >= length) {
			break;
		}
	}
	return out;
}

/**
 * Parses traditional PEM.
 *
 * @param pem The PEM-encoded text.
 * @returns The parsed traditional PEM.
 */
function parseTraditionalPem(pem: string): {
	/**
	 * Carries the label value.
	 */
	readonly label: string;
	/**
	 * Carries the headers value.
	 */
	readonly headers: ReadonlyMap<string, string>;
	/**
	 * Carries the base64 body value.
	 */
	readonly base64Body: string;
} {
	const normalized = pem.replace(/\r/g, '').trim();
	const lines = normalized.split('\n');
	const begin = lines[0];
	const end = lines[lines.length - 1];
	if (
		begin === undefined ||
		end === undefined ||
		!begin.startsWith('-----BEGIN ') ||
		!end.startsWith('-----END ')
	) {
		throw new Error('Invalid PEM block');
	}
	const label = begin.slice(11, -5);
	if (end !== `-----END ${label}-----`) {
		throw new Error('PEM boundaries do not match');
	}
	const headers = new Map<string, string>();
	let index = 1;
	while (index < lines.length - 1) {
		const line = lines[index];
		if (line === undefined) {
			break;
		}
		if (line.length === 0) {
			index += 1;
			break;
		}
		const delimiter = line.indexOf(': ');
		if (delimiter === -1) {
			break;
		}
		headers.set(line.slice(0, delimiter), line.slice(delimiter + 2));
		index += 1;
	}
	const body = lines.slice(index, lines.length - 1).join('');
	return { label, headers, base64Body: body };
}
