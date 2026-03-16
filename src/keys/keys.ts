/**
 * WebCrypto key generation plus import/export for PKCS#1, PKCS#8, SEC1, SPKI, and JWK
 * key containers.
 *
 * @module
 */

import {
	decodeObjectIdentifier,
	hexToBytes,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1.ts';
import {
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { md5 } from '#micro509/internal/crypto/hash.ts';
import {
	decryptPbes2,
	encryptPbes2,
	type Pbes2EncryptionOptions,
} from '#micro509/internal/crypto/pbes2.ts';
import { getCrypto } from '#micro509/internal/crypto/webcrypto.ts';
import { base64Decode, base64Encode } from '#micro509/internal/shared/base64.ts';
import { pemDecode, pemEncode } from '#micro509/pem/pem.ts';

export type {
	Pbes2EncryptionOptions,
	Pbes2EncryptionScheme,
	Pbes2Prf,
} from '#micro509/internal/crypto/pbes2.ts';

/** Hash algorithm paired with an RSA key. */
export type RsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** RSA signature padding scheme. */
export type RsaScheme = 'pkcs1-v1_5' | 'pss';

/** NIST elliptic curve for ECDSA keys. */
export type EcNamedCurve = 'P-256' | 'P-384' | 'P-521';

/** RSA variant of {@linkcode KeyAlgorithmInput}. */
export interface RsaKeyAlgorithmInput {
	/** Discriminant selecting RSA key generation. */
	readonly kind: 'rsa';
	/** RSA modulus size in bits. Defaults to `2048`. */
	readonly modulusLength?: 2048 | 3072 | 4096;
	/** Hash algorithm for the key. Defaults to `'SHA-256'`. */
	readonly hash?: RsaHash;
	/** Signature padding scheme. Defaults to `'pkcs1-v1_5'`. */
	readonly scheme?: RsaScheme;
}

/** ECDSA variant of {@linkcode KeyAlgorithmInput}. */
export interface EcKeyAlgorithmInput {
	/** Discriminant selecting ECDSA key generation. */
	readonly kind: 'ecdsa';
	/** NIST curve. Defaults to `'P-256'`. */
	readonly namedCurve?: EcNamedCurve;
}

/** Ed25519 variant of {@linkcode KeyAlgorithmInput}. */
export interface Ed25519KeyAlgorithmInput {
	/** Discriminant selecting Ed25519 key generation. */
	readonly kind: 'ed25519';
}

/** Input for {@linkcode generateKeyPair}. Selects algorithm family and parameters. */
export type KeyAlgorithmInput =
	| RsaKeyAlgorithmInput
	| EcKeyAlgorithmInput
	| Ed25519KeyAlgorithmInput;

/** Key pair with convenience export helpers. Returned by {@linkcode generateKeyPair}. */
export interface KeyPairMaterial {
	/** The WebCrypto public key (extractable, `verify` usage). */
	readonly publicKey: CryptoKey;
	/** The WebCrypto private key (extractable, `sign` usage). */
	readonly privateKey: CryptoKey;
	/** Export the public key as DER-encoded SubjectPublicKeyInfo. */
	exportSpkiDer(): Promise<Uint8Array>;
	/** Export the public key as PEM-encoded SubjectPublicKeyInfo. */
	exportSpkiPem(): Promise<string>;
	/** Export the private key as DER-encoded PKCS#8 PrivateKeyInfo. */
	exportPkcs8Der(): Promise<Uint8Array>;
	/** Export the private key as PEM-encoded PKCS#8 PrivateKeyInfo. */
	exportPkcs8Pem(): Promise<string>;
	/** Export the public key as a JSON Web Key. */
	exportPublicJwk(): Promise<JsonWebKey>;
	/** Export the private key as a JSON Web Key. */
	exportPrivateJwk(): Promise<JsonWebKey>;
}

/** RSA variant of {@linkcode PublicKeyImportInput}. */
export interface ImportRsaPublicKeyInput {
	/** Discriminant selecting RSA import. */
	readonly kind: 'rsa';
	/** Hash algorithm. Defaults to `'SHA-256'`. */
	readonly hash?: RsaHash;
	/** Signature padding scheme. Defaults to `'pkcs1-v1_5'`. */
	readonly scheme?: RsaScheme;
}

/** ECDSA variant of {@linkcode PublicKeyImportInput}. */
export interface ImportEcPublicKeyInput {
	/** Discriminant selecting ECDSA import. */
	readonly kind: 'ecdsa';
	/** NIST curve the key belongs to. Required for EC import. */
	readonly namedCurve: EcNamedCurve;
}

/** Ed25519 variant of {@linkcode PublicKeyImportInput}. */
export interface ImportEd25519PublicKeyInput {
	/** Discriminant selecting Ed25519 import. */
	readonly kind: 'ed25519';
}

/** Algorithm descriptor for public key import functions. */
export type PublicKeyImportInput =
	| ImportRsaPublicKeyInput
	| ImportEcPublicKeyInput
	| ImportEd25519PublicKeyInput;

/** Algorithm descriptor for private key import functions. Same shape as {@linkcode PublicKeyImportInput}. */
export type PrivateKeyImportInput = PublicKeyImportInput;

/** PBES2 encryption options for {@linkcode exportEncryptedPkcs8Der} and {@linkcode exportEncryptedPkcs8Pem}. */
export type EncryptedPkcs8Options = Pbes2EncryptionOptions;

/** Options for OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM encryption (PKCS#1/SEC1). */
export interface LegacyPemEncryptionOptions {
	/** Passphrase used to derive the encryption key. */
	readonly password: string;
	/** 16-byte initialization vector. Random when omitted. */
	readonly iv?: Uint8Array;
	/** AES-CBC cipher. Defaults to `'AES-256-CBC'`. */
	readonly cipher?: 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC';
}

/**
 * Generate an asymmetric key pair for signing and verification.
 *
 * @example
 * ```ts
 * const ecKeys = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-384' });
 * const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 4096 });
 * const edKeys = await generateKeyPair({ kind: 'ed25519' });
 *
 * // Default: ECDSA P-256
 * const keys = await generateKeyPair();
 * const pem = await keys.exportPkcs8Pem();
 * ```
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

function wrapKeyPair(publicKey: CryptoKey, privateKey: CryptoKey): KeyPairMaterial {
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

/** Export a public key as DER-encoded SubjectPublicKeyInfo. */
export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
}

/** Export a private key as DER-encoded PKCS#8 PrivateKeyInfo. */
export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
}

/**
 * Export a public key as a JSON Web Key.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
 * const jwk = await exportPublicJwk(keys.publicKey);
 * ```
 */
export async function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', publicKey);
}

/** Export a private key as a JSON Web Key. */
export async function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', privateKey);
}

/** Export a private key as a PEM-encoded PKCS#8 PrivateKeyInfo. */
export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('PRIVATE KEY', await exportPkcs8Der(privateKey));
}

/** Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo. */
export async function exportEncryptedPkcs8Der(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const encryption = await encryptPbes2(pkcs8, options);
	return sequence([encryption.algorithmIdentifierDer, octetString(encryption.encryptedData)]);
}

/** Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo. */
export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode('ENCRYPTED PRIVATE KEY', await exportEncryptedPkcs8Der(privateKey, options));
}

/** Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys. */
export async function exportPkcs1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.rsaEncryption) {
		throw new Error('PKCS#1 export requires an RSA private key');
	}
	return parsed.privateKeyDer;
}

/** Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys. */
export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('RSA PRIVATE KEY', await exportPkcs1Der(privateKey));
}

/** Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1). */
export async function exportEncryptedPkcs1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('RSA PRIVATE KEY', await exportPkcs1Der(privateKey), options);
}

/** Export an EC private key as DER-encoded SEC 1 ECPrivateKey. Throws for non-EC keys. */
export async function exportSec1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.ecPublicKey) {
		throw new Error('SEC1 export requires an EC private key');
	}
	return parsed.privateKeyDer;
}

/** Export an EC private key as PEM-encoded SEC 1 ECPrivateKey. */
export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('EC PRIVATE KEY', await exportSec1Der(privateKey));
}

/** Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1). */
export async function exportEncryptedSec1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('EC PRIVATE KEY', await exportSec1Der(privateKey), options);
}

/**
 * Export a public key as PEM-encoded SubjectPublicKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportSpkiPem(keys.publicKey);
 * ```
 */
export async function exportSpkiPem(publicKey: CryptoKey): Promise<string> {
	return pemEncode('PUBLIC KEY', await exportSpkiDer(publicKey));
}

/** Export a key as raw base64: SPKI for public keys, PKCS#8 for private keys. */
export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === 'public') {
		return base64Encode(await exportSpkiDer(key));
	}
	if (key.type === 'private') {
		return base64Encode(await exportPkcs8Der(key));
	}
	throw new Error('Cannot export secret/symmetric CryptoKey');
}

/** Import a public key from DER-encoded SubjectPublicKeyInfo. */
export async function importSpkiDer(
	der: Uint8Array,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	assertSpkiDer(der);
	return getCrypto().subtle.importKey(
		'spki',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['verify'],
	);
}

/** Import a public key from PEM-encoded SubjectPublicKeyInfo. */
export async function importSpkiPem(
	pem: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(pemDecode('PUBLIC KEY', pem), algorithm);
}

/** Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers). */
export async function importSpkiBase64(
	base64: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	try {
		return importSpkiDer(base64Decode(base64), algorithm);
	} catch (error) {
		if (error instanceof Error && error.message === 'Malformed SubjectPublicKeyInfo') {
			throw error;
		}
		throw new Error('Invalid base64 SubjectPublicKeyInfo');
	}
}

/** Import a private key from DER-encoded PKCS#8 PrivateKeyInfo. */
export async function importPkcs8Der(
	der: Uint8Array,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	try {
		parsePkcs8PrivateKey(der);
	} catch {
		throw new Error('Malformed PKCS#8 private key');
	}
	return getCrypto().subtle.importKey(
		'pkcs8',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['sign'],
	);
}

/**
 * Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * @example
 * ```ts
 * const key = await importPkcs8Pem(pemString, { kind: 'ecdsa', namedCurve: 'P-256' });
 * ```
 */
export async function importPkcs8Pem(
	pem: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(pemDecode('PRIVATE KEY', pem), algorithm);
}

/** Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo. */
export async function importEncryptedPkcs8Der(
	der: Uint8Array,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	let children: readonly ReturnType<typeof readSequenceChildren>[number][];
	try {
		children = readSequenceChildren(der);
	} catch {
		throw new Error('Malformed EncryptedPrivateKeyInfo');
	}
	const algorithmIdentifier = children[0];
	const encryptedData = children[1];
	if (
		children.length !== 2 ||
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
 * Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @example
 * ```ts
 * const key = await importEncryptedPkcs8Pem(pem, 'secret', { kind: 'rsa' });
 * ```
 */
export async function importEncryptedPkcs8Pem(
	pem: string,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importEncryptedPkcs8Der(pemDecode('ENCRYPTED PRIVATE KEY', pem), password, algorithm);
}

/** Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey. */
export async function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs8Der(wrapPkcs1InPkcs8(der), algorithm);
}

/** Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey (`RSA PRIVATE KEY` label). */
export async function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs1Der(pemDecode('RSA PRIVATE KEY', pem), algorithm);
}

/** Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1). */
export async function importEncryptedPkcs1Pem(
	pem: string,
	password: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('RSA PRIVATE KEY', pem, password);
	return importPkcs1Der(decrypted, algorithm);
}

/** Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers). */
export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	try {
		return importPkcs8Der(base64Decode(base64), algorithm);
	} catch (error) {
		if (error instanceof Error && error.message === 'Malformed PKCS#8 private key') {
			throw error;
		}
		throw new Error('Invalid base64 PKCS#8 private key');
	}
}

/** Import an EC private key from DER-encoded SEC 1 ECPrivateKey. */
export async function importSec1Der(
	der: Uint8Array,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importPkcs8Der(wrapSec1InPkcs8(der, algorithm.namedCurve), algorithm);
}

/** Import an EC private key from PEM-encoded SEC 1 ECPrivateKey (`EC PRIVATE KEY` label). */
export async function importSec1Pem(
	pem: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importSec1Der(pemDecode('EC PRIVATE KEY', pem), algorithm);
}

/** Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1). */
export async function importEncryptedSec1Pem(
	pem: string,
	password: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('EC PRIVATE KEY', pem, password);
	return importSec1Der(decrypted, algorithm);
}

/** Import a public verification key from a JSON Web Key. */
export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['verify']);
}

/**
 * Import a private signing key from a JSON Web Key.
 *
 * @example
 * ```ts
 * const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' };
 * const key = await importPrivateJwk(jwk, { kind: 'ecdsa', namedCurve: 'P-256' });
 * ```
 */
export async function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['sign']);
}

/** Map a {@linkcode KeyAlgorithmInput} to the WebCrypto `generateKey` algorithm parameter. */
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

/** Map a {@linkcode PublicKeyImportInput} to the WebCrypto `importKey` algorithm parameter. */
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

/** Extract algorithm OID and inner key bytes from a PKCS#8 PrivateKeyInfo envelope. */
function parsePkcs8PrivateKey(der: Uint8Array): {
	/** OID identifying the algorithm family (e.g. rsaEncryption, ecPublicKey). */
	readonly algorithmOid: string;
	/** Optional algorithm parameter OID (e.g. named curve for EC keys). */
	readonly parametersOid?: string;
	/** Raw DER of the inner private key (PKCS#1 for RSA, SEC 1 for EC). */
	readonly privateKeyDer: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const algorithm = children[1];
	const privateKey = children[2];
	if (algorithm === undefined || privateKey === undefined || privateKey.tag !== 0x04) {
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

/** Wrap a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
function wrapPkcs1InPkcs8(der: Uint8Array): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(der)),
	]);
}

/** Wrap a SEC 1 ECPrivateKey in a PKCS#8 PrivateKeyInfo envelope for WebCrypto import. */
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

/** Map a WebCrypto named curve to its ASN.1 OID string. */
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

/** Map an {@linkcode RsaScheme} to the WebCrypto algorithm name string. */
function rsaSchemeToWebCryptoAlgorithmName(
	scheme: RsaScheme | undefined,
): 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' {
	if (scheme === 'pss') {
		return 'RSA-PSS';
	}
	return 'RSASSA-PKCS1-v1_5';
}

/** Encrypt DER key material as an OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM block. */
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

/** Decrypt an OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM block back to plaintext DER. */
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
	if (!isTraditionalPemIvHex(ivHex)) {
		throw new Error(
			'Traditional PEM encryption requires a 16-byte IV encoded as 32 hex characters',
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

/** Derive and import an AES-CBC key for legacy PEM encryption using OpenSSL `EVP_BytesToKey`. */
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

/** Type guard for the three AES-CBC ciphers supported by legacy PEM encryption. */
function isTraditionalPemCipher(
	cipher: string | undefined,
): cipher is 'AES-128-CBC' | 'AES-192-CBC' | 'AES-256-CBC' {
	return cipher === 'AES-128-CBC' || cipher === 'AES-192-CBC' || cipher === 'AES-256-CBC';
}

function isTraditionalPemIvHex(value: string): boolean {
	return value.length === 32 && /^[0-9A-Fa-f]+$/.test(value);
}

/** Return the AES key size in bits for a given cipher name. */
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

/** OpenSSL `EVP_BytesToKey` with MD5 — derives a fixed-length key from password + salt. */
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

/** Parse a PEM block into its label, RFC 1421 headers, and base64 body. */
function parseTraditionalPem(pem: string): {
	/** PEM type label between `BEGIN` and `END` markers. */
	readonly label: string;
	/** RFC 1421 encapsulated headers (e.g. `Proc-Type`, `DEK-Info`). */
	readonly headers: ReadonlyMap<string, string>;
	/** Base64-encoded payload after the headers. */
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

function assertSpkiDer(der: Uint8Array): void {
	try {
		const children = readSequenceChildren(der);
		if (children.length !== 2) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const algorithm = children[0];
		const subjectPublicKey = children[1];
		if (
			algorithm === undefined ||
			subjectPublicKey === undefined ||
			subjectPublicKey.tag !== 0x03
		) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const algorithmChildren = readSequenceChildren(
			der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
		);
		const algorithmOid = algorithmChildren[0];
		if (algorithmOid === undefined) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		decodeObjectIdentifier(algorithmOid.value);
	} catch {
		throw new Error('Malformed SubjectPublicKeyInfo');
	}
}
