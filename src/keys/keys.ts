/**
 * WebCrypto key generation plus import/export for PKCS#1, PKCS#8, SEC1, SPKI, and JWK.
 *
 * Supports RSA (PKCS#1v1.5 and PSS), ECDSA (P-256, P-384, P-521), and Ed25519 keys.
 * All functions use the WebCrypto API and return extractable keys.
 *
 * @example
 * ```ts
 * import { generateKeyPair, exportPkcs8Pem, importSpkiPem } from 'micro509/keys';
 *
 * // Generate and export
 * const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
 * const privatePem = await exportPkcs8Pem(keys.privateKey);
 *
 * // Import
 * const publicKey = await importSpkiPem(publicPem, { kind: 'ecdsa', curve: 'P-256' });
 * ```
 *
 * @module
 */

import {
	decodeObjectIdentifier,
	extractBitStringValue,
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
	readonly curve?: EcNamedCurve;
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
	readonly curve: EcNamedCurve;
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
 * const ecKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
 * const rsaKeys = await generateKeyPair({ kind: 'rsa', modulusLength: 4096 });
 * const edKeys = await generateKeyPair({ kind: 'ed25519' });
 *
 * // Default: ECDSA P-256
 * const keys = await generateKeyPair();
 * const pem = await keys.exportPkcs8Pem();
 * ```
 */
export async function generateKeyPair(
	algorithm: KeyAlgorithmInput = { kind: 'ecdsa', curve: 'P-256' },
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

/**
 * Export a public key as DER-encoded SubjectPublicKeyInfo.
 *
 * @see {@linkcode importSpkiDer} for the inverse operation
 * @see {@linkcode exportSpkiPem} for PEM output
 */
export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
}

/**
 * Export a private key as DER-encoded PKCS#8 PrivateKeyInfo.
 *
 * @see {@linkcode importPkcs8Der} for the inverse operation
 * @see {@linkcode exportPkcs8Pem} for PEM output
 * @see {@linkcode exportEncryptedPkcs8Der} for password-protected export
 */
export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
}

/**
 * Export a public key as a JSON Web Key.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
 * const jwk = await exportPublicJwk(keys.publicKey);
 * ```
 */
export async function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', publicKey);
}

/**
 * Export a private key as a JSON Web Key.
 *
 * @see {@linkcode importPrivateJwk} for the inverse operation
 * @see {@linkcode exportPublicJwk} for public key export
 */
export async function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', privateKey);
}

/**
 * Export a private key as PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportPkcs8Pem(keys.privateKey);
 * // -----BEGIN PRIVATE KEY-----
 * // MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH...
 * // -----END PRIVATE KEY-----
 * ```
 *
 * @see {@linkcode importPkcs8Pem} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs8Pem} for password-protected export
 */
export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('PRIVATE KEY', await exportPkcs8Der(privateKey));
}

/**
 * Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * Uses PBES2 (PKCS#5 v2.1) with AES-CBC and PBKDF2. Compatible with OpenSSL.
 *
 * @param privateKey - The private key to export
 * @param options - Encryption options including password and optional algorithm settings
 *
 * @see {@linkcode importEncryptedPkcs8Der} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs8Pem} for PEM output
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
 * Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * @example
 * ```ts
 * const keys = await generateKeyPair();
 * const pem = await exportEncryptedPkcs8Pem(keys.privateKey, { password: 'secret' });
 * // -----BEGIN ENCRYPTED PRIVATE KEY-----
 * // MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAc...
 * // -----END ENCRYPTED PRIVATE KEY-----
 * ```
 *
 * @see {@linkcode importEncryptedPkcs8Pem} for the inverse operation
 */
export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode('ENCRYPTED PRIVATE KEY', await exportEncryptedPkcs8Der(privateKey, options));
}

/**
 * Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey.
 *
 * PKCS#1 is the legacy RSA-only format. For algorithm-agnostic export, use
 * {@linkcode exportPkcs8Der}.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importPkcs1Der} for the inverse operation
 * @see {@linkcode exportPkcs1Pem} for PEM output
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
 * Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importPkcs1Pem} for the inverse operation
 * @see {@linkcode exportEncryptedPkcs1Pem} for password-protected export
 */
export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('RSA PRIVATE KEY', await exportPkcs1Der(privateKey));
}

/**
 * Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
 *
 * Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
 * For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
 *
 * @throws {Error} If the key is not an RSA key
 *
 * @see {@linkcode importEncryptedPkcs1Pem} for the inverse operation
 */
export async function exportEncryptedPkcs1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('RSA PRIVATE KEY', await exportPkcs1Der(privateKey), options);
}

/**
 * Export an EC private key as DER-encoded SEC 1 ECPrivateKey.
 *
 * SEC 1 is the legacy EC-only format. For algorithm-agnostic export, use
 * {@linkcode exportPkcs8Der}.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importSec1Der} for the inverse operation
 * @see {@linkcode exportSec1Pem} for PEM output
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
 * Export an EC private key as PEM-encoded SEC 1 ECPrivateKey.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importSec1Pem} for the inverse operation
 * @see {@linkcode exportEncryptedSec1Pem} for password-protected export
 */
export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('EC PRIVATE KEY', await exportSec1Der(privateKey));
}

/**
 * Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
 *
 * Uses OpenSSL's traditional PEM encryption with MD5-based key derivation.
 * For modern encryption, prefer {@linkcode exportEncryptedPkcs8Pem}.
 *
 * @throws {Error} If the key is not an EC key
 *
 * @see {@linkcode importEncryptedSec1Pem} for the inverse operation
 */
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

/**
 * Export a key as raw base64 (no PEM headers).
 *
 * Returns SPKI-encoded base64 for public keys, PKCS#8-encoded base64 for private keys.
 * Useful for compact storage or transmission where PEM overhead is undesirable.
 *
 * @throws {Error} If the key is a symmetric/secret key
 *
 * @see {@linkcode importSpkiBase64} for public key import
 * @see {@linkcode importPkcs8Base64} for private key import
 */
export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === 'public') {
		return base64Encode(await exportSpkiDer(key));
	}
	if (key.type === 'private') {
		return base64Encode(await exportPkcs8Der(key));
	}
	throw new Error('Cannot export secret/symmetric CryptoKey');
}

/**
 * Import a public key from DER-encoded SubjectPublicKeyInfo.
 *
 * @param der - DER-encoded SubjectPublicKeyInfo bytes
 * @param algorithm - Expected algorithm (must match key contents)
 * @returns Extractable CryptoKey with `verify` usage
 *
 * @throws {Error} If DER is malformed or algorithm doesn't match key
 *
 * @see {@linkcode exportSpkiDer} for the inverse operation
 * @see {@linkcode importSpkiPem} for PEM input
 */
export async function importSpkiDer(
	der: Uint8Array,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	const parsedSpki = parseSpkiDer(der);
	assertSpkiMatchesRequestedAlgorithm(parsedSpki, algorithm);
	try {
		return await getCrypto().subtle.importKey(
			'spki',
			new Uint8Array(der),
			toImportAlgorithm(algorithm),
			true,
			['verify'],
		);
	} catch {
		throw new Error('Malformed SubjectPublicKeyInfo');
	}
}

/**
 * Import a public key from PEM-encoded SubjectPublicKeyInfo.
 *
 * @example
 * ```ts
 * const pem = `-----BEGIN PUBLIC KEY-----
 * MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
 * -----END PUBLIC KEY-----`;
 * const key = await importSpkiPem(pem, { kind: 'ecdsa', curve: 'P-256' });
 * ```
 *
 * @see {@linkcode exportSpkiPem} for the inverse operation
 */
export async function importSpkiPem(
	pem: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(pemDecode('PUBLIC KEY', pem), algorithm);
}

/**
 * Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).
 *
 * @see {@linkcode exportBinaryBase64} for the inverse operation
 * @see {@linkcode importSpkiPem} for PEM input with headers
 */
export async function importSpkiBase64(
	base64: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	let decoded: Uint8Array;
	try {
		decoded = base64Decode(base64);
	} catch {
		throw new Error('Invalid base64 SubjectPublicKeyInfo');
	}
	return importSpkiDer(decoded, algorithm);
}

/**
 * Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.
 *
 * @param der - DER-encoded PKCS#8 PrivateKeyInfo bytes
 * @param algorithm - Expected algorithm (must match key contents)
 * @returns Extractable CryptoKey with `sign` usage
 *
 * @throws {Error} If DER is malformed or algorithm doesn't match key
 *
 * @see {@linkcode exportPkcs8Der} for the inverse operation
 * @see {@linkcode importPkcs8Pem} for PEM input
 * @see {@linkcode importEncryptedPkcs8Der} for encrypted PKCS#8
 */
export async function importPkcs8Der(
	der: Uint8Array,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	let parsedPrivateKey: ReturnType<typeof parsePkcs8PrivateKey>;
	try {
		parsedPrivateKey = parsePkcs8PrivateKey(der);
	} catch {
		throw new Error('Malformed PKCS#8 private key');
	}
	assertPkcs8MatchesRequestedAlgorithm(parsedPrivateKey, algorithm);
	try {
		return await getCrypto().subtle.importKey(
			'pkcs8',
			new Uint8Array(der),
			toImportAlgorithm(algorithm),
			true,
			['sign'],
		);
	} catch {
		throw new Error('Malformed PKCS#8 private key');
	}
}

/**
 * Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.
 *
 * @example
 * ```ts
 * const key = await importPkcs8Pem(pemString, { kind: 'ecdsa', curve: 'P-256' });
 * ```
 */
export async function importPkcs8Pem(
	pem: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(pemDecode('PRIVATE KEY', pem), algorithm);
}

/**
 * Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.
 *
 * Decrypts the PBES2 envelope using the provided password, then imports the key.
 *
 * @param der - DER-encoded EncryptedPrivateKeyInfo bytes
 * @param password - Decryption password
 * @param algorithm - Expected algorithm (must match decrypted key)
 *
 * @throws {Error} If DER is malformed, password is wrong, or algorithm doesn't match
 *
 * @see {@linkcode exportEncryptedPkcs8Der} for the inverse operation
 */
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

/**
 * Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.
 *
 * PKCS#1 is the legacy RSA-only format. Internally converts to PKCS#8 for import.
 *
 * @see {@linkcode exportPkcs1Der} for the inverse operation
 * @see {@linkcode importPkcs1Pem} for PEM input
 */
export async function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs8Der(wrapPkcs1InPkcs8(der), algorithm);
}

/**
 * Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey.
 *
 * Expects the `-----BEGIN RSA PRIVATE KEY-----` PEM label.
 *
 * @see {@linkcode exportPkcs1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs1Pem} for encrypted PEM
 */
export async function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs1Der(pemDecode('RSA PRIVATE KEY', pem), algorithm);
}

/**
 * Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).
 *
 * Decrypts OpenSSL's traditional PEM encryption format.
 *
 * @see {@linkcode exportEncryptedPkcs1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
 */
export async function importEncryptedPkcs1Pem(
	pem: string,
	password: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('RSA PRIVATE KEY', pem, password);
	return importPkcs1Der(decrypted, algorithm);
}

/**
 * Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).
 *
 * @see {@linkcode exportBinaryBase64} for the inverse operation
 * @see {@linkcode importPkcs8Pem} for PEM input with headers
 */
export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	let decoded: Uint8Array;
	try {
		decoded = base64Decode(base64);
	} catch {
		throw new Error('Invalid base64 PKCS#8 private key');
	}
	return importPkcs8Der(decoded, algorithm);
}

/**
 * Import an EC private key from DER-encoded SEC 1 ECPrivateKey.
 *
 * SEC 1 is the legacy EC-only format. Internally converts to PKCS#8 for import.
 *
 * @see {@linkcode exportSec1Der} for the inverse operation
 * @see {@linkcode importSec1Pem} for PEM input
 */
export async function importSec1Der(
	der: Uint8Array,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importPkcs8Der(wrapSec1InPkcs8(der, algorithm.curve), algorithm);
}

/**
 * Import an EC private key from PEM-encoded SEC 1 ECPrivateKey.
 *
 * Expects the `-----BEGIN EC PRIVATE KEY-----` PEM label.
 *
 * @see {@linkcode exportSec1Pem} for the inverse operation
 * @see {@linkcode importEncryptedSec1Pem} for encrypted PEM
 */
export async function importSec1Pem(
	pem: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importSec1Der(pemDecode('EC PRIVATE KEY', pem), algorithm);
}

/**
 * Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).
 *
 * Decrypts OpenSSL's traditional PEM encryption format.
 *
 * @see {@linkcode exportEncryptedSec1Pem} for the inverse operation
 * @see {@linkcode importEncryptedPkcs8Pem} for modern PBES2 encryption
 */
export async function importEncryptedSec1Pem(
	pem: string,
	password: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('EC PRIVATE KEY', pem, password);
	return importSec1Der(decrypted, algorithm);
}

/**
 * Import a public verification key from a JSON Web Key.
 *
 * @param jwk - JSON Web Key object with public key components
 * @param algorithm - Expected algorithm (must match JWK's `kty` and `crv`)
 * @returns Extractable CryptoKey with `verify` usage
 *
 * @throws {Error} If JWK is malformed or algorithm doesn't match
 *
 * @see {@linkcode exportPublicJwk} for the inverse operation
 */
export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	assertPublicJwkMatchesRequestedAlgorithm(jwk, algorithm);
	try {
		return await getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, [
			'verify',
		]);
	} catch {
		throw new Error('Malformed public JWK');
	}
}

/**
 * Import a private signing key from a JSON Web Key.
 *
 * @example
 * ```ts
 * const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' };
 * const key = await importPrivateJwk(jwk, { kind: 'ecdsa', curve: 'P-256' });
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
				namedCurve: algorithm.curve ?? 'P-256',
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
				namedCurve: algorithm.curve,
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
	/** Optional algorithm parameter tag. */
	readonly parametersTag?: number;
	/** Raw DER of the inner private key (PKCS#1 for RSA, SEC 1 for EC). */
	readonly privateKeyDer: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const algorithm = children[1];
	const privateKey = children[2];
	if (
		children.length < 3 ||
		children.length > 4 ||
		algorithm === undefined ||
		algorithm.tag !== 0x30 ||
		privateKey === undefined ||
		privateKey.tag !== 0x04
	) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const algorithmChildren = readSequenceChildren(
		der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
	);
	const algorithmOid = algorithmChildren[0];
	if (
		algorithmOid === undefined ||
		algorithmOid.tag !== 0x06 ||
		algorithmChildren.length < 1 ||
		algorithmChildren.length > 2
	) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const parameters = algorithmChildren[1];
	return {
		algorithmOid: decodeObjectIdentifier(algorithmOid.value),
		...(parameters === undefined ? {} : { parametersTag: parameters.tag }),
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
function wrapSec1InPkcs8(der: Uint8Array, curve: ImportEcPublicKeyInput['curve']): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.ecPublicKey), objectIdentifier(curveToOid(curve))]),
		octetString(new Uint8Array(der)),
	]);
}

/** Map a curve name to its ASN.1 OID string. */
function curveToOid(curve: ImportEcPublicKeyInput['curve']): string {
	switch (curve) {
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
		const headerName = line.slice(0, delimiter);
		if (headers.has(headerName)) {
			throw new Error(`Duplicate PEM header: ${headerName}`);
		}
		headers.set(headerName, line.slice(delimiter + 2));
		index += 1;
	}
	const body = lines.slice(index, lines.length - 1).join('');
	return { label, headers, base64Body: body };
}

function parseSpkiDer(der: Uint8Array): {
	readonly algorithmOid: string;
	readonly parametersOid?: string;
	readonly parametersTag?: number;
} {
	try {
		const children = readSequenceChildren(der);
		if (children.length !== 2) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const algorithm = children[0];
		const subjectPublicKey = children[1];
		if (
			algorithm === undefined ||
			algorithm.tag !== 0x30 ||
			subjectPublicKey === undefined ||
			subjectPublicKey.tag !== 0x03
		) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		extractBitStringValue(subjectPublicKey);
		const algorithmChildren = readSequenceChildren(
			der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
		);
		const algorithmOid = algorithmChildren[0];
		if (
			algorithmOid === undefined ||
			algorithmOid.tag !== 0x06 ||
			algorithmChildren.length < 1 ||
			algorithmChildren.length > 2
		) {
			throw new Error('Malformed SubjectPublicKeyInfo');
		}
		const parameters = algorithmChildren[1];
		return {
			algorithmOid: decodeObjectIdentifier(algorithmOid.value),
			...(parameters === undefined ? {} : { parametersTag: parameters.tag }),
			...(parameters?.tag === 0x06
				? { parametersOid: decodeObjectIdentifier(parameters.value) }
				: {}),
		};
	} catch {
		throw new Error('Malformed SubjectPublicKeyInfo');
	}
}

function assertSpkiMatchesRequestedAlgorithm(
	parsedSpki: {
		readonly algorithmOid: string;
		readonly parametersOid?: string;
		readonly parametersTag?: number;
	},
	algorithm: PublicKeyImportInput,
): void {
	switch (algorithm.kind) {
		case 'rsa':
			if (
				parsedSpki.algorithmOid !== OIDS.rsaEncryption ||
				(parsedSpki.parametersTag !== undefined && parsedSpki.parametersTag !== 0x05)
			) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				parsedSpki.algorithmOid !== OIDS.ecPublicKey ||
				parsedSpki.parametersTag !== 0x06 ||
				parsedSpki.parametersOid !== curveToOid(algorithm.curve)
			) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (parsedSpki.algorithmOid !== OIDS.ed25519 || parsedSpki.parametersTag !== undefined) {
				throw new Error('SubjectPublicKeyInfo algorithm does not match requested import algorithm');
			}
			return;
	}
}

function assertPkcs8MatchesRequestedAlgorithm(
	parsedPrivateKey: {
		readonly algorithmOid: string;
		readonly parametersOid?: string;
		readonly parametersTag?: number;
	},
	algorithm: PrivateKeyImportInput,
): void {
	switch (algorithm.kind) {
		case 'rsa':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.rsaEncryption ||
				(parsedPrivateKey.parametersTag !== undefined && parsedPrivateKey.parametersTag !== 0x05)
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.ecPublicKey ||
				parsedPrivateKey.parametersTag !== 0x06 ||
				parsedPrivateKey.parametersOid !== curveToOid(algorithm.curve)
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (
				parsedPrivateKey.algorithmOid !== OIDS.ed25519 ||
				parsedPrivateKey.parametersTag !== undefined
			) {
				throw new Error('PKCS#8 private key algorithm does not match requested import algorithm');
			}
			return;
	}
}

function assertPublicJwkMatchesRequestedAlgorithm(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): void {
	if (
		jwk.k !== undefined ||
		jwk.d !== undefined ||
		jwk.p !== undefined ||
		jwk.q !== undefined ||
		jwk.dp !== undefined ||
		jwk.dq !== undefined ||
		jwk.qi !== undefined ||
		jwk.oth !== undefined
	) {
		throw new Error('Public JWK must not contain private key material');
	}
	switch (algorithm.kind) {
		case 'rsa':
			if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ecdsa':
			if (
				jwk.kty !== 'EC' ||
				jwk.crv !== algorithm.curve ||
				typeof jwk.x !== 'string' ||
				typeof jwk.y !== 'string'
			) {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
		case 'ed25519':
			if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
				throw new Error('Public JWK algorithm does not match requested import algorithm');
			}
			return;
	}
}
