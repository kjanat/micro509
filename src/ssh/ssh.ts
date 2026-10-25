/**
 * OpenSSH public-key lines, unencrypted `openssh-key-v1` private keys, and
 * `SHA256:` fingerprints for RSA, Ed25519, and ECDSA on P-256, P-384 and P-521.
 *
 * Keys move through the existing WebCrypto, JWK and PKCS#8/SPKI APIs of
 * `micro509/keys`. Nothing here opens a connection, speaks the SSH transport,
 * reads SSH certificates, evaluates `authorized_keys` options, or decrypts a
 * private key.
 *
 * The `ssh-rsa` key type names the RSA public-key encoding (RFC 4253 §6.6). It
 * does not select a signature hash: RFC 8332 §3 keeps the `ssh-rsa` key format
 * for the `rsa-sha2-256` and `rsa-sha2-512` signature algorithms. Importing an
 * `ssh-rsa` key enables no SHA-1 signature.
 *
 * @example
 * ```ts
 * import { generateKeyPair, unwrap } from 'micro509';
 * import {
 * 	exportOpenSshPrivateKey,
 * 	exportSshPublicKey,
 * 	importOpenSshPrivateKey,
 * } from 'micro509/ssh';
 *
 * const keys = await generateKeyPair({ kind: 'ed25519' });
 * const line = await exportSshPublicKey(keys.publicKey, { comment: 'me@host' });
 * const pem = await exportOpenSshPrivateKey(keys.privateKey, { comment: 'me@host' });
 * const imported = unwrap(await importOpenSshPrivateKey(pem));
 * console.log(line, imported.fingerprint);
 * ```
 *
 * @module
 */

import { toArrayBuffer } from '#micro509/internal/asn1/asn1';
import { concatBytes } from '#micro509/internal/asn1/der';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import { base64Decode, base64Encode } from '#micro509/internal/shared/base64';
import type {
	EcNamedCurve,
	ImportEcKeyInput,
	ImportEd25519KeyInput,
	ImportRsaKeyInput,
	RsaHash,
	RsaSignatureScheme,
} from '#micro509/keys/keys';
import {
	exportPrivateJwk,
	exportPublicJwk,
	importPrivateJwkOrThrow,
	importPublicJwkOrThrow,
} from '#micro509/keys/keys';
import { pemDecodeOrThrow, pemEncode } from '#micro509/pem/pem';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import {
	failureResult,
	isResultError,
	rethrowIfInvariant,
	successResult,
	throwMicro509Error,
	unwrap,
} from '#micro509/result/result';
import type { SshErrorCode, SshReader } from '#micro509/ssh/wire';
import {
	asSshErrorCode,
	bigintToBytes,
	bytesEqual,
	bytesToBigint,
	createSshReader,
	decodeUtf8,
	sshFail,
	sshMpint,
	sshString,
	sshTextString,
	sshUint32,
} from '#micro509/ssh/wire';

export type { SshErrorCode } from '#micro509/ssh/wire';

/** SSH public-key type names (RFC 4253 §6.6, RFC 5656 §6.2, RFC 8709 §4) this module reads and writes. */
export type SshKeyType =
	| 'ssh-rsa'
	| 'ssh-ed25519'
	| 'ecdsa-sha2-nistp256'
	| 'ecdsa-sha2-nistp384'
	| 'ecdsa-sha2-nistp521';

/** Algorithm family of an SSH key, discriminated by `kind`. */
export type SshKeyAlgorithm =
	| {
			/** RSA. */
			readonly kind: 'rsa';
			/** Modulus size in bits. */
			readonly modulusBits: number;
	  }
	| {
			/** ECDSA. */
			readonly kind: 'ecdsa';
			/** NIST curve. */
			readonly curve: EcNamedCurve;
	  }
	| {
			/** Ed25519. */
			readonly kind: 'ed25519';
	  };

/** Structured failure payload of the SSH key import functions. */
export interface SshFailure extends Micro509Error<SshErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Success-or-failure result of the SSH key import functions.
 *
 * `code` is `'malformed'` for structurally invalid input, `'unsupported'` for a
 * valid construct this module does not read (encrypted keys, multi-key files,
 * other key types, RSA below the minimum size, compressed points unless
 * accepted), `'limit_exceeded'` for an implementation bound, and
 * `'key_mismatch'` when the declared key types or the embedded public and
 * private keys disagree. No message contains private key material.
 */
export type SshResult<T> =
	| { readonly ok: true; readonly value: T }
	| ErrorResult<SshErrorCode, Record<never, never>, SshFailure>;

/** Policy options of the SSH key import functions. */
export interface SshImportOptions {
	/**
	 * Smallest accepted RSA modulus in bits, an integer from 1 to 16384. Default: `2048`.
	 *
	 * The standards leave key strength to the relying party. RFC 8332 §5.1 calls
	 * 2048 bits prudent; OpenSSH itself accepts 1024.
	 */
	readonly minRsaModulusBits?: number;
	/**
	 * Accept SEC 1 compressed ECDSA points. Default: `false`.
	 *
	 * RFC 5656 §3.1 allows point compression; OpenSSH reads and writes only
	 * uncompressed points.
	 */
	readonly acceptCompressedEcPoints?: boolean;
	/**
	 * WebCrypto parameters of an imported RSA key. Default: PKCS#1 v1.5 with
	 * SHA-256. These choose how the `CryptoKey` signs; they do not change the
	 * `ssh-rsa` key encoding.
	 */
	readonly rsa?: {
		/** Signature padding scheme. */
		readonly scheme?: RsaSignatureScheme;
		/** Signature hash. */
		readonly hash?: RsaHash;
	};
}

/** Public key read from an OpenSSH public-key line. */
export interface ImportedSshPublicKey {
	/** SSH key type name. */
	readonly keyType: SshKeyType;
	/** Algorithm family and size. */
	readonly algorithm: SshKeyAlgorithm;
	/** Extractable WebCrypto key with `verify` usage. */
	readonly publicKey: CryptoKey;
	/** The line's trailing comment; empty when absent. */
	readonly comment: string;
	/** `SHA256:` fingerprint of the public-key blob. */
	readonly fingerprint: string;
}

/** Key pair read from an `openssh-key-v1` private-key file. */
export interface ImportedOpenSshPrivateKey extends ImportedSshPublicKey {
	/** Extractable WebCrypto private key with `sign` usage. */
	readonly privateKey: CryptoKey;
}

/** Options of {@linkcode exportSshPublicKey} and {@linkcode exportOpenSshPrivateKey}. */
export interface SshExportOptions {
	/** Comment to attach, at most 8192 UTF-8 bytes. Must be well-formed Unicode without CR, LF or NUL. Default: empty. */
	readonly comment?: string;
}

/** Machine-readable failure reason of the SSH key export functions. */
export type SshExportErrorCode =
	| 'invalid_key'
	| 'unsupported_algorithm'
	| 'not_extractable'
	| 'invalid_comment';

const MAX_PUBLIC_KEY_LINE_BYTES = 16 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES = 32 * 1024;
const MAX_MPINT_BYTES = 2049;
const MAX_STRING_BYTES = 8192;
const MAX_RSA_MODULUS_BITS = 16384;
const DEFAULT_MIN_RSA_MODULUS_BITS = 2048;
const PRIVATE_KEY_LABEL = 'OPENSSH PRIVATE KEY';
const AUTH_MAGIC = Uint8Array.from('openssh-key-v1', (character) => character.charCodeAt(0));
const NO_CIPHER_BLOCK_SIZE = 8;
const ED25519_KEY_BYTES = 32;

const SSH_KEY_TYPES = [
	'ssh-rsa',
	'ssh-ed25519',
	'ecdsa-sha2-nistp256',
	'ecdsa-sha2-nistp384',
	'ecdsa-sha2-nistp521',
] as const satisfies readonly SshKeyType[];

function asSshKeyType(name: string): SshKeyType | undefined {
	return SSH_KEY_TYPES.find((candidate) => candidate === name);
}

interface CurveInfo {
	readonly identifier: 'nistp256' | 'nistp384' | 'nistp521';
	readonly size: number;
	readonly hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
	readonly prime: bigint;
	readonly b: bigint;
}

const CURVES = {
	'P-256': {
		identifier: 'nistp256',
		size: 32,
		hash: 'SHA-256',
		prime: 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n,
		b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
	},
	'P-384': {
		identifier: 'nistp384',
		size: 48,
		hash: 'SHA-384',
		prime: 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n,
		b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
	},
	'P-521': {
		identifier: 'nistp521',
		size: 66,
		hash: 'SHA-512',
		prime: 2n ** 521n - 1n,
		b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
	},
} as const satisfies Record<EcNamedCurve, CurveInfo>;

const CURVE_NAMES = ['P-256', 'P-384', 'P-521'] as const satisfies readonly EcNamedCurve[];

const ECDSA_KEY_TYPE_CURVES = {
	'ecdsa-sha2-nistp256': 'P-256',
	'ecdsa-sha2-nistp384': 'P-384',
	'ecdsa-sha2-nistp521': 'P-521',
} as const satisfies Record<Exclude<SshKeyType, 'ssh-rsa' | 'ssh-ed25519'>, EcNamedCurve>;

type SshPublicMaterial =
	| { readonly kind: 'rsa'; readonly e: Uint8Array; readonly n: Uint8Array }
	| {
			readonly kind: 'ecdsa';
			readonly curve: EcNamedCurve;
			readonly x: Uint8Array;
			readonly y: Uint8Array;
	  }
	| { readonly kind: 'ed25519'; readonly x: Uint8Array };

type SshPrivateMaterial =
	| {
			readonly kind: 'rsa';
			readonly pub: Extract<SshPublicMaterial, { kind: 'rsa' }>;
			readonly d: Uint8Array;
			readonly p: Uint8Array;
			readonly q: Uint8Array;
			readonly iqmp: Uint8Array;
	  }
	| {
			readonly kind: 'ecdsa';
			readonly pub: Extract<SshPublicMaterial, { kind: 'ecdsa' }>;
			readonly d: Uint8Array;
	  }
	| {
			readonly kind: 'ed25519';
			readonly pub: Extract<SshPublicMaterial, { kind: 'ed25519' }>;
			readonly seed: Uint8Array;
	  };

interface ResolvedImportOptions {
	readonly minRsaModulusBits: number;
	readonly acceptCompressedEcPoints: boolean;
	readonly rsaScheme: RsaSignatureScheme;
	readonly rsaHash: RsaHash;
}

function resolveImportOptions(options: SshImportOptions): ResolvedImportOptions {
	if (typeof options !== 'object' || options === null || Array.isArray(options)) {
		return sshFail('invalid_options', 'SSH import options must be an object');
	}
	const minRsaModulusBits =
		options.minRsaModulusBits === undefined
			? DEFAULT_MIN_RSA_MODULUS_BITS
			: options.minRsaModulusBits;
	if (
		!Number.isSafeInteger(minRsaModulusBits) ||
		minRsaModulusBits < 1 ||
		minRsaModulusBits > MAX_RSA_MODULUS_BITS
	) {
		return sshFail('invalid_options', 'minRsaModulusBits must be an integer from 1 to 16384');
	}
	const acceptCompressedEcPoints =
		options.acceptCompressedEcPoints === undefined ? false : options.acceptCompressedEcPoints;
	if (typeof acceptCompressedEcPoints !== 'boolean') {
		return sshFail('invalid_options', 'acceptCompressedEcPoints must be a boolean');
	}
	const rsa = options.rsa === undefined ? {} : options.rsa;
	if (typeof rsa !== 'object' || rsa === null || Array.isArray(rsa)) {
		return sshFail('invalid_options', 'rsa must be an object');
	}
	const rsaScheme = rsa.scheme === undefined ? 'pkcs1-v1_5' : rsa.scheme;
	const rsaHash = rsa.hash === undefined ? 'SHA-256' : rsa.hash;
	if (rsaScheme !== 'pkcs1-v1_5' && rsaScheme !== 'pss') {
		return sshFail('invalid_options', 'Unsupported RSA signature scheme');
	}
	if (rsaHash !== 'SHA-256' && rsaHash !== 'SHA-384' && rsaHash !== 'SHA-512') {
		return sshFail('invalid_options', 'Unsupported RSA signature hash');
	}
	return { minRsaModulusBits, acceptCompressedEcPoints, rsaScheme, rsaHash };
}

function unhandledKey(value: never): never {
	throw new Error(`Unhandled SSH key: ${String(value)}`);
}

function keyTypeOf(material: SshPublicMaterial): SshKeyType {
	switch (material.kind) {
		case 'rsa':
			return 'ssh-rsa';
		case 'ed25519':
			return 'ssh-ed25519';
		case 'ecdsa':
			return `ecdsa-sha2-${CURVES[material.curve].identifier}`;
		default:
			return unhandledKey(material);
	}
}

function bitLength(magnitude: Uint8Array): number {
	return (magnitude.length - 1) * 8 + 32 - Math.clz32(magnitude[0] ?? 0);
}

function algorithmOf(material: SshPublicMaterial): SshKeyAlgorithm {
	switch (material.kind) {
		case 'rsa':
			return { kind: 'rsa', modulusBits: bitLength(material.n) };
		case 'ecdsa':
			return { kind: 'ecdsa', curve: material.curve };
		case 'ed25519':
			return { kind: 'ed25519' };
		default:
			return unhandledKey(material);
	}
}

function toBase64Url(bytes: Uint8Array): string {
	return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(value: string): Uint8Array {
	const padded = value.replace(/-/g, '+').replace(/_/g, '/');
	return base64Decode(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
	let result = 1n;
	let factor = base % modulus;
	let remaining = exponent;
	while (remaining > 0n) {
		if ((remaining & 1n) === 1n) {
			result = (result * factor) % modulus;
		}
		factor = (factor * factor) % modulus;
		remaining >>= 1n;
	}
	return result;
}

function decompressPoint(curve: EcNamedCurve, prefix: number, x: Uint8Array): Uint8Array {
	const { prime, b, size } = CURVES[curve];
	const xValue = bytesToBigint(x);
	if (xValue >= prime) {
		return sshFail('malformed', 'ECDSA point coordinate is out of range');
	}
	const rhs = ((((xValue * xValue - 3n) * xValue + b) % prime) + prime) % prime;
	const root = modPow(rhs, (prime + 1n) / 4n, prime);
	if ((root * root) % prime !== rhs) {
		return sshFail('malformed', 'ECDSA point is not on the curve');
	}
	const wantOdd = prefix === 0x03;
	const y = ((root & 1n) === 1n) === wantOdd ? root : prime - root;
	return bigintToBytes(y, size);
}

function readPoint(
	curve: EcNamedCurve,
	point: Uint8Array,
	options: ResolvedImportOptions,
): { readonly x: Uint8Array; readonly y: Uint8Array } {
	const { size } = CURVES[curve];
	const prefix = point[0];
	if (prefix === 0x04 && point.length === 1 + 2 * size) {
		return { x: point.subarray(1, 1 + size), y: point.subarray(1 + size) };
	}
	if ((prefix === 0x02 || prefix === 0x03) && point.length === 1 + size) {
		if (!options.acceptCompressedEcPoints) {
			return sshFail('unsupported', 'Compressed ECDSA points need acceptCompressedEcPoints');
		}
		const x = point.subarray(1);
		return { x, y: decompressPoint(curve, prefix, x) };
	}
	return sshFail('malformed', 'ECDSA point encoding is invalid');
}

function readRsaPublic(
	reader: SshReader,
	order: 'e-n' | 'n-e',
	options: ResolvedImportOptions,
): Extract<SshPublicMaterial, { kind: 'rsa' }> {
	const first = reader.mpint(MAX_MPINT_BYTES);
	const second = reader.mpint(MAX_MPINT_BYTES);
	const [e, n] = order === 'e-n' ? [first, second] : [second, first];
	const bits = bitLength(n);
	if (bits > MAX_RSA_MODULUS_BITS) {
		return sshFail('limit_exceeded', `RSA modulus of ${bits} bits exceeds ${MAX_RSA_MODULUS_BITS}`);
	}
	if (bits < options.minRsaModulusBits) {
		return sshFail(
			'unsupported',
			`RSA modulus of ${bits} bits is below ${options.minRsaModulusBits}`,
		);
	}
	const exponent = bytesToBigint(e);
	if (exponent < 3n || (exponent & 1n) === 0n || exponent >= bytesToBigint(n)) {
		return sshFail('malformed', 'RSA public exponent is invalid');
	}
	return { kind: 'rsa', e, n };
}

function readEcdsaPublic(
	reader: SshReader,
	curve: EcNamedCurve,
	options: ResolvedImportOptions,
): Extract<SshPublicMaterial, { kind: 'ecdsa' }> {
	if (reader.name() !== CURVES[curve].identifier) {
		return sshFail('key_mismatch', 'ECDSA curve identifier disagrees with the key type');
	}
	const point = reader.string(MAX_STRING_BYTES);
	return { kind: 'ecdsa', curve, ...readPoint(curve, point, options) };
}

function readEd25519Public(reader: SshReader): Extract<SshPublicMaterial, { kind: 'ed25519' }> {
	const x = reader.string(MAX_STRING_BYTES);
	if (x.length !== ED25519_KEY_BYTES) {
		return sshFail('malformed', 'Ed25519 public key is not 32 bytes');
	}
	return { kind: 'ed25519', x };
}

function decodePublicBlob(blob: Uint8Array, options: ResolvedImportOptions): SshPublicMaterial {
	const reader = createSshReader(blob);
	const keyType = asSshKeyType(reader.name());
	if (keyType === undefined) {
		return sshFail('unsupported', 'Unsupported SSH key type');
	}
	let material: SshPublicMaterial;
	switch (keyType) {
		case 'ssh-rsa':
			material = readRsaPublic(reader, 'e-n', options);
			break;
		case 'ssh-ed25519':
			material = readEd25519Public(reader);
			break;
		case 'ecdsa-sha2-nistp256':
		case 'ecdsa-sha2-nistp384':
		case 'ecdsa-sha2-nistp521': {
			material = readEcdsaPublic(reader, ECDSA_KEY_TYPE_CURVES[keyType], options);
			break;
		}
		default:
			return unhandledKey(keyType);
	}
	if (reader.remaining() !== 0) {
		return sshFail('malformed', 'SSH public key has trailing data');
	}
	return material;
}

function ecPoint(material: Extract<SshPublicMaterial, { kind: 'ecdsa' }>): Uint8Array {
	return concatBytes([Uint8Array.of(0x04), material.x, material.y]);
}

function encodePublicBlob(material: SshPublicMaterial): Uint8Array {
	const type = sshTextString(keyTypeOf(material));
	switch (material.kind) {
		case 'rsa':
			return concatBytes([type, sshMpint(material.e), sshMpint(material.n)]);
		case 'ed25519':
			return concatBytes([type, sshString(material.x)]);
		case 'ecdsa':
			return concatBytes([
				type,
				sshTextString(CURVES[material.curve].identifier),
				sshString(ecPoint(material)),
			]);
		default:
			return unhandledKey(material);
	}
}

function samePublicMaterial(left: SshPublicMaterial, right: SshPublicMaterial): boolean {
	return bytesEqual(encodePublicBlob(left), encodePublicBlob(right));
}

function publicJwk(material: SshPublicMaterial): JsonWebKey {
	switch (material.kind) {
		case 'rsa':
			return { kty: 'RSA', n: toBase64Url(material.n), e: toBase64Url(material.e) };
		case 'ecdsa':
			return {
				kty: 'EC',
				crv: material.curve,
				x: toBase64Url(material.x),
				y: toBase64Url(material.y),
			};
		case 'ed25519':
			return { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(material.x) };
		default:
			return unhandledKey(material);
	}
}

function privateJwk(material: SshPrivateMaterial): JsonWebKey {
	switch (material.kind) {
		case 'rsa': {
			const d = bytesToBigint(material.d);
			const p = bytesToBigint(material.p);
			const q = bytesToBigint(material.q);
			return {
				...publicJwk(material.pub),
				d: toBase64Url(material.d),
				p: toBase64Url(material.p),
				q: toBase64Url(material.q),
				dp: toBase64Url(bigintToBytes(d % (p - 1n))),
				dq: toBase64Url(bigintToBytes(d % (q - 1n))),
				qi: toBase64Url(material.iqmp),
			};
		}
		case 'ecdsa':
			return {
				...publicJwk(material.pub),
				d: toBase64Url(bigintToBytes(bytesToBigint(material.d), CURVES[material.pub.curve].size)),
			};
		case 'ed25519':
			return { ...publicJwk(material.pub), d: toBase64Url(material.seed) };
		default:
			return unhandledKey(material);
	}
}

type WebCryptoImportInput = ImportRsaKeyInput | ImportEcKeyInput | ImportEd25519KeyInput;

function importInputFor(
	material: SshPublicMaterial,
	options: ResolvedImportOptions,
): WebCryptoImportInput {
	switch (material.kind) {
		case 'rsa':
			return { kind: 'rsa', scheme: options.rsaScheme, hash: options.rsaHash };
		case 'ecdsa':
			return { kind: 'ecdsa', curve: material.curve };
		case 'ed25519':
			return { kind: 'ed25519' };
		default:
			return unhandledKey(material);
	}
}

function signParams(
	material: SshPublicMaterial,
	options: ResolvedImportOptions,
): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
	switch (material.kind) {
		case 'rsa':
			return options.rsaScheme === 'pss'
				? { name: 'RSA-PSS', saltLength: 32 }
				: { name: 'RSASSA-PKCS1-v1_5' };
		case 'ecdsa':
			return { name: 'ECDSA', hash: CURVES[material.curve].hash };
		case 'ed25519':
			return { name: 'Ed25519' };
		default:
			return unhandledKey(material);
	}
}

async function importPublicMaterial(
	material: SshPublicMaterial,
	options: ResolvedImportOptions,
): Promise<CryptoKey> {
	return await importPublicJwkOrThrow(publicJwk(material), importInputFor(material, options));
}

async function importPrivateMaterial(
	material: SshPrivateMaterial,
	envelope: SshPublicMaterial,
	options: ResolvedImportOptions,
): Promise<CryptoKey> {
	try {
		return await importPrivateJwkOrThrow(privateJwk(material), importInputFor(envelope, options));
	} catch (error) {
		rethrowIfInvariant(error);
		return sshFail('key_mismatch', 'Private key material is invalid for the embedded public key');
	}
}

async function assertKeyPairConsistent(
	privateKey: CryptoKey,
	publicKey: CryptoKey,
	material: SshPublicMaterial,
	options: ResolvedImportOptions,
): Promise<void> {
	const { subtle } = getCrypto();
	const challenge = getCrypto().getRandomValues(new Uint8Array(32));
	const params = signParams(material, options);
	const signature = await subtle.sign(params, privateKey, challenge);
	if (!(await subtle.verify(params, publicKey, signature, challenge))) {
		sshFail('key_mismatch', 'Private key does not match the embedded public key');
	}
}

async function sha256Fingerprint(blob: Uint8Array): Promise<string> {
	const digest = new Uint8Array(await getCrypto().subtle.digest('SHA-256', toArrayBuffer(blob)));
	return `SHA256:${base64Encode(digest).replace(/=+$/, '')}`;
}

function textOf(input: string | Uint8Array, maxBytes: number): string {
	if (typeof input === 'string') {
		if (input.length > maxBytes) {
			return sshFail('limit_exceeded', `SSH key input exceeds ${maxBytes} bytes`);
		}
		const bytes = new TextEncoder().encode(input);
		if (bytes.length > maxBytes) {
			return sshFail('limit_exceeded', `SSH key input exceeds ${maxBytes} bytes`);
		}
		return input;
	}
	if (input.length > maxBytes) {
		return sshFail('limit_exceeded', `SSH key input exceeds ${maxBytes} bytes`);
	}
	return decodeUtf8(input);
}

const PUBLIC_KEY_LINE = /^([^ \t]+)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+(.*))?$/;

async function decodePublicKeyLine(
	input: string | Uint8Array,
	options: ResolvedImportOptions,
): Promise<ImportedSshPublicKey> {
	const text = textOf(input, MAX_PUBLIC_KEY_LINE_BYTES).replace(/\r?\n$/, '');
	if (/[\r\n]/.test(text)) {
		return sshFail('malformed', 'SSH public key must be a single line');
	}
	const match = PUBLIC_KEY_LINE.exec(text);
	if (match === null) {
		return sshFail('malformed', 'SSH public key line is not "<type> <base64> [comment]"');
	}
	const [, typeToken = '', encoded = '', comment = ''] = match;
	assertImportedComment(comment);
	const keyType = asSshKeyType(typeToken);
	if (keyType === undefined) {
		return sshFail('unsupported', 'Unsupported SSH key type');
	}
	const blob = base64Decode(encoded);
	const material = decodePublicBlob(blob, options);
	if (keyTypeOf(material) !== keyType) {
		return sshFail('key_mismatch', 'Line key type disagrees with the key blob');
	}
	return {
		keyType,
		algorithm: algorithmOf(material),
		publicKey: await importPublicMaterial(material, options),
		comment,
		fingerprint: await sha256Fingerprint(encodePublicBlob(material)),
	};
}

function readPrivateMaterial(
	reader: SshReader,
	envelopeType: SshKeyType,
	options: ResolvedImportOptions,
): SshPrivateMaterial {
	const declared = reader.name();
	if (declared !== envelopeType) {
		return sshFail('key_mismatch', 'Private section key type disagrees with the public key');
	}
	switch (envelopeType) {
		case 'ssh-rsa': {
			const pub = readRsaPublic(reader, 'n-e', options);
			const d = reader.mpint(MAX_MPINT_BYTES);
			const iqmp = reader.mpint(MAX_MPINT_BYTES);
			const p = reader.mpint(MAX_MPINT_BYTES);
			const q = reader.mpint(MAX_MPINT_BYTES);
			return { kind: 'rsa', pub, d, iqmp, p, q };
		}
		case 'ssh-ed25519': {
			const pub = readEd25519Public(reader);
			const secret = reader.string(MAX_STRING_BYTES);
			if (secret.length !== 2 * ED25519_KEY_BYTES) {
				return sshFail('malformed', 'Ed25519 private key is not 64 bytes');
			}
			if (!bytesEqual(secret.subarray(ED25519_KEY_BYTES), pub.x)) {
				return sshFail('key_mismatch', 'Ed25519 private key suffix differs from the public key');
			}
			return { kind: 'ed25519', pub, seed: secret.subarray(0, ED25519_KEY_BYTES) };
		}
		case 'ecdsa-sha2-nistp256':
		case 'ecdsa-sha2-nistp384':
		case 'ecdsa-sha2-nistp521': {
			const pub = readEcdsaPublic(reader, ECDSA_KEY_TYPE_CURVES[envelopeType], options);
			const d = reader.mpint(MAX_MPINT_BYTES);
			if (d.length > CURVES[pub.curve].size) {
				return sshFail('malformed', 'ECDSA private scalar is larger than the curve order');
			}
			return { kind: 'ecdsa', pub, d };
		}
		default:
			return unhandledKey(envelopeType);
	}
}

function assertRsaConsistent(material: Extract<SshPrivateMaterial, { kind: 'rsa' }>): void {
	const n = bytesToBigint(material.pub.n);
	const e = bytesToBigint(material.pub.e);
	const d = bytesToBigint(material.d);
	const p = bytesToBigint(material.p);
	const q = bytesToBigint(material.q);
	const iqmp = bytesToBigint(material.iqmp);
	if (p < 3n || q < 3n || p * q !== n) {
		sshFail('key_mismatch', 'RSA primes do not multiply to the modulus');
	}
	if (d >= n || (d * e) % (p - 1n) !== 1n || (d * e) % (q - 1n) !== 1n) {
		sshFail('key_mismatch', 'RSA private exponent does not match the public exponent');
	}
	if (iqmp >= p || (iqmp * q) % p !== 1n) {
		sshFail('key_mismatch', 'RSA coefficient is not the inverse of q modulo p');
	}
}

function assertPadding(reader: SshReader): void {
	const padding = reader.raw(reader.remaining());
	if (padding.length >= NO_CIPHER_BLOCK_SIZE) {
		sshFail('malformed', 'OpenSSH private key padding is too long');
	}
	padding.forEach((byte, index) => {
		if (byte !== index + 1) {
			sshFail('malformed', 'OpenSSH private key padding is invalid');
		}
	});
}

async function decodePrivateKey(
	input: string | Uint8Array,
	options: ResolvedImportOptions,
): Promise<ImportedOpenSshPrivateKey> {
	const text = textOf(input, MAX_PRIVATE_KEY_FILE_BYTES);
	const binary = pemDecodeOrThrow(PRIVATE_KEY_LABEL, text);
	try {
		return await decodePrivateBinary(binary, options);
	} finally {
		binary.fill(0);
	}
}

async function decodePrivateBinary(
	binary: Uint8Array,
	options: ResolvedImportOptions,
): Promise<ImportedOpenSshPrivateKey> {
	const reader = createSshReader(binary);
	const magic = reader.raw(AUTH_MAGIC.length + 1);
	if (
		!bytesEqual(magic.subarray(0, AUTH_MAGIC.length), AUTH_MAGIC) ||
		magic[AUTH_MAGIC.length] !== 0
	) {
		return sshFail('malformed', 'Missing openssh-key-v1 magic');
	}
	const cipher = reader.name();
	const kdf = reader.name();
	if (cipher !== 'none' || kdf !== 'none') {
		return sshFail('unsupported', 'Encrypted OpenSSH private keys are not supported');
	}
	if (reader.string(MAX_STRING_BYTES).length !== 0) {
		return sshFail('malformed', 'KDF options must be empty for kdf none');
	}
	const keyCount = reader.uint32();
	if (keyCount === 0) {
		return sshFail('malformed', 'OpenSSH private key file holds no keys');
	}
	if (keyCount > 1) {
		return sshFail('unsupported', 'OpenSSH private key files with several keys are not supported');
	}
	const publicBlob = reader.string(MAX_STRING_BYTES);
	const envelope = decodePublicBlob(publicBlob, options);
	const section = reader.string(MAX_PRIVATE_KEY_FILE_BYTES);
	if (reader.remaining() !== 0) {
		return sshFail('malformed', 'OpenSSH private key file has trailing data');
	}
	if (section.length === 0 || section.length % NO_CIPHER_BLOCK_SIZE !== 0) {
		return sshFail('malformed', 'OpenSSH private section is not a multiple of the block size');
	}
	const inner = createSshReader(section);
	const firstCheck = inner.uint32();
	const secondCheck = inner.uint32();
	if (firstCheck !== secondCheck) {
		return sshFail('malformed', 'OpenSSH check integers differ');
	}
	const privateMaterial = readPrivateMaterial(inner, keyTypeOf(envelope), options);
	const comment = inner.text(MAX_STRING_BYTES);
	assertImportedComment(comment);
	assertPadding(inner);
	if (!samePublicMaterial(envelope, privateMaterial.pub)) {
		return sshFail('key_mismatch', 'Private section public key differs from the file public key');
	}
	if (privateMaterial.kind === 'rsa') {
		assertRsaConsistent(privateMaterial);
	}
	const publicKey = await importPublicMaterial(envelope, options);
	const privateKey = await importPrivateMaterial(privateMaterial, envelope, options);
	await assertKeyPairConsistent(privateKey, publicKey, envelope, options);
	return {
		keyType: keyTypeOf(envelope),
		algorithm: algorithmOf(envelope),
		publicKey,
		privateKey,
		comment,
		fingerprint: await sha256Fingerprint(encodePublicBlob(envelope)),
	};
}

async function toSshResult<T>(run: () => Promise<T>): Promise<SshResult<T>> {
	try {
		return successResult(await run());
	} catch (error) {
		if (isResultError(error)) {
			const code = asSshErrorCode(error.code);
			if (code !== undefined) {
				return failureResult<SshErrorCode>(code, error.error.message);
			}
		}
		rethrowIfInvariant(error);
		return failureResult<SshErrorCode>(
			'malformed',
			error instanceof Error ? error.message : 'Malformed SSH key',
		);
	}
}

/**
 * Import an OpenSSH public-key line (`<type> <base64> [comment]`).
 *
 * Reads `ssh-rsa`, `ssh-ed25519`, and `ecdsa-sha2-nistp256/384/521` keys as
 * written by `ssh-keygen` into `.pub` files. The line key type must equal the
 * type inside the blob (RFC 4253 §6.6), an ECDSA curve identifier must equal
 * its key type suffix (RFC 5656 §3.1), and trailing data after the blob is
 * rejected. Fields are separated by spaces or tabs, one trailing line break
 * is allowed, and everything after the base64 field is the comment.
 * `authorized_keys` options and SSH certificate types are not read.
 *
 * Input is capped at 16 KiB and RSA moduli at 16384 bits. `input` is never
 * modified.
 *
 * @param input - The line as text or UTF-8 bytes
 * @param options - Policy options; see {@linkcode SshImportOptions}
 * @returns The WebCrypto verification key, its comment and its SHA-256 fingerprint
 *
 * @see {@linkcode importSshPublicKeyOrThrow} for the throwing variant
 * @see {@linkcode exportSshPublicKey} for the inverse operation
 */
export function importSshPublicKey(
	input: string | Uint8Array,
	options: SshImportOptions = {},
): Promise<SshResult<ImportedSshPublicKey>> {
	return toSshResult(() => decodePublicKeyLine(input, resolveImportOptions(options)));
}

/**
 * Throwing variant of {@linkcode importSshPublicKey}.
 *
 * @throws {ResultError} Carrying an {@linkcode SshErrorCode} as `code`
 */
export async function importSshPublicKeyOrThrow(
	input: string | Uint8Array,
	options: SshImportOptions = {},
): Promise<ImportedSshPublicKey> {
	return unwrap(await importSshPublicKey(input, options));
}

/**
 * Import an unencrypted single-key `openssh-key-v1` private key file.
 *
 * Accepts the `-----BEGIN OPENSSH PRIVATE KEY-----` PEM that `ssh-keygen`
 * writes for RSA, Ed25519 and ECDSA P-256/P-384/P-521 keys. The cipher and
 * KDF must both be `none` with empty KDF options; any other value returns
 * `unsupported`, as does a file holding several keys. The check integers,
 * the `1, 2, 3, ...` padding, the block alignment, and the absence of trailing
 * bytes are verified, and RSA integers must be canonical positive `mpint`s.
 *
 * The public key embedded in the file must equal the public half of the
 * private section and its key type, or the result is `key_mismatch`. The
 * private material is then checked cryptographically: for RSA, `p·q = n`,
 * `d·e ≡ 1` modulo both `p-1` and `q-1`, and `iqmp·q ≡ 1 (mod p)`; for every
 * key, a signature made with the private key must verify under the embedded
 * public key. For Ed25519 the 32-byte suffix of the private field must equal
 * the public key.
 *
 * Both keys are returned extractable. The decoded binary copy of the file is
 * zeroed before returning. JavaScript strings, including the PEM text and the
 * JWK members used for the import, cannot be zeroed, and `input` is never
 * modified.
 *
 * @param input - The PEM file as text or UTF-8 bytes, at most 32 KiB
 * @param options - Policy options; see {@linkcode SshImportOptions}
 *
 * @see {@linkcode importOpenSshPrivateKeyOrThrow} for the throwing variant
 * @see {@linkcode exportOpenSshPrivateKey} for the inverse operation
 */
export function importOpenSshPrivateKey(
	input: string | Uint8Array,
	options: SshImportOptions = {},
): Promise<SshResult<ImportedOpenSshPrivateKey>> {
	return toSshResult(() => decodePrivateKey(input, resolveImportOptions(options)));
}

/**
 * Throwing variant of {@linkcode importOpenSshPrivateKey}.
 *
 * @throws {ResultError} Carrying an {@linkcode SshErrorCode} as `code`
 */
export async function importOpenSshPrivateKeyOrThrow(
	input: string | Uint8Array,
	options: SshImportOptions = {},
): Promise<ImportedOpenSshPrivateKey> {
	return unwrap(await importOpenSshPrivateKey(input, options));
}

function exportFail(code: SshExportErrorCode, message: string): never {
	return throwMicro509Error<SshExportErrorCode>(code, message);
}

function validCommentText(comment: string): boolean {
	return typeof comment === 'string' && comment.isWellFormed() && !/[\r\n\0]/.test(comment);
}

function oversizedComment(comment: string): boolean {
	return (
		comment.length > MAX_STRING_BYTES || new TextEncoder().encode(comment).length > MAX_STRING_BYTES
	);
}

function assertImportedComment(comment: string): void {
	if (!validCommentText(comment)) {
		sshFail('malformed', 'Comment must be well-formed Unicode without CR, LF or NUL');
	}
	if (oversizedComment(comment)) {
		sshFail('limit_exceeded', 'Comment exceeds 8192 UTF-8 bytes');
	}
}

function assertComment(comment: string): void {
	if (!validCommentText(comment) || oversizedComment(comment)) {
		exportFail(
			'invalid_comment',
			'Comment must be well-formed Unicode without CR, LF or NUL and at most 8192 UTF-8 bytes',
		);
	}
}

function assertExportable(key: CryptoKey, type: KeyType): void {
	if (key.type !== type) {
		exportFail('invalid_key', `Expected a ${type} key`);
	}
	if (!key.extractable) {
		exportFail('not_extractable', 'The key must be extractable');
	}
}

function jwkBytes(
	jwk: JsonWebKey,
	member: 'n' | 'e' | 'd' | 'p' | 'q' | 'qi' | 'x' | 'y',
): Uint8Array {
	const value = jwk[member];
	if (typeof value !== 'string') {
		throw new Error(`WebCrypto key export lacks JWK member ${member}`);
	}
	return fromBase64Url(value);
}

function publicMaterialFromJwk(jwk: JsonWebKey, algorithmName: string): SshPublicMaterial {
	if (jwk.kty === 'RSA') {
		return { kind: 'rsa', e: jwkBytes(jwk, 'e'), n: jwkBytes(jwk, 'n') };
	}
	if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && algorithmName === 'Ed25519') {
		return { kind: 'ed25519', x: jwkBytes(jwk, 'x') };
	}
	if (jwk.kty === 'EC' && algorithmName === 'ECDSA') {
		const curve = CURVE_NAMES.find((name) => name === jwk.crv);
		if (curve !== undefined) {
			return { kind: 'ecdsa', curve, x: jwkBytes(jwk, 'x'), y: jwkBytes(jwk, 'y') };
		}
	}
	return exportFail(
		'unsupported_algorithm',
		'Only RSA, ECDSA P-256/384/521 and Ed25519 are supported',
	);
}

/**
 * Export a public key as an OpenSSH public-key line.
 *
 * Writes `<type> <base64> [comment]` with padded base64 and no trailing line
 * break, the form `ssh-keygen` puts in `.pub` files. ECDSA points are written
 * uncompressed. The key must be an extractable RSA, ECDSA (P-256, P-384,
 * P-521) or Ed25519 public `CryptoKey`.
 *
 * @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} as `code`
 *
 * @see {@linkcode importSshPublicKey} for the inverse operation
 */
export async function exportSshPublicKey(
	publicKey: CryptoKey,
	options: SshExportOptions = {},
): Promise<string> {
	const comment = options.comment === undefined ? '' : options.comment;
	assertComment(comment);
	assertExportable(publicKey, 'public');
	const material = publicMaterialFromJwk(
		await exportPublicJwk(publicKey),
		publicKey.algorithm.name,
	);
	const line = `${keyTypeOf(material)} ${base64Encode(encodePublicBlob(material))}`;
	return comment === '' ? line : `${line} ${comment}`;
}

/**
 * Export a private key as an unencrypted `openssh-key-v1` PEM file.
 *
 * The file holds one key, cipher `none` and KDF `none`, with the check
 * integers drawn from the WebCrypto random source and the public key derived
 * from the private key. `ssh-keygen` reads it directly. Check integers are
 * random, so compare keys, not file bytes, between two exports.
 *
 * The private `CryptoKey` must be extractable. The binary encoding is zeroed
 * after the PEM text is built; the returned string and the JWK used for the
 * export cannot be zeroed.
 *
 * @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} as `code`
 *
 * @see {@linkcode importOpenSshPrivateKey} for the inverse operation
 */
export async function exportOpenSshPrivateKey(
	privateKey: CryptoKey,
	options: SshExportOptions = {},
): Promise<string> {
	const comment = options.comment === undefined ? '' : options.comment;
	assertComment(comment);
	assertExportable(privateKey, 'private');
	const jwk = await exportPrivateJwk(privateKey);
	const material = publicMaterialFromJwk(jwk, privateKey.algorithm.name);
	const fields = privateFields(material, jwk);
	const checkInt = getCrypto().getRandomValues(new Uint32Array(1))[0] ?? 0;
	const unpadded = concatBytes([
		sshUint32(checkInt),
		sshUint32(checkInt),
		sshTextString(keyTypeOf(material)),
		fields,
		sshTextString(comment),
	]);
	const paddingLength =
		(NO_CIPHER_BLOCK_SIZE - (unpadded.length % NO_CIPHER_BLOCK_SIZE)) % NO_CIPHER_BLOCK_SIZE;
	const section = concatBytes([
		unpadded,
		Uint8Array.from({ length: paddingLength }, (_, index) => index + 1),
	]);
	const file = concatBytes([
		AUTH_MAGIC,
		Uint8Array.of(0),
		sshTextString('none'),
		sshTextString('none'),
		sshUint32(0),
		sshUint32(1),
		sshString(encodePublicBlob(material)),
		sshString(section),
	]);
	try {
		return pemEncode(PRIVATE_KEY_LABEL, file);
	} finally {
		unpadded.fill(0);
		section.fill(0);
		file.fill(0);
		fields.fill(0);
	}
}

function privateFields(material: SshPublicMaterial, jwk: JsonWebKey): Uint8Array {
	switch (material.kind) {
		case 'rsa':
			return concatBytes([
				sshMpint(material.n),
				sshMpint(material.e),
				sshMpint(jwkBytes(jwk, 'd')),
				sshMpint(jwkBytes(jwk, 'qi')),
				sshMpint(jwkBytes(jwk, 'p')),
				sshMpint(jwkBytes(jwk, 'q')),
			]);
		case 'ecdsa':
			return concatBytes([
				sshTextString(CURVES[material.curve].identifier),
				sshString(ecPoint(material)),
				sshMpint(jwkBytes(jwk, 'd')),
			]);
		case 'ed25519':
			return concatBytes([
				sshString(material.x),
				sshString(concatBytes([jwkBytes(jwk, 'd'), material.x])),
			]);
		default:
			return unhandledKey(material);
	}
}

/**
 * The `SHA256:` fingerprint `ssh-keygen -l -E sha256` prints for a key.
 *
 * It is the SHA-256 digest of the SSH public-key blob (RFC 4253 §6.6 layout),
 * base64-encoded without padding and prefixed with `SHA256:`. It differs from a
 * certificate fingerprint and from a digest of the SPKI encoding. Pass a
 * public or private `CryptoKey`, or the raw blob bytes (the decoded base64
 * field of a public-key line). A private key must be extractable.
 *
 * @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} when a `CryptoKey` cannot be encoded
 */
export async function sshFingerprintSha256(key: CryptoKey | Uint8Array): Promise<string> {
	if (key instanceof Uint8Array) {
		return await sha256Fingerprint(key);
	}
	if (key.type === 'secret') {
		exportFail('invalid_key', 'Expected a public or private key');
	}
	assertExportable(key, key.type);
	const jwk = key.type === 'private' ? await exportPrivateJwk(key) : await exportPublicJwk(key);
	const material = publicMaterialFromJwk(jwk, key.algorithm.name);
	return await sha256Fingerprint(encodePublicBlob(material));
}
