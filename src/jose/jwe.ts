/** Compact JWE: RSA-OAEP-512 key management and A256GCM content encryption. @module */

import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import { base64UrlDecode, base64UrlEncode } from '#micro509/internal/jose/base64url';
import { snapshotJsonData } from '#micro509/internal/jose/json-data';
import type { JsonObject } from '#micro509/internal/jose/strict-json';
import { isJsonArray, isJsonObject } from '#micro509/internal/jose/strict-json';
import type { JoseResult, JweErrorCode } from '#micro509/jose/errors';
import { joseFailure } from '#micro509/jose/errors';
import type { JoseLimits } from '#micro509/jose/jws';
import { decodeJsonObject, resolveJoseLimits, validRsaPublicExponent } from '#micro509/jose/jws';
import { rethrowIfInvariant, successResult } from '#micro509/result/result';

/** Implemented key-management algorithm; SHA-512 and MGF1-SHA-512 with empty OAEP label. */
export type JweAlgorithm = 'RSA-OAEP-512';
/** Implemented content encryption: 256-bit AES-GCM, 96-bit IV, 128-bit tag. */
export type JweEncryption = 'A256GCM';

/** A compact JWE protected header, with every noncritical member retained. */
export interface JweHeader {
	/** Key-management algorithm. */
	readonly alg: string;
	/** Content-encryption algorithm. */
	readonly enc: string;
	/** All protected members. No unprotected header exists in this serialization. */
	readonly members: JsonObject;
}

/** Input to {@linkcode encryptCompactJwe}. */
export interface EncryptJweInput {
	/** An RSA-OAEP/SHA-512 public key with `encrypt` usage, 2048–8192 bits. */
	readonly publicKey: CryptoKey;
	/** Payload bytes; text encoding is the caller's decision. */
	readonly plaintext: Uint8Array;
	/** Explicit key-management algorithm. */
	readonly algorithm: JweAlgorithm;
	/** Explicit content-encryption algorithm. */
	readonly encryption: JweEncryption;
	/** Additional protected JSON data. `alg` and `enc`, if supplied, must agree. No default `typ`. */
	readonly header?: JsonObject;
	/** Existing JOSE bounds; `maxPayloadBytes` also bounds plaintext/ciphertext and `maxSignatureBytes` bounds the encrypted CEK. */
	readonly limits?: Partial<JoseLimits>;
}

/** Input policy for {@linkcode decryptCompactJwe}; neither allowlist is inferred from the token. */
export interface DecryptJweOptions {
	/** An RSA-OAEP/SHA-512 private key with `decrypt` usage, 2048–8192 bits. */
	readonly privateKey: CryptoKey;
	/** Accepted key-management algorithms for this application. */
	readonly keyManagementAlgorithms: readonly [JweAlgorithm, ...JweAlgorithm[]];
	/** Accepted content-encryption algorithms for this application. */
	readonly contentEncryptionAlgorithms: readonly [JweEncryption, ...JweEncryption[]];
	/** Bounds with the same meaning as {@linkcode EncryptJweInput.limits}. */
	readonly limits?: Partial<JoseLimits>;
}

/** Authenticated plaintext. Encryption does not establish sender identity: anyone with the public key can encrypt. */
export interface DecryptedJwe {
	/** GCM authentication succeeded under the supplied key. */
	readonly authenticated: true;
	/** Plaintext bytes; never an implicit JSON or nested JWT decode. */
	readonly plaintext: Uint8Array;
	/** Authenticated protected header. */
	readonly header: JweHeader;
}

const CEK_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

function checkKey(
	key: CryptoKey,
	type: 'public' | 'private',
): JoseResult<number, 'key_unsuitable'> {
	if (
		!(key instanceof CryptoKey) ||
		key.type !== type ||
		key.algorithm.name !== 'RSA-OAEP' ||
		!key.usages.includes(type === 'public' ? 'encrypt' : 'decrypt')
	) {
		return joseFailure(
			'key_unsuitable',
			'JWE requires an RSA-OAEP key with the correct type and usage',
		);
	}
	const algorithm = key.algorithm;
	if (
		!('hash' in algorithm) ||
		typeof algorithm.hash !== 'object' ||
		algorithm.hash === null ||
		!('name' in algorithm.hash) ||
		algorithm.hash.name !== 'SHA-512'
	) {
		return joseFailure('key_unsuitable', 'JWE RSA-OAEP-512 requires SHA-512');
	}
	if (
		!('modulusLength' in algorithm) ||
		typeof algorithm.modulusLength !== 'number' ||
		!Number.isSafeInteger(algorithm.modulusLength) ||
		algorithm.modulusLength < 2048 ||
		algorithm.modulusLength > 8192 ||
		!('publicExponent' in algorithm) ||
		!(algorithm.publicExponent instanceof Uint8Array) ||
		!validRsaPublicExponent(algorithm.publicExponent)
	) {
		return joseFailure(
			'key_unsuitable',
			'JWE RSA keys require a 2048–8192 bit modulus and a suitable exponent',
		);
	}
	return successResult(Math.ceil(algorithm.modulusLength / 8));
}

function checkCritical(members: JsonObject): JoseResult<undefined, JweErrorCode> {
	if (!Object.hasOwn(members, 'crit')) return successResult(undefined);
	const names = members.crit;
	if (!isJsonArray(names) || names.length === 0)
		return joseFailure('invalid_header', 'JWE crit must be a nonempty array');
	const seen = new Set<string>();
	for (const name of names) {
		if (
			typeof name !== 'string' ||
			name.length === 0 ||
			seen.has(name) ||
			!Object.hasOwn(members, name)
		)
			return joseFailure('invalid_header', 'JWE crit has a repeated, absent or invalid member');
		seen.add(name);
	}
	return joseFailure('unsupported_critical_header', 'JWE critical extensions are not supported');
}

function headerFromMembers(members: JsonObject): JoseResult<JweHeader, JweErrorCode> {
	if (
		typeof members.alg !== 'string' ||
		members.alg.length === 0 ||
		typeof members.enc !== 'string' ||
		members.enc.length === 0
	)
		return joseFailure('invalid_header', 'JWE requires string alg and enc');
	for (const name of ['typ', 'cty', 'kid']) {
		if (Object.hasOwn(members, name) && typeof members[name] !== 'string')
			return joseFailure('invalid_header', `JWE ${name} must be a string`);
	}
	const critical = checkCritical(members);
	if (!critical.ok) return critical;
	if (Object.hasOwn(members, 'zip'))
		return joseFailure('unsupported_compression', 'JWE compression is not supported');
	return successResult({ alg: members.alg, enc: members.enc, members });
}

function encryptionHeader(
	input: EncryptJweInput,
	limits: JoseLimits,
): JoseResult<string, JweErrorCode> {
	if (input.algorithm !== 'RSA-OAEP-512')
		return joseFailure('algorithm_not_allowed', 'Unsupported JWE key-management algorithm');
	if (input.encryption !== 'A256GCM')
		return joseFailure('encryption_not_allowed', 'Unsupported JWE content-encryption algorithm');
	const snapshot = snapshotJsonData(input.header === undefined ? {} : input.header, {
		maxBytes: limits.maxHeaderBytes,
		maxDepth: limits.maxJsonDepth,
		maxNodes: limits.maxJsonNodes,
	});
	if (!snapshot.ok) return joseFailure(snapshot.code, 'JWE header must be bounded plain JSON data');
	if (!isJsonObject(snapshot.value))
		return joseFailure('invalid_header', 'JWE header must be an object');
	const source = snapshot.value;
	if (
		(Object.hasOwn(source, 'alg') && source.alg !== input.algorithm) ||
		(Object.hasOwn(source, 'enc') && source.enc !== input.encryption)
	)
		return joseFailure('invalid_header', 'JWE header conflicts with the requested algorithms');
	const members = { ...source, alg: input.algorithm, enc: input.encryption };
	const completed = snapshotJsonData(members, {
		maxBytes: limits.maxHeaderBytes,
		maxDepth: limits.maxJsonDepth,
		maxNodes: limits.maxJsonNodes,
	});
	if (!completed.ok)
		return joseFailure(completed.code, 'JWE completed header exceeds its JSON bounds');
	const header = headerFromMembers(members);
	if (!header.ok) return header;
	const bytes = new TextEncoder().encode(JSON.stringify(members));
	if (bytes.length > limits.maxHeaderBytes)
		return joseFailure('limit_exceeded', 'JWE header exceeds maxHeaderBytes');
	return successResult(base64UrlEncode(bytes));
}

function encodedLength(length: number): number {
	return Math.ceil((length * 4) / 3);
}

/**
 * Encrypts one compact JWE for the limited RSA-OAEP-512/A256GCM profile (RFC 7516 §5.1).
 * Generates a fresh 32-byte CEK and 12-byte IV; no externally supplied IV, compression or external AAD.
 * The protected header's ORIGINAL base64url segment is the ASCII AAD (RFC 7516 §5.1 step 14).
 */
export async function encryptCompactJwe(
	input: EncryptJweInput,
): Promise<JoseResult<string, JweErrorCode>> {
	if (typeof input !== 'object' || input === null || !(input.plaintext instanceof Uint8Array))
		return joseFailure('invalid_options', 'JWE input requires plaintext bytes');
	const limits = resolveJoseLimits(input.limits);
	if (!limits.ok) return limits;
	if (input.plaintext.length > limits.value.maxPayloadBytes)
		return joseFailure('limit_exceeded', 'JWE plaintext exceeds maxPayloadBytes');
	const header = encryptionHeader(input, limits.value);
	if (!header.ok) return header;
	const key = checkKey(input.publicKey, 'public');
	if (!key.ok) return key;
	if (key.value > limits.value.maxSignatureBytes)
		return joseFailure('limit_exceeded', 'JWE encrypted key exceeds maxSignatureBytes');
	if (
		header.value.length +
			encodedLength(key.value) +
			encodedLength(IV_BYTES) +
			encodedLength(input.plaintext.length) +
			encodedLength(TAG_BYTES) +
			4 >
		limits.value.maxTokenLength
	)
		return joseFailure('token_too_large', 'JWE exceeds maxTokenLength');
	const plaintext = new Uint8Array(input.plaintext);
	const crypto = getCrypto();
	const cek = crypto.getRandomValues(new Uint8Array(CEK_BYTES));
	const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
	try {
		const encryptedKey = new Uint8Array(
			await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, input.publicKey, cek),
		);
		const aes = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
		const encrypted = new Uint8Array(
			await crypto.subtle.encrypt(
				{
					name: 'AES-GCM',
					iv,
					additionalData: new TextEncoder().encode(header.value),
					tagLength: 128,
				},
				aes,
				plaintext,
			),
		);
		return successResult(
			[
				header.value,
				base64UrlEncode(encryptedKey),
				base64UrlEncode(iv),
				base64UrlEncode(encrypted.subarray(0, encrypted.length - TAG_BYTES)),
				base64UrlEncode(encrypted.subarray(encrypted.length - TAG_BYTES)),
			].join('.'),
		);
	} catch (error) {
		rethrowIfInvariant(error);
		return joseFailure('encryption_failed', 'JWE encryption failed');
	} finally {
		cek.fill(0);
		plaintext.fill(0);
	}
}

interface ParsedJwe {
	readonly header: JweHeader;
	readonly aad: Uint8Array;
	readonly encryptedKey: Uint8Array;
	readonly iv: Uint8Array;
	readonly ciphertext: Uint8Array;
	readonly tag: Uint8Array;
}

function decodeSegment(segment: string, maxBytes: number): JoseResult<Uint8Array, JweErrorCode> {
	if (segment.length > encodedLength(maxBytes))
		return joseFailure('limit_exceeded', 'JWE segment exceeds its byte limit');
	const decoded = base64UrlDecode(segment);
	if (decoded === undefined)
		return joseFailure('invalid_encoding', 'JWE segment is not canonical base64url');
	if (decoded.length > maxBytes)
		return joseFailure('limit_exceeded', 'JWE segment exceeds its byte limit');
	return successResult(decoded);
}
function parse(token: string, limits: JoseLimits): JoseResult<ParsedJwe, JweErrorCode> {
	if (typeof token !== 'string') return joseFailure('malformed_token', 'JWE must be a string');
	if (token.length > limits.maxTokenLength)
		return joseFailure('token_too_large', 'JWE exceeds maxTokenLength');
	const segments = token.split('.');
	const [protectedSegment, encryptedKeySegment, ivSegment, ciphertextSegment, tagSegment] =
		segments;
	if (
		segments.length !== 5 ||
		!protectedSegment ||
		encryptedKeySegment === undefined ||
		!ivSegment ||
		ciphertextSegment === undefined ||
		!tagSegment
	)
		return joseFailure('malformed_token', 'JWE requires five compact segments');
	const protectedBytes = decodeSegment(protectedSegment, limits.maxHeaderBytes);
	if (!protectedBytes.ok) return protectedBytes;
	const object = decodeJsonObject(protectedBytes.value, limits, 'header', 'invalid_header', 'JWE');
	if (!object.ok) return object;
	const header = headerFromMembers(object.value);
	if (!header.ok) return header;
	const encryptedKey = decodeSegment(encryptedKeySegment, limits.maxSignatureBytes);
	if (!encryptedKey.ok) return encryptedKey;
	const iv = decodeSegment(ivSegment, IV_BYTES);
	if (!iv.ok) return iv;
	const ciphertext = decodeSegment(ciphertextSegment, limits.maxPayloadBytes);
	if (!ciphertext.ok) return ciphertext;
	const tag = decodeSegment(tagSegment, TAG_BYTES);
	if (!tag.ok) return tag;
	if (iv.value.length !== IV_BYTES || tag.value.length !== TAG_BYTES)
		return joseFailure('malformed_token', 'JWE requires a 12-byte IV and 16-byte tag');
	return successResult({
		header: header.value,
		aad: new TextEncoder().encode(protectedSegment),
		encryptedKey: encryptedKey.value,
		iv: iv.value,
		ciphertext: ciphertext.value,
		tag: tag.value,
	});
}
function decryptionFailure(): JoseResult<never, 'decryption_failed'> {
	return joseFailure('decryption_failed', 'JWE decryption failed');
}

/** Uniform CEK/tag refusal, with dummy CEK on unwrap failure (RFC 7516 §11.5). */
async function decryptPayload(
	parsed: ParsedJwe,
	key: CryptoKey,
	encryptedKeyBytes: number,
): Promise<JoseResult<DecryptedJwe, JweErrorCode>> {
	const crypto = getCrypto();
	let cek = crypto.getRandomValues(new Uint8Array(CEK_BYTES));
	let unwrapFailed = parsed.encryptedKey.length !== encryptedKeyBytes;
	try {
		if (!unwrapFailed) {
			try {
				const candidate = new Uint8Array(
					await crypto.subtle.decrypt(
						{ name: 'RSA-OAEP' },
						key,
						new Uint8Array(parsed.encryptedKey),
					),
				);
				if (candidate.length !== CEK_BYTES) {
					candidate.fill(0);
					unwrapFailed = true;
				} else {
					cek.fill(0);
					cek = candidate;
				}
			} catch (error) {
				rethrowIfInvariant(error);
				unwrapFailed = true;
			}
		}
		const aes = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt']);
		const ciphertextAndTag = new Uint8Array(parsed.ciphertext.length + TAG_BYTES);
		ciphertextAndTag.set(parsed.ciphertext);
		ciphertextAndTag.set(parsed.tag, parsed.ciphertext.length);
		const plaintext = new Uint8Array(
			await crypto.subtle.decrypt(
				{
					name: 'AES-GCM',
					iv: new Uint8Array(parsed.iv),
					additionalData: new Uint8Array(parsed.aad),
					tagLength: 128,
				},
				aes,
				ciphertextAndTag,
			),
		);
		if (unwrapFailed) {
			plaintext.fill(0);
			return decryptionFailure();
		}
		return successResult({ authenticated: true, plaintext, header: parsed.header });
	} catch (error) {
		rethrowIfInvariant(error);
		return decryptionFailure();
	} finally {
		cek.fill(0);
	}
}

/**
 * Decrypts with explicit application allowlists, bounded parsing and the supplied private key.
 * RSA unwrap, wrong CEK length, wrong key and GCM authentication failures share `decryption_failed`.
 * A wrong RSA ciphertext length skips RSA and follows the dummy-CEK/GCM path. This reduces oracle
 * information; JavaScript and provider implementations are not promised to be constant-time.
 */
export async function decryptCompactJwe(
	token: string,
	options: DecryptJweOptions,
): Promise<JoseResult<DecryptedJwe, JweErrorCode>> {
	if (
		typeof options !== 'object' ||
		options === null ||
		!Array.isArray(options.keyManagementAlgorithms) ||
		options.keyManagementAlgorithms.length === 0 ||
		options.keyManagementAlgorithms.some((alg) => alg !== 'RSA-OAEP-512') ||
		!Array.isArray(options.contentEncryptionAlgorithms) ||
		options.contentEncryptionAlgorithms.length === 0 ||
		options.contentEncryptionAlgorithms.some((enc) => enc !== 'A256GCM')
	)
		return joseFailure('invalid_options', 'JWE requires nonempty supported alg and enc allowlists');
	const limits = resolveJoseLimits(options.limits);
	if (!limits.ok) return limits;
	const parsed = parse(token, limits.value);
	if (!parsed.ok) return parsed;
	if (!options.keyManagementAlgorithms.some((alg) => alg === parsed.value.header.alg))
		return joseFailure('algorithm_not_allowed', 'JWE key-management algorithm is not allowed');
	if (!options.contentEncryptionAlgorithms.some((enc) => enc === parsed.value.header.enc))
		return joseFailure('encryption_not_allowed', 'JWE content-encryption algorithm is not allowed');
	const key = checkKey(options.privateKey, 'private');
	if (!key.ok) return key;
	return await decryptPayload(parsed.value, options.privateKey, key.value);
}
