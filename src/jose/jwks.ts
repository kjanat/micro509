/**
 * JSON Web Key Set (RFC 7517) parsing, key selection and a local key resolver. Nothing here
 * performs network access.
 *
 * @module
 */

import { base64UrlDecode } from '#micro509/internal/jose/base64url';
import type { JsonObject, JsonValue } from '#micro509/internal/jose/strict-json';
import { isJsonArray, isJsonObject, parseStrictJson } from '#micro509/internal/jose/strict-json';
import type { JoseErrorResult, JoseResult, KeyResolutionErrorCode } from '#micro509/jose/errors';
import { joseFailure } from '#micro509/jose/errors';
import type { JwsAlgorithm, JwsKeyResolver } from '#micro509/jose/jws';
import { checkRs256VerificationKey, MIN_RS256_MODULUS_BITS } from '#micro509/jose/jws';
import { importPublicJwk } from '#micro509/keys/keys';
import { successResult } from '#micro509/result/result';

/** Bounds applied while parsing a JWK Set. */
export interface JwksLimits {
	/** Maximum JWK Set size in bytes. Default `65536`. */
	readonly maxBytes: number;
	/** Maximum number of keys in the set. Default `32`. */
	readonly maxKeys: number;
}

/** The limits applied when a caller supplies none. */
export const DEFAULT_JWKS_LIMITS: JwksLimits = { maxBytes: 65_536, maxKeys: 32 };

const MAX_RSA_MODULUS_BYTES = 1024;
const MAX_JWKS_JSON_DEPTH = 8;

/** Members every JWK entry carries beside its key material. */
export interface JwkMetadata {
	/** Key identifier. */
	readonly kid?: string;
	/** Intended use: `sig` or `enc`, or another value kept verbatim. */
	readonly use?: string;
	/** Permitted operations, verbatim. */
	readonly keyOps?: readonly string[];
	/** The algorithm the key is restricted to. */
	readonly alg?: string;
}

/** Members shared by every parsed entry. */
export interface JwkEntryBase extends JwkMetadata {
	/** Every member the entry carried, as parsed, including key material this module does not read. */
	readonly members: JsonObject;
}

/** An RSA public key entry. */
export interface RsaJwkEntry extends JwkEntryBase {
	/** Discriminant. */
	readonly kind: 'rsa';
	/** Base64url modulus. */
	readonly n: string;
	/** Base64url public exponent. */
	readonly e: string;
}

/**
 * An entry this module never selects: a `kty` other than `RSA`, or an entry with missing or
 * wrongly typed members (RFC 7517 §5). Kept so callers can inspect the whole set.
 */
export interface UnsupportedJwkEntry extends JwkEntryBase {
	/** Discriminant. */
	readonly kind: 'unsupported';
	/** The `kty` the entry carried, when it was a string. */
	readonly kty?: string;
}

/** One key of a JWK Set. */
export type JwkEntry = RsaJwkEntry | UnsupportedJwkEntry;

/** A parsed JWK Set. */
export interface Jwks {
	/** The keys, in document order. */
	readonly keys: readonly JwkEntry[];
	/** Every top-level member of the document, as parsed. */
	readonly members: JsonObject;
}

/** Codes {@linkcode parseJwks} returns. */
export type ParseJwksErrorCode = 'jwks_malformed' | 'limit_exceeded' | 'invalid_options';

function malformed(message: string): JoseErrorResult<'jwks_malformed'> {
	return joseFailure('jwks_malformed', message);
}

function memberString(object: JsonObject, name: string): string | undefined | null {
	if (!Object.hasOwn(object, name)) return undefined;
	const value = object[name];
	return typeof value === 'string' ? value : null;
}

function memberStrings(object: JsonObject, name: string): readonly string[] | undefined | null {
	if (!Object.hasOwn(object, name)) return undefined;
	const value: JsonValue | undefined = object[name];
	if (!isJsonArray(value)) return null;
	const items: string[] = [];
	for (const item of value) {
		if (typeof item !== 'string' || items.includes(item)) return null;
		items.push(item);
	}
	return items;
}

function parseEntry(value: JsonValue): JoseResult<JwkEntry, 'jwks_malformed'> {
	if (!isJsonObject(value)) {
		return malformed('JWK Set key is not an object');
	}
	const kty = memberString(value, 'kty');
	const kid = memberString(value, 'kid');
	const use = memberString(value, 'use');
	const alg = memberString(value, 'alg');
	const ops = memberStrings(value, 'key_ops');
	if (typeof kty !== 'string' || kid === null || use === null || alg === null || ops === null) {
		return successResult({
			kind: 'unsupported',
			...(typeof kty === 'string' ? { kty } : {}),
			members: value,
		});
	}
	const metadata: JwkMetadata = {
		...(kid === undefined ? {} : { kid }),
		...(use === undefined ? {} : { use }),
		...(alg === undefined ? {} : { alg }),
		...(ops === undefined ? {} : { keyOps: ops }),
	};
	const n = value.n;
	const e = value.e;
	if (kty !== 'RSA' || typeof n !== 'string' || typeof e !== 'string') {
		return successResult({ kind: 'unsupported', kty, ...metadata, members: value });
	}
	return successResult({ kind: 'rsa', n, e, ...metadata, members: value });
}

/**
 * Parses a JWK Set document.
 *
 * The document must be duplicate-free JSON with a `keys` array within `limits`. Keys with a `kty`
 * other than `RSA`, and keys with missing or wrongly typed members, are kept as `unsupported`
 * entries and never selected (RFC 7517 §5). A set that is not a duplicate-free object with a
 * `keys` array of objects is `jwks_malformed`.
 */
export function parseJwks(
	input: string | Uint8Array,
	limits?: Partial<JwksLimits>,
): JoseResult<Jwks, ParseJwksErrorCode> {
	const bounds = resolveJwksLimits(limits);
	if (!bounds.ok) return bounds;
	return parseWithLimits(input, bounds.value);
}

const MAX_JWKS_BYTES_LIMIT = 16_777_216;
const MAX_JWKS_KEYS_LIMIT = 1024;

function resolveJwksLimits(
	overrides: Partial<JwksLimits> | undefined,
): JoseResult<JwksLimits, 'invalid_options'> {
	if (overrides !== undefined && (typeof overrides !== 'object' || overrides === null)) {
		return joseFailure('invalid_options', 'limits must be an object');
	}
	const maxBytes =
		overrides?.maxBytes === undefined ? DEFAULT_JWKS_LIMITS.maxBytes : overrides.maxBytes;
	const maxKeys =
		overrides?.maxKeys === undefined ? DEFAULT_JWKS_LIMITS.maxKeys : overrides.maxKeys;
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_JWKS_BYTES_LIMIT) {
		return joseFailure(
			'invalid_options',
			`limits.maxBytes must be from 1 to ${MAX_JWKS_BYTES_LIMIT}`,
		);
	}
	if (!Number.isSafeInteger(maxKeys) || maxKeys < 1 || maxKeys > MAX_JWKS_KEYS_LIMIT) {
		return joseFailure(
			'invalid_options',
			`limits.maxKeys must be from 1 to ${MAX_JWKS_KEYS_LIMIT}`,
		);
	}
	return successResult({ maxBytes, maxKeys });
}

function parseWithLimits(
	input: string | Uint8Array,
	bounds: JwksLimits,
): JoseResult<Jwks, 'jwks_malformed' | 'limit_exceeded'> {
	if (typeof input === 'string' && input.length > bounds.maxBytes) {
		return joseFailure('limit_exceeded', `JWK Set exceeds ${bounds.maxBytes} bytes`);
	}
	if (typeof input !== 'string' && !(input instanceof Uint8Array)) {
		return malformed('JWK Set input is neither a string nor bytes');
	}
	const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
	if (bytes.byteLength > bounds.maxBytes) {
		return joseFailure('limit_exceeded', `JWK Set exceeds ${bounds.maxBytes} bytes`);
	}
	let text: string;
	try {
		text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return malformed('JWK Set is not valid UTF-8');
	}
	const parsed = parseStrictJson(text, {
		maxDepth: MAX_JWKS_JSON_DEPTH,
		maxNodes: bounds.maxKeys * 64 + 64,
	});
	if (!parsed.ok) {
		return parsed.code === 'limit_exceeded'
			? joseFailure('limit_exceeded', `JWK Set: ${parsed.message}`)
			: malformed(`JWK Set: ${parsed.message}`);
	}
	const document = parsed.value;
	if (!isJsonObject(document)) {
		return malformed('JWK Set is not an object');
	}
	const keys = document.keys;
	if (!isJsonArray(keys)) return malformed('JWK Set "keys" is not an array');
	if (keys.length > bounds.maxKeys) {
		return joseFailure('limit_exceeded', `JWK Set holds more than ${bounds.maxKeys} keys`);
	}
	const entries: JwkEntry[] = [];
	for (const key of keys) {
		const entry = parseEntry(key);
		if (!entry.ok) return entry;
		entries.push(entry.value);
	}
	return successResult({ keys: entries, members: document });
}

/** Why a key entry cannot verify a given algorithm, or `undefined` when it can. */
function unsuitableReason(entry: JwkEntry, algorithm: JwsAlgorithm): string | undefined {
	if (entry.kind !== 'rsa') return 'key type does not match the algorithm';
	if (entry.use !== undefined && entry.use !== 'sig') return '"use" is not "sig"';
	if (entry.keyOps !== undefined && !entry.keyOps.includes('verify')) {
		return '"key_ops" does not include "verify"';
	}
	if (entry.use === 'sig' && entry.keyOps?.some((op) => op !== 'sign' && op !== 'verify')) {
		return '"use" and "key_ops" are inconsistent';
	}
	if (entry.alg !== undefined && entry.alg !== algorithm) return '"alg" names another algorithm';
	const modulus = base64UrlDecode(entry.n);
	const exponent = base64UrlDecode(entry.e);
	if (modulus === undefined || exponent === undefined || modulus.length === 0) {
		return 'RSA parameters are not canonical base64url';
	}
	if (modulus[0] === 0 || exponent[0] === 0 || exponent.length === 0) {
		return 'RSA parameters have leading zero octets';
	}
	if (modulus.length > MAX_RSA_MODULUS_BYTES) return 'RSA modulus is too large';
	const modulusBits = (modulus.length - 1) * 8 + 32 - Math.clz32(modulus[0] ?? 0);
	if (modulusBits < MIN_RS256_MODULUS_BITS) return 'RSA modulus is too small';
	return undefined;
}

/** What {@linkcode selectJwk} matches against. */
export interface JwkSelector {
	/** The algorithm the token uses. */
	readonly algorithm: JwsAlgorithm;
	/** The token's `kid`, when it carries one. */
	readonly kid?: string;
}

/**
 * Selects the one key of a set that can verify `selector`.
 *
 * Keys are filtered by `kid` (when the token has one), key type, `use`, `key_ops`, `alg` and RSA
 * parameters. No match is `key_not_found`, or `key_unsuitable` when `kid` matched only keys that
 * fail the other checks. More than one match is `ambiguous_key`: a token without `kid` therefore
 * resolves only against a set with a single usable key.
 */
export function selectJwk(
	jwks: Jwks,
	selector: JwkSelector,
): JoseResult<RsaJwkEntry, Exclude<KeyResolutionErrorCode, 'jwks_unavailable' | 'aborted'>> {
	const named = jwks.keys.filter(
		(entry) => selector.kid === undefined || entry.kid === selector.kid,
	);
	const details = selector.kid === undefined ? {} : { kid: selector.kid };
	if (named.length === 0) return joseFailure('key_not_found', 'No key matches the token', details);
	const usable: RsaJwkEntry[] = [];
	for (const entry of named) {
		if (entry.kind === 'rsa' && unsuitableReason(entry, selector.algorithm) === undefined) {
			usable.push(entry);
		}
	}
	const [only, second] = usable;
	if (only === undefined) {
		return joseFailure('key_unsuitable', 'No matching key can verify this algorithm', details);
	}
	if (second !== undefined) {
		return joseFailure('ambiguous_key', 'More than one key matches the token', details);
	}
	return successResult(only);
}

/** Imports a selected entry as a verify-only RS256 `CryptoKey`. */
export async function importJwkEntry(
	entry: RsaJwkEntry,
): Promise<JoseResult<CryptoKey, 'key_unsuitable'>> {
	const imported = await importPublicJwk(
		{ kty: 'RSA', n: entry.n, e: entry.e, alg: 'RS256', key_ops: ['verify'], ext: true },
		{ kind: 'rsa', scheme: 'pkcs1-v1_5', hash: 'SHA-256' },
	);
	if (!imported.ok) {
		return joseFailure('key_unsuitable', 'The RSA JWK cannot be imported', {
			...(entry.kid === undefined ? {} : { kid: entry.kid }),
		});
	}
	const suitable = checkRs256VerificationKey(imported.value);
	return suitable.ok ? successResult(imported.value) : suitable;
}

/**
 * Creates a key resolver over a fixed JWK Set.
 *
 * The resolver selects with {@linkcode selectJwk} and imports each key once, so repeated
 * verifications reuse the same `CryptoKey`.
 */
export function createJwksKeyResolver(jwks: Jwks): JwsKeyResolver {
	const imported = new Map<RsaJwkEntry, Promise<JoseResult<CryptoKey, 'key_unsuitable'>>>();
	return async (request) => {
		const selected = selectJwk(jwks, {
			algorithm: request.algorithm,
			...(request.kid === undefined ? {} : { kid: request.kid }),
		});
		if (!selected.ok) return selected;
		const cached = imported.get(selected.value);
		if (cached !== undefined) return await cached;
		const pending = importJwkEntry(selected.value);
		imported.set(selected.value, pending);
		return await pending;
	};
}
