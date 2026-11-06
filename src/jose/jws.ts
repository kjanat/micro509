/**
 * Compact JWS (RFC 7515) parsing, signing and verification with an explicit algorithm and token
 * type policy. Parsing yields an {@linkcode UnverifiedJws}; only {@linkcode verifyCompactJws}
 * yields a {@linkcode VerifiedJws}.
 *
 * @module
 */

import { ecdsaSignatureDerToRaw, signData, verifySignatureWithKey } from '#micro509/crypto/crypto';
import { OIDS } from '#micro509/internal/asn1/oids';
import { base64UrlDecode, base64UrlEncode } from '#micro509/internal/jose/base64url';
import type { JsonObject, JsonValue } from '#micro509/internal/jose/strict-json';
import { isJsonArray, isJsonObject, parseStrictJson } from '#micro509/internal/jose/strict-json';
import type {
	JoseErrorDetails,
	JoseErrorResult,
	JoseResult,
	JwsParseErrorCode,
	KeyResolutionErrorCode,
	VerifyJwsErrorCode,
} from '#micro509/jose/errors';
import { joseFailure } from '#micro509/jose/errors';
import { successResult, throwMicro509Error } from '#micro509/result/result';

/** Signature algorithms this module signs and verifies. */
export type JwsAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384';

/** Every {@linkcode JwsAlgorithm}. */
export const JWS_ALGORITHMS: readonly JwsAlgorithm[] = [
	'RS256',
	'RS384',
	'RS512',
	'ES256',
	'ES384',
];

/** Smallest RSA modulus RS256 accepts (RFC 7518 §3.3). */
export const MIN_RS256_MODULUS_BITS = 2048;

/** Smallest RSA modulus accepted by any implemented RSA JWS algorithm (RFC 7518 §3.3). */
export const MIN_JWS_RSA_MODULUS_BITS: number = MIN_RS256_MODULUS_BITS;

type JwsAlgorithmProfile =
	| { readonly kind: 'rsa'; readonly hash: 'SHA-256' | 'SHA-384' | 'SHA-512'; readonly oid: string }
	| {
			readonly kind: 'ec';
			readonly hash: 'SHA-256' | 'SHA-384';
			readonly curve: 'P-256' | 'P-384';
			readonly coordinateBytes: number;
			readonly oid: string;
	  };

const ALGORITHM_PROFILES: Readonly<Record<JwsAlgorithm, JwsAlgorithmProfile>> = {
	RS256: { kind: 'rsa', hash: 'SHA-256', oid: OIDS.sha256WithRSAEncryption },
	RS384: { kind: 'rsa', hash: 'SHA-384', oid: OIDS.sha384WithRSAEncryption },
	RS512: { kind: 'rsa', hash: 'SHA-512', oid: OIDS.sha512WithRSAEncryption },
	ES256: {
		kind: 'ec',
		hash: 'SHA-256',
		curve: 'P-256',
		coordinateBytes: 32,
		oid: OIDS.ecdsaWithSHA256,
	},
	ES384: {
		kind: 'ec',
		hash: 'SHA-384',
		curve: 'P-384',
		coordinateBytes: 48,
		oid: OIDS.ecdsaWithSHA384,
	},
};

/** The exact key and signature profile for an admitted JWS algorithm. */
export function jwsAlgorithmProfile(algorithm: JwsAlgorithm): JwsAlgorithmProfile {
	return ALGORITHM_PROFILES[algorithm];
}

/** Size and structure bounds enforced before any expensive parsing. */
export interface JoseLimits {
	/** Maximum compact serialization length in characters. Default `32768`. */
	readonly maxTokenLength: number;
	/** Maximum decoded protected header size in bytes. Default `4096`. */
	readonly maxHeaderBytes: number;
	/** Maximum decoded payload size in bytes. Default `16384`. */
	readonly maxPayloadBytes: number;
	/** Maximum decoded signature size in bytes. Default `1024`. */
	readonly maxSignatureBytes: number;
	/** Maximum JSON nesting in the header and payload. Default `16`. */
	readonly maxJsonDepth: number;
	/** Maximum JSON values in the header or payload. Default `2048`. */
	readonly maxJsonNodes: number;
}

/** The limits applied when a caller supplies none. */
export const DEFAULT_JOSE_LIMITS: JoseLimits = {
	maxTokenLength: 32_768,
	maxHeaderBytes: 4096,
	maxPayloadBytes: 16_384,
	maxSignatureBytes: 1024,
	maxJsonDepth: 16,
	maxJsonNodes: 2048,
};

const LIMIT_NAMES = [
	'maxTokenLength',
	'maxHeaderBytes',
	'maxPayloadBytes',
	'maxSignatureBytes',
	'maxJsonDepth',
	'maxJsonNodes',
] as const;

/** Deepest JSON nesting any limit may allow; keeps the recursive parser inside the stack. */
export const MAX_JSON_DEPTH_LIMIT = 64;

/**
 * Resolves caller-supplied limit overrides against {@linkcode DEFAULT_JOSE_LIMITS}. An omitted or
 * `undefined` field takes its default; any other value must be a positive safe integer, and
 * `maxJsonDepth` may not exceed {@linkcode MAX_JSON_DEPTH_LIMIT}.
 */
export function resolveJoseLimits(
	overrides: Partial<JoseLimits> | undefined,
): JoseResult<JoseLimits, 'invalid_options'> {
	if (overrides !== undefined && (typeof overrides !== 'object' || overrides === null)) {
		return joseFailure('invalid_options', 'limits must be an object');
	}
	const resolved: { -readonly [Name in keyof JoseLimits]: JoseLimits[Name] } = {
		...DEFAULT_JOSE_LIMITS,
	};
	for (const name of LIMIT_NAMES) {
		const value = overrides?.[name];
		if (value === undefined) continue;
		const ceiling = name === 'maxJsonDepth' ? MAX_JSON_DEPTH_LIMIT : Number.MAX_SAFE_INTEGER;
		if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) {
			return joseFailure('invalid_options', `limits.${name} must be a positive safe integer`);
		}
		resolved[name] = value;
	}
	return successResult(resolved);
}

/** A protected header. Every member the token carried stays reachable through `members`. */
export interface JwsHeader<TAlgorithm extends string = string> {
	/** The `alg` member. */
	readonly alg: TAlgorithm;
	/** The `typ` member, when present. */
	readonly typ?: string;
	/** The `kid` member, when present. */
	readonly kid?: string;
	/** The `cty` member, when present. */
	readonly cty?: string;
	/** Every header member as the token carried it. */
	readonly members: JsonObject;
}

/**
 * A parsed token whose signature has not been checked. Nothing in it is trustworthy until
 * {@linkcode verifyCompactJws} succeeds.
 */
export interface UnverifiedJws {
	/** Always `false`. */
	readonly verified: false;
	/** The header, unauthenticated. */
	readonly header: JwsHeader;
	/** The payload bytes, unauthenticated. */
	readonly payload: Uint8Array;
	/** ASCII bytes of `BASE64URL(header) || '.' || BASE64URL(payload)`. */
	readonly signingInput: Uint8Array;
	/** The decoded signature bytes. */
	readonly signature: Uint8Array;
}

/** A token whose signature verified under the caller's algorithm and key policy. */
export interface VerifiedJws {
	/** Always `true`. */
	readonly verified: true;
	/** The authenticated protected header. */
	readonly header: JwsHeader<JwsAlgorithm>;
	/** The authenticated payload bytes. */
	readonly payload: Uint8Array;
}

/** What a key resolver is asked for. The header is unauthenticated. */
export interface JwsKeyRequest {
	/** The unauthenticated header of the token being verified. */
	readonly header: JwsHeader<JwsAlgorithm>;
	/** The algorithm the policy admitted for this token. */
	readonly algorithm: JwsAlgorithm;
	/** The `kid` header, when present. */
	readonly kid?: string;
	/** Cancellation from {@linkcode VerifyJwsOptions.signal}. */
	readonly signal?: AbortSignal;
}

/** Supplies the verification key for a token. */
export type JwsKeyResolver = (
	request: JwsKeyRequest,
) => Promise<JoseResult<CryptoKey, KeyResolutionErrorCode>>;

/** Marks a policy dimension as deliberately not checked. */
export interface Unchecked {
	/** Always `true`. */
	readonly unchecked: true;
}

/**
 * Expectation for the `typ` header (RFC 7515 §4.1.9, RFC 8725 §3.11).
 *
 * A string requires that media type, compared case-insensitively with an omitted `application/`
 * prefix restored. `{ absent: true }` requires the header to be missing. `{ unchecked: true }`
 * accepts any value.
 */
export type TokenTypePolicy = string | { readonly absent: true } | Unchecked;

/** Options for {@linkcode verifyCompactJws}. */
export interface VerifyJwsOptions {
	/** Algorithms admitted for this token use. Never derived from the token. */
	readonly algorithms: readonly [JwsAlgorithm, ...JwsAlgorithm[]];
	/** A fixed verification key, or a resolver chosen by the caller. */
	readonly key: CryptoKey | JwsKeyResolver;
	/** The token type this verification accepts. */
	readonly tokenType: TokenTypePolicy;
	/** Overrides for {@linkcode DEFAULT_JOSE_LIMITS}. */
	readonly limits?: Partial<JoseLimits>;
	/** Cancels key resolution. */
	readonly signal?: AbortSignal;
}

/** Header members {@linkcode signCompactJws} sets beside `alg`. */
export interface JwsHeaderInput {
	/** Token type. */
	readonly typ?: string;
	/** Key identifier. */
	readonly kid?: string;
	/** Content type. */
	readonly cty?: string;
}

/** Input for {@linkcode signCompactJws}. */
export interface SignJwsInput {
	/** A signing key matching the algorithm's RSA hash or ECDSA curve. RSA needs at least 2048 bits. */
	readonly privateKey: CryptoKey;
	/** The signature algorithm. */
	readonly algorithm: JwsAlgorithm;
	/** The payload bytes. */
	readonly payload: Uint8Array;
	/** Header members beside `alg`. */
	readonly header?: JwsHeaderInput;
}

/** Codes {@linkcode signCompactJws} and {@linkcode signJwt} throw. */
export type SignJoseErrorCode =
	| 'unsupported_algorithm'
	| 'incompatible_key'
	| 'invalid_header'
	| 'invalid_claims';

const textEncoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function maxEncodedLength(decodedBytes: number): number {
	return Math.ceil((decodedBytes * 4) / 3);
}

function parseFailure(
	code: JwsParseErrorCode,
	message: string,
): JoseErrorResult<JwsParseErrorCode> {
	return joseFailure(code, message);
}

function decodeSegment(
	segment: string,
	maxBytes: number,
	name: string,
): JoseResult<Uint8Array, JwsParseErrorCode> {
	if (segment.length > maxEncodedLength(maxBytes)) {
		return parseFailure('limit_exceeded', `JWS ${name} exceeds ${maxBytes} bytes`);
	}
	const bytes = base64UrlDecode(segment);
	if (bytes === undefined) {
		return parseFailure('invalid_encoding', `JWS ${name} is not canonical base64url`);
	}
	return successResult(bytes);
}

/** Decodes UTF-8 strictly and parses it as a JSON object with no duplicate members. */
export function decodeJsonObject(
	bytes: Uint8Array,
	limits: JoseLimits,
	name: string,
	notObjectCode: 'invalid_header' | 'invalid_payload',
): JoseResult<JsonObject, JwsParseErrorCode> {
	let text: string;
	try {
		text = strictDecoder.decode(bytes);
	} catch {
		return parseFailure('invalid_utf8', `JWS ${name} is not valid UTF-8`);
	}
	const parsed = parseStrictJson(text, {
		maxDepth: limits.maxJsonDepth,
		maxNodes: limits.maxJsonNodes,
	});
	if (!parsed.ok) {
		return parseFailure(parsed.code, `JWS ${name}: ${parsed.message}`);
	}
	const value = parsed.value;
	if (!isJsonObject(value)) {
		return parseFailure(notObjectCode, `JWS ${name} is not a JSON object`);
	}
	return successResult(value);
}

function optionalString(
	members: JsonObject,
	name: string,
): JoseResult<string | undefined, JwsParseErrorCode> {
	if (!Object.hasOwn(members, name)) return successResult(undefined);
	const value = members[name];
	if (typeof value !== 'string') {
		return parseFailure('invalid_header', `JWS header "${name}" is not a string`);
	}
	return successResult(value);
}

function criticalNames(members: JsonObject): JoseResult<readonly string[], JwsParseErrorCode> {
	if (!Object.hasOwn(members, 'crit')) return successResult([]);
	const crit: JsonValue | undefined = members.crit;
	if (!isJsonArray(crit) || crit.length === 0) {
		return parseFailure('invalid_header', 'JWS header "crit" is not a non-empty array');
	}
	const names: string[] = [];
	for (const entry of crit) {
		if (typeof entry !== 'string' || names.includes(entry)) {
			return parseFailure(
				'invalid_header',
				'JWS header "crit" holds a non-string or repeated name',
			);
		}
		names.push(entry);
	}
	return successResult(names);
}

function parseHeader(
	bytes: Uint8Array,
	limits: JoseLimits,
): JoseResult<JwsHeader, JwsParseErrorCode> {
	const object = decodeJsonObject(bytes, limits, 'header', 'invalid_header');
	if (!object.ok) return object;
	const members = object.value;
	const alg = members.alg;
	if (typeof alg !== 'string' || alg.length === 0) {
		return parseFailure('invalid_header', 'JWS header "alg" is missing or not a string');
	}
	const typ = optionalString(members, 'typ');
	if (!typ.ok) return typ;
	const kid = optionalString(members, 'kid');
	if (!kid.ok) return kid;
	const cty = optionalString(members, 'cty');
	if (!cty.ok) return cty;
	const crit = criticalNames(members);
	if (!crit.ok) return crit;
	if (members.b64 === false || crit.value.includes('b64')) {
		return parseFailure(
			'unsupported_unencoded_payload',
			'Unencoded and detached payloads (RFC 7797) are not supported',
		);
	}
	if (Object.hasOwn(members, 'b64') && typeof members.b64 !== 'boolean') {
		return parseFailure('invalid_header', 'JWS header "b64" is not a boolean');
	}
	if (crit.value.length > 0) {
		return joseFailure('unsupported_critical_header', 'JWS header lists critical extensions', {
			alg,
			crit: crit.value,
		});
	}
	return successResult({
		alg,
		...(typ.value === undefined ? {} : { typ: typ.value }),
		...(kid.value === undefined ? {} : { kid: kid.value }),
		...(cty.value === undefined ? {} : { cty: cty.value }),
		members,
	});
}

/**
 * Parses a compact JWS without checking its signature.
 *
 * Refuses tokens that are oversized, do not have exactly three segments, carry non-canonical
 * base64url, invalid UTF-8, a header that is not a duplicate-free JSON object with a string `alg`,
 * a `crit` list, or an unencoded payload (`b64: false`). The result is {@linkcode UnverifiedJws};
 * pass the token to {@linkcode verifyCompactJws} before trusting any of it.
 */
export function parseCompactJws(
	token: string,
	limits?: Partial<JoseLimits>,
): JoseResult<UnverifiedJws, JwsParseErrorCode | 'invalid_options'> {
	const resolved = resolveJoseLimits(limits);
	if (!resolved.ok) return resolved;
	return parseWithLimits(token, resolved.value);
}

function parseWithLimits(
	token: string,
	bounds: JoseLimits,
): JoseResult<UnverifiedJws, JwsParseErrorCode> {
	if (typeof token !== 'string') {
		return parseFailure('malformed_token', 'JWS token is not a string');
	}
	if (token.length > bounds.maxTokenLength) {
		return parseFailure('token_too_large', `JWS token exceeds ${bounds.maxTokenLength} characters`);
	}
	const segments = token.split('.');
	const [headerSegment, payloadSegment, signatureSegment] = segments;
	if (
		segments.length !== 3 ||
		headerSegment === undefined ||
		payloadSegment === undefined ||
		signatureSegment === undefined ||
		headerSegment.length === 0
	) {
		return parseFailure('malformed_token', 'JWS compact serialization needs three segments');
	}
	const headerBytes = decodeSegment(headerSegment, bounds.maxHeaderBytes, 'header');
	if (!headerBytes.ok) return headerBytes;
	const header = parseHeader(headerBytes.value, bounds);
	if (!header.ok) return header;
	const payload = decodeSegment(payloadSegment, bounds.maxPayloadBytes, 'payload');
	if (!payload.ok) return payload;
	const signature = decodeSegment(signatureSegment, bounds.maxSignatureBytes, 'signature');
	if (!signature.ok) return signature;
	return successResult({
		verified: false,
		header: header.value,
		payload: payload.value,
		signingInput: textEncoder.encode(`${headerSegment}.${payloadSegment}`),
		signature: signature.value,
	});
}

/**
 * Comparison key for a media type per RFC 7515 §4.1.9: type, subtype and parameter names fold to
 * lower case, an omitted `application/` is restored, and parameter values stay exact.
 */
export function mediaTypeKey(value: string): string {
	const [essence = '', ...parameters] = value.split(';');
	const type = essence.trim().toLowerCase();
	const normalized = parameters.map((parameter) => {
		const separator = parameter.indexOf('=');
		return separator < 0
			? parameter.trim().toLowerCase()
			: `${parameter.slice(0, separator).trim().toLowerCase()}=${parameter.slice(separator + 1).trim()}`;
	});
	return [type.includes('/') ? type : `application/${type}`, ...normalized].join(';');
}

/** A token type policy reduced to the one form verification compares against. */
export type TypeRule =
	| { readonly kind: 'media'; readonly key: string }
	| { readonly kind: 'absent' }
	| { readonly kind: 'unchecked' };

/** Whether `value` is exactly `{ unchecked: true }`. */
export function isUncheckedPolicy(value: unknown): boolean {
	return soleTrueMember(value) === 'unchecked';
}

function soleTrueMember(value: unknown): string | undefined {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
	const names = Object.keys(value);
	const [name] = names;
	if (names.length !== 1 || name === undefined) return undefined;
	return Reflect.get(value, name) === true ? name : undefined;
}

function normalizeTokenType(policy: unknown): TypeRule | undefined {
	if (typeof policy === 'string') return { kind: 'media', key: mediaTypeKey(policy) };
	const member = soleTrueMember(policy);
	if (member === 'absent') return { kind: 'absent' };
	if (member === 'unchecked') return { kind: 'unchecked' };
	return undefined;
}

function matchesTokenType(header: JwsHeader, rule: TypeRule): boolean {
	switch (rule.kind) {
		case 'media':
			return header.typ !== undefined && mediaTypeKey(header.typ) === rule.key;
		case 'unchecked':
			return true;
		case 'absent':
			return header.typ === undefined;
		default: {
			const _exhaustive: never = rule;
			return _exhaustive;
		}
	}
}

function isAlgorithmAdmitted(
	algorithm: string,
	admitted: readonly string[],
): algorithm is JwsAlgorithm {
	return (
		admitted.includes(algorithm) && JWS_ALGORITHMS.some((supported) => supported === algorithm)
	);
}

/** Checks the observable RSA exponent constraints in RFC 8017 section 3.1. */
export function validRsaPublicExponent(exponent: Uint8Array, modulus?: Uint8Array): boolean {
	const first = exponent.findIndex((byte) => byte !== 0);
	const last = exponent[exponent.length - 1] ?? 0;
	if (first < 0 || (last & 1) === 0) return false;
	const length = exponent.length - first;
	if (length === 1 && last < 3) return false;
	if (modulus === undefined) return true;
	if (length !== modulus.length) return length < modulus.length;
	for (let i = 0; i < length; i++) {
		const left = exponent[first + i] ?? 0;
		const right = modulus[i] ?? 0;
		if (left !== right) return left < right;
	}
	return false;
}

/** Checks the key profile and returns the exact JOSE signature length (RFC 7518 §§3.3–3.4). */
export function checkJwsVerificationKey(
	key: CryptoKey,
	algorithm: JwsAlgorithm,
): JoseResult<number, 'key_unsuitable'> {
	return checkJwsKey(key, algorithm, 'public');
}

function checkJwsKey(
	key: CryptoKey,
	algorithm: JwsAlgorithm,
	type: 'public' | 'private',
): JoseResult<number, 'key_unsuitable'> {
	try {
		return inspectJwsKey(key, algorithm, type);
	} catch {
		return joseFailure('key_unsuitable', 'The key cannot be inspected');
	}
}

function inspectJwsKey(
	key: CryptoKey,
	algorithm: JwsAlgorithm,
	type: 'public' | 'private',
): JoseResult<number, 'key_unsuitable'> {
	const profile = jwsAlgorithmProfile(algorithm);
	const usage = type === 'public' ? 'verify' : 'sign';
	if (key.type !== type || !key.usages.includes(usage)) {
		return joseFailure('key_unsuitable', `${algorithm} needs a ${type} key with ${usage} usage`);
	}
	const keyAlgorithm = key.algorithm;
	if (profile.kind === 'ec') {
		if (
			keyAlgorithm.name !== 'ECDSA' ||
			!('namedCurve' in keyAlgorithm) ||
			keyAlgorithm.namedCurve !== profile.curve
		) {
			return joseFailure('key_unsuitable', `${algorithm} needs an ECDSA ${profile.curve} key`);
		}
		return successResult(profile.coordinateBytes * 2);
	}
	if (
		keyAlgorithm.name !== 'RSASSA-PKCS1-v1_5' ||
		!('hash' in keyAlgorithm) ||
		typeof keyAlgorithm.hash !== 'object' ||
		keyAlgorithm.hash === null ||
		!('name' in keyAlgorithm.hash) ||
		keyAlgorithm.hash.name !== profile.hash
	) {
		return joseFailure(
			'key_unsuitable',
			`${algorithm} needs an RSASSA-PKCS1-v1_5 ${profile.hash} key`,
		);
	}
	if (
		!('modulusLength' in keyAlgorithm) ||
		typeof keyAlgorithm.modulusLength !== 'number' ||
		keyAlgorithm.modulusLength < MIN_JWS_RSA_MODULUS_BITS
	) {
		return joseFailure(
			'key_unsuitable',
			`${algorithm} needs an RSA modulus of at least ${MIN_JWS_RSA_MODULUS_BITS} bits`,
		);
	}
	if (
		!('publicExponent' in keyAlgorithm) ||
		!(keyAlgorithm.publicExponent instanceof Uint8Array) ||
		!validRsaPublicExponent(keyAlgorithm.publicExponent)
	) {
		return joseFailure(
			'key_unsuitable',
			`${algorithm} needs a valid odd RSA public exponent of at least 3`,
		);
	}
	return successResult(Math.ceil(keyAlgorithm.modulusLength / 8));
}

/** Verification options validated once and copied, so later changes by the caller cannot alter a run. */
export interface PreparedVerify {
	/** The admitted algorithms. */
	readonly algorithms: readonly JwsAlgorithm[];
	/** The fixed key or the resolver. */
	readonly key: CryptoKey | JwsKeyResolver;
	/** The token type rule. */
	readonly typeRule: TypeRule;
	/** The resolved limits. */
	readonly limits: JoseLimits;
	/** Cancellation for key resolution. */
	readonly signal: AbortSignal | undefined;
}

function isCryptoKey(value: unknown): value is CryptoKey {
	return value instanceof CryptoKey;
}

/** Validates and copies verification options. Everything the run reads is captured here. */
export function prepareVerify(
	options: VerifyJwsOptions,
): JoseResult<PreparedVerify, 'invalid_options'> {
	if (typeof options !== 'object' || options === null) {
		return joseFailure('invalid_options', 'Verification options are required');
	}
	const { algorithms, key, tokenType, limits, signal } = options;
	if (!Array.isArray(algorithms) || algorithms.length === 0) {
		return joseFailure('invalid_options', 'An explicit, non-empty algorithm list is required');
	}
	const admitted: JwsAlgorithm[] = [];
	for (const algorithm of algorithms) {
		const supported = JWS_ALGORITHMS.find((candidate) => candidate === algorithm);
		if (supported === undefined) {
			return joseFailure('invalid_options', 'The algorithm list names an unsupported algorithm');
		}
		admitted.push(supported);
	}
	if (typeof key !== 'function' && !isCryptoKey(key)) {
		return joseFailure('invalid_options', 'A key or key resolver is required');
	}
	const typeRule = normalizeTokenType(tokenType);
	if (typeRule === undefined) {
		return joseFailure('invalid_options', 'A token type policy is required');
	}
	if (signal !== undefined && !(signal instanceof AbortSignal)) {
		return joseFailure('invalid_options', 'signal must be an AbortSignal');
	}
	const bounds = resolveJoseLimits(limits);
	if (!bounds.ok) return bounds;
	return successResult({ algorithms: admitted, key, typeRule, limits: bounds.value, signal });
}

async function resolveKey(
	prepared: PreparedVerify,
	header: JwsHeader<JwsAlgorithm>,
): Promise<JoseResult<CryptoKey, KeyResolutionErrorCode>> {
	const { key, signal } = prepared;
	if (typeof key !== 'function') return successResult(key);
	let resolved: unknown;
	try {
		resolved = await key({
			header,
			algorithm: header.alg,
			...(header.kid === undefined ? {} : { kid: header.kid }),
			...(signal === undefined ? {} : { signal }),
		});
	} catch {
		return signal?.aborted === true
			? joseFailure('aborted', 'Key resolution was cancelled')
			: joseFailure('key_resolution_failed', 'The key resolver failed');
	}
	if (typeof resolved !== 'object' || resolved === null) {
		return joseFailure('key_resolution_failed', 'The key resolver returned no result');
	}
	if (Reflect.get(resolved, 'ok') === true) {
		const value: unknown = Reflect.get(resolved, 'value');
		return isCryptoKey(value)
			? successResult(value)
			: joseFailure('key_resolution_failed', 'The key resolver returned no key');
	}
	const code: unknown = Reflect.get(resolved, 'code');
	switch (code) {
		case 'key_not_found':
		case 'ambiguous_key':
		case 'key_unsuitable':
		case 'key_resolution_failed':
		case 'jwks_unavailable':
		case 'jwks_malformed':
		case 'aborted':
			return joseFailure(code, `Key resolution failed: ${code}`, resolverDetails(resolved));
		default:
			return joseFailure('key_resolution_failed', 'The key resolver returned an unknown failure');
	}
}

function resolverDetails(resolved: object): JoseErrorDetails | undefined {
	const details: unknown = Reflect.get(resolved, 'details');
	if (typeof details !== 'object' || details === null) return undefined;
	const kid: unknown = Reflect.get(details, 'kid');
	const status: unknown = Reflect.get(details, 'status');
	return {
		...(typeof kid === 'string' ? { kid } : {}),
		...(typeof status === 'number' && Number.isSafeInteger(status) ? { status } : {}),
	};
}

/**
 * Verifies a compact JWS.
 *
 * The caller's `algorithms` list decides what is accepted; the token's `alg` only selects among
 * them, and `none` is always refused as `unsigned_token`. The `tokenType` policy is applied before
 * any key is resolved. The key must match the admitted algorithm's RSA hash (at least 2048 bits)
 * or ECDSA curve. ECDSA signatures must be fixed-width raw R || S, with no DER retry.
 * Header members such as `jku`, `jwk`, `x5u` and
 * `x5c` are never used to find a key. A resolver that throws or returns something other than a
 * result is reported as `key_resolution_failed` without its message.
 *
 * Returns a {@linkcode VerifiedJws} on success. Failures carry a stable code and never echo the
 * token.
 */
export async function verifyCompactJws(
	token: string,
	options: VerifyJwsOptions,
): Promise<JoseResult<VerifiedJws, VerifyJwsErrorCode>> {
	const prepared = prepareVerify(options);
	if (!prepared.ok) return prepared;
	return await verifyPrepared(token, prepared.value);
}

/** Verifies `token` under options already checked by {@linkcode prepareVerify}. */
export async function verifyPrepared(
	token: string,
	prepared: PreparedVerify,
): Promise<JoseResult<VerifiedJws, VerifyJwsErrorCode>> {
	const parsed = parseWithLimits(token, prepared.limits);
	if (!parsed.ok) return parsed;
	const unverified = parsed.value;
	const alg = unverified.header.alg;
	if (alg === 'none') {
		return joseFailure('unsigned_token', 'Unsigned tokens are never accepted', { alg });
	}
	if (!isAlgorithmAdmitted(alg, prepared.algorithms)) {
		return joseFailure('algorithm_not_allowed', 'The token algorithm is not in the allowed list', {
			alg,
		});
	}
	if (!matchesTokenType(unverified.header, prepared.typeRule)) {
		return joseFailure('token_type_mismatch', 'The token "typ" does not match the expected type', {
			alg,
		});
	}
	const header: JwsHeader<JwsAlgorithm> = { ...unverified.header, alg };
	const key = await resolveKey(prepared, header);
	if (!key.ok) return key;
	const signatureBytes = checkJwsVerificationKey(key.value, alg);
	if (!signatureBytes.ok) return signatureBytes;
	if (unverified.signature.length !== signatureBytes.value) {
		return joseFailure(
			'invalid_signature',
			'The signature length does not match the algorithm and key',
			{
				alg,
			},
		);
	}
	const failure = joseFailure('invalid_signature', 'The signature does not verify', {
		alg,
		...(header.kid === undefined ? {} : { kid: header.kid }),
	});
	const verification = await verifySignatureWithKey({
		publicKey: key.value,
		signatureAlgorithm: { oid: jwsAlgorithmProfile(alg).oid },
		signatureEncoding: 'raw',
		signature: unverified.signature,
		data: unverified.signingInput,
	});
	if (!verification.ok || !verification.valid) return failure;
	return successResult({ verified: true, header, payload: unverified.payload });
}

function assertSigningKey(input: SignJwsInput): void {
	if (!JWS_ALGORITHMS.includes(input.algorithm)) {
		throwMicro509Error('unsupported_algorithm', 'Unsupported JWS algorithm');
	}
	const suitable = checkJwsKey(input.privateKey, input.algorithm, 'private');
	if (!suitable.ok) {
		throwMicro509Error('incompatible_key', suitable.message);
	}
}

/**
 * Signs a compact JWS with an existing private `CryptoKey`.
 *
 * The header is `alg` followed by the optional `typ`, `kid` and `cty`. Throws a `ResultError`
 * (see `isResultError`) coded {@linkcode SignJoseErrorCode} when the algorithm, key or header
 * input is invalid. Intended for issuing tokens and for building synthetic tokens in tests.
 */
export async function signCompactJws(input: SignJwsInput): Promise<string> {
	assertSigningKey(input);
	const profile = jwsAlgorithmProfile(input.algorithm);
	const header: Record<string, string> = { alg: input.algorithm };
	for (const name of ['typ', 'kid', 'cty'] as const) {
		const value = input.header?.[name];
		if (value === undefined) continue;
		if (typeof value !== 'string') {
			throwMicro509Error('invalid_header', `Header "${name}" must be a string`);
		}
		header[name] = value;
	}
	const signingInput = `${base64UrlEncode(textEncoder.encode(JSON.stringify(header)))}.${base64UrlEncode(input.payload)}`;
	const { signature } = await signData(input.privateKey, textEncoder.encode(signingInput));
	const joseSignature =
		profile.kind === 'ec' ? ecdsaSignatureDerToRaw(signature, profile.curve) : signature;
	return `${signingInput}.${base64UrlEncode(joseSignature)}`;
}
