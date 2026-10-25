/**
 * JWT (RFC 7519) validation on top of compact JWS. Signature verification and the claims policy
 * are separate steps with separate types: {@linkcode decodeJwtUnverified} yields an
 * {@linkcode UnverifiedJwt}, and only {@linkcode verifyJwt} yields a {@linkcode VerifiedJwt}.
 *
 * @module
 */

import type { JsonObject } from '#micro509/internal/jose/strict-json';
import { isJsonArray } from '#micro509/internal/jose/strict-json';
import type {
	JoseErrorResult,
	JoseResult,
	JwsParseErrorCode,
	VerifyJwtErrorCode,
} from '#micro509/jose/errors';
import { joseFailure } from '#micro509/jose/errors';
import type {
	JoseLimits,
	JwsAlgorithm,
	JwsHeader,
	SignJwsInput,
	Unchecked,
	VerifyJwsOptions,
} from '#micro509/jose/jws';
import {
	decodeJsonObject,
	isUncheckedPolicy,
	mediaTypeKey,
	parseCompactJws,
	prepareVerify,
	resolveJoseLimits,
	signCompactJws,
	verifyPrepared,
} from '#micro509/jose/jws';
import { successResult, throwMicro509Error } from '#micro509/result/result';

/** Largest clock tolerance {@linkcode JwtClaimsPolicy.clockToleranceSeconds} accepts. */
export const MAX_CLOCK_TOLERANCE_SECONDS = 600;

/** The RFC 7519 §4.1 registered claims, each checked against its defined type. */
export interface RegisteredClaims {
	/** Issuer. */
	readonly iss?: string;
	/** Subject. */
	readonly sub?: string;
	/** Audience, as the token carried it: a string or an array of strings. */
	readonly aud?: string | readonly string[];
	/** Expiration time in seconds since the epoch. */
	readonly exp?: number;
	/** Not-before time in seconds since the epoch. */
	readonly nbf?: number;
	/** Issued-at time in seconds since the epoch. */
	readonly iat?: number;
	/** Token identifier. */
	readonly jti?: string;
}

/** A decoded JWT whose signature has not been checked. */
export interface UnverifiedJwt {
	/** Always `false`. */
	readonly verified: false;
	/** The header, unauthenticated. */
	readonly header: JwsHeader;
	/** The claims, unauthenticated and not policy-checked. */
	readonly claims: JsonObject;
}

/** A JWT whose signature and claims both passed the caller's policy. */
export interface VerifiedJwt {
	/** Always `true`. */
	readonly verified: true;
	/** The authenticated protected header. */
	readonly header: JwsHeader<JwsAlgorithm>;
	/** Every authenticated claim, exactly as the token carried it. */
	readonly claims: JsonObject;
	/** The registered claims, validated against their types. */
	readonly registered: RegisteredClaims;
}

/** Whether an `iat` later than the clock is accepted. */
export type FutureIssuedAtPolicy = 'reject' | 'allow';

/** Claims policy for {@linkcode verifyJwt}. Application authorization stays with the caller. */
export interface JwtClaimsPolicy {
	/** Accepted `iss` values (any one may match), or `{ unchecked: true }`. */
	readonly issuer: string | readonly string[] | Unchecked;
	/** Accepted `aud` values (any one may match), or `{ unchecked: true }`. */
	readonly audience: string | readonly string[] | Unchecked;
	/** Claims that must be present. Default `['exp']`. */
	readonly requiredClaims?: readonly string[];
	/** The clock. Default is the system time. */
	readonly now?: () => Date;
	/** Leeway in seconds for `exp`, `nbf` and `iat`, from 0 to 600. Default `0`. */
	readonly clockToleranceSeconds?: number;
	/** Oldest acceptable token age in seconds, measured from `iat`. Requires `iat`. */
	readonly maxAgeSeconds?: number;
	/** Whether `iat` after the clock is accepted. Default `'reject'`. */
	readonly futureIssuedAt?: FutureIssuedAtPolicy;
}

/** Options for {@linkcode verifyJwt}. */
export interface VerifyJwtOptions extends VerifyJwsOptions {
	/** Claims policy. */
	readonly claims: JwtClaimsPolicy;
}

/** Input for {@linkcode signJwt}. */
export interface SignJwtInput extends Omit<SignJwsInput, 'payload'> {
	/** The claims to sign. Must be JSON-serializable. */
	readonly claims: JsonObject;
}

function decodeClaims(
	header: JwsHeader,
	payload: Uint8Array,
	limits: JoseLimits,
): JoseResult<JsonObject, JwsParseErrorCode> {
	if (header.cty !== undefined && mediaTypeKey(header.cty) === 'application/jwt') {
		return joseFailure('unsupported_nested_jwt', 'Nested JWTs (cty "JWT") are not supported');
	}
	return decodeJsonObject(payload, limits, 'payload', 'invalid_payload');
}

/** Decodes a JWT without checking its signature. Every field of the result is unauthenticated. */
export function decodeJwtUnverified(
	token: string,
	limits?: Partial<JoseLimits>,
): JoseResult<UnverifiedJwt, JwsParseErrorCode | 'invalid_options'> {
	const bounds = resolveJoseLimits(limits);
	if (!bounds.ok) return bounds;
	const parsed = parseCompactJws(token, bounds.value);
	if (!parsed.ok) return parsed;
	const claims = decodeClaims(parsed.value.header, parsed.value.payload, bounds.value);
	if (!claims.ok) return claims;
	return successResult({ verified: false, header: parsed.value.header, claims: claims.value });
}

function claimFailure<TCode extends VerifyJwtErrorCode>(
	code: TCode,
	message: string,
	claim: string,
): JoseErrorResult<TCode> {
	return joseFailure(code, message, { claim });
}

function numericDate(
	claims: JsonObject,
	name: 'exp' | 'nbf' | 'iat',
): JoseResult<number | undefined, 'invalid_claim'> {
	if (!Object.hasOwn(claims, name)) return successResult(undefined);
	const value = claims[name];
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		return claimFailure('invalid_claim', `Claim "${name}" is not a NumericDate`, name);
	}
	return successResult(value);
}

function stringClaim(
	claims: JsonObject,
	name: 'iss' | 'sub' | 'jti',
): JoseResult<string | undefined, 'invalid_claim'> {
	if (!Object.hasOwn(claims, name)) return successResult(undefined);
	const value = claims[name];
	if (typeof value !== 'string') {
		return claimFailure('invalid_claim', `Claim "${name}" is not a string`, name);
	}
	return successResult(value);
}

function audienceClaim(
	claims: JsonObject,
): JoseResult<string | readonly string[] | undefined, 'invalid_claim'> {
	if (!Object.hasOwn(claims, 'aud')) return successResult(undefined);
	const value = claims.aud;
	if (typeof value === 'string') return successResult(value);
	if (!isJsonArray(value)) {
		return claimFailure('invalid_claim', 'Claim "aud" is neither a string nor an array', 'aud');
	}
	const audiences: string[] = [];
	for (const entry of value) {
		if (typeof entry !== 'string') {
			return claimFailure('invalid_claim', 'Claim "aud" holds a non-string', 'aud');
		}
		audiences.push(entry);
	}
	return successResult(audiences);
}

function registeredClaims(claims: JsonObject): JoseResult<RegisteredClaims, 'invalid_claim'> {
	const iss = stringClaim(claims, 'iss');
	if (!iss.ok) return iss;
	const sub = stringClaim(claims, 'sub');
	if (!sub.ok) return sub;
	const jti = stringClaim(claims, 'jti');
	if (!jti.ok) return jti;
	const aud = audienceClaim(claims);
	if (!aud.ok) return aud;
	const exp = numericDate(claims, 'exp');
	if (!exp.ok) return exp;
	const nbf = numericDate(claims, 'nbf');
	if (!nbf.ok) return nbf;
	const iat = numericDate(claims, 'iat');
	if (!iat.ok) return iat;
	return successResult({
		...(iss.value === undefined ? {} : { iss: iss.value }),
		...(sub.value === undefined ? {} : { sub: sub.value }),
		...(aud.value === undefined ? {} : { aud: aud.value }),
		...(exp.value === undefined ? {} : { exp: exp.value }),
		...(nbf.value === undefined ? {} : { nbf: nbf.value }),
		...(iat.value === undefined ? {} : { iat: iat.value }),
		...(jti.value === undefined ? {} : { jti: jti.value }),
	});
}

/** Claims policy validated once and copied, so later changes by the caller cannot alter a run. */
interface PreparedClaims {
	readonly issuers: readonly string[] | undefined;
	readonly audiences: readonly string[] | undefined;
	readonly required: readonly string[];
	readonly now: () => Date;
	readonly toleranceSeconds: number;
	readonly maxAgeSeconds: number | undefined;
	readonly allowFutureIssuedAt: boolean;
}

function expectedValues(
	expectation: unknown,
): JoseResult<readonly string[] | undefined, 'invalid_options'> {
	if (typeof expectation === 'string') return successResult([expectation]);
	if (isUncheckedPolicy(expectation)) return successResult(undefined);
	if (
		Array.isArray(expectation) &&
		expectation.length > 0 &&
		expectation.every((value) => typeof value === 'string')
	) {
		return successResult([...expectation]);
	}
	return joseFailure(
		'invalid_options',
		'issuer and audience need expected values or { unchecked: true }',
	);
}

function prepareClaims(policy: JwtClaimsPolicy): JoseResult<PreparedClaims, 'invalid_options'> {
	if (typeof policy !== 'object' || policy === null) {
		return joseFailure('invalid_options', 'A claims policy is required');
	}
	const tolerance = policy.clockToleranceSeconds ?? 0;
	if (
		typeof tolerance !== 'number' ||
		!Number.isFinite(tolerance) ||
		tolerance < 0 ||
		tolerance > MAX_CLOCK_TOLERANCE_SECONDS
	) {
		return joseFailure(
			'invalid_options',
			`clockToleranceSeconds must be between 0 and ${MAX_CLOCK_TOLERANCE_SECONDS}`,
		);
	}
	const maxAge = policy.maxAgeSeconds;
	if (
		maxAge !== undefined &&
		(typeof maxAge !== 'number' || !Number.isFinite(maxAge) || maxAge < 0)
	) {
		return joseFailure('invalid_options', 'maxAgeSeconds must be a non-negative number');
	}
	const required = policy.requiredClaims ?? ['exp'];
	if (!Array.isArray(required) || !required.every((name) => typeof name === 'string')) {
		return joseFailure('invalid_options', 'requiredClaims must be an array of strings');
	}
	if (
		policy.futureIssuedAt !== undefined &&
		policy.futureIssuedAt !== 'reject' &&
		policy.futureIssuedAt !== 'allow'
	) {
		return joseFailure('invalid_options', "futureIssuedAt must be 'reject' or 'allow'");
	}
	if (policy.now !== undefined && typeof policy.now !== 'function') {
		return joseFailure('invalid_options', 'now must be a function');
	}
	const issuers = expectedValues(policy.issuer);
	if (!issuers.ok) return issuers;
	const audiences = expectedValues(policy.audience);
	if (!audiences.ok) return audiences;
	return successResult({
		issuers: issuers.value,
		audiences: audiences.value,
		required: [...required],
		now: policy.now ?? (() => new Date()),
		toleranceSeconds: tolerance,
		maxAgeSeconds: maxAge,
		allowFutureIssuedAt: policy.futureIssuedAt === 'allow',
	});
}

function checkIdentity(
	registered: RegisteredClaims,
	policy: PreparedClaims,
): JoseErrorResult<VerifyJwtErrorCode> | undefined {
	const { issuers, audiences } = policy;
	if (
		issuers !== undefined &&
		(registered.iss === undefined || !issuers.includes(registered.iss))
	) {
		return claimFailure('issuer_mismatch', 'The token issuer is not accepted', 'iss');
	}
	if (audiences !== undefined) {
		const carried = typeof registered.aud === 'string' ? [registered.aud] : (registered.aud ?? []);
		if (!carried.some((entry) => audiences.includes(entry))) {
			return claimFailure('audience_mismatch', 'The token audience is not accepted', 'aud');
		}
	}
	return undefined;
}

function checkTimes(
	registered: RegisteredClaims,
	policy: PreparedClaims,
	nowSeconds: number,
): JoseErrorResult<VerifyJwtErrorCode> | undefined {
	const tolerance = policy.toleranceSeconds;
	const { exp, nbf, iat } = registered;
	if (exp !== undefined && nowSeconds >= exp + tolerance) {
		return claimFailure('expired', 'The token has expired', 'exp');
	}
	if (nbf !== undefined && nowSeconds < nbf - tolerance) {
		return claimFailure('not_yet_valid', 'The token is not valid yet', 'nbf');
	}
	if (iat !== undefined && !policy.allowFutureIssuedAt && iat - tolerance > nowSeconds) {
		return claimFailure('issued_in_future', 'The token was issued in the future', 'iat');
	}
	if (policy.maxAgeSeconds !== undefined) {
		if (iat === undefined) {
			return claimFailure('missing_claim', 'Claim "iat" is required by maxAgeSeconds', 'iat');
		}
		if (nowSeconds - iat > policy.maxAgeSeconds + tolerance) {
			return claimFailure('token_too_old', 'The token is older than the maximum age', 'iat');
		}
	}
	return undefined;
}

function clockSeconds(policy: PreparedClaims): JoseResult<number, 'invalid_options'> {
	let reading: unknown;
	try {
		reading = policy.now();
	} catch {
		return joseFailure('invalid_options', 'The claims clock threw');
	}
	if (!(reading instanceof Date) || !Number.isFinite(reading.getTime())) {
		return joseFailure('invalid_options', 'The claims clock did not return a valid Date');
	}
	return successResult(reading.getTime() / 1000);
}

function validateClaims(
	claims: JsonObject,
	policy: PreparedClaims,
): JoseResult<RegisteredClaims, VerifyJwtErrorCode> {
	for (const name of policy.required) {
		if (!Object.hasOwn(claims, name)) {
			return claimFailure('missing_claim', `Claim "${name}" is required`, name);
		}
	}
	const registered = registeredClaims(claims);
	if (!registered.ok) return registered;
	const identity = checkIdentity(registered.value, policy);
	if (identity !== undefined) return identity;
	const now = clockSeconds(policy);
	if (!now.ok) return now;
	const times = checkTimes(registered.value, policy, now.value);
	if (times !== undefined) return times;
	return registered;
}

/**
 * Verifies a JWT: the signature and `tokenType` policy as {@linkcode verifyCompactJws} applies
 * them, then the payload as a duplicate-free JSON object, then `claims`.
 *
 * `iss` and `aud` must be stated explicitly. Time claims follow RFC 7519 §4.1.4 and §4.1.5: the
 * token is expired when the clock is at or after `exp` and not yet valid when it is before
 * `nbf`, each moved by `clockToleranceSeconds`. Time claims must be JSON numbers; strings are never
 * coerced. `exp` is required unless `requiredClaims` says otherwise.
 */
export async function verifyJwt(
	token: string,
	options: VerifyJwtOptions,
): Promise<JoseResult<VerifiedJwt, VerifyJwtErrorCode>> {
	if (typeof options !== 'object' || options === null) {
		return joseFailure('invalid_options', 'Verification options are required');
	}
	const claimsPolicy = prepareClaims(options.claims);
	if (!claimsPolicy.ok) return claimsPolicy;
	const prepared = prepareVerify(options);
	if (!prepared.ok) return prepared;
	const jws = await verifyPrepared(token, prepared.value);
	if (!jws.ok) return jws;
	const claims = decodeClaims(jws.value.header, jws.value.payload, prepared.value.limits);
	if (!claims.ok) return claims;
	const registered = validateClaims(claims.value, claimsPolicy.value);
	if (!registered.ok) return registered;
	return successResult({
		verified: true,
		header: jws.value.header,
		claims: claims.value,
		registered: registered.value,
	});
}

/**
 * Signs a JWT. The header carries `typ: "JWT"` unless `header.typ` says otherwise.
 *
 * Throws a `ResultError` coded `SignJoseErrorCode` for an unusable key, algorithm or header, and
 * `invalid_claims` when `claims` cannot be serialized.
 */
export async function signJwt(input: SignJwtInput): Promise<string> {
	let payload: string | undefined;
	try {
		payload = JSON.stringify(input.claims);
	} catch {
		payload = undefined;
	}
	if (typeof payload !== 'string') {
		return throwMicro509Error('invalid_claims', 'JWT claims are not JSON-serializable');
	}
	const { claims: _claims, ...rest } = input;
	return await signCompactJws({
		...rest,
		payload: new TextEncoder().encode(payload),
		header: { typ: 'JWT', ...input.header },
	});
}
