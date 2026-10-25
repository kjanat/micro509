/**
 * Optional JOSE surface: signed compact JWS and JWT (RS256), JWK Sets, and opt-in remote JWKS
 * resolution. Importing this entrypoint performs no network access.
 *
 * Start with {@linkcode verifyJwt} for tokens, {@linkcode createJwksKeyResolver} for a local
 * JWK Set, and {@linkcode createRemoteJwksKeyResolver} to read keys from a trusted URL.
 *
 * @module micro509/jose
 */

export type { JsonObject, JsonValue } from '#micro509/internal/jose/strict-json';
export type {
	JoseErrorCode,
	JoseErrorDetails,
	JoseErrorResult,
	JoseFailure,
	JoseResult,
	JwsParseErrorCode,
	JwsPolicyErrorCode,
	JwtClaimsErrorCode,
	KeyResolutionErrorCode,
	VerifyJwsErrorCode,
	VerifyJwtErrorCode,
} from '#micro509/jose/errors';
export type {
	JwkEntry,
	JwkEntryBase,
	JwkMetadata,
	JwkSelector,
	Jwks,
	JwksLimits,
	ParseJwksErrorCode,
	RsaJwkEntry,
	UnsupportedJwkEntry,
} from '#micro509/jose/jwks';
export {
	createJwksKeyResolver,
	DEFAULT_JWKS_LIMITS,
	importJwkEntry,
	parseJwks,
	selectJwk,
} from '#micro509/jose/jwks';
export type {
	JoseLimits,
	JwsAlgorithm,
	JwsHeader,
	JwsHeaderInput,
	JwsKeyRequest,
	JwsKeyResolver,
	SignJoseErrorCode,
	SignJwsInput,
	TokenTypePolicy,
	Unchecked,
	UnverifiedJws,
	VerifiedJws,
	VerifyJwsOptions,
} from '#micro509/jose/jws';
export {
	DEFAULT_JOSE_LIMITS,
	JWS_ALGORITHMS,
	MIN_RS256_MODULUS_BITS,
	parseCompactJws,
	signCompactJws,
	verifyCompactJws,
} from '#micro509/jose/jws';
export type {
	FutureIssuedAtPolicy,
	JwtClaimsPolicy,
	RegisteredClaims,
	SignJwtInput,
	UnverifiedJwt,
	VerifiedJwt,
	VerifyJwtOptions,
} from '#micro509/jose/jwt';
export {
	decodeJwtUnverified,
	MAX_CLOCK_TOLERANCE_SECONDS,
	signJwt,
	verifyJwt,
} from '#micro509/jose/jwt';
export type {
	JwksRequestInit,
	JwksTransport,
	RemoteJwksConfig,
	RemoteJwksConfigErrorCode,
	RemoteJwksRedirectPolicy,
} from '#micro509/jose/remote-jwks';
export { createRemoteJwksKeyResolver } from '#micro509/jose/remote-jwks';
