/**
 * Typed failures shared by the JOSE parsing, verification and key-resolution APIs.
 *
 * @module
 */

import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult } from '#micro509/result/result';

/** Longest `kid` echoed into {@linkcode JoseErrorDetails}. */
const MAX_REPORTED_KID_LENGTH = 64;

/** Reasons a compact serialization is refused before any signature is checked. */
export type JwsParseErrorCode =
	| 'token_too_large'
	| 'malformed_token'
	| 'invalid_encoding'
	| 'invalid_utf8'
	| 'invalid_json'
	| 'duplicate_member'
	| 'limit_exceeded'
	| 'invalid_header'
	| 'unsupported_critical_header'
	| 'unsupported_unencoded_payload'
	| 'unsupported_nested_jwt'
	| 'invalid_payload';

/** Reasons a signing key cannot be resolved for a token. */
export type KeyResolutionErrorCode =
	| 'key_not_found'
	| 'ambiguous_key'
	| 'key_unsuitable'
	| 'key_resolution_failed'
	| 'jwks_unavailable'
	| 'jwks_malformed'
	| 'aborted';

/** Reasons a well-formed token is refused by the verification policy or its signature. */
export type JwsPolicyErrorCode =
	| 'invalid_options'
	| 'unsigned_token'
	| 'algorithm_not_allowed'
	| 'token_type_mismatch'
	| 'invalid_signature';

/** Reasons a signature-verified token fails the claims policy. */
export type JwtClaimsErrorCode =
	| 'missing_claim'
	| 'invalid_claim'
	| 'issuer_mismatch'
	| 'audience_mismatch'
	| 'expired'
	| 'not_yet_valid'
	| 'issued_in_future'
	| 'token_too_old';

/** Failure codes of {@linkcode verifyCompactJws}. */
export type VerifyJwsErrorCode = JwsParseErrorCode | KeyResolutionErrorCode | JwsPolicyErrorCode;

/** Failure codes of {@linkcode verifyJwt}. */
export type VerifyJwtErrorCode = VerifyJwsErrorCode | JwtClaimsErrorCode;

/** Every code a JOSE API reports. */
export type JoseErrorCode = VerifyJwtErrorCode;

/**
 * Structured context for a failure. Holds names and short identifiers only, never token
 * segments, claim values or key material.
 */
export interface JoseErrorDetails {
	/** The `alg` header value the token carried. */
	readonly alg?: string;
	/** The `kid` header value the token carried, truncated to 64 characters. */
	readonly kid?: string;
	/** The claim name a claims failure concerns. */
	readonly claim?: string;
	/** The critical header names that were refused. */
	readonly crit?: readonly string[];
	/** The HTTP status a JWKS endpoint answered with. */
	readonly status?: number;
}

/** Failure payload of the JOSE APIs. */
export interface JoseFailure<TCode extends string = JoseErrorCode>
	extends Micro509Error<TCode, JoseErrorDetails> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** A flattened failed result carrying a {@linkcode JoseFailure}. */
export type JoseErrorResult<TCode extends string = JoseErrorCode> = ErrorResult<
	TCode,
	JoseErrorDetails,
	JoseFailure<TCode>
>;

/** Success-or-failure result of a JOSE API. */
export type JoseResult<TValue, TCode extends string = JoseErrorCode> =
	| { readonly ok: true; readonly value: TValue }
	| JoseErrorResult<TCode>;

/** Builds a failed result, truncating any reported `kid`. */
export function joseFailure<TCode extends JoseErrorCode>(
	code: TCode,
	message: string,
	details?: JoseErrorDetails,
): JoseErrorResult<TCode> {
	return failureResult(
		code,
		message,
		details?.kid === undefined
			? details
			: { ...details, kid: details.kid.slice(0, MAX_REPORTED_KID_LENGTH) },
	);
}
