/**
 * Internal result helper types and constructors shared by low-level modules.
 *
 * Mirrors the public result model without depending on the public barrel.
 *
 * @module
 */

/**
 * Discriminated `ok` union: either `{ ok: true; value }` or `{ ok: false; error }`.
 *
 * Every fallible public API in micro509 returns a specialization of this type.
 */
export type Result<TValue, TError> =
	| {
			/** Operation succeeded. */
			readonly ok: true;
			/** Successful payload. */
			readonly value: TValue;
	  }
	| {
			/** Operation failed. */
			readonly ok: false;
			/** Structured error payload. */
			readonly error: TError;
	  };

/** Failed result with a flattened code/message/details surface for ergonomic matching. */
export interface ErrorResult<
	TCode extends string,
	TDetails,
	TError extends Micro509Error<TCode, TDetails>,
> {
	/** Always `false` for failures. */
	readonly ok: false;
	/** Structured error payload. */
	readonly error: TError;
	/** Machine-readable failure reason, mirrored from `error.code`. */
	readonly code: TCode;
	/** Human-readable diagnostic, mirrored from `error.message`. */
	readonly message: string;
	/** Optional structured context for the failure. */
	readonly details?: TDetails | undefined;
}

/** Like {@link ErrorResult} but also carries an index into the collection that was being processed. */
export interface IndexedErrorResult<
	TCode extends string,
	TDetails,
	TError extends IndexedMicro509Error<TCode, TDetails>,
> extends ErrorResult<TCode, TDetails, TError> {
	/** Zero-based position of the failing item in the input collection. */
	readonly index?: number | undefined;
}

/** Base error shape carried by all failure results in the library. */
export interface Micro509Error<TCode extends string, TDetails = Record<never, never>> {
	/** Machine-readable failure reason (e.g. `'malformed'`, `'expired'`). */
	readonly code: TCode;
	/** Human-readable diagnostic message. */
	readonly message: string;
	/** Optional structured context for the failure. */
	readonly details?: TDetails;
}

/** Like {@link Micro509Error} but includes a positional index for collection-processing APIs. */
export interface IndexedMicro509Error<TCode extends string, TDetails = Record<never, never>>
	extends Micro509Error<TCode, TDetails> {
	/** Zero-based position of the failing item in the input collection. */
	readonly index?: number;
}

/** Wraps a value in a success result (`{ ok: true, value }`). */
export function successResult<TValue>(value: TValue): {
	readonly ok: true;
	readonly value: TValue;
} {
	return { ok: true, value };
}

/**
 * Error thrown by {@link unwrap} when a result is a failure.
 *
 * Carries the structured {@link Micro509Error} payload so callers using the
 * throwing escape hatch still get the machine-readable `code` and any details.
 */
export interface ResultError<
	TError extends Micro509Error<string, unknown> = Micro509Error<string, unknown>,
> extends Error {
	/** Machine-readable failure reason, mirrored from `error.code`. */
	readonly code: TError['code'];
	/** The structured error payload that produced this exception. */
	readonly error: TError;
}

/** Module-private brand so {@link isResultError} cannot be fooled by look-alike objects. */
const resultErrorBrand = Symbol('micro509.ResultError');

/** Builds a {@link ResultError}: a branded `Error` (no class) carrying the structured failure. */
function makeResultError<TError extends Micro509Error<string, unknown>>(
	error: TError,
): ResultError<TError> {
	return Object.assign(new Error(`${error.code}: ${error.message}`), {
		name: 'ResultError',
		code: error.code,
		error,
		[resultErrorBrand]: true,
	});
}

/** Type guard: was `value` thrown by {@link unwrap}? Narrows to {@link ResultError}. */
export function isResultError(value: unknown): value is ResultError {
	return value instanceof Error && resultErrorBrand in value;
}

/** A minimal fallible-result shape: `{ ok: true, value }` or `{ ok: false, error }`. */
type UnwrappableResult<TValue, TError> =
	| { readonly ok: true; readonly value: TValue }
	| { readonly ok: false; readonly error: TError };

/**
 * Explicit escape hatch: returns the success value, or throws a
 * {@link ResultError} carrying the structured failure.
 *
 * Use when you have already validated the input (or prefer exceptions) and the
 * Result ceremony is noise. Accepts any of the library's `*Result` types.
 */
export function unwrap<TValue, TError extends Micro509Error<string, unknown>>(
	result: UnwrappableResult<TValue, TError>,
): TValue {
	if (result.ok) {
		return result.value;
	}
	throw makeResultError(result.error);
}

/** Returns the success value, or `fallback` when the result is a failure. */
export function unwrapOr<TValue>(
	result: UnwrappableResult<TValue, unknown>,
	fallback: TValue,
): TValue {
	return result.ok ? result.value : fallback;
}

/** Constructs a {@link Micro509Error} payload. */
export function micro509Error<TCode extends string, TDetails = Record<never, never>>(
	code: TCode,
	message: string,
	details?: TDetails,
): Micro509Error<TCode, TDetails> {
	return {
		code,
		message,
		...(details === undefined ? {} : { details }),
	};
}

/** Constructs an {@link IndexedMicro509Error} payload with an optional collection index. */
export function indexedMicro509Error<TCode extends string, TDetails = Record<never, never>>(
	code: TCode,
	message: string,
	index?: number,
	details?: TDetails,
): IndexedMicro509Error<TCode, TDetails> {
	return {
		code,
		message,
		...(index === undefined ? {} : { index }),
		...(details === undefined ? {} : { details }),
	};
}

/** Wraps a {@link Micro509Error} in a flattened {@link ErrorResult}. */
export function errorResult<
	TCode extends string,
	TDetails,
	TError extends Micro509Error<TCode, TDetails>,
>(error: TError): ErrorResult<TCode, TDetails, TError> {
	return {
		ok: false,
		error,
		code: error.code,
		message: error.message,
		...(error.details === undefined ? {} : { details: error.details }),
	};
}

/**
 * Builds a flattened failure result in one step.
 *
 * Single source of truth for the `{ ok: false, error, code, message }` shape:
 * modules should construct failures with this instead of hand-rolling the
 * object literal. The `error` payload carries the redundant `ok: false`
 * discriminant so it matches the per-operation `*Failure` interfaces
 * (`interface XFailure extends Micro509Error<…> { ok: false }`).
 */
export function failureResult<TCode extends string, TDetails = Record<never, never>>(
	code: TCode,
	message: string,
	details?: TDetails,
): ErrorResult<TCode, TDetails, Micro509Error<TCode, TDetails> & { readonly ok: false }> {
	return errorResult({ ok: false, ...micro509Error(code, message, details) });
}

/** Wraps an {@link IndexedMicro509Error} in a flattened {@link IndexedErrorResult}. */
export function indexedErrorResult<
	TCode extends string,
	TDetails,
	TError extends IndexedMicro509Error<TCode, TDetails>,
>(error: TError): IndexedErrorResult<TCode, TDetails, TError> {
	return {
		ok: false,
		error,
		code: error.code,
		message: error.message,
		...(error.details === undefined ? {} : { details: error.details }),
		...(error.index === undefined ? {} : { index: error.index }),
	};
}
