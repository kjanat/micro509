/**
 * Canonical shared result surface.
 * Owns the stable `micro509/result` entrypoint.
 *
 * @module micro509/result
 */

export type {
	DecodeFailureCode,
	DecodeRefusalCode,
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
	Result,
	ResultError,
	UnwrappableResult,
} from '#micro509/result/result';
export {
	DECODE_REFUSAL_CODES,
	errorResult,
	failureResult,
	indexedErrorResult,
	indexedMicro509Error,
	isResultError,
	micro509Error,
	rethrowIfInvariant,
	successResult,
	unwrap,
	unwrapOr,
} from '#micro509/result/result';
