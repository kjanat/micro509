/**
 * Canonical shared result surface.
 * Owns the stable `micro509/result` entrypoint.
 * @module
 */

export type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
	Result,
	ResultError,
	UnwrappableResult,
} from './result.ts';
export {
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
} from './result.ts';
