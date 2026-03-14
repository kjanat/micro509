/**
 * Canonical result and error types for the library's fallible APIs.
 *
 * Re-exports the success/failure discriminated unions and error constructors
 * used by every result-returning function in micro509.
 *
 * @module
 */

export type {
	ErrorResult,
	IndexedErrorResult,
	IndexedMicro509Error,
	Micro509Error,
	Result,
} from './core/result.ts';
export {
	errorResult,
	indexedErrorResult,
	indexedMicro509Error,
	micro509Error,
	successResult,
} from './core/result.ts';
