/**
 * Public result and error types shared across validation-heavy APIs.
 *
 * This module exposes the canonical success and failure shapes returned by the library's
 * result-oriented functions.
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
