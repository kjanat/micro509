/**
 * Typed refusals a decoder throws for input it does not call malformed: an
 * implementation limit, or a construct micro509 does not decode.
 *
 * @module
 */

import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, isResultError, throwMicro509Error } from '#micro509/result/result';

/** Codes a decoder throws besides `malformed`. */
export type DecodeRefusalCode = 'unsupported' | 'limit_exceeded';

/** Every refusal code, for boundaries whose input carries both. */
export const DECODE_REFUSAL_CODES: readonly ['unsupported', 'limit_exceeded'] = [
	'unsupported',
	'limit_exceeded',
];

/** The limit code alone, for boundaries whose input carries no text. */
export const DECODE_LIMIT_CODES: readonly ['limit_exceeded'] = ['limit_exceeded'];

/** Throws a {@link ResultError} carrying a decode refusal. */
export function throwDecodeRefusal(code: DecodeRefusalCode, message: string): never {
	return throwMicro509Error<DecodeRefusalCode>(code, message);
}

/** The refusal `error` carries when its code is one of `codes`. */
export function decodeRefusalOf<TCode extends DecodeRefusalCode>(
	error: unknown,
	codes: readonly TCode[],
): { readonly code: TCode; readonly message: string } | undefined {
	if (!isResultError(error)) {
		return undefined;
	}
	const code = codes.find((candidate) => candidate === error.code);
	return code === undefined ? undefined : { code, message: error.error.message };
}

/** A boundary's failure for a thrown decode error: its refusal, else `malformed` with its message. */
export function decodeFailureResult<TCode extends DecodeRefusalCode>(
	error: unknown,
	codes: readonly TCode[],
	fallback: string,
): ErrorResult<
	'malformed' | TCode,
	Record<never, never>,
	Micro509Error<'malformed' | TCode> & { readonly ok: false }
> {
	const refusal = decodeRefusalOf(error, codes);
	return refusal === undefined
		? failureResult<'malformed' | TCode>(
				'malformed',
				error instanceof Error ? error.message : fallback,
			)
		: failureResult<'malformed' | TCode>(refusal.code, refusal.message);
}
