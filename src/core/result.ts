export type Result<TValue, TError> =
	| { readonly ok: true; readonly value: TValue }
	| { readonly ok: false; readonly error: TError };

export interface ErrorResult<
	TCode extends string,
	TDetails,
	TError extends Micro509Error<TCode, TDetails>,
> {
	readonly ok: false;
	readonly error: TError;
	readonly code: TCode;
	readonly message: string;
	readonly details?: TDetails | undefined;
}

export interface IndexedErrorResult<
	TCode extends string,
	TDetails,
	TError extends IndexedMicro509Error<TCode, TDetails>,
> extends ErrorResult<TCode, TDetails, TError> {
	readonly index?: number | undefined;
}

export interface Micro509Error<TCode extends string, TDetails = Record<never, never>> {
	readonly code: TCode;
	readonly message: string;
	readonly details?: TDetails;
}

export interface IndexedMicro509Error<TCode extends string, TDetails = Record<never, never>>
	extends Micro509Error<TCode, TDetails> {
	readonly index?: number;
}

export function successResult<TValue>(value: TValue): {
	readonly ok: true;
	readonly value: TValue;
} {
	return { ok: true, value };
}

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
