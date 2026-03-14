/**
 * Internal result helper types and constructors shared by low-level modules.
 * This module mirrors the public result model without depending on the public barrel.
 */

/**
 * Represents the canonical success-or-failure result shape used by the library.
 */
export type Result<TValue, TError> =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: TValue;
	  }
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: false;
			/**
			 * Carries the canonical error payload.
			 */
			readonly error: TError;
	  };

/**
 * Represents a failed result carrying one typed error payload.
 */
export interface ErrorResult<
	TCode extends string,
	TDetails,
	TError extends Micro509Error<TCode, TDetails>,
> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the canonical error payload.
	 */
	readonly error: TError;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: TCode;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
	/**
	 * Carries structured details for the current failure.
	 */
	readonly details?: TDetails | undefined;
}

/**
 * Represents a failed result that also carries an index into the processed collection.
 */
export interface IndexedErrorResult<
	TCode extends string,
	TDetails,
	TError extends IndexedMicro509Error<TCode, TDetails>,
> extends ErrorResult<TCode, TDetails, TError> {
	/**
	 * Carries the zero-based index associated with this value.
	 */
	readonly index?: number | undefined;
}

/**
 * Represents the canonical typed error payload used by public result APIs.
 */
export interface Micro509Error<TCode extends string, TDetails = Record<never, never>> {
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: TCode;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
	/**
	 * Carries structured details for the current failure.
	 */
	readonly details?: TDetails;
}

/**
 * Represents a canonical typed error payload with an associated index.
 */
export interface IndexedMicro509Error<TCode extends string, TDetails = Record<never, never>>
	extends Micro509Error<TCode, TDetails> {
	/**
	 * Carries the zero-based index associated with this value.
	 */
	readonly index?: number;
}

/**
 * Success result.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function successResult<TValue>(value: TValue): {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: TValue;
} {
	return { ok: true, value };
}

/**
 * Micro509 error.
 *
 * @param code The code value.
 * @param message The message value.
 * @param details The structured details value.
 * @returns The computed value.
 */
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

/**
 * Indexed micro509 error.
 *
 * @param code The code value.
 * @param message The message value.
 * @param index The index value.
 * @param details The structured details value.
 * @returns The computed value.
 */
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

/**
 * Error result.
 *
 * @param error The error value.
 * @returns The computed value.
 */
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
 * Indexed error result.
 *
 * @param error The error value.
 * @returns The computed value.
 */
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
