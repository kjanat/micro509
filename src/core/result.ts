export type Result<TValue, TError> =
	| { readonly ok: true; readonly value: TValue }
	| { readonly ok: false; readonly error: TError };

export interface Micro509Error<TCode extends string, TDetails = Record<never, never>> {
	readonly code: TCode;
	readonly message: string;
	readonly details?: TDetails;
}

export interface IndexedMicro509Error<TCode extends string, TDetails = Record<never, never>>
	extends Micro509Error<TCode, TDetails> {
	readonly index?: number;
}
