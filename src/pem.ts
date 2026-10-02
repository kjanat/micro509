/**
 * Canonical PEM boundary surface.
 * Owns the stable `micro509/pem` entrypoint.
 *
 * @module micro509/pem
 */

export type {
	CategorizedPemBlocks,
	CategorizePemBlocksResult,
	PemBlock,
	PemDecodeResult,
	PemErrorCode,
	PemFailure,
	SplitPemBlocksResult,
} from '#micro509/pem/pem';
export {
	categorizePemBlocks,
	categorizePemBlocksOrThrow,
	pemDecode,
	pemDecodeOrThrow,
	pemEncode,
	splitPemBlocks,
	splitPemBlocksOrThrow,
} from '#micro509/pem/pem';
