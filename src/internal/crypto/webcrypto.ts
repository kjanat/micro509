/**
 * Shared WebCrypto runtime access helper.
 *
 * @module
 */

/** Return the global `Crypto` object. Throws when WebCrypto is unavailable. */
export function getCrypto(): Crypto {
	const c = globalThis.crypto;
	if (c?.subtle === undefined) {
		throw new Error('WebCrypto subtle API is required');
	}
	return c;
}
