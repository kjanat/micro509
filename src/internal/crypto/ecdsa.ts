/**
 * ECDSA signature encoding conversion between ASN.1 DER (r, s INTEGER) and the
 * fixed-width raw format used by WebCrypto.
 *
 * @module
 */

import { integer, readSequenceChildren, sequence } from '#micro509/internal/asn1/der.ts';

/** Convert a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs) to fixed-width raw `r || s`. */
export function derEcdsaSignatureToRaw(signature: Uint8Array, partLength: number): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error('Malformed ECDSA DER signature');
	}
	return concatFixedWidth(trimLeadingZero(r.value), trimLeadingZero(s.value), partLength);
}

/** Convert a fixed-width raw `r || s` ECDSA signature to DER-encoded SEQUENCE of two INTEGERs. */
export function rawEcdsaSignatureToDer(signature: Uint8Array, partLength: number): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error('Unexpected ECDSA raw signature length');
	}
	return sequence([integer(signature.slice(0, partLength)), integer(signature.slice(partLength))]);
}

/**
 * Try the opposite ECDSA encoding: DER→raw or raw→DER.
 *
 * Returns `undefined` if conversion fails, letting callers retry verification
 * with the alternate encoding.
 */
export function alternateEcdsaSignatureEncoding(
	signature: Uint8Array,
	partLength: number,
): Uint8Array | undefined {
	try {
		if (signature[0] === 0x30) {
			return derEcdsaSignatureToRaw(signature, partLength);
		}
		return rawEcdsaSignatureToDer(signature, partLength);
	} catch {
		return undefined;
	}
}

/** Left-pad and concatenate `r` and `s` into a fixed-width `partLength * 2` byte buffer. */
export function concatFixedWidth(
	left: Uint8Array,
	right: Uint8Array,
	partLength: number,
): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error('ECDSA signature integer too large');
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
}

/** Strip leading zero bytes from a DER INTEGER value, keeping at least one byte. */
function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}
