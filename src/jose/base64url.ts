/** Public byte-oriented JOSE base64url codecs. @module */
import {
	base64UrlDecode as decode,
	base64UrlEncode as encode,
} from '#micro509/internal/jose/base64url';

/** Encodes bytes as canonical unpadded base64url; does not encode text. */
export function base64UrlEncode(bytes: Uint8Array): string {
	return encode(bytes);
}

/** Decodes canonical unpadded base64url, or returns `undefined` for invalid/noncanonical input. Empty input yields empty bytes. */
export function base64UrlDecode(value: string): Uint8Array | undefined {
	return decode(value);
}
