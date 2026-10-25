const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const DECODE_TABLE: Int8Array = (() => {
	const table = new Int8Array(128).fill(-1);
	for (let index = 0; index < ALPHABET.length; index++) {
		table[ALPHABET.charCodeAt(index)] = index;
	}
	return table;
})();

/** Encodes bytes as unpadded base64url (RFC 4648 §5, RFC 7515 §2). */
export function base64UrlEncode(bytes: Uint8Array): string {
	let out = '';
	let index = 0;
	for (; index + 2 < bytes.length; index += 3) {
		const chunk =
			(bytes[index] ?? 0) * 65536 + (bytes[index + 1] ?? 0) * 256 + (bytes[index + 2] ?? 0);
		out += ALPHABET[(chunk >> 18) & 63] ?? '';
		out += ALPHABET[(chunk >> 12) & 63] ?? '';
		out += ALPHABET[(chunk >> 6) & 63] ?? '';
		out += ALPHABET[chunk & 63] ?? '';
	}
	const remaining = bytes.length - index;
	if (remaining === 1) {
		const chunk = (bytes[index] ?? 0) * 65536;
		out += ALPHABET[(chunk >> 18) & 63] ?? '';
		out += ALPHABET[(chunk >> 12) & 63] ?? '';
	} else if (remaining === 2) {
		const chunk = (bytes[index] ?? 0) * 65536 + (bytes[index + 1] ?? 0) * 256;
		out += ALPHABET[(chunk >> 18) & 63] ?? '';
		out += ALPHABET[(chunk >> 12) & 63] ?? '';
		out += ALPHABET[(chunk >> 6) & 63] ?? '';
	}
	return out;
}

/**
 * Decodes canonical unpadded base64url. Returns `undefined` for any character outside the URL-safe
 * alphabet, padding, whitespace, an impossible length, or non-zero trailing bits.
 */
export function base64UrlDecode(value: string): Uint8Array | undefined {
	const remainder = value.length % 4;
	if (remainder === 1) return undefined;
	const bytes = new Uint8Array(Math.floor((value.length * 3) / 4));
	let written = 0;
	let buffer = 0;
	let bits = 0;
	for (let index = 0; index < value.length; index++) {
		const code = value.charCodeAt(index);
		const sextet = code < 128 ? (DECODE_TABLE[code] ?? -1) : -1;
		if (sextet < 0) return undefined;
		buffer = (buffer << 6) | sextet;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			bytes[written++] = (buffer >> bits) & 0xff;
			buffer &= (1 << bits) - 1;
		}
	}
	if (buffer !== 0) return undefined;
	return bytes;
}
