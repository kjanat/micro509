/** Encode raw bytes as standard base64 without line breaks. */
export function base64Encode(bytes: Uint8Array): string {
	const parts: string[] = [];
	for (const byte of bytes) {
		parts.push(String.fromCharCode(byte));
	}
	return btoa(parts.join(''));
}

/** Decode a standard base64 string into raw bytes. */
export function base64Decode(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	assertCanonicalFinalQuantum(value, bytes);
	return bytes;
}

/** RFC 4648 §4 completes a final quantum with pad characters and bits of value zero. */
function assertCanonicalFinalQuantum(value: string, bytes: Uint8Array): void {
	const compact = value.replace(/[\t\n\f\r ]/g, '');
	if (compact.length % 4 !== 0) {
		throw new Error('Base64 final quantum is missing its padding');
	}
	if (compact.length === 0) {
		return;
	}
	const finalQuantum = bytes.slice(bytes.length - (((bytes.length - 1) % 3) + 1));
	if (base64Encode(finalQuantum) !== compact.slice(-4)) {
		throw new Error('Base64 final quantum has non-zero pad bits');
	}
}
