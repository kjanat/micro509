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
	return bytes;
}
