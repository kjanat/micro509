/**
 * PEM and base64 helpers used across the public API.
 *
 * This module encodes, decodes, splits, and categorizes PEM blocks.
 */

/**
 * Describes PEM block.
 */
export interface PemBlock {
	/**
	 * Carries the label value.
	 */
	readonly label: string;
	/**
	 * Carries the bytes value.
	 */
	readonly bytes: Uint8Array;
	/**
	 * Carries the pem value.
	 */
	readonly pem: string;
}

/**
 * Describes categorized PEM blocks.
 */
export interface CategorizedPemBlocks {
	/**
	 * Carries the certificates value.
	 */
	readonly certificates: readonly PemBlock[];
	/**
	 * Carries the certificate requests value.
	 */
	readonly certificateRequests: readonly PemBlock[];
	/**
	 * Carries the private keys value.
	 */
	readonly privateKeys: readonly PemBlock[];
	/**
	 * Carries the public keys value.
	 */
	readonly publicKeys: readonly PemBlock[];
	/**
	 * Carries the others value.
	 */
	readonly others: readonly PemBlock[];
}

/**
 * PEM encode.
 *
 * @param label The label value.
 * @param der The DER-encoded bytes.
 * @returns The computed value.
 */
export function pemEncode(label: string, der: Uint8Array): string {
	const body = base64Encode(der);
	const lines = body.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/**
 * Base64 encode.
 *
 * @param bytes The raw bytes to process.
 * @returns The computed value.
 */
export function base64Encode(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

/**
 * PEM decode.
 *
 * @param label The label value.
 * @param pem The PEM-encoded text.
 * @returns The computed value.
 */
export function pemDecode(label: string, pem: string): Uint8Array {
	const normalized = pem.replace(/\r/g, '').trim();
	const begin = `-----BEGIN ${label}-----`;
	const end = `-----END ${label}-----`;
	if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
		throw new Error(`Invalid PEM for ${label}`);
	}
	const body = normalized
		.slice(begin.length, normalized.length - end.length)
		.replace(/\n/g, '')
		.trim();
	return base64Decode(body);
}

/**
 * Base64 decode.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
export function base64Decode(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Split PEM blocks.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
export function splitPemBlocks(input: string): readonly PemBlock[] {
	const normalized = input.replace(/\r/g, '');
	return Array.from(
		normalized.matchAll(/-----BEGIN ([^-]+)-----[\s\S]*?-----END \1-----/g),
		(match) => {
			const pem = match[0];
			const label = match[1];
			if (pem === undefined || label === undefined) {
				throw new Error('Invalid PEM block match');
			}
			return {
				label,
				bytes: pemDecode(label, pem),
				pem,
			};
		},
	);
}

/**
 * Categorize PEM blocks.
 *
 * @param input The typed input payload.
 * @returns The computed value.
 */
export function categorizePemBlocks(input: string | readonly PemBlock[]): CategorizedPemBlocks {
	const blocks = typeof input === 'string' ? splitPemBlocks(input) : input;
	const certificates: PemBlock[] = [];
	const certificateRequests: PemBlock[] = [];
	const privateKeys: PemBlock[] = [];
	const publicKeys: PemBlock[] = [];
	const others: PemBlock[] = [];

	for (const block of blocks) {
		switch (block.label) {
			case 'CERTIFICATE':
				certificates.push(block);
				break;
			case 'CERTIFICATE REQUEST':
				certificateRequests.push(block);
				break;
			case 'PRIVATE KEY':
			case 'RSA PRIVATE KEY':
			case 'EC PRIVATE KEY':
				privateKeys.push(block);
				break;
			case 'PUBLIC KEY':
				publicKeys.push(block);
				break;
			default:
				others.push(block);
		}
	}

	return { certificates, certificateRequests, privateKeys, publicKeys, others };
}
