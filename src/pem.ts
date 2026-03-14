/**
 * PEM and base64 helpers used across the public API.
 *
 * Encodes, decodes, splits, and categorizes PEM blocks as defined by
 * RFC 7468.
 *
 * @module
 */

/** A single decoded PEM block with its label, decoded DER bytes, and original PEM text. */
export interface PemBlock {
	/** RFC 7468 label between the `BEGIN` / `END` markers (e.g. `"CERTIFICATE"`). */
	readonly label: string;
	/** Decoded DER content of this block. */
	readonly bytes: Uint8Array;
	/** The original PEM text including `BEGIN`/`END` lines. */
	readonly pem: string;
}

/**
 * PEM blocks grouped by their label into well-known PKI categories.
 * Blocks that don't match any known label land in {@link others}.
 */
export interface CategorizedPemBlocks {
	/** Blocks with label `CERTIFICATE`. */
	readonly certificates: readonly PemBlock[];
	/** Blocks with label `CERTIFICATE REQUEST`. */
	readonly certificateRequests: readonly PemBlock[];
	/** Blocks with label `PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`. */
	readonly privateKeys: readonly PemBlock[];
	/** Blocks with label `PUBLIC KEY`. */
	readonly publicKeys: readonly PemBlock[];
	/** Blocks whose label doesn't match any of the above categories. */
	readonly others: readonly PemBlock[];
}

/**
 * Wraps DER bytes in a PEM envelope with 64-character base64 lines.
 *
 * @param label PEM type label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).
 * @param der Raw DER-encoded content.
 */
export function pemEncode(label: string, der: Uint8Array): string {
	const body = base64Encode(der);
	const lines = body.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/** Encodes raw bytes to a standard base64 string (no line breaks). */
export function base64Encode(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

/**
 * Extracts and base64-decodes the DER content from a PEM string.
 * Throws if the `BEGIN`/`END` markers don't match `label`.
 *
 * @param label Expected PEM type label.
 * @param pem PEM-encoded text (may contain `\r`).
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

/** Decodes a standard base64 string to raw bytes. */
export function base64Decode(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns
 * them as parsed {@link PemBlock} entries. Handles concatenated PEM files
 * and ignores non-PEM text between blocks.
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
 * Groups PEM blocks by label into well-known PKI categories
 * (certificates, CSRs, private keys, public keys, and everything else).
 * Accepts either raw PEM text or pre-split {@link PemBlock} entries.
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
