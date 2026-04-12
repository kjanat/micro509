/**
 * PEM helpers used across the public API.
 *
 * Encodes, decodes, splits, and categorizes PEM blocks as defined by
 * RFC 7468.
 *
 * @module
 */

import { base64Decode, base64Encode } from '#micro509/internal/shared/base64.ts';

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
 * Blocks that don't match any known label land in {@linkcode others}.
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
	const lines = normalized.split('\n');
	if (lines[0] !== begin || lines[lines.length - 1] !== end || lines.length < 3) {
		throw new Error(`Invalid PEM for ${label}`);
	}
	const bodyLines = normalizePemBodyLines(lines.slice(1, -1));
	if (bodyLines === undefined) {
		throw new Error(`Invalid PEM for ${label}`);
	}
	try {
		return base64Decode(bodyLines.join(''));
	} catch {
		throw new Error(`Invalid PEM for ${label}`);
	}
}

/**
 * Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns
 * them as parsed {@linkcode PemBlock} entries. Handles concatenated PEM files
 * and ignores non-PEM text between blocks.
 */
export function splitPemBlocks(input: string): readonly PemBlock[] {
	const normalized = input.replace(/\r/g, '');
	const blocks: PemBlock[] = [];
	const pattern = /-----BEGIN ([^-]+)-----\n([\s\S]*?)\n-----END \1-----/g;
	let cursor = 0;
	for (const match of normalized.matchAll(pattern)) {
		const pem = match[0];
		const label = match[1];
		const index = match.index;
		if (pem === undefined || label === undefined || index === undefined) {
			throw new Error('Invalid PEM block match');
		}
		if (containsPemMarker(normalized.slice(cursor, index))) {
			throw new Error('Malformed PEM block');
		}
		blocks.push({
			label,
			bytes: pemDecode(label, pem),
			pem,
		});
		cursor = index + pem.length;
	}
	if (containsPemMarker(normalized.slice(cursor))) {
		throw new Error('Malformed PEM block');
	}
	return blocks;
}

/**
 * Groups PEM blocks by label into well-known PKI categories
 * (certificates, CSRs, private keys, public keys, and everything else).
 * Accepts either raw PEM text or pre-split {@linkcode PemBlock} entries.
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

function normalizePemBodyLines(lines: readonly string[]): readonly string[] | undefined {
	const normalizedLines = lines.map((line) => line.replace(/[ \t]/g, ''));
	const nonEmptyLines = normalizedLines.filter((line) => line !== '');
	if (nonEmptyLines.length === 0) {
		return [''];
	}
	return nonEmptyLines.every((line) => /^[A-Za-z0-9+/=]+$/.test(line)) ? nonEmptyLines : undefined;
}

function containsPemMarker(value: string): boolean {
	return value.includes('-----BEGIN ') || value.includes('-----END ');
}
