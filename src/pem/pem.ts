/**
 * PEM helpers used across the public API.
 *
 * Encodes, decodes, splits, and categorizes PEM blocks as defined by
 * RFC 7468.
 *
 * @module
 */

import { base64Decode, base64Encode } from '#micro509/internal/shared/base64';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import { failureResult, rethrowIfInvariant, successResult } from '#micro509/result/result';

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

// RFC 7468 §3 label ABNF: labelchar = %x21-2C / %x2E-7E, joined by an optional
// single "-" or SP; an empty label is legal.
const PEM_LABEL_PATTERN = /^(?:[!-,.-~](?:[- ]?[!-,.-~])*)?$/;

/**
 * Wraps DER bytes in a PEM envelope with 64-character base64 lines.
 *
 * @param label PEM type label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).
 * @param der Raw DER-encoded content.
 */
export function pemEncode(label: string, der: Uint8Array): string {
	if (!isPemLabel(label)) {
		throw new Error('Invalid PEM label');
	}
	const body = base64Encode(der);
	const lines = body.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/** Machine-readable failure reason for the PEM decoders. */
export type PemErrorCode = 'malformed';

/** Structured failure payload for PEM decoding. */
export interface PemFailure extends Micro509Error<PemErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode pemDecode}. */
export type PemDecodeResult =
	| { readonly ok: true; readonly value: Uint8Array }
	| ErrorResult<PemErrorCode, Record<never, never>, PemFailure>;

/** Success-or-failure result from {@linkcode splitPemBlocks}. */
export type SplitPemBlocksResult =
	| { readonly ok: true; readonly value: readonly PemBlock[] }
	| ErrorResult<PemErrorCode, Record<never, never>, PemFailure>;

/** Success-or-failure result from {@linkcode categorizePemBlocks}. */
export type CategorizePemBlocksResult =
	| { readonly ok: true; readonly value: CategorizedPemBlocks }
	| ErrorResult<PemErrorCode, Record<never, never>, PemFailure>;

/**
 * Throwing core for {@linkcode pemDecode}: extracts and base64-decodes the
 * DER content from a PEM string. Throws if the `BEGIN`/`END` markers don't
 * match `label`.
 *
 * @param label Expected PEM type label.
 * @param pem PEM-encoded text (may contain `\r`).
 */
export function pemDecodeOrThrow(label: string, pem: string): Uint8Array {
	const normalized = pem.replace(/\r\n?/g, '\n').trim();
	const lines = normalized.split('\n');
	if (
		parsePemBoundaryLine(lines[0] ?? '', 'BEGIN') !== label ||
		parsePemBoundaryLine(lines[lines.length - 1] ?? '', 'END') !== label ||
		lines.length < 3
	) {
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
export function splitPemBlocksOrThrow(input: string): readonly PemBlock[] {
	const normalized = input.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
	const blocks: PemBlock[] = [];
	let openBlock: { readonly label: string; readonly start: number } | undefined;
	let lineStart = 0;
	while (lineStart < normalized.length) {
		const newline = normalized.indexOf('\n', lineStart);
		const lineEnd = newline === -1 ? normalized.length : newline;
		const nextLineStart = newline === -1 ? normalized.length : newline + 1;
		const line = normalized.slice(lineStart, lineEnd);
		const beginLine = line.replace(/^[ \t]+/, '');
		const beginLabel = parsePemBoundaryLine(beginLine, 'BEGIN');
		const endLabel = parsePemBoundaryLine(line, 'END');

		if (beginLabel !== undefined) {
			if (openBlock !== undefined) {
				throw new Error('Malformed PEM block');
			}
			openBlock = { label: beginLabel, start: lineStart + line.length - beginLine.length };
		} else if (endLabel !== undefined) {
			blocks.push(closePemBlock(normalized, openBlock, endLabel, nextLineStart));
			openBlock = undefined;
		} else if (looksLikePemBoundary(line)) {
			throw new Error('Malformed PEM block');
		}

		if (newline === -1) {
			break;
		}
		lineStart = nextLineStart;
	}
	if (openBlock !== undefined) {
		throw new Error('Malformed PEM block');
	}
	return blocks;
}

function closePemBlock(
	input: string,
	openBlock: { readonly label: string; readonly start: number } | undefined,
	endLabel: string,
	end: number,
): PemBlock {
	if (openBlock === undefined || openBlock.label !== endLabel) {
		throw new Error('Malformed PEM block');
	}
	const pem = input.slice(openBlock.start, end);
	return {
		label: openBlock.label,
		bytes: pemDecodeOrThrow(openBlock.label, pem),
		pem,
	};
}

/**
 * Groups PEM blocks by label into well-known PKI categories
 * (certificates, CSRs, private keys, public keys, and everything else).
 * Accepts either raw PEM text or pre-split {@linkcode PemBlock} entries.
 */
export function categorizePemBlocksOrThrow(
	input: string | readonly PemBlock[],
): CategorizedPemBlocks {
	const blocks = typeof input === 'string' ? splitPemBlocksOrThrow(input) : input;
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

function parsePemBoundaryLine(line: string, kind: 'BEGIN' | 'END'): string | undefined {
	const prefix = `-----${kind} `;
	const withoutTrailingWsp = line.replace(/[ \t]+$/, '');
	if (!withoutTrailingWsp.startsWith(prefix) || !withoutTrailingWsp.endsWith('-----')) {
		return undefined;
	}
	const label = withoutTrailingWsp.slice(prefix.length, -5);
	return isPemLabel(label) ? label : undefined;
}

function looksLikePemBoundary(line: string): boolean {
	return /^[ \t]*-{5,}(?:BEGIN|END)/.test(line);
}

function isPemLabel(label: string): boolean {
	return PEM_LABEL_PATTERN.exec(label)?.[0] === label;
}

/**
 * Extracts and base64-decodes the DER content from a PEM string.
 *
 * Returns a typed failure (`code: 'malformed'`) when the `BEGIN`/`END`
 * markers don't match `label` or the body is not valid base64. For the
 * throwing form use {@linkcode pemDecodeOrThrow}.
 */
export function pemDecode(label: string, pem: string): PemDecodeResult {
	return toPemResult(() => pemDecodeOrThrow(label, pem), 'Invalid PEM');
}

/**
 * Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns them
 * as parsed {@linkcode PemBlock} entries. Handles concatenated PEM files and
 * ignores non-PEM text between blocks.
 *
 * Returns a typed failure (`code: 'malformed'`) on stray or truncated PEM
 * markers. For the throwing form use {@linkcode splitPemBlocksOrThrow}.
 */
export function splitPemBlocks(input: string): SplitPemBlocksResult {
	return toPemResult(() => splitPemBlocksOrThrow(input), 'Malformed PEM block');
}

/**
 * Groups PEM blocks by label into well-known PKI categories
 * (certificates, CSRs, private keys, public keys, and everything else).
 * Accepts either raw PEM text or pre-split {@linkcode PemBlock} entries.
 *
 * Returns a typed failure (`code: 'malformed'`) when raw text contains stray
 * or truncated PEM markers. For the throwing form use
 * {@linkcode categorizePemBlocksOrThrow}.
 */
export function categorizePemBlocks(
	input: string | readonly PemBlock[],
): CategorizePemBlocksResult {
	return toPemResult(() => categorizePemBlocksOrThrow(input), 'Malformed PEM block');
}

/** Shared Result wrapper around the throwing PEM cores. */
function toPemResult<TValue>(
	operation: () => TValue,
	fallbackMessage: string,
):
	| { readonly ok: true; readonly value: TValue }
	| ErrorResult<PemErrorCode, Record<never, never>, PemFailure> {
	try {
		return successResult(operation());
	} catch (error) {
		rethrowIfInvariant(error);
		return failureResult('malformed', error instanceof Error ? error.message : fallbackMessage);
	}
}
