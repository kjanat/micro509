/**
 * Bit-string helpers for key-usage and distribution-point reason flags.
 *
 * This module centralizes bit ordering so certificate builders and parsers stay aligned on
 * the same wire encoding.
 */

import { bitString, DEFAULT_MAX_DER_DEPTH, readRootElement } from './der.ts';
import type { DistributionPointReason, KeyUsage } from './extensions.ts';

/**
 * Defines the key usage order used by this module.
 */
const KEY_USAGE_ORDER = [
	'digitalSignature',
	'nonRepudiation',
	'keyEncipherment',
	'dataEncipherment',
	'keyAgreement',
	'keyCertSign',
	'cRLSign',
	'encipherOnly',
	'decipherOnly',
] as const satisfies readonly KeyUsage[];

/**
 * Defines the distribution point reason order used by this module.
 */
const DISTRIBUTION_POINT_REASON_ORDER = [
	'keyCompromise',
	'cACompromise',
	'affiliationChanged',
	'superseded',
	'cessationOfOperation',
	'certificateHold',
	'privilegeWithdrawn',
	'aACompromise',
] as const satisfies readonly DistributionPointReason[];

/**
 * Encodes key usage extension.
 *
 * @param usages The usages value.
 * @returns The encoded key usage extension.
 */
export function encodeKeyUsageExtension(usages: readonly KeyUsage[]): Uint8Array {
	const encoded = encodeBitFlags(usages, (usage) =>
		indexInOrder(KEY_USAGE_ORDER, usage, 'key usage'),
	);
	return bitString(encoded.bytes, encoded.unusedBits);
}

/**
 * Parses key usage extension.
 *
 * @param bytes The raw bytes to process.
 * @returns The parsed key usage extension.
 */
export function parseKeyUsageExtension(bytes: Uint8Array): readonly KeyUsage[] {
	const bitStringElement = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (bitStringElement.tag !== 0x03) {
		throw new Error('keyUsage must be a BIT STRING');
	}
	return decodeBitFlags(bitStringElement.value, KEY_USAGE_ORDER, 0);
}

/**
 * Encodes distribution point reason flags content.
 *
 * @param reasons The reasons value.
 * @returns The encoded distribution point reason flags content.
 */
export function encodeDistributionPointReasonFlagsContent(
	reasons: readonly DistributionPointReason[],
): Uint8Array {
	const encoded = encodeBitFlags(
		reasons,
		(reason) =>
			indexInOrder(DISTRIBUTION_POINT_REASON_ORDER, reason, 'distribution point reason') + 1,
	);
	return Uint8Array.of(encoded.unusedBits, ...encoded.bytes);
}

/**
 * Parses distribution point reason flags content.
 *
 * @param value The value to process.
 * @returns The parsed distribution point reason flags content.
 */
export function parseDistributionPointReasonFlagsContent(
	value: Uint8Array,
): readonly DistributionPointReason[] | undefined {
	const reasons = decodeBitFlags(value, DISTRIBUTION_POINT_REASON_ORDER, 1);
	return reasons.length === 0 ? undefined : reasons;
}

/**
 * Encodes bit flags.
 *
 * @param values The values to process.
 * @param bitForValue The bit for value value.
 * @returns The encoded bit flags.
 */
function encodeBitFlags<T extends string>(
	values: readonly T[],
	bitForValue: (value: T) => number,
): {
	/**
	 * Carries the bytes value.
	 */
	readonly bytes: Uint8Array;
	/**
	 * Carries the unused bits value.
	 */
	readonly unusedBits: number;
} {
	let highestBit = 0;
	for (const value of values) {
		const bit = bitForValue(value);
		if (bit > highestBit) {
			highestBit = bit;
		}
	}
	const byteLength = Math.floor(highestBit / 8) + 1;
	const bytes = new Uint8Array(byteLength);
	for (const value of values) {
		const bit = bitForValue(value);
		const byteIndex = Math.floor(bit / 8);
		const bitIndex = bit % 8;
		const current = bytes[byteIndex] ?? 0;
		bytes[byteIndex] = current | (1 << (7 - bitIndex));
	}
	return {
		bytes,
		unusedBits: (8 - ((highestBit + 1) % 8)) % 8,
	};
}

/**
 * Decodes bit flags.
 *
 * @param value The value to process.
 * @param candidates The candidates value.
 * @param bitOffset The bit offset value.
 * @returns The decoded bit flags.
 */
function decodeBitFlags<T extends string>(
	value: Uint8Array,
	candidates: readonly T[],
	bitOffset: number,
): readonly T[] {
	const unusedBits = value[0] ?? 0;
	if (unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	const bytes = value.slice(1);
	const out: T[] = [];
	for (let index = 0; index < candidates.length; index += 1) {
		const bit = index + bitOffset;
		const byte = bytes[Math.floor(bit / 8)] ?? 0;
		const bitIndex = bit % 8;
		if ((byte & (1 << (7 - bitIndex))) !== 0) {
			const candidate = candidates[index];
			if (candidate !== undefined) {
				out.push(candidate);
			}
		}
	}
	return out;
}

/**
 * Index in order.
 *
 * @param order The order value.
 * @param value The value to process.
 * @param label The label value.
 * @returns The computed value.
 */
function indexInOrder<T extends string>(order: readonly T[], value: T, label: string): number {
	const index = order.indexOf(value);
	if (index < 0) {
		throw new Error(`Unsupported ${label}: ${value}`);
	}
	return index;
}
