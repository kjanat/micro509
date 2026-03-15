/**
 * BIT STRING helpers for {@linkcode KeyUsage} and {@linkcode DistributionPointReason} flags.
 *
 * Centralizes the bit-position ordering so certificate builders and parsers
 * produce identical wire encodings.
 *
 * @module
 */

import { bitString, DEFAULT_MAX_DER_DEPTH, readRootElement } from '#micro509/internal/asn1/der.ts';
import type { DistributionPointReason, KeyUsage } from '#micro509/x509/extensions.ts';

/** Canonical bit-position order for Key Usage flags (RFC 5280 §4.2.1.3). */
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

/** Canonical bit-position order for DistributionPoint reason flags (RFC 5280 §4.2.1.13). */
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
 * Encode an array of {@linkcode KeyUsage} flags into a DER BIT STRING.
 *
 * @param usages Flags to set. Bit positions follow RFC 5280 §4.2.1.3 order.
 */
export function encodeKeyUsageExtension(usages: readonly KeyUsage[]): Uint8Array {
	const encoded = encodeBitFlags(usages, (usage) =>
		indexInOrder(KEY_USAGE_ORDER, usage, 'key usage'),
	);
	return bitString(encoded.bytes, encoded.unusedBits);
}

/**
 * Decode a DER-encoded Key Usage BIT STRING into an array of {@linkcode KeyUsage} flags.
 *
 * @param bytes DER of the keyUsage extension value (BIT STRING).
 */
export function parseKeyUsageExtension(bytes: Uint8Array): readonly KeyUsage[] {
	const bitStringElement = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (bitStringElement.tag !== 0x03) {
		throw new Error('keyUsage must be a BIT STRING');
	}
	return decodeBitFlags(bitStringElement.value, KEY_USAGE_ORDER, 0);
}

/**
 * Encode {@linkcode DistributionPointReason} flags as BIT STRING content bytes
 * (unusedBits prefix + flag bytes), suitable for wrapping in an implicit context tag.
 *
 * @param reasons Reason flags to encode.
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
 * Decode BIT STRING content bytes into {@linkcode DistributionPointReason} flags.
 *
 * @param value Raw content bytes (unusedBits prefix + flag bytes).
 * @returns Decoded reason flags, or `undefined` if no bits are set.
 */
export function parseDistributionPointReasonFlagsContent(
	value: Uint8Array,
): readonly DistributionPointReason[] | undefined {
	const reasons = decodeBitFlags(value, DISTRIBUTION_POINT_REASON_ORDER, 1);
	return reasons.length === 0 ? undefined : reasons;
}

/** Pack named flags into a minimal byte array with DER BIT STRING unused-bits count. */
function encodeBitFlags<T extends string>(
	values: readonly T[],
	bitForValue: (value: T) => number,
): {
	readonly bytes: Uint8Array;
	readonly unusedBits: number;
} {
	if (values.length === 0) {
		return { bytes: new Uint8Array(0), unusedBits: 0 };
	}
	let highestBit = -1;
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
	const totalBits = highestBit + 1;
	const unusedBits = (8 - (totalBits % 8)) % 8;
	return {
		bytes,
		unusedBits,
	};
}

/** Unpack set bits from a BIT STRING content into named flags from a candidate list. */
function decodeBitFlags<T extends string>(
	value: Uint8Array,
	candidates: readonly T[],
	bitOffset: number,
): readonly T[] {
	if (value.length === 0) {
		throw new Error('Empty BIT STRING');
	}
	const unusedBits = value[0] ?? 0;
	if (unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	const bytes = value.slice(1);
	if (bytes.length === 0 && unusedBits !== 0) {
		throw new Error('Invalid BIT STRING');
	}
	const out: T[] = [];
	for (let index = 0; index < candidates.length; index += 1) {
		const bit = index + bitOffset;
		const byteIndex = Math.floor(bit / 8);
		if (byteIndex >= bytes.length) {
			break;
		}
		const byte = bytes[byteIndex] ?? 0;
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

/** Look up the bit position of a flag in its canonical order array. Throws on unknown flags. */
function indexInOrder<T extends string>(order: readonly T[], value: T, label: string): number {
	const index = order.indexOf(value);
	if (index < 0) {
		throw new Error(`Unsupported ${label}: ${value}`);
	}
	return index;
}
