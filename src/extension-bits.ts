import { bitString, readElement } from './der.ts';
import type { DistributionPointReason, KeyUsage } from './extensions.ts';

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

export function encodeKeyUsageExtension(usages: readonly KeyUsage[]): Uint8Array {
	const encoded = encodeBitFlags(usages, (usage) =>
		indexInOrder(KEY_USAGE_ORDER, usage, 'key usage'),
	);
	return bitString(encoded.bytes, encoded.unusedBits);
}

export function parseKeyUsageExtension(bytes: Uint8Array): readonly KeyUsage[] {
	const bitStringElement = readElement(bytes);
	if (bitStringElement.tag !== 0x03) {
		throw new Error('keyUsage must be a BIT STRING');
	}
	return decodeBitFlags(bitStringElement.value, KEY_USAGE_ORDER, 0);
}

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

export function parseDistributionPointReasonFlagsContent(
	value: Uint8Array,
): readonly DistributionPointReason[] | undefined {
	const reasons = decodeBitFlags(value, DISTRIBUTION_POINT_REASON_ORDER, 1);
	return reasons.length === 0 ? undefined : reasons;
}

function encodeBitFlags<T extends string>(
	values: readonly T[],
	bitForValue: (value: T) => number,
): { readonly bytes: Uint8Array; readonly unusedBits: number } {
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

function indexInOrder<T extends string>(order: readonly T[], value: T, label: string): number {
	const index = order.indexOf(value);
	if (index < 0) {
		throw new Error(`Unsupported ${label}: ${value}`);
	}
	return index;
}
