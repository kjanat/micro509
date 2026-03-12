import { integer, readSequenceChildren, sequence } from './der.ts';

export function derEcdsaSignatureToRaw(signature: Uint8Array, partLength: number): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error('Malformed ECDSA DER signature');
	}
	return concatFixedWidth(trimLeadingZero(r.value), trimLeadingZero(s.value), partLength);
}

export function rawEcdsaSignatureToDer(signature: Uint8Array, partLength: number): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error('Unexpected ECDSA raw signature length');
	}
	return sequence([integer(signature.slice(0, partLength)), integer(signature.slice(partLength))]);
}

export function alternateEcdsaSignatureEncoding(
	signature: Uint8Array,
	partLength: number,
): Uint8Array | undefined {
	try {
		if (signature[0] === 0x30) {
			return derEcdsaSignatureToRaw(signature, partLength);
		}
		return rawEcdsaSignatureToDer(signature, partLength);
	} catch {
		return undefined;
	}
}

export function concatFixedWidth(
	left: Uint8Array,
	right: Uint8Array,
	partLength: number,
): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error('ECDSA signature integer too large');
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
}

function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}
