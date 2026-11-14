import type { SignatureVerifier, SignatureVerifierInput } from '#micro509/crypto';
import { readElement, readSequenceChildren } from '#micro509/internal/asn1/der';

export const DSA_WITH_SHA1 = '1.2.840.10040.4.3';
export const DSA_WITH_SHA256 = '2.16.840.1.101.3.4.3.2';

function integer(bytes: Uint8Array): bigint {
	let value = 0n;
	for (const byte of bytes) value = (value << 8n) | BigInt(byte);
	return value;
}

function integers(der: Uint8Array): bigint[] {
	return readSequenceChildren(der).map((element) => {
		if (element.tag !== 0x02) throw new Error('expected INTEGER');
		return integer(element.value);
	});
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
	let result = 1n;
	let factor = base % modulus;
	let rest = exponent;
	while (rest > 0n) {
		if ((rest & 1n) === 1n) result = (result * factor) % modulus;
		factor = (factor * factor) % modulus;
		rest >>= 1n;
	}
	return result;
}

function bitLength(value: bigint): number {
	return value.toString(2).length;
}

function publicKey(spkiDer: Uint8Array): bigint {
	const bitString = readSequenceChildren(spkiDer)[1];
	if (bitString?.tag !== 0x03 || bitString.value[0] !== 0) throw new Error('expected BIT STRING');
	const y = readElement(bitString.value.subarray(1));
	if (y.tag !== 0x02) throw new Error('expected DSA public key INTEGER');
	return integer(y.value);
}

async function verify(input: SignatureVerifierInput, hash: 'SHA-1' | 'SHA-256'): Promise<boolean> {
	if (input.signatureAlgorithm.parametersDer !== undefined) return false;
	if (input.signerPublicKeyParametersDer === undefined) return false;
	const [p, q, g] = integers(input.signerPublicKeyParametersDer);
	const [r, s] = integers(input.signature);
	if (p === undefined || q === undefined || g === undefined || r === undefined || s === undefined) {
		return false;
	}
	if (r <= 0n || r >= q || s <= 0n || s >= q) return false;
	const digest = new Uint8Array(await crypto.subtle.digest(hash, new Uint8Array(input.data)));
	const n = bitLength(q);
	const z = integer(digest) >> BigInt(Math.max(0, digest.length * 8 - n));
	const w = modPow(s, q - 2n, q);
	const u1 = (z * w) % q;
	const u2 = (r * w) % q;
	const v = ((modPow(g, u1, p) * modPow(publicKey(input.signerSpkiDer), u2, p)) % p) % q;
	return v === r;
}

/** FIPS 186-4 §4.7 DSA verification for dsa-with-sha1 and dsa-with-sha256 (RFC 3279 §2.2.2, RFC 5758 §3.1). */
export const dsaSignatureVerifiers: Readonly<Record<string, SignatureVerifier>> = {
	[DSA_WITH_SHA1]: (input) => verify(input, 'SHA-1'),
	[DSA_WITH_SHA256]: (input) => verify(input, 'SHA-256'),
};
