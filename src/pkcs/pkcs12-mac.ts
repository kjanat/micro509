/**
 * PKCS#12 MAC data creation and verification.
 *
 * Computes and verifies the password-based HMAC-SHA-256 integrity check
 * defined in PKCS#12 (RFC 7292), using the PKCS#12 key-derivation scheme.
 *
 * @module
 */

import {
	decodeIntegerNumber,
	decodeObjectIdentifier,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1.ts';
import {
	concatBytes,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { describeHashAlgorithm } from '#micro509/internal/crypto/algorithm-names.ts';
import { getCrypto } from '#micro509/internal/crypto/webcrypto.ts';

/** Input for {@linkcode createPkcs12MacData}. */
export interface Pkcs12MacOptions {
	/** Password used to derive the HMAC key via the PKCS#12 KDF. */
	readonly password: string;
	/** PKCS#12 KDF iteration count. Default: `2048`. */
	readonly iterations?: number;
	/** Random salt. Default: 16 cryptographically random bytes. */
	readonly salt?: Uint8Array;
}

/** Decoded PKCS#12 MacData block returned by {@linkcode parsePkcs12MacData}. */
export interface ParsedPkcs12MacData {
	/** OID of the digest algorithm (currently always SHA-256). */
	readonly digestAlgorithmOid: string;
	/** Human-readable digest algorithm name (currently `"SHA-256"`). */
	readonly digestAlgorithmName: string;
	/** Hex-encoded MAC digest value. */
	readonly digestHex: string;
	/** Hex-encoded salt bytes used during key derivation. */
	readonly saltHex: string;
	/** Number of PKCS#12 KDF iterations. */
	readonly iterations: number;
	/** MAC verification outcome. Present only when a password was supplied during parsing. */
	readonly valid?: boolean;
}

/**
 * Computes a PKCS#12 HMAC-SHA-256 MAC over the AuthenticatedSafe and returns
 * the DER-encoded MacData block alongside its parsed representation.
 */
export async function createPkcs12MacData(
	authenticatedSafe: Uint8Array,
	options: Pkcs12MacOptions,
): Promise<{
	/** DER-encoded MacData SEQUENCE. */
	readonly der: Uint8Array;
	/** Structured representation of the MAC parameters and digest. */
	readonly parsed: ParsedPkcs12MacData;
}> {
	const iterations = options.iterations ?? 2048;
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const mac = await computePkcs12Mac(authenticatedSafe, options.password, salt, iterations);
	const der = sequence([
		sequence([sequence([objectIdentifier(OIDS.sha256), nullValue()]), octetString(mac)]),
		octetString(salt),
		integerFromNumber(iterations),
	]);
	return {
		der,
		parsed: {
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: describeHashAlgorithm(OIDS.sha256),
			digestHex: toHex(mac),
			saltHex: toHex(salt),
			iterations,
		},
	};
}

/**
 * Decodes a DER-encoded MacData block. When `password` is provided, verifies
 * the MAC and sets the `valid` flag on the returned structure.
 */
export async function parsePkcs12MacData(
	der: Uint8Array,
	authenticatedSafe: Uint8Array,
	password?: string,
): Promise<ParsedPkcs12MacData> {
	const top = readSequenceChildren(der);
	const digestInfo = top[0];
	const salt = top[1];
	const iterations = top[2];
	if (
		digestInfo === undefined ||
		salt === undefined ||
		iterations === undefined ||
		salt.tag !== 0x04
	) {
		throw new Error('Malformed MacData');
	}
	const digestInfoDer = der.slice(digestInfo.start - digestInfo.headerLength, digestInfo.end);
	const digestInfoChildren = readSequenceChildren(digestInfoDer);
	const algorithm = digestInfoChildren[0];
	const digest = digestInfoChildren[1];
	if (algorithm === undefined || digest === undefined || digest.tag !== 0x04) {
		throw new Error('Malformed DigestInfo');
	}
	const algorithmDer = digestInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end);
	const algorithmChildren = readSequenceChildren(algorithmDer);
	const algorithmOid = algorithmChildren[0];
	if (algorithmOid === undefined) {
		throw new Error('MacData algorithm missing');
	}
	const digestAlgorithmOid = decodeObjectIdentifier(algorithmOid.value);
	if (digestAlgorithmOid !== OIDS.sha256) {
		throw new Error('Only SHA-256 PKCS#12 MAC is supported');
	}
	const parsed: ParsedPkcs12MacData = {
		digestAlgorithmOid,
		digestAlgorithmName: describeHashAlgorithm(digestAlgorithmOid),
		digestHex: toHex(digest.value),
		saltHex: toHex(salt.value),
		iterations: decodeIntegerNumber(iterations.value),
	};
	if (password === undefined) {
		return parsed;
	}
	const expected = await computePkcs12Mac(
		authenticatedSafe,
		password,
		salt.value,
		parsed.iterations,
	);
	return { ...parsed, valid: equalBytes(expected, digest.value) };
}

/** Derives an HMAC-SHA-256 key via the PKCS#12 KDF and signs the AuthenticatedSafe. */
async function computePkcs12Mac(
	authenticatedSafe: Uint8Array,
	password: string,
	salt: Uint8Array,
	iterations: number,
): Promise<Uint8Array> {
	const keyBytes = await derivePkcs12Key(password, salt, iterations, 3, 32);
	const key = await getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	);
	return new Uint8Array(
		await getCrypto().subtle.sign('HMAC', key, toArrayBuffer(authenticatedSafe)),
	);
}

/** PKCS#12 key derivation (RFC 7292 Appendix B). `id` selects the purpose (3 = MAC key). */
async function derivePkcs12Key(
	password: string,
	salt: Uint8Array,
	iterations: number,
	id: number,
	length: number,
): Promise<Uint8Array> {
	const u = 32;
	const v = 64;
	const D = new Uint8Array(v).fill(id);
	const passwordBytes = encodePkcs12Password(password);
	const S = repeatToMultiple(salt, v);
	const P = repeatToMultiple(passwordBytes, v);
	let I = concatBytes([S, P]);
	const blocks = Math.ceil(length / u);
	const output = new Uint8Array(blocks * u);
	for (let index = 0; index < blocks; index += 1) {
		let A = await digestSha256(concatBytes([D, I]));
		for (let round = 1; round < iterations; round += 1) {
			A = await digestSha256(A);
		}
		output.set(A, index * u);
		if (I.length === 0) {
			continue;
		}
		const B = repeatToLength(A, v);
		const next = new Uint8Array(I.length);
		for (let blockIndex = 0; blockIndex < I.length / v; blockIndex += 1) {
			const block = I.slice(blockIndex * v, blockIndex * v + v);
			addBlockInPlace(block, B);
			next.set(block, blockIndex * v);
		}
		I = next;
	}
	return output.slice(0, length);
}

/** SHA-256 hash via WebCrypto. */
async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest('SHA-256', toArrayBuffer(bytes)));
}

/** Encodes a password as a null-terminated UCS-2 big-endian byte array (RFC 7292 B.1). */
function encodePkcs12Password(password: string): Uint8Array {
	const out = new Uint8Array((password.length + 1) * 2);
	for (let index = 0; index < password.length; index += 1) {
		const code = password.charCodeAt(index);
		out[index * 2] = code >> 8;
		out[index * 2 + 1] = code & 0xff;
	}
	return out;
}

/** Repeats `bytes` to the nearest multiple of `size`. */
function repeatToMultiple(bytes: Uint8Array, size: number): Uint8Array {
	if (bytes.length === 0) {
		return new Uint8Array();
	}
	return repeatToLength(bytes, size * Math.ceil(bytes.length / size));
}

/** Cyclically repeats `bytes` to fill exactly `length` bytes. */
function repeatToLength(bytes: Uint8Array, length: number): Uint8Array {
	const out = new Uint8Array(length);
	for (let index = 0; index < length; index += 1) {
		out[index] = bytes[index % bytes.length] ?? 0;
	}
	return out;
}

/** Big-endian add-with-carry of `addend` into `block`, modifying `block` in place. */
function addBlockInPlace(block: Uint8Array, addend: Uint8Array): void {
	let carry = 1;
	for (let index = block.length - 1; index >= 0; index -= 1) {
		const sum = (block[index] ?? 0) + (addend[index] ?? 0) + carry;
		block[index] = sum & 0xff;
		carry = sum >> 8;
	}
}

/** Constant-time byte comparison to avoid timing side-channels in MAC checks. */
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	let result = 0;
	for (let index = 0; index < left.length; index += 1) {
		result |= (left[index] ?? 0) ^ (right[index] ?? 0);
	}
	return result === 0;
}
