/**
 * PKCS#12 MAC helpers used by PFX flows.
 *
 * This module creates and parses MAC data blocks and computes the password-based MAC used
 * by PKCS#12.
 */

import { decodeIntegerNumber, decodeObjectIdentifier, toArrayBuffer, toHex } from './asn1.ts';
import {
	concatBytes,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from './der.ts';
import { getCrypto } from './keys.ts';
import { OIDS } from './oids.ts';

/**
 * Configures PKCS#12 mac operations.
 */
export interface Pkcs12MacOptions {
	/**
	 * Carries the password value.
	 */
	readonly password: string;
	/**
	 * Carries the iterations value.
	 */
	readonly iterations?: number;
	/**
	 * Carries the salt value.
	 */
	readonly salt?: Uint8Array;
}

/**
 * Describes the structured PKCS#12 mac data produced by parsing helpers.
 */
export interface ParsedPkcs12MacData {
	/**
	 * Carries the OID for digest algorithm.
	 */
	readonly digestAlgorithmOid: string;
	/**
	 * Carries the hexadecimal digest.
	 */
	readonly digestHex: string;
	/**
	 * Carries the hexadecimal salt.
	 */
	readonly saltHex: string;
	/**
	 * Carries the iterations value.
	 */
	readonly iterations: number;
	/**
	 * Indicates whether valid.
	 */
	readonly valid?: boolean;
}

/**
 * Creates PKCS#12 mac data.
 *
 * @param authenticatedSafe The authenticated safe value.
 * @param options The options that control the operation.
 * @returns The created PKCS#12 mac data.
 */
export async function createPkcs12MacData(
	authenticatedSafe: Uint8Array,
	options: Pkcs12MacOptions,
): Promise<{
	/**
	 * Carries the der value.
	 */
	readonly der: Uint8Array;
	/**
	 * Carries the parsed value.
	 */
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
			digestHex: toHex(mac),
			saltHex: toHex(salt),
			iterations,
		},
	};
}

/**
 * Parses PKCS#12 mac data.
 *
 * @param der The DER-encoded bytes.
 * @param authenticatedSafe The authenticated safe value.
 * @param password The password used to protect or unlock the data.
 * @returns The parsed PKCS#12 mac data.
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
		/**
		 * Carries the OID for digest algorithm.
		 */
		digestAlgorithmOid,
		/**
		 * Carries the hexadecimal digest.
		 */
		digestHex: toHex(digest.value),
		/**
		 * Carries the hexadecimal salt.
		 */
		saltHex: toHex(salt.value),
		/**
		 * Carries the iterations value.
		 */
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

/**
 * Compute PKCS#12 mac.
 *
 * @param authenticatedSafe The authenticated safe value.
 * @param password The password used to protect or unlock the data.
 * @param salt The salt value.
 * @param iterations The iterations value.
 * @returns The computed value.
 */
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

/**
 * Derives PKCS#12 key.
 *
 * @param password The password used to protect or unlock the data.
 * @param salt The salt value.
 * @param iterations The iterations value.
 * @param id The id value.
 * @param length The length value.
 * @returns The derived PKCS#12 key.
 */
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

/**
 * Digest SHA-256.
 *
 * @param bytes The raw bytes to process.
 * @returns The computed value.
 */
async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest('SHA-256', toArrayBuffer(bytes)));
}

/**
 * Encodes PKCS#12 password.
 *
 * @param password The password used to protect or unlock the data.
 * @returns The encoded PKCS#12 password.
 */
function encodePkcs12Password(password: string): Uint8Array {
	const out = new Uint8Array((password.length + 1) * 2);
	for (let index = 0; index < password.length; index += 1) {
		const code = password.charCodeAt(index);
		out[index * 2] = code >> 8;
		out[index * 2 + 1] = code & 0xff;
	}
	return out;
}

/**
 * Repeat to multiple.
 *
 * @param bytes The raw bytes to process.
 * @param size The size value.
 * @returns The computed value.
 */
function repeatToMultiple(bytes: Uint8Array, size: number): Uint8Array {
	if (bytes.length === 0) {
		return new Uint8Array();
	}
	return repeatToLength(bytes, size * Math.ceil(bytes.length / size));
}

/**
 * Repeat to length.
 *
 * @param bytes The raw bytes to process.
 * @param length The length value.
 * @returns The computed value.
 */
function repeatToLength(bytes: Uint8Array, length: number): Uint8Array {
	const out = new Uint8Array(length);
	for (let index = 0; index < length; index += 1) {
		out[index] = bytes[index % bytes.length] ?? 0;
	}
	return out;
}

/**
 * Adds block in place.
 *
 * @param block The block value.
 * @param addend The addend value.
 */
function addBlockInPlace(block: Uint8Array, addend: Uint8Array): void {
	let carry = 1;
	for (let index = block.length - 1; index >= 0; index -= 1) {
		const sum = (block[index] ?? 0) + (addend[index] ?? 0) + carry;
		block[index] = sum & 0xff;
		carry = sum >> 8;
	}
}

/**
 * Equal bytes.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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
