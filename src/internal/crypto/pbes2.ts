/**
 * PBES2 password-based encryption and decryption (RFC 8018).
 *
 * Supports AES-CBC-128/192/256 with PBKDF2 using HMAC-SHA-1 or HMAC-SHA-256.
 * Used internally by encrypted PKCS#8 and PFX flows.
 *
 * @module
 */

import {
	decodeIntegerNumber,
	decodeObjectIdentifier,
	toArrayBuffer,
} from '#micro509/internal/asn1/asn1.ts';
import {
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { getCrypto } from './webcrypto.ts';

/**
 * Thrown when PBES2 / AES-CBC decryption fails its integrity check, which in
 * practice means the supplied password was wrong (or the ciphertext was
 * corrupted). Lets callers distinguish a bad password from malformed input.
 */
export class WrongPasswordError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'WrongPasswordError';
	}
}

/** AES-CBC key sizes supported by this PBES2 implementation. */
export type Pbes2EncryptionScheme = 'aes128-cbc' | 'aes192-cbc' | 'aes256-cbc';

/** PBKDF2 pseudo-random function choices. `hmac-sha1` is the RFC default; `hmac-sha256` is preferred. */
export type Pbes2Prf = 'hmac-sha1' | 'hmac-sha256';

/** Input for `encryptPbes2`. */
export interface Pbes2EncryptionOptions {
	/** Password fed to PBKDF2 for key derivation. */
	readonly password: string;
	/** PBKDF2 iteration count. Default: `100_000`. */
	readonly iterations?: number;
	/** PBKDF2 salt. Default: 16 cryptographically random bytes. */
	readonly salt?: Uint8Array;
	/** AES-CBC initialization vector. Default: 16 cryptographically random bytes. */
	readonly iv?: Uint8Array;
	/** AES key size. Default: `'aes256-cbc'`. */
	readonly encryption?: Pbes2EncryptionScheme;
	/** PBKDF2 PRF. Default: `'hmac-sha256'`. */
	readonly prf?: Pbes2Prf;
}

/** Resolved PBES2 algorithm parameters, either parsed from DER or built by `encryptPbes2`. */
export interface Pbes2Parameters {
	/** PBKDF2 iteration count. */
	readonly iterations: number;
	/** PBKDF2 salt bytes. */
	readonly salt: Uint8Array;
	/** AES-CBC initialization vector. */
	readonly iv: Uint8Array;
	/** AES-CBC key-size variant. */
	readonly encryption: Pbes2EncryptionScheme;
	/** PBKDF2 pseudo-random function. */
	readonly prf: Pbes2Prf;
}

/** Output of `encryptPbes2`: ciphertext plus the DER-encoded AlgorithmIdentifier. */
export interface Pbes2EncryptionResult {
	/** DER-encoded PBES2 AlgorithmIdentifier SEQUENCE (embeds KDF + cipher params). */
	readonly algorithmIdentifierDer: Uint8Array;
	/** AES-CBC ciphertext (includes PKCS#7 padding). */
	readonly encryptedData: Uint8Array;
	/** Resolved algorithm parameters used during encryption. */
	readonly parameters: Pbes2Parameters;
}

/** Encrypts `data` using PBES2 (PBKDF2 + AES-CBC) and returns ciphertext with algorithm params. */
export async function encryptPbes2(
	data: Uint8Array,
	options: Pbes2EncryptionOptions,
): Promise<Pbes2EncryptionResult> {
	const iterations = options.iterations ?? 100_000;
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	const encryption = options.encryption ?? 'aes256-cbc';
	const prf = options.prf ?? 'hmac-sha256';

	// Validate inputs before any WebCrypto calls
	if (!Number.isInteger(iterations) || iterations < 1) {
		throw new RangeError(`Invalid iterations: must be an integer >= 1, got ${iterations}`);
	}
	if (!(salt instanceof Uint8Array) || salt.length < 8) {
		throw new TypeError(
			`Invalid salt: must be Uint8Array with length >= 8, got length ${salt.length}`,
		);
	}
	if (!(iv instanceof Uint8Array) || iv.length !== 16) {
		throw new TypeError(
			`Invalid IV: must be Uint8Array of exactly 16 bytes, got length ${iv.length}`,
		);
	}

	const key = await deriveAesKey(options.password, salt, iterations, encryption, prf, ['encrypt']);
	const encryptedData = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(data),
		),
	);
	return {
		algorithmIdentifierDer: encodePbes2AlgorithmIdentifier({
			iterations,
			salt,
			iv,
			encryption,
			prf,
		}),
		encryptedData,
		parameters: { iterations, salt, iv, encryption, prf },
	};
}

/** Decrypts PBES2 ciphertext given the DER AlgorithmIdentifier and password. Throws on wrong password. */
export async function decryptPbes2(
	algorithmIdentifierDer: Uint8Array,
	encryptedData: Uint8Array,
	password: string,
): Promise<Uint8Array> {
	const parameters = parsePbes2AlgorithmIdentifier(algorithmIdentifierDer);
	const key = await deriveAesKey(
		password,
		parameters.salt,
		parameters.iterations,
		parameters.encryption,
		parameters.prf,
		['decrypt'],
	);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: 'AES-CBC', iv: toArrayBuffer(parameters.iv) },
				key,
				toArrayBuffer(encryptedData),
			),
		);
	} catch {
		throw new WrongPasswordError('Invalid password or encrypted content');
	}
}

/** DER-encodes a PBES2 AlgorithmIdentifier SEQUENCE from resolved parameters. */
export function encodePbes2AlgorithmIdentifier(parameters: Pbes2Parameters): Uint8Array {
	const encryption = resolveEncryptionProfile(parameters.encryption);
	const prf = resolvePrfProfile(parameters.prf);
	return sequence([
		objectIdentifier(OIDS.pbes2),
		sequence([
			sequence([
				objectIdentifier(OIDS.pbkdf2),
				sequence([
					octetString(parameters.salt),
					integerFromNumber(parameters.iterations),
					integerFromNumber(encryption.keyLengthBytes),
					sequence([objectIdentifier(prf.oid), nullValue()]),
				]),
			]),
			sequence([objectIdentifier(encryption.oid), octetString(parameters.iv)]),
		]),
	]);
}

/** Decodes a DER-encoded PBES2 AlgorithmIdentifier into structured {@linkcode Pbes2Parameters}. */
export function parsePbes2AlgorithmIdentifier(algorithmIdentifierDer: Uint8Array): Pbes2Parameters {
	const topLevel = readSequenceChildren(algorithmIdentifierDer);
	const oid = topLevel[0];
	const params = topLevel[1];
	if (oid === undefined || params === undefined) {
		throw new Error('Malformed PBES2 algorithm identifier');
	}
	if (decodeObjectIdentifier(oid.value) !== OIDS.pbes2) {
		throw new Error('Unsupported encryption algorithm');
	}
	const paramsDer = algorithmIdentifierDer.slice(params.start - params.headerLength, params.end);
	const pbes2Params = readSequenceChildren(paramsDer);
	const kdf = pbes2Params[0];
	const scheme = pbes2Params[1];
	if (kdf === undefined || scheme === undefined) {
		throw new Error('Malformed PBES2 params');
	}
	const kdfDer = paramsDer.slice(kdf.start - kdf.headerLength, kdf.end);
	const kdfChildren = readSequenceChildren(kdfDer);
	const kdfOid = kdfChildren[0];
	const kdfParams = kdfChildren[1];
	if (kdfOid === undefined || kdfParams === undefined) {
		throw new Error('Malformed KDF params');
	}
	if (decodeObjectIdentifier(kdfOid.value) !== OIDS.pbkdf2) {
		throw new Error('Unsupported KDF');
	}
	// PBKDF2 params: SEQUENCE { salt OCTET STRING, iterationCount INTEGER, [keyLength INTEGER], [prf AlgorithmIdentifier] }
	const pbkdf2Der = kdfDer.slice(kdfParams.start - kdfParams.headerLength, kdfParams.end);
	const pbkdf2Params = readSequenceChildren(pbkdf2Der);
	const salt = pbkdf2Params[0];
	const iterations = pbkdf2Params[1];
	if (salt === undefined || iterations === undefined || salt.tag !== 0x04) {
		throw new Error('Malformed PBKDF2 params');
	}
	const keyLengthElement = pbkdf2Params[2];
	const hasExplicitKeyLength = keyLengthElement?.tag === 0x02;
	const prfElement = hasExplicitKeyLength ? pbkdf2Params[3] : keyLengthElement;
	const schemeDer = paramsDer.slice(scheme.start - scheme.headerLength, scheme.end);
	const schemeChildren = readSequenceChildren(schemeDer);
	const schemeOid = schemeChildren[0];
	const iv = schemeChildren[1];
	if (schemeOid === undefined || iv === undefined || iv.tag !== 0x04) {
		throw new Error('Malformed encryption scheme');
	}
	const encryption = encryptionSchemeFromOid(decodeObjectIdentifier(schemeOid.value));
	if (encryption === undefined) {
		throw new Error('Unsupported content encryption scheme');
	}
	if (keyLengthElement !== undefined && !hasExplicitKeyLength && keyLengthElement.tag !== 0x30) {
		throw new Error('Malformed PBKDF2 params');
	}
	if (
		hasExplicitKeyLength &&
		decodeIntegerNumber(keyLengthElement.value) !== encryption.keyLengthBytes
	) {
		throw new Error('Unsupported PBKDF2 key length');
	}
	const prf = parsePbkdf2Prf(pbkdf2Der, prfElement);

	// Validate parsed parameters before returning
	const iterationsValue = decodeIntegerNumber(iterations.value);
	const saltValue = new Uint8Array(salt.value);
	const ivValue = new Uint8Array(iv.value);

	if (iterationsValue < 1) {
		throw new RangeError(`Invalid PBES2 iterations: must be >= 1, got ${iterationsValue}`);
	}
	if (saltValue.length < 8) {
		throw new RangeError(`Invalid PBES2 salt: must be >= 8 bytes, got ${saltValue.length}`);
	}
	if (ivValue.length !== 16) {
		throw new RangeError(`Invalid PBES2 IV: must be exactly 16 bytes, got ${ivValue.length}`);
	}

	return {
		salt: saltValue,
		iterations: iterationsValue,
		iv: ivValue,
		encryption: encryption.name,
		prf,
	};
}

/** Derives an AES-CBC `CryptoKey` from a password via PBKDF2. */
async function deriveAesKey(
	password: string,
	salt: Uint8Array,
	iterations: number,
	encryptionName: Pbes2EncryptionScheme,
	prfName: Pbes2Prf,
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const encryption = resolveEncryptionProfile(encryptionName);
	const prf = resolvePrfProfile(prfName);
	const passwordKey = await getCrypto().subtle.importKey(
		'raw',
		new TextEncoder().encode(password),
		'PBKDF2',
		false,
		['deriveKey'],
	);
	return getCrypto().subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: toArrayBuffer(salt),
			iterations,
			hash: prf.hash,
		},
		passwordKey,
		{ name: 'AES-CBC', length: encryption.keyLengthBits },
		false,
		usages,
	);
}

/** Parses the optional PRF AlgorithmIdentifier from PBKDF2 params. Absent means HMAC-SHA-1. */
function parsePbkdf2Prf(
	pbkdf2Der: Uint8Array,
	element: ReturnType<typeof readSequenceChildren>[number] | undefined,
): Pbes2Prf {
	if (element === undefined) {
		return 'hmac-sha1';
	}
	if (element.tag !== 0x30) {
		throw new Error('Malformed PBKDF2 PRF');
	}
	const prfDer = readSequenceChildren(
		pbkdf2Der.slice(element.start - element.headerLength, element.end),
	);
	const oid = prfDer[0];
	if (oid === undefined) {
		throw new Error('Malformed PBKDF2 PRF');
	}
	const prf = prfFromOid(decodeObjectIdentifier(oid.value));
	if (prf === undefined) {
		throw new Error('Unsupported PBKDF2 PRF');
	}
	return prf;
}

/** Maps an AES-CBC OID to the encryption profile, or `undefined` if unsupported. */
function encryptionSchemeFromOid(oid: string):
	| {
			readonly name: Pbes2EncryptionScheme;
			readonly oid: string;
			readonly keyLengthBits: 128 | 192 | 256;
			readonly keyLengthBytes: 16 | 24 | 32;
	  }
	| undefined {
	switch (oid) {
		case OIDS.aes128Cbc:
			return { name: 'aes128-cbc', oid, keyLengthBits: 128, keyLengthBytes: 16 };
		case OIDS.aes192Cbc:
			return { name: 'aes192-cbc', oid, keyLengthBits: 192, keyLengthBytes: 24 };
		case OIDS.aes256Cbc:
			return { name: 'aes256-cbc', oid, keyLengthBits: 256, keyLengthBytes: 32 };
	}
	return undefined;
}

/** Maps an HMAC OID to the PRF name, or `undefined` if unsupported. */
function prfFromOid(oid: string): Pbes2Prf | undefined {
	switch (oid) {
		case OIDS.hmacWithSHA1:
			return 'hmac-sha1';
		case OIDS.hmacWithSHA256:
			return 'hmac-sha256';
	}
	return undefined;
}

/** Looks up the full encryption profile for a scheme name. Throws if unsupported. */
function resolveEncryptionProfile(name: Pbes2EncryptionScheme): {
	readonly name: Pbes2EncryptionScheme;
	readonly oid: string;
	readonly keyLengthBits: 128 | 192 | 256;
	readonly keyLengthBytes: 16 | 24 | 32;
} {
	const profile = encryptionSchemeFromOid(
		name === 'aes128-cbc'
			? OIDS.aes128Cbc
			: name === 'aes192-cbc'
				? OIDS.aes192Cbc
				: OIDS.aes256Cbc,
	);
	if (profile === undefined) {
		throw new Error('Unsupported content encryption scheme');
	}
	return profile;
}

/** Looks up OID and WebCrypto hash name for a PRF. */
function resolvePrfProfile(name: Pbes2Prf): {
	readonly oid: string;
	readonly hash: 'SHA-1' | 'SHA-256';
} {
	switch (name) {
		case 'hmac-sha1':
			return { oid: OIDS.hmacWithSHA1, hash: 'SHA-1' };
		case 'hmac-sha256':
			return { oid: OIDS.hmacWithSHA256, hash: 'SHA-256' };
	}
}
