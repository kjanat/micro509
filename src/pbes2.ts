/**
 * Internal PBES2 helpers used by encrypted PKCS#8 and PFX flows.
 *
 * This module parses, encodes, encrypts, and decrypts the shipped PBES2 profiles.
 */

import { decodeIntegerNumber, decodeObjectIdentifier, toArrayBuffer } from './asn1.ts';
import {
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
 * Enumerates the supported PBES2 encryption schemes.
 */
export type Pbes2EncryptionScheme = 'aes128-cbc' | 'aes192-cbc' | 'aes256-cbc';

/**
 * Defines PBES2 PRF.
 */
export type Pbes2Prf = 'hmac-sha1' | 'hmac-sha256';

/**
 * Configures PBES2 encryption operations.
 */
export interface Pbes2EncryptionOptions {
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
	/**
	 * Carries the iv value.
	 */
	readonly iv?: Uint8Array;
	/**
	 * Carries the encryption value.
	 */
	readonly encryption?: Pbes2EncryptionScheme;
	/**
	 * Carries the prf value.
	 */
	readonly prf?: Pbes2Prf;
}

/**
 * Describes PBES2 parameters handled by this module.
 */
export interface Pbes2Parameters {
	/**
	 * Carries the iterations value.
	 */
	readonly iterations: number;
	/**
	 * Carries the salt value.
	 */
	readonly salt: Uint8Array;
	/**
	 * Carries the iv value.
	 */
	readonly iv: Uint8Array;
	/**
	 * Carries the encryption value.
	 */
	readonly encryption: Pbes2EncryptionScheme;
	/**
	 * Carries the prf value.
	 */
	readonly prf: Pbes2Prf;
}

/**
 * Represents the result returned by PBES2 encryption operations.
 */
export interface Pbes2EncryptionResult {
	/**
	 * Carries the DER-encoded algorithm identifier.
	 */
	readonly algorithmIdentifierDer: Uint8Array;
	/**
	 * Carries the encrypted data value.
	 */
	readonly encryptedData: Uint8Array;
	/**
	 * Carries the parameters value.
	 */
	readonly parameters: Pbes2Parameters;
}

/**
 * Encrypt PBES2.
 *
 * @param data The raw bytes to process.
 * @param options The options that control the operation.
 * @returns The computed value.
 */
export async function encryptPbes2(
	data: Uint8Array,
	options: Pbes2EncryptionOptions,
): Promise<Pbes2EncryptionResult> {
	const iterations = options.iterations ?? 100_000;
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	const encryption = options.encryption ?? 'aes256-cbc';
	const prf = options.prf ?? 'hmac-sha256';
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

/**
 * Decrypt PBES2.
 *
 * @param algorithmIdentifierDer The algorithm identifier DER value.
 * @param encryptedData The encrypted data value.
 * @param password The password used to protect or unlock the data.
 * @returns The computed value.
 */
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
		throw new Error('Invalid password or encrypted content');
	}
}

/**
 * Encodes PBES2 algorithm identifier.
 *
 * @param parameters The parameters value.
 * @returns The encoded PBES2 algorithm identifier.
 */
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

/**
 * Parses PBES2 algorithm identifier.
 *
 * @param algorithmIdentifierDer The algorithm identifier DER value.
 * @returns The parsed PBES2 algorithm identifier.
 */
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
	return {
		salt: new Uint8Array(salt.value),
		iterations: decodeIntegerNumber(iterations.value),
		iv: new Uint8Array(iv.value),
		encryption: encryption.name,
		prf,
	};
}

/**
 * Derives aes key.
 *
 * @param password The password used to protect or unlock the data.
 * @param salt The salt value.
 * @param iterations The iterations value.
 * @param encryptionName The encryption name value.
 * @param prfName The PRF name value.
 * @param usages The usages value.
 * @returns The derived aes key.
 */
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

/**
 * Parses PBKDF2 PRF.
 *
 * @param pbkdf2Der The PBKDF2 DER value.
 * @param element The ASN.1 element to process.
 * @returns The parsed PBKDF2 PRF.
 */
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

/**
 * Encryption scheme from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
function encryptionSchemeFromOid(oid: string):
	| {
			/**
			 * Carries the name value.
			 */
			readonly name: Pbes2EncryptionScheme;
			/**
			 * Carries the oid value.
			 */
			readonly oid: string;
			/**
			 * Carries the key length bits value.
			 */
			readonly keyLengthBits: 128 | 192 | 256;
			/**
			 * Carries the key length bytes value.
			 */
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

/**
 * PRF from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
function prfFromOid(oid: string): Pbes2Prf | undefined {
	switch (oid) {
		case OIDS.hmacWithSHA1:
			return 'hmac-sha1';
		case OIDS.hmacWithSHA256:
			return 'hmac-sha256';
	}
	return undefined;
}

/**
 * Resolves encryption profile.
 *
 * @param name The name value.
 * @returns The resolved encryption profile.
 */
function resolveEncryptionProfile(name: Pbes2EncryptionScheme): {
	/**
	 * Carries the name value.
	 */
	readonly name: Pbes2EncryptionScheme;
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the key length bits value.
	 */
	readonly keyLengthBits: 128 | 192 | 256;
	/**
	 * Carries the key length bytes value.
	 */
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

/**
 * Resolves PRF profile.
 *
 * @param name The name value.
 * @returns The resolved PRF profile.
 */
function resolvePrfProfile(name: Pbes2Prf): {
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the hash value.
	 */
	readonly hash: 'SHA-1' | 'SHA-256';
} {
	switch (name) {
		case 'hmac-sha1':
			return { oid: OIDS.hmacWithSHA1, hash: 'SHA-1' };
		case 'hmac-sha256':
			return { oid: OIDS.hmacWithSHA256, hash: 'SHA-256' };
	}
}
