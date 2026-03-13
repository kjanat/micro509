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

export type Pbes2EncryptionScheme = 'aes128-cbc' | 'aes192-cbc' | 'aes256-cbc';

export type Pbes2Prf = 'hmac-sha1' | 'hmac-sha256';

export interface Pbes2EncryptionOptions {
	readonly password: string;
	readonly iterations?: number;
	readonly salt?: Uint8Array;
	readonly iv?: Uint8Array;
	readonly encryption?: Pbes2EncryptionScheme;
	readonly prf?: Pbes2Prf;
}

export interface Pbes2Parameters {
	readonly iterations: number;
	readonly salt: Uint8Array;
	readonly iv: Uint8Array;
	readonly encryption: Pbes2EncryptionScheme;
	readonly prf: Pbes2Prf;
}

export interface Pbes2EncryptionResult {
	readonly algorithmIdentifierDer: Uint8Array;
	readonly encryptedData: Uint8Array;
	readonly parameters: Pbes2Parameters;
}

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

function prfFromOid(oid: string): Pbes2Prf | undefined {
	switch (oid) {
		case OIDS.hmacWithSHA1:
			return 'hmac-sha1';
		case OIDS.hmacWithSHA256:
			return 'hmac-sha256';
	}
	return undefined;
}

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
