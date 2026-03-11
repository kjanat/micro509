import { integerFromNumber, nullValue, objectIdentifier, octetString, readSequenceChildren, sequence } from "./der.ts";
import { getCrypto } from "./keys.ts";
import { OIDS } from "./oids.ts";

export interface Pbes2EncryptionOptions {
	readonly password: string;
	readonly iterations?: number;
	readonly salt?: Uint8Array;
	readonly iv?: Uint8Array;
}

export interface Pbes2Parameters {
	readonly iterations: number;
	readonly salt: Uint8Array;
	readonly iv: Uint8Array;
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
	const key = await deriveAesKey(options.password, salt, iterations, [
		"encrypt",
	]);
	const encryptedData = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: "AES-CBC", iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(data),
		),
	);
	return {
		algorithmIdentifierDer: encodePbes2AlgorithmIdentifier({
			iterations,
			salt,
			iv,
		}),
		encryptedData,
		parameters: { iterations, salt, iv },
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
		["decrypt"],
	);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: "AES-CBC", iv: toArrayBuffer(parameters.iv) },
				key,
				toArrayBuffer(encryptedData),
			),
		);
	} catch {
		throw new Error("Invalid password or encrypted content");
	}
}

export function encodePbes2AlgorithmIdentifier(
	parameters: Pbes2Parameters,
): Uint8Array {
	return sequence([
		objectIdentifier(OIDS.pbes2),
		sequence([
			sequence([
				objectIdentifier(OIDS.pbkdf2),
				sequence([
					octetString(parameters.salt),
					integerFromNumber(parameters.iterations),
					integerFromNumber(32),
					sequence([objectIdentifier(OIDS.hmacWithSHA256), nullValue()]),
				]),
			]),
			sequence([objectIdentifier(OIDS.aes256Cbc), octetString(parameters.iv)]),
		]),
	]);
}

export function parsePbes2AlgorithmIdentifier(
	algorithmIdentifierDer: Uint8Array,
): Pbes2Parameters {
	const topLevel = readSequenceChildren(algorithmIdentifierDer);
	const oid = topLevel[0];
	const params = topLevel[1];
	if (oid === undefined || params === undefined) {
		throw new Error("Malformed PBES2 algorithm identifier");
	}
	if (decodeObjectIdentifier(oid.value) !== OIDS.pbes2) {
		throw new Error("Unsupported encryption algorithm");
	}
	const paramsDer = algorithmIdentifierDer.slice(
		params.start - params.headerLength,
		params.end,
	);
	const pbes2Params = readSequenceChildren(paramsDer);
	const kdf = pbes2Params[0];
	const scheme = pbes2Params[1];
	if (kdf === undefined || scheme === undefined) {
		throw new Error("Malformed PBES2 params");
	}
	const kdfDer = paramsDer.slice(kdf.start - kdf.headerLength, kdf.end);
	const kdfChildren = readSequenceChildren(kdfDer);
	const kdfOid = kdfChildren[0];
	const kdfParams = kdfChildren[1];
	if (kdfOid === undefined || kdfParams === undefined) {
		throw new Error("Malformed KDF params");
	}
	if (decodeObjectIdentifier(kdfOid.value) !== OIDS.pbkdf2) {
		throw new Error("Unsupported KDF");
	}
	const pbkdf2Der = kdfDer.slice(
		kdfParams.start - kdfParams.headerLength,
		kdfParams.end,
	);
	const pbkdf2Params = readSequenceChildren(pbkdf2Der);
	const salt = pbkdf2Params[0];
	const iterations = pbkdf2Params[1];
	if (salt === undefined || iterations === undefined || salt.tag !== 0x04) {
		throw new Error("Malformed PBKDF2 params");
	}
	const schemeDer = paramsDer.slice(
		scheme.start - scheme.headerLength,
		scheme.end,
	);
	const schemeChildren = readSequenceChildren(schemeDer);
	const schemeOid = schemeChildren[0];
	const iv = schemeChildren[1];
	if (schemeOid === undefined || iv === undefined || iv.tag !== 0x04) {
		throw new Error("Malformed encryption scheme");
	}
	if (decodeObjectIdentifier(schemeOid.value) !== OIDS.aes256Cbc) {
		throw new Error("Unsupported content encryption scheme");
	}
	return {
		salt: new Uint8Array(salt.value),
		iterations: decodeInteger(iterations.value),
		iv: new Uint8Array(iv.value),
	};
}

async function deriveAesKey(
	password: string,
	salt: Uint8Array,
	iterations: number,
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const passwordKey = await getCrypto().subtle.importKey(
		"raw",
		new TextEncoder().encode(password),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return getCrypto().subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: toArrayBuffer(salt),
			iterations,
			hash: "SHA-256",
		},
		passwordKey,
		{ name: "AES-CBC", length: 256 },
		false,
		usages,
	);
}

function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error("OID is empty");
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error("Malformed OID");
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join(".");
}

function decodeInteger(bytes: Uint8Array): number {
	let value = 0;
	for (const byte of bytes) {
		value = (value << 8) | byte;
	}
	return value;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}
