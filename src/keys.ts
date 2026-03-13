import { decodeObjectIdentifier, hexToBytes, toArrayBuffer, toHex } from './asn1.ts';
import { nullValue, objectIdentifier, octetString, readSequenceChildren, sequence } from './der.ts';
import { md5 } from './hash.ts';
import { OIDS } from './oids.ts';
import { decryptPbes2, encryptPbes2, type Pbes2EncryptionOptions } from './pbes2.ts';
import { base64Decode, base64Encode, pemDecode, pemEncode } from './pem.ts';

export type RsaHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export type RsaScheme = 'pkcs1-v1_5' | 'pss';

export type EcNamedCurve = 'P-256' | 'P-384' | 'P-521';

export interface RsaKeyAlgorithmInput {
	readonly kind: 'rsa';
	readonly modulusLength?: 2048 | 3072 | 4096;
	readonly hash?: RsaHash;
	readonly scheme?: RsaScheme;
}

export interface EcKeyAlgorithmInput {
	readonly kind: 'ecdsa';
	readonly namedCurve?: EcNamedCurve;
}

export interface Ed25519KeyAlgorithmInput {
	readonly kind: 'ed25519';
}

export type KeyAlgorithmInput =
	| RsaKeyAlgorithmInput
	| EcKeyAlgorithmInput
	| Ed25519KeyAlgorithmInput;

export interface KeyPairMaterial {
	readonly publicKey: CryptoKey;
	readonly privateKey: CryptoKey;
	exportSpkiDer(): Promise<Uint8Array>;
	exportSpkiPem(): Promise<string>;
	exportPkcs8Der(): Promise<Uint8Array>;
	exportPkcs8Pem(): Promise<string>;
	exportPublicJwk(): Promise<JsonWebKey>;
	exportPrivateJwk(): Promise<JsonWebKey>;
}

export interface ImportRsaPublicKeyInput {
	readonly kind: 'rsa';
	readonly hash?: RsaHash;
	readonly scheme?: RsaScheme;
}

export interface ImportEcPublicKeyInput {
	readonly kind: 'ecdsa';
	readonly namedCurve: EcNamedCurve;
}

export interface ImportEd25519PublicKeyInput {
	readonly kind: 'ed25519';
}

export type PublicKeyImportInput =
	| ImportRsaPublicKeyInput
	| ImportEcPublicKeyInput
	| ImportEd25519PublicKeyInput;

export type PrivateKeyImportInput = PublicKeyImportInput;

export type EncryptedPkcs8Options = Pbes2EncryptionOptions;

export interface LegacyPemEncryptionOptions {
	readonly password: string;
	readonly iv?: Uint8Array;
}

export function getCrypto(): Crypto {
	const c = globalThis.crypto;
	if (c?.subtle === undefined) {
		throw new Error('WebCrypto subtle API is required');
	}
	return c;
}

export async function generateKeyPair(
	algorithm: KeyAlgorithmInput = { kind: 'ecdsa', namedCurve: 'P-256' },
): Promise<KeyPairMaterial> {
	const subtle = getCrypto().subtle;
	const generated = await subtle.generateKey(toGenerateKeyAlgorithm(algorithm), true, [
		'sign',
		'verify',
	]);

	if (!('publicKey' in generated) || !('privateKey' in generated)) {
		throw new Error('Expected an asymmetric key pair');
	}

	return wrapKeyPair(generated.publicKey, generated.privateKey);
}

export function wrapKeyPair(publicKey: CryptoKey, privateKey: CryptoKey): KeyPairMaterial {
	return {
		publicKey,
		privateKey,
		async exportSpkiDer() {
			return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
		},
		async exportSpkiPem() {
			return pemEncode('PUBLIC KEY', await this.exportSpkiDer());
		},
		async exportPkcs8Der() {
			return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
		},
		async exportPkcs8Pem() {
			return pemEncode('PRIVATE KEY', await this.exportPkcs8Der());
		},
		async exportPublicJwk() {
			return getCrypto().subtle.exportKey('jwk', publicKey);
		},
		async exportPrivateJwk() {
			return getCrypto().subtle.exportKey('jwk', privateKey);
		},
	};
}

export async function exportSpkiDer(publicKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('spki', publicKey));
}

export async function exportPkcs8Der(privateKey: CryptoKey): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.exportKey('pkcs8', privateKey));
}

export async function exportPublicJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', publicKey);
}

export async function exportPrivateJwk(privateKey: CryptoKey): Promise<JsonWebKey> {
	return getCrypto().subtle.exportKey('jwk', privateKey);
}

export async function exportPkcs8Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('PRIVATE KEY', await exportPkcs8Der(privateKey));
}

export async function exportEncryptedPkcs8Der(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const encryption = await encryptPbes2(pkcs8, options);
	return sequence([encryption.algorithmIdentifierDer, octetString(encryption.encryptedData)]);
}

export async function exportEncryptedPkcs8Pem(
	privateKey: CryptoKey,
	options: EncryptedPkcs8Options,
): Promise<string> {
	return pemEncode('ENCRYPTED PRIVATE KEY', await exportEncryptedPkcs8Der(privateKey, options));
}

export async function exportPkcs1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.rsaEncryption) {
		throw new Error('PKCS#1 export requires an RSA private key');
	}
	return parsed.privateKeyDer;
}

export async function exportPkcs1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('RSA PRIVATE KEY', await exportPkcs1Der(privateKey));
}

export async function exportEncryptedPkcs1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('RSA PRIVATE KEY', await exportPkcs1Der(privateKey), options);
}

export async function exportSec1Der(privateKey: CryptoKey): Promise<Uint8Array> {
	const pkcs8 = await exportPkcs8Der(privateKey);
	const parsed = parsePkcs8PrivateKey(pkcs8);
	if (parsed.algorithmOid !== OIDS.ecPublicKey) {
		throw new Error('SEC1 export requires an EC private key');
	}
	return parsed.privateKeyDer;
}

export async function exportSec1Pem(privateKey: CryptoKey): Promise<string> {
	return pemEncode('EC PRIVATE KEY', await exportSec1Der(privateKey));
}

export async function exportEncryptedSec1Pem(
	privateKey: CryptoKey,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	return encryptTraditionalPem('EC PRIVATE KEY', await exportSec1Der(privateKey), options);
}

export async function exportSpkiPem(publicKey: CryptoKey): Promise<string> {
	return pemEncode('PUBLIC KEY', await exportSpkiDer(publicKey));
}

export async function exportBinaryBase64(key: CryptoKey): Promise<string> {
	if (key.type === 'public') {
		return base64Encode(await exportSpkiDer(key));
	}
	return base64Encode(await exportPkcs8Der(key));
}

export async function importSpkiDer(
	der: Uint8Array,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		'spki',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['verify'],
	);
}

export async function importSpkiPem(
	pem: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(pemDecode('PUBLIC KEY', pem), algorithm);
}

export async function importSpkiBase64(
	base64: string,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return importSpkiDer(base64Decode(base64), algorithm);
}

export async function importPkcs8Der(
	der: Uint8Array,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey(
		'pkcs8',
		new Uint8Array(der),
		toImportAlgorithm(algorithm),
		true,
		['sign'],
	);
}

export async function importPkcs8Pem(
	pem: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(pemDecode('PRIVATE KEY', pem), algorithm);
}

export async function importEncryptedPkcs8Der(
	der: Uint8Array,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	const children = readSequenceChildren(der);
	const algorithmIdentifier = children[0];
	const encryptedData = children[1];
	if (
		algorithmIdentifier === undefined ||
		encryptedData === undefined ||
		encryptedData.tag !== 0x04
	) {
		throw new Error('Malformed EncryptedPrivateKeyInfo');
	}
	const decrypted = await decryptPbes2(
		der.slice(
			algorithmIdentifier.start - algorithmIdentifier.headerLength,
			algorithmIdentifier.end,
		),
		encryptedData.value,
		password,
	);
	return importPkcs8Der(decrypted, algorithm);
}

export async function importEncryptedPkcs8Pem(
	pem: string,
	password: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importEncryptedPkcs8Der(pemDecode('ENCRYPTED PRIVATE KEY', pem), password, algorithm);
}

export async function importPkcs1Der(
	der: Uint8Array,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs8Der(wrapPkcs1InPkcs8(der), algorithm);
}

export async function importPkcs1Pem(
	pem: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	return importPkcs1Der(pemDecode('RSA PRIVATE KEY', pem), algorithm);
}

export async function importEncryptedPkcs1Pem(
	pem: string,
	password: string,
	algorithm: ImportRsaPublicKeyInput = { kind: 'rsa' },
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('RSA PRIVATE KEY', pem, password);
	try {
		return importPkcs1Der(decrypted, algorithm);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

export async function importPkcs8Base64(
	base64: string,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return importPkcs8Der(base64Decode(base64), algorithm);
}

export async function importSec1Der(
	der: Uint8Array,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importPkcs8Der(wrapSec1InPkcs8(der, algorithm.namedCurve), algorithm);
}

export async function importSec1Pem(
	pem: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	return importSec1Der(pemDecode('EC PRIVATE KEY', pem), algorithm);
}

export async function importEncryptedSec1Pem(
	pem: string,
	password: string,
	algorithm: ImportEcPublicKeyInput,
): Promise<CryptoKey> {
	const decrypted = await decryptTraditionalPem('EC PRIVATE KEY', pem, password);
	try {
		return importSec1Der(decrypted, algorithm);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

export async function importPublicJwk(
	jwk: JsonWebKey,
	algorithm: PublicKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['verify']);
}

export async function importPrivateJwk(
	jwk: JsonWebKey,
	algorithm: PrivateKeyImportInput,
): Promise<CryptoKey> {
	return getCrypto().subtle.importKey('jwk', jwk, toImportAlgorithm(algorithm), true, ['sign']);
}

function toGenerateKeyAlgorithm(
	algorithm: KeyAlgorithmInput,
): EcKeyGenParams | RsaHashedKeyGenParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				modulusLength: algorithm.modulusLength ?? 2048,
				publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.namedCurve ?? 'P-256',
			};
		case 'ed25519':
			return { name: 'Ed25519' };
	}
}

function toImportAlgorithm(
	algorithm: PublicKeyImportInput,
): EcKeyImportParams | RsaHashedImportParams | AlgorithmIdentifier {
	switch (algorithm.kind) {
		case 'rsa':
			return {
				name: rsaSchemeToWebCryptoAlgorithmName(algorithm.scheme),
				hash: algorithm.hash ?? 'SHA-256',
			};
		case 'ecdsa':
			return {
				name: 'ECDSA',
				namedCurve: algorithm.namedCurve,
			};
		case 'ed25519':
			return { name: 'Ed25519' };
	}
}

function parsePkcs8PrivateKey(der: Uint8Array): {
	readonly algorithmOid: string;
	readonly parametersOid?: string;
	readonly privateKeyDer: Uint8Array;
} {
	const children = readSequenceChildren(der);
	const algorithm = children[1];
	const privateKey = children[2];
	if (algorithm === undefined || privateKey === undefined) {
		throw new Error('Malformed PKCS#8 private key');
	}
	const algorithmChildren = readSequenceChildren(
		der.slice(algorithm.start - algorithm.headerLength, algorithm.end),
	);
	const algorithmOid = algorithmChildren[0];
	if (algorithmOid === undefined) {
		throw new Error('PKCS#8 algorithm OID missing');
	}
	const parameters = algorithmChildren[1];
	return {
		algorithmOid: decodeObjectIdentifier(algorithmOid.value),
		...(parameters?.tag === 0x06
			? { parametersOid: decodeObjectIdentifier(parameters.value) }
			: {}),
		privateKeyDer: privateKey.value,
	};
}

function wrapPkcs1InPkcs8(der: Uint8Array): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		octetString(new Uint8Array(der)),
	]);
}

function wrapSec1InPkcs8(
	der: Uint8Array,
	namedCurve: ImportEcPublicKeyInput['namedCurve'],
): Uint8Array {
	return sequence([
		Uint8Array.of(0x02, 0x01, 0x00),
		sequence([objectIdentifier(OIDS.ecPublicKey), objectIdentifier(namedCurveToOid(namedCurve))]),
		octetString(new Uint8Array(der)),
	]);
}

function namedCurveToOid(namedCurve: ImportEcPublicKeyInput['namedCurve']): string {
	switch (namedCurve) {
		case 'P-256':
			return OIDS.prime256v1;
		case 'P-384':
			return OIDS.secp384r1;
		case 'P-521':
			return OIDS.secp521r1;
	}
}

function rsaSchemeToWebCryptoAlgorithmName(
	scheme: RsaScheme | undefined,
): 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' {
	if (scheme === 'pss') {
		return 'RSA-PSS';
	}
	return 'RSASSA-PKCS1-v1_5';
}

async function encryptTraditionalPem(
	label: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	der: Uint8Array,
	options: LegacyPemEncryptionOptions,
): Promise<string> {
	const iv = options.iv ?? getCrypto().getRandomValues(new Uint8Array(16));
	if (iv.length !== 16) {
		throw new Error('Traditional PEM encryption requires a 16-byte IV');
	}
	const key = await importTraditionalPemAesKey(options.password, iv.slice(0, 8), ['encrypt']);
	const encrypted = new Uint8Array(
		await getCrypto().subtle.encrypt(
			{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
			key,
			toArrayBuffer(der),
		),
	);
	const body =
		base64Encode(encrypted)
			.match(/.{1,64}/g)
			?.join('\n') ?? '';
	return [
		`-----BEGIN ${label}-----`,
		'Proc-Type: 4,ENCRYPTED',
		`DEK-Info: AES-256-CBC,${toHex(iv).toUpperCase()}`,
		'',
		body,
		`-----END ${label}-----`,
	].join('\n');
}

async function decryptTraditionalPem(
	expectedLabel: 'RSA PRIVATE KEY' | 'EC PRIVATE KEY',
	pem: string,
	password: string,
): Promise<Uint8Array> {
	const parsed = parseTraditionalPem(pem);
	if (parsed.label !== expectedLabel) {
		throw new Error(`Expected ${expectedLabel} PEM block`);
	}
	const dekInfo = parsed.headers.get('DEK-Info');
	if (parsed.headers.get('Proc-Type') !== '4,ENCRYPTED' || dekInfo === undefined) {
		throw new Error('Traditional PEM encryption headers missing');
	}
	const [cipher, ivHex] = dekInfo.split(',');
	if (cipher !== 'AES-256-CBC' || ivHex === undefined) {
		throw new Error('Only AES-256-CBC traditional PEM encryption is supported');
	}
	const iv = hexToBytes(ivHex);
	const key = await importTraditionalPemAesKey(password, iv.slice(0, 8), ['decrypt']);
	try {
		return new Uint8Array(
			await getCrypto().subtle.decrypt(
				{ name: 'AES-CBC', iv: toArrayBuffer(iv) },
				key,
				toArrayBuffer(base64Decode(parsed.base64Body)),
			),
		);
	} catch {
		throw new Error('Invalid password or encrypted PEM content');
	}
}

async function importTraditionalPemAesKey(
	password: string,
	salt: Uint8Array,
	usages: KeyUsage[],
): Promise<CryptoKey> {
	const keyBytes = opensslBytesToKey(password, salt, 32);
	return getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'AES-CBC', length: 256 },
		false,
		usages,
	);
}

function opensslBytesToKey(password: string, salt: Uint8Array, length: number): Uint8Array {
	const passwordBytes = new TextEncoder().encode(password);
	const chunks: Uint8Array[] = [];
	let previous = new Uint8Array();
	let total = 0;
	while (total < length) {
		const input = new Uint8Array(previous.length + passwordBytes.length + salt.length);
		input.set(previous, 0);
		input.set(passwordBytes, previous.length);
		input.set(salt, previous.length + passwordBytes.length);
		previous = md5(input);
		chunks.push(previous);
		total += previous.length;
	}
	const out = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		const slice = chunk.slice(0, Math.min(chunk.length, length - offset));
		out.set(slice, offset);
		offset += slice.length;
		if (offset >= length) {
			break;
		}
	}
	return out;
}

function parseTraditionalPem(pem: string): {
	readonly label: string;
	readonly headers: ReadonlyMap<string, string>;
	readonly base64Body: string;
} {
	const normalized = pem.replace(/\r/g, '').trim();
	const lines = normalized.split('\n');
	const begin = lines[0];
	const end = lines[lines.length - 1];
	if (
		begin === undefined ||
		end === undefined ||
		!begin.startsWith('-----BEGIN ') ||
		!end.startsWith('-----END ')
	) {
		throw new Error('Invalid PEM block');
	}
	const label = begin.slice(11, -5);
	if (end !== `-----END ${label}-----`) {
		throw new Error('PEM boundaries do not match');
	}
	const headers = new Map<string, string>();
	let index = 1;
	while (index < lines.length - 1) {
		const line = lines[index];
		if (line === undefined) {
			break;
		}
		if (line.length === 0) {
			index += 1;
			break;
		}
		const delimiter = line.indexOf(': ');
		if (delimiter === -1) {
			break;
		}
		headers.set(line.slice(0, delimiter), line.slice(delimiter + 2));
		index += 1;
	}
	const body = lines.slice(index, lines.length - 1).join('');
	return { label, headers, base64Body: body };
}
