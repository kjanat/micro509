/**
 * PKCS#12 MAC data creation and verification.
 *
 * Computes and verifies the password-based integrity check of a PFX: the
 * RFC 7292 HMAC-SHA-256 MAC keyed by the PKCS#12 key-derivation scheme, and
 * PBMAC1 (RFC 9879) keyed by PBKDF2.
 *
 * @module
 */

import {
	decodeIntegerMagnitude,
	decodeObjectIdentifier,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1';
import type { DerElement } from '#micro509/internal/asn1/der';
import {
	concatBytes,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { describeHashAlgorithm } from '#micro509/internal/crypto/algorithm-names';
import {
	chargeKdfBudget,
	createKdfBudget,
	DEFAULT_MAX_KDF_ITERATIONS,
	DEFAULT_MAX_PKCS12_MAC_ITERATIONS,
	derivePbkdf2Bytes,
	isKdfIterationLimitError,
	type KdfBudget,
	type KdfLimitOptions,
	type Pbkdf2Hash,
	WEBCRYPTO_MAX_PBKDF2_ITERATIONS,
} from '#micro509/internal/crypto/pbes2';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import type { ErrorResult, Micro509Error } from '#micro509/result/result';
import {
	failureResult,
	isResultError,
	rethrowIfInvariant,
	successResult,
	throwMicro509Error,
} from '#micro509/result/result';

/** Machine-readable reason {@linkcode createPkcs12MacData} rejected its construction input. */
export type CreatePkcs12MacDataErrorCode =
	| 'password_not_bmp_string'
	| 'password_not_utf8'
	| 'invalid_iterations';

function throwPkcs12MacError(code: CreatePkcs12MacDataErrorCode, message: string): never {
	throwMicro509Error(code, message);
}

/**
 * Input for {@linkcode createPkcs12MacData}. `type` selects the MAC: `'pkcs12-kdf'` (the
 * default) is the RFC 7292 HMAC-SHA-256 MAC keyed by the PKCS#12 KDF, and `'pbmac1'` is
 * RFC 9879 PBMAC1 with PBKDF2-HMAC-SHA-256, a 32-octet key and HMAC-SHA-256.
 */
export type Pkcs12MacOptions =
	| {
			/** RFC 7292 Appendix B key derivation with HMAC-SHA-256. */
			readonly type?: 'pkcs12-kdf';
			/**
			 * Password used to derive the HMAC key via the PKCS#12 KDF. Every character must be a
			 * BMPString character, so UTF-16 surrogates are rejected.
			 */
			readonly password: string;
			/** PKCS#12 KDF iteration count, a positive safe integer. Default: `2048`. */
			readonly iterations?: number;
			/** Random salt. Default: 16 cryptographically random bytes. */
			readonly salt?: Uint8Array;
	  }
	| {
			/** RFC 9879 PBMAC1. */
			readonly type: 'pbmac1';
			/**
			 * Password fed to PBKDF2 as UTF-8 without a NULL terminator. Unpaired UTF-16
			 * surrogates are rejected.
			 */
			readonly password: string;
			/** PBKDF2 iteration count, an integer from 1 to 4294967295. Default: `100_000`. */
			readonly iterations?: number;
			/** PBKDF2 salt, also written to the ignored MacData macSalt. Default: 16 random bytes. */
			readonly salt?: Uint8Array;
	  };

/**
 * Decoded PKCS#12 MacData block returned by {@linkcode parsePkcs12MacData}. `type` names the
 * MAC: `'pkcs12-kdf'` for the RFC 7292 MAC and `'pbmac1'` for RFC 9879 PBMAC1.
 */
export type ParsedPkcs12MacData =
	| {
			/** RFC 7292 MAC keyed by the PKCS#12 KDF. */
			readonly type: 'pkcs12-kdf';
			/** OID of the digest algorithm (always SHA-256). */
			readonly digestAlgorithmOid: string;
			/** Human-readable digest algorithm name (`"SHA-256"`). */
			readonly digestAlgorithmName: string;
			/** Hex-encoded MAC digest value. */
			readonly digestHex: string;
			/** Hex-encoded MacData macSalt. */
			readonly saltHex: string;
			/** MacData iterations, the PKCS#12 KDF iteration count. */
			readonly iterations: number;
			/**
			 * MAC verification outcome: `'unchecked'` when no password was supplied
			 * during parsing, otherwise `'valid'` or `'invalid'`.
			 */
			readonly verification: 'valid' | 'invalid' | 'unchecked';
	  }
	| {
			/** RFC 9879 PBMAC1 keyed by PBKDF2. */
			readonly type: 'pbmac1';
			/** The id-PBMAC1 OID. */
			readonly digestAlgorithmOid: string;
			/** Always `"PBMAC1"`. */
			readonly digestAlgorithmName: string;
			/** Hex-encoded MAC value. */
			readonly digestHex: string;
			/** Hex-encoded PBKDF2 salt. MacData macSalt is ignored. */
			readonly saltHex: string;
			/** PBKDF2 iteration count. MacData iterations is ignored. */
			readonly iterations: number;
			/** PBKDF2 keyLength in octets. */
			readonly keyLength: number;
			/** PBKDF2 pseudorandom function. */
			readonly prf: 'HMAC-SHA-256' | 'HMAC-SHA-384' | 'HMAC-SHA-512';
			/** PBMAC1 message authentication scheme. */
			readonly messageAuthScheme: 'HMAC-SHA-256' | 'HMAC-SHA-384' | 'HMAC-SHA-512';
			/**
			 * MAC verification outcome: `'unchecked'` when no password was supplied
			 * during parsing, otherwise `'valid'` or `'invalid'`.
			 */
			readonly verification: 'valid' | 'invalid' | 'unchecked';
	  };

type ParsedPbmac1MacData = Extract<ParsedPkcs12MacData, { readonly type: 'pbmac1' }>;
type Pbmac1Hmac = ParsedPbmac1MacData['prf'];

const PBMAC1_MAX_KEY_LENGTH = 64;
const PBMAC1_MIN_KEY_LENGTH = 20;

/**
 * Computes a PKCS#12 MAC over the AuthenticatedSafe and returns the DER-encoded MacData
 * block alongside its parsed representation.
 *
 * @throws {ResultError} with code `invalid_iterations` when `iterations` is out of range,
 * `password_not_bmp_string` when a `'pkcs12-kdf'` password contains a UTF-16 surrogate, and
 * `password_not_utf8` when a `'pbmac1'` password contains an unpaired UTF-16 surrogate.
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
	if (options.type === 'pbmac1') {
		return await createPbmac1MacData(authenticatedSafe, options);
	}
	const iterations = options.iterations ?? 2048;
	if (!Number.isSafeInteger(iterations) || iterations <= 0) {
		throwPkcs12MacError(
			'invalid_iterations',
			`MacData iterations must be a positive safe integer, got ${iterations}`,
		);
	}
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const mac = await computePkcs12Mac(authenticatedSafe, options.password, salt, iterations);
	const der = sequence([
		sequence([sequence([objectIdentifier(OIDS.sha256), nullValue()]), octetString(mac)]),
		octetString(salt),
		...(iterations === 1 ? [] : [integerFromNumber(iterations)]),
	]);
	return {
		der,
		parsed: {
			type: 'pkcs12-kdf',
			digestAlgorithmOid: OIDS.sha256,
			digestAlgorithmName: describeHashAlgorithm(OIDS.sha256),
			digestHex: toHex(mac),
			saltHex: toHex(salt),
			iterations,
			verification: 'valid',
		},
	};
}

async function createPbmac1MacData(
	authenticatedSafe: Uint8Array,
	options: Extract<Pkcs12MacOptions, { readonly type: 'pbmac1' }>,
): Promise<{ readonly der: Uint8Array; readonly parsed: ParsedPkcs12MacData }> {
	const iterations = options.iterations ?? 100_000;
	if (
		!Number.isInteger(iterations) ||
		iterations < 1 ||
		iterations > WEBCRYPTO_MAX_PBKDF2_ITERATIONS
	) {
		throwPkcs12MacError(
			'invalid_iterations',
			`PBMAC1 iterations must be an integer from 1 to ${WEBCRYPTO_MAX_PBKDF2_ITERATIONS}, got ${iterations}`,
		);
	}
	const salt = options.salt ?? getCrypto().getRandomValues(new Uint8Array(16));
	const parameters: Pbmac1Parameters = {
		salt,
		iterations,
		keyLength: 32,
		prf: 'HMAC-SHA-256',
		messageAuthScheme: 'HMAC-SHA-256',
	};
	const mac = await computePbmac1(authenticatedSafe, options.password, parameters);
	const hmacWithSha256 = sequence([objectIdentifier(OIDS.hmacWithSHA256), nullValue()]);
	const algorithm = sequence([
		objectIdentifier(OIDS.pbmac1),
		sequence([
			sequence([
				objectIdentifier(OIDS.pbkdf2),
				sequence([
					octetString(salt),
					integerFromNumber(iterations),
					integerFromNumber(parameters.keyLength),
					hmacWithSha256,
				]),
			]),
			hmacWithSha256,
		]),
	]);
	return {
		der: sequence([sequence([algorithm, octetString(mac)]), octetString(salt)]),
		parsed: {
			type: 'pbmac1',
			digestAlgorithmOid: OIDS.pbmac1,
			digestAlgorithmName: 'PBMAC1',
			digestHex: toHex(mac),
			saltHex: toHex(salt),
			iterations,
			keyLength: parameters.keyLength,
			prf: parameters.prf,
			messageAuthScheme: parameters.messageAuthScheme,
			verification: 'valid',
		},
	};
}

/** Machine-readable failure reason for {@linkcode parsePkcs12MacData}. */
export type ParsePkcs12MacDataErrorCode =
	| 'malformed'
	| 'kdf_iterations_exceeded'
	| 'password_not_bmp_string'
	| 'password_not_utf8'
	| 'unsupported_mac_algorithm'
	| 'weak_mac_key_length';

type ThrownMacDataErrorCode = Exclude<
	ParsePkcs12MacDataErrorCode,
	'malformed' | 'kdf_iterations_exceeded'
>;

const THROWN_MAC_DATA_ERROR_CODES = [
	'password_not_bmp_string',
	'password_not_utf8',
	'unsupported_mac_algorithm',
	'weak_mac_key_length',
] as const satisfies readonly ThrownMacDataErrorCode[];

function throwMacDataError(
	code: 'unsupported_mac_algorithm' | 'weak_mac_key_length',
	message: string,
): never {
	throwMicro509Error(code, message);
}

/** Options for {@linkcode parsePkcs12MacData} and {@linkcode parsePkcs12MacDataOrThrow}. */
export type ParsePkcs12MacDataOptions = KdfLimitOptions;

/** Structured failure payload for MacData parsing. */
export interface ParsePkcs12MacDataFailure extends Micro509Error<ParsePkcs12MacDataErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parsePkcs12MacData}. */
export type ParsePkcs12MacDataResult =
	| { readonly ok: true; readonly value: ParsedPkcs12MacData }
	| ErrorResult<ParsePkcs12MacDataErrorCode, Record<never, never>, ParsePkcs12MacDataFailure>;

/**
 * Throwing core for {@linkcode parsePkcs12MacData}. When `password` is
 * provided, verifies the MAC and reports the outcome in `verification`, and
 * throws before deriving when the iteration count exceeds
 * `options.maxKdfIterations` or {@linkcode Number.MAX_SAFE_INTEGER}. The
 * default limit is `100_000` for the PKCS#12 KDF and `2_000_000` for the
 * PBKDF2 behind PBMAC1. Without `password` no key is derived, so
 * `options.maxKdfIterations` is not applied and `verification` is
 * `'unchecked'`. Throws a {@linkcode ResultError} carrying a
 * {@linkcode ParsePkcs12MacDataErrorCode} for an unsupported MAC, a PBMAC1 key
 * length below 20 octets, or a password the MAC cannot encode.
 */
export async function parsePkcs12MacDataOrThrow(
	der: Uint8Array,
	authenticatedSafe: Uint8Array,
	password?: string,
	options?: ParsePkcs12MacDataOptions,
): Promise<ParsedPkcs12MacData> {
	const pkcs12Budget = createKdfBudget(options, DEFAULT_MAX_PKCS12_MAC_ITERATIONS);
	const pbkdf2Budget = createKdfBudget(options, DEFAULT_MAX_KDF_ITERATIONS);
	const top = readSequenceChildren(der);
	const digestInfo = top[0];
	const salt = top[1];
	const iterations = top[2];
	if (
		(top.length !== 2 && top.length !== 3) ||
		digestInfo === undefined ||
		salt === undefined ||
		salt.tag !== 0x04 ||
		(iterations !== undefined && iterations.tag !== 0x02)
	) {
		throw new Error('Malformed MacData');
	}
	const digestInfoDer = der.slice(digestInfo.start - digestInfo.headerLength, digestInfo.end);
	const digestInfoChildren = readSequenceChildren(digestInfoDer);
	const algorithm = digestInfoChildren[0];
	const digest = digestInfoChildren[1];
	if (
		digestInfoChildren.length !== 2 ||
		algorithm === undefined ||
		digest === undefined ||
		digest.tag !== 0x04
	) {
		throw new Error('Malformed DigestInfo');
	}
	const algorithmDer = digestInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end);
	const algorithmChildren = readSequenceChildren(algorithmDer);
	const algorithmOid = algorithmChildren[0];
	if (
		algorithmOid === undefined ||
		(algorithmChildren.length !== 1 && algorithmChildren.length !== 2)
	) {
		throw new Error('MacData algorithm missing');
	}
	const digestAlgorithmOid = decodeObjectIdentifier(algorithmOid.value);
	if (digestAlgorithmOid === OIDS.pbmac1) {
		return await verifyPbmac1MacData(
			algorithmDer,
			algorithmChildren[1],
			digest.value,
			authenticatedSafe,
			password,
			pbkdf2Budget,
		);
	}
	if (digestAlgorithmOid !== OIDS.sha256) {
		throwMacDataError(
			'unsupported_mac_algorithm',
			`Only SHA-256 PKCS#12 MAC and PBMAC1 are supported, got ${describeHashAlgorithm(digestAlgorithmOid)}`,
		);
	}
	const parsedIterations =
		iterations === undefined
			? 1
			: decodeMacIterations(iterations.value, pkcs12Budget, password, 'MacData iterations');
	if (parsedIterations === 0) {
		throw new Error('MacData iterations must be a positive safe integer');
	}
	const unchecked = {
		type: 'pkcs12-kdf',
		digestAlgorithmOid,
		digestAlgorithmName: describeHashAlgorithm(digestAlgorithmOid),
		digestHex: toHex(digest.value),
		saltHex: toHex(salt.value),
		iterations: parsedIterations,
		verification: 'unchecked',
	} as const;
	if (password === undefined) {
		return unchecked;
	}
	chargeKdfBudget(pkcs12Budget, parsedIterations);
	const expected = await computePkcs12Mac(
		authenticatedSafe,
		password,
		salt.value,
		parsedIterations,
	);
	return {
		...unchecked,
		verification: equalBytes(expected, digest.value) ? 'valid' : 'invalid',
	};
}

/**
 * Decodes a DER-encoded MacData block. When `password` is provided, verifies
 * the MAC and reports the outcome in `verification`.
 *
 * Returns a typed failure (`code: 'malformed'`) on malformed input, an
 * iteration count below 1, or a PBMAC1 iteration count above 4294967295,
 * `'unsupported_mac_algorithm'` for a MAC other than
 * the RFC 7292 SHA-256 MAC or a PBMAC1 variant this implementation does not
 * handle, `'weak_mac_key_length'` for a PBMAC1 key length below 20 octets,
 * `'password_not_bmp_string'` when an RFC 7292 password contains a UTF-16
 * surrogate, and `'password_not_utf8'` when a PBMAC1 password contains an
 * unpaired UTF-16 surrogate. With a `password`, returns
 * `code: 'kdf_iterations_exceeded'` when the iteration count exceeds
 * `options.maxKdfIterations`, or an RFC 7292 MAC count exceeds
 * {@linkcode Number.MAX_SAFE_INTEGER}. Without a `password` no key is derived:
 * `options.maxKdfIterations` is not applied, an RFC 7292 MAC count above
 * {@linkcode Number.MAX_SAFE_INTEGER} is `'malformed'`, and `verification` is
 * `'unchecked'`. For the throwing form use {@linkcode parsePkcs12MacDataOrThrow}.
 */
export async function parsePkcs12MacData(
	der: Uint8Array,
	authenticatedSafe: Uint8Array,
	password?: string,
	options?: ParsePkcs12MacDataOptions,
): Promise<ParsePkcs12MacDataResult> {
	try {
		return successResult(
			await parsePkcs12MacDataOrThrow(der, authenticatedSafe, password, options),
		);
	} catch (error) {
		rethrowIfInvariant(error);
		if (isKdfIterationLimitError(error)) {
			return failureResult('kdf_iterations_exceeded', error.message);
		}
		if (isResultError(error)) {
			const code = THROWN_MAC_DATA_ERROR_CODES.find((candidate) => candidate === error.code);
			if (code !== undefined) {
				return failureResult(code, error.error.message);
			}
		}
		return failureResult('malformed', error instanceof Error ? error.message : 'Malformed MacData');
	}
}

function decodeMacIterations(
	content: Uint8Array,
	budget: KdfBudget,
	password: string | undefined,
	label: string,
): number {
	const magnitude = decodeIntegerMagnitude(content, label);
	if (magnitude.type === 'safe') {
		return magnitude.value;
	}
	if (password !== undefined) {
		chargeKdfBudget(budget, Number.POSITIVE_INFINITY);
	}
	throw new Error(`${label} too large for safe number (${content.length} bytes)`);
}

interface Pbmac1Parameters {
	readonly salt: Uint8Array;
	readonly iterations: number;
	readonly keyLength: number;
	readonly prf: Pbmac1Hmac;
	readonly messageAuthScheme: Pbmac1Hmac;
}

interface AlgorithmIdentifierFields {
	readonly oid: string;
	readonly parameters: DerElement | undefined;
	readonly der: Uint8Array;
}

async function verifyPbmac1MacData(
	algorithmDer: Uint8Array,
	parametersElement: DerElement | undefined,
	digest: Uint8Array,
	authenticatedSafe: Uint8Array,
	password: string | undefined,
	budget: KdfBudget,
): Promise<ParsedPbmac1MacData> {
	if (parametersElement === undefined) {
		throw new Error('PBMAC1 parameters must be present');
	}
	const parameters = parsePbmac1Parameters(algorithmDer, parametersElement);
	const unchecked = {
		type: 'pbmac1',
		digestAlgorithmOid: OIDS.pbmac1,
		digestAlgorithmName: 'PBMAC1',
		digestHex: toHex(digest),
		saltHex: toHex(parameters.salt),
		iterations: parameters.iterations,
		keyLength: parameters.keyLength,
		prf: parameters.prf,
		messageAuthScheme: parameters.messageAuthScheme,
		verification: 'unchecked',
	} as const;
	if (password === undefined) {
		return unchecked;
	}
	chargeKdfBudget(budget, parameters.iterations);
	const expected = await computePbmac1(authenticatedSafe, password, parameters);
	return { ...unchecked, verification: equalBytes(expected, digest) ? 'valid' : 'invalid' };
}

function parsePbmac1Parameters(
	algorithmDer: Uint8Array,
	parametersElement: DerElement,
): Pbmac1Parameters {
	if (parametersElement.tag !== 0x30) {
		throw new Error('Malformed PBMAC1-params');
	}
	const paramsDer = algorithmDer.slice(
		parametersElement.start - parametersElement.headerLength,
		parametersElement.end,
	);
	const children = readSequenceChildren(paramsDer);
	const kdfElement = children[0];
	const macElement = children[1];
	if (children.length !== 2 || kdfElement === undefined || macElement === undefined) {
		throw new Error('Malformed PBMAC1-params');
	}
	const kdf = readAlgorithmIdentifier(paramsDer, kdfElement, 'PBMAC1 keyDerivationFunc');
	if (kdf.oid !== OIDS.pbkdf2) {
		throwMacDataError(
			'unsupported_mac_algorithm',
			`Unsupported PBMAC1 key derivation function ${kdf.oid}`,
		);
	}
	const messageAuthScheme = parseHmacAlgorithm(
		readAlgorithmIdentifier(paramsDer, macElement, 'PBMAC1 messageAuthScheme'),
		'PBMAC1 messageAuthScheme',
	);
	return { ...parsePbkdf2Parameters(kdf), messageAuthScheme };
}

function parsePbkdf2Parameters(
	kdf: AlgorithmIdentifierFields,
): Omit<Pbmac1Parameters, 'messageAuthScheme'> {
	if (kdf.parameters === undefined || kdf.parameters.tag !== 0x30) {
		throw new Error('Malformed PBKDF2-params');
	}
	const der = kdf.der.slice(kdf.parameters.start - kdf.parameters.headerLength, kdf.parameters.end);
	const [salt, iterationCount, ...optional] = readSequenceChildren(der);
	if (salt === undefined || iterationCount === undefined || iterationCount.tag !== 0x02) {
		throw new Error('Malformed PBKDF2-params');
	}
	if (salt.tag === 0x30) {
		throwMacDataError('unsupported_mac_algorithm', 'PBKDF2 otherSource salt is not supported');
	}
	if (salt.tag !== 0x04) {
		throw new Error('Malformed PBKDF2 salt');
	}
	const keyLengthElement = optional[0]?.tag === 0x02 ? optional[0] : undefined;
	const rest = keyLengthElement === undefined ? optional : optional.slice(1);
	const prfElement = rest[0];
	if (rest.length > 1 || (prfElement !== undefined && prfElement.tag !== 0x30)) {
		throw new Error('Malformed PBKDF2-params');
	}
	if (keyLengthElement === undefined) {
		throw new Error('PBKDF2-params in PBMAC1 must include keyLength');
	}
	if (prfElement === undefined) {
		throwMacDataError(
			'unsupported_mac_algorithm',
			'PBKDF2 prf is absent and defaults to HMAC-SHA-1, which PBMAC1 verification does not accept',
		);
	}
	const prf = parseHmacAlgorithm(
		readAlgorithmIdentifier(der, prfElement, 'PBKDF2 prf'),
		'PBKDF2 prf',
	);
	const iterations = decodeIntegerMagnitude(iterationCount.value, 'PBKDF2 iterationCount');
	if (iterations.type === 'unsafe' || iterations.value > WEBCRYPTO_MAX_PBKDF2_ITERATIONS) {
		throw new Error(`PBKDF2 iterationCount must be at most ${WEBCRYPTO_MAX_PBKDF2_ITERATIONS}`);
	}
	if (iterations.value === 0) {
		throw new Error('PBKDF2 iterationCount must be at least 1');
	}
	return {
		salt: new Uint8Array(salt.value),
		iterations: iterations.value,
		keyLength: decodePbmac1KeyLength(keyLengthElement.value),
		prf,
	};
}

function decodePbmac1KeyLength(content: Uint8Array): number {
	const magnitude = decodeIntegerMagnitude(content, 'PBKDF2 keyLength');
	if (magnitude.type === 'unsafe' || magnitude.value > PBMAC1_MAX_KEY_LENGTH) {
		throwMacDataError(
			'unsupported_mac_algorithm',
			`PBKDF2 keyLength above ${PBMAC1_MAX_KEY_LENGTH} octets is not supported`,
		);
	}
	if (magnitude.value === 0) {
		throw new Error('PBKDF2 keyLength must be at least 1');
	}
	if (magnitude.value < PBMAC1_MIN_KEY_LENGTH) {
		throwMacDataError(
			'weak_mac_key_length',
			`PBKDF2 keyLength ${magnitude.value} is below ${PBMAC1_MIN_KEY_LENGTH} octets`,
		);
	}
	return magnitude.value;
}

function readAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
	label: string,
): AlgorithmIdentifierFields {
	if (element.tag !== 0x30) {
		throw new Error(`Malformed ${label}`);
	}
	const der = source.slice(element.start - element.headerLength, element.end);
	const children = readSequenceChildren(der);
	const oid = children[0];
	if (oid === undefined || oid.tag !== 0x06 || children.length > 2) {
		throw new Error(`Malformed ${label}`);
	}
	return { oid: decodeObjectIdentifier(oid.value), parameters: children[1], der };
}

function parseHmacAlgorithm(algorithm: AlgorithmIdentifierFields, label: string): Pbmac1Hmac {
	if (
		algorithm.parameters !== undefined &&
		(algorithm.parameters.tag !== 0x05 || algorithm.parameters.length !== 0)
	) {
		throw new Error(`${label} parameters must be NULL`);
	}
	switch (algorithm.oid) {
		case OIDS.hmacWithSHA256:
			return 'HMAC-SHA-256';
		case OIDS.hmacWithSHA384:
			return 'HMAC-SHA-384';
		case OIDS.hmacWithSHA512:
			return 'HMAC-SHA-512';
	}
	return throwMacDataError('unsupported_mac_algorithm', `Unsupported ${label} ${algorithm.oid}`);
}

function hmacHash(name: Pbmac1Hmac): Pbkdf2Hash {
	switch (name) {
		case 'HMAC-SHA-256':
			return 'SHA-256';
		case 'HMAC-SHA-384':
			return 'SHA-384';
		case 'HMAC-SHA-512':
			return 'SHA-512';
		default: {
			const _exhaustive: never = name;
			throw new Error(`Unhandled PBMAC1 HMAC: ${String(_exhaustive)}`);
		}
	}
}

async function computePbmac1(
	authenticatedSafe: Uint8Array,
	password: string,
	parameters: Pbmac1Parameters,
): Promise<Uint8Array> {
	const keyBytes = await derivePbkdf2Bytes(
		encodePbmac1Password(password),
		parameters.salt,
		parameters.iterations,
		hmacHash(parameters.prf),
		parameters.keyLength,
	);
	return await hmac(authenticatedSafe, keyBytes, hmacHash(parameters.messageAuthScheme));
}

function encodePbmac1Password(password: string): Uint8Array {
	for (let index = 0; index < password.length; index += 1) {
		const code = password.charCodeAt(index);
		if (code >= 0xd800 && code <= 0xdbff) {
			const next = password.charCodeAt(index + 1);
			if (next >= 0xdc00 && next <= 0xdfff) {
				index += 1;
				continue;
			}
		}
		if (code >= 0xd800 && code <= 0xdfff) {
			throwPkcs12MacError(
				'password_not_utf8',
				`PBMAC1 password has no UTF-8 encoding: unpaired UTF-16 surrogate 0x${code.toString(16)} at index ${index}`,
			);
		}
	}
	return new TextEncoder().encode(password);
}

/** Derives an HMAC-SHA-256 key via the PKCS#12 KDF and signs the AuthenticatedSafe. */
async function computePkcs12Mac(
	authenticatedSafe: Uint8Array,
	password: string,
	salt: Uint8Array,
	iterations: number,
): Promise<Uint8Array> {
	const keyBytes = await derivePkcs12Key(password, salt, iterations, 3, 32);
	return await hmac(authenticatedSafe, keyBytes, 'SHA-256');
}

async function hmac(
	message: Uint8Array,
	keyBytes: Uint8Array,
	hash: Pbkdf2Hash,
): Promise<Uint8Array> {
	const key = await getCrypto().subtle.importKey(
		'raw',
		toArrayBuffer(keyBytes),
		{ name: 'HMAC', hash },
		false,
		['sign'],
	);
	return new Uint8Array(await getCrypto().subtle.sign('HMAC', key, toArrayBuffer(message)));
}

/**
 * PKCS#12 key derivation with SHA-256 (RFC 7292 Appendix B). `id` selects the purpose:
 * 1 for key material, 2 for an IV, 3 for a MAC key.
 *
 * @throws {ResultError} with code `password_not_bmp_string` when the password contains a
 * UTF-16 surrogate.
 */
export async function derivePkcs12Key(
	password: string,
	salt: Uint8Array,
	iterations: number,
	id: 1 | 2 | 3,
	length: number,
): Promise<Uint8Array> {
	const u = 32;
	const v = 64;
	const D = new Uint8Array(v).fill(id);
	const passwordBytes = encodePkcs12Password(password);
	const I = concatBytes([repeatToMultiple(salt, v), repeatToMultiple(passwordBytes, v)]);
	const blocks = Math.ceil(length / u);
	const output = new Uint8Array(blocks * u);
	for (let index = 0; index < blocks; index += 1) {
		let A = await digestSha256(concatBytes([D, I]));
		for (let round = 1; round < iterations; round += 1) {
			A = await digestSha256(A);
		}
		output.set(A, index * u);
		if (index + 1 === blocks) {
			break;
		}
		const B = repeatToLength(A, v);
		for (let offset = 0; offset < I.length; offset += v) {
			addBlockInPlace(I.subarray(offset, offset + v), B);
		}
	}
	return output.slice(0, length);
}

/** SHA-256 hash via WebCrypto. */
async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest('SHA-256', toArrayBuffer(bytes)));
}

/** Encodes a password as a null-terminated BMPString, two big-endian bytes per character (RFC 7292 B.1). */
function encodePkcs12Password(password: string): Uint8Array {
	const out = new Uint8Array((password.length + 1) * 2);
	for (let index = 0; index < password.length; index += 1) {
		const code = password.charCodeAt(index);
		if (code >= 0xd800 && code <= 0xdfff) {
			throwPkcs12MacError(
				'password_not_bmp_string',
				`PKCS#12 password is not a BMPString: UTF-16 surrogate 0x${code.toString(16)} at index ${index}`,
			);
		}
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
