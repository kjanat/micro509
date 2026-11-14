/**
 * Signature-verification helpers that resolve parsed algorithm OIDs into WebCrypto
 * verification configuration for higher-level validators.
 *
 * @module
 */

import { canonicalizeOid, toArrayBuffer } from '#micro509/internal/asn1/asn1';
import { DECODE_LIMIT_CODES, rethrowDecodeRefusal } from '#micro509/internal/asn1/decode-refusal';
import { readElement, readSequenceChildren } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	alternateEcdsaSignatureEncoding,
	derEcdsaSignatureToRaw,
} from '#micro509/internal/crypto/ecdsa';
import { parseRsaPssParameters } from '#micro509/internal/crypto/rsa-pss';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import type { PublicKeyImportInput, RsaHash, RsaSignatureScheme } from '#micro509/keys/keys';
import { importSpkiDerOrThrow } from '#micro509/keys/keys';

export {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	derEcdsaSignatureToRaw,
	rawEcdsaSignatureToDer,
} from '#micro509/internal/crypto/ecdsa';

/** One signature handed to a {@linkcode SignatureVerifier}. */
export interface SignatureVerifierInput {
	/** The signature algorithm as carried beside the signature. */
	readonly signatureAlgorithm: {
		/** Dotted-decimal signature algorithm OID. */
		readonly oid: string;
		/** DER algorithm parameters, when the signature carries them. */
		readonly parametersDer?: Uint8Array;
	};
	/** DER `SubjectPublicKeyInfo` of the signer. */
	readonly signerSpkiDer: Uint8Array;
	/**
	 * DER parameters to verify with: RFC 5280 §6.1 `working_public_key_parameters`.
	 * These are the signer's own key parameters, or the parameters it inherits along
	 * the certification path when its own are absent or NULL (RFC 5280 §6.1.4 (e),
	 * RFC 3279 §2.3.2). Absent when the path leaves none.
	 */
	readonly signerPublicKeyParametersDer?: Uint8Array;
	/** The signature bytes as carried. */
	readonly signature: Uint8Array;
	/** The exact bytes the signature covers. */
	readonly data: Uint8Array;
}

/**
 * Caller-supplied verification for a signature algorithm micro509 does not run
 * through WebCrypto. Resolves `true` only for a valid signature. A rejection is
 * reported as a verification error.
 */
export type SignatureVerifier = (input: SignatureVerifierInput) => Promise<boolean>;

/**
 * Caller verifiers keyed by dotted-decimal signature algorithm OID. A key that
 * micro509 verifies natively throws `RangeError`, so a caller verifier never
 * replaces WebCrypto verification.
 */
export type SignatureVerifiers = Readonly<Record<string, SignatureVerifier>>;

const NATIVE_SIGNATURE_ALGORITHMS: ReadonlySet<string> = new Set([
	OIDS.sha256WithRSAEncryption,
	OIDS.sha384WithRSAEncryption,
	OIDS.sha512WithRSAEncryption,
	OIDS.rsassaPss,
	OIDS.ecdsaWithSHA256,
	OIDS.ecdsaWithSHA384,
	OIDS.ecdsaWithSHA512,
	OIDS.ed25519,
]);

/**
 * Validates caller verifiers and indexes them by canonical OID.
 *
 * @throws RangeError for a key that is no encodable OID, a natively verified
 * algorithm, or a value that is no function.
 */
export function resolveSignatureVerifiers(
	verifiers: SignatureVerifiers | undefined,
): ReadonlyMap<string, SignatureVerifier> {
	const resolved = new Map<string, SignatureVerifier>();
	if (verifiers === undefined) return resolved;
	for (const [oid, verifier] of Object.entries(verifiers)) {
		const canonical = canonicalVerifierOid(oid);
		if (NATIVE_SIGNATURE_ALGORITHMS.has(canonical)) {
			throw new RangeError(`signatureVerifiers cannot replace native verification of ${oid}`);
		}
		if (typeof verifier !== 'function') {
			throw new RangeError(`signatureVerifiers value for ${oid} is not a function`);
		}
		if (resolved.has(canonical)) {
			throw new RangeError(`signatureVerifiers names ${canonical} twice`);
		}
		resolved.set(canonical, verifier);
	}
	return resolved;
}

function canonicalVerifierOid(oid: string): string {
	if (!/^\d+(?:\.\d+)+$/.test(oid)) {
		throw new RangeError(`signatureVerifiers key is not an OID: ${oid}`);
	}
	try {
		return canonicalizeOid(oid);
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
		throw new RangeError(`signatureVerifiers key is not an OID: ${oid}`);
	}
}

/** The caller verifiers for one signature, and the key parameters a certification path gives its signer. */
export interface CallerVerification {
	/** Resolved caller verifiers, keyed by canonical signature algorithm OID. */
	readonly verifiers: ReadonlyMap<string, SignatureVerifier>;
	/**
	 * RFC 5280 §6.1 `working_public_key_parameters` of the signer along its path.
	 * Omitted to use the parameters in the signer's own SubjectPublicKeyInfo.
	 */
	readonly workingParameters?: { readonly parametersDer: Uint8Array | undefined };
}

/** No caller verifiers: every signature goes through WebCrypto. */
export const NO_CALLER_VERIFICATION: CallerVerification = { verifiers: new Map() };

/** Caller verification with `verifiers` and the signer's own key parameters. */
export function callerVerification(verifiers: SignatureVerifiers | undefined): CallerVerification {
	return { verifiers: resolveSignatureVerifiers(verifiers) };
}

/** DER key parameters, or `undefined` when they are absent or NULL (RFC 5280 §6.1.4 (e)). */
export function explicitParameters(parametersDer: Uint8Array | undefined): Uint8Array | undefined {
	if (parametersDer === undefined) return undefined;
	return parametersDer.length === 2 && parametersDer[0] === 0x05 && parametersDer[1] === 0x00
		? undefined
		: parametersDer;
}

/** The AlgorithmIdentifier parameters of a SubjectPublicKeyInfo; a malformed one has none. */
export function spkiAlgorithmParametersDer(spkiDer: Uint8Array): Uint8Array | undefined {
	try {
		const [algorithm] = readSequenceChildren(spkiDer);
		if (algorithm === undefined) return undefined;
		const algorithmDer = spkiDer.subarray(algorithm.start - algorithm.headerLength, algorithm.end);
		const [, parameters] = readSequenceChildren(algorithmDer);
		return parameters === undefined
			? undefined
			: algorithmDer.subarray(parameters.start - parameters.headerLength, parameters.end);
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
		return undefined;
	}
}

/** Resolved WebCrypto parameters needed to verify a signature. */
export interface VerifySignatureConfig {
	/** Algorithm descriptor for importing the signer's public key via {@linkcode importSpkiDer}. */
	readonly importAlgorithm: PublicKeyImportInput;
	/** WebCrypto `verify()` algorithm parameter. */
	readonly verifyParams: Algorithm | EcdsaParams | RsaPssParams;
	/** When set, raw ECDSA signatures are this many bytes and may need DER/raw conversion. */
	readonly ecdsaRawSignatureBytes?: number;
}

/** Failure: the signature algorithm or its parameters are not supported. */
export interface VerifySignatureConfigFailure {
	/** Discriminant for the failure branch. */
	readonly ok: false;
	/** Machine-readable failure code. */
	readonly code: 'unsupported_signature_algorithm_parameters';
	/** Human-readable explanation of why the algorithm is unsupported. */
	readonly reason: string;
}

/** Failure: signature verification could not run to completion. */
export interface VerifySignedDataFailure {
	/** Discriminant for the failure branch. */
	readonly ok: false;
	/** Machine-readable failure code. */
	readonly code: 'verification_error';
	/** Human-readable explanation of the verification failure. */
	readonly reason: string;
}

/** Success branch of {@linkcode VerifySignatureConfigResult}. */
export interface VerifySignatureConfigSuccess {
	/** Discriminant for the success branch. */
	readonly ok: true;
	/** The resolved verification configuration. */
	readonly value: VerifySignatureConfig;
}

/** Result of resolving signature algorithm OIDs into a {@linkcode VerifySignatureConfig}. */
export type VerifySignatureConfigResult =
	| VerifySignatureConfigSuccess
	| VerifySignatureConfigFailure;

/** Success branch of {@linkcode VerifySignedDataResult}. */
export interface VerifySignedDataSuccess {
	/** Discriminant for the success branch. */
	readonly ok: true;
	/** Whether the cryptographic signature is valid for the given data and key. */
	readonly valid: boolean;
}

/** Result of a full signature verification: validity, unsupported params, or a runtime verification failure. */
export type VerifySignedDataResult =
	| VerifySignedDataSuccess
	| VerifySignatureConfigFailure
	| VerifySignedDataFailure;

/**
 * Resolve algorithm OIDs into a {@linkcode VerifySignatureConfig}.
 *
 * Throws on unsupported algorithms. Use {@linkcode getVerifySignatureConfigResult} for
 * a non-throwing variant.
 */
export function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	context = 'issuer',
): VerifySignatureConfig {
	const result = getVerifySignatureConfigResult(
		signatureAlgorithmOid,
		signatureAlgorithmParametersDer,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
		context,
	);
	if (!result.ok) {
		throw new Error(result.reason);
	}
	return result.value;
}

/** Non-throwing variant of {@linkcode getVerifySignatureConfig} — returns a typed result union. */
export function getVerifySignatureConfigResult(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	context = 'issuer',
): VerifySignatureConfigResult {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption: {
			const parameters = requireDerNullOrAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'SHA-256 with RSA',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-256', 'pkcs1-v1_5', context);
		}
		case OIDS.sha384WithRSAEncryption: {
			const parameters = requireDerNullOrAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'SHA-384 with RSA',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-384', 'pkcs1-v1_5', context);
		}
		case OIDS.sha512WithRSAEncryption: {
			const parameters = requireDerNullOrAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'SHA-512 with RSA',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-512', 'pkcs1-v1_5', context);
		}
		case OIDS.rsassaPss:
			return requireRsaPssVerifyConfig(
				signatureAlgorithmParametersDer,
				publicKeyAlgorithmOid,
				context,
			);
		case OIDS.ecdsaWithSHA256: {
			const parameters = requireAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'ECDSA with SHA-256',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-256', context);
		}
		case OIDS.ecdsaWithSHA384: {
			const parameters = requireAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'ECDSA with SHA-384',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-384', context);
		}
		case OIDS.ecdsaWithSHA512: {
			const parameters = requireAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'ECDSA with SHA-512',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-512', context);
		}
		case OIDS.ed25519: {
			const parameters = requireAbsentSignatureAlgorithmParameters(
				signatureAlgorithmParametersDer,
				'Ed25519',
			);
			if (parameters !== undefined) {
				return parameters;
			}
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				return unsupported('Ed25519', `requires Ed25519 ${context} public key`);
			}
			return ok({
				importAlgorithm: { kind: 'ed25519' },
				verifyParams: { name: 'Ed25519' },
			});
		}
		default:
			return unsupported(signatureAlgorithmOid, 'unrecognized signature algorithm OID');
	}
}

/** Validate that the public key OID is `rsaEncryption` and return an RSA verification config result. */
export function requireRsaPublicKey(
	algorithmOid: string,
	hash: RsaHash,
	scheme: RsaSignatureScheme = 'pkcs1-v1_5',
	context = 'issuer',
	saltLength?: number,
): VerifySignatureConfigResult {
	if (algorithmOid !== OIDS.rsaEncryption) {
		return unsupported('RSA', `requires RSA ${context} public key`);
	}
	const verifyParams: Algorithm | RsaPssParams =
		scheme === 'pss'
			? { name: 'RSA-PSS', saltLength: saltLength ?? 0 }
			: { name: 'RSASSA-PKCS1-v1_5' };
	return ok({ importAlgorithm: { kind: 'rsa', hash, scheme }, verifyParams });
}

/** Validate that the public key OID is `ecPublicKey`, resolve the curve, and return an ECDSA verification config result. */
export function requireEcPublicKey(
	algorithmOid: string,
	parametersOid: string | undefined,
	hash: string,
	context = 'issuer',
): VerifySignatureConfigResult {
	if (algorithmOid !== OIDS.ecPublicKey) {
		return unsupported('ECDSA', `requires EC ${context} public key`);
	}
	switch (parametersOid) {
		case OIDS.prime256v1:
			return ok({
				importAlgorithm: { kind: 'ecdsa', curve: 'P-256' },
				verifyParams: { name: 'ECDSA', hash },
				ecdsaRawSignatureBytes: 64,
			});
		case OIDS.secp384r1:
			return ok({
				importAlgorithm: { kind: 'ecdsa', curve: 'P-384' },
				verifyParams: { name: 'ECDSA', hash },
				ecdsaRawSignatureBytes: 96,
			});
		case OIDS.secp521r1:
			return ok({
				importAlgorithm: { kind: 'ecdsa', curve: 'P-521' },
				verifyParams: { name: 'ECDSA', hash },
				ecdsaRawSignatureBytes: 132,
			});
		default:
			return unsupported('ECDSA', `unsupported EC curve OID: ${parametersOid ?? 'missing'}`);
	}
}

/** Return the raw ECDSA signature byte count (r + s) for a given curve OID, if supported. */
export function curveBytes(parametersOid: string | undefined): number | undefined {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		case OIDS.secp521r1:
			return 132;
		default:
			return undefined;
	}
}

/**
 * Verify a signature against the signer's SPKI and the signed TBS bytes.
 *
 * Throws on unsupported algorithms. Use {@linkcode verifySignedDataDetailed} for
 * a non-throwing variant.
 */
export async function verifySignedData(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	subjectPublicKeyInfoDer: Uint8Array,
	signature: Uint8Array,
	signedData: Uint8Array,
): Promise<boolean> {
	const result = await verifySignedDataDetailed(
		signatureAlgorithmOid,
		signatureAlgorithmParametersDer,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
		subjectPublicKeyInfoDer,
		signature,
		signedData,
	);
	if (!result.ok) {
		throw new Error(result.reason);
	}
	return result.valid;
}

/**
 * Non-throwing variant of {@linkcode verifySignedData} — returns a typed
 * {@linkcode VerifySignedDataResult} instead of throwing on unsupported algorithms
 * or runtime verification failures.
 *
 * Tries both DER and raw ECDSA encodings when the first attempt fails.
 *
 * @throws `limit_exceeded` on algorithm parameters or a public key that exceed
 * a micro509 decoding limit.
 */
export async function verifySignedDataDetailed(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	subjectPublicKeyInfoDer: Uint8Array,
	signature: Uint8Array,
	signedData: Uint8Array,
	caller: CallerVerification = NO_CALLER_VERIFICATION,
): Promise<VerifySignedDataResult> {
	const config = getVerifySignatureConfigResult(
		signatureAlgorithmOid,
		signatureAlgorithmParametersDer,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
	);
	if (!config.ok) {
		const verifier = caller.verifiers.get(signatureAlgorithmOid);
		if (verifier === undefined) {
			return config;
		}
		const signerParametersDer =
			caller.workingParameters === undefined
				? explicitParameters(spkiAlgorithmParametersDer(subjectPublicKeyInfoDer))
				: caller.workingParameters.parametersDer;
		return await runCallerVerifier(verifier, {
			signatureAlgorithm: {
				oid: signatureAlgorithmOid,
				...(signatureAlgorithmParametersDer === undefined
					? {}
					: { parametersDer: new Uint8Array(signatureAlgorithmParametersDer) }),
			},
			signerSpkiDer: new Uint8Array(subjectPublicKeyInfoDer),
			...(signerParametersDer === undefined
				? {}
				: { signerPublicKeyParametersDer: new Uint8Array(signerParametersDer) }),
			signature: new Uint8Array(signature),
			data: new Uint8Array(signedData),
		});
	}
	try {
		const key = await importSpkiDerOrThrow(subjectPublicKeyInfoDer, config.value.importAlgorithm);
		return await verifyWithConfiguredKey(key, config.value, signature, signedData, 'auto');
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
		return verificationError(
			error instanceof Error ? error.message : 'signature verification failed',
		);
	}
}

async function runCallerVerifier(
	verifier: SignatureVerifier,
	input: SignatureVerifierInput,
): Promise<VerifySignedDataResult> {
	try {
		return { ok: true, valid: (await verifier(input)) === true };
	} catch (error) {
		return verificationError(
			error instanceof Error
				? `signature verifier failed: ${error.message}`
				: 'signature verifier failed',
		);
	}
}

/** Execute verification for imported SPKI and caller-owned keys with the same configuration. */
async function verifyWithConfiguredKey(
	key: CryptoKey,
	config: VerifySignatureConfig,
	signature: Uint8Array,
	signedData: Uint8Array,
	encoding: 'auto' | 'raw' | 'der',
): Promise<VerifySignedDataResult> {
	try {
		if (encoding === 'der' && config.ecdsaRawSignatureBytes !== undefined) {
			try {
				signature = derEcdsaSignatureToRaw(signature, config.ecdsaRawSignatureBytes / 2);
			} catch (error) {
				rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
				return { ok: true, valid: false };
			}
		}
		const subtle = getCrypto().subtle;
		const signatureView = toArrayBuffer(signature);
		const dataView = toArrayBuffer(signedData);
		if (await subtle.verify(config.verifyParams, key, signatureView, dataView)) {
			return { ok: true, valid: true };
		}
		if (encoding === 'auto' && config.ecdsaRawSignatureBytes !== undefined) {
			const alternate = alternateEcdsaSignatureEncoding(
				signature,
				config.ecdsaRawSignatureBytes / 2,
			);
			if (alternate !== undefined) {
				return {
					ok: true,
					valid: await subtle.verify(config.verifyParams, key, toArrayBuffer(alternate), dataView),
				};
			}
		}
		return { ok: true, valid: false };
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
		return verificationError(
			error instanceof Error ? error.message : 'signature verification failed',
		);
	}
}

/** Resolve a caller-owned key without exporting it, then run the shared verifier. */
export async function verifySignedDataWithKeyDetailed(
	key: CryptoKey,
	signatureAlgorithmOid: string,
	parametersDer: Uint8Array | undefined,
	signature: Uint8Array,
	data: Uint8Array,
	encoding: 'raw' | 'der',
): Promise<VerifySignedDataResult> {
	if (key.type !== 'public' || !key.usages.includes('verify')) {
		return verificationError('Signature verification requires a public key with verify usage');
	}
	const algorithm = key.algorithm;
	let oid: string;
	let curveOid: string | undefined;
	switch (algorithm.name) {
		case 'RSASSA-PKCS1-v1_5':
		case 'RSA-PSS':
			oid = OIDS.rsaEncryption;
			break;
		case 'ECDSA':
			oid = OIDS.ecPublicKey;
			if ('namedCurve' in algorithm) {
				switch (algorithm.namedCurve) {
					case 'P-256':
						curveOid = OIDS.prime256v1;
						break;
					case 'P-384':
						curveOid = OIDS.secp384r1;
						break;
					case 'P-521':
						curveOid = OIDS.secp521r1;
						break;
				}
			}
			break;
		case 'Ed25519':
			oid = OIDS.ed25519;
			break;
		default:
			return unsupported(algorithm.name, 'unsupported public key algorithm');
	}
	const config = getVerifySignatureConfigResult(
		signatureAlgorithmOid,
		parametersDer,
		oid,
		curveOid,
	);
	if (!config.ok) return config;
	if (encoding !== 'raw' && encoding !== 'der') {
		return unsupported(signatureAlgorithmOid, 'signature encoding must be raw or der');
	}
	if (encoding === 'der' && config.value.ecdsaRawSignatureBytes === undefined) {
		return unsupported(signatureAlgorithmOid, 'DER signature encoding requires ECDSA');
	}
	if (algorithm.name !== config.value.verifyParams.name) {
		return unsupported(signatureAlgorithmOid, 'signature scheme does not match the public key');
	}
	if (config.value.importAlgorithm.kind === 'rsa') {
		if (
			!('hash' in algorithm) ||
			typeof algorithm.hash !== 'object' ||
			algorithm.hash === null ||
			!('name' in algorithm.hash) ||
			algorithm.hash.name !== config.value.importAlgorithm.hash
		) {
			return unsupported(signatureAlgorithmOid, 'signature hash does not match the RSA public key');
		}
	}
	return await verifyWithConfiguredKey(key, config.value, signature, data, encoding);
}

/** Parse RSA-PSS algorithm parameters and build a verification config, or return failure. */
function requireRsaPssVerifyConfig(
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	context: string,
): VerifySignatureConfigResult {
	const parameters = parseRsaPssParameters(signatureAlgorithmParametersDer);
	if (!parameters.ok) {
		return unsupported('RSA-PSS', parameters.reason);
	}
	return requireRsaPublicKey(
		publicKeyAlgorithmOid,
		parameters.value.hash,
		'pss',
		context,
		parameters.value.saltLength,
	);
}

/** RFC 4055 §5 requires generators to encode NULL and implementations to accept absent parameters too. */
function requireDerNullOrAbsentSignatureAlgorithmParameters(
	parametersDer: Uint8Array | undefined,
	algorithm: string,
): VerifySignatureConfigFailure | undefined {
	if (parametersDer === undefined) {
		return undefined;
	}
	const reason = 'signature AlgorithmIdentifier parameters must be DER NULL or absent';
	try {
		const element = readElement(parametersDer);
		if (element.tag !== 0x05 || element.length !== 0 || element.end !== parametersDer.length) {
			return unsupported(algorithm, reason);
		}
		return undefined;
	} catch (error) {
		rethrowDecodeRefusal(error, DECODE_LIMIT_CODES);
		return unsupported(algorithm, reason);
	}
}

function requireAbsentSignatureAlgorithmParameters(
	parametersDer: Uint8Array | undefined,
	algorithm: string,
): VerifySignatureConfigFailure | undefined {
	if (parametersDer !== undefined) {
		return unsupported(algorithm, 'signature AlgorithmIdentifier parameters must be absent');
	}
	return undefined;
}

/** Wrap a config in a success result. */
function ok(value: VerifySignatureConfig): VerifySignatureConfigSuccess {
	return { ok: true, value };
}

/** Build an unsupported-algorithm failure result. */
function unsupported(algorithm: string, reason: string): VerifySignatureConfigFailure {
	return {
		ok: false,
		code: 'unsupported_signature_algorithm_parameters',
		reason: `${algorithm} parameters unsupported: ${reason}`,
	};
}

function verificationError(reason: string): VerifySignedDataFailure {
	return {
		ok: false,
		code: 'verification_error',
		reason,
	};
}
