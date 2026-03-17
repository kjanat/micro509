/**
 * Signature-verification helpers that resolve parsed algorithm OIDs into WebCrypto
 * verification configuration for higher-level validators.
 *
 * @module
 */

import { toArrayBuffer } from '#micro509/internal/asn1/asn1.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import type { PublicKeyImportInput, RsaHash, RsaScheme } from '#micro509/keys/keys.ts';
import { importSpkiDer } from '#micro509/keys/keys.ts';
import { alternateEcdsaSignatureEncoding } from './ecdsa.ts';
import { parseRsaPssParameters } from './rsa-pss.ts';
import { getCrypto } from './webcrypto.ts';

export {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	derEcdsaSignatureToRaw,
	rawEcdsaSignatureToDer,
} from './ecdsa.ts';

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
interface VerifySignatureConfigSuccess {
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
interface VerifySignedDataSuccess {
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
		case OIDS.sha256WithRSAEncryption:
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-256', 'pkcs1-v1_5', context);
		case OIDS.sha384WithRSAEncryption:
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-384', 'pkcs1-v1_5', context);
		case OIDS.sha512WithRSAEncryption:
			return requireRsaPublicKey(publicKeyAlgorithmOid, 'SHA-512', 'pkcs1-v1_5', context);
		case OIDS.rsassaPss:
			return requireRsaPssVerifyConfig(
				signatureAlgorithmParametersDer,
				publicKeyAlgorithmOid,
				context,
			);
		case OIDS.ecdsaWithSHA256:
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-256', context);
		case OIDS.ecdsaWithSHA384:
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-384', context);
		case OIDS.ecdsaWithSHA512:
			return requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, 'SHA-512', context);
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				return unsupported('Ed25519', `requires Ed25519 ${context} public key`);
			}
			return ok({
				importAlgorithm: { kind: 'ed25519' },
				verifyParams: { name: 'Ed25519' },
			});
		default:
			return unsupported(signatureAlgorithmOid, 'unrecognized signature algorithm OID');
	}
}

/** Validate that the public key OID is `rsaEncryption` and return an RSA verification config result. */
export function requireRsaPublicKey(
	algorithmOid: string,
	hash: RsaHash,
	scheme: RsaScheme = 'pkcs1-v1_5',
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
				importAlgorithm: { kind: 'ecdsa', namedCurve: 'P-256' },
				verifyParams: { name: 'ECDSA', hash },
				ecdsaRawSignatureBytes: 64,
			});
		case OIDS.secp384r1:
			return ok({
				importAlgorithm: { kind: 'ecdsa', namedCurve: 'P-384' },
				verifyParams: { name: 'ECDSA', hash },
				ecdsaRawSignatureBytes: 96,
			});
		case OIDS.secp521r1:
			return ok({
				importAlgorithm: { kind: 'ecdsa', namedCurve: 'P-521' },
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
 */
export async function verifySignedDataDetailed(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	subjectPublicKeyInfoDer: Uint8Array,
	signature: Uint8Array,
	signedData: Uint8Array,
): Promise<VerifySignedDataResult> {
	const config = getVerifySignatureConfigResult(
		signatureAlgorithmOid,
		signatureAlgorithmParametersDer,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
	);
	if (!config.ok) {
		return config;
	}
	try {
		const key = await importSpkiDer(subjectPublicKeyInfoDer, config.value.importAlgorithm);
		const subtle = getCrypto().subtle;
		const signatureView = toArrayBuffer(signature);
		const dataView = toArrayBuffer(signedData);
		if (await subtle.verify(config.value.verifyParams, key, signatureView, dataView)) {
			return { ok: true, valid: true };
		}
		if (config.value.ecdsaRawSignatureBytes !== undefined) {
			const alternate = alternateEcdsaSignatureEncoding(
				signature,
				config.value.ecdsaRawSignatureBytes / 2,
			);
			if (alternate !== undefined) {
				return {
					ok: true,
					valid: await subtle.verify(
						config.value.verifyParams,
						key,
						toArrayBuffer(alternate),
						dataView,
					),
				};
			}
		}
		return { ok: true, valid: false };
	} catch (error) {
		return verificationError(
			error instanceof Error ? error.message : 'signature verification failed',
		);
	}
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
