/**
 * Internal signature-verification helpers.
 *
 * This module resolves parsed algorithm metadata into the WebCrypto verification
 * configuration used by higher-level validators.
 */

import { toArrayBuffer } from './asn1.ts';
import { alternateEcdsaSignatureEncoding } from './ecdsa.ts';
import type { PublicKeyImportInput, RsaHash, RsaScheme } from './keys.ts';
import { getCrypto, importSpkiDer } from './keys.ts';
import { OIDS } from './oids.ts';
import { parseRsaPssParameters } from './rsa-pss.ts';

export {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	derEcdsaSignatureToRaw,
	rawEcdsaSignatureToDer,
} from './ecdsa.ts';

/**
 * Describes verify signature config.
 */
export interface VerifySignatureConfig {
	/**
	 * Carries the import algorithm value.
	 */
	readonly importAlgorithm: PublicKeyImportInput;
	/**
	 * Carries the verify params value.
	 */
	readonly verifyParams: Algorithm | EcdsaParams | RsaPssParams;
	/**
	 * Carries the ecdsa raw signature bytes value.
	 */
	readonly ecdsaRawSignatureBytes?: number;
}

/**
 * Represents a typed failure produced by verify signature config operations.
 */
export interface VerifySignatureConfigFailure {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: 'unsupported_signature_algorithm_parameters';
	/**
	 * Carries the reason value.
	 */
	readonly reason: string;
}

/**
 * Represents a successful outcome produced by verify signature config operations.
 */
interface VerifySignatureConfigSuccess {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: VerifySignatureConfig;
}

/**
 * Represents the result returned by verify signature config operations.
 */
export type VerifySignatureConfigResult =
	| VerifySignatureConfigSuccess
	| VerifySignatureConfigFailure;

/**
 * Represents a successful outcome produced by verify signed data operations.
 */
interface VerifySignedDataSuccess {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Indicates whether valid.
	 */
	readonly valid: boolean;
}

/**
 * Represents the result returned by verify signed data operations.
 */
export type VerifySignedDataResult = VerifySignedDataSuccess | VerifySignatureConfigFailure;

/**
 * Returns verify signature config.
 *
 * @param signatureAlgorithmOid The signature algorithm OID value.
 * @param signatureAlgorithmParametersDer The signature algorithm parameters DER value.
 * @param publicKeyAlgorithmOid The public key algorithm OID value.
 * @param publicKeyParametersOid The public key parameters OID value.
 * @param context The registry context value.
 * @returns The verify signature config.
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

/**
 * Returns verify signature config result.
 *
 * @param signatureAlgorithmOid The signature algorithm OID value.
 * @param signatureAlgorithmParametersDer The signature algorithm parameters DER value.
 * @param publicKeyAlgorithmOid The public key algorithm OID value.
 * @param publicKeyParametersOid The public key parameters OID value.
 * @param context The registry context value.
 * @returns The verify signature config result.
 */
export function getVerifySignatureConfigResult(
	signatureAlgorithmOid: string,
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	context = 'issuer',
): VerifySignatureConfigResult {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption:
			return ok({
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-256',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			});
		case OIDS.sha384WithRSAEncryption:
			return ok({
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-384',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			});
		case OIDS.sha512WithRSAEncryption:
			return ok({
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-512',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			});
		case OIDS.rsassaPss:
			return requireRsaPssVerifyConfig(
				signatureAlgorithmParametersDer,
				publicKeyAlgorithmOid,
				context,
			);
		case OIDS.ecdsaWithSHA256:
			return ok({
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			});
		case OIDS.ecdsaWithSHA384:
			return ok({
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			});
		case OIDS.ecdsaWithSHA512:
			return ok({
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-512' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			});
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error(`Ed25519 signature requires Ed25519 ${context} public key`);
			}
			return ok({
				importAlgorithm: { kind: 'ed25519' },
				verifyParams: { name: 'Ed25519' },
			});
		default:
			throw new Error(`Unsupported signature algorithm OID: ${signatureAlgorithmOid}`);
	}
}

/**
 * Requires and returns RSA public key.
 *
 * @param algorithmOid The algorithm OID value.
 * @param hash The hash value.
 * @param scheme The scheme value.
 * @param context The registry context value.
 * @returns The computed value.
 */
export function requireRsaPublicKey(
	algorithmOid: string,
	hash: RsaHash,
	scheme: RsaScheme = 'pkcs1-v1_5',
	context = 'issuer',
): PublicKeyImportInput {
	if (algorithmOid !== OIDS.rsaEncryption) {
		throw new Error(`RSA signature requires RSA ${context} public key`);
	}
	return { kind: 'rsa', hash, scheme };
}

/**
 * Requires and returns EC public key.
 *
 * @param algorithmOid The algorithm OID value.
 * @param parametersOid The parameters OID value.
 * @param context The registry context value.
 * @returns The computed value.
 */
export function requireEcPublicKey(
	algorithmOid: string,
	parametersOid: string | undefined,
	context = 'issuer',
): PublicKeyImportInput {
	if (algorithmOid !== OIDS.ecPublicKey) {
		throw new Error(`ECDSA signature requires EC ${context} public key`);
	}
	switch (parametersOid) {
		case OIDS.prime256v1:
			return { kind: 'ecdsa', namedCurve: 'P-256' };
		case OIDS.secp384r1:
			return { kind: 'ecdsa', namedCurve: 'P-384' };
		case OIDS.secp521r1:
			return { kind: 'ecdsa', namedCurve: 'P-521' };
		default:
			throw new Error(`Unsupported EC curve OID: ${parametersOid ?? 'missing'}`);
	}
}

/**
 * Curve bytes.
 *
 * @param parametersOid The parameters OID value.
 * @returns The computed value.
 */
export function curveBytes(parametersOid: string | undefined): number {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		case OIDS.secp521r1:
			return 132;
		default:
			throw new Error(`Unsupported EC curve OID: ${parametersOid ?? 'missing'}`);
	}
}

/**
 * Verifies signed data.
 *
 * @param signatureAlgorithmOid The signature algorithm OID value.
 * @param signatureAlgorithmParametersDer The signature algorithm parameters DER value.
 * @param publicKeyAlgorithmOid The public key algorithm OID value.
 * @param publicKeyParametersOid The public key parameters OID value.
 * @param subjectPublicKeyInfoDer The subject public key info DER value.
 * @param signature The signature value.
 * @param signedData The signed data value.
 * @returns The verification result.
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
 * Verifies signed data detailed.
 *
 * @param signatureAlgorithmOid The signature algorithm OID value.
 * @param signatureAlgorithmParametersDer The signature algorithm parameters DER value.
 * @param publicKeyAlgorithmOid The public key algorithm OID value.
 * @param publicKeyParametersOid The public key parameters OID value.
 * @param subjectPublicKeyInfoDer The subject public key info DER value.
 * @param signature The signature value.
 * @param signedData The signed data value.
 * @returns The verification result.
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
}

/**
 * Requires and returns RSA PSS verify config.
 *
 * @param signatureAlgorithmParametersDer The signature algorithm parameters DER value.
 * @param publicKeyAlgorithmOid The public key algorithm OID value.
 * @param context The registry context value.
 * @returns The computed value.
 */
function requireRsaPssVerifyConfig(
	signatureAlgorithmParametersDer: Uint8Array | undefined,
	publicKeyAlgorithmOid: string,
	context: string,
): VerifySignatureConfigResult {
	const parameters = parseRsaPssParameters(signatureAlgorithmParametersDer);
	if (!parameters.ok) {
		return unsupported('RSA-PSS', parameters.reason);
	}
	return ok({
		importAlgorithm: requireRsaPublicKey(
			publicKeyAlgorithmOid,
			parameters.value.hash,
			'pss',
			context,
		),
		verifyParams: {
			name: 'RSA-PSS',
			saltLength: parameters.value.saltLength,
		},
	});
}

/**
 * Builds a successful helper result for this module.
 *
 * @param value The value to process.
 * @returns The successful result wrapper.
 */
function ok(value: VerifySignatureConfig): VerifySignatureConfigSuccess {
	return { ok: true, value };
}

/**
 * Builds an unsupported helper result for this module.
 *
 * @param algorithm The algorithm configuration.
 * @param reason The reason value.
 * @returns The unsupported-result wrapper.
 */
function unsupported(algorithm: string, reason: string): VerifySignatureConfigFailure {
	return {
		ok: false,
		code: 'unsupported_signature_algorithm_parameters',
		reason: `${algorithm} parameters unsupported: ${reason}`,
	};
}
