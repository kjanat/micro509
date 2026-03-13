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

export interface VerifySignatureConfig {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams | RsaPssParams;
	readonly ecdsaRawSignatureBytes?: number;
}

export interface VerifySignatureConfigFailure {
	readonly ok: false;
	readonly code: 'unsupported_signature_algorithm_parameters';
	readonly reason: string;
}

interface VerifySignatureConfigSuccess {
	readonly ok: true;
	readonly value: VerifySignatureConfig;
}

export type VerifySignatureConfigResult =
	| VerifySignatureConfigSuccess
	| VerifySignatureConfigFailure;

interface VerifySignedDataSuccess {
	readonly ok: true;
	readonly valid: boolean;
}

export type VerifySignedDataResult = VerifySignedDataSuccess | VerifySignatureConfigFailure;

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

function ok(value: VerifySignatureConfig): VerifySignatureConfigSuccess {
	return { ok: true, value };
}

function unsupported(algorithm: string, reason: string): VerifySignatureConfigFailure {
	return {
		ok: false,
		code: 'unsupported_signature_algorithm_parameters',
		reason: `${algorithm} parameters unsupported: ${reason}`,
	};
}
