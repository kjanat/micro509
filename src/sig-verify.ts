import { toArrayBuffer } from './asn1.ts';
import { alternateEcdsaSignatureEncoding } from './ecdsa.ts';
import type { PublicKeyImportInput, RsaHash, RsaScheme } from './keys.ts';
import { getCrypto, importSpkiDer } from './keys.ts';
import { OIDS } from './oids.ts';

export {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	derEcdsaSignatureToRaw,
	rawEcdsaSignatureToDer,
} from './ecdsa.ts';

export interface VerifySignatureConfig {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
}

export function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	context = 'issuer',
): VerifySignatureConfig {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-256',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			};
		case OIDS.sha384WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-384',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			};
		case OIDS.sha512WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					'SHA-512',
					'pkcs1-v1_5',
					context,
				),
				verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
			};
		case OIDS.ecdsaWithSHA256:
			return {
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA384:
			return {
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA512:
			return {
				importAlgorithm: requireEcPublicKey(publicKeyAlgorithmOid, publicKeyParametersOid, context),
				verifyParams: { name: 'ECDSA', hash: 'SHA-512' },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error(`Ed25519 signature requires Ed25519 ${context} public key`);
			}
			return {
				importAlgorithm: { kind: 'ed25519' },
				verifyParams: { name: 'Ed25519' },
			};
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
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	subjectPublicKeyInfoDer: Uint8Array,
	signature: Uint8Array,
	signedData: Uint8Array,
): Promise<boolean> {
	const config = getVerifySignatureConfig(
		signatureAlgorithmOid,
		publicKeyAlgorithmOid,
		publicKeyParametersOid,
	);
	const key = await importSpkiDer(subjectPublicKeyInfoDer, config.importAlgorithm);
	const subtle = getCrypto().subtle;
	const signatureView = toArrayBuffer(signature);
	const dataView = toArrayBuffer(signedData);
	if (await subtle.verify(config.verifyParams, key, signatureView, dataView)) {
		return true;
	}
	if (config.ecdsaRawSignatureBytes !== undefined) {
		const alternate = alternateEcdsaSignatureEncoding(signature, config.ecdsaRawSignatureBytes / 2);
		if (alternate !== undefined) {
			return subtle.verify(config.verifyParams, key, toArrayBuffer(alternate), dataView);
		}
	}
	return false;
}
