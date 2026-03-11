import { toArrayBuffer } from "./asn1.ts";
import { integer, readSequenceChildren, sequence } from "./der.ts";
import { type PublicKeyImportInput, getCrypto, importSpkiDer } from "./keys.ts";
import { OIDS } from "./oids.ts";

export interface VerifySignatureConfig {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
}

export function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
	context = "issuer",
): VerifySignatureConfig {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					"SHA-256",
					context,
				),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha384WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					"SHA-384",
					context,
				),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha512WithRSAEncryption:
			return {
				importAlgorithm: requireRsaPublicKey(
					publicKeyAlgorithmOid,
					"SHA-512",
					context,
				),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.ecdsaWithSHA256:
			return {
				importAlgorithm: requireEcPublicKey(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
					context,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-256" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA384:
			return {
				importAlgorithm: requireEcPublicKey(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
					context,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-384" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error(
					`Ed25519 signature requires Ed25519 ${context} public key`,
				);
			}
			return {
				importAlgorithm: { kind: "ed25519" },
				verifyParams: { name: "Ed25519" },
			};
		default:
			throw new Error(
				`Unsupported signature algorithm OID: ${signatureAlgorithmOid}`,
			);
	}
}

export function requireRsaPublicKey(
	algorithmOid: string,
	hash: "SHA-256" | "SHA-384" | "SHA-512",
	context = "issuer",
): PublicKeyImportInput {
	if (algorithmOid !== OIDS.rsaEncryption) {
		throw new Error(`RSA signature requires RSA ${context} public key`);
	}
	return { kind: "rsa", hash };
}

export function requireEcPublicKey(
	algorithmOid: string,
	parametersOid: string | undefined,
	context = "issuer",
): PublicKeyImportInput {
	if (algorithmOid !== OIDS.ecPublicKey) {
		throw new Error(`ECDSA signature requires EC ${context} public key`);
	}
	switch (parametersOid) {
		case OIDS.prime256v1:
			return { kind: "ecdsa", namedCurve: "P-256" };
		case OIDS.secp384r1:
			return { kind: "ecdsa", namedCurve: "P-384" };
		default:
			throw new Error(
				`Unsupported EC curve OID: ${parametersOid ?? "missing"}`,
			);
	}
}

export function curveBytes(parametersOid: string | undefined): number {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		default:
			throw new Error(
				`Unsupported EC curve OID: ${parametersOid ?? "missing"}`,
			);
	}
}

export function derEcdsaSignatureToRaw(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error("Malformed ECDSA DER signature");
	}
	return concatFixedWidth(
		trimLeadingZero(r.value),
		trimLeadingZero(s.value),
		partLength,
	);
}

export function rawEcdsaSignatureToDer(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error("Unexpected ECDSA raw signature length");
	}
	return sequence([
		integer(signature.slice(0, partLength)),
		integer(signature.slice(partLength)),
	]);
}

export function alternateEcdsaSignatureEncoding(
	signature: Uint8Array,
	partLength: number,
): Uint8Array | undefined {
	try {
		if (signature[0] === 0x30) {
			return derEcdsaSignatureToRaw(signature, partLength);
		}
		return rawEcdsaSignatureToDer(signature, partLength);
	} catch {
		return undefined;
	}
}

export function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}

export function concatFixedWidth(
	left: Uint8Array,
	right: Uint8Array,
	partLength: number,
): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error("ECDSA signature integer too large");
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
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
	const key = await importSpkiDer(
		subjectPublicKeyInfoDer,
		config.importAlgorithm,
	);
	const subtle = getCrypto().subtle;
	const signatureView = toArrayBuffer(signature);
	const dataView = toArrayBuffer(signedData);
	if (await subtle.verify(config.verifyParams, key, signatureView, dataView)) {
		return true;
	}
	if (config.ecdsaRawSignatureBytes !== undefined) {
		const alternate = alternateEcdsaSignatureEncoding(
			signature,
			config.ecdsaRawSignatureBytes / 2,
		);
		if (alternate !== undefined) {
			return subtle.verify(
				config.verifyParams,
				key,
				toArrayBuffer(alternate),
				dataView,
			);
		}
	}
	return false;
}
