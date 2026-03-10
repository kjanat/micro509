import { integer, nullValue, objectIdentifier, sequence } from "./der.js";
import { getCrypto } from "./keys.js";
import { OIDS } from "./oids.js";

export interface SignatureAlgorithmIdentifier {
	readonly algorithmOid: string;
	readonly parameters?: Uint8Array;
	readonly signParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
}

export function getSignatureAlgorithm(privateKey: CryptoKey): SignatureAlgorithmIdentifier {
	const algorithm = privateKey.algorithm;
	if (algorithm.name === "RSASSA-PKCS1-v1_5") {
		if (!hasHash(algorithm)) {
			throw new Error("RSA key is missing hash metadata");
		}
		switch (algorithm.hash.name) {
			case "SHA-256":
				return {
					algorithmOid: OIDS.sha256WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: "RSASSA-PKCS1-v1_5" },
				};
			case "SHA-384":
				return {
					algorithmOid: OIDS.sha384WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: "RSASSA-PKCS1-v1_5" },
				};
			case "SHA-512":
				return {
					algorithmOid: OIDS.sha512WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: "RSASSA-PKCS1-v1_5" },
				};
			default:
				throw new Error(`Unsupported RSA hash: ${algorithm.hash.name}`);
		}
	}

	if (algorithm.name === "ECDSA") {
		if (!hasNamedCurve(algorithm)) {
			throw new Error("ECDSA key is missing namedCurve metadata");
		}
		switch (algorithm.namedCurve) {
			case "P-256":
				return {
					algorithmOid: OIDS.ecdsaWithSHA256,
					signParams: { name: "ECDSA", hash: "SHA-256" },
					ecdsaRawSignatureBytes: 64,
				};
			case "P-384":
				return {
					algorithmOid: OIDS.ecdsaWithSHA384,
					signParams: { name: "ECDSA", hash: "SHA-384" },
					ecdsaRawSignatureBytes: 96,
				};
			default:
				throw new Error(`Unsupported curve: ${algorithm.namedCurve}`);
		}
	}

	if (algorithm.name === "Ed25519") {
		return {
			algorithmOid: OIDS.ed25519,
			signParams: { name: "Ed25519" },
		};
	}

	throw new Error(`Unsupported signing key algorithm: ${algorithm.name}`);
}

export function encodeAlgorithmIdentifier(input: SignatureAlgorithmIdentifier): Uint8Array {
	const parts = [objectIdentifier(input.algorithmOid)];
	if (input.parameters !== undefined) {
		parts.push(input.parameters);
	}
	return sequence(parts);
}

export async function signBytes(
	privateKey: CryptoKey,
	algorithm: SignatureAlgorithmIdentifier,
	data: Uint8Array,
): Promise<Uint8Array> {
	const view = new Uint8Array(data);
	const signature = new Uint8Array(
		await getCrypto().subtle.sign(algorithm.signParams, privateKey, view),
	);
	if (algorithm.ecdsaRawSignatureBytes !== undefined && signature[0] !== 0x30) {
		return ecdsaRawToDer(signature, algorithm.ecdsaRawSignatureBytes / 2);
	}
	return signature;
}

function hasHash(algorithm: KeyAlgorithm): algorithm is RsaHashedKeyAlgorithm {
	return "hash" in algorithm;
}

function hasNamedCurve(algorithm: KeyAlgorithm): algorithm is EcKeyAlgorithm {
	return "namedCurve" in algorithm;
}

function ecdsaRawToDer(signature: Uint8Array, partLength: number): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error("Unexpected ECDSA signature length");
	}
	const r = trimInteger(signature.slice(0, partLength));
	const s = trimInteger(signature.slice(partLength));
	return sequence([integer(r), integer(s)]);
}

function trimInteger(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}
