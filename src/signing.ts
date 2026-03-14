/**
 * Internal signing helpers used by certificate and CSR builders.
 *
 * This module maps WebCrypto keys and signature profiles to the `AlgorithmIdentifier`
 * values emitted on wire.
 */

import { nullValue, objectIdentifier, sequence } from './der.ts';
import { rawEcdsaSignatureToDer } from './ecdsa.ts';
import { getCrypto } from './keys.ts';
import { OIDS } from './oids.ts';
import { encodeRsaPssParameters, type RsaPssHash, rsaPssParametersForHash } from './rsa-pss.ts';

/**
 * Describes the input shape for signature profile operations.
 */
export type SignatureProfileInput =
	| {
			/**
			 * Identifies the kind value.
			 */
			readonly kind?: 'auto';
	  }
	| {
			/**
			 * Identifies the kind value.
			 */
			readonly kind: 'rsa-pss';
			/**
			 * Carries the salt length value.
			 */
			readonly saltLength?: 32 | 48 | 64;
	  };

/**
 * Describes an algorithm identifier used by signature operations.
 */
export interface SignatureAlgorithmIdentifier {
	/**
	 * Carries the OID for algorithm.
	 */
	readonly algorithmOid: string;
	/**
	 * Carries the parameters value.
	 */
	readonly parameters?: Uint8Array;
	/**
	 * Carries the sign params value.
	 */
	readonly signParams: Algorithm | EcdsaParams | RsaPssParams;
	/**
	 * Carries the ecdsa raw signature bytes value.
	 */
	readonly ecdsaRawSignatureBytes?: number;
}

/**
 * Returns signature algorithm.
 *
 * @param privateKey The private key to use.
 * @param profile The profile value.
 * @returns The signature algorithm.
 */
export function getSignatureAlgorithm(
	privateKey: CryptoKey,
	profile: SignatureProfileInput = {},
): SignatureAlgorithmIdentifier {
	const algorithm = privateKey.algorithm;
	if (profile.kind === 'rsa-pss') {
		return getRsaPssSignatureAlgorithm(privateKey, profile.saltLength);
	}
	if (algorithm.name === 'RSASSA-PKCS1-v1_5') {
		if (!hasHash(algorithm)) {
			throw new Error('RSA key is missing hash metadata');
		}
		switch (algorithm.hash.name) {
			case 'SHA-256':
				return {
					algorithmOid: OIDS.sha256WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: 'RSASSA-PKCS1-v1_5' },
				};
			case 'SHA-384':
				return {
					algorithmOid: OIDS.sha384WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: 'RSASSA-PKCS1-v1_5' },
				};
			case 'SHA-512':
				return {
					algorithmOid: OIDS.sha512WithRSAEncryption,
					parameters: nullValue(),
					signParams: { name: 'RSASSA-PKCS1-v1_5' },
				};
			default:
				throw new Error(`Unsupported RSA hash: ${algorithm.hash.name}`);
		}
	}

	if (algorithm.name === 'RSA-PSS') {
		throw new Error('RSA-PSS signing requires an explicit signature profile');
	}

	if (algorithm.name === 'ECDSA') {
		if (!hasNamedCurve(algorithm)) {
			throw new Error('ECDSA key is missing namedCurve metadata');
		}
		switch (algorithm.namedCurve) {
			case 'P-256':
				return {
					algorithmOid: OIDS.ecdsaWithSHA256,
					signParams: { name: 'ECDSA', hash: 'SHA-256' },
					ecdsaRawSignatureBytes: 64,
				};
			case 'P-384':
				return {
					algorithmOid: OIDS.ecdsaWithSHA384,
					signParams: { name: 'ECDSA', hash: 'SHA-384' },
					ecdsaRawSignatureBytes: 96,
				};
			case 'P-521':
				return {
					algorithmOid: OIDS.ecdsaWithSHA512,
					signParams: { name: 'ECDSA', hash: 'SHA-512' },
					ecdsaRawSignatureBytes: 132,
				};
			default:
				throw new Error(`Unsupported curve: ${algorithm.namedCurve}`);
		}
	}

	if (algorithm.name === 'Ed25519') {
		return {
			algorithmOid: OIDS.ed25519,
			signParams: { name: 'Ed25519' },
		};
	}

	throw new Error(`Unsupported signing key algorithm: ${algorithm.name}`);
}

/**
 * Returns RSA PSS signature algorithm.
 *
 * @param privateKey The private key to use.
 * @param saltLength The salt length value.
 * @returns The RSA PSS signature algorithm.
 */
function getRsaPssSignatureAlgorithm(
	privateKey: CryptoKey,
	saltLength: number | undefined,
): SignatureAlgorithmIdentifier {
	const algorithm = privateKey.algorithm;
	if (algorithm.name !== 'RSA-PSS') {
		throw new Error('RSA-PSS signature profile requires an RSA-PSS private key');
	}
	if (!hasHash(algorithm)) {
		throw new Error('RSA-PSS key is missing hash metadata');
	}
	const hash = rsaPssHashFromWebCryptoName(algorithm.hash.name);
	const parameters = rsaPssParametersForHash(hash);
	if (saltLength !== undefined && saltLength !== parameters.saltLength) {
		throw new Error(
			`Unsupported RSA-PSS saltLength ${saltLength} for ${hash}; expected ${parameters.saltLength}`,
		);
	}
	return {
		algorithmOid: OIDS.rsassaPss,
		parameters: encodeRsaPssParameters(parameters),
		signParams: {
			name: 'RSA-PSS',
			saltLength: parameters.saltLength,
		},
	};
}

/**
 * Encodes algorithm identifier.
 *
 * @param input The typed input payload.
 * @returns The encoded algorithm identifier.
 */
export function encodeAlgorithmIdentifier(input: SignatureAlgorithmIdentifier): Uint8Array {
	const parts = [objectIdentifier(input.algorithmOid)];
	if (input.parameters !== undefined) {
		parts.push(input.parameters);
	}
	return sequence(parts);
}

/**
 * Sign bytes.
 *
 * @param privateKey The private key to use.
 * @param algorithm The algorithm configuration.
 * @param data The raw bytes to process.
 * @returns The computed value.
 */
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
		return rawEcdsaSignatureToDer(signature, algorithm.ecdsaRawSignatureBytes / 2);
	}
	return signature;
}

/**
 * Returns whether hash.
 *
 * @param algorithm The algorithm configuration.
 * @returns Whether the condition holds.
 */
function hasHash(algorithm: KeyAlgorithm): algorithm is RsaHashedKeyAlgorithm {
	return 'hash' in algorithm;
}

/**
 * Returns whether named curve.
 *
 * @param algorithm The algorithm configuration.
 * @returns Whether the condition holds.
 */
function hasNamedCurve(algorithm: KeyAlgorithm): algorithm is EcKeyAlgorithm {
	return 'namedCurve' in algorithm;
}

/**
 * RSA PSS hash from web crypto name.
 *
 * @param hash The hash value.
 * @returns The computed value.
 */
function rsaPssHashFromWebCryptoName(hash: string): RsaPssHash {
	switch (hash) {
		case 'SHA-256':
			return 'SHA-256';
		case 'SHA-384':
			return 'SHA-384';
		case 'SHA-512':
			return 'SHA-512';
		default:
			throw new Error(`Unsupported RSA hash: ${hash}`);
	}
}
