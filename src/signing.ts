import { nullValue, objectIdentifier, sequence } from './der.ts';
import { rawEcdsaSignatureToDer } from './ecdsa.ts';
import { getCrypto } from './keys.ts';
import { OIDS } from './oids.ts';
import { encodeRsaPssParameters, type RsaPssHash, rsaPssParametersForHash } from './rsa-pss.ts';

export type SignatureProfileInput =
	| { readonly kind?: 'auto' }
	| {
			readonly kind: 'rsa-pss';
			readonly saltLength?: 32 | 48 | 64;
	  };

export interface SignatureAlgorithmIdentifier {
	readonly algorithmOid: string;
	readonly parameters?: Uint8Array;
	readonly signParams: Algorithm | EcdsaParams | RsaPssParams;
	readonly ecdsaRawSignatureBytes?: number;
}

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
		return rawEcdsaSignatureToDer(signature, algorithm.ecdsaRawSignatureBytes / 2);
	}
	return signature;
}

function hasHash(algorithm: KeyAlgorithm): algorithm is RsaHashedKeyAlgorithm {
	return 'hash' in algorithm;
}

function hasNamedCurve(algorithm: KeyAlgorithm): algorithm is EcKeyAlgorithm {
	return 'namedCurve' in algorithm;
}

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
