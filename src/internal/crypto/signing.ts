/**
 * Signing helpers that map WebCrypto keys and signature profiles to on-wire
 * `AlgorithmIdentifier` values. Used by certificate and CSR builders.
 *
 * @module
 */

import { nullValue, objectIdentifier, sequence } from '../asn1/der.ts';
import { OIDS } from '../asn1/oids.ts';
import { rawEcdsaSignatureToDer } from './ecdsa.ts';
import { encodeRsaPssParameters, type RsaPssHash, rsaPssParametersForHash } from './rsa-pss.ts';
import { getCrypto } from './webcrypto.ts';

/**
 * Controls how the signature algorithm is chosen.
 *
 * `'auto'` (default) infers the algorithm from the key. `'rsa-pss'` forces RSA-PSS
 * padding and requires an RSA-PSS private key.
 */
export type SignatureProfileInput =
	| {
			/** Infer the signature algorithm from the private key. */
			readonly kind?: 'auto';
	  }
	| {
			/** Force RSA-PSS padding. */
			readonly kind: 'rsa-pss';
			/** Salt length in bytes. Must match the key's hash digest size. */
			readonly saltLength?: 32 | 48 | 64;
	  };

/** Resolved signature algorithm: the OID/parameters for DER encoding and the WebCrypto sign params. */
export interface SignatureAlgorithmIdentifier {
	/** ASN.1 OID of the signature algorithm (e.g. sha256WithRSAEncryption). */
	readonly algorithmOid: string;
	/** DER-encoded algorithm parameters, if the algorithm requires them (e.g. RSA-PSS). */
	readonly parameters?: Uint8Array;
	/** WebCrypto `sign()` algorithm parameter. */
	readonly signParams: Algorithm | EcdsaParams | RsaPssParams;
	/** When set, the raw ECDSA signature is this many bytes and must be DER-converted. */
	readonly ecdsaRawSignatureBytes?: number;
}

/** Resolve a private key and optional profile into a {@linkcode SignatureAlgorithmIdentifier}. */
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

/** Build an RSA-PSS {@linkcode SignatureAlgorithmIdentifier} from an RSA-PSS private key. */
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

/** DER-encode a {@linkcode SignatureAlgorithmIdentifier} as an ASN.1 `AlgorithmIdentifier` SEQUENCE. */
export function encodeAlgorithmIdentifier(input: SignatureAlgorithmIdentifier): Uint8Array {
	const parts = [objectIdentifier(input.algorithmOid)];
	if (input.parameters !== undefined) {
		parts.push(input.parameters);
	}
	return sequence(parts);
}

/** Sign `data` and return a DER-encoded signature. ECDSA raw signatures are auto-converted to DER. */
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

/** Type guard: does this key algorithm carry a `hash` property (RSA keys). */
function hasHash(algorithm: KeyAlgorithm): algorithm is RsaHashedKeyAlgorithm {
	return 'hash' in algorithm;
}

/** Type guard: does this key algorithm carry a `namedCurve` property (EC keys). */
function hasNamedCurve(algorithm: KeyAlgorithm): algorithm is EcKeyAlgorithm {
	return 'namedCurve' in algorithm;
}

/** Narrow a WebCrypto hash name string to the supported {@linkcode RsaPssHash} union. */
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
