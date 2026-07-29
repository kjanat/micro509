/**
 * Detached-signature primitives: verify a signature against a signer's SPKI,
 * sign arbitrary bytes with a WebCrypto private key, and convert ECDSA
 * signatures between DER `ECDSA-Sig-Value` and fixed-width raw encodings.
 *
 * @module
 */

import { derEcdsaSignatureToRaw, rawEcdsaSignatureToDer } from '#micro509/internal/crypto/ecdsa';
import type { VerifySignedDataResult } from '#micro509/internal/crypto/sig-verify';
import { verifySignedDataDetailed } from '#micro509/internal/crypto/sig-verify';
import type { SignatureProfileInput } from '#micro509/internal/crypto/signing';
import { getSignatureAlgorithm, signBytes } from '#micro509/internal/crypto/signing';
import type { EcNamedCurve } from '#micro509/keys/keys';

export type {
	VerifySignatureConfigFailure,
	VerifySignedDataFailure,
	VerifySignedDataResult,
	VerifySignedDataSuccess,
} from '#micro509/internal/crypto/sig-verify';
export type { SignatureProfileInput } from '#micro509/internal/crypto/signing';

/** Input for {@linkcode verifySignature}. */
export interface VerifySignatureInput {
	/** DER `SubjectPublicKeyInfo` of the signer (`subjectPublicKeyInfoDer` on a parsed certificate). */
	readonly signerSpkiDer: Uint8Array;
	/** The signature algorithm as carried beside the signature. */
	readonly signatureAlgorithm: {
		/** Dotted-decimal signature algorithm OID. */
		readonly oid: string;
		/** DER algorithm parameters when the algorithm carries them (RSA-PSS). */
		readonly parametersDer?: Uint8Array;
	};
	/** The signer's public key algorithm as carried in its SPKI. */
	readonly publicKeyAlgorithm: {
		/** Dotted-decimal public key algorithm OID. */
		readonly oid: string;
		/** Named-curve or scheme parameters OID, when present. */
		readonly parametersOid?: string;
	};
	/** The signature bytes. ECDSA accepts DER or raw encoding. */
	readonly signature: Uint8Array;
	/** The exact bytes the signature covers. */
	readonly data: Uint8Array;
}

/** Result of {@linkcode signData}: the signature plus its on-wire algorithm identity. */
export interface SignDataResult {
	/** The signature bytes. ECDSA is DER `ECDSA-Sig-Value`, everything else raw. */
	readonly signature: Uint8Array;
	/** Dotted-decimal signature algorithm OID. */
	readonly algorithmOid: string;
	/** DER algorithm parameters when the algorithm carries them (NULL for PKCS#1 v1.5, RSA-PSS params). */
	readonly parametersDer?: Uint8Array;
}

/**
 * Verifies a detached signature against the signer's DER `SubjectPublicKeyInfo`.
 *
 * Supports RSA PKCS#1 v1.5 (SHA-256/384/512), RSA-PSS with parsed parameters,
 * ECDSA P-256/P-384/P-521, and Ed25519. When an ECDSA signature fails to
 * verify under one encoding, the alternate DER/raw encoding is retried.
 *
 * Returns a typed union: `{ ok: true, valid }` when verification ran,
 * `unsupported_signature_algorithm_parameters` or `verification_error`
 * failures otherwise.
 */
export function verifySignature(input: VerifySignatureInput): Promise<VerifySignedDataResult> {
	return verifySignedDataDetailed(
		input.signatureAlgorithm.oid,
		input.signatureAlgorithm.parametersDer,
		input.publicKeyAlgorithm.oid,
		input.publicKeyAlgorithm.parametersOid,
		input.signerSpkiDer,
		input.signature,
		input.data,
	);
}

/**
 * Signs `data` with a WebCrypto private key and returns the signature beside
 * the resolved `AlgorithmIdentifier` material for embedding in a signed
 * structure.
 *
 * The algorithm is inferred from the key (RSASSA-PKCS1-v1_5, ECDSA, Ed25519);
 * RSA-PSS keys require an explicit `{ kind: 'rsa-pss' }` profile. ECDSA
 * signatures are returned DER-encoded. Throws on unsupported key algorithms.
 */
export async function signData(
	privateKey: CryptoKey,
	data: Uint8Array,
	profile?: SignatureProfileInput,
): Promise<SignDataResult> {
	const algorithm = getSignatureAlgorithm(privateKey, profile);
	const signature = await signBytes(privateKey, algorithm, data);
	return algorithm.parameters === undefined
		? { signature, algorithmOid: algorithm.algorithmOid }
		: { signature, algorithmOid: algorithm.algorithmOid, parametersDer: algorithm.parameters };
}

/**
 * Converts a DER `ECDSA-Sig-Value` (RFC 5480: SEQUENCE of INTEGERs r and s)
 * to the fixed-width raw `r || s` encoding WebCrypto and JOSE use.
 * Throws on malformed DER or integers too large for the curve.
 */
export function ecdsaSignatureDerToRaw(signature: Uint8Array, curve: EcNamedCurve): Uint8Array {
	return derEcdsaSignatureToRaw(signature, ecdsaPartLength(curve));
}

/**
 * Converts a fixed-width raw `r || s` ECDSA signature to the DER
 * `ECDSA-Sig-Value` encoding X.509 and CMS structures embed.
 * Throws when the input length does not match the curve.
 */
export function ecdsaSignatureRawToDer(signature: Uint8Array, curve: EcNamedCurve): Uint8Array {
	return rawEcdsaSignatureToDer(signature, ecdsaPartLength(curve));
}

/** Byte width of one ECDSA signature integer for the given curve. */
function ecdsaPartLength(curve: EcNamedCurve): number {
	switch (curve) {
		case 'P-256':
			return 32;
		case 'P-384':
			return 48;
		case 'P-521':
			return 66;
		default: {
			const _exhaustive: never = curve;
			throw new Error(`Unhandled EcNamedCurve: ${String(_exhaustive)}`);
		}
	}
}
