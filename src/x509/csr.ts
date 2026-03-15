/**
 * PKCS#10 Certificate Signing Request (CSR) creation.
 *
 * Builds a CSR from a subject name, WebCrypto key pair, and optional extensions,
 * producing DER, PEM, and base64 outputs.
 *
 * @module
 */

import { buildRequestedExtensions, type CertificateExtensionsInput } from './extensions.ts';
import {
	bitString,
	concatBytes,
	implicitConstructedContext,
	integerFromNumber,
	objectIdentifier,
	sequence,
	setOf,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	type SignatureProfileInput,
	signBytes,
} from '#micro509/internal/crypto/signing.ts';
import { base64Encode } from '#micro509/internal/shared/base64.ts';
import { exportSpkiDer } from '#micro509/keys/keys.ts';
import { encodeName, type NameInput } from './name.ts';
import { pemEncode } from '#micro509/pem/pem.ts';

export type * from './extensions.ts';
export type * from '#micro509/internal/crypto/signing.ts';
export type * from './name.ts';

/** Input for {@linkcode createCertificateSigningRequest}. */
export interface CreateCsrInput {
	/** Distinguished name for the CSR subject (e.g. `{ commonName: 'example.com' }`). */
	readonly subject: NameInput;
	/** WebCrypto public key to embed in the CSR's SubjectPublicKeyInfo. */
	readonly publicKey: CryptoKey;
	/** WebCrypto private key used to self-sign the CSR (proves key possession). */
	readonly signerPrivateKey: CryptoKey;
	/** Requested X.509v3 extensions to include in the CSR attributes. */
	readonly extensions?: CertificateExtensionsInput;
	/** Override the signature algorithm profile (hash, salt length, etc.). */
	readonly signature?: SignatureProfileInput;
}

/** DER, PEM, and base64 encodings of a CSR produced by {@linkcode createCertificateSigningRequest}. */
export interface CsrMaterial {
	/** Raw DER-encoded PKCS#10 CertificationRequest. */
	readonly der: Uint8Array;
	/** PEM-armored CSR (`-----BEGIN CERTIFICATE REQUEST-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armor). */
	readonly base64: string;
}

/**
 * Creates a PKCS#10 Certificate Signing Request signed with the given private key.
 *
 * The CSR embeds the public key's SPKI, the subject name, and any requested extensions
 * as attributes. The signature proves possession of the private key.
 *
 * @example
 * ```ts
 * import { createCertificateSigningRequest } from 'micro509';
 *
 * const keyPair = await crypto.subtle.generateKey(
 *   { name: 'ECDSA', namedCurve: 'P-256' },
 *   true,
 *   ['sign', 'verify'],
 * );
 * const csr = await createCertificateSigningRequest({
 *   subject: { commonName: 'example.com' },
 *   publicKey: keyPair.publicKey,
 *   signerPrivateKey: keyPair.privateKey,
 *   extensions: { subjectAltNames: [{ type: 'dns', value: 'example.com' }] },
 * });
 * console.log(csr.pem);
 * ```
 */
export async function createCertificateSigningRequest(input: CreateCsrInput): Promise<CsrMaterial> {
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey, input.signature);
	const spki = await exportSpkiDer(input.publicKey);
	const attributes = buildAttributes(input.extensions);
	const certificationRequestInfo = sequence([
		integerFromNumber(0),
		encodeName(input.subject),
		spki,
		implicitConstructedContext(0, concatBytes(attributes)),
	]);
	const normalizedSignature = await signBytes(
		input.signerPrivateKey,
		signatureAlgorithm,
		certificationRequestInfo,
	);

	const der = sequence([
		certificationRequestInfo,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(normalizedSignature),
	]);
	return {
		der,
		pem: pemEncode('CERTIFICATE REQUEST', der),
		base64: base64Encode(der),
	};
}

/** Encodes extensions into a CSR extensionRequest attribute, or returns empty. */
function buildAttributes(extensions: CertificateExtensionsInput | undefined): Uint8Array[] {
	const builtExtensions = buildRequestedExtensions(extensions);
	if (builtExtensions.length === 0) {
		return [];
	}
	return [sequence([objectIdentifier(OIDS.extensionRequest), setOf([sequence(builtExtensions)])])];
}
