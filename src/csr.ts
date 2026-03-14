/**
 * Certificate signing request creation helpers.
 *
 * This module builds PKCS#10 CSRs from typed subject, extension, and WebCrypto key inputs.
 */

import {
	bitString,
	concatBytes,
	implicitConstructedContext,
	integerFromNumber,
	objectIdentifier,
	sequence,
	setOf,
} from './der.ts';
import { buildRequestedExtensions, type CertificateExtensionsInput } from './extensions.ts';
import { exportSpkiDer } from './keys.ts';
import { encodeName, type NameInput } from './name.ts';
import { OIDS } from './oids.ts';
import { base64Encode, pemEncode } from './pem.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	type SignatureProfileInput,
	signBytes,
} from './signing.ts';

/**
 * Describes the input shape for create CSR operations.
 */
export interface CreateCsrInput {
	/**
	 * Carries the subject value.
	 */
	readonly subject: NameInput;
	/**
	 * Carries the public key value.
	 */
	readonly publicKey: CryptoKey;
	/**
	 * Carries the signer private key value.
	 */
	readonly signerPrivateKey: CryptoKey;
	/**
	 * Carries the extensions value.
	 */
	readonly extensions?: CertificateExtensionsInput;
	/**
	 * Carries the signature value.
	 */
	readonly signature?: SignatureProfileInput;
}

/**
 * Bundles the encoded artifacts produced by CSR operations.
 */
export interface CsrMaterial {
	/**
	 * Carries the der value.
	 */
	readonly der: Uint8Array;
	/**
	 * Carries the pem value.
	 */
	readonly pem: string;
	/**
	 * Carries the base64 value.
	 */
	readonly base64: string;
}

/**
 * Creates certificate signing request.
 *
 * @param input The typed input payload.
 * @returns The created certificate signing request.
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

/**
 * Builds attributes.
 *
 * @param extensions The extensions to process.
 * @returns The built attributes.
 */
function buildAttributes(extensions: CertificateExtensionsInput | undefined): Uint8Array[] {
	const builtExtensions = buildRequestedExtensions(extensions);
	if (builtExtensions.length === 0) {
		return [];
	}
	return [sequence([objectIdentifier(OIDS.extensionRequest), setOf([sequence(builtExtensions)])])];
}
