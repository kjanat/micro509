/**
 * Create X.509 certificates from typed names, extensions, and WebCrypto keys.
 *
 * Use this module to issue a certificate from an existing issuer key pair or to
 * generate a self-signed certificate in one step.
 *
 * @module
 */

import {
	bitString,
	explicitContext,
	integer,
	integerFromNumber,
	sequence,
	time,
} from '#micro509/internal/asn1/der.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	type SignatureProfileInput,
	signBytes,
} from '#micro509/internal/crypto/signing.ts';
import { getCrypto } from '#micro509/internal/crypto/webcrypto.ts';
import { base64Encode } from '#micro509/internal/shared/base64.ts';
import {
	exportSpkiDer,
	generateKeyPair,
	type KeyAlgorithmInput,
	type KeyPairMaterial,
} from '#micro509/keys/keys.ts';
import { pemEncode } from '#micro509/pem/pem.ts';
import { buildCertificateExtensions, type CertificateExtensionsInput } from './extensions.ts';
import { encodeName, isNameInputEmpty, type NameInput } from './name.ts';

export type * from './extensions.ts';
export type * from './name.ts';

/**
 * Configures the certificate validity window.
 *
 * If `notAfter` is omitted, it is derived from `notBefore` plus `days`. If both
 * `notAfter` and `days` are omitted, the certificate is valid for 30 days.
 */
export interface ValidityInput {
	/**
	 * Start of the validity window.
	 *
	 * Defaults to the current time.
	 */
	readonly notBefore?: Date;
	/**
	 * End of the validity window.
	 *
	 * Must be later than `notBefore`.
	 */
	readonly notAfter?: Date;
	/**
	 * Number of days to add to `notBefore` when `notAfter` is omitted.
	 */
	readonly days?: number;
}

/**
 * Input for {@linkcode createCertificate}.
 */
export interface CreateCertificateInput {
	/**
	 * Issuer distinguished name.
	 */
	readonly issuer: NameInput;
	/**
	 * Subject distinguished name.
	 */
	readonly subject: NameInput;
	/**
	 * Subject public key to encode into the certificate.
	 */
	readonly publicKey: CryptoKey;
	/**
	 * Private key used to sign the certificate.
	 */
	readonly signerPrivateKey: CryptoKey;
	/**
	 * Issuer public key.
	 *
	 * Provide this when extension builders need issuer key material, such as
	 * authority key identifier derivation.
	 */
	readonly issuerPublicKey?: CryptoKey;
	/**
	 * Validity window configuration.
	 */
	readonly validity?: ValidityInput;
	/**
	 * DER integer bytes for the certificate serial number.
	 *
	 * When omitted, a random positive 16-byte serial number is generated.
	 */
	readonly serialNumber?: Uint8Array;
	/**
	 * X.509 extensions to encode into the certificate.
	 */
	readonly extensions?: CertificateExtensionsInput;
	/**
	 * Signature algorithm override.
	 *
	 * When omitted, the library selects a compatible profile from the signing
	 * key.
	 */
	readonly signature?: SignatureProfileInput;
}

/**
 * Input for {@linkcode createSelfSignedCertificate}.
 */
export interface CreateSelfSignedCertificateInput {
	/**
	 * Subject distinguished name used as both subject and issuer.
	 */
	readonly subject: NameInput;
	/**
	 * Key generation parameters.
	 *
	 * Ignored when `keyPair` is provided.
	 */
	readonly algorithm?: KeyAlgorithmInput;
	/**
	 * Existing key pair to reuse for both subject and issuer.
	 *
	 * When omitted, a new key pair is generated.
	 */
	readonly keyPair?: KeyPairMaterial;
	/**
	 * Validity window configuration.
	 */
	readonly validity?: ValidityInput;
	/**
	 * DER integer bytes for the certificate serial number.
	 */
	readonly serialNumber?: Uint8Array;
	/**
	 * X.509 extensions to encode into the certificate.
	 */
	readonly extensions?: CertificateExtensionsInput;
	/**
	 * Signature algorithm override.
	 */
	readonly signature?: SignatureProfileInput;
}

/**
 * Encoded certificate material in common interchange formats.
 */
export interface CertificateMaterial {
	/**
	 * DER-encoded certificate bytes.
	 */
	readonly der: Uint8Array;
	/**
	 * PEM-encoded certificate.
	 */
	readonly pem: string;
	/**
	 * Base64 encoding of {@linkcode der} without PEM armor.
	 */
	readonly base64: string;
}

/**
 * Result returned by {@linkcode createSelfSignedCertificate}.
 */
export interface SelfSignedCertificateResult {
	/**
	 * Encoded certificate outputs.
	 */
	readonly certificate: CertificateMaterial;
	/**
	 * Key pair used to issue the certificate.
	 */
	readonly keyPair: KeyPairMaterial;
}

/**
 * Create a self-signed certificate.
 *
 * Reuses `input.keyPair` when provided; otherwise generates a new key pair from
 * `input.algorithm`. The returned certificate uses `input.subject` as both
 * issuer and subject.
 *
 * @example
 * ```ts
 * const { certificate, keyPair } = await createSelfSignedCertificate({
 * 	subject: { commonName: 'example.com' },
 * 	algorithm: { kind: 'ecdsa', curve: 'P-256' },
 * });
 * ```
 *
 * @param input Certificate subject, key, validity, and extension settings.
 * @returns The certificate plus the key pair used to sign it.
 */
export async function createSelfSignedCertificate(
	input: CreateSelfSignedCertificateInput,
): Promise<SelfSignedCertificateResult> {
	const keyPair = input.keyPair ?? (await generateKeyPair(input.algorithm));
	const certificateInput = {
		issuer: input.subject,
		subject: input.subject,
		publicKey: keyPair.publicKey,
		signerPrivateKey: keyPair.privateKey,
		issuerPublicKey: keyPair.publicKey,
		...(input.validity !== undefined ? { validity: input.validity } : {}),
		...(input.serialNumber !== undefined ? { serialNumber: input.serialNumber } : {}),
		...(input.extensions !== undefined ? { extensions: input.extensions } : {}),
		...(input.signature !== undefined ? { signature: input.signature } : {}),
	} satisfies CreateCertificateInput;
	const certificate = await createCertificate(certificateInput);

	return { certificate, keyPair };
}

/**
 * Create an X.509 certificate signed by `input.signerPrivateKey`.
 *
 * The certificate encodes `input.subject`, `input.publicKey`, and any supplied
 * extensions. When `serialNumber` is omitted, a random positive serial number is
 * generated. When `validity` is omitted, the certificate is valid from now for
 * 30 days.
 *
 * @example
 * ```ts
 * const certificate = await createCertificate({
 * 	issuer: { commonName: 'Example Root CA' },
 * 	subject: { commonName: 'example.com' },
 * 	publicKey: leafKeys.publicKey,
 * 	signerPrivateKey: issuerKeys.privateKey,
 * 	issuerPublicKey: issuerKeys.publicKey,
 * });
 * ```
 *
 * @param input Issuer, subject, key, validity, and extension settings.
 * @returns The encoded certificate material.
 */
export async function createCertificate(
	input: CreateCertificateInput,
): Promise<CertificateMaterial> {
	const subjectPublicKeyInfo = await exportSpkiDer(input.publicKey);
	const issuerPublicKeyInfo = input.issuerPublicKey
		? await exportSpkiDer(input.issuerPublicKey)
		: undefined;
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey, input.signature);
	const validity = resolveValidity(input.validity);
	const subjectIsEmpty = isNameInputEmpty(input.subject);
	const extensions = buildCertificateExtensions(
		subjectPublicKeyInfo,
		issuerPublicKeyInfo,
		input.extensions,
		subjectIsEmpty,
	);
	const tbsCertificate = sequence([
		explicitContext(0, integerFromNumber(2)),
		integer(input.serialNumber ?? randomSerialNumber()),
		encodeAlgorithmIdentifier(signatureAlgorithm),
		encodeName(input.issuer),
		sequence([time(validity.notBefore), time(validity.notAfter)]),
		encodeName(input.subject),
		subjectPublicKeyInfo,
		explicitContext(3, sequence(extensions)),
	]);

	const signatureValue = await signBytes(
		input.signerPrivateKey,
		signatureAlgorithm,
		tbsCertificate,
	);
	const certificateDer = sequence([
		tbsCertificate,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);

	return materializeCertificate(certificateDer);
}

/**
 * Convert DER bytes into all exported certificate encodings.
 *
 * @param der DER-encoded certificate bytes.
 * @returns DER, PEM, and base64 views of the same certificate.
 */
function materializeCertificate(der: Uint8Array): CertificateMaterial {
	return {
		der,
		pem: pemEncode('CERTIFICATE', der),
		base64: base64Encode(der),
	};
}

/**
 * Normalized validity window used during certificate creation.
 */
interface ResolvedValidity {
	/**
	 * Start of the validity window.
	 */
	readonly notBefore: Date;
	/**
	 * End of the validity window.
	 */
	readonly notAfter: Date;
}

/**
 * Resolve defaults for a certificate validity window.
 *
 * @param input Optional validity settings.
 * @returns A concrete `notBefore` and `notAfter` pair.
 */
function resolveValidity(input: ValidityInput | undefined): ResolvedValidity {
	const notBefore = input?.notBefore ?? new Date();
	const notAfter = input?.notAfter ?? addDays(notBefore, input?.days ?? 30);
	if (notAfter.getTime() <= notBefore.getTime()) {
		throw new Error('notAfter must be after notBefore');
	}
	return { notBefore, notAfter };
}

/**
 * Return a new date offset by a whole number of UTC days.
 *
 * @param date Base date.
 * @param days Number of days to add.
 * @returns The shifted date.
 */
function addDays(date: Date, days: number): Date {
	const out = new Date(date.getTime());
	out.setUTCDate(out.getUTCDate() + days);
	return out;
}

/**
 * Generate a random positive serial number suitable for certificate issuance.
 *
 * @returns A 16-byte positive serial number.
 */
function randomSerialNumber(): Uint8Array {
	const serial = getCrypto().getRandomValues(new Uint8Array(16));
	const first = serial[0] ?? 0;
	serial[0] = first & 0x7f;
	if ((serial[0] ?? 0) === 0) {
		serial[0] = 1;
	}
	return serial;
}
