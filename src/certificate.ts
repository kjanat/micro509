import { bitString, explicitContext, integer, integerFromNumber, sequence, time } from './der.ts';
import { buildCertificateExtensions, type CertificateExtensionsInput } from './extensions.ts';
import {
	exportSpkiDer,
	generateKeyPair,
	getCrypto,
	type KeyAlgorithmInput,
	type KeyPairMaterial,
} from './keys.ts';
import { encodeName, type NameInput } from './name.ts';
import { base64Encode, pemEncode } from './pem.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	type SignatureProfileInput,
	signBytes,
} from './signing.ts';

export interface ValidityInput {
	readonly notBefore?: Date;
	readonly notAfter?: Date;
	readonly days?: number;
}

export interface CreateCertificateInput {
	readonly issuer: NameInput;
	readonly subject: NameInput;
	readonly publicKey: CryptoKey;
	readonly signerPrivateKey: CryptoKey;
	readonly issuerPublicKey?: CryptoKey;
	readonly validity?: ValidityInput;
	readonly serialNumber?: Uint8Array;
	readonly extensions?: CertificateExtensionsInput;
	readonly signature?: SignatureProfileInput;
}

export interface CreateSelfSignedCertificateInput {
	readonly subject: NameInput;
	readonly algorithm?: KeyAlgorithmInput;
	readonly keyPair?: KeyPairMaterial;
	readonly validity?: ValidityInput;
	readonly serialNumber?: Uint8Array;
	readonly extensions?: CertificateExtensionsInput;
	readonly signature?: SignatureProfileInput;
}

export interface CertificateMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface SelfSignedCertificateResult {
	readonly certificate: CertificateMaterial;
	readonly keyPair: KeyPairMaterial;
}

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

export async function createCertificate(
	input: CreateCertificateInput,
): Promise<CertificateMaterial> {
	const subjectPublicKeyInfo = await exportSpkiDer(input.publicKey);
	const issuerPublicKeyInfo = input.issuerPublicKey
		? await exportSpkiDer(input.issuerPublicKey)
		: undefined;
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey, input.signature);
	const validity = resolveValidity(input.validity);
	const extensions = buildCertificateExtensions(
		subjectPublicKeyInfo,
		issuerPublicKeyInfo,
		input.extensions,
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

function materializeCertificate(der: Uint8Array): CertificateMaterial {
	return {
		der,
		pem: pemEncode('CERTIFICATE', der),
		base64: base64Encode(der),
	};
}

interface ResolvedValidity {
	readonly notBefore: Date;
	readonly notAfter: Date;
}

function resolveValidity(input: ValidityInput | undefined): ResolvedValidity {
	const notBefore = input?.notBefore ?? new Date();
	const notAfter = input?.notAfter ?? addDays(notBefore, input?.days ?? 30);
	if (notAfter.getTime() <= notBefore.getTime()) {
		throw new Error('notAfter must be after notBefore');
	}
	return { notBefore, notAfter };
}

function addDays(date: Date, days: number): Date {
	const out = new Date(date.getTime());
	out.setUTCDate(out.getUTCDate() + days);
	return out;
}

function randomSerialNumber(): Uint8Array {
	const serial = getCrypto().getRandomValues(new Uint8Array(16));
	const first = serial[0] ?? 0;
	serial[0] = first & 0x7f;
	if ((serial[0] ?? 0) === 0) {
		serial[0] = 1;
	}
	return serial;
}
