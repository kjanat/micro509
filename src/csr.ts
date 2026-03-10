import {
	bitString,
	concatBytes,
	implicitConstructedContext,
	integerFromNumber,
	objectIdentifier,
	sequence,
	setOf,
} from "./der.js";
import { buildRequestedExtensions, type CertificateExtensionsInput } from "./extensions.js";
import { exportSpkiDer } from "./keys.js";
import { encodeName, type NameInput } from "./name.js";
import { OIDS } from "./oids.js";
import { base64Encode, pemEncode } from "./pem.js";
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from "./signing.js";

export interface CreateCsrInput {
	readonly subject: NameInput;
	readonly publicKey: CryptoKey;
	readonly signerPrivateKey: CryptoKey;
	readonly extensions?: CertificateExtensionsInput;
}

export interface CsrMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export async function createCertificateSigningRequest(
	input: CreateCsrInput,
): Promise<CsrMaterial> {
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
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
	return { der, pem: pemEncode("CERTIFICATE REQUEST", der), base64: base64Encode(der) };
}

function buildAttributes(
	extensions: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const builtExtensions = buildRequestedExtensions(extensions);
	if (builtExtensions.length === 0) {
		return [];
	}
	return [
		sequence([
			objectIdentifier(OIDS.extensionRequest),
			setOf([sequence(builtExtensions)]),
		]),
	];
}
