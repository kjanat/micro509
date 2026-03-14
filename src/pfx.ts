/**
 * PKCS#12/PFX creation and parsing helpers.
 *
 * This module manages certificate bags, private-key bags, encryption, and MAC verification
 * for PFX containers.
 */

import { childrenOf, decodeObjectIdentifier, toHex } from './asn1.ts';
import type { Micro509Error } from './core/result.ts';
import type { DerElement } from './der.ts';
import {
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	tlv,
} from './der.ts';
import { exportPkcs8Der } from './keys.ts';
import { OIDS } from './oids.ts';
import { type ParsedCertificate, parseCertificateDer } from './parse.ts';
import { decryptPbes2, encryptPbes2, type Pbes2EncryptionOptions } from './pbes2.ts';
import { base64Encode, pemEncode, splitPemBlocks } from './pem.ts';
import {
	createPkcs12MacData,
	type ParsedPkcs12MacData,
	type Pkcs12MacOptions,
	parsePkcs12MacData,
} from './pkcs12-mac.ts';

/**
 * Describes the accepted source forms for PFX certificate inputs.
 */
export type PfxCertificateSource = string | Uint8Array;
/**
 * Describes the accepted source forms for PFX private key inputs.
 */
export type PfxPrivateKeySource = CryptoKey | Uint8Array;

/**
 * Describes the input shape for PFX bag attributes operations.
 */
export interface PfxBagAttributesInput {
	/**
	 * Carries the friendly name value.
	 */
	readonly friendlyName?: string;
	/**
	 * Carries the local key id value.
	 */
	readonly localKeyId?: Uint8Array;
}

/**
 * Describes the input shape for PFX certificate bag operations.
 */
export interface PfxCertificateBagInput {
	/**
	 * Carries the certificate value.
	 */
	readonly certificate: PfxCertificateSource;
	/**
	 * Carries the attributes value.
	 */
	readonly attributes?: PfxBagAttributesInput;
}

/**
 * Describes the input shape for PFX private key bag operations.
 */
export interface PfxPrivateKeyBagInput {
	/**
	 * Carries the private key value.
	 */
	readonly privateKey: PfxPrivateKeySource;
	/**
	 * Carries the attributes value.
	 */
	readonly attributes?: PfxBagAttributesInput;
}

/**
 * Describes the input shape for create PFX operations.
 */
export interface CreatePfxInput {
	/**
	 * Carries the certificates value.
	 */
	readonly certificates?: readonly PfxCertificateBagInput[];
	/**
	 * Carries the private keys value.
	 */
	readonly privateKeys?: readonly PfxPrivateKeyBagInput[];
	/**
	 * Carries the encryption value.
	 */
	readonly encryption?: PfxEncryptionOptions;
	/**
	 * Carries the mac value.
	 */
	readonly mac?: Pkcs12MacOptions;
}

/**
 * Configures PFX encryption operations.
 */
export type PfxEncryptionOptions = Pbes2EncryptionOptions;

/**
 * Configures parse PFX operations.
 */
export interface ParsePfxOptions {
	/**
	 * Carries the password value.
	 */
	readonly password?: string;
	/**
	 * Carries the mac password value.
	 */
	readonly macPassword?: string;
}

/**
 * Bundles the encoded artifacts produced by PFX operations.
 */
export interface PfxMaterial {
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
 * Describes the structured PFX attribute produced by parsing helpers.
 */
export interface ParsedPfxAttribute {
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the hexadecimal values.
	 */
	readonly valuesHex: readonly string[];
}

/**
 * Describes the structured PFX bag attributes produced by parsing helpers.
 */
export interface ParsedPfxBagAttributes {
	/**
	 * Carries the entries value.
	 */
	readonly entries: readonly ParsedPfxAttribute[];
	/**
	 * Carries the friendly name value.
	 */
	readonly friendlyName?: string;
	/**
	 * Carries the local key id value.
	 */
	readonly localKeyId?: string;
}

/**
 * Describes the structured PFX bag produced by parsing helpers.
 */
export type ParsedPfxBag =
	| {
			/**
			 * Identifies the kind value.
			 */
			readonly kind: 'certificate';
			/**
			 * Carries the bag id value.
			 */
			readonly bagId: string;
			/**
			 * Carries the attributes value.
			 */
			readonly attributes: ParsedPfxBagAttributes;
			/**
			 * Carries the certificate value.
			 */
			readonly certificate: ParsedCertificate;
	  }
	| {
			/**
			 * Identifies the kind value.
			 */
			readonly kind: 'privateKey';
			/**
			 * Carries the bag id value.
			 */
			readonly bagId: string;
			/**
			 * Carries the attributes value.
			 */
			readonly attributes: ParsedPfxBagAttributes;
			/**
			 * Carries the DER-encoded pkcs#8.
			 */
			readonly pkcs8Der: Uint8Array;
	  }
	| {
			/**
			 * Identifies the kind value.
			 */
			readonly kind: 'unknown';
			/**
			 * Carries the bag id value.
			 */
			readonly bagId: string;
			/**
			 * Carries the attributes value.
			 */
			readonly attributes: ParsedPfxBagAttributes;
			/**
			 * Carries the DER-encoded value.
			 */
			readonly valueDer: Uint8Array;
	  };

/**
 * Describes the structured PFX produced by parsing helpers.
 */
export interface ParsedPfx {
	/**
	 * Carries the bags value.
	 */
	readonly bags: readonly ParsedPfxBag[];
	/**
	 * Carries the certificates value.
	 */
	readonly certificates: readonly ParsedCertificate[];
	/**
	 * Carries the private keys value.
	 */
	readonly privateKeys: readonly Uint8Array[];
	/**
	 * Carries the mac data value.
	 */
	readonly macData?: ParsedPkcs12MacData;
}

// ---------------------------------------------------------------------------
// Result types for PFX parsing
// ---------------------------------------------------------------------------

/**
 * Enumerates the error codes used by parse PFX failures.
 */
export type ParsePfxErrorCode = 'malformed' | 'invalid_password' | 'password_required';

/**
 * Represents a typed failure produced by parse PFX operations.
 */
export interface ParsePfxFailure extends Micro509Error<ParsePfxErrorCode> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents the result returned by parse PFX failure operations.
 */
interface ParsePfxFailureResult {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the canonical error payload.
	 */
	readonly error: ParsePfxFailure;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: ParsePfxErrorCode;
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
}

/**
 * Represents the result returned by parse PFX operations.
 */
export type ParsePfxResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: ParsedPfx;
	  }
	| ParsePfxFailureResult;

// ---------------------------------------------------------------------------
// createPfx
// ---------------------------------------------------------------------------

/**
 * Creates PFX.
 *
 * @param input The typed input payload.
 * @returns The created PFX.
 */
export async function createPfx(input: CreatePfxInput): Promise<PfxMaterial> {
	const certificateBags: Uint8Array[] = [];
	const privateKeyBags: Uint8Array[] = [];
	for (const certificate of input.certificates ?? []) {
		certificateBags.push(
			createCertificateBag(
				await normalizeCertificate(certificate.certificate),
				certificate.attributes,
			),
		);
	}
	for (const privateKey of input.privateKeys ?? []) {
		privateKeyBags.push(
			createPrivateKeyBag(await normalizePrivateKey(privateKey.privateKey), privateKey.attributes),
		);
	}
	const contentInfos: Uint8Array[] = [];
	if (certificateBags.length > 0) {
		contentInfos.push(createDataContentInfo(sequence(certificateBags)));
	}
	if (privateKeyBags.length > 0) {
		const safeContents = sequence(privateKeyBags);
		contentInfos.push(
			input.encryption === undefined
				? createDataContentInfo(safeContents)
				: await createEncryptedDataContentInfo(safeContents, input.encryption),
		);
	}
	const authenticatedSafe = sequence(contentInfos);
	const macData =
		input.mac === undefined ? undefined : await createPkcs12MacData(authenticatedSafe, input.mac);
	const der = sequence([
		integerFromNumber(3),
		createDataContentInfo(authenticatedSafe),
		...(macData === undefined ? [] : [macData.der]),
	]);
	return {
		der,
		pem: pemEncode('PKCS12', der),
		base64: base64Encode(der),
	};
}

// ---------------------------------------------------------------------------
// parsePfxDer / parsePfxPem — Result-returning
// ---------------------------------------------------------------------------

/**
 * Parses PFX DER.
 *
 * @param der The DER-encoded bytes.
 * @param options The options that control the operation.
 * @returns The parsed PFX DER.
 */
export async function parsePfxDer(
	der: Uint8Array,
	options?: ParsePfxOptions,
): Promise<ParsePfxResult> {
	try {
		const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		const authSafe = topLevel[1];
		if (authSafe === undefined) {
			return pfxFailure('malformed', 'Malformed PFX structure');
		}
		const authSafeDer = der.slice(authSafe.start - authSafe.headerLength, authSafe.end);
		const authenticatedSafeOctets = extractContentInfoData(authSafeDer);
		const macElement = topLevel[2];
		let macData: ParsedPkcs12MacData | undefined;
		if (macElement !== undefined) {
			try {
				macData = await parsePkcs12MacData(
					der.slice(macElement.start - macElement.headerLength, macElement.end),
					authenticatedSafeOctets,
					options?.macPassword ?? options?.password,
				);
			} catch {
				return pfxFailure('invalid_password', 'Invalid PFX MAC password or corrupted content');
			}
			if (macData?.valid === false) {
				return pfxFailure('invalid_password', 'Invalid PFX MAC password or corrupted content');
			}
		}
		const authenticatedSafe = readSequenceChildren(authenticatedSafeOctets);
		const bags: ParsedPfxBag[] = [];
		for (const contentInfo of authenticatedSafe) {
			const contentInfoDer = authenticatedSafeOctets.slice(
				contentInfo.start - contentInfo.headerLength,
				contentInfo.end,
			);
			const safeContentsResult = await extractSafeContents(contentInfoDer, options);
			if (safeContentsResult.error !== undefined) {
				return safeContentsResult.error;
			}
			for (const bag of readSequenceChildren(safeContentsResult.data)) {
				const bagDer = safeContentsResult.data.slice(bag.start - bag.headerLength, bag.end);
				bags.push(parseSafeBag(bagDer));
			}
		}
		return {
			ok: true,
			value: {
				bags,
				certificates: bags.flatMap((bag) => (bag.kind === 'certificate' ? [bag.certificate] : [])),
				privateKeys: bags.flatMap((bag) => (bag.kind === 'privateKey' ? [bag.pkcs8Der] : [])),
				...(macData === undefined ? {} : { macData }),
			},
		};
	} catch {
		return pfxFailure('malformed', 'Malformed PFX structure');
	}
}

/**
 * Parses PFX PEM.
 *
 * @param pem The PEM-encoded text.
 * @param options The options that control the operation.
 * @returns The parsed PFX PEM.
 */
export async function parsePfxPem(pem: string, options?: ParsePfxOptions): Promise<ParsePfxResult> {
	try {
		const blocks = splitPemBlocks(pem).filter((block) => block.label === 'PKCS12');
		const block = blocks[0];
		if (block === undefined || blocks.length !== 1) {
			return pfxFailure('malformed', 'Expected exactly one PKCS12 PEM block');
		}
		return parsePfxDer(block.bytes, options);
	} catch {
		return pfxFailure('malformed', 'Expected exactly one PKCS12 PEM block');
	}
}

// ---------------------------------------------------------------------------
// Private: PFX helpers
// ---------------------------------------------------------------------------

/**
 * PFX failure.
 *
 * @param code The code value.
 * @param message The message value.
 * @returns The computed value.
 */
function pfxFailure(code: ParsePfxErrorCode, message: string): ParsePfxFailureResult {
	const error: ParsePfxFailure = {
		/**
		 * Indicates whether the operation succeeded.
		 */
		ok: false,
		/**
		 * Carries the machine-readable error code.
		 */
		code,
		/**
		 * Carries the human-readable error message.
		 */
		message,
	};
	return { ok: false, error, code, message };
}

/**
 * Extract content info data.
 *
 * @param contentInfoDer The content info DER value.
 * @returns The computed value.
 */
function extractContentInfoData(contentInfoDer: Uint8Array): Uint8Array {
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const contentType = contentInfoChildren[0];
	const content = contentInfoChildren[1];
	if (contentType === undefined || content === undefined) {
		throw new Error('Malformed ContentInfo');
	}
	if (decodeObjectIdentifier(contentType.value) !== OIDS.pkcs7Data) {
		throw new Error('Only passwordless data ContentInfo is supported');
	}
	return extractContextOctetString(contentInfoDer, content);
}

/**
 * Extract safe contents.
 *
 * @param contentInfoDer The content info DER value.
 * @param options The options that control the operation.
 * @returns The computed value.
 */
async function extractSafeContents(
	contentInfoDer: Uint8Array,
	options: ParsePfxOptions | undefined,
): Promise<
	| {
			/**
			 * Carries the data value.
			 */
			readonly data: Uint8Array;
			/**
			 * Carries the canonical error payload.
			 */
			readonly error?: undefined;
	  }
	| {
			/**
			 * Carries the data value.
			 */
			readonly data?: undefined;
			/**
			 * Carries the canonical error payload.
			 */
			readonly error: ParsePfxFailureResult;
	  }
> {
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const contentType = contentInfoChildren[0];
	const content = contentInfoChildren[1];
	if (contentType === undefined || content === undefined) {
		return { error: pfxFailure('malformed', 'Malformed ContentInfo') };
	}
	const oid = decodeObjectIdentifier(contentType.value);
	if (oid === OIDS.pkcs7Data) {
		return { data: extractContextOctetString(contentInfoDer, content) };
	}
	if (oid !== OIDS.pkcs7EncryptedData) {
		return {
			error: pfxFailure('malformed', 'Unsupported PFX ContentInfo type'),
		};
	}
	if (options?.password === undefined) {
		return {
			error: pfxFailure('password_required', 'Password required for encrypted PFX content'),
		};
	}
	const encryptedData = extractContextChild(contentInfoDer, content);
	try {
		const decrypted = await decryptEncryptedData(
			contentInfoDer.slice(encryptedData.start - encryptedData.headerLength, encryptedData.end),
			options.password,
		);
		readSequenceChildren(decrypted);
		return { data: decrypted };
	} catch {
		return {
			error: pfxFailure('invalid_password', 'Invalid PFX password or encrypted content'),
		};
	}
}

/**
 * Creates certificate bag.
 *
 * @param certificateDer The certificate DER value.
 * @param attributes The attributes value.
 * @returns The created certificate bag.
 */
function createCertificateBag(
	certificateDer: Uint8Array,
	attributes: PfxBagAttributesInput | undefined,
): Uint8Array {
	const certBag = sequence([
		objectIdentifier(OIDS.x509CertificateBagType),
		explicitContext(0, octetString(certificateDer)),
	]);
	return sequence([
		objectIdentifier(OIDS.pkcs12CertBag),
		explicitContext(0, certBag),
		...encodeBagAttributes(attributes),
	]);
}

/**
 * Creates private key bag.
 *
 * @param pkcs8Der The PKCS#8 DER value.
 * @param attributes The attributes value.
 * @returns The created private key bag.
 */
function createPrivateKeyBag(
	pkcs8Der: Uint8Array,
	attributes: PfxBagAttributesInput | undefined,
): Uint8Array {
	return sequence([
		objectIdentifier(OIDS.pkcs12KeyBag),
		explicitContext(0, pkcs8Der),
		...encodeBagAttributes(attributes),
	]);
}

/**
 * Creates data content info.
 *
 * @param data The raw bytes to process.
 * @returns The created data content info.
 */
function createDataContentInfo(data: Uint8Array): Uint8Array {
	return sequence([objectIdentifier(OIDS.pkcs7Data), explicitContext(0, octetString(data))]);
}

/**
 * Creates encrypted data content info.
 *
 * @param data The raw bytes to process.
 * @param options The options that control the operation.
 * @returns The created encrypted data content info.
 */
async function createEncryptedDataContentInfo(
	data: Uint8Array,
	options: PfxEncryptionOptions,
): Promise<Uint8Array> {
	const encryption = await encryptPbes2(data, options);
	const encryptedData = sequence([
		integerFromNumber(0),
		sequence([
			objectIdentifier(OIDS.pkcs7Data),
			encryption.algorithmIdentifierDer,
			tlv(0x80, encryption.encryptedData),
		]),
	]);
	return sequence([objectIdentifier(OIDS.pkcs7EncryptedData), explicitContext(0, encryptedData)]);
}

/**
 * Encodes bag attributes.
 *
 * @param attributes The attributes value.
 * @returns The encoded bag attributes.
 */
function encodeBagAttributes(attributes: PfxBagAttributesInput | undefined): readonly Uint8Array[] {
	if (attributes === undefined) {
		return [];
	}
	const out: Uint8Array[] = [];
	if (attributes.friendlyName !== undefined) {
		out.push(
			sequence([objectIdentifier(OIDS.friendlyName), setOf([bmpString(attributes.friendlyName)])]),
		);
	}
	if (attributes.localKeyId !== undefined) {
		out.push(
			sequence([objectIdentifier(OIDS.localKeyId), setOf([octetString(attributes.localKeyId)])]),
		);
	}
	return out.length === 0 ? [] : [setOf(out)];
}

/**
 * Parses safe bag.
 *
 * @param der The DER-encoded bytes.
 * @returns The parsed safe bag.
 */
function parseSafeBag(der: Uint8Array): ParsedPfxBag {
	const children = readSequenceChildren(der);
	const bagId = children[0];
	const bagValue = children[1];
	const attributeSet = children[2];
	if (bagId === undefined || bagValue === undefined) {
		throw new Error('Malformed SafeBag');
	}
	const bagOid = decodeObjectIdentifier(bagId.value);
	const attributes = parseBagAttributes(der, attributeSet);
	if (bagOid === OIDS.pkcs12CertBag) {
		const certBag = extractContextChild(der, bagValue);
		const certBagDer = der.slice(certBag.start - certBag.headerLength, certBag.end);
		const certBagChildren = readSequenceChildren(certBagDer);
		const certValue = certBagChildren[1];
		if (certValue === undefined) {
			throw new Error('Malformed certBag');
		}
		const certificateDer = extractContextOctetString(certBagDer, certValue);
		return {
			kind: 'certificate',
			bagId: bagOid,
			attributes,
			certificate: parseCertificateDer(certificateDer),
		};
	}
	if (bagOid === OIDS.pkcs12KeyBag) {
		const pkcs8 = extractContextChild(der, bagValue);
		return {
			kind: 'privateKey',
			bagId: bagOid,
			attributes,
			pkcs8Der: der.slice(pkcs8.start - pkcs8.headerLength, pkcs8.end),
		};
	}
	const value = extractContextChild(der, bagValue);
	return {
		kind: 'unknown',
		bagId: bagOid,
		attributes,
		valueDer: der.slice(value.start - value.headerLength, value.end),
	};
}

/**
 * Parses bag attributes.
 *
 * @param source The source value to process.
 * @param attributeSet The attribute set value.
 * @returns The parsed bag attributes.
 */
function parseBagAttributes(
	source: Uint8Array,
	attributeSet: DerElement | undefined,
): ParsedPfxBagAttributes {
	if (attributeSet === undefined) {
		return { entries: [] };
	}
	const entries: ParsedPfxAttribute[] = [];
	let friendlyName: string | undefined;
	let localKeyId: string | undefined;
	for (const attribute of childrenOf(source, attributeSet)) {
		const attributeDer = source.slice(attribute.start - attribute.headerLength, attribute.end);
		const parts = readSequenceChildren(attributeDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined) {
			throw new Error('Malformed PFX bag attribute');
		}
		const attrOid = decodeObjectIdentifier(oid.value);
		const rawValues = childrenOf(attributeDer, values).map((value) =>
			attributeDer.slice(value.start - value.headerLength, value.end),
		);
		entries.push({
			oid: attrOid,
			valuesHex: rawValues.map((value) => toHex(value)),
		});
		const firstValue = rawValues[0];
		if (firstValue === undefined) {
			continue;
		}
		if (attrOid === OIDS.friendlyName) {
			friendlyName = decodeBmpString(firstValue);
		}
		if (attrOid === OIDS.localKeyId) {
			localKeyId = toHex(readElement(firstValue).value);
		}
	}
	return {
		entries,
		...(friendlyName === undefined ? {} : { friendlyName }),
		...(localKeyId === undefined ? {} : { localKeyId }),
	};
}

/**
 * Normalizes private key.
 *
 * @param source The source value to process.
 * @returns The computed value.
 */
async function normalizePrivateKey(source: PfxPrivateKeySource): Promise<Uint8Array> {
	if (source instanceof CryptoKey) {
		return exportPkcs8Der(source);
	}
	return new Uint8Array(source);
}

/**
 * Normalizes certificate.
 *
 * @param source The source value to process.
 * @returns The computed value.
 */
async function normalizeCertificate(source: PfxCertificateSource): Promise<Uint8Array> {
	if (typeof source === 'string') {
		const block = splitPemBlocks(source).find((candidate) => candidate.label === 'CERTIFICATE');
		if (block === undefined) {
			throw new Error('Certificate PEM required');
		}
		return new Uint8Array(block.bytes);
	}
	return new Uint8Array(source);
}

/**
 * Decrypt encrypted data.
 *
 * @param encryptedDataDer The encrypted data DER value.
 * @param password The password used to protect or unlock the data.
 * @returns The computed value.
 */
async function decryptEncryptedData(
	encryptedDataDer: Uint8Array,
	password: string,
): Promise<Uint8Array> {
	const topLevel = readSequenceChildren(encryptedDataDer);
	const encryptedContentInfo = topLevel[1];
	if (encryptedContentInfo === undefined) {
		throw new Error('Malformed EncryptedData');
	}
	const contentInfoDer = encryptedDataDer.slice(
		encryptedContentInfo.start - encryptedContentInfo.headerLength,
		encryptedContentInfo.end,
	);
	const contentInfoChildren = readSequenceChildren(contentInfoDer);
	const algorithm = contentInfoChildren[1];
	const encryptedContent = contentInfoChildren[2];
	if (algorithm === undefined || encryptedContent === undefined) {
		throw new Error('Malformed EncryptedContentInfo');
	}
	if (encryptedContent.tag !== 0x80) {
		throw new Error('Malformed encrypted content');
	}
	return decryptPbes2(
		contentInfoDer.slice(algorithm.start - algorithm.headerLength, algorithm.end),
		encryptedContent.value,
		password,
	);
}

/**
 * Extract context octet string.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The computed value.
 */
function extractContextOctetString(source: Uint8Array, element: DerElement): Uint8Array {
	const child = extractContextChild(source, element);
	if (child.tag !== 0x04) {
		throw new Error('Expected OCTET STRING in context value');
	}
	return child.value;
}

/**
 * Extract context child.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The computed value.
 */
function extractContextChild(source: Uint8Array, element: DerElement): DerElement {
	if ((element.tag & 0xe0) !== 0xa0) {
		throw new Error('Expected context-specific constructed value');
	}
	return readElement(source, element.start);
}

/**
 * Bmp string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function bmpString(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length * 2);
	for (let index = 0; index < value.length; index += 1) {
		const codePoint = value.charCodeAt(index);
		bytes[index * 2] = codePoint >> 8;
		bytes[index * 2 + 1] = codePoint & 0xff;
	}
	return tlv(0x1e, bytes);
}

/**
 * Decodes bmp string.
 *
 * @param der The DER-encoded bytes.
 * @returns The decoded bmp string.
 */
function decodeBmpString(der: Uint8Array): string {
	const element = readElement(der);
	if (element.tag !== 0x1e) {
		throw new Error('Expected BMPString');
	}
	let value = '';
	for (let index = 0; index < element.value.length; index += 2) {
		const left = element.value[index] ?? 0;
		const right = element.value[index + 1] ?? 0;
		value += String.fromCharCode((left << 8) | right);
	}
	return value;
}
