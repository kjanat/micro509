/**
 * PKCS#7/CMS certificate bags and SignedData.
 *
 * Creates degenerate (signature-less) certificate bags, parses RFC 2315 / RFC 5652
 * SignedData structures, and verifies signer signatures including signed-attribute flows.
 *
 * @module
 */

import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	requireElement,
	toArrayBuffer,
	toHex,
} from '../internal/asn1/asn1.ts';
import type { DerElement } from '../internal/asn1/der.ts';
import {
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	integerFromNumber,
	objectIdentifier,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
} from '../internal/asn1/der.ts';
import { OIDS } from '../internal/asn1/oids.ts';
import { verifySignedData } from '../internal/crypto/sig-verify.ts';
import { getCrypto } from '../internal/crypto/webcrypto.ts';
import { base64Encode } from '../internal/shared/base64.ts';
import type { ParsedCertificate } from '../x509/parse.ts';
import { parseCertificateDer } from '../x509/parse.ts';
import { pemEncode, splitPemBlocks } from '../pem/pem.ts';
import type { ErrorResult, Micro509Error } from '../result/result.ts';

export type * from '../x509/parse.ts';
export type * from '../result/result.ts';

/** PEM text (may contain multiple CERTIFICATE blocks) or raw DER bytes. */
export type Pkcs7CertificateSource = string | Uint8Array;

/** DER, PEM, and base64 encodings of a PKCS#7 certificate bag. */
export interface Pkcs7CertBag {
	/** Raw DER-encoded PKCS#7 structure. */
	readonly der: Uint8Array;
	/** PEM-armored PKCS#7 (`-----BEGIN PKCS7-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armor). */
	readonly base64: string;
}

/** A single SignerInfo decoded from a PKCS#7 SignedData structure. */
export interface ParsedPkcs7SignerInfo {
	/** CMS SignerInfo version (typically 1 for issuerAndSerialNumber). */
	readonly version: number;
	/** Hex-encoded DER of the signer's issuer name, if present. */
	readonly issuerDerHex?: string;
	/** Hex-encoded serial number used to locate the signer certificate. */
	readonly serialNumberHex?: string;
	/** OID of the digest algorithm used to hash the content. */
	readonly digestAlgorithmOid: string;
	/** OID of the algorithm used to produce the signature. */
	readonly signatureAlgorithmOid: string;
	/** Hex-encoded raw signature bytes. */
	readonly signatureHex: string;
	/** Raw signature bytes. */
	readonly signature: Uint8Array;
	/** Whether this SignerInfo includes authenticated (signed) attributes. */
	readonly hasSignedAttrs: boolean;
	/** Raw DER of signedAttrs with original IMPLICIT [0] tag (0xa0). Present only when `hasSignedAttrs` is true. */
	readonly signedAttrsDer?: Uint8Array;
}

/** Decoded PKCS#7 SignedData content, including certificates and signer info. */
export interface ParsedPkcs7SignedData {
	/** Outer ContentInfo type OID (always `pkcs7-signedData`). */
	readonly contentTypeOid: string;
	/** SignedData version number. */
	readonly version: number;
	/** OIDs of digest algorithms declared in `digestAlgorithms`. */
	readonly digestAlgorithmOids: readonly string[];
	/** OID of the encapsulated content type (e.g. `pkcs7-data`). */
	readonly encapsulatedContentTypeOid: string;
	/** Raw encapsulated content bytes. Absent in degenerate (certs-only) bags. */
	readonly encapsulatedContent?: Uint8Array;
	/** Certificates included in the SignedData certificate set. */
	readonly certificates: readonly ParsedCertificate[];
	/** Decoded signer info entries. Empty for degenerate cert bags. */
	readonly signerInfos: readonly ParsedPkcs7SignerInfo[];
}

// ---------------------------------------------------------------------------
// Result types for PKCS#7 parsing
// ---------------------------------------------------------------------------

/** Error codes for PKCS#7 parse failures. */
export type ParsePkcs7ErrorCode = 'malformed' | 'not_signed_data';

/** Error payload for a failed PKCS#7 parse. */
export interface ParsePkcs7Failure extends Micro509Error<ParsePkcs7ErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode parsePkcs7SignedDataDer} / {@linkcode parsePkcs7SignedDataPem}. */
export type ParsePkcs7SignedDataResult =
	| {
			/** Parse succeeded. */
			readonly ok: true;
			/** Decoded SignedData. */
			readonly value: ParsedPkcs7SignedData;
	  }
	| ErrorResult<ParsePkcs7ErrorCode, Record<never, never>, ParsePkcs7Failure>;

/** Success-or-failure result from {@linkcode parsePkcs7CertBagDer} / {@linkcode parsePkcs7CertBagPem}. */
export type ParsePkcs7CertBagResult =
	| {
			/** Parse succeeded. */
			readonly ok: true;
			/** Parsed certificates from the cert bag. */
			readonly value: readonly ParsedCertificate[];
	  }
	| ErrorResult<ParsePkcs7ErrorCode, Record<never, never>, ParsePkcs7Failure>;

/** Error payload for a failed {@linkcode verifyPkcs7SignedData} call. */
export interface VerifyPkcs7SignedDataFailure
	extends Micro509Error<
		| 'signer_not_found'
		| 'signature_invalid'
		| 'message_digest_mismatch'
		| 'content_missing'
		| ParsePkcs7ErrorCode
	> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode verifyPkcs7SignedData}. */
export type VerifyPkcs7SignedDataResult =
	| {
			/** Verification succeeded. */
			readonly ok: true;
			/** The verified SignedData structure. */
			readonly value: ParsedPkcs7SignedData;
	  }
	| ErrorResult<
			| 'signer_not_found'
			| 'signature_invalid'
			| 'message_digest_mismatch'
			| 'content_missing'
			| ParsePkcs7ErrorCode,
			Record<never, never>,
			VerifyPkcs7SignedDataFailure
	  >;

// ---------------------------------------------------------------------------
// createPkcs7CertBag
// ---------------------------------------------------------------------------

/**
 * Creates a degenerate PKCS#7 SignedData structure containing only certificates (no signers).
 *
 * Returns the raw DER encoding. Use {@linkcode createPkcs7CertBagPem} for PEM + base64.
 */
export function createPkcs7CertBagDer(certificates: readonly Pkcs7CertificateSource[]): Uint8Array {
	const certificateDers = certificates.flatMap(normalizeCertificateSource);
	const signedData = sequence([
		integerFromNumber(1),
		setOf([]),
		sequence([objectIdentifier(OIDS.pkcs7Data)]),
		explicitContext(0, concatBytes(certificateDers)),
		setOf([]),
	]);
	return sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]);
}

/**
 * Creates a degenerate PKCS#7 SignedData certificate bag and returns DER, PEM, and base64 forms.
 */
export function createPkcs7CertBagPem(
	certificates: readonly Pkcs7CertificateSource[],
): Pkcs7CertBag {
	const der = createPkcs7CertBagDer(certificates);
	return {
		der,
		pem: pemEncode('PKCS7', der),
		base64: base64Encode(der),
	};
}

// ---------------------------------------------------------------------------
// parsePkcs7CertBag — Result-returning
// ---------------------------------------------------------------------------

/** Parses a DER-encoded PKCS#7 cert bag, returning the contained certificates. */
export function parsePkcs7CertBagDer(der: Uint8Array): ParsePkcs7CertBagResult {
	const result = parsePkcs7SignedDataDer(der);
	if (!result.ok) {
		return result;
	}
	return { ok: true, value: result.value.certificates };
}

/** Parses a PEM-armored PKCS#7 cert bag. Expects exactly one `PKCS7` PEM block. */
export function parsePkcs7CertBagPem(pem: string): ParsePkcs7CertBagResult {
	try {
		const blocks = splitPemBlocks(pem).filter((block) => block.label === 'PKCS7');
		if (blocks.length !== 1) {
			return pkcs7Failure('malformed', 'Expected exactly one PKCS7 PEM block');
		}
		const block = blocks[0];
		if (block === undefined) {
			return pkcs7Failure('malformed', 'Missing PKCS7 block');
		}
		return parsePkcs7CertBagDer(block.bytes);
	} catch {
		return pkcs7Failure('malformed', 'Expected exactly one PKCS7 PEM block');
	}
}

// ---------------------------------------------------------------------------
// parsePkcs7SignedData — Result-returning
// ---------------------------------------------------------------------------

/** Decodes a DER-encoded PKCS#7 ContentInfo expecting `signedData` content type. */
export function parsePkcs7SignedDataDer(der: Uint8Array): ParsePkcs7SignedDataResult {
	try {
		const contentInfo = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		const contentType = contentInfo[0];
		const content = contentInfo[1];
		if (contentType === undefined || content === undefined) {
			return pkcs7Failure('malformed', 'Malformed PKCS#7 content info');
		}
		const contentTypeOid = decodeObjectIdentifier(contentType.value);
		if (contentTypeOid !== OIDS.pkcs7SignedData) {
			return pkcs7Failure('not_signed_data', 'PKCS#7 content is not signedData');
		}
		const signedData = childAt(der, content, 0, 'signedData');
		const signedDataChildren = childrenOf(der, signedData);
		const version = signedDataChildren[0];
		const digestAlgorithms = signedDataChildren[1];
		const encapContentInfo = signedDataChildren[2];
		const certificates = signedDataChildren[3];
		const signerInfos = signedDataChildren[signedDataChildren.length - 1];
		if (
			version === undefined ||
			digestAlgorithms === undefined ||
			encapContentInfo === undefined ||
			signerInfos === undefined
		) {
			return pkcs7Failure('malformed', 'Malformed SignedData');
		}
		const encapDer = der.slice(
			encapContentInfo.start - encapContentInfo.headerLength,
			encapContentInfo.end,
		);
		const encapChildren = readSequenceChildren(encapDer);
		const encapType = encapChildren[0];
		const encapContent = encapChildren[1];
		if (encapType === undefined) {
			return pkcs7Failure('malformed', 'Malformed EncapsulatedContentInfo');
		}
		return {
			ok: true,
			value: {
				contentTypeOid,
				version: decodeIntegerNumber(version.value),
				digestAlgorithmOids: parseDigestAlgorithms(der, digestAlgorithms),
				encapsulatedContentTypeOid: decodeObjectIdentifier(encapType.value),
				...(encapContent === undefined
					? {}
					: {
							encapsulatedContent: extractEncapsulatedContent(encapDer, encapContent),
						}),
				certificates: parseCertificateSet(der, certificates),
				signerInfos: parseSignerInfos(der, signerInfos),
			},
		};
	} catch {
		return pkcs7Failure('malformed', 'Malformed PKCS#7 structure');
	}
}

/** Decodes a PEM-armored PKCS#7 SignedData. Expects exactly one `PKCS7` PEM block. */
export function parsePkcs7SignedDataPem(pem: string): ParsePkcs7SignedDataResult {
	try {
		const blocks = splitPemBlocks(pem).filter((block) => block.label === 'PKCS7');
		const block = blocks[0];
		if (block === undefined || blocks.length !== 1) {
			return pkcs7Failure('malformed', 'Expected exactly one PKCS7 PEM block');
		}
		return parsePkcs7SignedDataDer(block.bytes);
	} catch {
		return pkcs7Failure('malformed', 'Expected exactly one PKCS7 PEM block');
	}
}

// ---------------------------------------------------------------------------
// verifyPkcs7SignedData
// ---------------------------------------------------------------------------

/**
 * Verifies all signer signatures in a PKCS#7 SignedData structure.
 *
 * Accepts PEM text, raw DER, or an already-parsed {@linkcode ParsedPkcs7SignedData}.
 * For each signer, locates the matching certificate in the embedded set and
 * verifies the signature (including signed-attribute digest checks per RFC 5652 Section 5.4).
 *
 * @example
 * ```ts
 * import { verifyPkcs7SignedData } from 'micro509';
 *
 * const result = await verifyPkcs7SignedData(pkcs7Pem);
 * if (result.ok) {
 *   console.log('all signers verified');
 * }
 * ```
 */
export async function verifyPkcs7SignedData(
	input: string | Uint8Array | ParsedPkcs7SignedData,
): Promise<VerifyPkcs7SignedDataResult> {
	let parsed: ParsedPkcs7SignedData;
	if (typeof input === 'string') {
		const result = parsePkcs7SignedDataPem(input);
		if (!result.ok) {
			return result;
		}
		parsed = result.value;
	} else if (input instanceof Uint8Array) {
		const result = parsePkcs7SignedDataDer(input);
		if (!result.ok) {
			return result;
		}
		parsed = result.value;
	} else {
		parsed = input;
	}
	if (parsed.encapsulatedContent === undefined) {
		return verifyPkcs7Failure('content_missing', 'SignedData encapsulated content is missing');
	}
	for (const signerInfo of parsed.signerInfos) {
		const signer = parsed.certificates.find(
			(certificate) =>
				signerInfo.serialNumberHex !== undefined &&
				signerInfo.issuerDerHex !== undefined &&
				certificate.serialNumberHex === signerInfo.serialNumberHex &&
				certificate.issuer.derHex === signerInfo.issuerDerHex,
		);
		if (signer === undefined) {
			return verifyPkcs7Failure(
				'signer_not_found',
				'Signer certificate not found in SignedData certificates',
			);
		}
		if (signerInfo.hasSignedAttrs) {
			const attrsResult = await verifySignedAttrs(signerInfo, signer, parsed.encapsulatedContent);
			if (!attrsResult.ok) {
				return attrsResult;
			}
			continue;
		}
		let verified: boolean;
		try {
			verified = await verifySignedData(
				signerInfo.signatureAlgorithmOid,
				undefined,
				signer.publicKeyAlgorithmOid,
				signer.publicKeyParametersOid,
				signer.subjectPublicKeyInfoDer,
				signerInfo.signature,
				parsed.encapsulatedContent,
			);
		} catch {
			return verifyPkcs7Failure('malformed', 'Unsupported signature algorithm in SignedData');
		}
		if (!verified) {
			return verifyPkcs7Failure('signature_invalid', 'SignedData signature does not verify');
		}
	}
	return { ok: true, value: parsed };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/** Shorthand for constructing a PKCS#7 parse failure result. */
function pkcs7Failure(
	code: ParsePkcs7ErrorCode,
	message: string,
): ErrorResult<ParsePkcs7ErrorCode, Record<never, never>, ParsePkcs7Failure> {
	const error: ParsePkcs7Failure = { ok: false, code, message };
	return { ok: false, error, code, message };
}

/** Shorthand for constructing a PKCS#7 verification failure result. */
function verifyPkcs7Failure(
	code:
		| 'signer_not_found'
		| 'signature_invalid'
		| 'message_digest_mismatch'
		| 'content_missing'
		| ParsePkcs7ErrorCode,
	message: string,
): ErrorResult<
	| 'signer_not_found'
	| 'signature_invalid'
	| 'message_digest_mismatch'
	| 'content_missing'
	| ParsePkcs7ErrorCode,
	Record<never, never>,
	VerifyPkcs7SignedDataFailure
> {
	const error: VerifyPkcs7SignedDataFailure = { ok: false, code, message };
	return { ok: false, error, code, message };
}

/** Converts PEM text to an array of DER certificate blobs, or wraps raw DER. */
function normalizeCertificateSource(source: Pkcs7CertificateSource): readonly Uint8Array[] {
	if (typeof source === 'string') {
		return splitPemBlocks(source)
			.filter((block) => block.label === 'CERTIFICATE')
			.map((block) => new Uint8Array(block.bytes));
	}
	return [new Uint8Array(source)];
}

/** Parses the IMPLICIT [0] certificate set from a SignedData structure. */
function parseCertificateSet(
	source: Uint8Array,
	certificates: ReturnType<typeof readElement> | undefined,
): readonly ParsedCertificate[] {
	if (certificates === undefined || certificates.tag !== 0xa0) {
		return [];
	}
	const parsed: ParsedCertificate[] = [];
	let offset = certificates.start;
	while (offset < certificates.end) {
		const element = readElement(source, offset);
		parsed.push(parseCertificateDer(source.slice(offset, element.end)));
		offset = element.end;
	}
	return parsed;
}

/** Extracts the list of digest algorithm OIDs from the digestAlgorithms SET. */
function parseDigestAlgorithms(
	source: Uint8Array,
	element: ReturnType<typeof readElement>,
): readonly string[] {
	const digests: string[] = [];
	for (const child of childrenOf(source, element)) {
		const childDer = source.slice(child.start - child.headerLength, child.end);
		const parts = readSequenceChildren(childDer);
		const oid = parts[0];
		if (oid !== undefined) {
			digests.push(decodeObjectIdentifier(oid.value));
		}
	}
	return digests;
}

/** Decodes the signerInfos SET OF from a SignedData structure. */
function parseSignerInfos(
	source: Uint8Array,
	element: ReturnType<typeof readElement>,
): readonly ParsedPkcs7SignerInfo[] {
	const signers: ParsedPkcs7SignerInfo[] = [];
	for (const signerInfo of childrenOf(source, element)) {
		const signerDer = source.slice(signerInfo.start - signerInfo.headerLength, signerInfo.end);
		const parts = readSequenceChildren(signerDer);
		const version = parts[0];
		const sid = parts[1];
		const digestAlgorithm = parts[2];
		let index = 3;
		const signedAttrsElement = parts[index]?.tag === 0xa0 ? parts[index] : undefined;
		const hasSignedAttrs = signedAttrsElement !== undefined;
		if (hasSignedAttrs) {
			index += 1;
		}
		const signatureAlgorithm = parts[index];
		const signature = parts[index + 1];
		if (
			version === undefined ||
			sid === undefined ||
			digestAlgorithm === undefined ||
			signatureAlgorithm === undefined ||
			signature === undefined ||
			signature.tag !== 0x04
		) {
			throw new Error('Malformed SignerInfo');
		}
		const digestAlgorithmDer = signerDer.slice(
			digestAlgorithm.start - digestAlgorithm.headerLength,
			digestAlgorithm.end,
		);
		const digestAlgorithmOid = decodeObjectIdentifier(
			requireElement(readSequenceChildren(digestAlgorithmDer)[0], 'digest algorithm OID').value,
		);
		const signatureAlgorithmDer = signerDer.slice(
			signatureAlgorithm.start - signatureAlgorithm.headerLength,
			signatureAlgorithm.end,
		);
		const signatureAlgorithmOid = decodeObjectIdentifier(
			requireElement(readSequenceChildren(signatureAlgorithmDer)[0], 'signature algorithm OID')
				.value,
		);
		const parsedSid = parseSignerIdentifier(signerDer.slice(sid.start - sid.headerLength, sid.end));
		signers.push({
			version: decodeIntegerNumber(version.value),
			...(parsedSid.issuerDerHex === undefined ? {} : { issuerDerHex: parsedSid.issuerDerHex }),
			...(parsedSid.serialNumberHex === undefined
				? {}
				: { serialNumberHex: parsedSid.serialNumberHex }),
			digestAlgorithmOid,
			signatureAlgorithmOid,
			signatureHex: toHex(signature.value),
			signature: new Uint8Array(signature.value),
			hasSignedAttrs,
			...(signedAttrsElement === undefined
				? {}
				: {
						signedAttrsDer: new Uint8Array(
							signerDer.slice(
								signedAttrsElement.start - signedAttrsElement.headerLength,
								signedAttrsElement.end,
							),
						),
					}),
		});
	}
	return signers;
}

/** Unwraps the OCTET STRING inside the IMPLICIT [0] encapsulated content. */
function extractEncapsulatedContent(
	encapDer: Uint8Array,
	element: ReturnType<typeof readElement>,
): Uint8Array {
	if (element.tag !== 0xa0) {
		throw new Error('Unexpected encapsulated content tag');
	}
	const inner = readElement(encapDer, element.start);
	if (inner.tag !== 0x04) {
		throw new Error('Expected encapsulated OCTET STRING');
	}
	return inner.value;
}

/** Extracts issuer DER and serial number from an issuerAndSerialNumber SEQUENCE. */
function parseSignerIdentifier(der: Uint8Array): {
	readonly issuerDerHex?: string;
	readonly serialNumberHex?: string;
} {
	const top = readSequenceChildren(der);
	const issuer = top[0];
	const serial = top[1];
	if (issuer === undefined || serial === undefined) {
		return {};
	}
	return {
		issuerDerHex: toHex(der.slice(issuer.start - issuer.headerLength, issuer.end)),
		serialNumberHex: toHex(serial.value),
	};
}

/** Returns the nth child element inside a constructed ASN.1 element, or throws. */
function childAt(source: Uint8Array, parent: DerElement, index: number, label: string): DerElement {
	let offset = parent.start;
	let currentIndex = 0;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		if (currentIndex === index) {
			return child;
		}
		offset = child.end;
		currentIndex += 1;
	}
	throw new Error(`Missing ${label}`);
}

// ---------------------------------------------------------------------------
// CMS signed attributes verification (RFC 5652 Section 5.4)
// ---------------------------------------------------------------------------

/** Maps a digest algorithm OID to the WebCrypto hash name. */
function digestAlgorithmHash(digestAlgorithmOid: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
	switch (digestAlgorithmOid) {
		case OIDS.sha256:
			return 'SHA-256';
		case OIDS.sha384:
			return 'SHA-384';
		case OIDS.sha512:
			return 'SHA-512';
		default:
			throw new Error(`Unsupported digest algorithm OID: ${digestAlgorithmOid}`);
	}
}

/** Locates and returns the messageDigest OCTET STRING value from signedAttrs. */
function extractMessageDigest(signedAttrsDer: Uint8Array): Uint8Array | undefined {
	// signedAttrs is IMPLICIT [0] — parse children (each is a SEQUENCE of {OID, SET OF values})
	const outer = readElement(signedAttrsDer);
	for (const attr of childrenOf(signedAttrsDer, outer)) {
		const attrDer = signedAttrsDer.slice(attr.start - attr.headerLength, attr.end);
		const parts = readSequenceChildren(attrDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined) {
			continue;
		}
		if (decodeObjectIdentifier(oid.value) === OIDS.cmsMessageDigest) {
			// values is SET OF, first child is the OCTET STRING digest
			const digestElement = readElement(attrDer, values.start);
			if (digestElement.tag !== 0x04) {
				return undefined;
			}
			return digestElement.value;
		}
	}
	return undefined;
}

/** Replaces the IMPLICIT [0] tag (0xa0) with SET OF (0x31) per RFC 5652 Section 5.4. */
function retagSignedAttrsAsSet(signedAttrsDer: Uint8Array): Uint8Array {
	// Replace IMPLICIT [0] tag (0xa0) with SET OF tag (0x31) per RFC 5652 Section 5.4
	const copy = new Uint8Array(signedAttrsDer);
	copy[0] = 0x31;
	return copy;
}

/** Constant-time byte comparison to avoid timing side-channels in digest checks. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let diff = 0;
	for (let index = 0; index < a.length; index += 1) {
		diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
	}
	return diff === 0;
}

/** Verifies a signed-attributes flow: digest match + signature over re-tagged attrs. */
async function verifySignedAttrs(
	signerInfo: ParsedPkcs7SignerInfo,
	signer: ParsedCertificate,
	encapsulatedContent: Uint8Array,
): Promise<
	| { readonly ok: true }
	| ErrorResult<
			| 'signer_not_found'
			| 'signature_invalid'
			| 'message_digest_mismatch'
			| 'content_missing'
			| ParsePkcs7ErrorCode,
			Record<never, never>,
			VerifyPkcs7SignedDataFailure
	  >
> {
	if (signerInfo.signedAttrsDer === undefined) {
		return verifyPkcs7Failure('malformed', 'Missing signedAttrs DER');
	}
	// Step 1: Extract messageDigest attribute from signedAttrs
	const expectedDigest = extractMessageDigest(signerInfo.signedAttrsDer);
	if (expectedDigest === undefined) {
		return verifyPkcs7Failure('malformed', 'Missing messageDigest attribute in signedAttrs');
	}
	// Step 2: Compute digest of encapsulated content
	let actualDigest: Uint8Array;
	try {
		const hash = digestAlgorithmHash(signerInfo.digestAlgorithmOid);
		actualDigest = new Uint8Array(
			await getCrypto().subtle.digest(hash, toArrayBuffer(encapsulatedContent)),
		);
	} catch {
		return verifyPkcs7Failure('malformed', 'Unsupported digest algorithm in SignedData');
	}
	// Step 3: Compare digests (constant-time)
	if (!constantTimeEqual(actualDigest, expectedDigest)) {
		return verifyPkcs7Failure(
			'message_digest_mismatch',
			'Content digest does not match messageDigest attribute',
		);
	}
	// Step 4: Verify signature over re-tagged signedAttrs (0xa0 → 0x31 SET OF)
	const signedData = retagSignedAttrsAsSet(signerInfo.signedAttrsDer);
	let verified: boolean;
	try {
		verified = await verifySignedData(
			signerInfo.signatureAlgorithmOid,
			undefined,
			signer.publicKeyAlgorithmOid,
			signer.publicKeyParametersOid,
			signer.subjectPublicKeyInfoDer,
			signerInfo.signature,
			signedData,
		);
	} catch {
		return verifyPkcs7Failure('malformed', 'Unsupported signature algorithm in SignedData');
	}
	if (!verified) {
		return verifyPkcs7Failure(
			'signature_invalid',
			'SignedData signature over signedAttrs does not verify',
		);
	}
	return { ok: true };
}
