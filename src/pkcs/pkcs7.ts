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
	decodeString,
	hexToBytes,
	requireElement,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1.ts';
import type { DerElement } from '#micro509/internal/asn1/der.ts';
import {
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	integer,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	readRootElement,
	readSequenceChildren,
	sequence,
	setOf,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import {
	describeHashAlgorithm,
	describeSignatureAlgorithm,
} from '#micro509/internal/crypto/algorithm-names.ts';
import { verifySignedDataDetailed } from '#micro509/internal/crypto/sig-verify.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
	type SignatureAlgorithmIdentifier,
	type SignatureProfileInput,
	signBytes,
} from '#micro509/internal/crypto/signing.ts';
import { getCrypto } from '#micro509/internal/crypto/webcrypto.ts';
import { base64Encode } from '#micro509/internal/shared/base64.ts';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn.ts';
import { pemEncode, splitPemBlocks } from '#micro509/pem/pem.ts';
import type { ErrorResult, Micro509Error } from '#micro509/result/result.ts';
import { type NameFieldKey, nameFieldKeyFromOid } from '#micro509/x509/name.ts';
import type {
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse.ts';
import { parseCertificateDer } from '#micro509/x509/parse.ts';

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
	/** Parsed issuer distinguished name, if present (issuerAndSerialNumber signer identifier). */
	readonly issuer?: ParsedName;
	/** Hex-encoded serial number used to locate the signer certificate, if present. */
	readonly serialNumberHex?: string;
	/** Hex-encoded SubjectKeyIdentifier used to locate the signer certificate, if present. */
	readonly subjectKeyIdentifier?: string;
	/** OID of the digest algorithm used to hash the content. */
	readonly digestAlgorithmOid: string;
	/** Human-readable digest algorithm name (e.g. `"SHA-256"`). */
	readonly digestAlgorithmName: string;
	/** OID of the algorithm used to produce the signature. */
	readonly signatureAlgorithmOid: string;
	/** Human-readable signature algorithm name. */
	readonly signatureAlgorithmName: string;
	/** Raw DER of the signature AlgorithmIdentifier parameters, if present. */
	readonly signatureAlgorithmParametersDer?: Uint8Array;
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
	/** Original DER bytes when this object came from {@linkcode parsePkcs7SignedDataDer} or PEM parsing. */
	readonly der?: Uint8Array;
	/** Outer ContentInfo type OID (always `pkcs7-signedData`). */
	readonly contentTypeOid: string;
	/** SignedData version number. */
	readonly version: number;
	/** OIDs of digest algorithms declared in `digestAlgorithms`. */
	readonly digestAlgorithmOids: readonly string[];
	/** Human-readable digest algorithm names declared in `digestAlgorithms`. */
	readonly digestAlgorithmNames: readonly string[];
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
// createPkcs7SignedData
// ---------------------------------------------------------------------------

/** A single signer for {@linkcode createPkcs7SignedDataDer} / {@linkcode createPkcs7SignedDataPem}. */
export interface Pkcs7Signer {
	/**
	 * Signer certificate (PEM text with one CERTIFICATE block, or raw DER).
	 * Embedded in the SignedData certificate set and referenced by the
	 * SignerInfo via issuerAndSerialNumber.
	 */
	readonly certificate: Pkcs7CertificateSource;
	/** Private key matching the certificate's public key, used to sign. */
	readonly privateKey: CryptoKey;
	/**
	 * Signature profile. Defaults to inferring the algorithm from the key
	 * (e.g. ECDSA→ecdsa-with-SHA*, RSA→sha*WithRSAEncryption, Ed25519).
	 * Pass `{ kind: 'rsa-pss' }` to force RSA-PSS padding for an RSA-PSS key.
	 */
	readonly signature?: SignatureProfileInput;
}

/** Input for {@linkcode createPkcs7SignedDataDer} / {@linkcode createPkcs7SignedDataPem}. */
export interface CreatePkcs7SignedDataInput {
	/** Content to encapsulate and sign (the eContent). */
	readonly content: Uint8Array;
	/** One or more signers. Each produces a SignerInfo with signed attributes. */
	readonly signers: readonly Pkcs7Signer[];
	/**
	 * Additional certificates to embed (e.g. intermediates). Signer
	 * certificates are always embedded; duplicate DER is removed.
	 */
	readonly additionalCertificates?: readonly Pkcs7CertificateSource[];
	/**
	 * Encapsulated content type OID.
	 * @default `'1.2.840.113549.1.7.1'` (pkcs7-data)
	 */
	readonly encapsulatedContentTypeOid?: string;
}

/** DER, PEM, and base64 encodings of a PKCS#7 SignedData structure. */
export interface Pkcs7SignedDataMaterial {
	/** Raw DER-encoded PKCS#7 SignedData. */
	readonly der: Uint8Array;
	/** PEM-armored PKCS#7 (`-----BEGIN PKCS7-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armor). */
	readonly base64: string;
}

/** Caller-correctable failure codes from {@linkcode createPkcs7SignedDataDer} / {@linkcode createPkcs7SignedDataPem}. */
export type CreatePkcs7SignedDataErrorCode =
	| 'no_signers'
	| 'invalid_signer_certificate'
	| 'unsupported_signer_key';

/** Error payload for a failed PKCS#7 SignedData creation. */
export interface CreatePkcs7SignedDataFailure
	extends Micro509Error<CreatePkcs7SignedDataErrorCode> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/** Success-or-failure result from {@linkcode createPkcs7SignedDataDer}. */
export type CreatePkcs7SignedDataDerResult =
	| {
			/** Creation succeeded. */
			readonly ok: true;
			/** Raw DER-encoded SignedData. */
			readonly value: Uint8Array;
	  }
	| ErrorResult<CreatePkcs7SignedDataErrorCode, Record<never, never>, CreatePkcs7SignedDataFailure>;

/** Success-or-failure result from {@linkcode createPkcs7SignedDataPem}. */
export type CreatePkcs7SignedDataResult =
	| {
			/** Creation succeeded. */
			readonly ok: true;
			/** DER, PEM, and base64 forms of the SignedData. */
			readonly value: Pkcs7SignedDataMaterial;
	  }
	| ErrorResult<CreatePkcs7SignedDataErrorCode, Record<never, never>, CreatePkcs7SignedDataFailure>;

/**
 * Creates a PKCS#7/CMS SignedData with one or more signers over `content`.
 *
 * Each signer uses the RFC 5652 Section 5.4 signed-attributes flow: the
 * signature covers a `SET OF` authenticated attributes carrying `contentType`
 * and `messageDigest` (the digest of the encapsulated content). The content is
 * embedded (attached signature), so the result verifies with
 * {@linkcode verifyPkcs7SignedData} without any external data.
 *
 * The content digest is derived from each signer's key (P-256/RSA-SHA256 →
 * SHA-256, P-384 → SHA-384, P-521 → SHA-512, Ed25519 → SHA-512 per RFC 8419).
 *
 * Returns a {@linkcode CreatePkcs7SignedDataDerResult}: the raw DER on success,
 * or a typed failure for caller-correctable input (no signers, a signer source
 * that is not exactly one certificate, or an unsupported signer key). Use
 * {@linkcode createPkcs7SignedDataPem} for PEM + base64.
 */
export async function createPkcs7SignedDataDer(
	input: CreatePkcs7SignedDataInput,
): Promise<CreatePkcs7SignedDataDerResult> {
	if (input.signers.length === 0) {
		return createPkcs7Failure('no_signers', 'createPkcs7SignedData requires at least one signer');
	}
	const encapsulatedContentTypeOid = input.encapsulatedContentTypeOid ?? OIDS.pkcs7Data;

	// Snapshot the caller-owned content into a private copy before any await.
	// Every signer's messageDigest and the emitted eContent must derive from the
	// same bytes; reading input.content across awaits could otherwise observe a
	// caller mutation and yield a SignedData whose digest disagrees with its own
	// encapsulated content.
	const content = input.content.slice();

	const certificateDers: Uint8Array[] = [];
	const seenCertificates = new Set<string>();
	const addCertificate = (der: Uint8Array): void => {
		const hex = toHex(der);
		if (!seenCertificates.has(hex)) {
			seenCertificates.add(hex);
			certificateDers.push(der);
		}
	};

	const digestAlgorithmOids = new Set<string>();
	const signerInfos: Uint8Array[] = [];
	for (const signer of input.signers) {
		const signerCertDers = normalizeCertificateSource(signer.certificate);
		const signerCertDer = signerCertDers[0];
		if (signerCertDer === undefined || signerCertDers.length !== 1) {
			return createPkcs7Failure(
				'invalid_signer_certificate',
				'Each PKCS#7 signer must provide exactly one certificate',
			);
		}
		addCertificate(signerCertDer);
		// parseCertificateDer throws on malformed DER — a caller-correctable input,
		// so convert it to the typed invalid_signer_certificate failure rather than
		// rejecting the public Promise.
		let certificate: ParsedCertificate;
		try {
			certificate = parseCertificateDer(signerCertDer);
		} catch {
			return createPkcs7Failure(
				'invalid_signer_certificate',
				'Each PKCS#7 signer certificate must be a parseable X.509 certificate',
			);
		}
		// getSignatureAlgorithm throws only for unsupported/misconfigured keys —
		// all caller-correctable, so map to a typed failure rather than propagate.
		let signatureAlgorithm: SignatureAlgorithmIdentifier;
		try {
			signatureAlgorithm = getSignatureAlgorithm(signer.privateKey, signer.signature);
		} catch {
			return createPkcs7Failure(
				'unsupported_signer_key',
				'Unsupported signer key or signature profile',
			);
		}
		const digest = contentDigestForPrivateKey(signer.privateKey);
		if (digest === undefined) {
			return createPkcs7Failure(
				'unsupported_signer_key',
				'Unsupported signer key algorithm for content digest',
			);
		}
		digestAlgorithmOids.add(digest.digestOid);
		const messageDigest = new Uint8Array(
			await getCrypto().subtle.digest(digest.hashName, toArrayBuffer(content)),
		);
		const { setForSigning, implicitForEmit } = buildSignedAttributes(
			encapsulatedContentTypeOid,
			messageDigest,
		);
		const signature = await signBytes(signer.privateKey, signatureAlgorithm, setForSigning);
		signerInfos.push(
			sequence([
				integerFromNumber(1),
				sequence([
					hexToBytes(certificate.issuer.derHex),
					integer(hexToBytes(certificate.serialNumberHex)),
				]),
				sequence([objectIdentifier(digest.digestOid), nullValue()]),
				implicitForEmit,
				encodeAlgorithmIdentifier(signatureAlgorithm),
				octetString(signature),
			]),
		);
	}

	for (const source of input.additionalCertificates ?? []) {
		for (const der of normalizeCertificateSource(source)) {
			addCertificate(der);
		}
	}

	// SignedData version: 1 for id-data content, otherwise 3 (RFC 5652 Section 5.1).
	const signedDataVersion = encapsulatedContentTypeOid === OIDS.pkcs7Data ? 1 : 3;
	// certificates [0] IMPLICIT CertificateSet — a DER SET OF must be canonically
	// ordered, so sort via setOf, then retag 0x31 -> 0xa0 for the IMPLICIT [0].
	const certificateSet = new Uint8Array(setOf(certificateDers));
	certificateSet[0] = 0xa0;
	const signedData = sequence([
		integerFromNumber(signedDataVersion),
		setOf([...digestAlgorithmOids].map((oid) => sequence([objectIdentifier(oid), nullValue()]))),
		sequence([
			objectIdentifier(encapsulatedContentTypeOid),
			explicitContext(0, octetString(content)),
		]),
		certificateSet,
		setOf(signerInfos),
	]);
	return {
		ok: true,
		value: sequence([objectIdentifier(OIDS.pkcs7SignedData), explicitContext(0, signedData)]),
	};
}

/**
 * Creates a PKCS#7/CMS SignedData over `content` and returns DER, PEM, and
 * base64 forms, or a typed {@linkcode CreatePkcs7SignedDataFailure} for
 * caller-correctable input.
 */
export async function createPkcs7SignedDataPem(
	input: CreatePkcs7SignedDataInput,
): Promise<CreatePkcs7SignedDataResult> {
	const der = await createPkcs7SignedDataDer(input);
	if (!der.ok) {
		return der;
	}
	return {
		ok: true,
		value: { der: der.value, pem: pemEncode('PKCS7', der.value), base64: base64Encode(der.value) },
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
		if (
			contentType === undefined ||
			content === undefined ||
			contentInfo.length !== 2 ||
			contentType.tag !== 0x06 ||
			content.tag !== 0xa0
		) {
			return pkcs7Failure('malformed', 'Malformed PKCS#7 content info');
		}
		if (childrenOf(der, content).length !== 1) {
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
		const trailingChildren = signedDataChildren.slice(3);
		const signerInfos = trailingChildren[trailingChildren.length - 1];
		let certificates: ReturnType<typeof readElement> | undefined;
		let crls: ReturnType<typeof readElement> | undefined;
		for (const child of trailingChildren.slice(0, -1)) {
			if (child?.tag === 0xa0) {
				if (crls !== undefined) {
					return pkcs7Failure('malformed', 'SignedData certificates field must precede CRLs field');
				}
				if (certificates !== undefined) {
					return pkcs7Failure('malformed', 'SignedData certificates field must not repeat');
				}
				certificates = child;
				continue;
			}
			if (child?.tag === 0xa1) {
				if (crls !== undefined) {
					return pkcs7Failure('malformed', 'SignedData CRLs field must not repeat');
				}
				crls = child;
				continue;
			}
			return pkcs7Failure('malformed', 'Malformed SignedData optional field');
		}
		if (
			version === undefined ||
			digestAlgorithms === undefined ||
			encapContentInfo === undefined ||
			signerInfos === undefined ||
			signerInfos.tag !== 0x31
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
		const digestAlgorithmOids = parseDigestAlgorithms(der, digestAlgorithms);
		if (encapType === undefined) {
			return pkcs7Failure('malformed', 'Malformed EncapsulatedContentInfo');
		}
		return {
			ok: true,
			value: {
				der: new Uint8Array(der),
				contentTypeOid,
				version: decodeIntegerNumber(version.value),
				digestAlgorithmOids,
				digestAlgorithmNames: digestAlgorithmOids.map((oid) => describeHashAlgorithm(oid)),
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
		if (!hasReparseablePkcs7SignedData(input)) {
			return verifyPkcs7Failure('malformed', 'SignedData parsed input is malformed');
		}
		const result = parsePkcs7SignedDataDer(new Uint8Array(input.der));
		if (!result.ok) {
			return result;
		}
		parsed = result.value;
	}
	if (parsed.encapsulatedContent === undefined) {
		return verifyPkcs7Failure('content_missing', 'SignedData encapsulated content is missing');
	}
	for (const signerInfo of parsed.signerInfos) {
		const signer = parsed.certificates.find((certificate) =>
			signerIdentifierMatches(certificate, signerInfo),
		);
		if (signer === undefined) {
			return verifyPkcs7Failure(
				'signer_not_found',
				'Signer certificate not found in SignedData certificates',
			);
		}
		if (signerInfo.hasSignedAttrs) {
			const attrsResult = await verifySignedAttrs(
				signerInfo,
				signer,
				parsed.encapsulatedContent,
				parsed.encapsulatedContentTypeOid,
			);
			if (!attrsResult.ok) {
				return attrsResult;
			}
			continue;
		}
		let verified: boolean;
		try {
			const verificationResult = await verifySignedDataDetailed(
				signerInfo.signatureAlgorithmOid,
				signerInfo.signatureAlgorithmParametersDer,
				signer.publicKeyAlgorithmOid,
				signer.publicKeyParametersOid,
				signer.subjectPublicKeyInfoDer,
				signerInfo.signature,
				parsed.encapsulatedContent,
			);
			if (!verificationResult.ok) {
				if (verificationResult.code === 'verification_error') {
					return verifyPkcs7Failure('malformed', 'SignedData signature verification failed');
				}
				return verifyPkcs7Failure('malformed', 'Unsupported signature algorithm in SignedData');
			}
			verified = verificationResult.valid;
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

/** Shorthand for constructing a PKCS#7 SignedData creation failure result. */
function createPkcs7Failure(
	code: CreatePkcs7SignedDataErrorCode,
	message: string,
): ErrorResult<CreatePkcs7SignedDataErrorCode, Record<never, never>, CreatePkcs7SignedDataFailure> {
	const error: CreatePkcs7SignedDataFailure = { ok: false, code, message };
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

/** Type guard: key algorithm carries an RSA `hash`. */
function signerHasHash(algorithm: KeyAlgorithm): algorithm is RsaHashedKeyAlgorithm {
	return 'hash' in algorithm;
}

/** Type guard: key algorithm carries an EC `namedCurve`. */
function signerHasNamedCurve(algorithm: KeyAlgorithm): algorithm is EcKeyAlgorithm {
	return 'namedCurve' in algorithm;
}

/**
 * Resolves the content-digest hash and its OID for a signer key.
 *
 * Pairs each key with the digest used by its signature algorithm (RFC 5754):
 * P-256/RSA-SHA256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512. Ed25519 uses
 * SHA-512 for the messageDigest attribute, per RFC 8419.
 */
function contentDigestForPrivateKey(
	privateKey: CryptoKey,
):
	| { readonly hashName: 'SHA-256' | 'SHA-384' | 'SHA-512'; readonly digestOid: string }
	| undefined {
	const algorithm = privateKey.algorithm;
	if (algorithm.name === 'ECDSA') {
		if (!signerHasNamedCurve(algorithm)) {
			return undefined;
		}
		switch (algorithm.namedCurve) {
			case 'P-256':
				return { hashName: 'SHA-256', digestOid: OIDS.sha256 };
			case 'P-384':
				return { hashName: 'SHA-384', digestOid: OIDS.sha384 };
			case 'P-521':
				return { hashName: 'SHA-512', digestOid: OIDS.sha512 };
			default:
				return undefined;
		}
	}
	if (algorithm.name === 'RSASSA-PKCS1-v1_5' || algorithm.name === 'RSA-PSS') {
		if (!signerHasHash(algorithm)) {
			return undefined;
		}
		switch (algorithm.hash.name) {
			case 'SHA-256':
				return { hashName: 'SHA-256', digestOid: OIDS.sha256 };
			case 'SHA-384':
				return { hashName: 'SHA-384', digestOid: OIDS.sha384 };
			case 'SHA-512':
				return { hashName: 'SHA-512', digestOid: OIDS.sha512 };
			default:
				return undefined;
		}
	}
	if (algorithm.name === 'Ed25519') {
		return { hashName: 'SHA-512', digestOid: OIDS.sha512 };
	}
	return undefined;
}

/**
 * Builds CMS signed attributes (contentType + messageDigest) in two forms:
 * `setForSigning` (SET OF, tag 0x31) is what the signature covers per RFC 5652
 * Section 5.4; `implicitForEmit` (IMPLICIT [0], tag 0xa0) is what goes in the
 * SignerInfo. The two differ only in the leading tag byte.
 */
function buildSignedAttributes(
	contentTypeOid: string,
	messageDigest: Uint8Array,
): { readonly setForSigning: Uint8Array; readonly implicitForEmit: Uint8Array } {
	const setForSigning = setOf([
		sequence([objectIdentifier(OIDS.cmsContentType), setOf([objectIdentifier(contentTypeOid)])]),
		sequence([objectIdentifier(OIDS.cmsMessageDigest), setOf([octetString(messageDigest)])]),
	]);
	const implicitForEmit = new Uint8Array(setForSigning);
	implicitForEmit[0] = 0xa0;
	return { setForSigning, implicitForEmit };
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
	if (element.tag !== 0x31) {
		throw new Error('digestAlgorithms must use SET');
	}
	for (const child of childrenOf(source, element)) {
		if (child.tag !== 0x30) {
			throw new Error('digestAlgorithm must use AlgorithmIdentifier SEQUENCE');
		}
		const childDer = source.slice(child.start - child.headerLength, child.end);
		const parts = readSequenceChildren(childDer);
		const oid = parts[0];
		if (oid === undefined || parts.length < 1 || parts.length > 2 || oid.tag !== 0x06) {
			throw new Error('Malformed digest AlgorithmIdentifier');
		}
		digests.push(decodeObjectIdentifier(oid.value));
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
		const unauthenticatedAttributes = parts[index + 2];
		if (
			version === undefined ||
			sid === undefined ||
			digestAlgorithm === undefined ||
			signatureAlgorithm === undefined ||
			signature === undefined ||
			signature.tag !== 0x04 ||
			parts.length > index + 3 ||
			(unauthenticatedAttributes !== undefined && unauthenticatedAttributes.tag !== 0xa1)
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
		const signatureAlgorithmChildren = readSequenceChildren(signatureAlgorithmDer);
		const signatureAlgorithmOid = decodeObjectIdentifier(
			requireElement(signatureAlgorithmChildren[0], 'signature algorithm OID').value,
		);
		const signatureAlgorithmParams = signatureAlgorithmChildren[1];
		const parsedSid = parseSignerIdentifier(signerDer.slice(sid.start - sid.headerLength, sid.end));
		signers.push({
			version: decodeIntegerNumber(version.value),
			...(parsedSid.issuer === undefined ? {} : { issuer: parsedSid.issuer }),
			...(parsedSid.serialNumberHex === undefined
				? {}
				: { serialNumberHex: parsedSid.serialNumberHex }),
			...(parsedSid.subjectKeyIdentifier === undefined
				? {}
				: { subjectKeyIdentifier: parsedSid.subjectKeyIdentifier }),
			digestAlgorithmOid,
			digestAlgorithmName: describeHashAlgorithm(digestAlgorithmOid),
			signatureAlgorithmOid,
			signatureAlgorithmName: describeSignatureAlgorithm(
				signatureAlgorithmOid,
				signatureAlgorithmParams === undefined
					? undefined
					: new Uint8Array(
							signatureAlgorithmDer.slice(
								signatureAlgorithmParams.start - signatureAlgorithmParams.headerLength,
								signatureAlgorithmParams.end,
							),
						),
			),
			...(signatureAlgorithmParams === undefined
				? {}
				: {
						signatureAlgorithmParametersDer: new Uint8Array(
							signatureAlgorithmDer.slice(
								signatureAlgorithmParams.start - signatureAlgorithmParams.headerLength,
								signatureAlgorithmParams.end,
							),
						),
					}),
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

/** Extracts issuer Name and serial number from an issuerAndSerialNumber SEQUENCE, or subjectKeyIdentifier from [0] IMPLICIT. */
function parseSignerIdentifier(der: Uint8Array): {
	readonly issuer?: ParsedName;
	readonly serialNumberHex?: string;
	readonly subjectKeyIdentifier?: string;
} {
	const element = readRootElement(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	// [0] IMPLICIT SubjectKeyIdentifier
	if (element.tag === 0x80) {
		if (element.value.length === 0) {
			throw new Error('SignerIdentifier subjectKeyIdentifier must not be empty');
		}
		return {
			subjectKeyIdentifier: toHex(element.value),
		};
	}
	// SEQUENCE { issuer Name, serialNumber INTEGER }
	if (element.tag === 0x30) {
		const top = readSequenceChildren(der);
		const issuerElement = top[0];
		const serial = top[1];
		if (issuerElement === undefined || serial === undefined || top.length !== 2) {
			throw new Error('SignerIdentifier issuerAndSerialNumber is malformed');
		}
		if (issuerElement.tag !== 0x30) {
			throw new Error('SignerIdentifier issuer must use Name SEQUENCE');
		}
		if (serial.tag !== 0x02) {
			throw new Error('SignerIdentifier serialNumber must use INTEGER');
		}
		assertImplicitSerialNumberEncoding(serial.value, 'SignerIdentifier serialNumber');
		return {
			issuer: parseSignerIssuerName(der, issuerElement),
			serialNumberHex: toHex(serial.value),
		};
	}
	throw new Error(`Unsupported SignerIdentifier tag: ${String(element.tag)}`);
}

const textDecoder = new TextDecoder();

/** Parses a Name SEQUENCE element from a PKCS#7 signer identifier into a {@linkcode ParsedName}. */
function parseSignerIssuerName(source: Uint8Array, element: DerElement): ParsedName {
	const derHex = toHex(source.slice(element.start - element.headerLength, element.end));
	const rdns: ParsedRelativeDistinguishedName[] = [];
	const allAttributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const setElement of childrenOf(source, element)) {
		const rdnAttributes: ParsedNameAttribute[] = [];
		const rdnValues: Partial<Record<NameFieldKey, string>> = {};
		for (const attrSequence of childrenOf(source, setElement)) {
			const parts = childrenOf(source, attrSequence);
			const oidElement = requireElement(parts[0], 'signer issuer attribute OID');
			const valueElement = requireElement(parts[1], 'signer issuer attribute value');
			const oid = decodeObjectIdentifier(oidElement.value);
			let fieldValue: string;
			try {
				fieldValue = decodeString(valueElement.tag, valueElement.value);
			} catch {
				fieldValue = textDecoder.decode(valueElement.value);
			}
			const fieldKey = nameFieldKeyFromOid(oid);
			const attribute: ParsedNameAttribute =
				fieldKey !== undefined
					? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
					: { oid, valueTag: valueElement.tag, value: fieldValue };
			rdnAttributes.push(attribute);
			allAttributes.push(attribute);
			if (fieldKey !== undefined) {
				if (rdnValues[fieldKey] === undefined) {
					rdnValues[fieldKey] = fieldValue;
				}
				if (values[fieldKey] === undefined) {
					values[fieldKey] = fieldValue;
				}
			}
		}
		rdns.push({
			derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
			attributes: rdnAttributes,
			values: rdnValues,
		});
	}
	return { derHex, rdns, attributes: allAttributes, values };
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

/** Parses required signed attributes and enforces uniqueness + exact-one-value shape. */
function parseSignedAttributeRequirements(signedAttrsDer: Uint8Array): {
	readonly messageDigest: Uint8Array;
	readonly contentTypeOid: string;
} {
	const outer = readElement(signedAttrsDer);
	let messageDigest: Uint8Array | undefined;
	let contentTypeOid: string | undefined;
	for (const attr of childrenOf(signedAttrsDer, outer)) {
		const attrDer = signedAttrsDer.slice(attr.start - attr.headerLength, attr.end);
		const parts = readSequenceChildren(attrDer);
		const oid = parts[0];
		const values = parts[1];
		if (oid === undefined || values === undefined || parts.length !== 2 || values.tag !== 0x31) {
			throw new Error('Malformed signedAttrs attribute');
		}
		const attrOid = decodeObjectIdentifier(oid.value);
		const valueElements = childrenOf(attrDer, values);
		if (attrOid === OIDS.cmsMessageDigest) {
			if (messageDigest !== undefined || valueElements.length !== 1) {
				throw new Error('messageDigest attribute must appear exactly once with one value');
			}
			const digestElement = valueElements[0];
			if (digestElement === undefined || digestElement.tag !== 0x04) {
				throw new Error('messageDigest attribute value must use OCTET STRING');
			}
			messageDigest = digestElement.value;
			continue;
		}
		if (attrOid === OIDS.cmsContentType) {
			if (contentTypeOid !== undefined || valueElements.length !== 1) {
				throw new Error('contentType attribute must appear exactly once with one value');
			}
			const contentType = valueElements[0];
			if (contentType === undefined || contentType.tag !== 0x06) {
				throw new Error('contentType attribute value must use OBJECT IDENTIFIER');
			}
			contentTypeOid = decodeObjectIdentifier(contentType.value);
		}
	}
	if (messageDigest === undefined) {
		throw new Error('Missing messageDigest attribute in signedAttrs');
	}
	if (contentTypeOid === undefined) {
		throw new Error('Missing contentType attribute in signedAttrs');
	}
	return { messageDigest, contentTypeOid };
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
	encapsulatedContentTypeOid: string,
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
	// Step 1: Parse required signed attributes from signedAttrs
	let signedAttributes: { readonly messageDigest: Uint8Array; readonly contentTypeOid: string };
	try {
		assertImplicitSignedAttrsDer(signerInfo.signedAttrsDer);
		signedAttributes = parseSignedAttributeRequirements(signerInfo.signedAttrsDer);
	} catch {
		return verifyPkcs7Failure('malformed', 'Malformed signedAttrs in SignedData');
	}
	if (signedAttributes.contentTypeOid !== encapsulatedContentTypeOid) {
		return verifyPkcs7Failure('malformed', 'SignedData contentType attribute does not match');
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
	if (!constantTimeEqual(actualDigest, signedAttributes.messageDigest)) {
		return verifyPkcs7Failure(
			'message_digest_mismatch',
			'Content digest does not match messageDigest attribute',
		);
	}
	// Step 4: Verify signature over re-tagged signedAttrs (0xa0 → 0x31 SET OF)
	let signedData: Uint8Array;
	try {
		signedData = retagSignedAttrsAsSet(signerInfo.signedAttrsDer);
	} catch {
		return verifyPkcs7Failure('malformed', 'Malformed signedAttrs in SignedData');
	}
	let verified: boolean;
	try {
		const verificationResult = await verifySignedDataDetailed(
			signerInfo.signatureAlgorithmOid,
			signerInfo.signatureAlgorithmParametersDer,
			signer.publicKeyAlgorithmOid,
			signer.publicKeyParametersOid,
			signer.subjectPublicKeyInfoDer,
			signerInfo.signature,
			signedData,
		);
		if (!verificationResult.ok) {
			if (verificationResult.code === 'verification_error') {
				return verifyPkcs7Failure('malformed', 'SignedData signature verification failed');
			}
			return verifyPkcs7Failure('malformed', 'Unsupported signature algorithm in SignedData');
		}
		verified = verificationResult.valid;
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

function signerIdentifierMatches(
	certificate: ParsedCertificate,
	signerInfo: ParsedPkcs7SignerInfo,
): boolean {
	if (signerInfo.issuer !== undefined || signerInfo.serialNumberHex !== undefined) {
		return (
			signerInfo.issuer !== undefined &&
			signerInfo.serialNumberHex !== undefined &&
			certificate.serialNumberHex === signerInfo.serialNumberHex &&
			compareDistinguishedNames(certificate.issuer, signerInfo.issuer)
		);
	}
	return (
		signerInfo.subjectKeyIdentifier !== undefined &&
		certificate.subjectKeyIdentifier === signerInfo.subjectKeyIdentifier
	);
}

function assertImplicitSignedAttrsDer(signedAttrsDer: Uint8Array): void {
	if (readElement(signedAttrsDer).tag !== 0xa0) {
		throw new Error('signedAttrs must use IMPLICIT [0] tag');
	}
}

function hasReparseablePkcs7SignedData(
	value: ParsedPkcs7SignedData,
): value is ParsedPkcs7SignedData & { readonly der: Uint8Array } {
	return 'der' in value && value.der instanceof Uint8Array;
}

function assertImplicitSerialNumberEncoding(bytes: Uint8Array, label: string): void {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error(`${label} must not be empty`);
	}
	if ((first & 0x80) !== 0) {
		throw new Error(`${label} must be non-negative`);
	}
	if (bytes.length > 1 && first === 0 && ((bytes[1] ?? 0) & 0x80) === 0) {
		throw new Error(`${label} must use minimal encoding`);
	}
}
