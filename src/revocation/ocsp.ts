/**
 * Full OCSP lifecycle: build requests, create/parse/verify/validate responses.
 *
 * Supports SHA-1 and SHA-256 cert-ID hashing, nonce replay protection,
 * delegated responder certificate validation (direct and chain-based),
 * and embedded responder certificate discovery.
 *
 * @module
 */

import {
	childrenOf,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	hexToBytes,
	parseTime,
	requireElement,
	toArrayBuffer,
	toHex,
} from '#micro509/internal/asn1/asn1.ts';
import type { DerElement } from '#micro509/internal/asn1/der.ts';
import {
	bitString,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	implicitPrimitiveContext,
	integer,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	readRootElement,
	readSequenceChildren,
	sequence,
	time,
	tlv,
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
	signBytes,
} from '#micro509/internal/crypto/signing.ts';
import { getCrypto } from '#micro509/internal/crypto/webcrypto.ts';
import { base64Encode } from '#micro509/internal/shared/base64.ts';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn.ts';
import { pemDecode, pemEncode } from '#micro509/pem/pem.ts';
import type { ErrorResult, Micro509Error } from '#micro509/result/result.ts';
import { verifyCertificateChain } from '#micro509/verify/verify.ts';
import type {
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from '#micro509/x509/parse.ts';
import { parseCertificateDer, parseCertificateFromSource } from '#micro509/x509/parse.ts';

/** Hash algorithm used to compute OCSP CertID fields. SHA-1 is the RFC 6960 default. */
export type OcspHashAlgorithm = 'SHA-1' | 'SHA-256';
/** PEM string, DER bytes, or already-parsed certificate. */
export type OcspCertificateSource = string | Uint8Array | ParsedCertificate;
/** PEM string, DER bytes, or already-parsed OCSP request. */
export type OcspRequestSource = string | Uint8Array | ParsedOcspRequest;

/**
 * One certificate whose status to query in an OCSP request.
 * Used as an element of {@linkcode CreateOcspRequestInput.requests}.
 */
export interface CreateOcspRequestItemInput {
	/** Certificate whose revocation status is being queried. */
	readonly certificate: OcspCertificateSource;
	/** Issuer of `certificate` — needed to compute the CertID hash. */
	readonly issuerCertificate: OcspCertificateSource;
}

/**
 * Input for {@linkcode createOcspRequest}.
 */
export interface CreateOcspRequestInput {
	/** One or more certificates to query (batched into a single OCSP request). */
	readonly requests: readonly CreateOcspRequestItemInput[];
	/** Hash algorithm for CertID computation. Defaults to `'SHA-1'`. */
	readonly hashAlgorithm?: OcspHashAlgorithm;
	/** Random nonce for replay protection. Omit to skip the nonce extension. */
	readonly nonce?: Uint8Array;
}

/**
 * Encoded OCSP request in multiple serialisation formats, returned by {@linkcode createOcspRequest}.
 */
export interface OcspRequestMaterial {
	/** Raw DER bytes. */
	readonly der: Uint8Array;
	/** PEM-encoded request (`-----BEGIN OCSP REQUEST-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armour). */
	readonly base64: string;
}

/**
 * Decoded OCSP CertID — identifies a certificate by hashed issuer name,
 * hashed issuer key, and serial number.
 */
export interface ParsedOcspCertId {
	/** OID of the hash algorithm used for the name and key hashes. */
	readonly hashAlgorithmOid: string;
	/** Human-readable hash algorithm name (e.g. `"SHA-256"`). */
	readonly hashAlgorithmName: string;
	/** Hex-encoded hash of the issuer's distinguished name DER. */
	readonly issuerNameHashHex: string;
	/** Hex-encoded hash of the issuer's SubjectPublicKey BIT STRING content. */
	readonly issuerKeyHashHex: string;
	/** Hex-encoded serial number of the certificate. */
	readonly serialNumberHex: string;
}

/**
 * Decoded OCSP request, returned by {@linkcode parseOcspRequestDer} / {@linkcode parseOcspRequestPem}.
 */
export interface ParsedOcspRequest {
	/** Original DER bytes when this object came from {@linkcode parseOcspRequestDer} or PEM parsing. */
	readonly der?: Uint8Array;
	/** CertIDs of the certificates being queried. */
	readonly requests: readonly ParsedOcspCertId[];
	/** Hex-encoded nonce extension value, if present. */
	readonly nonce?: string;
}

/** RFC 6960 certificate status reported by the responder for a single CertID. */
export type OcspCertStatus = 'good' | 'revoked' | 'unknown';
/** RFC 6960 overall response status — anything other than `'successful'` means the response body is absent or unusable. */
export type OcspResponseStatus =
	| 'successful'
	| 'malformedRequest'
	| 'internalError'
	| 'tryLater'
	| 'sigRequired'
	| 'unauthorized';

/**
 * Status of one certificate inside an OCSP BasicResponse.
 */
export interface ParsedOcspSingleResponse {
	/** Which certificate this status applies to. */
	readonly certId: ParsedOcspCertId;
	/** Responder's verdict: `good`, `revoked`, or `unknown`. */
	readonly certStatus: OcspCertStatus;
	/** Start of the validity window for this status assertion. */
	readonly thisUpdate: Date;
	/** End of the validity window. Absent if the responder does not commit to a schedule. */
	readonly nextUpdate?: Date;
	/** When the certificate was revoked (only for `certStatus === 'revoked'`). */
	readonly revokedAt?: Date;
	/** CRLReason integer (only for `certStatus === 'revoked'`). */
	readonly revocationReasonCode?: number;
}

/**
 * How the OCSP responder identifies itself — either by distinguished name or
 * by SHA-1 hash of its public key.
 */
export type ParsedOcspResponderId =
	| {
			/** Responder identified by its certificate subject name. */
			readonly type: 'byName';
			/** Parsed distinguished name of the responder. */
			readonly name: ParsedName;
	  }
	| {
			/** Responder identified by public-key hash. */
			readonly type: 'byKeyHash';
			/** Hex-encoded SHA-1 hash of the responder's SubjectPublicKey content. */
			readonly keyHashHex: string;
	  };

/**
 * Decoded OCSP response, returned by {@linkcode parseOcspResponseDer} / {@linkcode parseOcspResponsePem}.
 *
 * When `responseStatus` is not `'successful'`, most fields are absent.
 */
export interface ParsedOcspResponse {
	/** Original DER bytes when this object came from {@linkcode parseOcspResponseDer} or PEM parsing. */
	readonly der?: Uint8Array;
	/** Overall response status. Only `'successful'` carries a BasicOCSPResponse body. */
	readonly responseStatus: OcspResponseStatus;
	/** OID of the response type (normally `id-pkix-ocsp-basic`). */
	readonly responseTypeOid?: string;
	/** DER-encoded ResponseData — the signed payload for signature verification. */
	readonly responseDataDer?: Uint8Array;
	/** How the responder identifies itself. */
	readonly responderId?: ParsedOcspResponderId;
	/** OID of the algorithm used to sign this response. */
	readonly signatureAlgorithmOid?: string;
	/** Human-readable signature algorithm name. */
	readonly signatureAlgorithmName?: string;
	/** Raw signature bytes. */
	readonly signatureValue?: Uint8Array;
	/** Timestamp when the responder produced this response. */
	readonly producedAt?: Date;
	/** Per-certificate status entries. */
	readonly responses?: readonly ParsedOcspSingleResponse[];
	/** Hex-encoded nonce, if the response echoed one. */
	readonly nonce?: string;
	/** Certificates embedded in the response (typically the responder's chain). */
	readonly certificates?: readonly ParsedCertificate[];
}

/**
 * One certificate's status entry for {@linkcode CreateOcspResponseInput.responses}.
 * Extends {@linkcode CreateOcspRequestItemInput} with status and timing fields.
 */
export interface CreateOcspSingleResponseInput extends CreateOcspRequestItemInput {
	/** Status to assert for this certificate. */
	readonly certStatus: OcspCertStatus;
	/** Start of the validity window for this status assertion. Defaults to `new Date()`. */
	readonly thisUpdate?: Date;
	/** End of the validity window. Omit for open-ended assertions. */
	readonly nextUpdate?: Date;
	/** Revocation time (required when `certStatus` is `'revoked'`). Defaults to `thisUpdate`. */
	readonly revokedAt?: Date;
	/** CRLReason integer code (only meaningful when `certStatus` is `'revoked'`). */
	readonly revocationReasonCode?: number;
}

/**
 * Input for {@linkcode createOcspResponse}.
 */
export interface CreateOcspResponseInput {
	/** Private key used to sign the response. Algorithm is inferred from the key. */
	readonly signerPrivateKey: CryptoKey;
	/** Certificate of the OCSP responder — used to build the responder ID (by key hash). */
	readonly signerCertificate: OcspCertificateSource;
	/** Per-certificate status entries to include in the BasicOCSPResponse. */
	readonly responses: readonly CreateOcspSingleResponseInput[];
	/** Timestamp for the `producedAt` field. Defaults to `new Date()`. */
	readonly producedAt?: Date;
	/** Nonce to echo back for replay protection. */
	readonly nonce?: Uint8Array;
	/** Hash algorithm for CertID computation. Defaults to `'SHA-1'`. */
	readonly hashAlgorithm?: OcspHashAlgorithm;
	/** Extra certificates to embed in the response (e.g. the responder's issuer chain). */
	readonly includedCertificates?: readonly OcspCertificateSource[];
}

/**
 * Encoded OCSP response in multiple serialisation formats, returned by {@linkcode createOcspResponse}.
 */
export interface OcspResponseMaterial {
	/** Raw DER bytes. */
	readonly der: Uint8Array;
	/** PEM-encoded response (`-----BEGIN OCSP RESPONSE-----`). */
	readonly pem: string;
	/** Base64-encoded DER (no PEM armour). */
	readonly base64: string;
}

/** Failure detail when OCSP response signature verification fails. */
export interface VerifyOcspResponseFailure extends Micro509Error<'signature_invalid'> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Result of {@linkcode verifyOcspResponse}.
 *
 * On success, `value` is the parsed response whose signature has been verified.
 */
export type VerifyOcspResponseResult =
	| {
			readonly ok: true;
			/** Parsed response with a verified signature. */
			readonly value: ParsedOcspResponse;
	  }
	| ErrorResult<'signature_invalid', Record<never, never>, VerifyOcspResponseFailure>;

/**
 * Input for {@linkcode validateOcspResponse}.
 */
export interface ValidateOcspResponseInput {
	/** The OCSP response to validate. */
	readonly response: string | Uint8Array | ParsedOcspResponse;
	/** Certificate of the CA that issued the target certificate. */
	readonly issuerCertificate: OcspCertificateSource;
	/** Original request — enables nonce and request-coverage checks. */
	readonly request?: OcspRequestSource;
	/** Explicit responder certificate — overrides embedded certificate discovery. */
	readonly responderCertificate?: OcspCertificateSource;
	/** When `true`, allows delegated responder chain validation beyond direct issuance. */
	readonly allowChainedResponderCertificate?: boolean;
	/** Evaluation time for freshness checks. Defaults to `new Date()`. */
	readonly at?: Date;
	/** Clock-skew tolerance in milliseconds for `thisUpdate`/`nextUpdate`/`producedAt`. */
	readonly clockSkewMs?: number;
}

/**
 * Failure detail for {@linkcode validateOcspResponse}.
 *
 * Possible codes: `response_status_invalid`, `signature_invalid`,
 * `responder_id_mismatch`, `nonce_mismatch`, `request_mismatch`,
 * `issuer_mismatch`, `responder_chain_invalid`, `ocsp_signing_missing`,
 * `stale_response`.
 */
export interface ValidateOcspResponseFailure
	extends Micro509Error<
		| 'response_status_invalid'
		| 'signature_invalid'
		| 'responder_id_mismatch'
		| 'nonce_mismatch'
		| 'request_mismatch'
		| 'issuer_mismatch'
		| 'responder_chain_invalid'
		| 'ocsp_signing_missing'
		| 'stale_response'
	> {
	/** Always `false` for failures. */
	readonly ok: false;
}

/**
 * Result of {@linkcode validateOcspResponse}.
 *
 * On success, the response has passed status, signature, responder binding,
 * freshness, nonce, and request-coverage checks.
 */
export type ValidateOcspResponseResult =
	| {
			readonly ok: true;
			/** Fully validated OCSP response. */
			readonly value: ParsedOcspResponse;
	  }
	| ErrorResult<
			| 'response_status_invalid'
			| 'signature_invalid'
			| 'responder_id_mismatch'
			| 'nonce_mismatch'
			| 'request_mismatch'
			| 'issuer_mismatch'
			| 'responder_chain_invalid'
			| 'ocsp_signing_missing'
			| 'stale_response',
			Record<never, never>,
			ValidateOcspResponseFailure
	  >;

/**
 * Builds a DER-encoded OCSP request containing one or more CertID entries
 * and an optional nonce extension.
 *
 * @example
 * ```ts
 * import { createOcspRequest } from 'micro509';
 *
 * const req = await createOcspRequest({
 *   requests: [{ certificate: leafPem, issuerCertificate: caPem }],
 *   hashAlgorithm: 'SHA-256',
 *   nonce: crypto.getRandomValues(new Uint8Array(16)),
 * });
 * // POST req.der to the OCSP responder URI
 * ```
 */
export async function createOcspRequest(
	input: CreateOcspRequestInput,
): Promise<OcspRequestMaterial> {
	const hashAlgorithm = input.hashAlgorithm ?? 'SHA-1';
	const requestEntries: Uint8Array[] = [];
	for (const request of input.requests) {
		const certificate = await normalizeCertificate(request.certificate);
		const issuer = await normalizeCertificate(request.issuerCertificate);
		requestEntries.push(sequence([await encodeOcspCertId(certificate, issuer, hashAlgorithm)]));
	}
	const tbsRequestFields: Uint8Array[] = [sequence(requestEntries)];
	if (input.nonce !== undefined) {
		tbsRequestFields.push(
			explicitContext(
				2,
				sequence([
					sequence([objectIdentifier(OIDS.ocspNonce), octetString(octetString(input.nonce))]),
				]),
			),
		);
	}
	const der = sequence([sequence(tbsRequestFields)]);
	return {
		der,
		pem: pemEncode('OCSP REQUEST', der),
		base64: base64Encode(der),
	};
}

/** Decodes a DER-encoded OCSP request into a structured {@linkcode ParsedOcspRequest}. */
export function parseOcspRequestDer(der: Uint8Array): ParsedOcspRequest {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (top.length < 1 || top.length > 2) {
		throw new Error('Malformed OCSP request');
	}
	const tbsRequest = requireElement(top[0], 'tbsRequest');
	const optionalSignature = top[1];
	if (optionalSignature !== undefined && optionalSignature.tag !== 0xa0) {
		throw new Error('Malformed OCSP request');
	}
	const tbsChildren = childrenOf(der, tbsRequest);
	let cursor = 0;
	if (tbsChildren[cursor]?.tag === 0xa0) {
		const versionWrapper = requireElement(tbsChildren[cursor], 'version');
		const versionFields = childrenOf(der, versionWrapper);
		const versionElement = requireElement(versionFields[0], 'version');
		if (versionFields.length !== 1 || versionElement.tag !== 0x02) {
			throw new Error('version must use INTEGER');
		}
		if (decodeNonNegativeIntegerNumber(versionElement.value, 'OCSP request version') !== 0) {
			throw new Error('Unsupported OCSP request version');
		}
		cursor += 1;
	}
	if (tbsChildren[cursor]?.tag === 0xa1) {
		cursor += 1;
	}
	const requestList = requireElement(tbsChildren[cursor], 'requestList');
	if (requestList.tag !== 0x30) {
		throw new Error('requestList must use SEQUENCE');
	}
	if (childrenOf(der, requestList).length === 0) {
		throw new Error('requestList must not be empty');
	}
	const requests = childrenOf(der, requestList).map((request) => {
		const requestChildren = childrenOf(der, request);
		if (requestChildren.length < 1 || requestChildren.length > 2) {
			throw new Error('Malformed OCSP request entry');
		}
		if (requestChildren[1] !== undefined && requestChildren[1].tag !== 0xa0) {
			throw new Error('Malformed OCSP request entry');
		}
		const certId = requireElement(requestChildren[0], 'reqCert');
		return parseOcspCertId(der.slice(certId.start - certId.headerLength, certId.end));
	});
	cursor += 1;
	const extensions = tbsChildren[cursor];
	if (extensions !== undefined && extensions.tag !== 0xa2) {
		throw new Error('Malformed OCSP request');
	}
	if (tbsChildren.length !== cursor + (extensions === undefined ? 0 : 1)) {
		throw new Error('Malformed OCSP request');
	}
	const nonce =
		extensions === undefined ? undefined : parseOcspNonceFromExtensions(der, extensions);
	return {
		der: new Uint8Array(der),
		requests,
		...(nonce === undefined ? {} : { nonce }),
	};
}

/** Decodes a PEM-encoded OCSP request (`-----BEGIN OCSP REQUEST-----`). */
export function parseOcspRequestPem(pem: string): ParsedOcspRequest {
	return parseOcspRequestDer(pemDecode('OCSP REQUEST', pem));
}

/** Decodes a DER-encoded OCSP response into a structured {@linkcode ParsedOcspResponse}. Does not verify the signature. */
export function parseOcspResponseDer(der: Uint8Array): ParsedOcspResponse {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (top.length < 1 || top.length > 2) {
		throw new Error('Malformed OCSP response');
	}
	const statusElement = requireElement(top[0], 'responseStatus');
	if (statusElement.tag !== 0x0a) {
		throw new Error('responseStatus must use ENUMERATED');
	}
	const responseStatus = ocspResponseStatusFromCode(
		decodeNonNegativeIntegerNumber(statusElement.value, 'OCSP responseStatus'),
	);
	const responseBytes = top[1];
	if (responseBytes === undefined) {
		return { der: new Uint8Array(der), responseStatus };
	}
	if (responseBytes.tag !== 0xa0) {
		throw new Error('Malformed OCSP response');
	}
	const responseBytesWrapper = childrenOf(der, responseBytes);
	const bytesSequence = requireElement(responseBytesWrapper[0], 'responseBytes');
	if (responseBytesWrapper.length !== 1 || bytesSequence.tag !== 0x30) {
		throw new Error('Malformed OCSP response');
	}
	const responseBytesChildren = childrenOf(der, bytesSequence);
	if (responseBytesChildren.length !== 2) {
		throw new Error('Malformed OCSP response');
	}
	const responseType = requireElement(responseBytesChildren[0], 'responseType');
	const response = requireElement(responseBytesChildren[1], 'response');
	if (response.tag !== 0x04) {
		throw new Error('response must use OCTET STRING');
	}
	const responseTypeOid = decodeObjectIdentifier(responseType.value);
	if (responseTypeOid !== OIDS.ocspBasicResponse) {
		return { der: new Uint8Array(der), responseStatus, responseTypeOid };
	}
	const basicResponse = response.value;
	const basicChildren = readSequenceChildren(basicResponse);
	if (basicChildren.length < 3 || basicChildren.length > 4) {
		throw new Error('Malformed BasicOCSPResponse');
	}
	const responseData = requireElement(basicChildren[0], 'responseData');
	const signatureAlgorithm = requireElement(basicChildren[1], 'signatureAlgorithm');
	const signatureValue = requireElement(basicChildren[2], 'signatureValue');
	const certificatesElement = basicChildren[3];
	if (certificatesElement !== undefined && certificatesElement.tag !== 0xa0) {
		throw new Error('Malformed BasicOCSPResponse');
	}
	const signatureAlgorithmChildren = childrenOf(basicResponse, signatureAlgorithm);
	const signatureAlgorithmOid = decodeObjectIdentifier(
		requireElement(signatureAlgorithmChildren[0], 'signatureAlgorithm OID').value,
	);
	const signatureAlgorithmParameters = signatureAlgorithmChildren[1];
	const responseDataDer = basicResponse.slice(
		responseData.start - responseData.headerLength,
		responseData.end,
	);
	const signedResponseData = parseSignedOcspResponseData(responseDataDer);
	return {
		der: new Uint8Array(der),
		responseStatus,
		responseTypeOid,
		responseDataDer,
		responderId: signedResponseData.responderId,
		signatureAlgorithmOid,
		signatureAlgorithmName: describeSignatureAlgorithm(
			signatureAlgorithmOid,
			signatureAlgorithmParameters === undefined
				? undefined
				: basicResponse.slice(
						signatureAlgorithmParameters.start - signatureAlgorithmParameters.headerLength,
						signatureAlgorithmParameters.end,
					),
		),
		signatureValue: extractBitStringValue(signatureValue),
		producedAt: signedResponseData.producedAt,
		responses: signedResponseData.responses,
		...(signedResponseData.nonce === undefined ? {} : { nonce: signedResponseData.nonce }),
		...(certificatesElement?.tag === 0xa0
			? {
					certificates: parseEmbeddedCertificates(basicResponse, certificatesElement),
				}
			: {}),
	};
}

/**
 * Decodes a PEM-encoded OCSP response (`-----BEGIN OCSP RESPONSE-----`).
 *
 * @example
 * ```ts
 * import { parseOcspResponsePem } from 'micro509';
 *
 * const resp = parseOcspResponsePem(pemString);
 * if (resp.responseStatus === 'successful') {
 *   for (const entry of resp.responses ?? []) {
 *     console.log(entry.certId.serialNumberHex, entry.certStatus);
 *   }
 * }
 * ```
 */
export function parseOcspResponsePem(pem: string): ParsedOcspResponse {
	return parseOcspResponseDer(pemDecode('OCSP RESPONSE', pem));
}

/**
 * Signs and encodes an OCSP BasicResponse with a `successful` status.
 *
 * The responder is identified by key hash (SHA-1 of the signer's SubjectPublicKey).
 * Use `includedCertificates` to embed the responder's chain for relying parties.
 *
 * @example
 * ```ts
 * import { createOcspResponse } from 'micro509';
 *
 * const resp = await createOcspResponse({
 *   signerPrivateKey: responderPrivateKey,
 *   signerCertificate: responderCertPem,
 *   responses: [
 *     {
 *       certificate: leafPem,
 *       issuerCertificate: caPem,
 *       certStatus: 'good',
 *       thisUpdate: new Date('2025-01-01'),
 *       nextUpdate: new Date('2025-01-08'),
 *     },
 *   ],
 *   nonce: requestNonce,
 * });
 * // resp.der, resp.pem, resp.base64
 * ```
 */
export async function createOcspResponse(
	input: CreateOcspResponseInput,
): Promise<OcspResponseMaterial> {
	const signerCertificate = await normalizeCertificate(input.signerCertificate);
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const producedAt = input.producedAt ?? new Date();
	const hashAlgorithm = input.hashAlgorithm ?? 'SHA-1';
	const responses: Uint8Array[] = [];
	for (const response of input.responses) {
		const certificate = await normalizeCertificate(response.certificate);
		const issuer = await normalizeCertificate(response.issuerCertificate);
		responses.push(await encodeSingleResponse(certificate, issuer, response, hashAlgorithm));
	}
	const responderKeyHash = await digestBytes(
		'SHA-1',
		extractSubjectPublicKeyBytes(signerCertificate.subjectPublicKeyInfoDer),
	);
	const responseDataFields: Uint8Array[] = [
		implicitPrimitiveContext(2, responderKeyHash),
		time(producedAt),
		sequence(responses),
	];
	if (input.nonce !== undefined) {
		responseDataFields.push(
			explicitContext(
				1,
				sequence([
					sequence([objectIdentifier(OIDS.ocspNonce), octetString(octetString(input.nonce))]),
				]),
			),
		);
	}
	const responseData = sequence(responseDataFields);
	const signature = await signBytes(input.signerPrivateKey, signatureAlgorithm, responseData);
	const includedCertificates =
		input.includedCertificates === undefined
			? []
			: await Promise.all(input.includedCertificates.map(normalizeCertificate));
	const basicResponseFields: Uint8Array[] = [
		responseData,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signature),
	];
	if (includedCertificates.length > 0) {
		basicResponseFields.push(
			explicitContext(0, concatBytes(includedCertificates.map((certificate) => certificate.der))),
		);
	}
	const basicResponse = sequence(basicResponseFields);
	const der = sequence([
		tlv(0x0a, Uint8Array.of(0x00)),
		explicitContext(
			0,
			sequence([objectIdentifier(OIDS.ocspBasicResponse), octetString(basicResponse)]),
		),
	]);
	return {
		der,
		pem: pemEncode('OCSP RESPONSE', der),
		base64: base64Encode(der),
	};
}

/**
 * Verifies the OCSP response signature against the given signer certificate.
 *
 * Does **not** check responder binding, freshness, or nonce — use
 * {@linkcode validateOcspResponse} for full validation.
 */
export async function verifyOcspResponse(
	response: string | Uint8Array | ParsedOcspResponse,
	signerCertificate: OcspCertificateSource,
): Promise<VerifyOcspResponseResult> {
	let parsed: ParsedOcspResponse;
	try {
		parsed = normalizeOcspResponse(response);
	} catch {
		return verifyOcspResponseFailureResult(
			'signature_invalid',
			'OCSP response signed content is malformed',
		);
	}
	if (
		parsed.responseDataDer === undefined ||
		parsed.signatureAlgorithmOid === undefined ||
		parsed.signatureValue === undefined
	) {
		return verifyOcspResponseFailureResult('signature_invalid', 'OCSP response is not signed');
	}
	let signer: ParsedCertificate;
	try {
		signer = await normalizeCertificate(signerCertificate);
	} catch {
		return verifyOcspResponseFailureResult(
			'signature_invalid',
			'OCSP signer certificate input is malformed',
		);
	}
	let verifiedResult: Awaited<ReturnType<typeof verifySignedDataDetailed>>;
	try {
		verifiedResult = await verifySignedDataDetailed(
			parsed.signatureAlgorithmOid,
			undefined,
			signer.publicKeyAlgorithmOid,
			signer.publicKeyParametersOid,
			signer.subjectPublicKeyInfoDer,
			parsed.signatureValue,
			parsed.responseDataDer,
		);
	} catch {
		return verifyOcspResponseFailureResult(
			'signature_invalid',
			'OCSP response signature verification failed',
		);
	}
	if (!verifiedResult.ok) {
		return verifyOcspResponseFailureResult(
			'signature_invalid',
			'OCSP response signature uses unsupported algorithm parameters',
		);
	}
	return verifiedResult.valid
		? { ok: true, value: parsed }
		: verifyOcspResponseFailureResult(
				'signature_invalid',
				'OCSP response signature does not verify',
			);
}

/**
 * Full OCSP response validation: response status check, signature verification,
 * responder ID binding (byName or byKeyHash), delegated-responder chain and
 * ocspSigning EKU checks, `producedAt`/`thisUpdate`/`nextUpdate` freshness,
 * nonce match, and request-coverage completeness.
 *
 * @example
 * ```ts
 * import { validateOcspResponse } from 'micro509';
 *
 * const result = await validateOcspResponse({
 *   response: ocspResponseDer,
 *   issuerCertificate: caPem,
 *   request: ocspRequestDer,
 * });
 * if (result.ok) {
 *   const entry = result.value.responses?.[0];
 *   console.log(entry?.certStatus); // 'good' | 'revoked' | 'unknown'
 * }
 * ```
 */
export async function validateOcspResponse(
	input: ValidateOcspResponseInput,
): Promise<ValidateOcspResponseResult> {
	let parsedResponse: ParsedOcspResponse;
	try {
		parsedResponse = normalizeOcspResponse(input.response);
	} catch {
		return validateOcspResponseFailureResult(
			'signature_invalid',
			'OCSP response signed content is malformed',
		);
	}
	if (parsedResponse.responseStatus !== 'successful') {
		return validateOcspResponseFailureResult(
			'response_status_invalid',
			`OCSP response status is ${parsedResponse.responseStatus}`,
		);
	}
	let issuer: ParsedCertificate;
	try {
		issuer = await normalizeCertificate(input.issuerCertificate);
	} catch {
		return validateOcspResponseFailureResult(
			'signature_invalid',
			'issuer certificate input is malformed',
		);
	}
	let resolvedResponder: OcspCertificateSource;
	try {
		resolvedResponder =
			input.responderCertificate ??
			(await findMatchingOcspResponderCertificate(
				parsedResponse.certificates,
				parsedResponse.responderId,
			)) ??
			parsedResponse.certificates?.[0] ??
			input.issuerCertificate;
	} catch {
		return validateOcspResponseFailureResult(
			'signature_invalid',
			'OCSP responder certificate input is malformed',
		);
	}
	let signer: ParsedCertificate;
	try {
		signer = await normalizeCertificate(resolvedResponder);
	} catch {
		return validateOcspResponseFailureResult(
			'signature_invalid',
			'OCSP responder certificate input is malformed',
		);
	}
	const signature = await verifyOcspResponse(parsedResponse, signer);
	if (!signature.ok) {
		return validateOcspResponseFailureResult(signature.code, signature.message);
	}
	let responderBinding:
		| Extract<ValidateOcspResponseResult, { readonly ok: false }>
		| { readonly ok: true };
	try {
		responderBinding = await validateOcspResponderIdBinding(parsedResponse.responderId, signer);
	} catch {
		return validateOcspResponseFailureResult(
			'signature_invalid',
			'OCSP responder certificate input is malformed',
		);
	}
	if (!responderBinding.ok) {
		return responderBinding;
	}
	if (!isSameOcspCertificate(signer, issuer)) {
		const allowChainedResponderCertificate = input.allowChainedResponderCertificate === true;
		if (!allowChainedResponderCertificate && !isDirectlyIssuedByOcspIssuer(signer, issuer)) {
			return validateOcspResponseFailureResult(
				'responder_chain_invalid',
				'Delegated OCSP responder must be directly issued by issuer certificate',
			);
		}
		const chain = await verifyCertificateChain({
			leaf: signer.der,
			intermediates: allowChainedResponderCertificate
				? buildOcspResponderIntermediates(parsedResponse.certificates, signer, issuer)
				: [],
			roots: [issuer.der],
		});
		if (!chain.ok) {
			return validateOcspResponseFailureResult(
				'responder_chain_invalid',
				'OCSP responder certificate chain does not validate',
			);
		}
		if (signer.extendedKeyUsage === undefined || !signer.extendedKeyUsage.includes('ocspSigning')) {
			return validateOcspResponseFailureResult(
				'ocsp_signing_missing',
				'Delegated OCSP responder lacks ocspSigning EKU',
			);
		}
	}
	const at = input.at ?? new Date();
	const skew = input.clockSkewMs ?? 0;
	if (
		parsedResponse.producedAt !== undefined &&
		parsedResponse.producedAt.getTime() - skew > at.getTime()
	) {
		return validateOcspResponseFailureResult(
			'stale_response',
			'OCSP response producedAt is later than requested time',
		);
	}
	for (const response of parsedResponse.responses ?? []) {
		let expected: ParsedOcspCertId;
		try {
			expected = await buildParsedOcspCertId(
				response.certId.hashAlgorithmOid,
				issuer,
				response.certId.serialNumberHex,
			);
		} catch {
			return validateOcspResponseFailureResult(
				'signature_invalid',
				'OCSP response CertID hash algorithm is unsupported',
			);
		}
		if (
			response.certId.issuerNameHashHex !== expected.issuerNameHashHex ||
			response.certId.issuerKeyHashHex !== expected.issuerKeyHashHex
		) {
			return validateOcspResponseFailureResult(
				'issuer_mismatch',
				'OCSP response certId does not match issuer certificate',
			);
		}
		if (
			response.thisUpdate.getTime() - skew > at.getTime() ||
			(response.nextUpdate !== undefined && response.nextUpdate.getTime() + skew < at.getTime())
		) {
			return validateOcspResponseFailureResult(
				'stale_response',
				'OCSP response is not valid at requested time',
			);
		}
		if (
			parsedResponse.producedAt !== undefined &&
			response.nextUpdate !== undefined &&
			parsedResponse.producedAt.getTime() - skew > response.nextUpdate.getTime()
		) {
			return validateOcspResponseFailureResult(
				'stale_response',
				'OCSP response producedAt is later than nextUpdate',
			);
		}
	}
	if (input.request !== undefined) {
		let request: ParsedOcspRequest;
		try {
			request = normalizeOcspRequest(input.request);
		} catch {
			return validateOcspResponseFailureResult(
				'request_mismatch',
				'OCSP request input is malformed',
			);
		}
		if (request.nonce !== undefined && request.nonce !== parsedResponse.nonce) {
			return validateOcspResponseFailureResult(
				'nonce_mismatch',
				'OCSP response nonce does not match request nonce',
			);
		}
		const requestIds = new Set(request.requests.map((entry) => serializeCertId(entry)));
		const responseIds = new Set(
			(parsedResponse.responses ?? []).map((response) => serializeCertId(response.certId)),
		);
		for (const response of parsedResponse.responses ?? []) {
			if (!requestIds.has(serializeCertId(response.certId))) {
				return validateOcspResponseFailureResult(
					'request_mismatch',
					'OCSP response includes a certId not present in request',
				);
			}
		}
		for (const requestId of requestIds) {
			if (!responseIds.has(requestId)) {
				return validateOcspResponseFailureResult(
					'request_mismatch',
					'OCSP response does not cover every requested certId',
				);
			}
		}
	}
	return { ok: true, value: parsedResponse };
}

/** Builds a `VerifyOcspResponseFailureResult`. */
function verifyOcspResponseFailureResult(
	code: 'signature_invalid',
	message: string,
): ErrorResult<'signature_invalid', Record<never, never>, VerifyOcspResponseFailure> {
	const error: VerifyOcspResponseFailure = {
		ok: false,
		code,
		message,
	};
	return { ok: false, error, code, message };
}

/** Builds a `ValidateOcspResponseFailureResult`. */
function validateOcspResponseFailureResult(
	code:
		| 'response_status_invalid'
		| 'signature_invalid'
		| 'responder_id_mismatch'
		| 'nonce_mismatch'
		| 'request_mismatch'
		| 'issuer_mismatch'
		| 'responder_chain_invalid'
		| 'ocsp_signing_missing'
		| 'stale_response',
	message: string,
): ErrorResult<
	| 'response_status_invalid'
	| 'signature_invalid'
	| 'responder_id_mismatch'
	| 'nonce_mismatch'
	| 'request_mismatch'
	| 'issuer_mismatch'
	| 'responder_chain_invalid'
	| 'ocsp_signing_missing'
	| 'stale_response',
	Record<never, never>,
	ValidateOcspResponseFailure
> {
	const error: ValidateOcspResponseFailure = {
		ok: false,
		code,
		message,
	};
	return { ok: false, error, code, message };
}

/** Accepts PEM, DER, or already-parsed OCSP response and returns a parsed response. */
function normalizeOcspResponse(
	response: string | Uint8Array | ParsedOcspResponse,
): ParsedOcspResponse {
	if (typeof response === 'string') {
		return parseOcspResponsePem(response);
	}
	if (response instanceof Uint8Array) {
		return parseOcspResponseDer(response);
	}
	if (hasReparseableOcspResponseShape(response)) {
		return parseOcspResponseDer(new Uint8Array(response.der));
	}
	throw new Error('OCSP response input is malformed');
}

/** Accepts PEM, DER, or already-parsed OCSP request and returns a parsed request. */
function normalizeOcspRequest(request: OcspRequestSource): ParsedOcspRequest {
	if (typeof request === 'string') {
		return parseOcspRequestPem(request);
	}
	if (request instanceof Uint8Array) {
		return parseOcspRequestDer(request);
	}
	if (hasReparseableOcspRequestShape(request)) {
		return parseOcspRequestDer(new Uint8Array(request.der));
	}
	throw new Error('OCSP request input is malformed');
}

function parseSignedOcspResponseData(responseDataDer: Uint8Array): {
	readonly responderId: ParsedOcspResponderId;
	readonly producedAt: Date;
	readonly responses: readonly ParsedOcspSingleResponse[];
	readonly nonce?: string;
} {
	const responseDataChildren = readSequenceChildren(responseDataDer);
	if (responseDataChildren.length < 3 || responseDataChildren.length > 5) {
		throw new Error('Malformed OCSP responseData');
	}
	let index = 0;
	if (responseDataChildren[index]?.tag === 0xa0) {
		const versionWrapper = requireElement(responseDataChildren[index], 'version');
		const versionFields = childrenOf(responseDataDer, versionWrapper);
		const versionElement = requireElement(versionFields[0], 'version');
		if (versionFields.length !== 1 || versionElement.tag !== 0x02) {
			throw new Error('version must use INTEGER');
		}
		if (decodeNonNegativeIntegerNumber(versionElement.value, 'OCSP response version') !== 0) {
			throw new Error('Unsupported OCSP response version');
		}
		index += 1;
	}
	const responderIdElement = requireElement(responseDataChildren[index], 'responderID');
	const responderId = parseOcspResponderId(responseDataDer, responderIdElement);
	index += 1;
	const producedAtElement = requireElement(responseDataChildren[index], 'producedAt');
	const responsesElement = requireElement(responseDataChildren[index + 1], 'responses');
	if (responsesElement.tag !== 0x30) {
		throw new Error('responses must use SEQUENCE');
	}
	if (childrenOf(responseDataDer, responsesElement).length === 0) {
		throw new Error('responses must not be empty');
	}
	const responseExtensions = responseDataChildren[index + 2];
	if (responseExtensions !== undefined && responseExtensions.tag !== 0xa1) {
		throw new Error('Malformed OCSP responseData');
	}
	if (responseDataChildren.length !== index + 2 + (responseExtensions === undefined ? 0 : 1)) {
		throw new Error('Malformed OCSP responseData');
	}
	const nonce =
		responseExtensions === undefined
			? undefined
			: parseOcspNonceFromExtensions(responseDataDer, responseExtensions);
	return {
		responderId,
		producedAt: parseTime(producedAtElement),
		responses: childrenOf(responseDataDer, responsesElement).map((singleResponse) =>
			parseSingleResponse(responseDataDer, singleResponse),
		),
		...(nonce === undefined ? {} : { nonce }),
	};
}

/** Searches embedded certificates for one whose subject or key hash matches the responder ID. */
async function findMatchingOcspResponderCertificate(
	certificates: readonly ParsedCertificate[] | undefined,
	responderId: ParsedOcspResponderId | undefined,
): Promise<ParsedCertificate | undefined> {
	if (certificates === undefined || responderId === undefined) {
		return undefined;
	}
	for (const certificate of certificates) {
		if (await matchesOcspResponderId(responderId, certificate)) {
			return certificate;
		}
	}
	return undefined;
}

/** Verifies that the signer certificate matches the response's responder ID (byName or byKeyHash). */
async function validateOcspResponderIdBinding(
	responderId: ParsedOcspResponderId | undefined,
	signer: ParsedCertificate,
): Promise<Extract<ValidateOcspResponseResult, { readonly ok: false }> | { readonly ok: true }> {
	if (responderId === undefined) {
		return { ok: true };
	}
	if (await matchesOcspResponderId(responderId, signer)) {
		return { ok: true };
	}
	return responderId.type === 'byName'
		? validateOcspResponseFailureResult(
				'responder_id_mismatch',
				'OCSP responder certificate subject does not match responderID byName',
			)
		: validateOcspResponseFailureResult(
				'responder_id_mismatch',
				'OCSP responder certificate public key does not match responderID byKeyHash',
			);
}

/** Returns `true` if the certificate matches the responder ID (subject name or key hash). */
async function matchesOcspResponderId(
	responderId: ParsedOcspResponderId,
	certificate: ParsedCertificate,
): Promise<boolean> {
	if (responderId.type === 'byName') {
		return compareOcspResponderNames(responderId.name, certificate.subject);
	}
	const certificateKeyHashHex = toHex(
		await digestBytes('SHA-1', extractSubjectPublicKeyBytes(certificate.subjectPublicKeyInfoDer)),
	);
	return certificateKeyHashHex === responderId.keyHashHex;
}

/** Identity check — same serial, issuer, subject, and SPKI. */
function isSameOcspCertificate(left: ParsedCertificate, right: ParsedCertificate): boolean {
	return (
		left.serialNumberHex === right.serialNumberHex &&
		compareDistinguishedNames(left.issuer, right.issuer) &&
		compareDistinguishedNames(left.subject, right.subject) &&
		left.subjectPublicKeyInfoDer.length === right.subjectPublicKeyInfoDer.length &&
		left.subjectPublicKeyInfoDer.every(
			(byte, index) => byte === right.subjectPublicKeyInfoDer[index],
		)
	);
}

/** Returns `true` if `signer` was directly issued by `issuer` (name + AKI match). */
function isDirectlyIssuedByOcspIssuer(
	signer: ParsedCertificate,
	issuer: ParsedCertificate,
): boolean {
	if (!compareDistinguishedNames(signer.issuer, issuer.subject)) {
		return false;
	}
	if (
		signer.authorityKeyIdentifier !== undefined &&
		issuer.subjectKeyIdentifier !== undefined &&
		signer.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
	) {
		return false;
	}
	return true;
}

/** Filters embedded certificates to produce an intermediate chain (excluding signer and issuer). */
function buildOcspResponderIntermediates(
	certificates: readonly ParsedCertificate[] | undefined,
	signer: ParsedCertificate,
	issuer: ParsedCertificate,
): readonly Uint8Array[] {
	if (certificates === undefined) {
		return [];
	}
	const intermediates: Uint8Array[] = [];
	for (const certificate of certificates) {
		if (isSameOcspCertificate(certificate, signer) || isSameOcspCertificate(certificate, issuer)) {
			continue;
		}
		intermediates.push(certificate.der);
	}
	return intermediates;
}

/** DER-encodes a CertID SEQUENCE (hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber). */
async function encodeOcspCertId(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
	hashAlgorithm: OcspHashAlgorithm,
): Promise<Uint8Array> {
	const hashAlgorithmOid = hashAlgorithm === 'SHA-1' ? OIDS.sha1 : OIDS.sha256;
	const parsed = await buildParsedOcspCertId(hashAlgorithmOid, issuer, certificate.serialNumberHex);
	return sequence([
		sequence([objectIdentifier(hashAlgorithmOid), nullValue()]),
		octetString(hexToBytes(parsed.issuerNameHashHex)),
		octetString(hexToBytes(parsed.issuerKeyHashHex)),
		integer(hexToBytes(parsed.serialNumberHex)),
	]);
}

/** Computes issuer name/key hashes for a CertID given the hash algorithm OID and issuer certificate. */
async function buildParsedOcspCertId(
	hashAlgorithmOid: string,
	issuer: ParsedCertificate,
	serialNumberHex: string,
): Promise<ParsedOcspCertId> {
	const hashAlgorithm = ocspHashAlgorithmFromOid(hashAlgorithmOid);
	return {
		hashAlgorithmOid,
		hashAlgorithmName: describeHashAlgorithm(hashAlgorithmOid),
		issuerNameHashHex: toHex(await digestBytes(hashAlgorithm, hexToBytes(issuer.subject.derHex))),
		issuerKeyHashHex: toHex(
			await digestBytes(
				hashAlgorithm,
				extractSubjectPublicKeyBytes(issuer.subjectPublicKeyInfoDer),
			),
		),
		serialNumberHex,
	};
}

/** Hashes `bytes` with the given WebCrypto algorithm name. */
async function digestBytes(algorithm: OcspHashAlgorithm, bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest(algorithm, toArrayBuffer(bytes)));
}

/** DER-encodes a SingleResponse (certId, certStatus, thisUpdate, optional nextUpdate). */
async function encodeSingleResponse(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
	input: CreateOcspSingleResponseInput,
	hashAlgorithm: OcspHashAlgorithm,
): Promise<Uint8Array> {
	const certId = await encodeOcspCertId(certificate, issuer, hashAlgorithm);
	const certStatus = encodeOcspCertStatus(input);
	return sequence([
		certId,
		certStatus,
		time(input.thisUpdate ?? new Date()),
		...(input.nextUpdate === undefined ? [] : [explicitContext(0, time(input.nextUpdate))]),
	]);
}

/** DER-encodes the CertStatus CHOICE (good [0], revoked [1], unknown [2]). */
function encodeOcspCertStatus(input: CreateOcspSingleResponseInput): Uint8Array {
	switch (input.certStatus) {
		case 'good':
			return tlv(0x80, new Uint8Array());
		case 'unknown':
			return tlv(0x82, new Uint8Array());
		case 'revoked': {
			const revokedFields: Uint8Array[] = [time(input.revokedAt ?? input.thisUpdate ?? new Date())];
			if (input.revocationReasonCode !== undefined) {
				revokedFields.push(
					explicitContext(0, tlv(0x0a, Uint8Array.of(input.revocationReasonCode))),
				);
			}
			return tlv(0xa1, concatBytes(revokedFields));
		}
	}
}

/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(source: OcspCertificateSource): ParsedCertificate {
	if (hasParsedCertificateShape(source)) {
		return parseCertificateDer(new Uint8Array(source.der));
	}
	return parseCertificateFromSource(source);
}

/** Type guard: distinguishes a `ParsedCertificate` from raw `Uint8Array`. */
function hasParsedCertificateShape(value: OcspCertificateSource): value is ParsedCertificate {
	return typeof value !== 'string' && 'subjectPublicKeyInfoDer' in value;
}

/** Decodes a DER-encoded CertID SEQUENCE into a {@linkcode ParsedOcspCertId}. */
function parseOcspCertId(der: Uint8Array): ParsedOcspCertId {
	const root = readRootElement(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (root.tag !== 0x30) {
		throw new Error('CertID must use SEQUENCE');
	}
	const children = childrenOf(der, root);
	if (children.length !== 4) {
		throw new Error(
			'CertID must contain hashAlgorithm, issuerNameHash, issuerKeyHash, and serialNumber',
		);
	}
	const hashAlgorithm = requireElement(children[0], 'hashAlgorithm');
	if (hashAlgorithm.tag !== 0x30) {
		throw new Error('hashAlgorithm must use SEQUENCE');
	}
	const algorithmChildren = childrenOf(der, hashAlgorithm);
	if (algorithmChildren.length < 1 || algorithmChildren.length > 2) {
		throw new Error('Malformed hashAlgorithm');
	}
	const algorithmOid = requireElement(algorithmChildren[0], 'hashAlgorithm OID');
	const hashAlgorithmOid = decodeObjectIdentifier(algorithmOid.value);
	if (requireElement(children[1], 'issuerNameHash').tag !== 0x04) {
		throw new Error('issuerNameHash must use OCTET STRING');
	}
	if (requireElement(children[2], 'issuerKeyHash').tag !== 0x04) {
		throw new Error('issuerKeyHash must use OCTET STRING');
	}
	const serialNumber = requireElement(children[3], 'serialNumber');
	if (serialNumber.tag !== 0x02) {
		throw new Error('serialNumber must use INTEGER');
	}
	return {
		hashAlgorithmOid,
		hashAlgorithmName: describeHashAlgorithm(hashAlgorithmOid),
		issuerNameHashHex: toHex(requireElement(children[1], 'issuerNameHash').value),
		issuerKeyHashHex: toHex(requireElement(children[2], 'issuerKeyHash').value),
		serialNumberHex: toHex(serialNumber.value),
	};
}

/** Decodes a SingleResponse from its ASN.1 element within the ResponseData. */
function parseSingleResponse(source: Uint8Array, element: DerElement): ParsedOcspSingleResponse {
	const children = childrenOf(source, element);
	if (children.length < 3 || children.length > 5) {
		throw new Error('Malformed OCSP SingleResponse');
	}
	const certId = requireElement(children[0], 'certId');
	const certStatus = requireElement(children[1], 'certStatus');
	const thisUpdate = requireElement(children[2], 'thisUpdate');
	let cursor = 3;
	const nextUpdateElement = children[cursor]?.tag === 0xa0 ? children[cursor] : undefined;
	if (nextUpdateElement !== undefined) {
		cursor += 1;
	}
	const singleExtensions = children[cursor];
	if (singleExtensions !== undefined && singleExtensions.tag !== 0xa1) {
		throw new Error('Malformed OCSP SingleResponse');
	}
	if (children.length !== cursor + (singleExtensions === undefined ? 0 : 1)) {
		throw new Error('Malformed OCSP SingleResponse');
	}
	let revokedAt: Date | undefined;
	let revocationReasonCode: number | undefined;
	if (certStatus.tag === 0x80) {
		if (certStatus.value.length !== 0) {
			throw new Error('OCSP good certStatus must be empty');
		}
		return {
			certId: parseOcspCertId(source.slice(certId.start - certId.headerLength, certId.end)),
			certStatus: 'good',
			thisUpdate: parseTime(thisUpdate),
			...(nextUpdateElement === undefined
				? {}
				: {
						nextUpdate: parseTime(
							requireElement(childrenOf(source, nextUpdateElement)[0], 'nextUpdate'),
						),
					}),
		};
	}
	if (certStatus.tag === 0xa1) {
		const revokedInfo = childrenOf(source, certStatus);
		if (revokedInfo.length < 1 || revokedInfo.length > 2) {
			throw new Error('Malformed OCSP revoked certStatus');
		}
		revokedAt = parseTime(requireElement(revokedInfo[0], 'revocationTime'));
		const reason = revokedInfo[1];
		if (reason?.tag === 0xa0) {
			const reasonChildren = childrenOf(source, reason);
			const enumerated = requireElement(reasonChildren[0], 'revocationReason');
			if (reasonChildren.length !== 1 || enumerated.tag !== 0x0a) {
				throw new Error('revocationReason must use ENUMERATED');
			}
			revocationReasonCode = decodeNonNegativeIntegerNumber(
				enumerated.value,
				'OCSP revocationReason',
			);
		} else if (reason !== undefined) {
			throw new Error('Malformed OCSP revoked certStatus');
		}
	} else if (certStatus.tag !== 0x82) {
		throw new Error(`Unsupported OCSP certStatus tag: ${String(certStatus.tag)}`);
	} else if (certStatus.value.length !== 0) {
		throw new Error('OCSP unknown certStatus must be empty');
	}
	return {
		certId: parseOcspCertId(source.slice(certId.start - certId.headerLength, certId.end)),
		certStatus: certStatus.tag === 0x82 ? 'unknown' : 'revoked',
		thisUpdate: parseTime(thisUpdate),
		...(nextUpdateElement === undefined
			? {}
			: {
					nextUpdate: parseTime(
						requireElement(childrenOf(source, nextUpdateElement)[0], 'nextUpdate'),
					),
				}),
		...(revokedAt === undefined ? {} : { revokedAt }),
		...(revocationReasonCode === undefined ? {} : { revocationReasonCode }),
	};
}

/** Decodes a ResponderID from its context-tagged ASN.1 element (byName [1] or byKeyHash [2]). */
function parseOcspResponderId(source: Uint8Array, element: DerElement): ParsedOcspResponderId {
	switch (element.tag) {
		case 0x82:
			return { type: 'byKeyHash', keyHashHex: toHex(element.value) };
		case 0xa1:
			return {
				type: 'byName',
				name: parseResponderName(
					source,
					requireElement(childrenOf(source, element)[0], 'ResponderID byName'),
				),
			};
		case 0xa2:
			return {
				type: 'byKeyHash',
				keyHashHex: toHex(
					requireElement(childrenOf(source, element)[0], 'ResponderID byKeyHash').value,
				),
			};
		default:
			throw new Error(`Unsupported OCSP responderID tag: ${String(element.tag)}`);
	}
}

/** Decodes a Name SEQUENCE from the ResponderID byName form. */
function parseResponderName(source: Uint8Array, element: DerElement): ParsedName {
	const rdns: ParsedRelativeDistinguishedName[] = [];
	const attributes: ParsedNameAttribute[] = [];
	const values: ParsedName['values'] = {};
	for (const setElement of childrenOf(source, element)) {
		const rdn = parseResponderNameAttributeSet(source, setElement);
		rdns.push(rdn);
		for (const attribute of rdn.attributes) {
			attributes.push(attribute);
			if (attribute.key !== undefined && values[attribute.key] === undefined) {
				values[attribute.key] = attribute.value;
			}
		}
	}
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
		rdns,
		attributes,
		values,
	};
}

/** Decodes one RDN SET from a responder name. */
function parseResponderNameAttributeSet(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: ParsedRelativeDistinguishedName['values'] = {};
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const key = responderNameKeyFromOid(oid);
		const value = decodeString(valueElement.tag, valueElement.value);
		const attribute: ParsedNameAttribute =
			key === undefined
				? { oid, valueTag: valueElement.tag, value }
				: { oid, key, valueTag: valueElement.tag, value };
		attributes.push(attribute);
		if (key !== undefined && values[key] === undefined) {
			values[key] = value;
		}
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
}

/** RDN-by-RDN responder name comparison with RFC 4518 string prep. */
function compareOcspResponderNames(left: ParsedName, right: ParsedName): boolean {
	if (left.rdns.length !== right.rdns.length) {
		return false;
	}
	for (let index = 0; index < left.rdns.length; index += 1) {
		const leftRdn = left.rdns[index];
		const rightRdn = right.rdns[index];
		if (leftRdn === undefined || rightRdn === undefined) {
			return false;
		}
		if (!compareOcspRelativeDistinguishedNames(leftRdn, rightRdn)) {
			return false;
		}
	}
	return true;
}

/** Set-equality comparison for RDN attribute sets (order-independent). */
function compareOcspRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = new Array(right.attributes.length).fill(false);
	for (const leftAttribute of left.attributes) {
		let found = false;
		for (let index = 0; index < right.attributes.length; index += 1) {
			const rightAttribute = right.attributes[index];
			if (rightAttribute === undefined || matched[index]) {
				continue;
			}
			if (!compareOcspNameAttributeValue(leftAttribute, rightAttribute)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/** Compares two name attributes with RFC 4518 string prep for directory-string types. */
function compareOcspNameAttributeValue(
	left: ParsedNameAttribute,
	right: ParsedNameAttribute,
): boolean {
	if (left.oid !== right.oid) {
		return false;
	}
	if (isOcspDirectoryStringTag(left.valueTag) && isOcspDirectoryStringTag(right.valueTag)) {
		const preparedLeft = prepareOcspNameCompareString(left.value);
		const preparedRight = prepareOcspNameCompareString(right.value);
		if (preparedLeft === undefined || preparedRight === undefined) {
			return false;
		}
		return preparedLeft === preparedRight;
	}
	return left.valueTag === right.valueTag && left.value === right.value;
}

/** Returns `true` for UTF8String (0x0c) and PrintableString (0x13). */
function isOcspDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/** NFKC-normalises, lowercases, trims, and collapses whitespace for RFC 4518 name comparison. */
function prepareOcspNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

/** Maps an X.500 attribute type OID to its friendly key name for responder name parsing. */
function responderNameKeyFromOid(oid: string): ParsedNameAttribute['key'] {
	switch (oid) {
		case OIDS.commonName:
			return 'commonName';
		case OIDS.surname:
			return 'surname';
		case OIDS.serialNumber:
			return 'serialNumber';
		case OIDS.countryName:
			return 'country';
		case OIDS.localityName:
			return 'locality';
		case OIDS.stateOrProvinceName:
			return 'state';
		case OIDS.streetAddress:
			return 'street';
		case OIDS.organizationName:
			return 'organization';
		case OIDS.organizationalUnitName:
			return 'organizationalUnit';
		case OIDS.title:
			return 'title';
		case OIDS.givenName:
			return 'givenName';
		case OIDS.emailAddress:
			return 'emailAddress';
		default:
			return undefined;
	}
}

/** Extracts the nonce value (as hex) from an OCSP extensions wrapper, if present. */
function parseOcspNonceFromExtensions(source: Uint8Array, element: DerElement): string | undefined {
	const extensionsSequence = requireElement(childrenOf(source, element)[0], 'extensions');
	if (childrenOf(source, element).length !== 1 || extensionsSequence.tag !== 0x30) {
		throw new Error('Malformed OCSP extensions');
	}
	const seenOids = new Set<string>();
	let nonce: string | undefined;
	for (const extension of childrenOf(source, extensionsSequence)) {
		const parts = childrenOf(source, extension);
		if (parts.length < 2 || parts.length > 3) {
			throw new Error('Malformed OCSP extension');
		}
		if (parts.length === 3 && parts[1]?.tag !== 0x01) {
			throw new Error('Malformed OCSP extension');
		}
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'extension OID').value);
		if (seenOids.has(oid)) {
			throw new Error(`Duplicate OCSP extension OID: ${oid}`);
		}
		seenOids.add(oid);
		const extnValue = requireElement(parts[parts.length - 1], 'extnValue');
		if (extnValue.tag !== 0x04) {
			throw new Error('OCSP extension value must use OCTET STRING');
		}
		if (oid !== OIDS.ocspNonce) {
			continue;
		}
		const nonceElement = readRootElement(extnValue.value, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		if (nonceElement.tag !== 0x04) {
			throw new Error('OCSP nonce extension value must use OCTET STRING');
		}
		nonce = toHex(nonceElement.value);
	}
	return nonce;
}

/** Decodes the optional `certs [0]` field from a BasicOCSPResponse. */
function parseEmbeddedCertificates(
	source: Uint8Array,
	element: DerElement,
): readonly ParsedCertificate[] {
	const certificates: ParsedCertificate[] = [];
	let offset = element.start;
	while (offset < element.end) {
		const child = readElement(source, offset);
		certificates.push(parseCertificateDer(source.slice(offset, child.end)));
		offset = child.end;
	}
	return certificates;
}

/** Extracts the raw public key bytes (without BIT STRING padding byte) from SPKI DER. */
function extractSubjectPublicKeyBytes(spkiDer: Uint8Array): Uint8Array {
	const top = childrenOf(spkiDer, readElement(spkiDer));
	const bitStringElement = requireElement(top[1], 'subjectPublicKey BIT STRING');
	if (bitStringElement.tag !== 0x03) {
		throw new Error('SPKI missing subjectPublicKey BIT STRING');
	}
	return bitStringElement.value.slice(1);
}

/** Maps an integer response-status code to its {@linkcode OcspResponseStatus} string. */
function ocspResponseStatusFromCode(code: number | undefined): OcspResponseStatus {
	switch (code) {
		case 0:
			return 'successful';
		case 1:
			return 'malformedRequest';
		case 2:
			return 'internalError';
		case 3:
			return 'tryLater';
		case 5:
			return 'sigRequired';
		case 6:
			return 'unauthorized';
		default:
			throw new Error(`Unsupported OCSP responseStatus value: ${String(code)}`);
	}
}

function hasReparseableOcspRequestShape(
	request: ParsedOcspRequest,
): request is ParsedOcspRequest & { readonly der: Uint8Array } {
	return 'der' in request && request.der instanceof Uint8Array;
}

function hasReparseableOcspResponseShape(
	response: ParsedOcspResponse,
): response is ParsedOcspResponse & { readonly der: Uint8Array } {
	return 'der' in response && response.der instanceof Uint8Array;
}

/** Maps a hash algorithm OID to the WebCrypto algorithm name. Throws on unsupported OIDs. */
function ocspHashAlgorithmFromOid(oid: string): OcspHashAlgorithm {
	switch (oid) {
		case OIDS.sha1:
			return 'SHA-1';
		case OIDS.sha256:
			return 'SHA-256';
		default:
			throw new Error(`Unsupported OCSP hash algorithm OID: ${oid}`);
	}
}

/** Produces a colon-delimited canonical string for CertID set comparison. */
function serializeCertId(certId: ParsedOcspCertId): string {
	return [
		certId.hashAlgorithmOid,
		certId.issuerNameHashHex,
		certId.issuerKeyHashHex,
		certId.serialNumberHex,
	].join(':');
}
