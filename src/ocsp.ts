/**
 * OCSP request and response helpers.
 *
 * This module builds, parses, verifies, and validates OCSP messages and responder
 * metadata.
 */

import {
	childrenOf,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	hexToBytes,
	parseTime,
	requireElement,
	toArrayBuffer,
	toHex,
} from './asn1.ts';
import type { Micro509Error } from './core/result.ts';
import type { DerElement } from './der.ts';
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
	readSequenceChildren,
	sequence,
	time,
	tlv,
} from './der.ts';
import { getCrypto } from './keys.ts';
import { OIDS } from './oids.ts';
import type {
	ParsedCertificate,
	ParsedName,
	ParsedNameAttribute,
	ParsedRelativeDistinguishedName,
} from './parse.ts';
import { parseCertificateDer, parseCertificatePem } from './parse.ts';
import { base64Encode, pemDecode, pemEncode } from './pem.ts';
import { verifySignedData } from './sig-verify.ts';
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from './signing.ts';
import { verifyCertificateChain } from './verify.ts';

/**
 * Defines OCSP hash algorithm.
 */
export type OcspHashAlgorithm = 'SHA-1' | 'SHA-256';
/**
 * Describes the accepted source forms for OCSP certificate inputs.
 */
export type OcspCertificateSource = string | Uint8Array | ParsedCertificate;
/**
 * Describes the accepted source forms for OCSP request inputs.
 */
export type OcspRequestSource = string | Uint8Array | ParsedOcspRequest;

/**
 * Describes the input shape for create OCSP request item operations.
 */
export interface CreateOcspRequestItemInput {
	/**
	 * Carries the certificate value.
	 */
	readonly certificate: OcspCertificateSource;
	/**
	 * Carries the issuer certificate value.
	 */
	readonly issuerCertificate: OcspCertificateSource;
}

/**
 * Describes the input shape for create OCSP request operations.
 */
export interface CreateOcspRequestInput {
	/**
	 * Carries the requests value.
	 */
	readonly requests: readonly CreateOcspRequestItemInput[];
	/**
	 * Carries the hash algorithm value.
	 */
	readonly hashAlgorithm?: OcspHashAlgorithm;
	/**
	 * Carries the nonce value.
	 */
	readonly nonce?: Uint8Array;
}

/**
 * Bundles the encoded artifacts produced by OCSP request operations.
 */
export interface OcspRequestMaterial {
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
 * Describes the structured OCSP cert id produced by parsing helpers.
 */
export interface ParsedOcspCertId {
	/**
	 * Carries the OID for hash algorithm.
	 */
	readonly hashAlgorithmOid: string;
	/**
	 * Carries the hexadecimal issuer name hash.
	 */
	readonly issuerNameHashHex: string;
	/**
	 * Carries the hexadecimal issuer key hash.
	 */
	readonly issuerKeyHashHex: string;
	/**
	 * Carries the hexadecimal serial number.
	 */
	readonly serialNumberHex: string;
}

/**
 * Describes the structured OCSP request produced by parsing helpers.
 */
export interface ParsedOcspRequest {
	/**
	 * Carries the requests value.
	 */
	readonly requests: readonly ParsedOcspCertId[];
	/**
	 * Carries the nonce value.
	 */
	readonly nonce?: string;
}

/**
 * Enumerates OCSP cert values used by this module.
 */
export type OcspCertStatus = 'good' | 'revoked' | 'unknown';
/**
 * Enumerates OCSP response values used by this module.
 */
export type OcspResponseStatus =
	| 'successful'
	| 'malformedRequest'
	| 'internalError'
	| 'tryLater'
	| 'sigRequired'
	| 'unauthorized';

/**
 * Describes the structured OCSP single response produced by parsing helpers.
 */
export interface ParsedOcspSingleResponse {
	/**
	 * Carries the cert id value.
	 */
	readonly certId: ParsedOcspCertId;
	/**
	 * Carries the cert status value.
	 */
	readonly certStatus: OcspCertStatus;
	/**
	 * Carries the this update value.
	 */
	readonly thisUpdate: Date;
	/**
	 * Carries the next update value.
	 */
	readonly nextUpdate?: Date;
	/**
	 * Carries the revoked at value.
	 */
	readonly revokedAt?: Date;
	/**
	 * Carries the revocation reason code value.
	 */
	readonly revocationReasonCode?: number;
}

/**
 * Describes the structured OCSP responder id produced by parsing helpers.
 */
export type ParsedOcspResponderId =
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'byName';
			/**
			 * Carries the name value.
			 */
			readonly name: ParsedName;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'byKeyHash';
			/**
			 * Carries the hexadecimal key hash.
			 */
			readonly keyHashHex: string;
	  };

/**
 * Describes the structured OCSP response produced by parsing helpers.
 */
export interface ParsedOcspResponse {
	/**
	 * Carries the response status value.
	 */
	readonly responseStatus: OcspResponseStatus;
	/**
	 * Carries the OID for response type.
	 */
	readonly responseTypeOid?: string;
	/**
	 * Carries the DER-encoded response data.
	 */
	readonly responseDataDer?: Uint8Array;
	/**
	 * Carries the responder id value.
	 */
	readonly responderId?: ParsedOcspResponderId;
	/**
	 * Carries the OID for signature algorithm.
	 */
	readonly signatureAlgorithmOid?: string;
	/**
	 * Carries the signature value value.
	 */
	readonly signatureValue?: Uint8Array;
	/**
	 * Carries the produced at value.
	 */
	readonly producedAt?: Date;
	/**
	 * Carries the responses value.
	 */
	readonly responses?: readonly ParsedOcspSingleResponse[];
	/**
	 * Carries the nonce value.
	 */
	readonly nonce?: string;
	/**
	 * Carries the certificates value.
	 */
	readonly certificates?: readonly ParsedCertificate[];
}

/**
 * Describes the input shape for create OCSP single response operations.
 */
export interface CreateOcspSingleResponseInput extends CreateOcspRequestItemInput {
	/**
	 * Carries the cert status value.
	 */
	readonly certStatus: OcspCertStatus;
	/**
	 * Carries the this update value.
	 */
	readonly thisUpdate?: Date;
	/**
	 * Carries the next update value.
	 */
	readonly nextUpdate?: Date;
	/**
	 * Carries the revoked at value.
	 */
	readonly revokedAt?: Date;
	/**
	 * Carries the revocation reason code value.
	 */
	readonly revocationReasonCode?: number;
}

/**
 * Describes the input shape for create OCSP response operations.
 */
export interface CreateOcspResponseInput {
	/**
	 * Carries the signer private key value.
	 */
	readonly signerPrivateKey: CryptoKey;
	/**
	 * Carries the signer certificate value.
	 */
	readonly signerCertificate: OcspCertificateSource;
	/**
	 * Carries the responses value.
	 */
	readonly responses: readonly CreateOcspSingleResponseInput[];
	/**
	 * Carries the produced at value.
	 */
	readonly producedAt?: Date;
	/**
	 * Carries the nonce value.
	 */
	readonly nonce?: Uint8Array;
	/**
	 * Carries the hash algorithm value.
	 */
	readonly hashAlgorithm?: OcspHashAlgorithm;
	/**
	 * Carries the included certificates value.
	 */
	readonly includedCertificates?: readonly OcspCertificateSource[];
}

/**
 * Bundles the encoded artifacts produced by OCSP response operations.
 */
export interface OcspResponseMaterial {
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
 * Represents a typed failure produced by verify OCSP response operations.
 */
export interface VerifyOcspResponseFailure extends Micro509Error<'signature_invalid'> {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents the result returned by verify OCSP response failure operations.
 */
interface VerifyOcspResponseFailureResult {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the canonical error payload.
	 */
	readonly error: VerifyOcspResponseFailure;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: 'signature_invalid';
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
}

/**
 * Represents the result returned by verify OCSP response operations.
 */
export type VerifyOcspResponseResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: ParsedOcspResponse;
	  }
	| VerifyOcspResponseFailureResult;

/**
 * Describes the input shape for validate OCSP response operations.
 */
export interface ValidateOcspResponseInput {
	/**
	 * Carries the response value.
	 */
	readonly response: string | Uint8Array | ParsedOcspResponse;
	/**
	 * Carries the issuer certificate value.
	 */
	readonly issuerCertificate: OcspCertificateSource;
	/**
	 * Carries the request value.
	 */
	readonly request?: OcspRequestSource;
	/**
	 * Carries the responder certificate value.
	 */
	readonly responderCertificate?: OcspCertificateSource;
	/**
	 * Indicates whether allow chained responder certificate.
	 */
	readonly allowChainedResponderCertificate?: boolean;
	/**
	 * Carries the at value.
	 */
	readonly at?: Date;
	/**
	 * Carries the clock skew ms value.
	 */
	readonly clockSkewMs?: number;
}

/**
 * Represents a typed failure produced by validate OCSP response operations.
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
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
}

/**
 * Represents the result returned by validate OCSP response failure operations.
 */
interface ValidateOcspResponseFailureResult {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the canonical error payload.
	 */
	readonly error: ValidateOcspResponseFailure;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code:
		| 'response_status_invalid'
		| 'signature_invalid'
		| 'responder_id_mismatch'
		| 'nonce_mismatch'
		| 'request_mismatch'
		| 'issuer_mismatch'
		| 'responder_chain_invalid'
		| 'ocsp_signing_missing'
		| 'stale_response';
	/**
	 * Carries the human-readable error message.
	 */
	readonly message: string;
}

/**
 * Represents the result returned by validate OCSP response operations.
 */
export type ValidateOcspResponseResult =
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: ParsedOcspResponse;
	  }
	| ValidateOcspResponseFailureResult;

/**
 * Creates OCSP request.
 *
 * @param input The typed input payload.
 * @returns The created OCSP request.
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

/**
 * Parses OCSP request DER.
 *
 * @param der The DER-encoded bytes.
 * @returns The parsed OCSP request DER.
 */
export function parseOcspRequestDer(der: Uint8Array): ParsedOcspRequest {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const tbsRequest = requireElement(top[0], 'tbsRequest');
	const tbsChildren = childrenOf(der, tbsRequest);
	const requestList = requireElement(
		tbsChildren.find((child) => child.tag === 0x30),
		'requestList',
	);
	const requests = childrenOf(der, requestList).map((request) => {
		const certId = requireElement(childrenOf(der, request)[0], 'reqCert');
		return parseOcspCertId(der.slice(certId.start - certId.headerLength, certId.end));
	});
	const extensions = tbsChildren.find((child) => child.tag === 0xa2);
	const nonce =
		extensions === undefined ? undefined : parseOcspNonceFromExtensions(der, extensions);
	return {
		requests,
		...(nonce === undefined ? {} : { nonce }),
	};
}

/**
 * Parses OCSP request PEM.
 *
 * @param pem The PEM-encoded text.
 * @returns The parsed OCSP request PEM.
 */
export function parseOcspRequestPem(pem: string): ParsedOcspRequest {
	return parseOcspRequestDer(pemDecode('OCSP REQUEST', pem));
}

/**
 * Parses OCSP response DER.
 *
 * @param der The DER-encoded bytes.
 * @returns The parsed OCSP response DER.
 */
export function parseOcspResponseDer(der: Uint8Array): ParsedOcspResponse {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const statusElement = requireElement(top[0], 'responseStatus');
	const responseStatus = ocspResponseStatusFromCode(statusElement.value[0]);
	const responseBytes = top[1];
	if (responseBytes === undefined) {
		return { responseStatus };
	}
	const bytesSequence = requireElement(childrenOf(der, responseBytes)[0], 'responseBytes');
	const responseBytesChildren = childrenOf(der, bytesSequence);
	const responseType = requireElement(responseBytesChildren[0], 'responseType');
	const response = requireElement(responseBytesChildren[1], 'response');
	const responseTypeOid = decodeObjectIdentifier(responseType.value);
	if (responseTypeOid !== OIDS.ocspBasicResponse) {
		return { responseStatus, responseTypeOid };
	}
	const basicResponse = response.value;
	const basicChildren = readSequenceChildren(basicResponse);
	const responseData = requireElement(basicChildren[0], 'responseData');
	const signatureAlgorithm = requireElement(basicChildren[1], 'signatureAlgorithm');
	const signatureValue = requireElement(basicChildren[2], 'signatureValue');
	const certificatesElement = basicChildren[3];
	const responseDataDer = basicResponse.slice(
		responseData.start - responseData.headerLength,
		responseData.end,
	);
	const responseDataChildren = readSequenceChildren(responseDataDer);
	let index = 0;
	if (responseDataChildren[index]?.tag === 0xa0) {
		index += 1;
	}
	const responderIdElement = requireElement(responseDataChildren[index], 'responderID');
	const responderId = parseOcspResponderId(responseDataDer, responderIdElement);
	index += 1;
	const producedAt = requireElement(responseDataChildren[index], 'producedAt');
	const responses = requireElement(responseDataChildren[index + 1], 'responses');
	const responseExtensions = responseDataChildren[index + 2];
	const nonce =
		responseExtensions === undefined
			? undefined
			: parseOcspNonceFromExtensions(responseDataDer, responseExtensions);
	return {
		responseStatus,
		responseTypeOid,
		responseDataDer,
		responderId,
		signatureAlgorithmOid: decodeObjectIdentifier(
			requireElement(childrenOf(basicResponse, signatureAlgorithm)[0], 'signatureAlgorithm OID')
				.value,
		),
		signatureValue: extractBitStringValue(signatureValue),
		producedAt: parseTime(producedAt),
		responses: childrenOf(responseDataDer, responses).map((singleResponse) =>
			parseSingleResponse(responseDataDer, singleResponse),
		),
		...(nonce === undefined ? {} : { nonce }),
		...(certificatesElement?.tag === 0xa0
			? {
					certificates: parseEmbeddedCertificates(basicResponse, certificatesElement),
				}
			: {}),
	};
}

/**
 * Parses OCSP response PEM.
 *
 * @param pem The PEM-encoded text.
 * @returns The parsed OCSP response PEM.
 */
export function parseOcspResponsePem(pem: string): ParsedOcspResponse {
	return parseOcspResponseDer(pemDecode('OCSP RESPONSE', pem));
}

/**
 * Creates OCSP response.
 *
 * @param input The typed input payload.
 * @returns The created OCSP response.
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
 * Verifies OCSP response.
 *
 * @param response The response input.
 * @param signerCertificate The signer certificate value.
 * @returns The verification result.
 */
export async function verifyOcspResponse(
	response: string | Uint8Array | ParsedOcspResponse,
	signerCertificate: OcspCertificateSource,
): Promise<VerifyOcspResponseResult> {
	const parsed = normalizeOcspResponse(response);
	if (
		parsed.responseDataDer === undefined ||
		parsed.signatureAlgorithmOid === undefined ||
		parsed.signatureValue === undefined
	) {
		return verifyOcspResponseFailureResult('signature_invalid', 'OCSP response is not signed');
	}
	const signer = await normalizeCertificate(signerCertificate);
	const verified = await verifySignedData(
		parsed.signatureAlgorithmOid,
		undefined,
		signer.publicKeyAlgorithmOid,
		signer.publicKeyParametersOid,
		signer.subjectPublicKeyInfoDer,
		parsed.signatureValue,
		parsed.responseDataDer,
	);
	return verified
		? { ok: true, value: parsed }
		: verifyOcspResponseFailureResult(
				'signature_invalid',
				'OCSP response signature does not verify',
			);
}

/**
 * Validates OCSP response.
 *
 * @param input The typed input payload.
 * @returns The validation result.
 */
export async function validateOcspResponse(
	input: ValidateOcspResponseInput,
): Promise<ValidateOcspResponseResult> {
	const parsedResponse = normalizeOcspResponse(input.response);
	if (parsedResponse.responseStatus !== 'successful') {
		return validateOcspResponseFailureResult(
			'response_status_invalid',
			`OCSP response status is ${parsedResponse.responseStatus}`,
		);
	}
	const issuer = await normalizeCertificate(input.issuerCertificate);
	const resolvedResponder =
		input.responderCertificate ??
		(await findMatchingOcspResponderCertificate(
			parsedResponse.certificates,
			parsedResponse.responderId,
		)) ??
		parsedResponse.certificates?.[0] ??
		input.issuerCertificate;
	const signer = await normalizeCertificate(resolvedResponder);
	const signature = await verifyOcspResponse(parsedResponse, signer);
	if (!signature.ok) {
		return validateOcspResponseFailureResult(signature.code, signature.message);
	}
	const responderBinding = await validateOcspResponderIdBinding(parsedResponse.responderId, signer);
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
		const expected = await buildParsedOcspCertId(
			response.certId.hashAlgorithmOid,
			issuer,
			response.certId.serialNumberHex,
		);
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
		const request = normalizeOcspRequest(input.request);
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

/**
 * Verifies OCSP response failure result.
 *
 * @param code The code value.
 * @param message The message value.
 * @returns The verification result.
 */
function verifyOcspResponseFailureResult(
	code: 'signature_invalid',
	message: string,
): VerifyOcspResponseFailureResult {
	const error: VerifyOcspResponseFailure = {
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
 * Validates OCSP response failure result.
 *
 * @param code The code value.
 * @param message The message value.
 * @returns The validation result.
 */
function validateOcspResponseFailureResult(
	code: ValidateOcspResponseFailureResult['code'],
	message: string,
): ValidateOcspResponseFailureResult {
	const error: ValidateOcspResponseFailure = {
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
 * Normalizes OCSP response.
 *
 * @param response The response input.
 * @returns The computed value.
 */
function normalizeOcspResponse(
	response: string | Uint8Array | ParsedOcspResponse,
): ParsedOcspResponse {
	if (typeof response === 'string') {
		return parseOcspResponsePem(response);
	}
	if (response instanceof Uint8Array) {
		return parseOcspResponseDer(response);
	}
	return response;
}

/**
 * Normalizes OCSP request.
 *
 * @param request The request input.
 * @returns The computed value.
 */
function normalizeOcspRequest(request: OcspRequestSource): ParsedOcspRequest {
	if (typeof request === 'string') {
		return parseOcspRequestPem(request);
	}
	if (request instanceof Uint8Array) {
		return parseOcspRequestDer(request);
	}
	return request;
}

/**
 * Finds matching OCSP responder certificate.
 *
 * @param certificates The certificate inputs.
 * @param responderId The responder id value.
 * @returns The matching matching OCSP responder certificate.
 */
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

/**
 * Validates OCSP responder id binding.
 *
 * @param responderId The responder id value.
 * @param signer The signer value.
 * @returns The validation result.
 */
async function validateOcspResponderIdBinding(
	responderId: ParsedOcspResponderId | undefined,
	signer: ParsedCertificate,
): Promise<
	| Extract<
			ValidateOcspResponseResult,
			{
				/**
				 * Indicates whether the operation succeeded.
				 */
				readonly ok: false;
			}
	  >
	| {
			/**
			 * Indicates whether the operation succeeded.
			 */
			readonly ok: true;
	  }
> {
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

/**
 * Matches es OCSP responder id.
 *
 * @param responderId The responder id value.
 * @param certificate The certificate input.
 * @returns The computed value.
 */
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

/**
 * Returns whether same OCSP certificate.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns Whether the condition holds.
 */
function isSameOcspCertificate(left: ParsedCertificate, right: ParsedCertificate): boolean {
	return (
		left.serialNumberHex === right.serialNumberHex &&
		left.issuer.derHex === right.issuer.derHex &&
		left.subject.derHex === right.subject.derHex &&
		left.subjectPublicKeyInfoDer.length === right.subjectPublicKeyInfoDer.length &&
		left.subjectPublicKeyInfoDer.every(
			(byte, index) => byte === right.subjectPublicKeyInfoDer[index],
		)
	);
}

/**
 * Returns whether directly issued by OCSP issuer.
 *
 * @param signer The signer value.
 * @param issuer The issuer value.
 * @returns Whether the condition holds.
 */
function isDirectlyIssuedByOcspIssuer(
	signer: ParsedCertificate,
	issuer: ParsedCertificate,
): boolean {
	if (signer.issuer.derHex !== issuer.subject.derHex) {
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

/**
 * Builds OCSP responder intermediates.
 *
 * @param certificates The certificate inputs.
 * @param signer The signer value.
 * @param issuer The issuer value.
 * @returns The built OCSP responder intermediates.
 */
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

/**
 * Encodes OCSP cert id.
 *
 * @param certificate The certificate input.
 * @param issuer The issuer value.
 * @param hashAlgorithm The hash algorithm value.
 * @returns The encoded OCSP cert id.
 */
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

/**
 * Builds parsed OCSP cert id.
 *
 * @param hashAlgorithmOid The hash algorithm OID value.
 * @param issuer The issuer value.
 * @param serialNumberHex The serial number hex value.
 * @returns The built parsed OCSP cert id.
 */
async function buildParsedOcspCertId(
	hashAlgorithmOid: string,
	issuer: ParsedCertificate,
	serialNumberHex: string,
): Promise<ParsedOcspCertId> {
	const hashAlgorithm = ocspHashAlgorithmFromOid(hashAlgorithmOid);
	return {
		hashAlgorithmOid,
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

/**
 * Digest bytes.
 *
 * @param algorithm The algorithm configuration.
 * @param bytes The raw bytes to process.
 * @returns The computed value.
 */
async function digestBytes(algorithm: OcspHashAlgorithm, bytes: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await getCrypto().subtle.digest(algorithm, toArrayBuffer(bytes)));
}

/**
 * Encodes single response.
 *
 * @param certificate The certificate input.
 * @param issuer The issuer value.
 * @param input The typed input payload.
 * @param hashAlgorithm The hash algorithm value.
 * @returns The encoded single response.
 */
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

/**
 * Encodes OCSP cert status.
 *
 * @param input The typed input payload.
 * @returns The encoded OCSP cert status.
 */
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

/**
 * Normalizes certificate.
 *
 * @param source The source value to process.
 * @returns The computed value.
 */
async function normalizeCertificate(source: OcspCertificateSource): Promise<ParsedCertificate> {
	if (typeof source === 'string') {
		return parseCertificatePem(source);
	}
	if (hasParsedCertificateShape(source)) {
		return source;
	}
	return parseCertificateDer(source);
}

/**
 * Returns whether parsed certificate shape.
 *
 * @param value The value to process.
 * @returns Whether the condition holds.
 */
function hasParsedCertificateShape(value: OcspCertificateSource): value is ParsedCertificate {
	return typeof value !== 'string' && 'subjectPublicKeyInfoDer' in value;
}

/**
 * Parses OCSP cert id.
 *
 * @param der The DER-encoded bytes.
 * @returns The parsed OCSP cert id.
 */
function parseOcspCertId(der: Uint8Array): ParsedOcspCertId {
	const children = childrenOf(der, readElement(der));
	const hashAlgorithm = requireElement(children[0], 'hashAlgorithm');
	const algorithmChildren = childrenOf(der, hashAlgorithm);
	const algorithmOid = requireElement(algorithmChildren[0], 'hashAlgorithm OID');
	return {
		hashAlgorithmOid: decodeObjectIdentifier(algorithmOid.value),
		issuerNameHashHex: toHex(requireElement(children[1], 'issuerNameHash').value),
		issuerKeyHashHex: toHex(requireElement(children[2], 'issuerKeyHash').value),
		serialNumberHex: toHex(requireElement(children[3], 'serialNumber').value),
	};
}

/**
 * Parses single response.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed single response.
 */
function parseSingleResponse(source: Uint8Array, element: DerElement): ParsedOcspSingleResponse {
	const children = childrenOf(source, element);
	const certId = requireElement(children[0], 'certId');
	const certStatus = requireElement(children[1], 'certStatus');
	const thisUpdate = requireElement(children[2], 'thisUpdate');
	const nextUpdateElement = children[3]?.tag === 0xa0 ? children[3] : undefined;
	let revokedAt: Date | undefined;
	let revocationReasonCode: number | undefined;
	if (certStatus.tag === 0xa1) {
		const revokedInfo = childrenOf(source, certStatus);
		revokedAt = parseTime(requireElement(revokedInfo[0], 'revocationTime'));
		const reason = revokedInfo[1];
		if (reason?.tag === 0xa0) {
			revocationReasonCode = readElement(source, reason.start).value[0];
		}
	}
	return {
		certId: parseOcspCertId(source.slice(certId.start - certId.headerLength, certId.end)),
		certStatus: certStatus.tag === 0x80 ? 'good' : certStatus.tag === 0x82 ? 'unknown' : 'revoked',
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

/**
 * Parses OCSP responder id.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed OCSP responder id.
 */
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

/**
 * Parses responder name.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed responder name.
 */
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

/**
 * Parses responder name attribute set.
 *
 * @param source The source value to process.
 * @param setElement The set element value.
 * @returns The parsed responder name attribute set.
 */
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

/**
 * Compares OCSP responder names.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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

/**
 * Compares OCSP relative distinguished names.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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

/**
 * Compares OCSP name attribute value.
 *
 * @param left The left value.
 * @param right The right value.
 * @returns The computed value.
 */
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

/**
 * Returns whether OCSP directory string tag.
 *
 * @param tag The tag value.
 * @returns Whether the condition holds.
 */
function isOcspDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

/**
 * Prepare OCSP name compare string.
 *
 * @param value The value to process.
 * @returns The computed value.
 */
function prepareOcspNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

/**
 * Responder name key from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
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

/**
 * Parses OCSP nonce from extensions.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed OCSP nonce from extensions.
 */
function parseOcspNonceFromExtensions(source: Uint8Array, element: DerElement): string | undefined {
	const extensionsSequence = requireElement(childrenOf(source, element)[0], 'extensions');
	for (const extension of childrenOf(source, extensionsSequence)) {
		const parts = childrenOf(source, extension);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'extension OID').value);
		if (oid !== OIDS.ocspNonce) {
			continue;
		}
		const extnValue = requireElement(parts[parts.length - 1], 'extnValue');
		return toHex(readElement(extnValue.value).value);
	}
	return undefined;
}

/**
 * Parses embedded certificates.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed embedded certificates.
 */
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

/**
 * Extract subject public key bytes.
 *
 * @param spkiDer The SPKI DER value.
 * @returns The computed value.
 */
function extractSubjectPublicKeyBytes(spkiDer: Uint8Array): Uint8Array {
	const top = childrenOf(spkiDer, readElement(spkiDer));
	const bitStringElement = requireElement(top[1], 'subjectPublicKey BIT STRING');
	if (bitStringElement.tag !== 0x03) {
		throw new Error('SPKI missing subjectPublicKey BIT STRING');
	}
	return bitStringElement.value.slice(1);
}

/**
 * OCSP response status from code.
 *
 * @param code The code value.
 * @returns The computed value.
 */
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
			return 'internalError';
	}
}

/**
 * OCSP hash algorithm from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
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

/**
 * Serialize cert id.
 *
 * @param certId The cert id value.
 * @returns The computed value.
 */
function serializeCertId(certId: ParsedOcspCertId): string {
	return [
		certId.hashAlgorithmOid,
		certId.issuerNameHashHex,
		certId.issuerKeyHashHex,
		certId.serialNumberHex,
	].join(':');
}
