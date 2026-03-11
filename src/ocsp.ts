import {
	childrenOf,
	decodeObjectIdentifier,
	extractBitStringValue,
	hexToBytes,
	parseTime,
	requireElement,
	toArrayBuffer,
	toHex,
} from "./asn1.ts";
import {
	bitString,
	concatBytes,
	type DerElement,
	explicitContext,
	implicitPrimitiveContext,
	integer,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
	setOf,
	time,
	tlv,
} from "./der.ts";
import { getCrypto } from "./keys.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, parseCertificatePem, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemDecode, pemEncode } from "./pem.ts";
import { verifySignedData } from "./sig-verify.ts";
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from "./signing.ts";
import { verifyCertificateChain } from "./verify.ts";

export type OcspHashAlgorithm = "SHA-1" | "SHA-256";
export type OcspCertificateSource = string | Uint8Array | ParsedCertificate;
export type OcspRequestSource = string | Uint8Array | ParsedOcspRequest;

export interface CreateOcspRequestItemInput {
	readonly certificate: OcspCertificateSource;
	readonly issuerCertificate: OcspCertificateSource;
}

export interface CreateOcspRequestInput {
	readonly requests: readonly CreateOcspRequestItemInput[];
	readonly hashAlgorithm?: OcspHashAlgorithm;
	readonly nonce?: Uint8Array;
}

export interface OcspRequestMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface ParsedOcspCertId {
	readonly hashAlgorithmOid: string;
	readonly issuerNameHashHex: string;
	readonly issuerKeyHashHex: string;
	readonly serialNumberHex: string;
}

export interface ParsedOcspRequest {
	readonly requests: readonly ParsedOcspCertId[];
	readonly nonce?: string;
}

export type OcspCertStatus = "good" | "revoked" | "unknown";
export type OcspResponseStatus =
	| "successful"
	| "malformedRequest"
	| "internalError"
	| "tryLater"
	| "sigRequired"
	| "unauthorized";

export interface ParsedOcspSingleResponse {
	readonly certId: ParsedOcspCertId;
	readonly certStatus: OcspCertStatus;
	readonly thisUpdate: Date;
	readonly nextUpdate?: Date;
	readonly revokedAt?: Date;
	readonly revocationReasonCode?: number;
}

export interface ParsedOcspResponse {
	readonly responseStatus: OcspResponseStatus;
	readonly responseTypeOid?: string;
	readonly responseDataDer?: Uint8Array;
	readonly signatureAlgorithmOid?: string;
	readonly signatureValue?: Uint8Array;
	readonly producedAt?: Date;
	readonly responses?: readonly ParsedOcspSingleResponse[];
	readonly nonce?: string;
	readonly certificates?: readonly ParsedCertificate[];
}

export interface CreateOcspSingleResponseInput extends CreateOcspRequestItemInput {
	readonly certStatus: OcspCertStatus;
	readonly thisUpdate?: Date;
	readonly nextUpdate?: Date;
	readonly revokedAt?: Date;
	readonly revocationReasonCode?: number;
}

export interface CreateOcspResponseInput {
	readonly signerPrivateKey: CryptoKey;
	readonly signerCertificate: OcspCertificateSource;
	readonly responses: readonly CreateOcspSingleResponseInput[];
	readonly producedAt?: Date;
	readonly nonce?: Uint8Array;
	readonly hashAlgorithm?: OcspHashAlgorithm;
	readonly includedCertificates?: readonly OcspCertificateSource[];
}

export interface OcspResponseMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export type VerifyOcspResponseResult =
	| { readonly ok: true; readonly value: ParsedOcspResponse }
	| {
		readonly ok: false;
		readonly code: "signature_invalid";
		readonly message: string;
	};

export interface ValidateOcspResponseInput {
	readonly response: string | Uint8Array | ParsedOcspResponse;
	readonly issuerCertificate: OcspCertificateSource;
	readonly request?: OcspRequestSource;
	readonly responderCertificate?: OcspCertificateSource;
	readonly at?: Date;
}

export type ValidateOcspResponseResult =
	| { readonly ok: true; readonly value: ParsedOcspResponse }
	| {
		readonly ok: false;
		readonly code:
			| "response_status_invalid"
			| "signature_invalid"
			| "nonce_mismatch"
			| "request_mismatch"
			| "issuer_mismatch"
			| "responder_chain_invalid"
			| "ocsp_signing_missing"
			| "stale_response";
		readonly message: string;
	};

export async function createOcspRequest(
	input: CreateOcspRequestInput,
): Promise<OcspRequestMaterial> {
	const hashAlgorithm = input.hashAlgorithm ?? "SHA-1";
	const requestEntries: Uint8Array[] = [];
	for (const request of input.requests) {
		const certificate = await normalizeCertificate(request.certificate);
		const issuer = await normalizeCertificate(request.issuerCertificate);
		requestEntries.push(
			sequence([await encodeOcspCertId(certificate, issuer, hashAlgorithm)]),
		);
	}
	const tbsRequestFields: Uint8Array[] = [sequence(requestEntries)];
	if (input.nonce !== undefined) {
		tbsRequestFields.push(
			explicitContext(
				2,
				sequence([
					sequence([
						objectIdentifier(OIDS.ocspNonce),
						octetString(octetString(input.nonce)),
					]),
				]),
			),
		);
	}
	const der = sequence([sequence(tbsRequestFields)]);
	return {
		der,
		pem: pemEncode("OCSP REQUEST", der),
		base64: base64Encode(der),
	};
}

export function parseOcspRequestDer(der: Uint8Array): ParsedOcspRequest {
	const top = childrenOf(der, readElement(der));
	const tbsRequest = requireElement(top[0], "tbsRequest");
	const tbsChildren = childrenOf(der, tbsRequest);
	const requestList = requireElement(
		tbsChildren.find((child) => child.tag === 0x30),
		"requestList",
	);
	const requests = childrenOf(der, requestList).map((request) => {
		const certId = requireElement(childrenOf(der, request)[0], "reqCert");
		return parseOcspCertId(
			der.slice(certId.start - certId.headerLength, certId.end),
		);
	});
	const extensions = tbsChildren.find((child) => child.tag === 0xa2);
	const nonce = extensions === undefined
		? undefined
		: parseOcspNonceFromExtensions(der, extensions);
	return {
		requests,
		...(nonce === undefined ? {} : { nonce }),
	};
}

export function parseOcspRequestPem(pem: string): ParsedOcspRequest {
	return parseOcspRequestDer(pemDecode("OCSP REQUEST", pem));
}

export function parseOcspResponseDer(der: Uint8Array): ParsedOcspResponse {
	const top = childrenOf(der, readElement(der));
	const statusElement = requireElement(top[0], "responseStatus");
	const responseStatus = ocspResponseStatusFromCode(statusElement.value[0]);
	const responseBytes = top[1];
	if (responseBytes === undefined) {
		return { responseStatus };
	}
	const bytesSequence = requireElement(
		childrenOf(der, responseBytes)[0],
		"responseBytes",
	);
	const responseBytesChildren = childrenOf(der, bytesSequence);
	const responseType = requireElement(responseBytesChildren[0], "responseType");
	const response = requireElement(responseBytesChildren[1], "response");
	const responseTypeOid = decodeObjectIdentifier(responseType.value);
	if (responseTypeOid !== OIDS.ocspBasicResponse) {
		return { responseStatus, responseTypeOid };
	}
	const basicResponse = response.value;
	const basicChildren = childrenOf(basicResponse, readElement(basicResponse));
	const responseData = requireElement(basicChildren[0], "responseData");
	const signatureAlgorithm = requireElement(
		basicChildren[1],
		"signatureAlgorithm",
	);
	const signatureValue = requireElement(basicChildren[2], "signatureValue");
	const certificatesElement = basicChildren[3];
	const responseDataDer = basicResponse.slice(
		responseData.start - responseData.headerLength,
		responseData.end,
	);
	const responseDataChildren = childrenOf(
		responseDataDer,
		readElement(responseDataDer),
	);
	let index = 0;
	if (responseDataChildren[index]?.tag === 0xa0) {
		index += 1;
	}
	index += 1; // responderID
	const producedAt = requireElement(responseDataChildren[index], "producedAt");
	const responses = requireElement(
		responseDataChildren[index + 1],
		"responses",
	);
	const responseExtensions = responseDataChildren[index + 2];
	const nonce = responseExtensions === undefined
		? undefined
		: parseOcspNonceFromExtensions(responseDataDer, responseExtensions);
	return {
		responseStatus,
		responseTypeOid,
		responseDataDer,
		signatureAlgorithmOid: decodeObjectIdentifier(
			requireElement(
				childrenOf(basicResponse, signatureAlgorithm)[0],
				"signatureAlgorithm OID",
			).value,
		),
		signatureValue: extractBitStringValue(signatureValue),
		producedAt: parseTime(producedAt),
		responses: childrenOf(responseDataDer, responses).map((singleResponse) =>
			parseSingleResponse(responseDataDer, singleResponse)
		),
		...(nonce === undefined ? {} : { nonce }),
		...(certificatesElement?.tag === 0xa0
			? {
				certificates: parseEmbeddedCertificates(
					basicResponse,
					certificatesElement,
				),
			}
			: {}),
	};
}

export function parseOcspResponsePem(pem: string): ParsedOcspResponse {
	return parseOcspResponseDer(pemDecode("OCSP RESPONSE", pem));
}

export async function createOcspResponse(
	input: CreateOcspResponseInput,
): Promise<OcspResponseMaterial> {
	const signerCertificate = await normalizeCertificate(input.signerCertificate);
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const producedAt = input.producedAt ?? new Date();
	const hashAlgorithm = input.hashAlgorithm ?? "SHA-1";
	const responses: Uint8Array[] = [];
	for (const response of input.responses) {
		const certificate = await normalizeCertificate(response.certificate);
		const issuer = await normalizeCertificate(response.issuerCertificate);
		responses.push(
			await encodeSingleResponse(certificate, issuer, response, hashAlgorithm),
		);
	}
	const responderKeyHash = await digestBytes(
		hashAlgorithm,
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
					sequence([
						objectIdentifier(OIDS.ocspNonce),
						octetString(octetString(input.nonce)),
					]),
				]),
			),
		);
	}
	const responseData = sequence(responseDataFields);
	const signature = await signBytes(
		input.signerPrivateKey,
		signatureAlgorithm,
		responseData,
	);
	const includedCertificates = input.includedCertificates === undefined
		? []
		: await Promise.all(input.includedCertificates.map(normalizeCertificate));
	const basicResponseFields: Uint8Array[] = [
		responseData,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signature),
	];
	if (includedCertificates.length > 0) {
		basicResponseFields.push(
			explicitContext(
				0,
				concatBytes(includedCertificates.map((certificate) => certificate.der)),
			),
		);
	}
	const basicResponse = sequence(basicResponseFields);
	const der = sequence([
		tlv(0x0a, Uint8Array.of(0x00)),
		explicitContext(
			0,
			sequence([
				objectIdentifier(OIDS.ocspBasicResponse),
				octetString(basicResponse),
			]),
		),
	]);
	return {
		der,
		pem: pemEncode("OCSP RESPONSE", der),
		base64: base64Encode(der),
	};
}

export async function verifyOcspResponse(
	response: string | Uint8Array | ParsedOcspResponse,
	signerCertificate: OcspCertificateSource,
): Promise<VerifyOcspResponseResult> {
	const parsed = typeof response === "string"
		? parseOcspResponsePem(response)
		: response instanceof Uint8Array
		? parseOcspResponseDer(response)
		: response;
	if (
		parsed.responseDataDer === undefined
		|| parsed.signatureAlgorithmOid === undefined
		|| parsed.signatureValue === undefined
	) {
		return {
			ok: false,
			code: "signature_invalid",
			message: "OCSP response is not signed",
		};
	}
	const signer = await normalizeCertificate(signerCertificate);
	const verified = await verifySignedData(
		parsed.signatureAlgorithmOid,
		signer.publicKeyAlgorithmOid,
		signer.publicKeyParametersOid,
		signer.subjectPublicKeyInfoDer,
		parsed.signatureValue,
		parsed.responseDataDer,
	);
	return verified
		? { ok: true, value: parsed }
		: {
			ok: false,
			code: "signature_invalid",
			message: "OCSP response signature does not verify",
		};
}

export async function validateOcspResponse(
	input: ValidateOcspResponseInput,
): Promise<ValidateOcspResponseResult> {
	const parsedResponse = typeof input.response === "string"
		? parseOcspResponsePem(input.response)
		: input.response instanceof Uint8Array
		? parseOcspResponseDer(input.response)
		: input.response;
	if (parsedResponse.responseStatus !== "successful") {
		return {
			ok: false,
			code: "response_status_invalid",
			message: `OCSP response status is ${parsedResponse.responseStatus}`,
		};
	}
	const issuer = await normalizeCertificate(input.issuerCertificate);
	const resolvedResponder = input.responderCertificate
		?? parsedResponse.certificates?.[0]
		?? input.issuerCertificate;
	const signer = await normalizeCertificate(resolvedResponder);
	const signature = await verifyOcspResponse(parsedResponse, signer);
	if (!signature.ok) {
		return signature;
	}
	if (signer.subject.derHex !== issuer.subject.derHex) {
		if (
			typeof resolvedResponder === "string"
			|| resolvedResponder instanceof Uint8Array
		) {
			const chain = await verifyCertificateChain({
				leaf: resolvedResponder,
				intermediates: (parsedResponse.certificates ?? [])
					.slice(1)
					.map((certificate) => certificate.der),
				roots: [certificateSourceToInput(input.issuerCertificate)],
			});
			if (!chain.ok) {
				return {
					ok: false,
					code: "responder_chain_invalid",
					message: "OCSP responder certificate chain does not validate",
				};
			}
		}
		if (
			signer.extendedKeyUsage !== undefined
			&& !signer.extendedKeyUsage.includes("ocspSigning")
		) {
			return {
				ok: false,
				code: "ocsp_signing_missing",
				message: "Delegated OCSP responder lacks ocspSigning EKU",
			};
		}
	}
	const at = input.at ?? new Date();
	for (const response of parsedResponse.responses ?? []) {
		const expected = await buildParsedOcspCertId(
			response.certId.hashAlgorithmOid,
			issuer,
			response.certId.serialNumberHex,
		);
		if (
			response.certId.issuerNameHashHex !== expected.issuerNameHashHex
			|| response.certId.issuerKeyHashHex !== expected.issuerKeyHashHex
		) {
			return {
				ok: false,
				code: "issuer_mismatch",
				message: "OCSP response certId does not match issuer certificate",
			};
		}
		if (
			response.thisUpdate.getTime() > at.getTime()
			|| (response.nextUpdate !== undefined
				&& response.nextUpdate.getTime() < at.getTime())
		) {
			return {
				ok: false,
				code: "stale_response",
				message: "OCSP response is not valid at requested time",
			};
		}
	}
	if (input.request !== undefined) {
		const request = typeof input.request === "string"
			? parseOcspRequestPem(input.request)
			: input.request instanceof Uint8Array
			? parseOcspRequestDer(input.request)
			: input.request;
		if (request.nonce !== undefined && request.nonce !== parsedResponse.nonce) {
			return {
				ok: false,
				code: "nonce_mismatch",
				message: "OCSP response nonce does not match request nonce",
			};
		}
		const requestIds = new Set(
			request.requests.map((entry) => serializeCertId(entry)),
		);
		for (const response of parsedResponse.responses ?? []) {
			if (!requestIds.has(serializeCertId(response.certId))) {
				return {
					ok: false,
					code: "request_mismatch",
					message: "OCSP response includes a certId not present in request",
				};
			}
		}
	}
	return { ok: true, value: parsedResponse };
}

async function encodeOcspCertId(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
	hashAlgorithm: OcspHashAlgorithm,
): Promise<Uint8Array> {
	const hashAlgorithmOid = hashAlgorithm === "SHA-1" ? OIDS.sha1 : OIDS.sha256;
	const parsed = await buildParsedOcspCertId(
		hashAlgorithmOid,
		issuer,
		certificate.serialNumberHex,
	);
	return sequence([
		sequence([objectIdentifier(hashAlgorithmOid), nullValue()]),
		octetString(hexToBytes(parsed.issuerNameHashHex)),
		octetString(hexToBytes(parsed.issuerKeyHashHex)),
		integer(hexToBytes(parsed.serialNumberHex)),
	]);
}

async function buildParsedOcspCertId(
	hashAlgorithmOid: string,
	issuer: ParsedCertificate,
	serialNumberHex: string,
): Promise<ParsedOcspCertId> {
	const hashAlgorithm = ocspHashAlgorithmFromOid(hashAlgorithmOid);
	return {
		hashAlgorithmOid,
		issuerNameHashHex: toHex(
			await digestBytes(hashAlgorithm, hexToBytes(issuer.subject.derHex)),
		),
		issuerKeyHashHex: toHex(
			await digestBytes(
				hashAlgorithm,
				extractSubjectPublicKeyBytes(issuer.subjectPublicKeyInfoDer),
			),
		),
		serialNumberHex,
	};
}

async function digestBytes(
	algorithm: OcspHashAlgorithm,
	bytes: Uint8Array,
): Promise<Uint8Array> {
	return new Uint8Array(
		await getCrypto().subtle.digest(algorithm, toArrayBuffer(bytes)),
	);
}

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
		...(input.nextUpdate === undefined
			? []
			: [explicitContext(0, time(input.nextUpdate))]),
	]);
}

function encodeOcspCertStatus(
	input: CreateOcspSingleResponseInput,
): Uint8Array {
	switch (input.certStatus) {
		case "good":
			return tlv(0x80, new Uint8Array());
		case "unknown":
			return tlv(0x82, new Uint8Array());
		case "revoked": {
			const revokedFields: Uint8Array[] = [
				time(input.revokedAt ?? input.thisUpdate ?? new Date()),
			];
			if (input.revocationReasonCode !== undefined) {
				revokedFields.push(
					explicitContext(
						0,
						tlv(0x0a, Uint8Array.of(input.revocationReasonCode)),
					),
				);
			}
			return tlv(0xa1, concatBytes(revokedFields));
		}
	}
}

async function normalizeCertificate(
	source: OcspCertificateSource,
): Promise<ParsedCertificate> {
	if (typeof source === "string") {
		return parseCertificatePem(source);
	}
	if (hasParsedCertificateShape(source)) {
		return source;
	}
	return parseCertificateDer(source);
}

function hasParsedCertificateShape(
	value: OcspCertificateSource,
): value is ParsedCertificate {
	return typeof value !== "string" && "subjectPublicKeyInfoDer" in value;
}

function parseOcspCertId(der: Uint8Array): ParsedOcspCertId {
	const children = childrenOf(der, readElement(der));
	const hashAlgorithm = requireElement(children[0], "hashAlgorithm");
	const algorithmChildren = childrenOf(der, hashAlgorithm);
	const algorithmOid = requireElement(
		algorithmChildren[0],
		"hashAlgorithm OID",
	);
	return {
		hashAlgorithmOid: decodeObjectIdentifier(algorithmOid.value),
		issuerNameHashHex: toHex(
			requireElement(children[1], "issuerNameHash").value,
		),
		issuerKeyHashHex: toHex(requireElement(children[2], "issuerKeyHash").value),
		serialNumberHex: toHex(requireElement(children[3], "serialNumber").value),
	};
}

function parseSingleResponse(
	source: Uint8Array,
	element: DerElement,
): ParsedOcspSingleResponse {
	const children = childrenOf(source, element);
	const certId = requireElement(children[0], "certId");
	const certStatus = requireElement(children[1], "certStatus");
	const thisUpdate = requireElement(children[2], "thisUpdate");
	const nextUpdateElement = children[3]?.tag === 0xa0 ? children[3] : undefined;
	let revokedAt: Date | undefined;
	let revocationReasonCode: number | undefined;
	if (certStatus.tag === 0xa1) {
		const revokedInfo = childrenOf(source, certStatus);
		revokedAt = parseTime(requireElement(revokedInfo[0], "revocationTime"));
		const reason = revokedInfo[1];
		if (reason?.tag === 0xa0) {
			revocationReasonCode = readElement(source, reason.start).value[0];
		}
	}
	return {
		certId: parseOcspCertId(
			source.slice(certId.start - certId.headerLength, certId.end),
		),
		certStatus: certStatus.tag === 0x80
			? "good"
			: certStatus.tag === 0x82
			? "unknown"
			: "revoked",
		thisUpdate: parseTime(thisUpdate),
		...(nextUpdateElement === undefined
			? {}
			: {
				nextUpdate: parseTime(
					requireElement(
						childrenOf(source, nextUpdateElement)[0],
						"nextUpdate",
					),
				),
			}),
		...(revokedAt === undefined ? {} : { revokedAt }),
		...(revocationReasonCode === undefined ? {} : { revocationReasonCode }),
	};
}

function parseOcspNonceFromExtensions(
	source: Uint8Array,
	element: DerElement,
): string | undefined {
	const extensionsSequence = requireElement(
		childrenOf(source, element)[0],
		"extensions",
	);
	for (const extension of childrenOf(source, extensionsSequence)) {
		const parts = childrenOf(source, extension);
		const oid = decodeObjectIdentifier(
			requireElement(parts[0], "extension OID").value,
		);
		if (oid !== OIDS.ocspNonce) {
			continue;
		}
		const extnValue = requireElement(parts[parts.length - 1], "extnValue");
		return toHex(readElement(extnValue.value).value);
	}
	return undefined;
}

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

function extractSubjectPublicKeyBytes(spkiDer: Uint8Array): Uint8Array {
	const top = childrenOf(spkiDer, readElement(spkiDer));
	const bitStringElement = requireElement(
		top[1],
		"subjectPublicKey BIT STRING",
	);
	if (bitStringElement.tag !== 0x03) {
		throw new Error("SPKI missing subjectPublicKey BIT STRING");
	}
	return bitStringElement.value.slice(1);
}

function ocspResponseStatusFromCode(
	code: number | undefined,
): OcspResponseStatus {
	switch (code) {
		case 0:
			return "successful";
		case 1:
			return "malformedRequest";
		case 2:
			return "internalError";
		case 3:
			return "tryLater";
		case 5:
			return "sigRequired";
		case 6:
			return "unauthorized";
		default:
			return "internalError";
	}
}

function ocspHashAlgorithmFromOid(oid: string): OcspHashAlgorithm {
	switch (oid) {
		case OIDS.sha1:
			return "SHA-1";
		case OIDS.sha256:
			return "SHA-256";
		default:
			throw new Error(`Unsupported OCSP hash algorithm OID: ${oid}`);
	}
}

function serializeCertId(certId: ParsedOcspCertId): string {
	return [
		certId.hashAlgorithmOid,
		certId.issuerNameHashHex,
		certId.issuerKeyHashHex,
		certId.serialNumberHex,
	].join(":");
}

function certificateSourceToInput(
	source: OcspCertificateSource,
): string | Uint8Array {
	if (typeof source === "string" || source instanceof Uint8Array) {
		return source;
	}
	throw new Error(
		"Responder chain validation requires PEM or DER certificate input",
	);
}
