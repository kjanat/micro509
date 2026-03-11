import {
	type DerElement,
	explicitContext,
	integer,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
} from "./der.ts";
import { getCrypto } from "./keys.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, parseCertificatePem, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemDecode, pemEncode } from "./pem.ts";

export type OcspHashAlgorithm = "SHA-1" | "SHA-256";
export type OcspCertificateSource = string | Uint8Array | ParsedCertificate;

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
	readonly producedAt?: Date;
	readonly responses?: readonly ParsedOcspSingleResponse[];
	readonly nonce?: string;
}

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
		producedAt: parseTime(producedAt),
		responses: childrenOf(responseDataDer, responses).map((singleResponse) =>
			parseSingleResponse(responseDataDer, singleResponse)
		),
		...(nonce === undefined ? {} : { nonce }),
	};
}

export function parseOcspResponsePem(pem: string): ParsedOcspResponse {
	return parseOcspResponseDer(pemDecode("OCSP RESPONSE", pem));
}

async function encodeOcspCertId(
	certificate: ParsedCertificate,
	issuer: ParsedCertificate,
	hashAlgorithm: OcspHashAlgorithm,
): Promise<Uint8Array> {
	const hashAlgorithmOid = hashAlgorithm === "SHA-1" ? OIDS.sha1 : OIDS.sha256;
	return sequence([
		sequence([objectIdentifier(hashAlgorithmOid), nullValue()]),
		octetString(
			await digestBytes(hashAlgorithm, hexToBytes(issuer.subject.derHex)),
		),
		octetString(
			await digestBytes(
				hashAlgorithm,
				extractSubjectPublicKeyBytes(issuer.subjectPublicKeyInfoDer),
			),
		),
		integer(hexToBytes(certificate.serialNumberHex)),
	]);
}

async function digestBytes(
	algorithm: OcspHashAlgorithm,
	bytes: Uint8Array,
): Promise<Uint8Array> {
	return new Uint8Array(
		await getCrypto().subtle.digest(algorithm, toArrayBuffer(bytes)),
	);
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

function parseTime(element: DerElement): Date {
	const value = new TextDecoder().decode(element.value);
	if (element.tag === 0x17) {
		const prefix = Number.parseInt(value.slice(0, 2), 10) >= 50 ? "19" : "20";
		return new Date(
			`${prefix}${value.slice(0, 2)}-${value.slice(2, 4)}-${value.slice(4, 6)}T${value.slice(6, 8)}:${
				value.slice(
					8,
					10,
				)
			}:${value.slice(10, 12)}Z`,
		);
	}
	if (element.tag === 0x18) {
		return new Date(
			`${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${
				value.slice(
					12,
					14,
				)
			}Z`,
		);
	}
	throw new Error(`Unsupported time tag: ${element.tag}`);
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

function childrenOf(source: Uint8Array, parent: DerElement): DerElement[] {
	const children: DerElement[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		children.push(child);
		offset = child.end;
	}
	return children;
}

function requireElement<T>(value: T | undefined, label: string): T {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}

function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error("OID is empty");
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error("Malformed OID");
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join(".");
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
		"",
	);
}

function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const out = new Uint8Array(normalized.length / 2);
	for (let index = 0; index < out.length; index += 1) {
		out[index] = Number.parseInt(
			normalized.slice(index * 2, index * 2 + 2),
			16,
		);
	}
	return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}
