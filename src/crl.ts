import { createHash } from "node:crypto";
import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from "./asn1.ts";
import {
	bitString,
	bool,
	type DerElement,
	explicitContext,
	generalizedTime,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integer,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	time,
	tlv,
} from "./der.ts";
import { encodeCrlDistributionPoints } from "./extensions.ts";
import { exportSpkiDer } from "./keys.ts";
import { encodeName, type NameInput } from "./name.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, parseCertificatePem, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemDecode, pemEncode } from "./pem.ts";
import { verifySignedData } from "./sig-verify.ts";
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from "./signing.ts";

export interface RevokedCertificateInput {
	readonly serialNumber: Uint8Array;
	readonly revocationDate?: Date;
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
}

export type RevocationReason =
	| "unspecified"
	| "keyCompromise"
	| "cACompromise"
	| "affiliationChanged"
	| "superseded"
	| "cessationOfOperation"
	| "certificateHold"
	| "removeFromCRL"
	| "privilegeWithdrawn"
	| "aACompromise";

export interface CreateCertificateRevocationListInput {
	readonly issuer: NameInput;
	readonly signerPrivateKey: CryptoKey;
	readonly issuerPublicKey?: CryptoKey;
	readonly thisUpdate?: Date;
	readonly nextUpdate?: Date;
	readonly revokedCertificates?: readonly RevokedCertificateInput[];
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPointUri?: string;
	readonly freshestCrlUris?: readonly string[];
}

export interface CertificateRevocationListMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface ParsedRevokedCertificate {
	readonly serialNumberHex: string;
	readonly revocationDate: Date;
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
}

export interface ParsedCertificateRevocationList {
	readonly version: number;
	readonly tbsCertListDer: Uint8Array;
	readonly signatureValue: Uint8Array;
	readonly issuer: {
		readonly derHex: string;
		readonly commonName?: string;
	};
	readonly thisUpdate: Date;
	readonly nextUpdate?: Date;
	readonly signatureAlgorithmOid: string;
	readonly issuerPublicKeyAlgorithmOid?: string;
	readonly issuerPublicKeyParametersOid?: string;
	readonly authorityKeyIdentifier?: string;
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	readonly issuingDistributionPointUri?: string;
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly freshestCrlUris?: readonly string[];
	readonly revokedCertificates: readonly ParsedRevokedCertificate[];
}

export interface ParsedDistributionPoint {
	readonly fullNameUris: readonly string[];
}

export interface ParsedIssuingDistributionPoint {
	readonly distributionPoint?: ParsedDistributionPoint;
}

const REVOCATION_REASON_CODES: Record<RevocationReason, number> = {
	unspecified: 0,
	keyCompromise: 1,
	cACompromise: 2,
	affiliationChanged: 3,
	superseded: 4,
	cessationOfOperation: 5,
	certificateHold: 6,
	removeFromCRL: 8,
	privilegeWithdrawn: 9,
	aACompromise: 10,
};

export type VerifyCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| {
		readonly ok: false;
		readonly code: "signature_invalid";
		readonly message: string;
	};

export async function createCertificateRevocationList(
	input: CreateCertificateRevocationListInput,
): Promise<CertificateRevocationListMaterial> {
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const thisUpdate = input.thisUpdate ?? new Date();
	const nextUpdate = input.nextUpdate;
	const extensions = await buildCrlExtensions(
		input.issuerPublicKey,
		input.crlNumber,
		input.baseCrlNumber,
		input.issuingDistributionPointUri,
		input.freshestCrlUris,
	);
	const revoked = input.revokedCertificates ?? [];
	const revokedSequence = revoked.length === 0
		? []
		: [
			sequence(
				revoked.map((entry) => createRevokedCertificate(entry, thisUpdate)),
			),
		];
	const tbsCertList = sequence([
		integerFromNumber(1),
		encodeAlgorithmIdentifier(signatureAlgorithm),
		encodeName(input.issuer),
		time(thisUpdate),
		...(nextUpdate === undefined ? [] : [time(nextUpdate)]),
		...revokedSequence,
		...(extensions.length === 0
			? []
			: [explicitContext(0, sequence(extensions))]),
	]);
	const signatureValue = await signBytes(
		input.signerPrivateKey,
		signatureAlgorithm,
		tbsCertList,
	);
	const der = sequence([
		tbsCertList,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
	return {
		der,
		pem: pemEncode("X509 CRL", der),
		base64: base64Encode(der),
	};
}

export function parseCertificateRevocationListDer(
	der: Uint8Array,
): ParsedCertificateRevocationList {
	const top = childrenOf(der, readElement(der));
	const tbsCertList = requireElement(top[0], "TBSCertList");
	const signatureAlgorithm = requireElement(top[1], "signatureAlgorithm");
	const signatureValue = requireElement(top[2], "signatureValue");
	const tbsChildren = childrenOf(der, tbsCertList);
	let index = 0;
	let version = 1;
	if (tbsChildren[index]?.tag === 0x02) {
		version = decodeIntegerNumber(requireElement(tbsChildren[index], "version").value)
			+ 1;
		index += 1;
	}
	index += 1; // signature algorithm in TBS
	const issuer = requireElement(tbsChildren[index], "issuer");
	const thisUpdate = requireElement(tbsChildren[index + 1], "thisUpdate");
	let cursor = index + 2;
	const maybeNextUpdate = tbsChildren[cursor];
	const nextUpdate = maybeNextUpdate !== undefined
			&& (maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
		? parseTime(maybeNextUpdate)
		: undefined;
	if (nextUpdate !== undefined) {
		cursor += 1;
	}
	let revokedCertificates: readonly ParsedRevokedCertificate[] = [];
	const maybeRevoked = tbsChildren[cursor];
	if (maybeRevoked?.tag === 0x30) {
		revokedCertificates = childrenOf(der, maybeRevoked).map((entry) => {
			const entryDer = der.slice(entry.start - entry.headerLength, entry.end);
			const parts = readSequenceChildren(entryDer);
			const entryExtensions = parts[2];
			const parsedEntryExtensions = parseRevokedCertificateExtensions(
				entryDer,
				entryExtensions,
			);
			return {
				serialNumberHex: toHex(
					requireElement(parts[0], "revoked serialNumber").value,
				),
				revocationDate: parseTime(requireElement(parts[1], "revocationDate")),
				...(parsedEntryExtensions.reasonCode === undefined
					? {}
					: { reasonCode: parsedEntryExtensions.reasonCode }),
				...(parsedEntryExtensions.invalidityDate === undefined
					? {}
					: { invalidityDate: parsedEntryExtensions.invalidityDate }),
			};
		});
		cursor += 1;
	}
	let authorityKeyIdentifier: string | undefined;
	let crlNumber: number | undefined;
	let baseCrlNumber: number | undefined;
	let issuingDistributionPoint: ParsedIssuingDistributionPoint | undefined;
	let issuingDistributionPointUri: string | undefined;
	let freshestCrlDistributionPoints:
		| readonly ParsedDistributionPoint[]
		| undefined;
	let freshestCrlUris: readonly string[] | undefined;
	const maybeExtensions = tbsChildren[cursor];
	if (maybeExtensions?.tag === 0xa0) {
		const extensionSequence = requireElement(
			childrenOf(der, maybeExtensions)[0],
			"crl extensions",
		);
		for (const extension of childrenOf(der, extensionSequence)) {
			const parts = childrenOf(der, extension);
			const oid = decodeObjectIdentifier(
				requireElement(parts[0], "extension OID").value,
			);
			const valueElement = requireElement(
				parts[parts.length - 1],
				"extension value",
			);
			if (oid === OIDS.authorityKeyIdentifier) {
				authorityKeyIdentifier = parseAuthorityKeyIdentifier(
					valueElement.value,
				);
			}
			if (oid === OIDS.cRLNumber) {
				crlNumber = decodeIntegerNumber(readElement(valueElement.value).value);
			}
			if (oid === OIDS.deltaCRLIndicator) {
				baseCrlNumber = decodeIntegerNumber(
					readElement(valueElement.value).value,
				);
			}
			if (oid === OIDS.issuingDistributionPoint) {
				issuingDistributionPoint = parseIssuingDistributionPoint(
					valueElement.value,
				);
				issuingDistributionPointUri = issuingDistributionPoint.distributionPoint?.fullNameUris[0];
			}
			if (oid === OIDS.freshestCRL) {
				freshestCrlDistributionPoints = parseDistributionPoints(
					valueElement.value,
				);
				freshestCrlUris = freshestCrlDistributionPoints.flatMap(
					(entry) => entry.fullNameUris,
				);
			}
		}
	}
	return {
		version,
		tbsCertListDer: der.slice(
			tbsCertList.start - tbsCertList.headerLength,
			tbsCertList.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseIssuer(der, issuer),
		thisUpdate: parseTime(thisUpdate),
		...(nextUpdate === undefined ? {} : { nextUpdate }),
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm)
			.oid,
		...(authorityKeyIdentifier === undefined ? {} : { authorityKeyIdentifier }),
		...(crlNumber === undefined ? {} : { crlNumber }),
		...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
		...(issuingDistributionPoint === undefined
			? {}
			: { issuingDistributionPoint }),
		...(issuingDistributionPointUri === undefined
			? {}
			: { issuingDistributionPointUri }),
		...(freshestCrlDistributionPoints === undefined
			? {}
			: { freshestCrlDistributionPoints }),
		...(freshestCrlUris === undefined ? {} : { freshestCrlUris }),
		revokedCertificates,
	};
}

export function parseCertificateRevocationListPem(
	pem: string,
): ParsedCertificateRevocationList {
	return parseCertificateRevocationListDer(pemDecode("X509 CRL", pem));
}

export async function verifyCertificateRevocationList(
	crl: string | Uint8Array,
	issuerCertificate: string | Uint8Array,
): Promise<VerifyCertificateRevocationListResult> {
	const parsedCrl = typeof crl === "string"
		? parseCertificateRevocationListPem(crl)
		: parseCertificateRevocationListDer(new Uint8Array(crl));
	const issuer = typeof issuerCertificate === "string"
		? parseIssuerCertificatePem(issuerCertificate)
		: parseIssuerCertificateDer(new Uint8Array(issuerCertificate));
	const verified = await verifySignedData(
		parsedCrl.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		parsedCrl.signatureValue,
		parsedCrl.tbsCertListDer,
	);
	return verified
		? { ok: true, value: parsedCrl }
		: {
			ok: false,
			code: "signature_invalid",
			message: "certificate revocation list signature does not verify",
		};
}

export function isCertificateRevoked(
	certificateSerialNumber: Uint8Array | string,
	crl: ParsedCertificateRevocationList,
): boolean {
	const serialNumberHex = typeof certificateSerialNumber === "string"
		? normalizeHex(certificateSerialNumber)
		: toHex(certificateSerialNumber);
	return crl.revokedCertificates.some(
		(entry) => normalizeHex(entry.serialNumberHex) === serialNumberHex,
	);
}

async function buildCrlExtensions(
	issuerPublicKey: CryptoKey | undefined,
	crlNumber: number | undefined,
	baseCrlNumber?: number,
	issuingDistributionPointUri?: string,
	freshestCrlUris?: readonly string[],
): Promise<Uint8Array[]> {
	const extensions: Uint8Array[] = [];
	if (issuerPublicKey !== undefined) {
		const spki = await exportSpkiDer(issuerPublicKey);
		extensions.push(
			encodeExtension(
				OIDS.authorityKeyIdentifier,
				sequence([
					implicitPrimitiveContext(0, buildSubjectKeyIdentifier(spki)),
				]),
			),
		);
	}
	if (crlNumber !== undefined) {
		extensions.push(
			encodeExtension(OIDS.cRLNumber, integerFromNumber(crlNumber)),
		);
	}
	if (baseCrlNumber !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.deltaCRLIndicator,
				integerFromNumber(baseCrlNumber),
				true,
			),
		);
	}
	if (issuingDistributionPointUri !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.issuingDistributionPoint,
				sequence([
					implicitConstructedContext(
						0,
						implicitConstructedContext(
							0,
							tlv(0x86, new TextEncoder().encode(issuingDistributionPointUri)),
						),
					),
				]),
				true,
			),
		);
	}
	if (freshestCrlUris !== undefined && freshestCrlUris.length > 0) {
		extensions.push(
			encodeExtension(
				OIDS.freshestCRL,
				encodeCrlDistributionPoints(freshestCrlUris),
			),
		);
	}
	return extensions;
}

function createRevokedCertificate(
	entry: RevokedCertificateInput,
	thisUpdate: Date,
): Uint8Array {
	const extensions = buildRevokedCertificateExtensions(entry);
	return sequence([
		integer(entry.serialNumber),
		time(entry.revocationDate ?? thisUpdate),
		...(extensions.length === 0 ? [] : [sequence(extensions)]),
	]);
}

function buildRevokedCertificateExtensions(
	entry: RevokedCertificateInput,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	if (entry.reasonCode !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.cRLReason,
				tlv(0x0a, Uint8Array.of(REVOCATION_REASON_CODES[entry.reasonCode])),
			),
		);
	}
	if (entry.invalidityDate !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.invalidityDate,
				generalizedTime(entry.invalidityDate),
			),
		);
	}
	return extensions;
}

function parseRevokedCertificateExtensions(
	entryDer: Uint8Array | undefined,
	element: DerElement | undefined,
): { readonly reasonCode?: RevocationReason; readonly invalidityDate?: Date } {
	if (entryDer === undefined || element === undefined) {
		return {};
	}
	let reasonCode: RevocationReason | undefined;
	let invalidityDate: Date | undefined;
	for (const extension of childrenOf(entryDer, element)) {
		const parts = childrenOf(entryDer, extension);
		const oid = decodeObjectIdentifier(
			requireElement(parts[0], "revoked certificate extension OID").value,
		);
		const valueElement = requireElement(
			parts[parts.length - 1],
			"revoked certificate extension value",
		);
		if (oid === OIDS.cRLReason) {
			reasonCode = revocationReasonFromCode(
				readElement(valueElement.value).value[0],
			);
		}
		if (oid === OIDS.invalidityDate) {
			invalidityDate = parseTime(readElement(valueElement.value));
		}
	}
	return {
		...(reasonCode === undefined ? {} : { reasonCode }),
		...(invalidityDate === undefined ? {} : { invalidityDate }),
	};
}

function parseIssuingDistributionPoint(
	valueDer: Uint8Array,
): ParsedIssuingDistributionPoint {
	const sequenceElement = readElement(valueDer);
	for (const child of childrenOf(valueDer, sequenceElement)) {
		if (child.tag !== 0xa0) {
			continue;
		}
		const distributionPointName = requireElement(
			childrenOf(valueDer, child)[0],
			"distributionPointName",
		);
		if (distributionPointName.tag !== 0xa0) {
			continue;
		}
		return {
			distributionPoint: parseDistributionPointName(
				valueDer,
				distributionPointName,
			),
		};
	}
	return {};
}

function parseDistributionPoints(
	valueDer: Uint8Array,
): readonly ParsedDistributionPoint[] {
	const sequenceElement = readElement(valueDer);
	const points: ParsedDistributionPoint[] = [];
	for (const distributionPoint of childrenOf(valueDer, sequenceElement)) {
		for (const child of childrenOf(valueDer, distributionPoint)) {
			if (child.tag !== 0xa0) {
				continue;
			}
			const distributionPointName = requireElement(
				childrenOf(valueDer, child)[0],
				"distributionPointName",
			);
			if (distributionPointName.tag !== 0xa0) {
				continue;
			}
			points.push(parseDistributionPointName(valueDer, distributionPointName));
		}
	}
	return points;
}

function parseDistributionPointName(
	valueDer: Uint8Array,
	fullName: DerElement,
): ParsedDistributionPoint {
	const fullNameUris: string[] = [];
	for (const generalName of childrenOf(valueDer, fullName)) {
		if (generalName.tag === 0x86) {
			fullNameUris.push(textDecoder.decode(generalName.value));
		}
	}
	return { fullNameUris };
}

function encodeExtension(
	oid: string,
	value: Uint8Array,
	critical = false,
): Uint8Array {
	return sequence([
		objectIdentifier(oid),
		...(critical ? [bool(true)] : []),
		octetString(value),
	]);
}

function buildSubjectKeyIdentifier(spki: Uint8Array): Uint8Array {
	const top = readSequenceChildren(spki);
	const keyBitString = top[1];
	if (keyBitString === undefined || keyBitString.tag !== 0x03) {
		throw new Error("SPKI missing subject public key bit string");
	}
	return new Uint8Array(
		createHash("sha1").update(keyBitString.value.slice(1)).digest(),
	);
}

function parseIssuer(
	source: Uint8Array,
	element: DerElement,
): { readonly derHex: string; readonly commonName?: string } {
	let commonName: string | undefined;
	for (const setElement of childrenOf(source, element)) {
		const attribute = requireElement(
			childrenOf(source, setElement)[0],
			"issuer attribute",
		);
		const parts = childrenOf(source, attribute);
		const oid = decodeObjectIdentifier(
			requireElement(parts[0], "issuer attribute OID").value,
		);
		if (oid === OIDS.commonName) {
			commonName = textDecoder.decode(
				requireElement(parts[1], "issuer attribute value").value,
			);
		}
	}
	return {
		derHex: toHex(
			source.slice(element.start - element.headerLength, element.end),
		),
		...(commonName === undefined ? {} : { commonName }),
	};
}

function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = readElement(bytes);
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80 || child.tag === 0xa0) {
			return toHex(child.value);
		}
	}
	return undefined;
}

function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string } {
	const children = childrenOf(source, element);
	const oid = requireElement(children[0], "algorithm OID");
	return { oid: decodeObjectIdentifier(oid.value) };
}

function normalizeHex(value: string): string {
	return value.replace(/^0+/, "").toLowerCase();
}

function revocationReasonFromCode(
	code: number | undefined,
): RevocationReason | undefined {
	switch (code) {
		case 0:
			return "unspecified";
		case 1:
			return "keyCompromise";
		case 2:
			return "cACompromise";
		case 3:
			return "affiliationChanged";
		case 4:
			return "superseded";
		case 5:
			return "cessationOfOperation";
		case 6:
			return "certificateHold";
		case 8:
			return "removeFromCRL";
		case 9:
			return "privilegeWithdrawn";
		case 10:
			return "aACompromise";
	}
	return undefined;
}

function parseIssuerCertificateDer(der: Uint8Array): ParsedCertificate {
	return parseCertificateDer(der);
}

function parseIssuerCertificatePem(pem: string): ParsedCertificate {
	return parseCertificatePem(pem);
}

const textDecoder = new TextDecoder();
