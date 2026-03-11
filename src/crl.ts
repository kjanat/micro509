import { createHash } from "node:crypto";
import {
	bitString,
	bool,
	type DerElement,
	explicitContext,
	generalizedTime,
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
import { exportSpkiDer, getCrypto, importSpkiDer, type PublicKeyImportInput } from "./keys.ts";
import { encodeName, type NameInput } from "./name.ts";
import { OIDS } from "./oids.ts";
import { parseCertificateDer, parseCertificatePem, type ParsedCertificate } from "./parse.ts";
import { base64Encode, pemDecode, pemEncode } from "./pem.ts";
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
	readonly issuingDistributionPointUri?: string;
	readonly freshestCrlUris?: readonly string[];
	readonly revokedCertificates: readonly ParsedRevokedCertificate[];
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
	let issuingDistributionPointUri: string | undefined;
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
				issuingDistributionPointUri = parseIssuingDistributionPoint(
					valueElement.value,
				);
			}
			if (oid === OIDS.freshestCRL) {
				freshestCrlUris = parseDistributionPointUris(valueElement.value);
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
		...(issuingDistributionPointUri === undefined
			? {}
			: { issuingDistributionPointUri }),
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
	const config = getVerifySignatureConfig(
		parsedCrl.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
	);
	const key = await importSpkiDer(
		issuer.subjectPublicKeyInfoDer,
		config.importAlgorithm,
	);
	const subtle = getCrypto().subtle;
	const signatureView = toArrayBuffer(parsedCrl.signatureValue);
	const dataView = toArrayBuffer(parsedCrl.tbsCertListDer);
	if (await subtle.verify(config.verifyParams, key, signatureView, dataView)) {
		return { ok: true, value: parsedCrl };
	}
	if (config.ecdsaRawSignatureBytes !== undefined) {
		const alternate = alternateEcdsaSignatureEncoding(
			parsedCrl.signatureValue,
			config.ecdsaRawSignatureBytes / 2,
		);
		if (
			alternate !== undefined
			&& (await subtle.verify(
				config.verifyParams,
				key,
				toArrayBuffer(alternate),
				dataView,
			))
		) {
			return { ok: true, value: parsedCrl };
		}
	}
	return {
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
					explicitContext(
						0,
						explicitContext(
							0,
							sequence([
								tlv(
									0x86,
									new TextEncoder().encode(issuingDistributionPointUri),
								),
							]),
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
): string | undefined {
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
		for (
			const generalName of childrenOf(
				valueDer,
				requireElement(
					childrenOf(valueDer, distributionPointName)[0],
					"fullName",
				),
			)
		) {
			if (generalName.tag === 0x86) {
				return textDecoder.decode(generalName.value);
			}
		}
	}
	return undefined;
}

function parseDistributionPointUris(valueDer: Uint8Array): readonly string[] {
	const sequenceElement = readElement(valueDer);
	const uris: string[] = [];
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
			const fullName = requireElement(
				childrenOf(valueDer, distributionPointName)[0],
				"fullName",
			);
			for (const generalName of childrenOf(valueDer, fullName)) {
				if (generalName.tag === 0x86) {
					uris.push(textDecoder.decode(generalName.value));
				}
			}
		}
	}
	return uris;
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

function parseTime(element: DerElement): Date {
	const value = textDecoder.decode(element.value);
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

function extractBitStringValue(element: DerElement): Uint8Array {
	if (element.tag !== 0x03) {
		throw new Error("Expected BIT STRING");
	}
	return element.value.slice(1);
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

function decodeIntegerNumber(bytes: Uint8Array): number {
	let value = 0;
	for (const byte of bytes) {
		value = (value << 8) | byte;
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

function getVerifySignatureConfig(
	signatureAlgorithmOid: string,
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): {
	readonly importAlgorithm: PublicKeyImportInput;
	readonly verifyParams: Algorithm | EcdsaParams;
	readonly ecdsaRawSignatureBytes?: number;
} {
	switch (signatureAlgorithmOid) {
		case OIDS.sha256WithRSAEncryption:
			return {
				importAlgorithm: requireRsa(publicKeyAlgorithmOid, "SHA-256"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha384WithRSAEncryption:
			return {
				importAlgorithm: requireRsa(publicKeyAlgorithmOid, "SHA-384"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.sha512WithRSAEncryption:
			return {
				importAlgorithm: requireRsa(publicKeyAlgorithmOid, "SHA-512"),
				verifyParams: { name: "RSASSA-PKCS1-v1_5" },
			};
		case OIDS.ecdsaWithSHA256:
			return {
				importAlgorithm: requireEc(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-256" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ecdsaWithSHA384:
			return {
				importAlgorithm: requireEc(
					publicKeyAlgorithmOid,
					publicKeyParametersOid,
				),
				verifyParams: { name: "ECDSA", hash: "SHA-384" },
				ecdsaRawSignatureBytes: curveBytes(publicKeyParametersOid),
			};
		case OIDS.ed25519:
			if (publicKeyAlgorithmOid !== OIDS.ed25519) {
				throw new Error("Ed25519 signature requires Ed25519 issuer public key");
			}
			return {
				importAlgorithm: { kind: "ed25519" },
				verifyParams: { name: "Ed25519" },
			};
		default:
			throw new Error(
				`Unsupported signature algorithm OID: ${signatureAlgorithmOid}`,
			);
	}
}

function requireRsa(
	publicKeyAlgorithmOid: string,
	hash: "SHA-256" | "SHA-384" | "SHA-512",
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.rsaEncryption) {
		throw new Error("RSA signature requires RSA public key");
	}
	return { kind: "rsa", hash };
}

function requireEc(
	publicKeyAlgorithmOid: string,
	publicKeyParametersOid: string | undefined,
): PublicKeyImportInput {
	if (publicKeyAlgorithmOid !== OIDS.ecPublicKey) {
		throw new Error("ECDSA signature requires EC public key");
	}
	switch (publicKeyParametersOid) {
		case OIDS.prime256v1:
			return { kind: "ecdsa", namedCurve: "P-256" };
		case OIDS.secp384r1:
			return { kind: "ecdsa", namedCurve: "P-384" };
		default:
			throw new Error(
				`Unsupported EC curve OID: ${publicKeyParametersOid ?? "missing"}`,
			);
	}
}

function curveBytes(parametersOid: string | undefined): number {
	switch (parametersOid) {
		case OIDS.prime256v1:
			return 64;
		case OIDS.secp384r1:
			return 96;
		default:
			throw new Error(
				`Unsupported EC curve OID: ${parametersOid ?? "missing"}`,
			);
	}
}

function derEcdsaSignatureToRaw(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	const parts = readSequenceChildren(signature);
	const r = parts[0];
	const s = parts[1];
	if (r === undefined || s === undefined) {
		throw new Error("Malformed ECDSA DER signature");
	}
	return concatFixedWidth(
		trimLeadingZero(r.value),
		trimLeadingZero(s.value),
		partLength,
	);
}

function rawEcdsaSignatureToDer(
	signature: Uint8Array,
	partLength: number,
): Uint8Array {
	if (signature.length !== partLength * 2) {
		throw new Error("Unexpected ECDSA raw signature length");
	}
	return sequence([
		integer(signature.slice(0, partLength)),
		integer(signature.slice(partLength)),
	]);
}

function alternateEcdsaSignatureEncoding(
	signature: Uint8Array,
	partLength: number,
): Uint8Array | undefined {
	try {
		if (signature[0] === 0x30) {
			return new Uint8Array(derEcdsaSignatureToRaw(signature, partLength));
		}
		return new Uint8Array(rawEcdsaSignatureToDer(signature, partLength));
	} catch {
		return undefined;
	}
}

function trimLeadingZero(bytes: Uint8Array): Uint8Array {
	let index = 0;
	while (index < bytes.length - 1 && bytes[index] === 0) {
		index += 1;
	}
	return bytes.slice(index);
}

function concatFixedWidth(
	left: Uint8Array,
	right: Uint8Array,
	partLength: number,
): Uint8Array {
	if (left.length > partLength || right.length > partLength) {
		throw new Error("ECDSA signature integer too large");
	}
	const out = new Uint8Array(partLength * 2);
	out.set(left, partLength - left.length);
	out.set(right, out.length - right.length);
	return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const out = new ArrayBuffer(bytes.length);
	new Uint8Array(out).set(bytes);
	return out;
}

const textDecoder = new TextDecoder();
