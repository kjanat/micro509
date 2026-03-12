import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from './asn1.ts';
import {
	bitString,
	bool,
	concatBytes,
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
} from './der.ts';
import {
	type DistributionPoint,
	type DistributionPointReason,
	encodeCrlDistributionPoints,
	encodeSubjectAltName,
	type GeneralName,
	type IssuingDistributionPoint,
} from './extensions.ts';
import { sha1 } from './hash.ts';
import { exportSpkiDer } from './keys.ts';
import {
	encodeName,
	encodeRelativeDistinguishedName,
	type NameFieldKey,
	type NameInput,
} from './name.ts';
import { OIDS } from './oids.ts';
import {
	type ParsedCertificate,
	type ParsedDistributionPoint,
	type ParsedDistributionPointName,
	type ParsedIssuingDistributionPoint,
	type ParsedNameAttribute,
	type ParsedRelativeDistinguishedName,
	parseCertificateDer,
	parseCertificatePem,
} from './parse.ts';
import { base64Encode, pemDecode, pemEncode } from './pem.ts';
import { verifySignedData } from './sig-verify.ts';
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from './signing.ts';

export interface RevokedCertificateInput {
	readonly serialNumber: Uint8Array;
	readonly revocationDate?: Date;
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
}

export type RevocationReason =
	| 'unspecified'
	| 'keyCompromise'
	| 'cACompromise'
	| 'affiliationChanged'
	| 'superseded'
	| 'cessationOfOperation'
	| 'certificateHold'
	| 'removeFromCRL'
	| 'privilegeWithdrawn'
	| 'aACompromise';

export interface CreateCertificateRevocationListInput {
	readonly issuer: NameInput;
	readonly signerPrivateKey: CryptoKey;
	readonly issuerPublicKey?: CryptoKey;
	readonly thisUpdate?: Date;
	readonly nextUpdate?: Date;
	readonly revokedCertificates?: readonly RevokedCertificateInput[];
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: IssuingDistributionPoint;
	readonly freshestCrlDistributionPoints?: readonly DistributionPoint[];
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
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
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

export type CrlSource = string | Uint8Array | ParsedCertificateRevocationList;
export type CrlCertificateSource = string | Uint8Array | ParsedCertificate;

export type VerifyCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| {
			readonly ok: false;
			readonly code: 'signature_invalid';
			readonly message: string;
	  };

export interface ValidateCertificateRevocationListInput {
	readonly crl: CrlSource;
	readonly issuerCertificate: CrlCertificateSource;
	readonly at?: Date;
	readonly clockSkewMs?: number;
}

export type ValidateCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| {
			readonly ok: false;
			readonly code: 'signature_invalid' | 'issuer_mismatch' | 'stale_crl';
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
		input.issuingDistributionPoint,
		input.freshestCrlDistributionPoints,
	);
	const revoked = input.revokedCertificates ?? [];
	const revokedSequence =
		revoked.length === 0
			? []
			: [sequence(revoked.map((entry) => createRevokedCertificate(entry, thisUpdate)))];
	const tbsCertList = sequence([
		integerFromNumber(1),
		encodeAlgorithmIdentifier(signatureAlgorithm),
		encodeName(input.issuer),
		time(thisUpdate),
		...(nextUpdate === undefined ? [] : [time(nextUpdate)]),
		...revokedSequence,
		...(extensions.length === 0 ? [] : [explicitContext(0, sequence(extensions))]),
	]);
	const signatureValue = await signBytes(input.signerPrivateKey, signatureAlgorithm, tbsCertList);
	const der = sequence([
		tbsCertList,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
	return {
		der,
		pem: pemEncode('X509 CRL', der),
		base64: base64Encode(der),
	};
}

export function parseCertificateRevocationListDer(
	der: Uint8Array,
): ParsedCertificateRevocationList {
	const top = childrenOf(der, readElement(der));
	const tbsCertList = requireElement(top[0], 'TBSCertList');
	const signatureAlgorithm = requireElement(top[1], 'signatureAlgorithm');
	const signatureValue = requireElement(top[2], 'signatureValue');
	const tbsChildren = childrenOf(der, tbsCertList);
	let index = 0;
	let version = 1;
	if (tbsChildren[index]?.tag === 0x02) {
		version = decodeIntegerNumber(requireElement(tbsChildren[index], 'version').value) + 1;
		index += 1;
	}
	index += 1; // signature algorithm in TBS
	const issuer = requireElement(tbsChildren[index], 'issuer');
	const thisUpdate = requireElement(tbsChildren[index + 1], 'thisUpdate');
	let cursor = index + 2;
	const maybeNextUpdate = tbsChildren[cursor];
	const nextUpdate =
		maybeNextUpdate !== undefined && (maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
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
			const parsedEntryExtensions = parseRevokedCertificateExtensions(entryDer, entryExtensions);
			return {
				serialNumberHex: toHex(requireElement(parts[0], 'revoked serialNumber').value),
				revocationDate: parseTime(requireElement(parts[1], 'revocationDate')),
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
	let freshestCrlDistributionPoints: readonly ParsedDistributionPoint[] | undefined;
	const maybeExtensions = tbsChildren[cursor];
	if (maybeExtensions?.tag === 0xa0) {
		const extensionSequence = requireElement(childrenOf(der, maybeExtensions)[0], 'crl extensions');
		for (const extension of childrenOf(der, extensionSequence)) {
			const parts = childrenOf(der, extension);
			const oid = decodeObjectIdentifier(requireElement(parts[0], 'extension OID').value);
			const valueElement = requireElement(parts[parts.length - 1], 'extension value');
			if (oid === OIDS.authorityKeyIdentifier) {
				authorityKeyIdentifier = parseAuthorityKeyIdentifier(valueElement.value);
			}
			if (oid === OIDS.cRLNumber) {
				crlNumber = decodeIntegerNumber(readElement(valueElement.value).value);
			}
			if (oid === OIDS.deltaCRLIndicator) {
				baseCrlNumber = decodeIntegerNumber(readElement(valueElement.value).value);
			}
			if (oid === OIDS.issuingDistributionPoint) {
				issuingDistributionPoint = parseIssuingDistributionPoint(valueElement.value);
			}
			if (oid === OIDS.freshestCRL) {
				freshestCrlDistributionPoints = parseDistributionPoints(valueElement.value);
			}
		}
	}
	return {
		version,
		tbsCertListDer: der.slice(tbsCertList.start - tbsCertList.headerLength, tbsCertList.end),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseIssuer(der, issuer),
		thisUpdate: parseTime(thisUpdate),
		...(nextUpdate === undefined ? {} : { nextUpdate }),
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm).oid,
		...(authorityKeyIdentifier === undefined ? {} : { authorityKeyIdentifier }),
		...(crlNumber === undefined ? {} : { crlNumber }),
		...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
		...(issuingDistributionPoint === undefined ? {} : { issuingDistributionPoint }),
		...(freshestCrlDistributionPoints === undefined ? {} : { freshestCrlDistributionPoints }),
		revokedCertificates,
	};
}

export function parseCertificateRevocationListPem(pem: string): ParsedCertificateRevocationList {
	return parseCertificateRevocationListDer(pemDecode('X509 CRL', pem));
}

export async function verifyCertificateRevocationList(
	crl: string | Uint8Array,
	issuerCertificate: string | Uint8Array,
): Promise<VerifyCertificateRevocationListResult> {
	const parsedCrl =
		typeof crl === 'string'
			? parseCertificateRevocationListPem(crl)
			: parseCertificateRevocationListDer(new Uint8Array(crl));
	const issuer =
		typeof issuerCertificate === 'string'
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
				code: 'signature_invalid',
				message: 'certificate revocation list signature does not verify',
			};
}

export async function validateCertificateRevocationList(
	input: ValidateCertificateRevocationListInput,
): Promise<ValidateCertificateRevocationListResult> {
	const parsedCrl = normalizeCrl(input.crl);
	const issuer = normalizeCrlCertificate(input.issuerCertificate);
	if (parsedCrl.issuer.derHex !== issuer.subject.derHex) {
		return {
			ok: false,
			code: 'issuer_mismatch',
			message: 'CRL issuer name does not match certificate subject',
		};
	}
	if (
		parsedCrl.authorityKeyIdentifier !== undefined &&
		issuer.subjectKeyIdentifier !== undefined &&
		parsedCrl.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
	) {
		return {
			ok: false,
			code: 'issuer_mismatch',
			message: 'CRL authority key identifier does not match issuer subject key identifier',
		};
	}
	const verified = await verifySignedData(
		parsedCrl.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		parsedCrl.signatureValue,
		parsedCrl.tbsCertListDer,
	);
	if (!verified) {
		return {
			ok: false,
			code: 'signature_invalid',
			message: 'certificate revocation list signature does not verify',
		};
	}
	const at = input.at ?? new Date();
	const skew = input.clockSkewMs ?? 0;
	if (
		parsedCrl.thisUpdate.getTime() - skew > at.getTime() ||
		(parsedCrl.nextUpdate !== undefined && parsedCrl.nextUpdate.getTime() + skew < at.getTime())
	) {
		return {
			ok: false,
			code: 'stale_crl',
			message: 'CRL is not valid at requested time',
		};
	}
	return { ok: true, value: parsedCrl };
}

export function isCertificateRevoked(
	certificateSerialNumber: Uint8Array | string,
	crl: ParsedCertificateRevocationList,
): boolean {
	const serialNumberHex =
		typeof certificateSerialNumber === 'string'
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
	issuingDistributionPoint?: IssuingDistributionPoint,
	freshestCrlDistributionPoints?: readonly DistributionPoint[],
): Promise<Uint8Array[]> {
	const extensions: Uint8Array[] = [];
	if (issuerPublicKey !== undefined) {
		const spki = await exportSpkiDer(issuerPublicKey);
		extensions.push(
			encodeExtension(
				OIDS.authorityKeyIdentifier,
				sequence([implicitPrimitiveContext(0, buildSubjectKeyIdentifier(spki))]),
			),
		);
	}
	if (crlNumber !== undefined) {
		extensions.push(encodeExtension(OIDS.cRLNumber, integerFromNumber(crlNumber)));
	}
	if (baseCrlNumber !== undefined) {
		extensions.push(
			encodeExtension(OIDS.deltaCRLIndicator, integerFromNumber(baseCrlNumber), true),
		);
	}
	if (issuingDistributionPoint !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.issuingDistributionPoint,
				encodeIssuingDistributionPoint(issuingDistributionPoint),
				true,
			),
		);
	}
	if (freshestCrlDistributionPoints !== undefined && freshestCrlDistributionPoints.length > 0) {
		extensions.push(
			encodeExtension(OIDS.freshestCRL, encodeCrlDistributionPoints(freshestCrlDistributionPoints)),
		);
	}
	return extensions;
}

function createRevokedCertificate(entry: RevokedCertificateInput, thisUpdate: Date): Uint8Array {
	const extensions = buildRevokedCertificateExtensions(entry);
	return sequence([
		integer(entry.serialNumber),
		time(entry.revocationDate ?? thisUpdate),
		...(extensions.length === 0 ? [] : [sequence(extensions)]),
	]);
}

function buildRevokedCertificateExtensions(entry: RevokedCertificateInput): Uint8Array[] {
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
		extensions.push(encodeExtension(OIDS.invalidityDate, generalizedTime(entry.invalidityDate)));
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
			requireElement(parts[0], 'revoked certificate extension OID').value,
		);
		const valueElement = requireElement(
			parts[parts.length - 1],
			'revoked certificate extension value',
		);
		if (oid === OIDS.cRLReason) {
			reasonCode = revocationReasonFromCode(readElement(valueElement.value).value[0]);
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

function parseIssuingDistributionPoint(valueDer: Uint8Array): ParsedIssuingDistributionPoint {
	const sequenceElement = readElement(valueDer);
	let distributionPoint: ParsedDistributionPointName | undefined;
	let onlyContainsUserCerts: boolean | undefined;
	let onlyContainsCACerts: boolean | undefined;
	let onlySomeReasons: readonly DistributionPointReason[] | undefined;
	let indirectCrl: boolean | undefined;
	let onlyContainsAttributeCerts: boolean | undefined;
	for (const child of childrenOf(valueDer, sequenceElement)) {
		if (child.tag === 0xa0) {
			const parsedDistributionPoint = parseDistributionPointName(valueDer, child);
			if (parsedDistributionPoint !== undefined) {
				distributionPoint = parsedDistributionPoint;
			}
		} else if (child.tag === 0x81) {
			onlyContainsUserCerts = parseImplicitBoolean(child);
		} else if (child.tag === 0x82) {
			onlyContainsCACerts = parseImplicitBoolean(child);
		} else if (child.tag === 0x83) {
			onlySomeReasons = parseDistributionPointReasonFlags(child.value);
		} else if (child.tag === 0x84) {
			indirectCrl = parseImplicitBoolean(child);
		} else if (child.tag === 0x85) {
			onlyContainsAttributeCerts = parseImplicitBoolean(child);
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(onlyContainsUserCerts === undefined ? {} : { onlyContainsUserCerts }),
		...(onlyContainsCACerts === undefined ? {} : { onlyContainsCACerts }),
		...(onlySomeReasons === undefined ? {} : { onlySomeReasons }),
		...(indirectCrl === undefined ? {} : { indirectCrl }),
		...(onlyContainsAttributeCerts === undefined ? {} : { onlyContainsAttributeCerts }),
	};
}

function parseDistributionPoints(valueDer: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = readElement(valueDer);
	return childrenOf(valueDer, sequenceElement).map((distributionPoint) =>
		parseDistributionPoint(valueDer, distributionPoint),
	);
}

function parseDistributionPointName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName | undefined {
	const distributionPointName = requireElement(
		childrenOf(valueDer, element)[0],
		'distributionPointName',
	);
	if (distributionPointName.tag === 0xa0) {
		return {
			fullName: childrenOf(valueDer, distributionPointName).map((name) => parseGeneralName(name)),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		const relativeName = parseRelativeName(valueDer, distributionPointName);
		return { relativeName };
	}
	return undefined;
}

function parseDistributionPoint(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPoint {
	let distributionPoint: ParsedDistributionPointName | undefined;
	let reasons: readonly DistributionPointReason[] | undefined;
	let crlIssuer: readonly GeneralName[] | undefined;
	for (const child of childrenOf(valueDer, element)) {
		if (child.tag === 0xa0) {
			const parsedDistributionPoint = parseDistributionPointName(valueDer, child);
			if (parsedDistributionPoint !== undefined) {
				distributionPoint = parsedDistributionPoint;
			}
		} else if (child.tag === 0x81) {
			reasons = parseDistributionPointReasonFlags(child.value);
		} else if (child.tag === 0xa2) {
			crlIssuer = childrenOf(valueDer, child).map((name) => parseGeneralName(name));
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(reasons === undefined ? {} : { reasons }),
		...(crlIssuer === undefined ? {} : { crlIssuer }),
	};
}

function parseGeneralName(element: DerElement): GeneralName {
	switch (element.tag) {
		case 0x81:
			return { type: 'email' as const, value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns' as const, value: textDecoder.decode(element.value) };
		case 0x86:
			return { type: 'uri' as const, value: textDecoder.decode(element.value) };
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(rebuildDirectoryNameFromImplicit(element)),
			};
		default:
			return { type: 'unknown' as const, tag: element.tag, value: new Uint8Array(element.value) };
	}
}

function parseRelativeName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of childrenOf(valueDer, element)) {
		const parts = childrenOf(valueDer, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const key = nameKeyFromOid(oid);
		const value = decodeNameValue(valueElement);
		attributes.push({ oid, ...(key === undefined ? {} : { key }), value });
		if (key !== undefined && values[key] === undefined) {
			values[key] = value;
		}
	}
	return {
		derHex: toHex(valueDer.slice(element.start - element.headerLength, element.end)),
		attributes,
		values,
	};
}

function nameKeyFromOid(oid: string): NameFieldKey | undefined {
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
	}
	return undefined;
}

function decodeNameValue(element: DerElement): string {
	return decodeString(element.tag, element.value);
}

function parseImplicitBoolean(element: DerElement): boolean {
	return (element.value[0] ?? 0) !== 0;
}

function parseDistributionPointReasonFlags(
	value: Uint8Array,
): readonly DistributionPointReason[] | undefined {
	const unusedBits = value[0] ?? 0;
	if (unusedBits > 7) {
		throw new Error('Invalid distribution point reasons BIT STRING');
	}
	const bytes = value.slice(1);
	const reasons: DistributionPointReason[] = [];
	const candidates: readonly DistributionPointReason[] = [
		'keyCompromise',
		'cACompromise',
		'affiliationChanged',
		'superseded',
		'cessationOfOperation',
		'certificateHold',
		'privilegeWithdrawn',
		'aACompromise',
	];
	for (let index = 0; index < candidates.length; index += 1) {
		const bit = index + 1;
		const byte = bytes[Math.floor(bit / 8)] ?? 0;
		const bitIndex = bit % 8;
		if ((byte & (1 << (7 - bitIndex))) !== 0) {
			const reason = candidates[index];
			if (reason !== undefined) {
				reasons.push(reason);
			}
		}
	}
	return reasons.length === 0 ? undefined : reasons;
}

function encodeIssuingDistributionPoint(value: IssuingDistributionPoint): Uint8Array {
	const certificateScopeFlags = [
		value.onlyContainsUserCerts === true,
		value.onlyContainsCACerts === true,
		value.onlyContainsAttributeCerts === true,
	].filter(Boolean).length;
	if (certificateScopeFlags > 1) {
		throw new Error(
			'IssuingDistributionPoint can assert at most one of user, CA, or attribute cert scope',
		);
	}
	const fields: Uint8Array[] = [];
	if (value.distributionPoint !== undefined) {
		fields.push(
			implicitConstructedContext(0, encodeDistributionPointName(value.distributionPoint)),
		);
	}
	if (value.onlyContainsUserCerts) {
		fields.push(implicitPrimitiveContext(1, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsCACerts) {
		fields.push(implicitPrimitiveContext(2, Uint8Array.of(0xff)));
	}
	if (value.onlySomeReasons !== undefined && value.onlySomeReasons.length > 0) {
		fields.push(
			implicitPrimitiveContext(3, encodeDistributionPointReasonFlags(value.onlySomeReasons)),
		);
	}
	if (value.indirectCrl) {
		fields.push(implicitPrimitiveContext(4, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsAttributeCerts) {
		fields.push(implicitPrimitiveContext(5, Uint8Array.of(0xff)));
	}
	return sequence(fields);
}

function encodeDistributionPointName(
	value: IssuingDistributionPoint['distributionPoint'],
): Uint8Array {
	if (value === undefined) {
		throw new Error('IssuingDistributionPoint distributionPoint is required');
	}
	if (value.fullName !== undefined && value.relativeName !== undefined) {
		throw new Error('DistributionPointName cannot contain both fullName and relativeName');
	}
	if (value.fullName !== undefined) {
		if (value.fullName.length === 0) {
			throw new Error('DistributionPointName fullName must not be empty');
		}
		return implicitConstructedContext(0, concatGeneralNames(value.fullName));
	}
	if (value.relativeName !== undefined) {
		const relativeName = encodeRelativeDistinguishedName(value.relativeName);
		const relativeNameElement = readElement(relativeName);
		return implicitConstructedContext(
			1,
			relativeName.slice(relativeNameElement.start, relativeNameElement.end),
		);
	}
	throw new Error('DistributionPointName must contain fullName or relativeName');
}

function concatGeneralNames(names: readonly GeneralName[]): Uint8Array {
	return concatBytes(names.map((name) => encodeSubjectAltName(name)));
}

function encodeDistributionPointReasonFlags(
	reasons: readonly DistributionPointReason[],
): Uint8Array {
	const bitMap: Record<DistributionPointReason, number> = {
		keyCompromise: 1,
		cACompromise: 2,
		affiliationChanged: 3,
		superseded: 4,
		cessationOfOperation: 5,
		certificateHold: 6,
		privilegeWithdrawn: 7,
		aACompromise: 8,
	};
	let highestBit = 0;
	for (const reason of reasons) {
		const bit = bitMap[reason];
		if (bit > highestBit) {
			highestBit = bit;
		}
	}
	const byteLength = Math.floor(highestBit / 8) + 1;
	const bytes = new Uint8Array(byteLength);
	for (const reason of reasons) {
		const bit = bitMap[reason];
		const byteIndex = Math.floor(bit / 8);
		const bitIndex = bit % 8;
		const current = bytes[byteIndex] ?? 0;
		bytes[byteIndex] = current | (1 << (7 - bitIndex));
	}
	const unusedBits = (8 - ((highestBit + 1) % 8)) % 8;
	return Uint8Array.of(unusedBits, ...bytes);
}

function rebuildDirectoryNameFromImplicit(element: DerElement): Uint8Array {
	return tlv(0x30, element.value);
}

function decodeIpAddress(bytes: Uint8Array): string {
	if (bytes.length === 4) {
		return Array.from(bytes).join('.');
	}
	if (bytes.length === 16) {
		const parts: string[] = [];
		for (let index = 0; index < 16; index += 2) {
			parts.push((((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0)).toString(16));
		}
		return parts.join(':');
	}
	throw new Error(`Unsupported IP address length: ${bytes.length}`);
}

function encodeExtension(oid: string, value: Uint8Array, critical = false): Uint8Array {
	return sequence([objectIdentifier(oid), ...(critical ? [bool(true)] : []), octetString(value)]);
}

function buildSubjectKeyIdentifier(spki: Uint8Array): Uint8Array {
	const top = readSequenceChildren(spki);
	const keyBitString = top[1];
	if (keyBitString === undefined || keyBitString.tag !== 0x03) {
		throw new Error('SPKI missing subject public key bit string');
	}
	return sha1(keyBitString.value.slice(1));
}

function parseIssuer(
	source: Uint8Array,
	element: DerElement,
): { readonly derHex: string; readonly commonName?: string } {
	let commonName: string | undefined;
	for (const setElement of childrenOf(source, element)) {
		const attribute = requireElement(childrenOf(source, setElement)[0], 'issuer attribute');
		const parts = childrenOf(source, attribute);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'issuer attribute OID').value);
		if (oid === OIDS.commonName) {
			commonName = textDecoder.decode(requireElement(parts[1], 'issuer attribute value').value);
		}
	}
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
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
	const oid = requireElement(children[0], 'algorithm OID');
	return { oid: decodeObjectIdentifier(oid.value) };
}

function normalizeHex(value: string): string {
	return value.replace(/^0+/, '').toLowerCase();
}

function revocationReasonFromCode(code: number | undefined): RevocationReason | undefined {
	switch (code) {
		case 0:
			return 'unspecified';
		case 1:
			return 'keyCompromise';
		case 2:
			return 'cACompromise';
		case 3:
			return 'affiliationChanged';
		case 4:
			return 'superseded';
		case 5:
			return 'cessationOfOperation';
		case 6:
			return 'certificateHold';
		case 8:
			return 'removeFromCRL';
		case 9:
			return 'privilegeWithdrawn';
		case 10:
			return 'aACompromise';
	}
	return undefined;
}

function parseIssuerCertificateDer(der: Uint8Array): ParsedCertificate {
	return parseCertificateDer(der);
}

function parseIssuerCertificatePem(pem: string): ParsedCertificate {
	return parseCertificatePem(pem);
}

function normalizeCrl(source: CrlSource): ParsedCertificateRevocationList {
	if (typeof source === 'string') {
		return parseCertificateRevocationListPem(source);
	}
	if (source instanceof Uint8Array) {
		return parseCertificateRevocationListDer(new Uint8Array(source));
	}
	return source;
}

function normalizeCrlCertificate(source: CrlCertificateSource): ParsedCertificate {
	if (typeof source === 'string') {
		return parseCertificatePem(source);
	}
	if (source instanceof Uint8Array) {
		return parseCertificateDer(new Uint8Array(source));
	}
	return source;
}

const textDecoder = new TextDecoder();
