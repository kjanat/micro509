import {
	childrenOf,
	decodeBoolean,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from './asn1.ts';
import type { DerElement } from './der.ts';
import { readElement } from './der.ts';
import type {
	AuthorityInformationAccess,
	BasicConstraints,
	DistributionPointReason,
	ExtendedKeyUsage,
	GeneralName,
	GeneralSubtree,
	KeyUsage,
	NameConstraintForm,
	NameConstraints,
	SubjectAltName,
} from './extensions.ts';
import { parseAuthorityInfoAccessMethodOid, parseExtendedKeyUsageOid } from './extensions.ts';
import type { NameFieldKey } from './name.ts';
import { OIDS } from './oids.ts';
import { pemDecode, splitPemBlocks } from './pem.ts';

const textDecoder = new TextDecoder();

export interface ParsedNameAttribute {
	readonly oid: string;
	readonly key?: NameFieldKey;
	readonly value: string;
}

export interface ParsedName {
	readonly derHex: string;
	readonly attributes: readonly ParsedNameAttribute[];
	readonly values: Partial<Record<NameFieldKey, string>>;
}

export interface ParsedRelativeDistinguishedName {
	readonly derHex: string;
	readonly attributes: readonly ParsedNameAttribute[];
	readonly values: Partial<Record<NameFieldKey, string>>;
}

export interface ParsedDistributionPointName {
	readonly fullName?: readonly GeneralName[];
	readonly relativeName?: ParsedRelativeDistinguishedName;
}

export interface ParsedDistributionPoint {
	readonly distributionPoint?: ParsedDistributionPointName;
	readonly reasons?: readonly DistributionPointReason[];
	readonly crlIssuer?: readonly GeneralName[];
}

export interface ParsedIssuingDistributionPoint {
	readonly distributionPoint?: ParsedDistributionPointName;
	readonly onlyContainsUserCerts?: boolean;
	readonly onlyContainsCACerts?: boolean;
	readonly onlySomeReasons?: readonly DistributionPointReason[];
	readonly indirectCrl?: boolean;
	readonly onlyContainsAttributeCerts?: boolean;
}

export interface ParsedExtension {
	readonly oid: string;
	readonly critical: boolean;
	readonly valueDer: Uint8Array;
	readonly valueHex: string;
}

export interface ExtensionDecoder<TValue> {
	readonly oid: string;
	decode(extension: ParsedExtension): TValue;
}

export function defineExtensionDecoder<TValue>(
	decoder: ExtensionDecoder<TValue>,
): ExtensionDecoder<TValue> {
	return decoder;
}

export function defineExtensionDecoderMap<TMap extends ExtensionDecoderMap>(
	decoderMap: TMap,
): TMap {
	return decoderMap;
}

export type ExtensionDecoderMap = Record<string, ExtensionDecoder<unknown>>;

export type DecodedExtensionMap<TMap extends ExtensionDecoderMap> = {
	[TKey in keyof TMap]?: TMap[TKey] extends ExtensionDecoder<infer TValue>
		? DecodedExtensionValue<TValue>
		: never;
};

export interface DecodedExtensionValue<TValue> {
	readonly oid: string;
	readonly critical: boolean;
	readonly value: TValue;
}

export interface ParseOptions<TMap extends ExtensionDecoderMap = Record<never, never>> {
	readonly decoders?: readonly ExtensionDecoder<unknown>[];
	readonly decoderMap?: TMap;
}

export interface ParsedCertificate<TMap extends ExtensionDecoderMap = Record<never, never>> {
	readonly der: Uint8Array;
	readonly version: number;
	readonly serialNumberHex: string;
	readonly tbsCertificateDer: Uint8Array;
	readonly subjectPublicKeyInfoDer: Uint8Array;
	readonly signatureValue: Uint8Array;
	readonly issuer: ParsedName;
	readonly subject: ParsedName;
	readonly notBefore: Date;
	readonly notAfter: Date;
	readonly signatureAlgorithmOid: string;
	readonly publicKeyAlgorithmOid: string;
	readonly publicKeyParametersOid?: string;
	readonly extensions: readonly ParsedExtension[];
	readonly basicConstraints?: BasicConstraints;
	readonly keyUsage?: readonly KeyUsage[];
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	readonly subjectAltNames?: readonly SubjectAltName[];
	readonly nameConstraints?: NameConstraints;
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
	readonly subjectKeyIdentifier?: string;
	readonly authorityKeyIdentifier?: string;
}

export interface ParsedCertificateSigningRequest<
	TMap extends ExtensionDecoderMap = Record<never, never>,
> {
	readonly version: number;
	readonly certificationRequestInfoDer: Uint8Array;
	readonly subjectPublicKeyInfoDer: Uint8Array;
	readonly signatureValue: Uint8Array;
	readonly subject: ParsedName;
	readonly signatureAlgorithmOid: string;
	readonly publicKeyAlgorithmOid: string;
	readonly publicKeyParametersOid?: string;
	readonly requestedExtensions: readonly ParsedExtension[];
	readonly basicConstraints?: BasicConstraints;
	readonly keyUsage?: readonly KeyUsage[];
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	readonly subjectAltNames?: readonly SubjectAltName[];
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
}

export function parseCertificateDer<TMap extends ExtensionDecoderMap = Record<never, never>>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	const topLevel = childrenOf(der, readElement(der));
	const tbsCertificate = requireElement(topLevel[0], 'TBSCertificate');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const tbsChildren = childrenOf(der, tbsCertificate);

	let index = 0;
	let version = 1;
	const maybeVersion = tbsChildren[index];
	if (maybeVersion?.tag === 0xa0) {
		const versionElement = requireElement(childrenOf(der, maybeVersion)[0], 'version INTEGER');
		version = decodeIntegerNumber(versionElement.value) + 1;
		index += 1;
	}

	const serialNumber = requireElement(tbsChildren[index], 'serialNumber');
	const issuer = requireElement(tbsChildren[index + 2], 'issuer');
	const validity = requireElement(tbsChildren[index + 3], 'validity');
	const subject = requireElement(tbsChildren[index + 4], 'subject');
	const subjectPublicKeyInfo = requireElement(tbsChildren[index + 5], 'subjectPublicKeyInfo');
	const extensions = tbsChildren.find((element) => element.tag === 0xa3);
	const parsedExtensions = parseExtensionContainer(der, extensions);
	const parsedValidity = parseValidity(der, validity);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const decodedExtensions =
		options?.decoders === undefined
			? undefined
			: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap =
		options?.decoderMap === undefined
			? undefined
			: decodeExtensionMap(parsedExtensions.all, options.decoderMap);

	return {
		der: new Uint8Array(der),
		version,
		serialNumberHex: toHex(serialNumber.value),
		tbsCertificateDer: der.slice(
			tbsCertificate.start - tbsCertificate.headerLength,
			tbsCertificate.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			subjectPublicKeyInfo.start - subjectPublicKeyInfo.headerLength,
			subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseName(der, issuer),
		subject: parseName(der, subject),
		notBefore: parsedValidity.notBefore,
		notAfter: parsedValidity.notAfter,
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm).oid,
		publicKeyAlgorithmOid: parsedSpki.oid,
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		extensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined ? { keyUsage: parsedExtensions.keyUsage } : {}),
		...(parsedExtensions.extendedKeyUsage !== undefined
			? { extendedKeyUsage: parsedExtensions.extendedKeyUsage }
			: {}),
		...(parsedExtensions.subjectAltNames !== undefined
			? { subjectAltNames: parsedExtensions.subjectAltNames }
			: {}),
		...(parsedExtensions.nameConstraints !== undefined
			? { nameConstraints: parsedExtensions.nameConstraints }
			: {}),
		...(parsedExtensions.authorityInfoAccess !== undefined
			? { authorityInfoAccess: parsedExtensions.authorityInfoAccess }
			: {}),
		...(parsedExtensions.crlDistributionPoints !== undefined
			? { crlDistributionPoints: parsedExtensions.crlDistributionPoints }
			: {}),
		...(decodedExtensions !== undefined ? { decodedExtensions } : {}),
		...(decodedExtensionMap !== undefined ? { decodedExtensionMap } : {}),
		...(parsedExtensions.subjectKeyIdentifier !== undefined
			? { subjectKeyIdentifier: parsedExtensions.subjectKeyIdentifier }
			: {}),
		...(parsedExtensions.authorityKeyIdentifier !== undefined
			? { authorityKeyIdentifier: parsedExtensions.authorityKeyIdentifier }
			: {}),
	};
}

export function parseCertificatePem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pem: string,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	return parseCertificateDer(pemDecode('CERTIFICATE', pem), options);
}

export function parseCertificateChainPem<TMap extends ExtensionDecoderMap = Record<never, never>>(
	pemBundle: string,
	options?: ParseOptions<TMap>,
): readonly ParsedCertificate<TMap>[] {
	return splitPemBlocks(pemBundle)
		.filter((block) => block.label === 'CERTIFICATE')
		.map((block) => parseCertificateDer(block.bytes, options));
}

export function parseCertificateSigningRequestDer<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(der: Uint8Array, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	const topLevel = childrenOf(der, readElement(der));
	const certificationRequestInfo = requireElement(topLevel[0], 'CertificationRequestInfo');
	const signatureAlgorithm = requireElement(topLevel[1], 'signatureAlgorithm');
	const signatureValue = requireElement(topLevel[2], 'signatureValue');
	const criChildren = childrenOf(der, certificationRequestInfo);
	const version = decodeIntegerNumber(requireElement(criChildren[0], 'version').value) + 1;
	const subject = requireElement(criChildren[1], 'subject');
	const subjectPublicKeyInfo = requireElement(criChildren[2], 'subjectPublicKeyInfo');
	const attributes = criChildren[3];
	const parsedExtensions = parseRequestedExtensions(der, attributes);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const decodedExtensions =
		options?.decoders === undefined
			? undefined
			: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap =
		options?.decoderMap === undefined
			? undefined
			: decodeExtensionMap(parsedExtensions.all, options.decoderMap);

	return {
		version,
		certificationRequestInfoDer: der.slice(
			certificationRequestInfo.start - certificationRequestInfo.headerLength,
			certificationRequestInfo.end,
		),
		subjectPublicKeyInfoDer: der.slice(
			subjectPublicKeyInfo.start - subjectPublicKeyInfo.headerLength,
			subjectPublicKeyInfo.end,
		),
		signatureValue: extractBitStringValue(signatureValue),
		subject: parseName(der, subject),
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm).oid,
		publicKeyAlgorithmOid: parsedSpki.oid,
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		requestedExtensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined ? { keyUsage: parsedExtensions.keyUsage } : {}),
		...(parsedExtensions.extendedKeyUsage !== undefined
			? { extendedKeyUsage: parsedExtensions.extendedKeyUsage }
			: {}),
		...(parsedExtensions.subjectAltNames !== undefined
			? { subjectAltNames: parsedExtensions.subjectAltNames }
			: {}),
		...(parsedExtensions.authorityInfoAccess !== undefined
			? { authorityInfoAccess: parsedExtensions.authorityInfoAccess }
			: {}),
		...(parsedExtensions.crlDistributionPoints !== undefined
			? { crlDistributionPoints: parsedExtensions.crlDistributionPoints }
			: {}),
		...(decodedExtensions !== undefined ? { decodedExtensions } : {}),
		...(decodedExtensionMap !== undefined ? { decodedExtensionMap } : {}),
	};
}

export function parseCertificateSigningRequestPem<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pem: string, options?: ParseOptions<TMap>): ParsedCertificateSigningRequest<TMap> {
	return parseCertificateSigningRequestDer(pemDecode('CERTIFICATE REQUEST', pem), options);
}

export function findExtension(
	extensions: readonly ParsedExtension[],
	oid: string,
): ParsedExtension | undefined {
	return extensions.find((extension) => extension.oid === oid);
}

export function decodeExtension<TValue>(
	extensions: readonly ParsedExtension[],
	decoder: ExtensionDecoder<TValue>,
): TValue | undefined {
	const extension = findExtension(extensions, decoder.oid);
	if (extension === undefined) {
		return undefined;
	}
	return decoder.decode(extension);
}

export function decodeExtensions(
	extensions: readonly ParsedExtension[],
	decoders: readonly ExtensionDecoder<unknown>[],
): readonly DecodedExtensionValue<unknown>[] {
	const decoded: DecodedExtensionValue<unknown>[] = [];
	for (const decoder of decoders) {
		const extension = findExtension(extensions, decoder.oid);
		if (extension === undefined) {
			continue;
		}
		decoded.push({
			oid: extension.oid,
			critical: extension.critical,
			value: decoder.decode(extension),
		});
	}
	return decoded;
}

export function decodeExtensionMap<TMap extends ExtensionDecoderMap>(
	extensions: readonly ParsedExtension[],
	decoderMap: TMap,
): DecodedExtensionMap<TMap> {
	let decoded: DecodedExtensionMap<TMap> = {};
	for (const key in decoderMap) {
		const decoder = decoderMap[key];
		if (decoder === undefined) {
			continue;
		}
		const extension = findExtension(extensions, decoder.oid);
		if (extension === undefined) {
			continue;
		}
		decoded = {
			...decoded,
			[key]: {
				oid: extension.oid,
				critical: extension.critical,
				value: decoder.decode(extension),
			},
		};
	}
	return decoded;
}

interface ParsedExtensions {
	readonly all: readonly ParsedExtension[];
	readonly basicConstraints?: BasicConstraints;
	readonly keyUsage?: readonly KeyUsage[];
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	readonly subjectAltNames?: readonly SubjectAltName[];
	readonly nameConstraints?: NameConstraints;
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly subjectKeyIdentifier?: string;
	readonly authorityKeyIdentifier?: string;
}

function parseExtensionContainer(
	source: Uint8Array,
	container: DerElement | undefined,
): ParsedExtensions {
	if (container === undefined) {
		return { all: [] };
	}
	const sequenceElement = requireElement(childrenOf(source, container)[0], 'extensions sequence');
	return parseExtensionSequence(source, sequenceElement);
}

function parseRequestedExtensions(
	source: Uint8Array,
	attributes: DerElement | undefined,
): ParsedExtensions {
	if (attributes === undefined) {
		return { all: [] };
	}
	for (const attribute of childrenOf(source, attributes)) {
		const attributeChildren = childrenOf(source, attribute);
		const oid = requireElement(attributeChildren[0], 'attribute OID');
		if (decodeObjectIdentifier(oid.value) !== OIDS.extensionRequest) {
			continue;
		}
		const valuesSet = requireElement(attributeChildren[1], 'attribute values');
		const requested = requireElement(childrenOf(source, valuesSet)[0], 'requested extensions');
		return parseExtensionSequence(source, requested);
	}
	return { all: [] };
}

function parseExtensionSequence(source: Uint8Array, sequenceElement: DerElement): ParsedExtensions {
	const parsed: ParsedExtension[] = [];
	let basicConstraints: BasicConstraints | undefined;
	let keyUsage: readonly KeyUsage[] | undefined;
	let extendedKeyUsage: readonly ExtendedKeyUsage[] | undefined;
	let subjectAltNames: readonly SubjectAltName[] | undefined;
	let nameConstraints: NameConstraints | undefined;
	let authorityInfoAccess: readonly AuthorityInformationAccess[] | undefined;
	let crlDistributionPoints: readonly ParsedDistributionPoint[] | undefined;
	let subjectKeyIdentifier: string | undefined;
	let authorityKeyIdentifier: string | undefined;

	for (const extension of childrenOf(source, sequenceElement)) {
		const children = childrenOf(source, extension);
		const oidElement = requireElement(children[0], 'extension OID');
		const oid = decodeObjectIdentifier(oidElement.value);
		let offset = 1;
		let critical = false;
		const maybeCritical = children[offset];
		if (maybeCritical?.tag === 0x01) {
			critical = decodeBoolean(maybeCritical.value);
			offset += 1;
		}
		const extnValue = requireElement(children[offset], 'extension value');
		const inner = readElement(extnValue.value);
		parsed.push({
			oid,
			critical,
			valueDer: new Uint8Array(extnValue.value),
			valueHex: toHex(extnValue.value),
		});
		switch (oid) {
			case OIDS.basicConstraints:
				basicConstraints = parseBasicConstraints(extnValue.value);
				break;
			case OIDS.keyUsage:
				keyUsage = parseKeyUsage(extnValue.value);
				break;
			case OIDS.extendedKeyUsage:
				extendedKeyUsage = parseExtendedKeyUsage(extnValue.value);
				break;
			case OIDS.subjectAltName:
				subjectAltNames = parseSubjectAltNames(extnValue.value);
				break;
			case OIDS.nameConstraints:
				nameConstraints = parseNameConstraints(extnValue.value);
				break;
			case OIDS.authorityInfoAccess:
				authorityInfoAccess = parseAuthorityInfoAccess(extnValue.value);
				break;
			case OIDS.cRLDistributionPoints:
				crlDistributionPoints = parseCrlDistributionPoints(extnValue.value);
				break;
			case OIDS.subjectKeyIdentifier:
				subjectKeyIdentifier = toHex(inner.value);
				break;
			case OIDS.authorityKeyIdentifier:
				authorityKeyIdentifier = parseAuthorityKeyIdentifier(extnValue.value);
				break;
		}
	}

	return {
		all: parsed,
		...(basicConstraints !== undefined ? { basicConstraints } : {}),
		...(keyUsage !== undefined ? { keyUsage } : {}),
		...(extendedKeyUsage !== undefined ? { extendedKeyUsage } : {}),
		...(subjectAltNames !== undefined ? { subjectAltNames } : {}),
		...(nameConstraints !== undefined ? { nameConstraints } : {}),
		...(authorityInfoAccess !== undefined ? { authorityInfoAccess } : {}),
		...(crlDistributionPoints !== undefined ? { crlDistributionPoints } : {}),
		...(subjectKeyIdentifier !== undefined ? { subjectKeyIdentifier } : {}),
		...(authorityKeyIdentifier !== undefined ? { authorityKeyIdentifier } : {}),
	};
}

function parseName(source: Uint8Array, element: DerElement): ParsedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const setElement of childrenOf(source, element)) {
		parseNameAttributeSet(source, setElement, attributes, values);
	}
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
		attributes,
		values,
	};
}

function parseRelativeDistinguishedName(
	source: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	parseNameAttributeSet(source, element, attributes, values);
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
		attributes,
		values,
	};
}

function parseNameAttributeSet(
	source: Uint8Array,
	setElement: DerElement,
	attributes: ParsedNameAttribute[],
	values: Partial<Record<NameFieldKey, string>>,
): void {
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const key = nameKeyFromOid(oid);
		const value = decodeString(valueElement.tag, valueElement.value);
		attributes.push({ oid, ...(key !== undefined ? { key } : {}), value });
		if (key !== undefined && values[key] === undefined) {
			values[key] = value;
		}
	}
}

function parseValidity(
	source: Uint8Array,
	element: DerElement,
): { readonly notBefore: Date; readonly notAfter: Date } {
	const children = childrenOf(source, element);
	return {
		notBefore: parseTime(requireElement(children[0], 'notBefore')),
		notAfter: parseTime(requireElement(children[1], 'notAfter')),
	};
}

function parseSubjectPublicKeyInfo(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string; readonly parametersOid?: string } {
	const children = childrenOf(source, element);
	const algorithm = parseAlgorithmIdentifier(source, requireElement(children[0], 'SPKI algorithm'));
	return algorithm;
}

function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string; readonly parametersOid?: string } {
	const children = childrenOf(source, element);
	const oid = decodeObjectIdentifier(requireElement(children[0], 'algorithm OID').value);
	const parameters = children[1];
	if (parameters?.tag === 0x06) {
		return { oid, parametersOid: decodeObjectIdentifier(parameters.value) };
	}
	return { oid };
}

function parseBasicConstraints(bytes: Uint8Array): BasicConstraints {
	const element = readElement(bytes);
	const children = childrenOf(bytes, element);
	let ca = false;
	let pathLength: number | undefined;
	for (const child of children) {
		if (child.tag === 0x01) {
			ca = decodeBoolean(child.value);
		}
		if (child.tag === 0x02) {
			pathLength = decodeIntegerNumber(child.value);
		}
	}
	return pathLength !== undefined ? { ca, pathLength } : { ca };
}

function parseKeyUsage(bytes: Uint8Array): readonly KeyUsage[] {
	const bitString = requireElement(readElement(bytes), 'keyUsage bit string');
	const unusedBits = bitString.value[0] ?? 0;
	if (unusedBits > 7) {
		throw new Error('Invalid BIT STRING');
	}
	const data = bitString.value.slice(1);
	const usages: KeyUsage[] = [];
	const candidates: readonly KeyUsage[] = [
		'digitalSignature',
		'nonRepudiation',
		'keyEncipherment',
		'dataEncipherment',
		'keyAgreement',
		'keyCertSign',
		'cRLSign',
		'encipherOnly',
		'decipherOnly',
	];
	for (let index = 0; index < candidates.length; index += 1) {
		const byteIndex = Math.floor(index / 8);
		const bitIndex = index % 8;
		const byte = data[byteIndex] ?? 0;
		if ((byte & (1 << (7 - bitIndex))) !== 0) {
			const usage = candidates[index];
			if (usage !== undefined) {
				usages.push(usage);
			}
		}
	}
	return usages;
}

function parseExtendedKeyUsage(bytes: Uint8Array): readonly ExtendedKeyUsage[] {
	const sequenceElement = requireElement(readElement(bytes), 'extendedKeyUsage sequence');
	return childrenOf(bytes, sequenceElement).map((element) =>
		parseExtendedKeyUsageOid(decodeObjectIdentifier(element.value)),
	);
}

function parseSubjectAltNames(bytes: Uint8Array): readonly SubjectAltName[] {
	const sequenceElement = requireElement(readElement(bytes), 'subjectAltName sequence');
	return childrenOf(bytes, sequenceElement).map((element) => parseGeneralName(bytes, element));
}

function parseAuthorityInfoAccess(bytes: Uint8Array): readonly AuthorityInformationAccess[] {
	const sequenceElement = requireElement(readElement(bytes), 'authorityInfoAccess sequence');
	return childrenOf(bytes, sequenceElement).map((element) => {
		const children = childrenOf(bytes, element);
		const method = requireElement(children[0], 'authorityInfoAccess method');
		const location = requireElement(children[1], 'authorityInfoAccess location');
		if (location.tag !== 0x86) {
			throw new Error(`Unsupported authorityInfoAccess location tag: ${location.tag}`);
		}
		return {
			method: parseAuthorityInfoAccessMethodOid(decodeObjectIdentifier(method.value)),
			uri: textDecoder.decode(location.value),
		};
	});
}

function parseCrlDistributionPoints(bytes: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = requireElement(readElement(bytes), 'cRLDistributionPoints sequence');
	const points: ParsedDistributionPoint[] = [];
	for (const distributionPoint of childrenOf(bytes, sequenceElement)) {
		points.push(parseDistributionPoint(bytes, distributionPoint));
	}
	return points;
}

function parseDistributionPoint(source: Uint8Array, element: DerElement): ParsedDistributionPoint {
	let distributionPoint: ParsedDistributionPointName | undefined;
	let reasons: readonly DistributionPointReason[] | undefined;
	let crlIssuer: readonly GeneralName[] | undefined;
	for (const child of childrenOf(source, element)) {
		if (child.tag === 0xa0) {
			distributionPoint = parseDistributionPointName(source, child);
		} else if (child.tag === 0x81) {
			reasons = parseDistributionPointReasonFlags(child.value);
		} else if (child.tag === 0xa2) {
			crlIssuer = parseGeneralNames(source, child);
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(reasons === undefined ? {} : { reasons }),
		...(crlIssuer === undefined ? {} : { crlIssuer }),
	};
}

function parseDistributionPointName(
	source: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName {
	const distributionPointName = requireElement(
		childrenOf(source, element)[0],
		'distributionPointName',
	);
	if (distributionPointName.tag === 0xa0) {
		return {
			fullName: childrenOf(source, distributionPointName).map((name) =>
				parseGeneralName(source, name),
			),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		return { relativeName: parseRelativeDistinguishedName(source, distributionPointName) };
	}
	throw new Error(`Unsupported distributionPointName tag: ${distributionPointName.tag}`);
}

function parseGeneralNames(source: Uint8Array, element: DerElement): readonly GeneralName[] {
	return childrenOf(source, element).map((name) => parseGeneralName(source, name));
}

function parseGeneralName(source: Uint8Array, element: DerElement): GeneralName {
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
				derHex: toHex(rebuildDirectoryNameFromImplicit(element, source)),
			};
		default:
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
	}
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
		const byte = bytes[Math.floor((index + 1) / 8)] ?? 0;
		const bitIndex = (index + 1) % 8;
		if ((byte & (1 << (7 - bitIndex))) !== 0) {
			const reason = candidates[index];
			if (reason !== undefined) {
				reasons.push(reason);
			}
		}
	}
	return reasons.length === 0 ? undefined : reasons;
}

/** @internal Exported for testing only — not part of the public API. */
export function parseNameConstraints(bytes: Uint8Array): NameConstraints {
	const sequenceElement = requireElement(readElement(bytes), 'nameConstraints sequence');
	let permittedSubtrees: readonly GeneralSubtree[] | undefined;
	let excludedSubtrees: readonly GeneralSubtree[] | undefined;
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0xa0) {
			permittedSubtrees = parseGeneralSubtrees(bytes, child);
		} else if (child.tag === 0xa1) {
			excludedSubtrees = parseGeneralSubtrees(bytes, child);
		}
	}
	return {
		...(permittedSubtrees !== undefined ? { permittedSubtrees } : {}),
		...(excludedSubtrees !== undefined ? { excludedSubtrees } : {}),
	};
}

function parseGeneralSubtrees(
	source: Uint8Array,
	container: DerElement,
): readonly GeneralSubtree[] {
	const subtrees: GeneralSubtree[] = [];
	for (const subtreeElement of childrenOf(source, container)) {
		const children = childrenOf(source, subtreeElement);
		const baseElement = children[0];
		if (baseElement === undefined) {
			continue;
		}

		// RFC 5280 §4.2.1.10: minimum MUST be zero (default), maximum
		// MUST be absent. Reject non-standard values.
		for (let i = 1; i < children.length; i += 1) {
			const child = children[i];
			if (child === undefined) {
				continue;
			}
			if (child.tag === 0x80) {
				// minimum [0] INTEGER — must be 0
				if (child.value.length !== 1 || child.value[0] !== 0) {
					throw new Error('name constraints GeneralSubtree minimum must be 0');
				}
			} else if (child.tag === 0x81) {
				// maximum [1] INTEGER — must be absent
				throw new Error('name constraints GeneralSubtree maximum is not supported');
			}
		}

		const form = parseNameConstraintGeneralName(source, baseElement);
		if (form !== undefined) {
			subtrees.push({ base: form });
		}
	}
	return subtrees;
}

function parseNameConstraintGeneralName(
	source: Uint8Array,
	element: DerElement,
): NameConstraintForm | undefined {
	switch (element.tag) {
		case 0x81:
			return { type: 'email', value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns', value: textDecoder.decode(element.value) };
		case 0x86:
			return { type: 'uri', value: textDecoder.decode(element.value) };
		case 0x87: {
			if (element.value.length === 8) {
				return {
					type: 'ip',
					addressBytes: element.value.slice(0, 4),
					maskBytes: element.value.slice(4, 8),
				};
			}
			if (element.value.length === 32) {
				return {
					type: 'ip',
					addressBytes: element.value.slice(0, 16),
					maskBytes: element.value.slice(16, 32),
				};
			}
			throw new Error(
				`Invalid IP name constraint: expected 8 (IPv4) or 32 (IPv6) bytes, got ${String(element.value.length)}`,
			);
		}
		case 0xa4:
			return {
				type: 'directoryName',
				derHex: toHex(rebuildDirectoryNameFromImplicit(element, source)),
			};
	}
	return undefined;
}

/**
 * DirectoryName in GeneralName is IMPLICIT [4], meaning the outer tag
 * is 0xa4 but the content is a SEQUENCE of RDNs. We must reconstruct
 * the original SEQUENCE (tag 0x30) for DER hex comparison.
 */
function rebuildDirectoryNameFromImplicit(element: DerElement, source: Uint8Array): Uint8Array {
	const contentBytes = source.slice(element.start, element.end);
	const lengthEncoded = encodeAsn1Length(contentBytes.length);
	const result = new Uint8Array(1 + lengthEncoded.length + contentBytes.length);
	result[0] = 0x30;
	result.set(lengthEncoded, 1);
	result.set(contentBytes, 1 + lengthEncoded.length);
	return result;
}

function encodeAsn1Length(length: number): Uint8Array {
	if (length < 128) {
		return Uint8Array.of(length);
	}
	const parts: number[] = [];
	let current = length;
	while (current > 0) {
		parts.unshift(current & 0xff);
		current >>= 8;
	}
	return Uint8Array.of(0x80 | parts.length, ...parts);
}

function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = requireElement(readElement(bytes), 'authorityKeyIdentifier sequence');
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			return toHex(child.value);
		}
	}
	return undefined;
}

function decodeIpAddress(bytes: Uint8Array): string {
	if (bytes.length === 4) {
		return Array.from(bytes, (value) => String(value)).join('.');
	}
	if (bytes.length === 16) {
		const groups: string[] = [];
		for (let index = 0; index < bytes.length; index += 2) {
			const left = bytes[index] ?? 0;
			const right = bytes[index + 1] ?? 0;
			groups.push(((left << 8) | right).toString(16));
		}
		return groups.join(':');
	}
	throw new Error('Unsupported IP address length');
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
