import {
	childrenOf,
	decodeBoolean,
	decodeIntegerNumber,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from './asn1.ts';
import type { DerElement } from './der.ts';
import { DEFAULT_MAX_DER_DEPTH, encodeLength, readElement, readSequenceChildren } from './der.ts';
import {
	parseDistributionPointReasonFlagsContent,
	parseKeyUsageExtension,
} from './extension-bits.ts';
import type {
	AuthorityInformationAccess,
	BasicConstraints,
	CertificatePolicies,
	DistributionPointReason,
	ExtendedKeyUsage,
	GeneralName,
	GeneralSubtree,
	InhibitAnyPolicy,
	KeyUsage,
	NameConstraints,
	ParsedNameConstraintForm,
	PolicyConstraints,
	PolicyMappings,
	SubjectAltName,
} from './extensions.ts';
import { parseAuthorityInfoAccessMethodOid, parseExtendedKeyUsageOid } from './extensions.ts';
import { decodeIpAddress } from './ip.ts';
import { type NameFieldKey, nameFieldKeyFromOid } from './name.ts';
import { OIDS } from './oids.ts';
import { pemDecode, splitPemBlocks } from './pem.ts';

const textDecoder = new TextDecoder();

export interface ParsedNameAttribute {
	readonly oid: string;
	readonly key?: NameFieldKey;
	readonly valueTag: number;
	readonly value: string;
}

export interface ParsedName {
	readonly derHex: string;
	readonly rdns: readonly ParsedRelativeDistinguishedName[];
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
	readonly nameConstraints?: NameConstraints<ParsedNameConstraintForm>;
	readonly certificatePolicies?: CertificatePolicies;
	readonly policyMappings?: PolicyMappings;
	readonly policyConstraints?: PolicyConstraints;
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
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
	readonly nameConstraints?: NameConstraints<ParsedNameConstraintForm>;
	readonly certificatePolicies?: CertificatePolicies;
	readonly policyMappings?: PolicyMappings;
	readonly policyConstraints?: PolicyConstraints;
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
}

export function parseCertificateDer<TMap extends ExtensionDecoderMap = Record<never, never>>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificate<TMap> {
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
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
		...(parsedExtensions.certificatePolicies !== undefined
			? { certificatePolicies: parsedExtensions.certificatePolicies }
			: {}),
		...(parsedExtensions.policyMappings !== undefined
			? { policyMappings: parsedExtensions.policyMappings }
			: {}),
		...(parsedExtensions.policyConstraints !== undefined
			? { policyConstraints: parsedExtensions.policyConstraints }
			: {}),
		...(parsedExtensions.inhibitAnyPolicy !== undefined
			? { inhibitAnyPolicy: parsedExtensions.inhibitAnyPolicy }
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
	const topLevel = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
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
		...(parsedExtensions.nameConstraints !== undefined
			? { nameConstraints: parsedExtensions.nameConstraints }
			: {}),
		...(parsedExtensions.certificatePolicies !== undefined
			? { certificatePolicies: parsedExtensions.certificatePolicies }
			: {}),
		...(parsedExtensions.policyMappings !== undefined
			? { policyMappings: parsedExtensions.policyMappings }
			: {}),
		...(parsedExtensions.policyConstraints !== undefined
			? { policyConstraints: parsedExtensions.policyConstraints }
			: {}),
		...(parsedExtensions.inhibitAnyPolicy !== undefined
			? { inhibitAnyPolicy: parsedExtensions.inhibitAnyPolicy }
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
	readonly nameConstraints?: NameConstraints<ParsedNameConstraintForm>;
	readonly certificatePolicies?: CertificatePolicies;
	readonly policyMappings?: PolicyMappings;
	readonly policyConstraints?: PolicyConstraints;
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
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
	let nameConstraints: NameConstraints<ParsedNameConstraintForm> | undefined;
	let certificatePolicies: CertificatePolicies | undefined;
	let policyMappings: PolicyMappings | undefined;
	let policyConstraints: PolicyConstraints | undefined;
	let inhibitAnyPolicy: InhibitAnyPolicy | undefined;
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
			case OIDS.certificatePolicies:
				certificatePolicies = parseCertificatePolicies(extnValue.value);
				break;
			case OIDS.policyMappings:
				policyMappings = parsePolicyMappings(extnValue.value);
				break;
			case OIDS.policyConstraints:
				policyConstraints = parsePolicyConstraints(extnValue.value);
				break;
			case OIDS.inhibitAnyPolicy:
				inhibitAnyPolicy = parseInhibitAnyPolicy(extnValue.value);
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
		...(certificatePolicies !== undefined ? { certificatePolicies } : {}),
		...(policyMappings !== undefined ? { policyMappings } : {}),
		...(policyConstraints !== undefined ? { policyConstraints } : {}),
		...(inhibitAnyPolicy !== undefined ? { inhibitAnyPolicy } : {}),
		...(authorityInfoAccess !== undefined ? { authorityInfoAccess } : {}),
		...(crlDistributionPoints !== undefined ? { crlDistributionPoints } : {}),
		...(subjectKeyIdentifier !== undefined ? { subjectKeyIdentifier } : {}),
		...(authorityKeyIdentifier !== undefined ? { authorityKeyIdentifier } : {}),
	};
}

function parseName(source: Uint8Array, element: DerElement): ParsedName {
	const rdns: ParsedRelativeDistinguishedName[] = [];
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const setElement of childrenOf(source, element)) {
		const rdn = parseNameAttributeSet(source, setElement);
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

function parseRelativeDistinguishedName(
	source: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	return parseNameAttributeSet(source, element);
}

function parseNameAttributeSet(
	source: Uint8Array,
	setElement: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of childrenOf(source, setElement)) {
		const parts = childrenOf(source, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const fieldKey = nameFieldKeyFromOid(oid);
		const fieldValue = decodeString(valueElement.tag, valueElement.value);
		const attribute: ParsedNameAttribute =
			fieldKey !== undefined
				? { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue }
				: { oid, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(source.slice(setElement.start - setElement.headerLength, setElement.end)),
		attributes,
		values,
	};
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

/** @internal Exported for the extension registry. */
export function parseBasicConstraints(bytes: Uint8Array): BasicConstraints {
	const element = readElement(bytes);
	const children = childrenOf(bytes, element);
	let ca = false;
	let pathLength: number | undefined;
	for (const child of children) {
		if (child.tag === 0x01) {
			ca = decodeBoolean(child.value);
		}
		if (child.tag === 0x02) {
			pathLength = decodeNonNegativeIntegerNumber(child.value, 'basicConstraints pathLength');
		}
	}
	return pathLength !== undefined ? { ca, pathLength } : { ca };
}

/** @internal Exported for the extension registry. */
export function parseKeyUsage(bytes: Uint8Array): readonly KeyUsage[] {
	return parseKeyUsageExtension(bytes);
}

/** @internal Exported for the extension registry. */
export function parseExtendedKeyUsage(bytes: Uint8Array): readonly ExtendedKeyUsage[] {
	const sequenceElement = requireElement(readElement(bytes), 'extendedKeyUsage sequence');
	return childrenOf(bytes, sequenceElement).map((element) =>
		parseExtendedKeyUsageOid(decodeObjectIdentifier(element.value)),
	);
}

/** @internal Exported for the extension registry. */
export function parseCertificatePolicies(bytes: Uint8Array): CertificatePolicies {
	const sequenceElement = requireElement(readElement(bytes), 'certificatePolicies sequence');
	const policyElements = childrenOf(bytes, sequenceElement);
	if (policyElements.length === 0) {
		throw new Error('certificatePolicies must not be empty');
	}
	return policyElements.map((policyElement) => parsePolicyInformation(bytes, policyElement));
}

function parsePolicyInformation(source: Uint8Array, element: DerElement) {
	const children = childrenOf(source, element);
	const policyIdentifier = decodeObjectIdentifier(
		requireElement(children[0], 'policyIdentifier').value,
	);
	const qualifiersElement = children[1];
	if (children.length > 2) {
		throw new Error('policyInformation has unexpected trailing fields');
	}
	if (qualifiersElement === undefined) {
		return { policyIdentifier };
	}
	const qualifiers = childrenOf(source, qualifiersElement);
	if (qualifiers.length === 0) {
		throw new Error('policyQualifiers must not be empty');
	}
	return {
		policyIdentifier,
		policyQualifiers: qualifiers.map((qualifierElement) =>
			parsePolicyQualifierInfo(source, qualifierElement),
		),
	};
}

function parsePolicyQualifierInfo(source: Uint8Array, element: DerElement) {
	const children = childrenOf(source, element);
	const qualifierId = decodeObjectIdentifier(
		requireElement(children[0], 'policyQualifierId').value,
	);
	const qualifierValue = requireElement(children[1], 'policyQualifier');
	if (children.length > 2) {
		throw new Error('policyQualifierInfo has unexpected trailing fields');
	}
	if (qualifierId === OIDS.cpsPolicyQualifier) {
		if (qualifierValue.tag !== 0x16) {
			throw new Error('cps policy qualifier must use IA5String');
		}
		return { type: 'cps' as const, uri: decodeString(qualifierValue.tag, qualifierValue.value) };
	}
	if (qualifierId === OIDS.userNoticePolicyQualifier) {
		return {
			type: 'userNotice' as const,
			...parseUserNoticePolicyQualifierInfo(source, qualifierValue),
		};
	}
	return {
		type: 'oid' as const,
		oid: qualifierId,
		qualifierDer: source.slice(
			qualifierValue.start - qualifierValue.headerLength,
			qualifierValue.end,
		),
	};
}

function parseUserNoticePolicyQualifierInfo(
	source: Uint8Array,
	element: DerElement,
): {
	readonly noticeRef?: { readonly organization: string; readonly noticeNumbers: readonly number[] };
	readonly explicitText?: string;
} {
	const children = childrenOf(source, element);
	let noticeRef:
		| { readonly organization: string; readonly noticeNumbers: readonly number[] }
		| undefined;
	let explicitText: string | undefined;
	for (const child of children) {
		if (child.tag === 0x30) {
			if (noticeRef !== undefined) {
				throw new Error('userNotice must not contain multiple noticeRef values');
			}
			noticeRef = parsePolicyNoticeReference(source, child);
			continue;
		}
		if (explicitText !== undefined) {
			throw new Error('userNotice must not contain multiple explicitText values');
		}
		explicitText = parseDisplayText(child);
	}
	return {
		...(noticeRef === undefined ? {} : { noticeRef }),
		...(explicitText === undefined ? {} : { explicitText }),
	};
}

function parsePolicyNoticeReference(
	source: Uint8Array,
	element: DerElement,
): { readonly organization: string; readonly noticeNumbers: readonly number[] } {
	const children = childrenOf(source, element);
	const organization = parseDisplayText(requireElement(children[0], 'noticeRef organization'));
	const noticeNumbersElement = requireElement(children[1], 'noticeRef noticeNumbers');
	if (children.length > 2) {
		throw new Error('noticeRef has unexpected trailing fields');
	}
	return {
		organization,
		noticeNumbers: parsePolicyNoticeNumbers(source, noticeNumbersElement),
	};
}

function parsePolicyNoticeNumbers(source: Uint8Array, element: DerElement): readonly number[] {
	const noticeNumberElements = childrenOf(source, element);
	if (noticeNumberElements.length === 0) {
		throw new Error('noticeRef noticeNumbers must not be empty');
	}
	return noticeNumberElements.map((noticeNumberElement) =>
		decodeNonNegativeIntegerNumber(noticeNumberElement.value, 'noticeRef noticeNumber'),
	);
}

/** @internal Exported for the extension registry. */
export function parsePolicyMappings(bytes: Uint8Array): PolicyMappings {
	const sequenceElement = requireElement(readElement(bytes), 'policyMappings sequence');
	const mappingElements = childrenOf(bytes, sequenceElement);
	if (mappingElements.length === 0) {
		throw new Error('policyMappings must not be empty');
	}
	return mappingElements.map((mappingElement) => {
		const children = childrenOf(bytes, mappingElement);
		const issuerDomainPolicy = decodeObjectIdentifier(
			requireElement(children[0], 'policyMappings issuerDomainPolicy').value,
		);
		const subjectDomainPolicy = decodeObjectIdentifier(
			requireElement(children[1], 'policyMappings subjectDomainPolicy').value,
		);
		if (children.length > 2) {
			throw new Error('policyMappings entry has unexpected trailing fields');
		}
		if (issuerDomainPolicy === OIDS.anyPolicy || subjectDomainPolicy === OIDS.anyPolicy) {
			throw new Error('policyMappings must not use anyPolicy');
		}
		return { issuerDomainPolicy, subjectDomainPolicy };
	});
}

/** @internal Exported for the extension registry. */
export function parsePolicyConstraints(bytes: Uint8Array): PolicyConstraints {
	const sequenceElement = requireElement(readElement(bytes), 'policyConstraints sequence');
	let requireExplicitPolicy: number | undefined;
	let inhibitPolicyMapping: number | undefined;
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			if (requireExplicitPolicy !== undefined) {
				throw new Error('policyConstraints must not repeat requireExplicitPolicy');
			}
			requireExplicitPolicy = decodeNonNegativeIntegerNumber(
				child.value,
				'policyConstraints requireExplicitPolicy',
			);
			continue;
		}
		if (child.tag === 0x81) {
			if (inhibitPolicyMapping !== undefined) {
				throw new Error('policyConstraints must not repeat inhibitPolicyMapping');
			}
			inhibitPolicyMapping = decodeNonNegativeIntegerNumber(
				child.value,
				'policyConstraints inhibitPolicyMapping',
			);
			continue;
		}
		throw new Error(`Unsupported policyConstraints field tag: ${child.tag}`);
	}
	if (requireExplicitPolicy === undefined && inhibitPolicyMapping === undefined) {
		throw new Error('policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping');
	}
	return {
		...(requireExplicitPolicy === undefined ? {} : { requireExplicitPolicy }),
		...(inhibitPolicyMapping === undefined ? {} : { inhibitPolicyMapping }),
	};
}

/** @internal Exported for the extension registry. */
export function parseInhibitAnyPolicy(bytes: Uint8Array): InhibitAnyPolicy {
	const integerElement = requireElement(readElement(bytes), 'inhibitAnyPolicy integer');
	if (integerElement.tag !== 0x02) {
		throw new Error('inhibitAnyPolicy must be an INTEGER');
	}
	return {
		skipCerts: decodeNonNegativeIntegerNumber(integerElement.value, 'inhibitAnyPolicy skipCerts'),
	};
}

/** @internal Exported for the extension registry. */
export function parseSubjectAltNames(bytes: Uint8Array): readonly SubjectAltName[] {
	const sequenceElement = requireElement(readElement(bytes), 'subjectAltName sequence');
	return childrenOf(bytes, sequenceElement).map((element) => parseGeneralName(bytes, element));
}

/** @internal Exported for the extension registry. */
export function parseAuthorityInfoAccess(bytes: Uint8Array): readonly AuthorityInformationAccess[] {
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

/** @internal Exported for the extension registry. */
export function parseCrlDistributionPoints(bytes: Uint8Array): readonly ParsedDistributionPoint[] {
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
			reasons = parseDistributionPointReasonFlagsContent(child.value);
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
		case 0xa0: {
			const otherName = parseOtherName(source, element);
			if (otherName !== undefined) {
				return otherName;
			}
			return {
				type: 'unknown' as const,
				tag: element.tag,
				value: source.slice(element.start, element.end),
			};
		}
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

function parseOtherName(source: Uint8Array, element: DerElement): SubjectAltName | undefined {
	const otherNameSequence = requireElement(childrenOf(source, element)[0], 'otherName sequence');
	const otherNameChildren = childrenOf(source, otherNameSequence);
	const typeId = requireElement(otherNameChildren[0], 'otherName type-id');
	const valueElement = requireElement(otherNameChildren[1], 'otherName value');
	const typeIdOid = decodeObjectIdentifier(typeId.value);
	if (typeIdOid !== OIDS.idOnDnsSrv) {
		return undefined;
	}
	if (valueElement.tag !== 0xa0) {
		throw new Error('SRV-ID otherName value must use explicit [0]');
	}
	const srvNameElement = requireElement(childrenOf(source, valueElement)[0], 'SRV-ID IA5String');
	if (srvNameElement.tag !== 0x16) {
		throw new Error('SRV-ID otherName value must be an IA5String');
	}
	return { type: 'srv', value: decodeString(srvNameElement.tag, srvNameElement.value) };
}

/** @internal Exported for testing only — not part of the public API. */
export function parseNameConstraints(bytes: Uint8Array): NameConstraints<ParsedNameConstraintForm> {
	const sequenceElement = requireElement(readElement(bytes), 'nameConstraints sequence');
	let permittedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
	let excludedSubtrees: readonly GeneralSubtree<ParsedNameConstraintForm>[] | undefined;
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
): readonly GeneralSubtree<ParsedNameConstraintForm>[] {
	const subtrees: GeneralSubtree<ParsedNameConstraintForm>[] = [];
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
): ParsedNameConstraintForm | undefined {
	switch (element.tag) {
		case 0xa0:
			return { type: 'otherName', value: new Uint8Array(element.value) };
		case 0x81:
			return { type: 'email', value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns', value: textDecoder.decode(element.value) };
		case 0xa3:
			return { type: 'x400Address', value: new Uint8Array(element.value) };
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
		case 0xa5:
			return { type: 'ediPartyName', value: new Uint8Array(element.value) };
		case 0x88:
			return { type: 'registeredID', value: decodeObjectIdentifier(element.value) };
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
	const lengthEncoded = encodeLength(contentBytes.length);
	const result = new Uint8Array(1 + lengthEncoded.length + contentBytes.length);
	result[0] = 0x30;
	result.set(lengthEncoded, 1);
	result.set(contentBytes, 1 + lengthEncoded.length);
	return result;
}

function parseDisplayText(element: DerElement): string {
	switch (element.tag) {
		case 0x0c:
		case 0x16:
		case 0x1a:
			return textDecoder.decode(element.value);
		case 0x1e:
			return decodeBmpString(element.value);
		default:
			throw new Error(`Unsupported DisplayText tag: ${element.tag}`);
	}
}

function decodeBmpString(bytes: Uint8Array): string {
	if (bytes.length % 2 !== 0) {
		throw new Error('Invalid BMPString length');
	}
	let value = '';
	for (let index = 0; index < bytes.length; index += 2) {
		const left = bytes[index];
		const right = bytes[index + 1];
		if (left === undefined || right === undefined) {
			throw new Error('Invalid BMPString content');
		}
		value += String.fromCharCode((left << 8) | right);
	}
	return value;
}

/** @internal Exported for the extension registry. */
export function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = requireElement(readElement(bytes), 'authorityKeyIdentifier sequence');
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			return toHex(child.value);
		}
	}
	return undefined;
}
