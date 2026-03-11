import { type DerElement, readElement } from "./der.ts";
import {
	type AuthorityInformationAccess,
	type BasicConstraints,
	type ExtendedKeyUsage,
	type KeyUsage,
	parseAuthorityInfoAccessMethodOid,
	parseExtendedKeyUsageOid,
	type SubjectAltName,
} from "./extensions.ts";
import type { NameFieldKey } from "./name.ts";
import { OIDS } from "./oids.ts";
import { pemDecode, splitPemBlocks } from "./pem.ts";

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

export type DecodedExtensionMap<TMap extends ExtensionDecoderMap> =
	& {
		[TKey in keyof TMap]?: TMap[TKey] extends ExtensionDecoder<infer TValue> ? DecodedExtensionValue<TValue>
			: never;
	}
	& Partial<Record<keyof TMap, DecodedExtensionValue<unknown>>>;

export interface DecodedExtensionValue<TValue> {
	readonly oid: string;
	readonly critical: boolean;
	readonly value: TValue;
}

export interface ParseOptions<
	TMap extends ExtensionDecoderMap = Record<never, never>,
> {
	readonly decoders?: readonly ExtensionDecoder<unknown>[];
	readonly decoderMap?: TMap;
}

export interface ParsedCertificate<
	TMap extends ExtensionDecoderMap = Record<never, never>,
> {
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
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly string[];
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
	readonly crlDistributionPoints?: readonly string[];
	readonly decodedExtensions?: readonly DecodedExtensionValue<unknown>[];
	readonly decodedExtensionMap?: DecodedExtensionMap<TMap>;
}

export function parseCertificateDer<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(der: Uint8Array, options?: ParseOptions<TMap>): ParsedCertificate<TMap> {
	const topLevel = childrenOf(der, readElement(der));
	const tbsCertificate = requireElement(topLevel[0], "TBSCertificate");
	const signatureAlgorithm = requireElement(topLevel[1], "signatureAlgorithm");
	const signatureValue = requireElement(topLevel[2], "signatureValue");
	const tbsChildren = childrenOf(der, tbsCertificate);

	let index = 0;
	let version = 1;
	const maybeVersion = tbsChildren[index];
	if (maybeVersion?.tag === 0xa0) {
		const versionElement = requireElement(
			childrenOf(der, maybeVersion)[0],
			"version INTEGER",
		);
		version = decodeIntegerNumber(versionElement.value) + 1;
		index += 1;
	}

	const serialNumber = requireElement(tbsChildren[index], "serialNumber");
	const issuer = requireElement(tbsChildren[index + 2], "issuer");
	const validity = requireElement(tbsChildren[index + 3], "validity");
	const subject = requireElement(tbsChildren[index + 4], "subject");
	const subjectPublicKeyInfo = requireElement(
		tbsChildren[index + 5],
		"subjectPublicKeyInfo",
	);
	const extensions = tbsChildren.find((element) => element.tag === 0xa3);
	const parsedExtensions = parseExtensionContainer(der, extensions);
	const parsedValidity = parseValidity(der, validity);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const decodedExtensions = options?.decoders === undefined
		? undefined
		: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap = options?.decoderMap === undefined
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
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm)
			.oid,
		publicKeyAlgorithmOid: parsedSpki.oid,
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		extensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined
			? { keyUsage: parsedExtensions.keyUsage }
			: {}),
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
		...(parsedExtensions.subjectKeyIdentifier !== undefined
			? { subjectKeyIdentifier: parsedExtensions.subjectKeyIdentifier }
			: {}),
		...(parsedExtensions.authorityKeyIdentifier !== undefined
			? { authorityKeyIdentifier: parsedExtensions.authorityKeyIdentifier }
			: {}),
	};
}

export function parseCertificatePem<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(pem: string, options?: ParseOptions<TMap>): ParsedCertificate<TMap> {
	return parseCertificateDer(pemDecode("CERTIFICATE", pem), options);
}

export function parseCertificateChainPem<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(
	pemBundle: string,
	options?: ParseOptions<TMap>,
): readonly ParsedCertificate<TMap>[] {
	return splitPemBlocks(pemBundle)
		.filter((block) => block.label === "CERTIFICATE")
		.map((block) => parseCertificateDer(block.bytes, options));
}

export function parseCertificateSigningRequestDer<
	TMap extends ExtensionDecoderMap = Record<never, never>,
>(
	der: Uint8Array,
	options?: ParseOptions<TMap>,
): ParsedCertificateSigningRequest<TMap> {
	const topLevel = childrenOf(der, readElement(der));
	const certificationRequestInfo = requireElement(
		topLevel[0],
		"CertificationRequestInfo",
	);
	const signatureAlgorithm = requireElement(topLevel[1], "signatureAlgorithm");
	const signatureValue = requireElement(topLevel[2], "signatureValue");
	const criChildren = childrenOf(der, certificationRequestInfo);
	const version = decodeIntegerNumber(requireElement(criChildren[0], "version").value) + 1;
	const subject = requireElement(criChildren[1], "subject");
	const subjectPublicKeyInfo = requireElement(
		criChildren[2],
		"subjectPublicKeyInfo",
	);
	const attributes = criChildren[3];
	const parsedExtensions = parseRequestedExtensions(der, attributes);
	const parsedSpki = parseSubjectPublicKeyInfo(der, subjectPublicKeyInfo);
	const decodedExtensions = options?.decoders === undefined
		? undefined
		: decodeExtensions(parsedExtensions.all, options.decoders);
	const decodedExtensionMap = options?.decoderMap === undefined
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
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm)
			.oid,
		publicKeyAlgorithmOid: parsedSpki.oid,
		...(parsedSpki.parametersOid !== undefined
			? { publicKeyParametersOid: parsedSpki.parametersOid }
			: {}),
		requestedExtensions: parsedExtensions.all,
		...(parsedExtensions.basicConstraints !== undefined
			? { basicConstraints: parsedExtensions.basicConstraints }
			: {}),
		...(parsedExtensions.keyUsage !== undefined
			? { keyUsage: parsedExtensions.keyUsage }
			: {}),
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
>(
	pem: string,
	options?: ParseOptions<TMap>,
): ParsedCertificateSigningRequest<TMap> {
	return parseCertificateSigningRequestDer(
		pemDecode("CERTIFICATE REQUEST", pem),
		options,
	);
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
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly string[];
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
	const sequenceElement = requireElement(
		childrenOf(source, container)[0],
		"extensions sequence",
	);
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
		const oid = requireElement(attributeChildren[0], "attribute OID");
		if (decodeObjectIdentifier(oid.value) !== OIDS.extensionRequest) {
			continue;
		}
		const valuesSet = requireElement(attributeChildren[1], "attribute values");
		const requested = requireElement(
			childrenOf(source, valuesSet)[0],
			"requested extensions",
		);
		return parseExtensionSequence(source, requested);
	}
	return { all: [] };
}

function parseExtensionSequence(
	source: Uint8Array,
	sequenceElement: DerElement,
): ParsedExtensions {
	const parsed: ParsedExtension[] = [];
	let basicConstraints: BasicConstraints | undefined;
	let keyUsage: readonly KeyUsage[] | undefined;
	let extendedKeyUsage: readonly ExtendedKeyUsage[] | undefined;
	let subjectAltNames: readonly SubjectAltName[] | undefined;
	let authorityInfoAccess: readonly AuthorityInformationAccess[] | undefined;
	let crlDistributionPoints: readonly string[] | undefined;
	let subjectKeyIdentifier: string | undefined;
	let authorityKeyIdentifier: string | undefined;

	for (const extension of childrenOf(source, sequenceElement)) {
		const children = childrenOf(source, extension);
		const oidElement = requireElement(children[0], "extension OID");
		const oid = decodeObjectIdentifier(oidElement.value);
		let offset = 1;
		let critical = false;
		const maybeCritical = children[offset];
		if (maybeCritical?.tag === 0x01) {
			critical = decodeBoolean(maybeCritical.value);
			offset += 1;
		}
		const extnValue = requireElement(children[offset], "extension value");
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
		const attributeSequence = requireElement(
			childrenOf(source, setElement)[0],
			"name attribute",
		);
		const parts = childrenOf(source, attributeSequence);
		const oid = decodeObjectIdentifier(
			requireElement(parts[0], "name OID").value,
		);
		const valueElement = requireElement(parts[1], "name value");
		const key = nameKeyFromOid(oid);
		const value = decodeString(valueElement.tag, valueElement.value);
		attributes.push({ oid, ...(key !== undefined ? { key } : {}), value });
		if (key !== undefined) {
			values[key] = value;
		}
	}
	return {
		derHex: toHex(
			source.slice(element.start - element.headerLength, element.end),
		),
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
		notBefore: parseTime(requireElement(children[0], "notBefore")),
		notAfter: parseTime(requireElement(children[1], "notAfter")),
	};
}

function parseSubjectPublicKeyInfo(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string; readonly parametersOid?: string } {
	const children = childrenOf(source, element);
	const algorithm = parseAlgorithmIdentifier(
		source,
		requireElement(children[0], "SPKI algorithm"),
	);
	return algorithm;
}

function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string; readonly parametersOid?: string } {
	const children = childrenOf(source, element);
	const oid = decodeObjectIdentifier(
		requireElement(children[0], "algorithm OID").value,
	);
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
	const bitString = requireElement(readElement(bytes), "keyUsage bit string");
	const unusedBits = bitString.value[0] ?? 0;
	const data = bitString.value.slice(1);
	const usages: KeyUsage[] = [];
	const candidates: readonly KeyUsage[] = [
		"digitalSignature",
		"nonRepudiation",
		"keyEncipherment",
		"dataEncipherment",
		"keyAgreement",
		"keyCertSign",
		"cRLSign",
		"encipherOnly",
		"decipherOnly",
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
	if (unusedBits > 7) {
		throw new Error("Invalid BIT STRING");
	}
	return usages;
}

function parseExtendedKeyUsage(bytes: Uint8Array): readonly ExtendedKeyUsage[] {
	const sequenceElement = requireElement(
		readElement(bytes),
		"extendedKeyUsage sequence",
	);
	return childrenOf(bytes, sequenceElement).map((element) =>
		parseExtendedKeyUsageOid(decodeObjectIdentifier(element.value))
	);
}

function parseSubjectAltNames(bytes: Uint8Array): readonly SubjectAltName[] {
	const sequenceElement = requireElement(
		readElement(bytes),
		"subjectAltName sequence",
	);
	return childrenOf(bytes, sequenceElement).map((element) => {
		switch (element.tag) {
			case 0x81:
				return { type: "email", value: textDecoder.decode(element.value) };
			case 0x82:
				return { type: "dns", value: textDecoder.decode(element.value) };
			case 0x86:
				return { type: "uri", value: textDecoder.decode(element.value) };
			case 0x87:
				return { type: "ip", value: decodeIpAddress(element.value) };
			default:
				throw new Error(`Unsupported GeneralName tag: ${element.tag}`);
		}
	});
}

function parseAuthorityInfoAccess(
	bytes: Uint8Array,
): readonly AuthorityInformationAccess[] {
	const sequenceElement = requireElement(
		readElement(bytes),
		"authorityInfoAccess sequence",
	);
	return childrenOf(bytes, sequenceElement).map((element) => {
		const children = childrenOf(bytes, element);
		const method = requireElement(children[0], "authorityInfoAccess method");
		const location = requireElement(
			children[1],
			"authorityInfoAccess location",
		);
		if (location.tag !== 0x86) {
			throw new Error(
				`Unsupported authorityInfoAccess location tag: ${location.tag}`,
			);
		}
		return {
			method: parseAuthorityInfoAccessMethodOid(
				decodeObjectIdentifier(method.value),
			),
			uri: textDecoder.decode(location.value),
		};
	});
}

function parseCrlDistributionPoints(bytes: Uint8Array): readonly string[] {
	const sequenceElement = requireElement(
		readElement(bytes),
		"cRLDistributionPoints sequence",
	);
	const uris: string[] = [];
	for (const distributionPoint of childrenOf(bytes, sequenceElement)) {
		for (const child of childrenOf(bytes, distributionPoint)) {
			if (child.tag !== 0xa0) {
				continue;
			}
			const distributionPointName = requireElement(
				childrenOf(bytes, child)[0],
				"distributionPointName",
			);
			if (distributionPointName.tag !== 0xa0) {
				continue;
			}
			const generalNames = requireElement(
				childrenOf(bytes, distributionPointName)[0],
				"generalNames",
			);
			for (const name of childrenOf(bytes, generalNames)) {
				if (name.tag === 0x86) {
					uris.push(textDecoder.decode(name.value));
				}
			}
		}
	}
	return uris;
}

function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = requireElement(
		readElement(bytes),
		"authorityKeyIdentifier sequence",
	);
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			return toHex(child.value);
		}
	}
	return undefined;
}

function parseTime(element: DerElement): Date {
	const value = textDecoder.decode(element.value);
	if (element.tag === 0x17) {
		const yearPrefix = Number.parseInt(value.slice(0, 2), 10) >= 50 ? "19" : "20";
		return new Date(
			`${yearPrefix}${value.slice(0, 2)}-${value.slice(2, 4)}-${value.slice(4, 6)}T${value.slice(6, 8)}:${
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

function decodeString(tag: number, bytes: Uint8Array): string {
	switch (tag) {
		case 0x0c:
		case 0x13:
		case 0x16:
			return textDecoder.decode(bytes);
		default:
			throw new Error(`Unsupported string tag: ${tag}`);
	}
}

function decodeBoolean(bytes: Uint8Array): boolean {
	return (bytes[0] ?? 0) !== 0;
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

function decodeIpAddress(bytes: Uint8Array): string {
	if (bytes.length === 4) {
		return Array.from(bytes, (value) => String(value)).join(".");
	}
	if (bytes.length === 16) {
		const groups: string[] = [];
		for (let index = 0; index < bytes.length; index += 2) {
			const left = bytes[index] ?? 0;
			const right = bytes[index + 1] ?? 0;
			groups.push(((left << 8) | right).toString(16));
		}
		return groups.join(":");
	}
	throw new Error("Unsupported IP address length");
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

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join(
		"",
	);
}

function nameKeyFromOid(oid: string): NameFieldKey | undefined {
	switch (oid) {
		case OIDS.commonName:
			return "commonName";
		case OIDS.surname:
			return "surname";
		case OIDS.serialNumber:
			return "serialNumber";
		case OIDS.countryName:
			return "country";
		case OIDS.localityName:
			return "locality";
		case OIDS.stateOrProvinceName:
			return "state";
		case OIDS.streetAddress:
			return "street";
		case OIDS.organizationName:
			return "organization";
		case OIDS.organizationalUnitName:
			return "organizationalUnit";
		case OIDS.title:
			return "title";
		case OIDS.givenName:
			return "givenName";
		case OIDS.emailAddress:
			return "emailAddress";
	}
	return undefined;
}
