import { hexToBytes } from './asn1.ts';
import {
	bitString,
	bool,
	concatBytes,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	tlv,
} from './der.ts';
import { sha1 } from './hash.ts';
import { encodeRelativeDistinguishedName, type RelativeDistinguishedNameInput } from './name.ts';
import { OIDS } from './oids.ts';

export type KeyUsage =
	| 'digitalSignature'
	| 'nonRepudiation'
	| 'keyEncipherment'
	| 'dataEncipherment'
	| 'keyAgreement'
	| 'keyCertSign'
	| 'cRLSign'
	| 'encipherOnly'
	| 'decipherOnly';

export type SubjectAltName =
	| { readonly type: 'dns'; readonly value: string }
	| { readonly type: 'ip'; readonly value: string }
	| { readonly type: 'email'; readonly value: string }
	| { readonly type: 'uri'; readonly value: string }
	| { readonly type: 'directoryName'; readonly derHex: string }
	| {
			readonly type: 'unknown';
			readonly tag: number;
			readonly value: Uint8Array;
	  };

export type GeneralName = SubjectAltName;

export type DistributionPointReason =
	| 'keyCompromise'
	| 'cACompromise'
	| 'affiliationChanged'
	| 'superseded'
	| 'cessationOfOperation'
	| 'certificateHold'
	| 'privilegeWithdrawn'
	| 'aACompromise';

export interface DistributionPointName {
	readonly fullName?: readonly GeneralName[];
	readonly relativeName?: RelativeDistinguishedNameInput;
}

export type DistributionPoint =
	| {
			readonly distributionPoint: DistributionPointName;
			readonly reasons?: readonly DistributionPointReason[];
			readonly crlIssuer?: readonly GeneralName[];
	  }
	| {
			readonly distributionPoint?: DistributionPointName;
			readonly reasons?: readonly DistributionPointReason[];
			readonly crlIssuer: readonly GeneralName[];
	  };

interface IssuingDistributionPointBase {
	readonly distributionPoint?: DistributionPointName;
	readonly onlySomeReasons?: readonly DistributionPointReason[];
	readonly indirectCrl?: boolean;
	readonly onlyContainsUserCerts?: false;
	readonly onlyContainsCACerts?: false;
	readonly onlyContainsAttributeCerts?: boolean;
}

interface IssuingDistributionPointForUserCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsUserCerts'> {
	readonly onlyContainsUserCerts: true;
	readonly onlyContainsCACerts?: false;
	readonly onlyContainsAttributeCerts?: false;
}

interface IssuingDistributionPointForCaCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsCACerts'> {
	readonly onlyContainsUserCerts?: false;
	readonly onlyContainsCACerts: true;
	readonly onlyContainsAttributeCerts?: false;
}

interface IssuingDistributionPointForAttributeCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsAttributeCerts'> {
	readonly onlyContainsUserCerts?: false;
	readonly onlyContainsCACerts?: false;
	readonly onlyContainsAttributeCerts: true;
}

export type IssuingDistributionPoint =
	| IssuingDistributionPointBase
	| IssuingDistributionPointForUserCerts
	| IssuingDistributionPointForCaCerts
	| IssuingDistributionPointForAttributeCerts;

export interface BasicConstraints {
	readonly ca: boolean;
	readonly pathLength?: number;
}

export type CertificatePolicies = readonly PolicyInformation[];

export interface PolicyInformation {
	readonly policyIdentifier: string;
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

export interface CpsPolicyQualifierInfo {
	readonly type: 'cps';
	readonly uri: string;
}

export interface PolicyNoticeReference {
	readonly organization: string;
	readonly noticeNumbers: readonly number[];
}

export interface UserNoticePolicyQualifierInfo {
	readonly type: 'userNotice';
	readonly noticeRef?: PolicyNoticeReference;
	readonly explicitText?: string;
}

export interface CustomPolicyQualifierInfo {
	readonly type: 'oid';
	readonly oid: string;
	readonly qualifierDer: Uint8Array;
}

export type PolicyQualifierInfo =
	| CpsPolicyQualifierInfo
	| UserNoticePolicyQualifierInfo
	| CustomPolicyQualifierInfo;

export type PolicyMappings = readonly PolicyMapping[];

export interface PolicyMapping {
	readonly issuerDomainPolicy: string;
	readonly subjectDomainPolicy: string;
}

export interface PolicyConstraints {
	readonly requireExplicitPolicy?: number;
	readonly inhibitPolicyMapping?: number;
}

export interface InhibitAnyPolicy {
	readonly skipCerts: number;
}

export interface CertificateExtensionsInput {
	readonly subjectAltNames?: readonly SubjectAltName[];
	readonly keyUsage?: readonly KeyUsage[];
	readonly basicConstraints?: BasicConstraints;
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	readonly nameConstraints?: NameConstraints;
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	readonly crlDistributionPoints?: readonly DistributionPoint[];
	readonly customExtensions?: readonly CustomExtension[];
}

export interface CustomExtension {
	readonly oid: string;
	readonly value: Uint8Array;
	readonly critical?: boolean;
}

// ---------------------------------------------------------------------------
// Name constraints (RFC 5280 §4.2.1.10)
// ---------------------------------------------------------------------------

/**
 * A name form used as a constraint base in nameConstraints.
 * Distinct from {@link SubjectAltName} because IP constraints carry
 * address + mask bytes (8 for IPv4, 32 for IPv6) rather than bare addresses.
 */
export type NameConstraintForm =
	| { readonly type: 'dns'; readonly value: string }
	| { readonly type: 'email'; readonly value: string }
	| { readonly type: 'uri'; readonly value: string }
	| {
			readonly type: 'ip';
			readonly addressBytes: Uint8Array;
			readonly maskBytes: Uint8Array;
	  }
	| { readonly type: 'directoryName'; readonly derHex: string };

export interface GeneralSubtree {
	readonly base: NameConstraintForm;
}

export interface NameConstraints {
	readonly permittedSubtrees?: readonly GeneralSubtree[];
	readonly excludedSubtrees?: readonly GeneralSubtree[];
}

export type KnownAuthorityInfoAccessMethod = 'ocsp' | 'caIssuers';

export interface CustomAuthorityInfoAccessMethod {
	readonly type: 'oid';
	readonly value: string;
}

export type AuthorityInfoAccessMethod =
	| KnownAuthorityInfoAccessMethod
	| CustomAuthorityInfoAccessMethod;

export interface AuthorityInformationAccess {
	readonly method: AuthorityInfoAccessMethod;
	readonly uri: string;
}

export type KnownExtendedKeyUsage =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

export interface CustomExtendedKeyUsage {
	readonly type: 'oid';
	readonly value: string;
}

export type ExtendedKeyUsage = KnownExtendedKeyUsage | CustomExtendedKeyUsage;

const EXTENDED_KEY_USAGE_OIDS: Record<KnownExtendedKeyUsage, string> = {
	serverAuth: OIDS.serverAuth,
	clientAuth: OIDS.clientAuth,
	codeSigning: OIDS.codeSigning,
	emailProtection: OIDS.emailProtection,
	timeStamping: OIDS.timeStamping,
	ocspSigning: OIDS.ocspSigning,
};

const AUTHORITY_INFO_ACCESS_METHOD_OIDS: Record<KnownAuthorityInfoAccessMethod, string> = {
	ocsp: OIDS.ocspAccessMethod,
	caIssuers: OIDS.caIssuersAccessMethod,
};

const KEY_USAGE_BITS: Record<KeyUsage, number> = {
	digitalSignature: 0,
	nonRepudiation: 1,
	keyEncipherment: 2,
	dataEncipherment: 3,
	keyAgreement: 4,
	keyCertSign: 5,
	cRLSign: 6,
	encipherOnly: 7,
	decipherOnly: 8,
};

const DISTRIBUTION_POINT_REASON_BITS: Record<DistributionPointReason, number> = {
	keyCompromise: 1,
	cACompromise: 2,
	affiliationChanged: 3,
	superseded: 4,
	cessationOfOperation: 5,
	certificateHold: 6,
	privilegeWithdrawn: 7,
	aACompromise: 8,
};

export function buildCertificateExtensions(
	subjectPublicKeyInfo: Uint8Array,
	issuerPublicKeyInfo: Uint8Array | undefined,
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	const seen = new Set<string>();
	const basicConstraints = input?.basicConstraints ?? { ca: false };
	pushExtension(
		extensions,
		seen,
		OIDS.basicConstraints,
		encodeBasicConstraints(basicConstraints),
		true,
	);
	pushExtension(
		extensions,
		seen,
		OIDS.subjectKeyIdentifier,
		octetString(buildSubjectKeyIdentifier(subjectPublicKeyInfo)),
	);
	if (issuerPublicKeyInfo !== undefined) {
		pushExtension(
			extensions,
			seen,
			OIDS.authorityKeyIdentifier,
			sequence([implicitPrimitiveContext(0, buildSubjectKeyIdentifier(issuerPublicKeyInfo))]),
		);
	}
	if (input?.keyUsage !== undefined && input.keyUsage.length > 0) {
		pushExtension(extensions, seen, OIDS.keyUsage, encodeKeyUsage(input.keyUsage), true);
	}
	if (input?.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.subjectAltName,
			sequence(input.subjectAltNames.map(encodeSubjectAltName)),
		);
	}
	if (input?.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.extendedKeyUsage,
			encodeExtendedKeyUsage(input.extendedKeyUsage),
		);
	}
	if (input?.nameConstraints !== undefined) {
		pushExtension(
			extensions,
			seen,
			OIDS.nameConstraints,
			encodeNameConstraints(input.nameConstraints),
			true,
		);
	}
	if (input?.authorityInfoAccess !== undefined && input.authorityInfoAccess.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.authorityInfoAccess,
			encodeAuthorityInfoAccess(input.authorityInfoAccess),
		);
	}
	if (input?.crlDistributionPoints !== undefined && input.crlDistributionPoints.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.cRLDistributionPoints,
			encodeCrlDistributionPoints(input.crlDistributionPoints),
		);
	}
	if (input?.customExtensions !== undefined) {
		for (const extension of input.customExtensions) {
			pushExtension(
				extensions,
				seen,
				extension.oid,
				new Uint8Array(extension.value),
				extension.critical ?? false,
			);
		}
	}
	return extensions;
}

export function buildRequestedExtensions(
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	const seen = new Set<string>();
	if (input?.basicConstraints !== undefined) {
		pushExtension(
			extensions,
			seen,
			OIDS.basicConstraints,
			encodeBasicConstraints(input.basicConstraints),
			true,
		);
	}
	if (input?.keyUsage !== undefined && input.keyUsage.length > 0) {
		pushExtension(extensions, seen, OIDS.keyUsage, encodeKeyUsage(input.keyUsage), true);
	}
	if (input?.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.subjectAltName,
			sequence(input.subjectAltNames.map(encodeSubjectAltName)),
		);
	}
	if (input?.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.extendedKeyUsage,
			encodeExtendedKeyUsage(input.extendedKeyUsage),
		);
	}
	if (input?.authorityInfoAccess !== undefined && input.authorityInfoAccess.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.authorityInfoAccess,
			encodeAuthorityInfoAccess(input.authorityInfoAccess),
		);
	}
	if (input?.crlDistributionPoints !== undefined && input.crlDistributionPoints.length > 0) {
		pushExtension(
			extensions,
			seen,
			OIDS.cRLDistributionPoints,
			encodeCrlDistributionPoints(input.crlDistributionPoints),
		);
	}
	if (input?.customExtensions !== undefined) {
		for (const extension of input.customExtensions) {
			pushExtension(
				extensions,
				seen,
				extension.oid,
				new Uint8Array(extension.value),
				extension.critical ?? false,
			);
		}
	}
	return extensions;
}

export function encodeExtension(oid: string, extnValue: Uint8Array, critical = false): Uint8Array {
	const fields = [objectIdentifier(oid)];
	if (critical) {
		fields.push(bool(true));
	}
	fields.push(octetString(extnValue));
	return sequence(fields);
}

export function encodeBasicConstraints(input: BasicConstraints): Uint8Array {
	const fields: Uint8Array[] = [];
	if (input.ca) {
		fields.push(bool(true));
	}
	if (input.pathLength !== undefined) {
		if (!input.ca) {
			throw new Error('pathLength requires ca=true');
		}
		fields.push(integerFromNumber(input.pathLength));
	}
	return sequence(fields);
}

export function encodeKeyUsage(usages: readonly KeyUsage[]): Uint8Array {
	let highestBit = 0;
	for (const usage of usages) {
		const index = KEY_USAGE_BITS[usage];
		if (index > highestBit) {
			highestBit = index;
		}
	}
	const byteLength = Math.floor(highestBit / 8) + 1;
	const bytes = new Uint8Array(byteLength);
	for (const usage of usages) {
		const index = KEY_USAGE_BITS[usage];
		const byteIndex = Math.floor(index / 8);
		const bitIndex = index % 8;
		const current = bytes[byteIndex] ?? 0;
		bytes[byteIndex] = current | (1 << (7 - bitIndex));
	}
	const unusedBits = (8 - ((highestBit + 1) % 8)) % 8;
	return bitString(bytes, unusedBits);
}

export function encodeSubjectAltName(value: SubjectAltName): Uint8Array {
	switch (value.type) {
		case 'dns':
			return implicitPrimitiveContext(2, new TextEncoder().encode(value.value));
		case 'email':
			return implicitPrimitiveContext(1, new TextEncoder().encode(value.value));
		case 'uri':
			return implicitPrimitiveContext(6, new TextEncoder().encode(value.value));
		case 'ip':
			return implicitPrimitiveContext(7, encodeIpAddress(value.value));
		case 'directoryName':
			return implicitConstructedContext(4, hexToBytes(value.derHex));
		case 'unknown':
			return tlv(value.tag, value.value);
		default: {
			const _exhaustive: never = value;
			throw new Error(`Unhandled SubjectAltName type: ${String(_exhaustive)}`);
		}
	}
}

export function encodeExtendedKeyUsage(usages: readonly ExtendedKeyUsage[]): Uint8Array {
	return sequence(usages.map((usage) => objectIdentifier(getExtendedKeyUsageOid(usage))));
}

export function encodeAuthorityInfoAccess(
	entries: readonly AuthorityInformationAccess[],
): Uint8Array {
	return sequence(
		entries.map((entry) =>
			sequence([
				objectIdentifier(getAuthorityInfoAccessMethodOid(entry.method)),
				implicitPrimitiveContext(6, new TextEncoder().encode(entry.uri)),
			]),
		),
	);
}

export function encodeCrlDistributionPoints(points: readonly DistributionPoint[]): Uint8Array {
	return sequence(points.map((point) => sequence(encodeDistributionPoint(point))));
}

export function encodeNameConstraints(constraints: NameConstraints): Uint8Array {
	const parts: Uint8Array[] = [];
	if (constraints.permittedSubtrees !== undefined && constraints.permittedSubtrees.length > 0) {
		parts.push(
			implicitConstructedContext(
				0,
				concatBytes(constraints.permittedSubtrees.map(encodeGeneralSubtree)),
			),
		);
	}
	if (constraints.excludedSubtrees !== undefined && constraints.excludedSubtrees.length > 0) {
		parts.push(
			implicitConstructedContext(
				1,
				concatBytes(constraints.excludedSubtrees.map(encodeGeneralSubtree)),
			),
		);
	}
	return sequence(parts);
}

function encodeGeneralSubtree(subtree: GeneralSubtree): Uint8Array {
	return sequence([encodeNameConstraintForm(subtree.base)]);
}

function encodeDistributionPoint(point: DistributionPoint): Uint8Array[] {
	if (point.distributionPoint === undefined && point.crlIssuer === undefined) {
		throw new Error('DistributionPoint must contain distributionPoint or crlIssuer');
	}
	const fields: Uint8Array[] = [];
	if (point.distributionPoint !== undefined) {
		fields.push(
			implicitConstructedContext(0, encodeDistributionPointName(point.distributionPoint)),
		);
	}
	if (point.reasons !== undefined && point.reasons.length > 0) {
		fields.push(implicitPrimitiveContext(1, encodeDistributionPointReasonFlags(point.reasons)));
	}
	if (point.crlIssuer !== undefined && point.crlIssuer.length > 0) {
		fields.push(
			implicitConstructedContext(2, concatBytes(point.crlIssuer.map(encodeSubjectAltName))),
		);
	}
	return fields;
}

function encodeDistributionPointName(name: DistributionPointName): Uint8Array {
	if (name.fullName !== undefined && name.relativeName !== undefined) {
		throw new Error('DistributionPointName cannot contain both fullName and relativeName');
	}
	if (name.fullName !== undefined) {
		if (name.fullName.length === 0) {
			throw new Error('DistributionPointName fullName must not be empty');
		}
		return implicitConstructedContext(0, concatBytes(name.fullName.map(encodeSubjectAltName)));
	}
	if (name.relativeName !== undefined) {
		const relativeName = encodeRelativeDistinguishedName(name.relativeName);
		const relativeNameElement = readElement(relativeName);
		return implicitConstructedContext(
			1,
			relativeName.slice(relativeNameElement.start, relativeNameElement.end),
		);
	}
	throw new Error('DistributionPointName must contain fullName or relativeName');
}

function encodeDistributionPointReasonFlags(
	reasons: readonly DistributionPointReason[],
): Uint8Array {
	let highestBit = 0;
	for (const reason of reasons) {
		const bit = DISTRIBUTION_POINT_REASON_BITS[reason];
		if (bit > highestBit) {
			highestBit = bit;
		}
	}
	const byteLength = Math.floor(highestBit / 8) + 1;
	const bytes = new Uint8Array(byteLength);
	for (const reason of reasons) {
		const bit = DISTRIBUTION_POINT_REASON_BITS[reason];
		const byteIndex = Math.floor(bit / 8);
		const bitIndex = bit % 8;
		const current = bytes[byteIndex] ?? 0;
		bytes[byteIndex] = current | (1 << (7 - bitIndex));
	}
	const unusedBits = (8 - ((highestBit + 1) % 8)) % 8;
	return concatBytes([Uint8Array.of(unusedBits), bytes]);
}

function encodeNameConstraintForm(form: NameConstraintForm): Uint8Array {
	switch (form.type) {
		case 'dns':
			return implicitPrimitiveContext(2, new TextEncoder().encode(form.value));
		case 'email':
			return implicitPrimitiveContext(1, new TextEncoder().encode(form.value));
		case 'uri':
			return implicitPrimitiveContext(6, new TextEncoder().encode(form.value));
		case 'ip':
			return implicitPrimitiveContext(7, concatBytes([form.addressBytes, form.maskBytes]));
		case 'directoryName':
			return implicitConstructedContext(4, hexToBytes(form.derHex));
		default: {
			const _exhaustive: never = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(_exhaustive)}`);
		}
	}
}

export function getExtendedKeyUsageOid(usage: ExtendedKeyUsage): string {
	if (typeof usage === 'string') {
		return EXTENDED_KEY_USAGE_OIDS[usage];
	}
	validateOid(usage.value);
	return usage.value;
}

export function parseExtendedKeyUsageOid(oid: string): ExtendedKeyUsage {
	switch (oid) {
		case OIDS.serverAuth:
			return 'serverAuth';
		case OIDS.clientAuth:
			return 'clientAuth';
		case OIDS.codeSigning:
			return 'codeSigning';
		case OIDS.emailProtection:
			return 'emailProtection';
		case OIDS.timeStamping:
			return 'timeStamping';
		case OIDS.ocspSigning:
			return 'ocspSigning';
	}
	return { type: 'oid', value: oid };
}

export function getAuthorityInfoAccessMethodOid(method: AuthorityInfoAccessMethod): string {
	if (typeof method === 'string') {
		return AUTHORITY_INFO_ACCESS_METHOD_OIDS[method];
	}
	validateOid(method.value);
	return method.value;
}

export function parseAuthorityInfoAccessMethodOid(oid: string): AuthorityInfoAccessMethod {
	switch (oid) {
		case OIDS.ocspAccessMethod:
			return 'ocsp';
		case OIDS.caIssuersAccessMethod:
			return 'caIssuers';
	}
	return { type: 'oid', value: oid };
}

function encodeIpAddress(input: string): Uint8Array {
	if (input.includes(':')) {
		return encodeIpv6Address(input);
	}
	const segments = input.split('.');
	if (segments.length !== 4) {
		throw new Error(`Invalid IPv4 address: ${input}`);
	}
	return Uint8Array.from(
		segments.map((segment) => {
			const parsed = Number(segment);
			if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
				throw new Error(`Invalid IPv4 address: ${input}`);
			}
			return parsed;
		}),
	);
}

function encodeIpv6Address(input: string): Uint8Array {
	const pieces = input.split('::');
	const head = pieces[0] ?? '';
	const tail = pieces[1];
	if (tail !== undefined && input.indexOf('::') !== input.lastIndexOf('::')) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const headParts = head.length > 0 ? head.split(':') : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(':') : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const zeroes = Array.from({ length: missing }, () => '0');
	const parts = tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts];
	if (parts.length !== 8) {
		throw new Error(`Invalid IPv6 address: ${input}`);
	}
	const out = new Uint8Array(16);
	parts.forEach((part, index) => {
		const parsed = Number.parseInt(part, 16);
		if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffff) {
			throw new Error(`Invalid IPv6 address: ${input}`);
		}
		out[index * 2] = parsed >> 8;
		out[index * 2 + 1] = parsed & 0xff;
	});
	return out;
}

function buildSubjectKeyIdentifier(subjectPublicKeyInfo: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(subjectPublicKeyInfo);
	const subjectPublicKey = topLevel[1];
	if (subjectPublicKey === undefined || subjectPublicKey.tag !== 0x03) {
		throw new Error('SPKI missing subject public key bit string');
	}
	const publicKeyBytes = subjectPublicKey.value.slice(1);
	return sha1(publicKeyBytes);
}

function validateOid(oid: string): void {
	if (!/^\d+(?:\.\d+)+$/.test(oid)) {
		throw new Error(`Invalid OID: ${oid}`);
	}
}

function pushExtension(
	encoded: Uint8Array[],
	seen: Set<string>,
	oid: string,
	value: Uint8Array,
	critical = false,
): void {
	validateOid(oid);
	if (seen.has(oid)) {
		throw new Error(`Duplicate extension OID: ${oid}`);
	}
	seen.add(oid);
	encoded.push(encodeExtension(oid, value, critical));
}
