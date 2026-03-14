/**
 * Typed certificate and CSR extension model plus encoder helpers.
 *
 * This module defines the public extension input surface and the shared builders used by
 * create flows.
 */

import { hexToBytes } from './asn1.ts';
import {
	bool,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	ia5String,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readRootElement,
	readSequenceChildren,
	sequence,
	tlv,
	utf8String,
} from './der.ts';
import {
	encodeDistributionPointReasonFlagsContent,
	encodeKeyUsageExtension,
} from './extension-bits.ts';
import {
	AUTHORITY_INFO_ACCESS_EXTENSION_DEFINITION,
	AUTHORITY_KEY_IDENTIFIER_EXTENSION_DEFINITION,
	BASIC_CONSTRAINTS_EXTENSION_DEFINITION,
	CERTIFICATE_POLICIES_EXTENSION_DEFINITION,
	CRL_DISTRIBUTION_POINTS_EXTENSION_DEFINITION,
	EXTENDED_KEY_USAGE_EXTENSION_DEFINITION,
	type ExtensionDefinition,
	type ExtensionRegistryContext,
	getExtensionDefinition,
	INHIBIT_ANY_POLICY_EXTENSION_DEFINITION,
	KEY_USAGE_EXTENSION_DEFINITION,
	NAME_CONSTRAINTS_EXTENSION_DEFINITION,
	POLICY_CONSTRAINTS_EXTENSION_DEFINITION,
	POLICY_MAPPINGS_EXTENSION_DEFINITION,
	SUBJECT_ALT_NAME_EXTENSION_DEFINITION,
	SUBJECT_KEY_IDENTIFIER_EXTENSION_DEFINITION,
} from './extension-registry.ts';
import { sha1 } from './hash.ts';
import { parseIpAddressToBytes } from './ip.ts';
import { encodeRelativeDistinguishedName, type RelativeDistinguishedNameInput } from './name.ts';
import { OIDS } from './oids.ts';

/**
 * Defines key usage.
 */
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

/**
 * Defines subject alt name.
 */
export type SubjectAltName =
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'dns';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'ip';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'email';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'uri';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'srv';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'directoryName';
			/**
			 * Carries the hexadecimal der.
			 */
			readonly derHex: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'unknown';
			/**
			 * Carries the tag value.
			 */
			readonly tag: number;
			/**
			 * Carries the successful value payload.
			 */
			readonly value: Uint8Array;
	  };

/**
 * Defines general name.
 */
export type GeneralName = SubjectAltName;

/**
 * Enumerates distribution point values used by this module.
 */
export type DistributionPointReason =
	| 'keyCompromise'
	| 'cACompromise'
	| 'affiliationChanged'
	| 'superseded'
	| 'cessationOfOperation'
	| 'certificateHold'
	| 'privilegeWithdrawn'
	| 'aACompromise';

/**
 * Describes distribution point name.
 */
export interface DistributionPointName {
	/**
	 * Carries the full name value.
	 */
	readonly fullName?: readonly GeneralName[];
	/**
	 * Carries the relative name value.
	 */
	readonly relativeName?: RelativeDistinguishedNameInput;
}

/**
 * Defines distribution point.
 */
export type DistributionPoint =
	| {
			/**
			 * Carries the distribution point value.
			 */
			readonly distributionPoint: DistributionPointName;
			/**
			 * Carries the reasons value.
			 */
			readonly reasons?: readonly DistributionPointReason[];
			/**
			 * Carries the crl issuer value.
			 */
			readonly crlIssuer?: readonly GeneralName[];
	  }
	| {
			/**
			 * Carries the distribution point value.
			 */
			readonly distributionPoint?: DistributionPointName;
			/**
			 * Carries the reasons value.
			 */
			readonly reasons?: readonly DistributionPointReason[];
			/**
			 * Carries the crl issuer value.
			 */
			readonly crlIssuer: readonly GeneralName[];
	  };

/**
 * Describes issuing distribution point base.
 */
interface IssuingDistributionPointBase {
	/**
	 * Carries the distribution point value.
	 */
	readonly distributionPoint?: DistributionPointName;
	/**
	 * Carries the only some reasons value.
	 */
	readonly onlySomeReasons?: readonly DistributionPointReason[];
	/**
	 * Indicates whether indirect crl.
	 */
	readonly indirectCrl?: boolean;
	/**
	 * Indicates whether only contains user certs.
	 */
	readonly onlyContainsUserCerts?: false;
	/**
	 * Indicates whether only contains ca certs.
	 */
	readonly onlyContainsCACerts?: false;
	/**
	 * Indicates whether only contains attribut e certs.
	 */
	readonly onlyContainsAttributeCerts?: boolean;
}

/**
 * Describes issuing distribution point for user certs.
 */
interface IssuingDistributionPointForUserCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsUserCerts'> {
	/**
	 * Indicates whether only contains user certs.
	 */
	readonly onlyContainsUserCerts: true;
	/**
	 * Indicates whether only contains ca certs.
	 */
	readonly onlyContainsCACerts?: false;
	/**
	 * Indicates whether only contains attribut e certs.
	 */
	readonly onlyContainsAttributeCerts?: false;
}

/**
 * Describes issuing distribution point for CA certs.
 */
interface IssuingDistributionPointForCaCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsCACerts'> {
	/**
	 * Indicates whether only contains user certs.
	 */
	readonly onlyContainsUserCerts?: false;
	/**
	 * Indicates whether only contains ca certs.
	 */
	readonly onlyContainsCACerts: true;
	/**
	 * Indicates whether only contains attribut e certs.
	 */
	readonly onlyContainsAttributeCerts?: false;
}

/**
 * Describes issuing distribution point for attribute certs.
 */
interface IssuingDistributionPointForAttributeCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsAttributeCerts'> {
	/**
	 * Indicates whether only contains user certs.
	 */
	readonly onlyContainsUserCerts?: false;
	/**
	 * Indicates whether only contains ca certs.
	 */
	readonly onlyContainsCACerts?: false;
	/**
	 * Indicates whether only contains attribut e certs.
	 */
	readonly onlyContainsAttributeCerts: true;
}

/**
 * Defines issuing distribution point.
 */
export type IssuingDistributionPoint =
	| IssuingDistributionPointBase
	| IssuingDistributionPointForUserCerts
	| IssuingDistributionPointForCaCerts
	| IssuingDistributionPointForAttributeCerts;

/**
 * Describes basic constraints.
 */
export interface BasicConstraints {
	/**
	 * Indicates whether ca.
	 */
	readonly ca: boolean;
	/**
	 * Carries the path length value.
	 */
	readonly pathLength?: number;
}

/**
 * Defines certificate policies.
 */
export type CertificatePolicies = readonly PolicyInformation[];

/**
 * Describes policy information.
 */
export interface PolicyInformation {
	/**
	 * Carries the policy identifier value.
	 */
	readonly policyIdentifier: string;
	/**
	 * Carries the policy qualifiers value.
	 */
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

/**
 * Describes cps policy qualifier info.
 */
export interface CpsPolicyQualifierInfo {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'cps';
	/**
	 * Carries the uri value.
	 */
	readonly uri: string;
}

/**
 * Describes policy notice reference.
 */
export interface PolicyNoticeReference {
	/**
	 * Carries the organization value.
	 */
	readonly organization: string;
	/**
	 * Carries the notice numbers value.
	 */
	readonly noticeNumbers: readonly number[];
}

/**
 * Describes user notice policy qualifier info.
 */
export interface UserNoticePolicyQualifierInfo {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'userNotice';
	/**
	 * Carries the notice ref value.
	 */
	readonly noticeRef?: PolicyNoticeReference;
	/**
	 * Carries the explicit text value.
	 */
	readonly explicitText?: string;
}

/**
 * Describes custom policy qualifier info.
 */
export interface CustomPolicyQualifierInfo {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'oid';
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the DER-encoded qualifier.
	 */
	readonly qualifierDer: Uint8Array;
}

/**
 * Defines policy qualifier info.
 */
export type PolicyQualifierInfo =
	| CpsPolicyQualifierInfo
	| UserNoticePolicyQualifierInfo
	| CustomPolicyQualifierInfo;

/**
 * Defines policy mappings.
 */
export type PolicyMappings = readonly PolicyMapping[];

/**
 * Describes policy mapping.
 */
export interface PolicyMapping {
	/**
	 * Carries the issuer domain policy value.
	 */
	readonly issuerDomainPolicy: string;
	/**
	 * Carries the subject domain policy value.
	 */
	readonly subjectDomainPolicy: string;
}

/**
 * Describes policy constraints.
 */
export interface PolicyConstraints {
	/**
	 * Carries the require explicit policy value.
	 */
	readonly requireExplicitPolicy?: number;
	/**
	 * Carries the inhibit policy mapping value.
	 */
	readonly inhibitPolicyMapping?: number;
}

/**
 * Describes inhibit any policy.
 */
export interface InhibitAnyPolicy {
	/**
	 * Carries the skip certs value.
	 */
	readonly skipCerts: number;
}

/**
 * Describes the input shape for certificate extensions operations.
 */
export interface CertificateExtensionsInput {
	/**
	 * Carries the subject alt names value.
	 */
	readonly subjectAltNames?: readonly SubjectAltName[];
	/**
	 * Carries the key usage value.
	 */
	readonly keyUsage?: readonly KeyUsage[];
	/**
	 * Carries the basic constraints value.
	 */
	readonly basicConstraints?: BasicConstraints;
	/**
	 * Carries the extended key usage value.
	 */
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	/**
	 * Carries the nam e constraints value.
	 */
	readonly nameConstraints?: NameConstraints;
	/**
	 * Carries the certificate policies value.
	 */
	readonly certificatePolicies?: CertificatePolicies;
	/**
	 * Carries the policy mappings value.
	 */
	readonly policyMappings?: PolicyMappings;
	/**
	 * Carries the policy constraints value.
	 */
	readonly policyConstraints?: PolicyConstraints;
	/**
	 * Carries the inhibit any policy value.
	 */
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
	/**
	 * Carries the authority info access value.
	 */
	readonly authorityInfoAccess?: readonly AuthorityInformationAccess[];
	/**
	 * Carries the crl distribution points value.
	 */
	readonly crlDistributionPoints?: readonly DistributionPoint[];
	/**
	 * Carries the custom extensions value.
	 */
	readonly customExtensions?: readonly CustomExtension[];
}

/**
 * Describes custom extension.
 */
export interface CustomExtension {
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: Uint8Array;
	/**
	 * Indicates whether critical.
	 */
	readonly critical?: boolean;
}

// ---------------------------------------------------------------------------
// Name constraints (RFC 5280 §4.2.1.10)
// ---------------------------------------------------------------------------

/**
 * A name form used as a constraint base in namEConstraints.
 * Distinct from {@link SubjectAltName} because IP constraints carry
 * address + mask bytes (8 for IPv4, 32 for IPv6) rather than bare addresses.
 */
export type NameConstraintForm =
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'dns';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'email';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'uri';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'ip';
			/**
			 * Carries the address bytes value.
			 */
			readonly addressBytes: Uint8Array;
			/**
			 * Carries the mask bytes value.
			 */
			readonly maskBytes: Uint8Array;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'directoryName';
			/**
			 * Carries the hexadecimal der.
			 */
			readonly derHex: string;
	  };

/**
 * Defines unsupported name constraint form.
 */
export type UnsupportedNameConstraintForm =
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'otherName';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: Uint8Array;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'x400Address';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: Uint8Array;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'ediPartyName';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: Uint8Array;
	  }
	| {
			/**
			 * Identifies the type value.
			 */
			readonly type: 'registeredID';
			/**
			 * Carries the successful value payload.
			 */
			readonly value: string;
	  };

/**
 * Describes the structured name constraint form produced by parsing helpers.
 */
export type ParsedNameConstraintForm = NameConstraintForm | UnsupportedNameConstraintForm;

/**
 * Describes general subtree.
 */
export interface GeneralSubtree<TForm extends ParsedNameConstraintForm = NameConstraintForm> {
	/**
	 * Carries the base value.
	 */
	readonly base: TForm;
}

/**
 * Describes name constraints.
 */
export interface NameConstraints<TForm extends ParsedNameConstraintForm = NameConstraintForm> {
	/**
	 * Carries the permitted subtrees value.
	 */
	readonly permittedSubtrees?: readonly GeneralSubtree<TForm>[];
	/**
	 * Carries the excluded subtrees value.
	 */
	readonly excludedSubtrees?: readonly GeneralSubtree<TForm>[];
}

/**
 * Defines known authority info access method.
 */
export type KnownAuthorityInfoAccessMethod = 'ocsp' | 'caIssuers';

/**
 * Describes custom authority info access method.
 */
export interface CustomAuthorityInfoAccessMethod {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'oid';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Defines authority info access method.
 */
export type AuthorityInfoAccessMethod =
	| KnownAuthorityInfoAccessMethod
	| CustomAuthorityInfoAccessMethod;

/**
 * Describes authority information access.
 */
export interface AuthorityInformationAccess {
	/**
	 * Carries the method value.
	 */
	readonly method: AuthorityInfoAccessMethod;
	/**
	 * Carries the uri value.
	 */
	readonly uri: string;
}

/**
 * Defines known extended key usage.
 */
export type KnownExtendedKeyUsage =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

/**
 * Describes custom extended key usage.
 */
export interface CustomExtendedKeyUsage {
	/**
	 * Identifies the type value.
	 */
	readonly type: 'oid';
	/**
	 * Carries the successful value payload.
	 */
	readonly value: string;
}

/**
 * Defines extended key usage.
 */
export type ExtendedKeyUsage = KnownExtendedKeyUsage | CustomExtendedKeyUsage;

/**
 * Defines the extended key usage oids used by this module.
 */
const EXTENDED_KEY_USAGE_OIDS: Record<KnownExtendedKeyUsage, string> = {
	/**
	 * Carries the server auth value.
	 */
	serverAuth: OIDS.serverAuth,
	/**
	 * Carries the client auth value.
	 */
	clientAuth: OIDS.clientAuth,
	/**
	 * Carries the code signing value.
	 */
	codeSigning: OIDS.codeSigning,
	/**
	 * Carries the email protection value.
	 */
	emailProtection: OIDS.emailProtection,
	/**
	 * Carries the time stamping value.
	 */
	timeStamping: OIDS.timeStamping,
	/**
	 * Carries the ocsp signing value.
	 */
	ocspSigning: OIDS.ocspSigning,
};

/**
 * Defines the authority info access method oids used by this module.
 */
const AUTHORITY_INFO_ACCESS_METHOD_OIDS: Record<KnownAuthorityInfoAccessMethod, string> = {
	/**
	 * Carries the ocsp value.
	 */
	ocsp: OIDS.ocspAccessMethod,
	/**
	 * Carries the ca issuers value.
	 */
	caIssuers: OIDS.caIssuersAccessMethod,
};

/**
 * Builds certificate extensions.
 *
 * @param subjectPublicKeyInfo The subject public key info value.
 * @param issuerPublicKeyInfo The issuer public key info value.
 * @param input The typed input payload.
 * @returns The built certificate extensions.
 */
export function buildCertificateExtensions(
	subjectPublicKeyInfo: Uint8Array,
	issuerPublicKeyInfo: Uint8Array | undefined,
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	const seen = new Set<string>();
	const basicConstraints = input?.basicConstraints ?? { ca: false };
	pushKnownExtension(extensions, seen, BASIC_CONSTRAINTS_EXTENSION_DEFINITION, basicConstraints);
	pushKnownExtension(
		extensions,
		seen,
		SUBJECT_KEY_IDENTIFIER_EXTENSION_DEFINITION,
		buildSubjectKeyIdentifier(subjectPublicKeyInfo),
	);
	if (issuerPublicKeyInfo !== undefined) {
		pushKnownExtension(
			extensions,
			seen,
			AUTHORITY_KEY_IDENTIFIER_EXTENSION_DEFINITION,
			buildSubjectKeyIdentifier(issuerPublicKeyInfo),
		);
	}
	appendConfiguredExtensions(extensions, seen, input, 'certificate', {
		includeBasicConstraints: false,
	});
	return extensions;
}

/**
 * Builds requested extensions.
 *
 * @param input The typed input payload.
 * @returns The built requested extensions.
 */
export function buildRequestedExtensions(
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	const seen = new Set<string>();
	appendConfiguredExtensions(extensions, seen, input, 'csr', { includeBasicConstraints: true });
	return extensions;
}

/**
 * Append configured extensions.
 *
 * @param encoded The encoded value.
 * @param seen The seen value.
 * @param input The typed input payload.
 * @param context The registry context value.
 * @param options The options that control the operation.
 */
function appendConfiguredExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput | undefined,
	context: ExtensionRegistryContext,
	options: {
		/**
		 * Indicates whether include basic constraints.
		 */
		readonly includeBasicConstraints: boolean;
	},
): void {
	if (input === undefined) {
		return;
	}
	if (options.includeBasicConstraints && input.basicConstraints !== undefined) {
		pushKnownExtension(
			encoded,
			seen,
			BASIC_CONSTRAINTS_EXTENSION_DEFINITION,
			input.basicConstraints,
		);
	}
	if (input.keyUsage !== undefined && input.keyUsage.length > 0) {
		pushKnownExtension(encoded, seen, KEY_USAGE_EXTENSION_DEFINITION, input.keyUsage);
	}
	if (input.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		pushKnownExtension(encoded, seen, SUBJECT_ALT_NAME_EXTENSION_DEFINITION, input.subjectAltNames);
	}
	if (input.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		pushKnownExtension(
			encoded,
			seen,
			EXTENDED_KEY_USAGE_EXTENSION_DEFINITION,
			input.extendedKeyUsage,
		);
	}
	if (input.nameConstraints !== undefined) {
		pushKnownExtension(encoded, seen, NAME_CONSTRAINTS_EXTENSION_DEFINITION, input.nameConstraints);
	}
	if (input.certificatePolicies !== undefined && input.certificatePolicies.length > 0) {
		pushKnownExtension(
			encoded,
			seen,
			CERTIFICATE_POLICIES_EXTENSION_DEFINITION,
			input.certificatePolicies,
		);
	}
	if (input.policyMappings !== undefined && input.policyMappings.length > 0) {
		pushKnownExtension(encoded, seen, POLICY_MAPPINGS_EXTENSION_DEFINITION, input.policyMappings);
	}
	if (input.policyConstraints !== undefined) {
		pushKnownExtension(
			encoded,
			seen,
			POLICY_CONSTRAINTS_EXTENSION_DEFINITION,
			input.policyConstraints,
		);
	}
	if (input.inhibitAnyPolicy !== undefined) {
		pushKnownExtension(
			encoded,
			seen,
			INHIBIT_ANY_POLICY_EXTENSION_DEFINITION,
			input.inhibitAnyPolicy,
		);
	}
	if (input.authorityInfoAccess !== undefined && input.authorityInfoAccess.length > 0) {
		pushKnownExtension(
			encoded,
			seen,
			AUTHORITY_INFO_ACCESS_EXTENSION_DEFINITION,
			input.authorityInfoAccess,
		);
	}
	if (input.crlDistributionPoints !== undefined && input.crlDistributionPoints.length > 0) {
		pushKnownExtension(
			encoded,
			seen,
			CRL_DISTRIBUTION_POINTS_EXTENSION_DEFINITION,
			input.crlDistributionPoints,
		);
	}
	if (input.customExtensions !== undefined) {
		for (const extension of input.customExtensions) {
			const knownDefinition = getExtensionDefinition(extension.oid);
			if (knownDefinition !== undefined && !knownDefinition.contexts.includes(context)) {
				throw new Error(`Extension ${extension.oid} is not supported in ${context} context`);
			}
			pushExtension(
				encoded,
				seen,
				extension.oid,
				new Uint8Array(extension.value),
				extension.critical ?? false,
			);
		}
	}
}

/**
 * Push known extension.
 *
 * @param encoded The encoded value.
 * @param seen The seen value.
 * @param definition The definition value.
 * @param value The value to process.
 * @param critical The critical value.
 */
function pushKnownExtension<TParsed, TInput>(
	encoded: Uint8Array[],
	seen: Set<string>,
	definition: ExtensionDefinition<TParsed, TInput>,
	value: TInput,
	critical = definition.defaultCritical,
): void {
	pushExtension(encoded, seen, definition.oid, definition.encode(value), critical);
}

/**
 * Encodes extension.
 *
 * @param oid The object identifier.
 * @param extnValue The extn value value.
 * @param critical The critical value.
 * @returns The encoded extension.
 */
export function encodeExtension(oid: string, extnValue: Uint8Array, critical = false): Uint8Array {
	const fields = [objectIdentifier(oid)];
	if (critical) {
		fields.push(bool(true));
	}
	fields.push(octetString(extnValue));
	return sequence(fields);
}

/**
 * Encodes basic constraints.
 *
 * @param input The typed input payload.
 * @returns The encoded basic constraints.
 */
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

/**
 * Encodes key usage.
 *
 * @param usages The usages value.
 * @returns The encoded key usage.
 */
export function encodeKeyUsage(usages: readonly KeyUsage[]): Uint8Array {
	return encodeKeyUsageExtension(usages);
}

/**
 * Encodes subject alt name.
 *
 * @param value The value to process.
 * @returns The encoded subject alt name.
 */
export function encodeSubjectAltName(value: SubjectAltName): Uint8Array {
	switch (value.type) {
		case 'dns':
			return implicitPrimitiveContext(2, new TextEncoder().encode(value.value));
		case 'email':
			return implicitPrimitiveContext(1, new TextEncoder().encode(value.value));
		case 'uri':
			return implicitPrimitiveContext(6, new TextEncoder().encode(value.value));
		case 'srv':
			return implicitConstructedContext(
				0,
				sequence([objectIdentifier(OIDS.idOnDnsSrv), explicitContext(0, ia5String(value.value))]),
			);
		case 'ip':
			return implicitPrimitiveContext(7, encodeIpAddress(value.value));
		case 'directoryName':
			return implicitConstructedContext(4, extractDirectoryNameContent(value.derHex));
		case 'unknown':
			return tlv(value.tag, value.value);
		default: {
			const _exhaustive: never = value;
			throw new Error(`Unhandled SubjectAltName type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * Encodes extended key usage.
 *
 * @param usages The usages value.
 * @returns The encoded extended key usage.
 */
export function encodeExtendedKeyUsage(usages: readonly ExtendedKeyUsage[]): Uint8Array {
	return sequence(usages.map((usage) => objectIdentifier(getExtendedKeyUsageOid(usage))));
}

/**
 * Encodes authority info access.
 *
 * @param entries The entries value.
 * @returns The encoded authority info access.
 */
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

/**
 * Encodes CRL distribution points.
 *
 * @param points The points value.
 * @returns The encoded CRL distribution points.
 */
export function encodeCrlDistributionPoints(points: readonly DistributionPoint[]): Uint8Array {
	return sequence(points.map((point) => sequence(encodeDistributionPoint(point))));
}

/**
 * Encodes name constraints.
 *
 * @param constraints The constraints value.
 * @returns The encoded name constraints.
 */
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

/**
 * Encodes certificate policies.
 *
 * @param policies The policies value.
 * @returns The encoded certificate policies.
 */
export function encodeCertificatePolicies(policies: CertificatePolicies): Uint8Array {
	if (policies.length === 0) {
		throw new Error('certificatePolicies must not be empty');
	}
	return sequence(policies.map(encodePolicyInformation));
}

/**
 * Encodes policy mappings.
 *
 * @param mappings The mappings value.
 * @returns The encoded policy mappings.
 */
export function encodePolicyMappings(mappings: PolicyMappings): Uint8Array {
	if (mappings.length === 0) {
		throw new Error('policyMappings must not be empty');
	}
	return sequence(
		mappings.map((mapping) => {
			validatePolicyOid(mapping.issuerDomainPolicy);
			validatePolicyOid(mapping.subjectDomainPolicy);
			if (
				mapping.issuerDomainPolicy === OIDS.anyPolicy ||
				mapping.subjectDomainPolicy === OIDS.anyPolicy
			) {
				throw new Error('policyMappings must not use anyPolicy');
			}
			return sequence([
				objectIdentifier(mapping.issuerDomainPolicy),
				objectIdentifier(mapping.subjectDomainPolicy),
			]);
		}),
	);
}

/**
 * Encodes policy constraints.
 *
 * @param constraints The constraints value.
 * @returns The encoded policy constraints.
 */
export function encodePolicyConstraints(constraints: PolicyConstraints): Uint8Array {
	const fields: Uint8Array[] = [];
	if (constraints.requireExplicitPolicy !== undefined) {
		fields.push(
			implicitPrimitiveContext(0, encodeIntegerContent(constraints.requireExplicitPolicy)),
		);
	}
	if (constraints.inhibitPolicyMapping !== undefined) {
		fields.push(
			implicitPrimitiveContext(1, encodeIntegerContent(constraints.inhibitPolicyMapping)),
		);
	}
	if (fields.length === 0) {
		throw new Error('policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping');
	}
	return sequence(fields);
}

/**
 * Encodes inhibit any policy.
 *
 * @param input The typed input payload.
 * @returns The encoded inhibit any policy.
 */
export function encodeInhibitAnyPolicy(input: InhibitAnyPolicy): Uint8Array {
	return integerFromNumber(input.skipCerts);
}

/**
 * Encodes policy information.
 *
 * @param policy The policy value.
 * @returns The encoded policy information.
 */
function encodePolicyInformation(policy: PolicyInformation): Uint8Array {
	validatePolicyOid(policy.policyIdentifier);
	const fields = [objectIdentifier(policy.policyIdentifier)];
	if (policy.policyQualifiers !== undefined && policy.policyQualifiers.length > 0) {
		fields.push(sequence(policy.policyQualifiers.map(encodePolicyQualifierInfo)));
	}
	return sequence(fields);
}

/**
 * Encodes policy qualifier info.
 *
 * @param qualifier The qualifier value.
 * @returns The encoded policy qualifier info.
 */
function encodePolicyQualifierInfo(qualifier: PolicyQualifierInfo): Uint8Array {
	switch (qualifier.type) {
		case 'cps':
			return sequence([objectIdentifier(OIDS.cpsPolicyQualifier), ia5String(qualifier.uri)]);
		case 'userNotice':
			return sequence([
				objectIdentifier(OIDS.userNoticePolicyQualifier),
				encodeUserNoticePolicyQualifierInfo(qualifier),
			]);
		case 'oid':
			validateOid(qualifier.oid);
			return sequence([objectIdentifier(qualifier.oid), new Uint8Array(qualifier.qualifierDer)]);
		default: {
			const _exhaustive: never = qualifier;
			throw new Error(`Unhandled PolicyQualifierInfo type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * Encodes user notice policy qualifier info.
 *
 * @param qualifier The qualifier value.
 * @returns The encoded user notice policy qualifier info.
 */
function encodeUserNoticePolicyQualifierInfo(qualifier: UserNoticePolicyQualifierInfo): Uint8Array {
	const fields: Uint8Array[] = [];
	if (qualifier.noticeRef !== undefined) {
		fields.push(encodePolicyNoticeReference(qualifier.noticeRef));
	}
	if (qualifier.explicitText !== undefined) {
		fields.push(utf8String(qualifier.explicitText));
	}
	return sequence(fields);
}

/**
 * Encodes policy notice reference.
 *
 * @param reference The reference value.
 * @returns The encoded policy notice reference.
 */
function encodePolicyNoticeReference(reference: PolicyNoticeReference): Uint8Array {
	return sequence([
		utf8String(reference.organization),
		sequence(reference.noticeNumbers.map((noticeNumber) => integerFromNumber(noticeNumber))),
	]);
}

/**
 * Encodes integer content.
 *
 * @param value The value to process.
 * @returns The encoded integer content.
 */
function encodeIntegerContent(value: number): Uint8Array {
	return readElement(integerFromNumber(value)).value;
}

/**
 * Encodes general subtree.
 *
 * @param subtree The subtree value.
 * @returns The encoded general subtree.
 */
function encodeGeneralSubtree(subtree: GeneralSubtree): Uint8Array {
	return sequence([encodeNameConstraintForm(subtree.base)]);
}

/**
 * Encodes distribution point.
 *
 * @param point The point value.
 * @returns The encoded distribution point.
 */
function encodeDistributionPoint(point: DistributionPoint): Uint8Array[] {
	if (point.crlIssuer !== undefined && point.crlIssuer.length === 0) {
		throw new Error('DistributionPoint crlIssuer must not be empty');
	}
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
		fields.push(
			implicitPrimitiveContext(1, encodeDistributionPointReasonFlagsContent(point.reasons)),
		);
	}
	if (point.crlIssuer !== undefined && point.crlIssuer.length > 0) {
		fields.push(
			implicitConstructedContext(2, concatBytes(point.crlIssuer.map(encodeSubjectAltName))),
		);
	}
	return fields;
}

/**
 * Encodes distribution point name.
 *
 * @param name The name value.
 * @returns The encoded distribution point name.
 */
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

/**
 * Encodes name constraint form.
 *
 * @param form The form value.
 * @returns The encoded name constraint form.
 */
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
			return implicitConstructedContext(4, extractDirectoryNameContent(form.derHex));
		default: {
			const _exhaustive: never = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * Extract directory name content.
 *
 * @param derHex The DER hex value.
 * @returns The computed value.
 */
function extractDirectoryNameContent(derHex: string): Uint8Array {
	const element = readRootElement(hexToBytes(derHex), { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (element.tag !== 0x30) {
		throw new Error('directoryName derHex must encode a DER SEQUENCE');
	}
	return new Uint8Array(element.value);
}

/**
 * Returns extended key usage OID.
 *
 * @param usage The usage value.
 * @returns The extended key usage OID.
 */
export function getExtendedKeyUsageOid(usage: ExtendedKeyUsage): string {
	if (typeof usage === 'string') {
		return EXTENDED_KEY_USAGE_OIDS[usage];
	}
	validateOid(usage.value);
	return usage.value;
}

/**
 * Parses extended key usage OID.
 *
 * @param oid The object identifier.
 * @returns The parsed extended key usage OID.
 */
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

/**
 * Returns authority info access method OID.
 *
 * @param method The method value.
 * @returns The authority info access method OID.
 */
export function getAuthorityInfoAccessMethodOid(method: AuthorityInfoAccessMethod): string {
	if (typeof method === 'string') {
		return AUTHORITY_INFO_ACCESS_METHOD_OIDS[method];
	}
	validateOid(method.value);
	return method.value;
}

/**
 * Parses authority info access method OID.
 *
 * @param oid The object identifier.
 * @returns The parsed authority info access method OID.
 */
export function parseAuthorityInfoAccessMethodOid(oid: string): AuthorityInfoAccessMethod {
	switch (oid) {
		case OIDS.ocspAccessMethod:
			return 'ocsp';
		case OIDS.caIssuersAccessMethod:
			return 'caIssuers';
	}
	return { type: 'oid', value: oid };
}

/**
 * Encodes IP address.
 *
 * @param input The typed input payload.
 * @returns The encoded IP address.
 */
function encodeIpAddress(input: string): Uint8Array {
	return parseIpAddressToBytes(input);
}

/** @internal Exported for the extension registry. */
export function buildSubjectKeyIdentifier(subjectPublicKeyInfo: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(subjectPublicKeyInfo);
	const subjectPublicKey = topLevel[1];
	if (subjectPublicKey === undefined || subjectPublicKey.tag !== 0x03) {
		throw new Error('SPKI missing subject public key bit string');
	}
	const publicKeyBytes = subjectPublicKey.value.slice(1);
	return sha1(publicKeyBytes);
}

/**
 * Validates OID.
 *
 * @param oid The object identifier.
 */
function validateOid(oid: string): void {
	if (!/^\d+(?:\.\d+)+$/.test(oid)) {
		throw new Error(`Invalid OID: ${oid}`);
	}
}

/**
 * Validates policy OID.
 *
 * @param oid The object identifier.
 */
function validatePolicyOid(oid: string): void {
	validateOid(oid);
}

/**
 * Push extension.
 *
 * @param encoded The encoded value.
 * @param seen The seen value.
 * @param oid The object identifier.
 * @param value The value to process.
 * @param critical The critical value.
 */
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
