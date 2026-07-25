/**
 * Typed certificate and CSR extension model plus ASN.1 encoder helpers.
 *
 * Defines input types for every supported X.509v3 extension (RFC 5280) and
 * the DER encoders consumed by certificate and CSR builder flows.
 *
 * @module
 */

import { canonicalizeOid, hexToBytes, toHex } from '#micro509/internal/asn1/asn1';
import {
	bool,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	ia5Bytes,
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
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { sha1 } from '#micro509/internal/crypto/hash';
import { parseIpAddressToBytes } from '#micro509/internal/shared/ip';
import {
	encodeDistributionPointReasonFlagsContent,
	encodeKeyUsageExtension,
} from '#micro509/internal/x509/extension-bits';
import { throwExtensionEncoderError } from '#micro509/internal/x509/extension-errors';
import type {
	ExtensionDefinition,
	ExtensionRegistryContext,
} from '#micro509/internal/x509/extension-registry';
import {
	AUTHORITY_INFO_ACCESS_EXTENSION_DEFINITION,
	AUTHORITY_KEY_IDENTIFIER_EXTENSION_DEFINITION,
	BASIC_CONSTRAINTS_EXTENSION_DEFINITION,
	CERTIFICATE_POLICIES_EXTENSION_DEFINITION,
	CRL_DISTRIBUTION_POINTS_EXTENSION_DEFINITION,
	EXTENDED_KEY_USAGE_EXTENSION_DEFINITION,
	getExtensionDefinition,
	INHIBIT_ANY_POLICY_EXTENSION_DEFINITION,
	KEY_USAGE_EXTENSION_DEFINITION,
	NAME_CONSTRAINTS_EXTENSION_DEFINITION,
	POLICY_CONSTRAINTS_EXTENSION_DEFINITION,
	POLICY_MAPPINGS_EXTENSION_DEFINITION,
	SUBJECT_ALT_NAME_EXTENSION_DEFINITION,
	SUBJECT_KEY_IDENTIFIER_EXTENSION_DEFINITION,
} from '#micro509/internal/x509/extension-registry';
import { GENERAL_NAME_WIRE_TAGS } from '#micro509/internal/x509/general-name-tags';
import { isResultError } from '#micro509/result/result';
import type { RelativeDistinguishedNameInput } from '#micro509/x509/name';
import { encodeRelativeDistinguishedName } from '#micro509/x509/name';

export type { ExtensionEncoderErrorCode } from '#micro509/internal/x509/extension-errors';
export type {
	NameAttribute,
	NameFieldKey,
	RelativeDistinguishedNameInput,
} from '#micro509/x509/name';

/**
 * A decoded BIT STRING flag set.
 *
 * `flags` contains the recognized flag values with any non-zero padding bits
 * masked out. `nonZeroPadding` is `true` when the original BIT STRING encoding
 * had non-zero bits in positions that DER ({@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §11.2.1}) requires to be zero.
 * Extension flag decoding rejects such encodings, so parsed extension values
 * always report `false`.
 */
export interface ParsedBitFlags<T extends string> {
	/** Decoded flag values, padding bits masked. */
	readonly flags: readonly T[];
	/** `true` when the original encoding had non-zero padding bits (DER violation). */
	readonly nonZeroPadding: boolean;
}

/**
 * RFC 5280 §4.2.1.3 Key Usage bit flag.
 *
 * Each value corresponds to one bit in the KeyUsage BIT STRING.
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 RFC 5280 §4.2.1.3}
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
 * RFC 5280 §4.2.1.6 Subject Alternative Name / GeneralName.
 *
 * Discriminated union keyed on `type`.
 *
 * The `'unknown'` variant preserves unrecognized {@linkcode GeneralName} tags for round-trip fidelity.
 */
export type SubjectAltName =
	| {
			/** DNS hostname (dNSName [2]). */
			readonly type: 'dns';
			/** Fully-qualified domain name, e.g. `"example.com"`. */
			readonly value: string;
	  }
	| {
			/** IP address (iPAddress [7]). */
			readonly type: 'ip';
			/** Dotted-decimal IPv4 or colon-hex IPv6 string. */
			readonly value: string;
	  }
	| {
			/** Email address (rfc822Name [1]). */
			readonly type: 'email';
			/** RFC 2821 §4.1.2 Mailbox (`Local-part@Domain`), e.g. `"admin@example.com"`. */
			readonly value: string;
	  }
	| {
			/** URI (uniformResourceIdentifier [6]). */
			readonly type: 'uri';
			/** Absolute URI string. */
			readonly value: string;
	  }
	| {
			/** SRV-ID otherName (id-on-dnsSRV). */
			readonly type: 'srv';
			/** SRV service name, e.g. `"_imaps.example.com"`. */
			readonly value: string;
	  }
	| {
			/** X.500 directory name (directoryName [4]). */
			readonly type: 'directoryName';
			/** Hex-encoded DER of the Name SEQUENCE. */
			readonly derHex: string;
	  }
	| {
			/** Unrecognized {@linkcode GeneralName} tag, preserved as raw bytes. */
			readonly type: 'unknown';
			/** ASN.1 context tag number. */
			readonly tag: number;
			/** Raw content bytes of the element. */
			readonly value: Uint8Array;
	  };

/** Alias for {@linkcode SubjectAltName} — used where RFC 5280 says "GeneralName". */
export type GeneralName = SubjectAltName;

/**
 * Revocation reason flags for CRL Distribution Points and Issuing Distribution Points
 * (RFC 5280 §4.2.1.13, §5.2.5).
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
 * Name component of a CRL Distribution Point (RFC 5280 §4.2.1.13).
 *
 * Supply exactly one of `fullName` or `relativeName`.
 */
export interface DistributionPointName {
	/** Absolute {@linkcode GeneralName}(s) identifying the distribution point (usually a URI). */
	readonly fullName?: readonly GeneralName[];
	/** Name relative to the issuer's DN; mutually exclusive with `fullName`. */
	readonly relativeName?: RelativeDistinguishedNameInput;
}

/**
 * Input for a single CRL Distribution Point (RFC 5280 §4.2.1.13).
 *
 * At least one of `distributionPoint` or `crlIssuer` must be provided.
 * The union enforces this constraint at the type level.
 */
export type DistributionPoint =
	| {
			/** Where to fetch the CRL (fullName or relativeName). */
			readonly distributionPoint: DistributionPointName;
			/** Revocation reason subset. Absent means all reasons. */
			readonly reasons?: readonly DistributionPointReason[];
			/** Entity that signed the CRL, when different from the cert issuer. */
			readonly crlIssuer?: readonly GeneralName[];
	  }
	| {
			/** Where to fetch the CRL. Optional when `crlIssuer` is present. */
			readonly distributionPoint?: DistributionPointName;
			/** Revocation reason subset. Absent means all reasons. */
			readonly reasons?: readonly DistributionPointReason[];
			/** Entity that signed the CRL. Required when `distributionPoint` is absent. */
			readonly crlIssuer: readonly GeneralName[];
	  };

/** Base shape for Issuing Distribution Point (RFC 5280 §5.2.5) — no scope restriction. */
export interface IssuingDistributionPointBase {
	/** Where to fetch this CRL. */
	readonly distributionPoint?: DistributionPointName;
	/** Limits the CRL to these revocation reasons. Absent means all reasons. */
	readonly onlySomeReasons?: readonly DistributionPointReason[];
	/** When true, the CRL may contain entries from other CAs. Default false. */
	readonly indirectCrl?: boolean;
	/** Must be absent or false in this variant (no user-cert-only restriction). */
	readonly onlyContainsUserCerts?: false;
	/** Must be absent or false in this variant (no CA-cert-only restriction). */
	readonly onlyContainsCACerts?: false;
	/** When true, the CRL only covers attribute certificates. Default false. */
	readonly onlyContainsAttributeCerts?: boolean;
}

/** IDP scoped to end-entity (user) certificates only. Mutually exclusive with CA / attribute scopes. */
export interface IssuingDistributionPointForUserCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsUserCerts'> {
	/** This variant only covers end-entity certificates. */
	readonly onlyContainsUserCerts: true;
	/** Must be absent or false when the CRL is not CA-only. */
	readonly onlyContainsCACerts?: false;
	/** Must be absent or false when the CRL is not attribute-cert-only. */
	readonly onlyContainsAttributeCerts?: false;
}

/** IDP scoped to CA certificates only. Mutually exclusive with user / attribute scopes. */
export interface IssuingDistributionPointForCaCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsCACerts'> {
	/** Must be absent or false when the CRL is not user-cert-only. */
	readonly onlyContainsUserCerts?: false;
	/** This variant only covers CA certificates. */
	readonly onlyContainsCACerts: true;
	/** Must be absent or false when the CRL is not attribute-cert-only. */
	readonly onlyContainsAttributeCerts?: false;
}

/** IDP scoped to attribute certificates only. Mutually exclusive with user / CA scopes. */
export interface IssuingDistributionPointForAttributeCerts
	extends Omit<IssuingDistributionPointBase, 'onlyContainsAttributeCerts'> {
	/** Must be absent or false when the CRL is not user-cert-only. */
	readonly onlyContainsUserCerts?: false;
	/** Must be absent or false when the CRL is not CA-only. */
	readonly onlyContainsCACerts?: false;
	/** This variant only covers attribute certificates. */
	readonly onlyContainsAttributeCerts: true;
}

/**
 * Input for the Issuing Distribution Point CRL extension (RFC 5280 §5.2.5).
 *
 * The union enforces that at most one of the `onlyContains*` flags is true.
 */
export type IssuingDistributionPoint =
	| IssuingDistributionPointBase
	| IssuingDistributionPointForUserCerts
	| IssuingDistributionPointForCaCerts
	| IssuingDistributionPointForAttributeCerts;

/**
 * RFC 5280 §4.2.1.9 Basic Constraints.
 *
 * A certificate with `ca: true` may issue other certificates; `pathLength`
 * limits how many additional CAs may appear below it in the chain.
 */
export type BasicConstraints =
	| {
			/** End-entity certificate: not a CA. */
			readonly ca: false;
			/** Never present on end-entity certificates. */
			readonly pathLength?: undefined;
	  }
	| {
			/** CA certificate: may issue other certificates. */
			readonly ca: true;
			/** Maximum number of intermediate CA certificates allowed below this CA. */
			readonly pathLength?: number;
	  };

/** A single certificate policy: an OID plus optional qualifiers. */
export interface PolicyInformation {
	/** Dotted-decimal OID of the policy (e.g. `"2.23.140.1.2.1"` for DV). */
	readonly policyIdentifier: string;
	/** Optional CPS URIs or user notices attached to this policy. */
	readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

/** RFC 5280 §4.2.1.4 — array of policy OIDs with optional qualifiers. */
export type CertificatePolicies = readonly {
	/** Dotted-decimal OID of the policy (e.g. `"2.23.140.1.2.1"` for DV). */
	readonly policyIdentifier: string;
	/** Optional CPS URIs or user notices attached to this policy. */
	readonly policyQualifiers?: readonly (
		| {
				readonly type: 'cps';
				readonly uri: string;
		  }
		| {
				readonly type: 'userNotice';
				readonly noticeRef?: {
					readonly organization: string;
					readonly noticeNumbers: readonly number[];
				};
				readonly explicitText?: string;
		  }
		| {
				readonly type: 'oid';
				readonly oid: string;
				readonly qualifierDer: Uint8Array;
		  }
	)[];
}[];

/** CPS (Certification Practice Statement) URI policy qualifier. */
export interface CpsPolicyQualifierInfo {
	/** Discriminant for the `'cps'` qualifier variant. */
	readonly type: 'cps';
	/** URL of the Certification Practice Statement document. */
	readonly uri: string;
}

/** Reference to a numbered notice within an organization's practice statement. */
export interface PolicyNoticeReference {
	/** Organization name that published the notice. */
	readonly organization: string;
	/** One-based notice numbers within that organization's documentation. */
	readonly noticeNumbers: readonly number[];
}

/** UserNotice policy qualifier — human-readable notice text and/or a notice reference. */
export interface UserNoticePolicyQualifierInfo {
	/** Discriminant for the `'userNotice'` qualifier variant. */
	readonly type: 'userNotice';
	/** Pointer to a numbered notice in an organization's practice statement. */
	readonly noticeRef?: PolicyNoticeReference;
	/** Free-form text to display to relying parties. */
	readonly explicitText?: string;
}

/** Opaque policy qualifier identified by a custom OID, carried as raw DER. */
export interface CustomPolicyQualifierInfo {
	/** Discriminant for the custom-OID qualifier variant. */
	readonly type: 'oid';
	/** Dotted-decimal OID of the qualifier. */
	readonly oid: string;
	/** DER-encoded qualifier payload. */
	readonly qualifierDer: Uint8Array;
}

/** Discriminated union of all supported policy qualifier types. */
export type PolicyQualifierInfo =
	| CpsPolicyQualifierInfo
	| UserNoticePolicyQualifierInfo
	| CustomPolicyQualifierInfo;

/** Maps a policy OID in the issuer's domain to an equivalent OID in the subject's domain. */
export interface PolicyMapping {
	/** Policy OID as defined by the issuing CA. Must not be anyPolicy. */
	readonly issuerDomainPolicy: string;
	/** Equivalent policy OID in the subject CA's domain. Must not be anyPolicy. */
	readonly subjectDomainPolicy: string;
}

/** RFC 5280 §4.2.1.5 — array of issuer-to-subject policy OID pairs. */
export type PolicyMappings = readonly {
	/** Policy OID as defined by the issuing CA. Must not be anyPolicy. */
	readonly issuerDomainPolicy: string;
	/** Equivalent policy OID in the subject CA's domain. Must not be anyPolicy. */
	readonly subjectDomainPolicy: string;
}[];

/**
 * RFC 5280 §4.2.1.11 Policy Constraints.
 *
 * At least one field must be present. Values are certificate-count
 * thresholds measured from the current certificate toward the end entity.
 */
export interface PolicyConstraints {
	/** After this many certificates, an acceptable policy must be in the path. */
	readonly requireExplicitPolicy?: number;
	/** After this many certificates, policy mapping is no longer allowed. */
	readonly inhibitPolicyMapping?: number;
}

/**
 * RFC 5280 §4.2.1.14 Inhibit anyPolicy.
 *
 * After `skipCerts` additional non-self-issued certificates in the path, the
 * special anyPolicy OID is no longer considered a match, except when it
 * appears in an intermediate self-issued CA certificate.
 */
export interface InhibitAnyPolicy {
	/** Number of additional non-self-issued certificates before anyPolicy stops being valid. */
	readonly skipCerts: number;
}

/**
 * Input for `createCertificate`, `createSelfSignedCertificate`,
 * and `createCertificateSigningRequest`.
 *
 * Every field is optional. Omitted extensions are not encoded. Built-in
 * extensions (SKI, AKI, basicConstraints defaults) are handled automatically
 * by the builder.
 */
export interface CertificateExtensionsInput {
	/** Subject Alternative Names (dns, ip, email, uri, srv, directoryName). */
	readonly subjectAltNames?: readonly SubjectAltName[];
	/** Key Usage flags (digitalSignature, keyCertSign, etc.). */
	readonly keyUsage?: readonly KeyUsage[];
	/** Basic Constraints (CA flag + optional pathLength). Defaults to `{ ca: false }` for certs. */
	readonly basicConstraints?: BasicConstraints;
	/** Extended Key Usage purposes (serverAuth, clientAuth, etc.). */
	readonly extendedKeyUsage?: readonly ExtendedKeyUsage[];
	/** Name Constraints — permitted and/or excluded subtrees. */
	readonly nameConstraints?: NameConstraints;
	/** Certificate Policies with optional qualifiers. */
	readonly certificatePolicies?: CertificatePolicies;
	/** Policy Mappings between issuer and subject policy domains. */
	readonly policyMappings?: PolicyMappings;
	/** Policy Constraints (requireExplicitPolicy / inhibitPolicyMapping thresholds). */
	readonly policyConstraints?: PolicyConstraints;
	/** Inhibit anyPolicy skip-certs threshold. */
	readonly inhibitAnyPolicy?: InhibitAnyPolicy;
	/** Authority Information Access — OCSP responder and CA issuer locations. */
	readonly authorityInfoAccess?: readonly AuthorityInformationAccessInput[];
	/** CRL Distribution Points — where to check revocation status. */
	readonly crlDistributionPoints?: readonly DistributionPoint[];
	/** Arbitrary extensions not covered by the built-in fields. */
	readonly customExtensions?: readonly CustomExtension[];
}

/** An extension not covered by the typed fields in {@linkcode CertificateExtensionsInput}. */
export interface CustomExtension {
	/** Dotted-decimal OID of the extension. */
	readonly oid: string;
	/** Pre-encoded DER content for the extnValue OCTET STRING. */
	readonly value: Uint8Array;
	/** Whether the extension is critical. Default `false`. */
	readonly critical?: boolean;
}

// Name constraints (RFC 5280 §4.2.1.10)

/**
 * A name form used as a constraint base in namEConstraints.
 * Distinct from {@linkcode SubjectAltName} because IP constraints carry
 * address + mask bytes (8 for IPv4, 32 for IPv6) rather than bare addresses.
 */
export type NameConstraintForm =
	| {
			/** DNS domain constraint (dNSName [2]). */
			readonly type: 'dns';
			/** Domain suffix, e.g. `".example.com"` or `"example.com"`. */
			readonly value: string;
	  }
	| {
			/** Email constraint (rfc822Name [1]). */
			readonly type: 'email';
			/** Email domain or full address pattern. */
			readonly value: string;
	  }
	| {
			/** URI constraint (uniformResourceIdentifier [6]). */
			readonly type: 'uri';
			/** Host or domain component of a URI. */
			readonly value: string;
	  }
	| {
			/** IP range constraint (iPAddress [7]). */
			readonly type: 'ip';
			/** Network address bytes (4 for IPv4, 16 for IPv6). */
			readonly addressBytes: Uint8Array;
			/** Subnet mask bytes (same length as addressBytes). */
			readonly maskBytes: Uint8Array;
	  }
	| {
			/** Directory name constraint (directoryName [4]). */
			readonly type: 'directoryName';
			/** Hex-encoded DER of the Name SEQUENCE. */
			readonly derHex: string;
	  };

/**
 * Name constraint forms parsed from DER but not supported for encoding or
 * validation. Preserved for diagnostic round-tripping.
 */
export type UnsupportedNameConstraintForm =
	| {
			/** otherName [0] — raw bytes. */
			readonly type: 'otherName';
			readonly value: Uint8Array;
	  }
	| {
			/** x400Address [3] — raw bytes. */
			readonly type: 'x400Address';
			readonly value: Uint8Array;
	  }
	| {
			/** ediPartyName [5] — raw bytes. */
			readonly type: 'ediPartyName';
			readonly value: Uint8Array;
	  }
	| {
			/** registeredID [8] — decoded OID string. */
			readonly type: 'registeredID';
			readonly value: string;
	  };

/** Union of supported and unsupported name constraint forms as produced by parsing. */
export type ParsedNameConstraintForm =
	| {
			readonly type: 'dns';
			readonly value: string;
	  }
	| {
			readonly type: 'email';
			readonly value: string;
	  }
	| {
			readonly type: 'uri';
			readonly value: string;
	  }
	| {
			readonly type: 'ip';
			readonly addressBytes: Uint8Array;
			readonly maskBytes: Uint8Array;
	  }
	| {
			readonly type: 'directoryName';
			readonly derHex: string;
	  }
	| {
			readonly type: 'otherName';
			readonly value: Uint8Array;
	  }
	| {
			readonly type: 'x400Address';
			readonly value: Uint8Array;
	  }
	| {
			readonly type: 'ediPartyName';
			readonly value: Uint8Array;
	  }
	| {
			readonly type: 'registeredID';
			readonly value: string;
	  };

/** A single subtree entry in a Name Constraints permitted/excluded list. */
export interface GeneralSubtree<
	TForm extends ParsedNameConstraintForm =
		| {
				readonly type: 'dns';
				readonly value: string;
		  }
		| {
				readonly type: 'email';
				readonly value: string;
		  }
		| {
				readonly type: 'uri';
				readonly value: string;
		  }
		| {
				readonly type: 'ip';
				readonly addressBytes: Uint8Array;
				readonly maskBytes: Uint8Array;
		  }
		| {
				readonly type: 'directoryName';
				readonly derHex: string;
		  },
> {
	/** The name form that defines this constraint boundary. */
	readonly base: TForm;
}

/**
 * RFC 5280 §4.2.1.10 Name Constraints.
 *
 * A CA certificate may restrict the namespace of all subject names in
 * subsequent certificates in the path.
 */
export interface NameConstraints<
	TForm extends ParsedNameConstraintForm =
		| {
				readonly type: 'dns';
				readonly value: string;
		  }
		| {
				readonly type: 'email';
				readonly value: string;
		  }
		| {
				readonly type: 'uri';
				readonly value: string;
		  }
		| {
				readonly type: 'ip';
				readonly addressBytes: Uint8Array;
				readonly maskBytes: Uint8Array;
		  }
		| {
				readonly type: 'directoryName';
				readonly derHex: string;
		  },
> {
	/** Names that MUST fall within these subtrees to be valid. */
	readonly permittedSubtrees?: readonly GeneralSubtree<TForm>[];
	/** Names that MUST NOT fall within these subtrees. Takes precedence over permitted. */
	readonly excludedSubtrees?: readonly GeneralSubtree<TForm>[];
}

/** Well-known AIA access methods: OCSP responder or CA issuer certificate. */
export type KnownAuthorityInfoAccessMethod = 'ocsp' | 'caIssuers';

/** AIA access method identified by a custom OID not in the well-known set. */
export interface CustomAuthorityInfoAccessMethod {
	/** Discriminant for the custom-OID access method variant. */
	readonly type: 'oid';
	/** Dotted-decimal OID of the access method. */
	readonly value: string;
}

/** AIA access method — either a well-known string or a custom OID. */
export type AuthorityInfoAccessMethod =
	| KnownAuthorityInfoAccessMethod
	| CustomAuthorityInfoAccessMethod;

/** A single entry in the Authority Information Access extension (RFC 5280 §4.2.2.1). */
export interface AuthorityInformationAccess {
	/** Access method (`'ocsp'`, `'caIssuers'`, or custom OID). */
	readonly method:
		| 'ocsp'
		| 'caIssuers'
		| {
				readonly type: 'oid';
				readonly value: string;
		  };
	/** accessLocation GeneralName where the resource is available (usually a URI). */
	readonly location: GeneralName;
}

/**
 * Builder input for one Authority Information Access entry.
 *
 * Parsed AIA locations stay broad ({@linkcode AuthorityInformationAccess}), but
 * an `'ocsp'` entry must supply a URI location, since RFC 6960 §3.1 defines the
 * `id-ad-ocsp` location as a URI; `directoryName` is defined for `caIssuers`.
 */
export type AuthorityInformationAccessInput =
	| {
			/** OCSP responder access method. */
			readonly method: 'ocsp';
			/** OCSP responder URI (RFC 6960 §3.1). */
			readonly location: { readonly type: 'uri'; readonly value: string };
	  }
	| {
			/** caIssuers or a custom access method. */
			readonly method: 'caIssuers' | CustomAuthorityInfoAccessMethod;
			/** Any accessLocation GeneralName. */
			readonly location: GeneralName;
	  };

/** Well-known Extended Key Usage purpose strings (RFC 5280 §4.2.1.12). */
export type KnownExtendedKeyUsage =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning';

/** Extended Key Usage purpose identified by a custom OID. */
export interface CustomExtendedKeyUsage {
	/** Discriminant for the custom-OID EKU variant. */
	readonly type: 'oid';
	/** Dotted-decimal OID of the usage purpose. */
	readonly value: string;
}

/** Extended Key Usage — either a well-known purpose string or a custom OID. */
export type ExtendedKeyUsage =
	| 'serverAuth'
	| 'clientAuth'
	| 'codeSigning'
	| 'emailProtection'
	| 'timeStamping'
	| 'ocspSigning'
	| {
			readonly type: 'oid';
			readonly value: string;
	  };

/** Map from well-known EKU names to their dotted-decimal OIDs. */
const EXTENDED_KEY_USAGE_OIDS: Record<KnownExtendedKeyUsage, string> = {
	serverAuth: OIDS.serverAuth,
	clientAuth: OIDS.clientAuth,
	codeSigning: OIDS.codeSigning,
	emailProtection: OIDS.emailProtection,
	timeStamping: OIDS.timeStamping,
	ocspSigning: OIDS.ocspSigning,
};

/** Map from well-known AIA method names to their dotted-decimal OIDs. */
const AUTHORITY_INFO_ACCESS_METHOD_OIDS: Record<KnownAuthorityInfoAccessMethod, string> = {
	ocsp: OIDS.ocspAccessMethod,
	caIssuers: OIDS.caIssuersAccessMethod,
};

/**
 * Build the v3 extensions block for a certificate.
 *
 * Automatically adds SKI, AKI (when issuer key is available), and
 * basicConstraints (defaults to `{ ca: false }`). Additional extensions
 * come from the caller's {@linkcode CertificateExtensionsInput}.
 *
 * @param subjectPublicKeyInfo DER-encoded SPKI of the subject.
 * @param issuerPublicKeyInfo DER-encoded SPKI of the issuer, or `undefined` for self-signed.
 * @param input Optional extension configuration.
 * @param subjectIsEmpty Whether the certificate subject DN is empty. When `true`, a
 *   subjectAltName extension is required and marked critical per RFC 5280 §4.2.1.6.
 * @returns Array of DER-encoded Extension SEQUENCEs.
 */
export function buildCertificateExtensions(
	subjectPublicKeyInfo: Uint8Array,
	issuerPublicKeyInfo: Uint8Array | undefined,
	input: CertificateExtensionsInput | undefined,
	subjectIsEmpty = false,
): Uint8Array[] {
	assertCustomExtensionsValid(input, 'certificate');
	if (subjectIsEmpty) {
		assertEmptySubjectHasCriticalSubjectAltName(input);
	}
	assertPathLengthKeyUsage(input);
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
	appendConfiguredExtensions(extensions, seen, input, {
		includeBasicConstraints: false,
		subjectIsEmpty,
	});
	return extensions;
}

/**
 * Build the extensions for a CSR's extensionRequest attribute.
 *
 * Unlike {@linkcode buildCertificateExtensions}, SKI/AKI are not auto-generated.
 *
 * @param input Optional extension configuration.
 * @returns Array of DER-encoded Extension SEQUENCEs.
 */
export function buildRequestedExtensions(
	input: CertificateExtensionsInput | undefined,
): Uint8Array[] {
	assertCustomExtensionsValid(input, 'csr');
	const extensions: Uint8Array[] = [];
	const seen = new Set<string>();
	appendConfiguredExtensions(extensions, seen, input, { includeBasicConstraints: true });
	return extensions;
}

/** Encode and push each configured extension from the input, enforcing no duplicates. */
function appendConfiguredExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput | undefined,
	options: {
		readonly includeBasicConstraints: boolean;
		/** When true, SAN is marked critical per RFC 5280 §4.2.1.6. */
		readonly subjectIsEmpty?: boolean;
	},
): void {
	if (input === undefined) {
		return;
	}
	appendConstraintExtensions(encoded, seen, input, options.includeBasicConstraints);
	appendIdentityExtensions(encoded, seen, input, options.subjectIsEmpty === true);
	appendPolicyExtensions(encoded, seen, input);
	appendAccessExtensions(encoded, seen, input);
	appendCustomExtensions(encoded, seen, input);
}

/**
 * RFC 5280 §4.2.1.9: pathLenConstraint requires the keyUsage extension to assert keyCertSign.
 * Absent, empty, or keyCertSign-less keyUsage is rejected. Known extensions supplied through
 * customExtensions participate in the effective view.
 */
function assertPathLengthKeyUsage(input: CertificateExtensionsInput | undefined): void {
	const basicConstraints = resolveEffectiveBasicConstraints(input);
	if (basicConstraints?.pathLength === undefined) {
		return;
	}
	const keyUsage = resolveEffectiveKeyUsage(input);
	if (keyUsage === undefined || keyUsage.length === 0 || !keyUsage.includes('keyCertSign')) {
		throwExtensionEncoderError(
			'path_length_requires_key_cert_sign',
			'basicConstraints pathLength requires the keyUsage keyCertSign bit',
		);
	}
}

/**
 * RFC 5280 §4.2.1.9: basicConstraints is critical in a CA certificate whose key
 * validates signatures on certificates. Both conjuncts live in other extensions,
 * so the rule sits here rather than in the basicConstraints profile hook.
 *
 * §4.2.1.3 restricts a key only through a keyUsage extension that reaches the
 * wire, so an absent keyUsage, and an empty one the builder therefore omits,
 * leave the key free to validate certificate signatures. Only an emitted keyUsage
 * without keyCertSign takes the certificate out of the clause's scope.
 *
 * Only a custom extension can carry the wrong criticality; the typed field is
 * always emitted with the registry default.
 */
function assertCaBasicConstraintsCritical(input: CertificateExtensionsInput | undefined): void {
	const custom = input?.customExtensions?.find((extension) =>
		oidEquals(extension.oid, OIDS.basicConstraints),
	);
	if (custom === undefined || custom.critical === true) {
		return;
	}
	const basicConstraints = BASIC_CONSTRAINTS_EXTENSION_DEFINITION.decode(
		new Uint8Array(custom.value),
	);
	if (!basicConstraints.ca) {
		return;
	}
	const keyUsage = resolveEffectiveKeyUsage(input);
	const mayValidateCertificates =
		keyUsage === undefined || keyUsage.length === 0 || keyUsage.includes('keyCertSign');
	if (mayValidateCertificates) {
		assertExtensionCriticality('basicConstraints', true, false);
	}
}

/**
 * RFC 5280 §4.2.1.6: an empty subject DN requires a subjectAltName extension
 * present, marked critical, and carrying at least one non-empty GeneralName.
 */
function assertEmptySubjectHasCriticalSubjectAltName(
	input: CertificateExtensionsInput | undefined,
): void {
	if (input?.subjectAltNames?.some(subjectAltNameHasIdentity) === true) {
		return;
	}
	const criticalCustomSan = input?.customExtensions?.some(
		(extension) =>
			oidEquals(extension.oid, OIDS.subjectAltName) &&
			extension.critical === true &&
			customSubjectAltNameHasIdentity(extension.value),
	);
	if (criticalCustomSan === true) {
		return;
	}
	throwExtensionEncoderError(
		'empty_subject_requires_subject_alt_name',
		'An empty subject requires a critical subjectAltName extension',
	);
}

/**
 * Canonical OID equality: matches even when arcs carry redundant leading zeros.
 *
 * Both sides must be encodable. Callers run after `assertCustomExtensionsValid`,
 * which rejects an OID that cannot be canonicalized.
 */
function oidEquals(candidate: string, known: string): boolean {
	return candidate === known || canonicalizeOid(candidate) === canonicalizeOid(known);
}

/** First customExtensions value whose OID canonically matches `oid`. */
function findCustomExtensionValue(
	input: CertificateExtensionsInput | undefined,
	oid: string,
): Uint8Array | undefined {
	return input?.customExtensions?.find((extension) => oidEquals(extension.oid, oid))?.value;
}

/** The subset of a DistributionPointName the RFC 5280 §4.2.1.13 rules read. */
interface ProfileDistributionPointName<TRelativeName> {
	/** Absolute GeneralName(s) identifying the distribution point. */
	readonly fullName?: readonly GeneralName[];
	/** Name relative to the CRL issuer, in whichever form the caller holds. */
	readonly relativeName?: TRelativeName;
}

/** The subset of a distribution point the RFC 5280 §4.2.1.13 rules read. */
interface ProfileDistributionPoint<TRelativeName> {
	/** Where to fetch the CRL. */
	readonly distributionPoint?: ProfileDistributionPointName<TRelativeName>;
	/** Entity that signed the CRL, when different from the certificate issuer. */
	readonly crlIssuer?: readonly GeneralName[];
}

/** The DistributionPointName alternative in use, once proven to be exactly one. */
type DistributionPointNameChoice<TRelativeName> =
	| { readonly kind: 'fullName'; readonly fullName: readonly GeneralName[] }
	| { readonly kind: 'relativeName'; readonly relativeName: TRelativeName };

/**
 * Rejects a custom extension carrying a known OID whose payload is not the DER
 * that OID's schema defines, and a known extension offered in the wrong context.
 *
 * Runs before every cross-field guard so the effective-value resolvers below can
 * decode a custom payload without having to tolerate failure.
 */
function assertCustomExtensionsValid(
	input: CertificateExtensionsInput | undefined,
	context: ExtensionRegistryContext,
): void {
	for (const extension of input?.customExtensions ?? []) {
		const oid = validateOid(extension.oid);
		const definition = getExtensionDefinition(oid);
		if (definition === undefined) {
			continue;
		}
		if (!definition.contexts.includes(context)) {
			throwExtensionEncoderError(
				'extension_not_supported_in_context',
				`Extension ${extension.oid} is not supported in ${context} context`,
			);
		}
		assertKnownExtensionPayload(
			definition,
			new Uint8Array(extension.value),
			extension.critical ?? false,
			extension.oid,
		);
	}
}

/**
 * Decode a custom payload once through its known OID's definition and apply that
 * extension's profile rules to the decoded value and its criticality.
 *
 * A profile violation already carries its own code and propagates unchanged; a
 * decode failure means the payload is not the DER the OID's schema defines.
 */
function assertKnownExtensionPayload(
	definition: {
		readonly oid: string;
		assertDerProfile(valueDer: Uint8Array, critical: boolean): void;
	},
	value: Uint8Array,
	critical: boolean,
	submittedOid: string,
): void {
	try {
		definition.assertDerProfile(value, critical);
	} catch (error) {
		if (isResultError(error)) {
			throw error;
		}
		throwExtensionEncoderError(
			'malformed_known_extension_value',
			`Custom extension ${submittedOid} does not decode as ${definition.oid}`,
		);
	}
}

/** Effective basicConstraints across the typed field and any custom-known extension. */
function resolveEffectiveBasicConstraints(
	input: CertificateExtensionsInput | undefined,
): BasicConstraints | undefined {
	if (input?.basicConstraints !== undefined) {
		return input.basicConstraints;
	}
	const custom = findCustomExtensionValue(input, OIDS.basicConstraints);
	return custom === undefined ? undefined : BASIC_CONSTRAINTS_EXTENSION_DEFINITION.decode(custom);
}

/** Effective keyUsage flags across the typed field and any custom-known extension. */
function resolveEffectiveKeyUsage(
	input: CertificateExtensionsInput | undefined,
): readonly KeyUsage[] | undefined {
	if (input?.keyUsage !== undefined) {
		return input.keyUsage;
	}
	const custom = findCustomExtensionValue(input, OIDS.keyUsage);
	return custom === undefined ? undefined : KEY_USAGE_EXTENSION_DEFINITION.decode(custom).flags;
}

/** Whether a typed GeneralName carries a non-empty identity value. */
function subjectAltNameHasIdentity(name: SubjectAltName): boolean {
	return name.type === 'directoryName' ? name.derHex.length > 0 : name.value.length > 0;
}

/** Whether a custom subjectAltName value decodes to at least one non-empty GeneralName. */
function customSubjectAltNameHasIdentity(value: Uint8Array): boolean {
	return SUBJECT_ALT_NAME_EXTENSION_DEFINITION.decode(value).some(subjectAltNameHasIdentity);
}

function appendConstraintExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput,
	includeBasicConstraints: boolean,
): void {
	assertPathLengthKeyUsage(input);
	assertCaBasicConstraintsCritical(input);
	if (includeBasicConstraints && input.basicConstraints !== undefined) {
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
	if (input.nameConstraints !== undefined) {
		pushKnownExtension(encoded, seen, NAME_CONSTRAINTS_EXTENSION_DEFINITION, input.nameConstraints);
	}
}

function appendIdentityExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput,
	subjectIsEmpty: boolean,
): void {
	if (input.subjectAltNames !== undefined && input.subjectAltNames.length > 0) {
		// RFC 5280 §4.2.1.6: SAN MUST be critical when subject DN is empty.
		const sanCritical = subjectIsEmpty ? true : undefined;
		pushKnownExtension(
			encoded,
			seen,
			SUBJECT_ALT_NAME_EXTENSION_DEFINITION,
			input.subjectAltNames,
			sanCritical,
		);
	}
	if (input.extendedKeyUsage !== undefined && input.extendedKeyUsage.length > 0) {
		pushKnownExtension(
			encoded,
			seen,
			EXTENDED_KEY_USAGE_EXTENSION_DEFINITION,
			input.extendedKeyUsage,
		);
	}
}

/** Appends configured certificate-policy extensions while enforcing unique OIDs. */
function appendPolicyExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput,
): void {
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
}

function appendAccessExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput,
): void {
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
}

/** Push each custom extension. Context and payload were checked by `assertCustomExtensionsValid`. */
function appendCustomExtensions(
	encoded: Uint8Array[],
	seen: Set<string>,
	input: CertificateExtensionsInput,
): void {
	for (const extension of input.customExtensions ?? []) {
		pushExtension(
			encoded,
			seen,
			extension.oid,
			new Uint8Array(extension.value),
			extension.critical ?? false,
		);
	}
}

/** Encode a known extension via its registry definition and push it. */
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
 * Encode a single X.509 Extension SEQUENCE (OID + optional critical BOOLEAN + OCTET STRING).
 *
 * @param oid Dotted-decimal extension OID.
 * @param extnValue DER-encoded extension payload.
 * @param critical Whether to mark the extension as critical. Default `false`.
 */
export function encodeExtension(oid: string, extnValue: Uint8Array, critical = false): Uint8Array {
	validateOid(oid);
	const fields = [objectIdentifier(oid)];
	if (critical) {
		fields.push(bool(true));
	}
	fields.push(octetString(extnValue));
	return sequence(fields);
}

/**
 * DER-encode a {@linkcode BasicConstraints} value.
 *
 * @param input CA flag and optional pathLength.
 * @returns DER SEQUENCE suitable for wrapping in an Extension OCTET STRING.
 */
export function encodeBasicConstraints(input: BasicConstraints): Uint8Array {
	const fields: Uint8Array[] = [];
	if (input.ca) {
		fields.push(bool(true));
	}
	if (input.pathLength !== undefined) {
		if (!input.ca) {
			throwExtensionEncoderError(
				'path_length_requires_ca',
				'basicConstraints pathLength requires ca = true',
			);
		}
		fields.push(integerFromNumber(input.pathLength));
	}
	return sequence(fields);
}

/**
 * DER-encode a Key Usage BIT STRING from an array of {@linkcode KeyUsage} flags.
 *
 * @param usages Flags to set in the bit string.
 */
export function encodeKeyUsage(usages: readonly KeyUsage[]): Uint8Array {
	return encodeKeyUsageExtension(usages);
}

function encodeIa5Content(value: string): Uint8Array {
	try {
		return ia5Bytes(value);
	} catch {
		throwExtensionEncoderError(
			'invalid_ia5_string',
			'Invalid IA5String: contains non-ASCII characters',
		);
	}
}

/** RFC 5280 §4.2.1.6: reject an empty GeneralName string value (empty dNSName, rfc822Name, URI, or SRV name). */
function requireNonEmptyName(value: string): string {
	if (value.length === 0) {
		throwExtensionEncoderError('empty_general_name_value', 'GeneralName value must not be empty');
	}
	return value;
}

/**
 * DER-encode a single {@linkcode SubjectAltName} GeneralName element.
 *
 * @param value The SAN entry to encode.
 */
export function encodeSubjectAltName(value: SubjectAltName): Uint8Array {
	switch (value.type) {
		case 'dns':
			return implicitPrimitiveContext(2, encodeIa5Content(requireNonEmptyName(value.value)));
		case 'email':
			return implicitPrimitiveContext(1, encodeIa5Content(requireNonEmptyName(value.value)));
		case 'uri':
			return implicitPrimitiveContext(6, encodeIa5Content(requireNonEmptyName(value.value)));
		case 'srv':
			return implicitConstructedContext(
				0,
				concatBytes([
					objectIdentifier(OIDS.idOnDnsSrv),
					explicitContext(0, tlv(0x16, encodeIa5Content(requireNonEmptyName(value.value)))),
				]),
			);
		case 'ip':
			return implicitPrimitiveContext(7, encodeIpAddress(value.value));
		case 'directoryName':
			return implicitConstructedContext(4, readDirectoryNameTlv(value.derHex));
		case 'unknown':
			if (!GENERAL_NAME_WIRE_TAGS.has(value.tag)) {
				throwExtensionEncoderError(
					'invalid_general_name_tag',
					`Invalid GeneralName tag: ${value.tag}`,
				);
			}
			return tlv(value.tag, value.value);
		default: {
			const _exhaustive: never = value;
			throw new Error(`Unhandled SubjectAltName type: ${String(_exhaustive)}`);
		}
	}
}

/**
 * DER-encode an Extended Key Usage SEQUENCE OF OIDs.
 *
 * @param usages EKU purposes to encode.
 */
export function encodeExtendedKeyUsage(usages: readonly ExtendedKeyUsage[]): Uint8Array {
	if (usages.length === 0) {
		throwExtensionEncoderError('extended_key_usage_empty', 'extendedKeyUsage must not be empty');
	}
	return sequence(usages.map((usage) => objectIdentifier(getExtendedKeyUsageOid(usage))));
}

/**
 * DER-encode an Authority Information Access SEQUENCE.
 *
 * @param entries AIA entries (OCSP, caIssuers, or custom) to encode.
 */
export function encodeAuthorityInfoAccess(
	entries: readonly AuthorityInformationAccessInput[],
): Uint8Array {
	assertAuthorityInfoAccessProfile(entries);
	return sequence(
		entries.map((entry) =>
			sequence([
				objectIdentifier(getAuthorityInfoAccessMethodOid(entry.method)),
				encodeSubjectAltName(entry.location),
			]),
		),
	);
}

/**
 * @internal RFC 5280 §4.2.2.1 and RFC 6960 §3.1 rules for Authority Information
 * Access: at least one entry, and an id-ad-ocsp location that is a URI.
 *
 * The method OID is resolved before the URI check so a custom-OID wrapper cannot
 * smuggle a non-URI OCSP location past the input union.
 */
export function assertAuthorityInfoAccessProfile(
	entries: readonly AuthorityInformationAccess[],
): void {
	if (entries.length === 0) {
		throwExtensionEncoderError(
			'authority_info_access_empty',
			'authorityInfoAccess must not be empty',
		);
	}
	for (const entry of entries) {
		const methodOid = getAuthorityInfoAccessMethodOid(entry.method);
		if (methodOid === OIDS.ocspAccessMethod && entry.location.type !== 'uri') {
			throwExtensionEncoderError(
				'authority_info_access_ocsp_not_uri',
				'authorityInfoAccess OCSP location must be a URI',
			);
		}
	}
}

/**
 * DER-encode a CRL Distribution Points SEQUENCE.
 *
 * @param points Distribution points to encode.
 */
export function encodeCrlDistributionPoints(points: readonly DistributionPoint[]): Uint8Array {
	assertCrlDistributionPointsProfile(points);
	return sequence(points.map((point) => sequence(encodeDistributionPoint(point))));
}

/**
 * @internal RFC 5280 §4.2.1.13 profile rules for a CRLDistributionPoints value,
 * stated over the fields a typed {@linkcode DistributionPoint} and a decoded
 * `ParsedDistributionPoint` share.
 *
 * `TRelativeName` differs between the two: builder input carries an unencoded RDN,
 * a decoded point carries the parsed one. The rules only read its presence.
 */
export function assertCrlDistributionPointsProfile<TRelativeName>(
	points: readonly ProfileDistributionPoint<TRelativeName>[],
): void {
	if (points.length === 0) {
		throwExtensionEncoderError(
			'crl_distribution_points_empty',
			'cRLDistributionPoints must not be empty',
		);
	}
	for (const point of points) {
		assertDistributionPointProfile(point);
	}
}

/** RFC 5280 §4.2.1.13 rules for one distribution point. */
function assertDistributionPointProfile<TRelativeName>(
	point: ProfileDistributionPoint<TRelativeName>,
): void {
	if (point.crlIssuer !== undefined && point.crlIssuer.length === 0) {
		throwExtensionEncoderError(
			'distribution_point_crl_issuer_empty',
			'DistributionPoint crlIssuer must not be empty',
		);
	}
	if (point.distributionPoint === undefined && point.crlIssuer === undefined) {
		throwExtensionEncoderError(
			'distribution_point_empty',
			'DistributionPoint must contain distributionPoint or crlIssuer',
		);
	}
	assertCrlIssuerDistinguishedNames(point);
	if (point.distributionPoint !== undefined) {
		resolveDistributionPointNameChoice(point.distributionPoint);
	}
}

/**
 * DER-encode a Name Constraints extension value.
 *
 * @param constraints Permitted and/or excluded subtrees.
 */
export function encodeNameConstraints(constraints: NameConstraints): Uint8Array {
	assertNameConstraintsProfile(constraints);
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
 * @internal RFC 5280 fixes the criticality of several extensions: nameConstraints
 * (§4.2.1.10), policyConstraints (§4.2.1.11), and inhibitAnyPolicy (§4.2.1.14) are
 * critical; authorityKeyIdentifier (§4.2.1.1), subjectKeyIdentifier (§4.2.1.2),
 * and authorityInfoAccess (§4.2.2.1) are not.
 *
 * @param label Extension name quoted in the diagnostic.
 * @param required The criticality RFC 5280 mandates.
 * @param critical The criticality the caller asked for.
 */
export function assertExtensionCriticality(
	label: string,
	required: boolean,
	critical: boolean,
): void {
	if (critical === required) {
		return;
	}
	throwExtensionEncoderError(
		required ? 'extension_must_be_critical' : 'extension_must_be_non_critical',
		`The ${label} extension must be marked ${required ? 'critical' : 'non-critical'}`,
	);
}

/**
 * @internal RFC 5280 §4.2.1.10: a nameConstraints extension states at least one
 * of permittedSubtrees and excludedSubtrees, and neither may be an empty set.
 */
export function assertNameConstraintsProfile(constraints: {
	readonly permittedSubtrees?: readonly unknown[];
	readonly excludedSubtrees?: readonly unknown[];
}): void {
	const permitted = constraints.permittedSubtrees?.length ?? 0;
	const excluded = constraints.excludedSubtrees?.length ?? 0;
	if (permitted === 0 && excluded === 0) {
		throwExtensionEncoderError(
			'name_constraints_empty',
			'nameConstraints must set permittedSubtrees or excludedSubtrees',
		);
	}
}

/**
 * DER-encode a Certificate Policies extension value.
 *
 * @param policies Non-empty array of policy information entries.
 */
export function encodeCertificatePolicies(policies: CertificatePolicies): Uint8Array {
	if (policies.length === 0) {
		throwExtensionEncoderError(
			'certificate_policies_empty',
			'certificatePolicies must not be empty',
		);
	}
	const seen = new Set<string>();
	for (const policy of policies) {
		const key = validatePolicyOid(policy.policyIdentifier);
		if (seen.has(key)) {
			throwExtensionEncoderError(
				'duplicate_policy_oid',
				`Duplicate certificate policy OID: ${policy.policyIdentifier}`,
			);
		}
		seen.add(key);
	}
	return sequence(policies.map(encodePolicyInformation));
}

/**
 * DER-encode a Policy Mappings extension value.
 *
 * @param mappings Non-empty array of issuer-to-subject policy pairs. Neither OID may be anyPolicy.
 */
export function encodePolicyMappings(mappings: PolicyMappings): Uint8Array {
	if (mappings.length === 0) {
		throwExtensionEncoderError('policy_mappings_empty', 'policyMappings must not be empty');
	}
	return sequence(
		mappings.map((mapping) => {
			const issuerDomainPolicy = validatePolicyOid(mapping.issuerDomainPolicy);
			const subjectDomainPolicy = validatePolicyOid(mapping.subjectDomainPolicy);
			if (issuerDomainPolicy === OIDS.anyPolicy || subjectDomainPolicy === OIDS.anyPolicy) {
				throwExtensionEncoderError(
					'policy_mappings_any_policy',
					'policyMappings must not use anyPolicy',
				);
			}
			return sequence([
				objectIdentifier(mapping.issuerDomainPolicy),
				objectIdentifier(mapping.subjectDomainPolicy),
			]);
		}),
	);
}

/**
 * DER-encode a Policy Constraints extension value.
 *
 * @param constraints At least one of `requireExplicitPolicy` or `inhibitPolicyMapping` must be set.
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
		throwExtensionEncoderError(
			'policy_constraints_empty',
			'policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping',
		);
	}
	return sequence(fields);
}

/**
 * DER-encode an Inhibit anyPolicy extension value (single INTEGER).
 *
 * @param input The skipCerts threshold.
 */
export function encodeInhibitAnyPolicy(input: InhibitAnyPolicy): Uint8Array {
	return integerFromNumber(input.skipCerts);
}

/** DER-encode a single PolicyInformation SEQUENCE. */
function encodePolicyInformation(policy: PolicyInformation): Uint8Array {
	validatePolicyOid(policy.policyIdentifier);
	const fields = [objectIdentifier(policy.policyIdentifier)];
	if (policy.policyQualifiers !== undefined && policy.policyQualifiers.length > 0) {
		fields.push(sequence(policy.policyQualifiers.map(encodePolicyQualifierInfo)));
	}
	return sequence(fields);
}

/** DER-encode a single PolicyQualifierInfo SEQUENCE. */
function encodePolicyQualifierInfo(qualifier: PolicyQualifierInfo): Uint8Array {
	switch (qualifier.type) {
		case 'cps':
			return sequence([objectIdentifier(OIDS.cpsPolicyQualifier), ia5String(qualifier.uri)]);
		case 'userNotice':
			return sequence([
				objectIdentifier(OIDS.userNoticePolicyQualifier),
				encodeUserNoticePolicyQualifierInfo(qualifier),
			]);
		case 'oid': {
			validateOid(qualifier.oid);
			const encodedOid = objectIdentifier(qualifier.oid);
			const canonicalOid = toHex(encodedOid);
			if (
				canonicalOid === toHex(objectIdentifier(OIDS.cpsPolicyQualifier)) ||
				canonicalOid === toHex(objectIdentifier(OIDS.userNoticePolicyQualifier))
			) {
				throwExtensionEncoderError(
					'reserved_policy_qualifier_oid',
					'Policy qualifier must use the typed cps or userNotice variant, not a built-in OID',
				);
			}
			return sequence([encodedOid, new Uint8Array(qualifier.qualifierDer)]);
		}
		default: {
			const _exhaustive: never = qualifier;
			throw new Error(`Unhandled PolicyQualifierInfo type: ${String(_exhaustive)}`);
		}
	}
}

/** DER-encode a UserNotice qualifier SEQUENCE. */
function assertDisplayText(value: string): void {
	const length = [...value].length;
	if (length === 0 || length > 200) {
		throwExtensionEncoderError(
			'display_text_out_of_range',
			'DisplayText must be 1 to 200 characters',
		);
	}
}

function encodeUserNoticePolicyQualifierInfo(qualifier: UserNoticePolicyQualifierInfo): Uint8Array {
	const fields: Uint8Array[] = [];
	if (qualifier.noticeRef !== undefined) {
		fields.push(encodePolicyNoticeReference(qualifier.noticeRef));
	}
	if (qualifier.explicitText !== undefined) {
		assertDisplayText(qualifier.explicitText);
		fields.push(utf8String(qualifier.explicitText));
	}
	return sequence(fields);
}

/** DER-encode a NoticeReference SEQUENCE. */
function encodePolicyNoticeReference(reference: PolicyNoticeReference): Uint8Array {
	assertDisplayText(reference.organization);
	return sequence([
		utf8String(reference.organization),
		sequence(reference.noticeNumbers.map((noticeNumber) => integerFromNumber(noticeNumber))),
	]);
}

/** Encode an INTEGER and return only the content bytes (no TLV wrapper). */
function encodeIntegerContent(value: number): Uint8Array {
	return readElement(integerFromNumber(value)).value;
}

/** DER-encode a GeneralSubtree SEQUENCE (base name only; min/max omitted per RFC 5280). */
function encodeGeneralSubtree(subtree: GeneralSubtree): Uint8Array {
	return sequence([encodeNameConstraintForm(subtree.base)]);
}

/**
 * RFC 5280 §4.2.1.13: cRLIssuer, when present, only contains the CRL issuer's
 * distinguished name; nameRelativeToCRLIssuer additionally requires exactly one.
 *
 * Applies to a typed {@linkcode DistributionPoint} and to a decoded
 * {@linkcode ParsedDistributionPoint} alike, so the rule holds whether the value
 * arrives through `crlDistributionPoints` or through `customExtensions`.
 */
function assertCrlIssuerDistinguishedNames<TRelativeName>(
	point: ProfileDistributionPoint<TRelativeName>,
): void {
	if (point.crlIssuer === undefined) {
		return;
	}
	if (point.crlIssuer.some((name) => name.type !== 'directoryName')) {
		throwExtensionEncoderError(
			'distribution_point_crl_issuer_not_directory_name',
			'DistributionPoint cRLIssuer must only contain directoryName entries',
		);
	}
	if (point.distributionPoint?.relativeName !== undefined && point.crlIssuer.length > 1) {
		throwExtensionEncoderError(
			'distribution_point_relative_name_multiple_crl_issuers',
			'DistributionPointName relativeName requires at most one cRLIssuer distinguished name',
		);
	}
}

/** DER-encode the fields of a single DistributionPoint, already profile-checked. */
function encodeDistributionPoint(point: DistributionPoint): Uint8Array[] {
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
	if (point.crlIssuer !== undefined) {
		fields.push(
			implicitConstructedContext(2, concatBytes(point.crlIssuer.map(encodeSubjectAltName))),
		);
	}
	return fields;
}

/**
 * RFC 5280 §4.2.1.13: a DistributionPointName holds exactly one of fullName and
 * relativeName, and a fullName holds at least one GeneralName.
 */
function resolveDistributionPointNameChoice<TRelativeName>(
	name: ProfileDistributionPointName<TRelativeName>,
): DistributionPointNameChoice<TRelativeName> {
	if (name.fullName !== undefined && name.relativeName !== undefined) {
		throwExtensionEncoderError(
			'distribution_point_name_conflict',
			'DistributionPointName cannot contain both fullName and relativeName',
		);
	}
	if (name.fullName !== undefined) {
		if (name.fullName.length === 0) {
			throwExtensionEncoderError(
				'distribution_point_full_name_empty',
				'DistributionPointName fullName must not be empty',
			);
		}
		return { kind: 'fullName', fullName: name.fullName };
	}
	if (name.relativeName !== undefined) {
		return { kind: 'relativeName', relativeName: name.relativeName };
	}
	throwExtensionEncoderError(
		'distribution_point_name_empty',
		'DistributionPointName must contain fullName or relativeName',
	);
}

/** DER-encode a DistributionPointName (fullName or relativeName). */
function encodeDistributionPointName(name: DistributionPointName): Uint8Array {
	const choice = resolveDistributionPointNameChoice(name);
	if (choice.kind === 'fullName') {
		return implicitConstructedContext(0, concatBytes(choice.fullName.map(encodeSubjectAltName)));
	}
	const relativeName = encodeRelativeDistinguishedName(choice.relativeName);
	const relativeNameElement = readElement(relativeName);
	return implicitConstructedContext(
		1,
		relativeName.slice(relativeNameElement.start, relativeNameElement.end),
	);
}

/** DER-encode a NameConstraintForm as an implicit-tagged {@linkcode GeneralName}. */
function encodeNameConstraintForm(form: NameConstraintForm): Uint8Array {
	switch (form.type) {
		case 'dns':
			return implicitPrimitiveContext(2, ia5Bytes(form.value));
		case 'email':
			return implicitPrimitiveContext(1, ia5Bytes(form.value));
		case 'uri':
			return implicitPrimitiveContext(6, ia5Bytes(form.value));
		case 'ip': {
			const total = form.addressBytes.length + form.maskBytes.length;
			if (form.addressBytes.length !== form.maskBytes.length || (total !== 8 && total !== 32)) {
				throwExtensionEncoderError(
					'invalid_ip_name_constraint',
					'IP name constraint must be 8 octets (IPv4) or 32 octets (IPv6)',
				);
			}
			return implicitPrimitiveContext(7, concatBytes([form.addressBytes, form.maskBytes]));
		}
		case 'directoryName':
			return implicitConstructedContext(4, readDirectoryNameTlv(form.derHex));
		default: {
			const _exhaustive: never = form;
			throw new Error(`Unhandled NameConstraintForm type: ${String(_exhaustive)}`);
		}
	}
}

/** Returns the complete Name TLV from a hex-encoded DER SEQUENCE, validating the root tag. */
function readDirectoryNameTlv(derHex: string): Uint8Array {
	const bytes = hexToBytes(derHex);
	const element = readRootElement(bytes, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	if (element.tag !== 0x30) {
		throwExtensionEncoderError(
			'directory_name_not_sequence',
			'directoryName derHex must encode a DER SEQUENCE',
		);
	}
	return bytes.slice(element.start - element.headerLength, element.end);
}

/**
 * Resolve an {@linkcode ExtendedKeyUsage} to its dotted-decimal OID.
 *
 * @param usage Well-known string or custom OID object.
 */
export function getExtendedKeyUsageOid(usage: ExtendedKeyUsage): string {
	if (typeof usage === 'string') {
		return EXTENDED_KEY_USAGE_OIDS[usage];
	}
	return validateOid(usage.value);
}

/**
 * Map a dotted-decimal OID to an {@linkcode ExtendedKeyUsage} value.
 *
 * Returns a well-known string for recognized OIDs, or `{ type: 'oid', value }` otherwise.
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
 * Resolve an {@linkcode AuthorityInfoAccessMethod} to its dotted-decimal OID.
 *
 * @param method Well-known string or custom OID object.
 */
export function getAuthorityInfoAccessMethodOid(method: AuthorityInfoAccessMethod): string {
	if (typeof method === 'string') {
		return AUTHORITY_INFO_ACCESS_METHOD_OIDS[method];
	}
	return validateOid(method.value);
}

/**
 * Map a dotted-decimal OID to an {@linkcode AuthorityInfoAccessMethod} value.
 *
 * Returns `'ocsp'` or `'caIssuers'` for recognized OIDs, or `{ type: 'oid', value }` otherwise.
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

/** Parse a dotted-decimal/colon-hex IP string to raw address bytes. */
function encodeIpAddress(input: string): Uint8Array {
	return parseIpAddressToBytes(input);
}

/** @internal Compute the SKI as SHA-1 of the subjectPublicKey BIT STRING content. */
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
 * Throw if the string is not an encodable dotted-decimal OID, and return its
 * canonical spelling.
 *
 * Syntax alone is not enough. X.660 bounds the first arc to 0, 1, or 2 and the
 * second to under 40 beneath arcs 0 and 1, so `3.1` and `1.40` parse as decimals
 * yet cannot be encoded.
 */
function validateOid(oid: string): string {
	if (!/^\d+(?:\.\d+)+$/.test(oid)) {
		throwExtensionEncoderError('invalid_oid', `Invalid OID: ${oid}`);
	}
	try {
		return canonicalizeOid(oid);
	} catch {
		throwExtensionEncoderError('invalid_oid', `Invalid OID: ${oid}`);
	}
}

/** Validate a policy OID and return its canonical spelling. */
function validatePolicyOid(oid: string): string {
	return validateOid(oid);
}

/**
 * Encode and push an extension, rejecting duplicate OIDs.
 *
 * Duplicate identity is the canonical OID, because two spellings that differ only
 * by leading zeros in an arc encode to the same wire bytes. The diagnostic quotes
 * the OID as submitted, which is the string the caller can find in their input.
 */
function pushExtension(
	encoded: Uint8Array[],
	seen: Set<string>,
	oid: string,
	value: Uint8Array,
	critical = false,
): void {
	const identity = validateOid(oid);
	if (seen.has(identity)) {
		throwExtensionEncoderError('duplicate_extension_oid', `Duplicate extension OID: ${oid}`);
	}
	seen.add(identity);
	encoded.push(encodeExtension(oid, value, critical));
}
