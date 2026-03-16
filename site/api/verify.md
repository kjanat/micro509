[micro509](modules.md) / verify

# verify

Canonical advanced verification domain surface.
Owns chain validation, service identity, policy, and name-constraint APIs.

## Interfaces

### BuildCandidatePathInput

Defined in: [verify/verify.ts:226](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L226)

Input for [`buildCandidatePath`](#buildcandidatepath).

#### Extended by

- [`ValidateForCaInput`](#validateforcainput)
- [`ValidateForCodeSigningInput`](#validateforcodesigninginput)
- [`ValidateForTlsClientInput`](#validatefortlsclientinput)
- [`ValidateForTlsServerInput`](#validatefortlsserverinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L236)

Validation time. Defaults to `new Date()`.

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L230)

Intermediate CA certificates available for path building. Order does not matter.

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L228)

End-entity certificate to verify.

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:232](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L232)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L234)

Bare trust anchors to try when no root certificate matches.

---

### CandidatePath

Defined in: [verify/verify.ts:240](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L240)

A signature-verified certification path from leaf to root, before constraint validation.

#### Properties

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:244](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L244)

Full chain in leaf-to-root order (includes both leaf and root).

##### leaf

> `readonly` **leaf**: [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [verify/verify.ts:242](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L242)

Parsed end-entity certificate.

##### root

> `readonly` **root**: [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [verify/verify.ts:246](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L246)

Trusted root that terminates the path.

---

### ConstrainedPolicy

Defined in: [verify/policy.ts:33](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L33)

One policy OID that survives RFC 5280 / RFC 9618 processing.

#### Properties

##### policyIdentifier

> `readonly` **policyIdentifier**: `string`

Defined in: [verify/policy.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L35)

Dotted-decimal OID of the surviving policy.

##### policyQualifiers?

> `readonly` `optional` **policyQualifiers**: readonly [`PolicyQualifierInfo`](x509.md#policyqualifierinfo)[]

Defined in: [verify/policy.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L37)

Qualifier info (CPS URIs, user notices) attached to this policy, if any.

---

### DnsServiceIdentityInput

Defined in: [verify/identity.ts:17](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L17)

DNS hostname reference identifier.

#### Properties

##### allowCommonNameFallback?

> `readonly` `optional` **allowCommonNameFallback**: `boolean`

Defined in: [verify/identity.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L27)

When `true`, falls back to the subject CN if the SAN extension has no
dns/uri/srv entries. Suppressed when any supported SAN type is present.

###### Default

```ts
false;
```

##### type

> `readonly` **type**: `"dns"`

Defined in: [verify/identity.ts:19](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L19)

Discriminant for DNS hostname matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:21](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L21)

The hostname to match (e.g. `"mail.example.com"`). Wildcard labels in the certificate are handled internally.

---

### EkuCheckFailure

Defined in: [verify/verify.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L110)

Failure from [`checkExtendedKeyUsage`](#checkextendedkeyusage) with the chain index of the certificate that failed.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"leaf_eku_missing"` \| `"intermediate_eku_constraint"`\>

#### Properties

##### code

> `readonly` **code**: `"intermediate_eku_constraint"` \| `"leaf_eku_missing"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### index

> `readonly` **index**: `number`

Defined in: [verify/verify.ts:115](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L115)

Zero-based index into the chain of the certificate that lacks the required EKU.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:113](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L113)

Always `false` for failures.

---

### InitialNameConstraintsInput

Defined in: [verify/name-constraints.ts:18](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L18)

Input for `createNameConstraintValidationState`.

Seeds the name-constraint engine with trust-anchor-level subtree
restrictions that apply before any certificate in the chain is processed.

#### Extended by

- [`ValidateCandidatePathInput`](#validatecandidatepathinput)
- [`ValidateForCaInput`](#validateforcainput)
- [`ValidateForCodeSigningInput`](#validateforcodesigninginput)
- [`ValidateForTlsClientInput`](#validatefortlsclientinput)
- [`ValidateForTlsServerInput`](#validatefortlsserverinput)
- [`VerifyCertificateChainInput`](#verifycertificatechaininput)

#### Properties

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

---

### IpServiceIdentityInput

Defined in: [verify/identity.ts:31](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L31)

IP address reference identifier.

#### Properties

##### type

> `readonly` **type**: `"ip"`

Defined in: [verify/identity.ts:33](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L33)

Discriminant for IP address matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L35)

IPv4 or IPv6 address string. Normalized before comparison.

---

### MatchServiceIdentityFailure

Defined in: [verify/identity.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L94)

A failed identity-matching attempt.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<[`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](#matchserviceidentityfailuredetails-1)\>

#### Properties

##### code

> `readonly` **code**: [`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: [`MatchServiceIdentityFailureDetails`](#matchserviceidentityfailuredetails-1)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/identity.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L97)

Always `false` for failures.

---

### MatchServiceIdentityFailureDetails

Defined in: [verify/identity.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L76)

Diagnostic context attached to an identity-matching failure.

#### Properties

##### actual?

> `readonly` `optional` **actual**: `string`

Defined in: [verify/identity.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L82)

Comma-joined presented identifiers (from SAN) that were compared.

##### commonNameFallbackReason?

> `readonly` `optional` **commonNameFallbackReason**: `"disabled"` \| `"suppressed_by_presented_identifier"` \| `"common_name_missing"` \| `"common_name_mismatch"`

Defined in: [verify/identity.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L86)

Explains why CN fallback was not used or failed.

##### expected?

> `readonly` `optional` **expected**: `string`

Defined in: [verify/identity.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L80)

The reference identifier the caller asked to verify.

##### presentedIdentifierTypes?

> `readonly` `optional` **presentedIdentifierTypes**: readonly (`"uri"` \| `"dns"` \| `"srv"`)[]

Defined in: [verify/identity.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L84)

SAN types that were present, relevant to CN-fallback suppression logic.

##### subjectCommonName?

> `readonly` `optional` **subjectCommonName**: `string`

Defined in: [verify/identity.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L78)

CN of the certificate that was being matched, if present.

---

### MatchServiceIdentityInput

Defined in: [verify/identity.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L128)

Input for [`matchServiceIdentity`](#matchserviceidentity).

#### Properties

##### certificate

> `readonly` **certificate**: [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [verify/identity.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L130)

The parsed leaf certificate to check.

##### serviceIdentity

> `readonly` **serviceIdentity**: [`ServiceIdentityInput`](#serviceidentityinput)

Defined in: [verify/identity.ts:132](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L132)

The reference identifier the client wants to verify.

---

### MatchServiceIdentitySuccess

Defined in: [verify/identity.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L101)

A successful identity match (the certificate covers the requested name).

#### Properties

##### ok

> `readonly` **ok**: `true`

Defined in: [verify/identity.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L103)

Always `true` for success.

##### value

> `readonly` **value**: `undefined`

Defined in: [verify/identity.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L105)

No payload on success — the match itself is the signal.

---

### PolicyValidationInput

Defined in: [verify/policy.ts:18](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L18)

Input for the policy-validation engine.

All fields are optional — omitted values produce the most permissive
behavior (accept any policy, allow mappings, allow anyPolicy).

#### Extended by

- [`ValidateCandidatePathInput`](#validatecandidatepathinput)
- [`ValidateForCaInput`](#validateforcainput)
- [`ValidateForCodeSigningInput`](#validateforcodesigninginput)
- [`ValidateForTlsClientInput`](#validatefortlsclientinput)
- [`ValidateForTlsServerInput`](#validatefortlsserverinput)
- [`VerifyCertificateChainInput`](#verifycertificatechaininput)

#### Properties

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

---

### PolicyValidationOutcome

Defined in: [verify/policy.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L41)

Final policy outputs exposed by successful path-validation APIs.

#### Properties

##### authorityConstrainedPolicies

> `readonly` **authorityConstrainedPolicies**: readonly [`ConstrainedPolicy`](#constrainedpolicy)[]

Defined in: [verify/policy.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L43)

Policies valid under the authority's (CA chain) constraints alone.

##### userConstrainedPolicies

> `readonly` **userConstrainedPolicies**: readonly [`ConstrainedPolicy`](#constrainedpolicy)[]

Defined in: [verify/policy.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L45)

Policies that also satisfy the caller's [`PolicyValidationInput.initialPolicySet`](#initialpolicyset).

---

### SrvServiceIdentityInput

Defined in: [verify/identity.ts:47](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L47)

SRV-ID reference identifier (RFC 4985).

#### Properties

##### type

> `readonly` **type**: `"srv"`

Defined in: [verify/identity.ts:49](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L49)

Discriminant for SRV-ID matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:51](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L51)

SRV name in `_service.domain` form (e.g. `"_imap.example.com"`).

---

### TrustAnchor

Defined in: [verify/verify.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L127)

Bare trust anchor — subject identity and public key material without a
full certificate. Used when the root CA certificate is unavailable but
its key is known. Build from a certificate with [`trustAnchorFromCertificate`](#trustanchorfromcertificate).

#### Properties

##### publicKeyAlgorithmOid

> `readonly` **publicKeyAlgorithmOid**: `string`

Defined in: [verify/verify.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L133)

OID of the public key algorithm (e.g. `1.2.840.10045.2.1` for EC).

##### publicKeyParametersOid?

> `readonly` `optional` **publicKeyParametersOid**: `string`

Defined in: [verify/verify.ts:135](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L135)

OID of the key parameters, when algorithm-specific (e.g. named curve OID for EC).

##### subject

> `readonly` **subject**: [`ParsedName`](x509.md#parsedname)

Defined in: [verify/verify.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L129)

Parsed subject distinguished name. Used for semantic issuer matching (RFC 5280 §7.1).

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [verify/verify.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L137)

Hex-encoded subject key identifier for AKI matching.

##### subjectPublicKeyInfoDer

> `readonly` **subjectPublicKeyInfoDer**: `Uint8Array`

Defined in: [verify/verify.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L131)

DER-encoded SubjectPublicKeyInfo used to verify signatures from this anchor.

---

### UriServiceIdentityInput

Defined in: [verify/identity.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L39)

URI-ID reference identifier (RFC 6125 §6.5). Scheme and host are matched.

#### Properties

##### type

> `readonly` **type**: `"uri"`

Defined in: [verify/identity.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L41)

Discriminant for URI-ID matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L43)

Full URI whose scheme and reg-name will be compared.

---

### ValidateCandidatePathInput

Defined in: [verify/verify.ts:262](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L262)

Input for [`validateCandidatePath`](#validatecandidatepath).

#### Extends

- [`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### allowSelfSignedLeaf?

> `readonly` `optional` **allowSelfSignedLeaf**: `boolean`

Defined in: [verify/verify.ts:276](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L276)

When `true`, allows a self-signed leaf that is also the root. Defaults to `false`.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:272](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L272)

Validation time. Defaults to `new Date()`.

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:270](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L270)

Pre-built certificate chain in leaf-to-root order.

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:268](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L268)

Nested name constraint overrides (takes precedence over flat fields).

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:266](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L266)

Nested policy validation overrides (takes precedence over flat fields).

##### purpose?

> `readonly` `optional` **purpose**: [`VerifyPurpose`](#verifypurpose)

Defined in: [verify/verify.ts:274](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L274)

Leaf purpose constraint to enforce.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

---

### ValidateCandidatePathSuccess

Defined in: [verify/verify.ts:280](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L280)

Success payload from [`validateCandidatePath`](#validatecandidatepath).

#### Properties

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](#policyvalidationoutcome)

Defined in: [verify/verify.ts:282](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L282)

Final RFC 9618-constrained policy outputs for this validated path.

---

### ValidateForCaInput

Defined in: [verify/verify.ts:427](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L427)

Input for [`validateForCa`](#validateforca). Enforces `basicConstraints.ca` on the leaf.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L236)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L230)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L228)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:434](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L434)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:432](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L432)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:232](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L232)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L234)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForCodeSigningInput

Defined in: [verify/verify.ts:417](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L417)

Input for [`validateForCodeSigning`](#validateforcodesigning). Enforces `codeSigning` EKU.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L236)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L230)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L228)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:424](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L424)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:422](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L422)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:232](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L232)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L234)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForTlsClientInput

Defined in: [verify/verify.ts:407](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L407)

Input for [`validateForTlsClient`](#validatefortlsclient). Enforces `clientAuth` EKU.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L236)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L230)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L228)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:414](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L414)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:412](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L412)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:232](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L232)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L234)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForTlsServerInput

Defined in: [verify/verify.ts:384](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L384)

Input for [`validateForTlsServer`](#validatefortlsserver). Enforces `serverAuth` EKU and optional DNS/IP identity matching.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:401](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L401)

Validation time. Defaults to `new Date()`.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:395](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L395)

Intermediate CA certificates.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:393](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L393)

End-entity certificate to verify.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:391](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L391)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:389](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L389)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:397](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L397)

Trusted root CA certificates.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### serviceIdentity?

> `readonly` `optional` **serviceIdentity**: [`VerifyServiceIdentityInput`](#verifyserviceidentityinput)

Defined in: [verify/verify.ts:403](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L403)

DNS/IP identity to match against the leaf's SAN.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:399](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L399)

Bare trust anchors.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### VerifiedCertificateChain

Defined in: [verify/verify.ts:334](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L334)

Fully verified certificate chain returned on success from [`verifyCertificateChain`](#verifycertificatechain).

#### Properties

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:338](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L338)

Full chain in leaf-to-root order.

##### leaf

> `readonly` **leaf**: [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [verify/verify.ts:336](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L336)

Parsed end-entity certificate.

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](#policyvalidationoutcome)

Defined in: [verify/verify.ts:342](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L342)

Final RFC 5280 §6 / RFC 9618 constrained policy outputs for this validated path.

##### root

> `readonly` **root**: [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [verify/verify.ts:340](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L340)

Trusted root that terminates the path.

---

### VerifyCertificateChainInput

Defined in: [verify/verify.ts:308](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L308)

Input for [`verifyCertificateChain`](#verifycertificatechain). Combines path-building, validation, and identity options.

#### Extends

- [`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### allowSelfSignedLeaf?

> `readonly` `optional` **allowSelfSignedLeaf**: `boolean`

Defined in: [verify/verify.ts:330](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L330)

When `true`, allows a self-signed leaf. Defaults to `false`.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:324](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L324)

Validation time. Defaults to `new Date()`.

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:318](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L318)

Intermediate CA certificates available for path building.

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:316](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L316)

End-entity certificate to verify.

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:314](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L314)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](x509.md#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:312](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L312)

Nested policy validation overrides.

##### purpose?

> `readonly` `optional` **purpose**: [`VerifyPurpose`](#verifypurpose)

Defined in: [verify/verify.ts:326](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L326)

Leaf purpose constraint to enforce during validation.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:320](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L320)

Trusted root CA certificates.

##### serviceIdentity?

> `readonly` `optional` **serviceIdentity**: [`VerifyServiceIdentityInput`](#verifyserviceidentityinput)

Defined in: [verify/verify.ts:328](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L328)

DNS/IP/URI/SRV identity to match against the leaf's SAN.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:322](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L322)

Bare trust anchors to try when no root certificate matches.

---

### VerifyChainFailure

Defined in: [verify/verify.ts:215](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L215)

A chain verification failure with its error code, human message, chain index, and diagnostic details.

#### Extends

- [`IndexedMicro509Error`](result.md#indexedmicro509error)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails)\>

#### Properties

##### code

> `readonly` **code**: [`VerifyErrorCode`](#verifyerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`IndexedMicro509Error`](result.md#indexedmicro509error).[`code`](result.md#code-2)

##### details?

> `readonly` `optional` **details**: [`VerifyFailureDetails`](#verifyfailuredetails)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`IndexedMicro509Error`](result.md#indexedmicro509error).[`details`](result.md#details-2)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L70)

Zero-based position of the failing item in the input collection.

###### Inherited from

[`IndexedMicro509Error`](result.md#indexedmicro509error).[`index`](result.md#index-1)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`IndexedMicro509Error`](result.md#indexedmicro509error).[`message`](result.md#message-2)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:218](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L218)

Always `false` for failures.

---

### VerifyFailureDetails

Defined in: [verify/verify.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L193)

Diagnostic context attached to every [`VerifyChainFailure`](#verifychainfailure). All fields are optional; presence depends on the error code.

#### Properties

##### actual?

> `readonly` `optional` **actual**: `string`

Defined in: [verify/verify.ts:201](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L201)

The value actually found.

##### chainCommonNames?

> `readonly` `optional` **chainCommonNames**: readonly `string`[]

Defined in: [verify/verify.ts:203](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L203)

CNs of every certificate in the chain, leaf-first. Present on `no_trusted_root`.

##### commonNameFallbackReason?

> `readonly` `optional` **commonNameFallbackReason**: `"disabled"` \| `"suppressed_by_presented_identifier"` \| `"common_name_missing"` \| `"common_name_mismatch"`

Defined in: [verify/verify.ts:207](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L207)

Why the CN-fallback path was not taken. Set on `common_name_fallback_suppressed`.

##### expected?

> `readonly` `optional` **expected**: `string`

Defined in: [verify/verify.ts:199](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L199)

The value the verifier expected (e.g. a validity window bound or SKI).

##### issuerCommonName?

> `readonly` `optional` **issuerCommonName**: `string`

Defined in: [verify/verify.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L197)

CN of the issuer of the offending certificate.

##### presentedIdentifierTypes?

> `readonly` `optional` **presentedIdentifierTypes**: readonly (`"uri"` \| `"dns"` \| `"srv"`)[]

Defined in: [verify/verify.ts:205](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L205)

SAN identifier types the leaf actually presents. Set on identity-match failures.

##### subjectCommonName?

> `readonly` `optional` **subjectCommonName**: `string`

Defined in: [verify/verify.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L195)

CN of the certificate that triggered the failure.

---

### VerifyRequestFailure

Defined in: [verify/verify.ts:358](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L358)

Failure from [`verifyCertificateSigningRequest`](#verifycertificatesigningrequest).

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"signature_invalid"` \| `"unsupported_signature_algorithm_parameters"`, [`VerifyFailureDetails`](#verifyfailuredetails)\>

#### Properties

##### code

> `readonly` **code**: `"unsupported_signature_algorithm_parameters"` \| `"signature_invalid"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: [`VerifyFailureDetails`](#verifyfailuredetails)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:364](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L364)

Always `false` for failures.

## Type Aliases

### BuildCandidatePathResult

> **BuildCandidatePathResult** = \{ `ok`: `true`; `value`: [`CandidatePath`](#candidatepath); \} \| [`IndexedErrorResult`](result.md#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:250](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L250)

Result of [`buildCandidatePath`](#buildcandidatepath). On success, contains the [`CandidatePath`](#candidatepath).

---

### CertificateSource

> **CertificateSource** = `string` \| `Uint8Array`

Defined in: [verify/verify.ts:77](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L77)

PEM string or DER bytes for a certificate. PEM may contain multiple blocks.

---

### CsrSource

> **CsrSource** = `string` \| `Uint8Array`

Defined in: [verify/verify.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L79)

PEM string or DER bytes for a certificate signing request.

---

### EkuCheckPurpose

> **EkuCheckPurpose** = `"serverAuth"` \| `"clientAuth"` \| `"codeSigning"` \| `"emailProtection"` \| `"timeStamping"` \| `"ocspSigning"`

Defined in: [verify/verify.ts:89](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L89)

Extended key usage purpose checked by [`checkExtendedKeyUsage`](#checkextendedkeyusage).

---

### EkuCheckResult

> **EkuCheckResult** = \{ `ok`: `true`; `value`: `undefined`; \} \| [`IndexedErrorResult`](result.md#indexederrorresult)\<`"leaf_eku_missing"` \| `"intermediate_eku_constraint"`, `Record`\<`never`, `never`\>, [`EkuCheckFailure`](#ekucheckfailure)\>

Defined in: [verify/verify.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L98)

Result of [`checkExtendedKeyUsage`](#checkextendedkeyusage). Success carries no value; failure identifies the offending certificate.

---

### MatchableServiceIdentityInput

> **MatchableServiceIdentityInput** = [`ServiceIdentityInput`](#serviceidentityinput)

Defined in: [verify/identity.ts:64](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L64)

Alias for the full identity union accepted by matching functions.

---

### MatchServiceIdentityErrorCode

> **MatchServiceIdentityErrorCode** = `"subject_alt_name_mismatch"` \| `"common_name_fallback_suppressed"` \| `"service_identity_service_mismatch"` \| `"service_identity_type_unsupported"`

Defined in: [verify/identity.ts:69](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L69)

Discriminant codes for identity-matching failures.

---

### MatchServiceIdentityEvaluation

> **MatchServiceIdentityEvaluation** = [`Result`](result.md#result)\<`void`, [`MatchServiceIdentityFailure`](#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L125)

Void-valued result type used internally during identity evaluation.

---

### MatchServiceIdentityFailureResult

> **MatchServiceIdentityFailureResult** = [`ErrorResult`](result.md#errorresult)\<[`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](#matchserviceidentityfailuredetails-1), [`MatchServiceIdentityFailure`](#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:109](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L109)

Failure branch of [`MatchServiceIdentityResult`](#matchserviceidentityresult) with structured error details.

---

### MatchServiceIdentityResult

> **MatchServiceIdentityResult** = [`MatchServiceIdentitySuccess`](#matchserviceidentitysuccess) \| [`ErrorResult`](result.md#errorresult)\<[`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](#matchserviceidentityfailuredetails-1), [`MatchServiceIdentityFailure`](#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:116](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L116)

Result of matching a reference identifier against a certificate's presented identifiers.

---

### ServiceIdentityInput

> **ServiceIdentityInput** = [`DnsServiceIdentityInput`](#dnsserviceidentityinput) \| [`IpServiceIdentityInput`](#ipserviceidentityinput) \| [`UriServiceIdentityInput`](#uriserviceidentityinput) \| [`SrvServiceIdentityInput`](#srvserviceidentityinput)

Defined in: [verify/identity.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L55)

Discriminated union of all supported reference identifier types.

---

### ServiceIdentityType

> **ServiceIdentityType** = [`ServiceIdentityInput`](#serviceidentityinput)\[`"type"`\]

Defined in: [verify/identity.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L62)

The `type` discriminant values of [`ServiceIdentityInput`](#serviceidentityinput).

---

### ValidateCandidatePathResult

> **ValidateCandidatePathResult** = \{ `ok`: `true`; `policyValidation`: [`PolicyValidationOutcome`](#policyvalidationoutcome); `value`: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess); \} \| [`IndexedErrorResult`](result.md#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:294](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L294)

Result of [`validateCandidatePath`](#validatecandidatepath).

#### Type Declaration

\{ `ok`: `true`; `policyValidation`: [`PolicyValidationOutcome`](#policyvalidationoutcome); `value`: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess); \}

##### ok

> `readonly` **ok**: `true`

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](#policyvalidationoutcome)

Shorthand duplicate of `value.policyValidation` for internal forwarding.

##### value

> `readonly` **value**: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess)

[`IndexedErrorResult`](result.md#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

---

### VerifyChainResult

> **VerifyChainResult** = \{ `ok`: `true`; `value`: [`VerifiedCertificateChain`](#verifiedcertificatechain); \} \| [`IndexedErrorResult`](result.md#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:346](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L346)

Result of [`verifyCertificateChain`](#verifycertificatechain). On success, contains the [`VerifiedCertificateChain`](#verifiedcertificatechain).

---

### VerifyErrorCode

> **VerifyErrorCode** = `"no_trusted_root"` \| `"issuer_not_found"` \| `"signature_invalid"` \| `"certificate_expired"` \| `"ca_required"` \| `"key_cert_sign_required"` \| `"path_length_exceeded"` \| `"authority_key_identifier_mismatch"` \| `"extended_key_usage_invalid"` \| `"subject_alt_name_mismatch"` \| `"common_name_fallback_suppressed"` \| `"self_signed_leaf_not_allowed"` \| `"unrecognized_critical_extension"` \| `"intermediate_eku_constraint"` \| `"policy_processing_not_implemented"` \| `"explicit_policy_required"` \| `"initial_policy_set_not_satisfied"` \| `"initial_name_constraints_not_implemented"` \| `"unsupported_name_constraints"` \| `"name_constraints_violated"` \| `"unsupported_signature_algorithm_parameters"`

Defined in: [verify/verify.ts:169](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L169)

Discriminant for every failure a verify operation can produce.

- `no_trusted_root` — chain could not be anchored to any root or [`TrustAnchor`](#trustanchor).
- `issuer_not_found` — an intermediate's issuer was not in the candidate set.
- `signature_invalid` — a certificate's signature failed cryptographic verification.
- `certificate_expired` — a certificate's notBefore/notAfter window excludes the validation time.
- `ca_required` — an issuer lacks `basicConstraints.ca = true`.
- `key_cert_sign_required` — an issuer has keyUsage but omits `keyCertSign`.
- `path_length_exceeded` — the number of CA certificates below an issuer exceeds its pathLength.
- `authority_key_identifier_mismatch` — a certificate's AKI does not match the issuer's SKI.
- `extended_key_usage_invalid` — the leaf certificate lacks the required EKU for the requested purpose.
- `subject_alt_name_mismatch` — no SAN entry matches the requested service identity.
- `common_name_fallback_suppressed` — CN fallback was attempted but suppressed (SAN present or disabled).
- `self_signed_leaf_not_allowed` — the leaf is self-signed and `allowSelfSignedLeaf` was not set.
- `unrecognized_critical_extension` — a certificate contains a critical extension the verifier cannot process.
- `intermediate_eku_constraint` — an intermediate CA's EKU set does not include the required purpose.
- `policy_processing_not_implemented` — policy processing encountered an unsupported construct.
- `explicit_policy_required` — `requireExplicitPolicy` was set but no acceptable policy was found.
- `initial_policy_set_not_satisfied` — the chain's policies do not intersect `initialPolicySet`.
- `initial_name_constraints_not_implemented` — caller-supplied initial name constraints are unsupported.
- `unsupported_name_constraints` — a certificate's nameConstraints use an unsupported form.
- `name_constraints_violated` — a subject name violates a permitted/excluded subtree.
- `unsupported_signature_algorithm_parameters` — the signature algorithm uses unrecognized parameters.

---

### VerifyPurpose

> **VerifyPurpose** = `"serverAuth"` \| `"clientAuth"` \| `"ca"`

Defined in: [verify/verify.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L86)

High-level purpose applied during path validation to enforce leaf constraints.

---

### VerifyRequestResult

> **VerifyRequestResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateSigningRequest`](x509.md#parsedcertificatesigningrequest); \} \| [`ErrorResult`](result.md#errorresult)\<`"signature_invalid"` \| `"unsupported_signature_algorithm_parameters"`, [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyRequestFailure`](#verifyrequestfailure)\>

Defined in: [verify/verify.ts:368](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L368)

Result of [`verifyCertificateSigningRequest`](#verifycertificatesigningrequest). On success, contains the parsed CSR.

---

### VerifyServiceIdentityInput

> **VerifyServiceIdentityInput** = [`DnsServiceIdentityInput`](#dnsserviceidentityinput) \| [`IpServiceIdentityInput`](#ipserviceidentityinput)

Defined in: [verify/identity.ts:66](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L66)

Subset of identities usable for TLS server verification (DNS and IP only).

## Functions

### buildCandidatePath()

> **buildCandidatePath**(`input`): `Promise`\<[`BuildCandidatePathResult`](#buildcandidatepathresult)\>

Defined in: [verify/verify.ts:612](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L612)

Builds a signature-verified path from a leaf certificate to a trusted root.

Parses the supplied certificates, walks the issuer chain, signature-checks
each link, and returns the first valid path. Does not enforce time, constraints,
or leaf purpose — call [`validateCandidatePath`](#validatecandidatepath) or use the all-in-one
[`verifyCertificateChain`](#verifycertificatechain) for full validation.

#### Parameters

##### input

[`BuildCandidatePathInput`](#buildcandidatepathinput)

#### Returns

`Promise`\<[`BuildCandidatePathResult`](#buildcandidatepathresult)\>

#### Example

```ts
import { buildCandidatePath } from 'micro509';

const result = await buildCandidatePath({
  leaf: leafPem,
  intermediates: [intermediatePem],
  roots: [rootPem],
});
if (result.ok) {
  console.log('path length:', result.value.chain.length);
}
```

---

### checkExtendedKeyUsage()

> **checkExtendedKeyUsage**(`chain`, `purpose`): [`EkuCheckResult`](#ekucheckresult)

Defined in: [verify/verify.ts:967](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L967)

Standalone EKU check against a verified certificate chain.
Validates that the leaf has the requested purpose and that
intermediate CA EKU constraints (if present) permit it.

#### Parameters

##### chain

readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

##### purpose

[`EkuCheckPurpose`](#ekucheckpurpose)

#### Returns

[`EkuCheckResult`](#ekucheckresult)

#### Example

```ts
import { checkExtendedKeyUsage } from 'micro509';

const result = checkExtendedKeyUsage(chain, 'serverAuth');
if (!result.ok) {
  console.error(result.error.code, result.error.message);
}
```

---

### matchCertificateServiceIdentity()

> **matchCertificateServiceIdentity**(`certificate`, `serviceIdentity`): [`MatchServiceIdentityResult`](#matchserviceidentityresult)

Defined in: [verify/identity.ts:177](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L177)

Compares a reference identifier against a certificate's SAN entries.

Supports DNS (with wildcard matching), IP, URI-ID, and SRV-ID.
For DNS, optionally falls back to subject CN when no SAN of a supported type is present.

#### Parameters

##### certificate

[`ParsedCertificate`](x509.md#parsedcertificate)

##### serviceIdentity

[`ServiceIdentityInput`](#serviceidentityinput)

#### Returns

[`MatchServiceIdentityResult`](#matchserviceidentityresult)

#### Examples

```ts
const result = matchCertificateServiceIdentity(parsed, {
  type: 'ip',
  value: '192.168.1.1',
});
```

```ts
const result = matchCertificateServiceIdentity(parsed, {
  type: 'dns',
  value: 'mail.example.com',
  allowCommonNameFallback: true,
});
```

---

### matchServiceIdentity()

> **matchServiceIdentity**(`input`): [`MatchServiceIdentityResult`](#matchserviceidentityresult)

Defined in: [verify/identity.ts:150](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L150)

Checks whether a certificate covers the requested service identity.

Delegates to [`matchCertificateServiceIdentity`](#matchcertificateserviceidentity) — this overload
accepts a single options object.

#### Parameters

##### input

[`MatchServiceIdentityInput`](#matchserviceidentityinput)

#### Returns

[`MatchServiceIdentityResult`](#matchserviceidentityresult)

#### Example

```ts
const result = matchServiceIdentity({
  certificate: parsed,
  serviceIdentity: { type: 'dns', value: 'example.com' },
});
if (!result.ok) console.error(result.error.message);
```

---

### trustAnchorFromCertificate()

> **trustAnchorFromCertificate**(`certificate`): [`TrustAnchor`](#trustanchor)

Defined in: [verify/verify.ts:1006](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1006)

Extracts a [`TrustAnchor`](#trustanchor) from a parsed certificate, copying the subject, SPKI, and key identifiers.

#### Parameters

##### certificate

[`ParsedCertificate`](x509.md#parsedcertificate)

#### Returns

[`TrustAnchor`](#trustanchor)

---

### validateCandidatePath()

> **validateCandidatePath**(`input`): `Promise`\<[`ValidateCandidatePathResult`](#validatecandidatepathresult)\>

Defined in: [verify/verify.ts:807](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L807)

Validates a pre-built certificate chain for time, constraints, policy, and
optionally leaf purpose. Wrap the result of [`buildCandidatePath`](#buildcandidatepath).

#### Parameters

##### input

[`ValidateCandidatePathInput`](#validatecandidatepathinput)

#### Returns

`Promise`\<[`ValidateCandidatePathResult`](#validatecandidatepathresult)\>

---

### validateForCa()

> **validateForCa**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:1134](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1134)

Validates a certificate chain for CA use:
chain verification + `basicConstraints.ca` check on the leaf.

#### Parameters

##### input

[`ValidateForCaInput`](#validateforcainput)

#### Returns

`Promise`\<[`VerifyChainResult`](#verifychainresult)\>

#### Example

```ts
import { validateForCa } from 'micro509';

const result = await validateForCa({
  leaf: intermediateCertPem,
  roots: [rootCaPem],
});
```

---

### validateForCodeSigning()

> **validateForCodeSigning**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:1114](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1114)

Validates a certificate chain for code signing:
chain verification + `codeSigning` EKU (leaf + intermediate propagation).

#### Parameters

##### input

[`ValidateForCodeSigningInput`](#validateforcodesigninginput)

#### Returns

`Promise`\<[`VerifyChainResult`](#verifychainresult)\>

#### Example

```ts
import { validateForCodeSigning } from 'micro509';

const result = await validateForCodeSigning({
  leaf: codeSigningCertPem,
  roots: [rootCaPem],
});
```

---

### validateForTlsClient()

> **validateForTlsClient**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:1094](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1094)

Validates a certificate chain for TLS client use:
chain verification + `clientAuth` EKU (leaf + intermediate propagation).

#### Parameters

##### input

[`ValidateForTlsClientInput`](#validatefortlsclientinput)

#### Returns

`Promise`\<[`VerifyChainResult`](#verifychainresult)\>

#### Example

```ts
import { validateForTlsClient } from 'micro509';

const result = await validateForTlsClient({
  leaf: clientCertPem,
  roots: [rootCaPem],
});
```

---

### validateForTlsServer()

> **validateForTlsServer**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:1064](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1064)

Validates a certificate chain for TLS server use:
chain verification + `serverAuth` EKU (leaf + intermediate propagation)

- DNS/IP identity matching.

#### Parameters

##### input

[`ValidateForTlsServerInput`](#validatefortlsserverinput)

#### Returns

`Promise`\<[`VerifyChainResult`](#verifychainresult)\>

#### Example

```ts
import { validateForTlsServer } from 'micro509';

const result = await validateForTlsServer({
  leaf: serverCertPem,
  roots: [rootCaPem],
  serviceIdentity: { type: 'dns', value: 'example.com' },
});
if (result.ok) {
  console.log(
    'valid for',
    result.value.leaf.subject.values.commonName,
  );
}
```

---

### verifyCertificateChain()

> **verifyCertificateChain**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:843](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L843)

All-in-one certificate chain verification: builds a candidate path then
validates time, constraints, policy, purpose, and optional service identity.

Equivalent to calling [`buildCandidatePath`](#buildcandidatepath) followed by
[`validateCandidatePath`](#validatecandidatepath) (plus identity matching when configured).

#### Parameters

##### input

[`VerifyCertificateChainInput`](#verifycertificatechaininput)

#### Returns

`Promise`\<[`VerifyChainResult`](#verifychainresult)\>

#### Example

```ts
import { verifyCertificateChain } from 'micro509';

const result = await verifyCertificateChain({
  leaf: serverCertPem,
  intermediates: [intermediatePem],
  roots: [rootCaPem],
  purpose: 'serverAuth',
  serviceIdentity: { type: 'dns', value: 'example.com' },
});
if (!result.ok) {
  console.error(result.error.code, result.error.message);
}
```

---

### verifyCertificateSigningRequest()

> **verifyCertificateSigningRequest**(`input`): `Promise`\<[`VerifyRequestResult`](#verifyrequestresult)\>

Defined in: [verify/verify.ts:912](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L912)

Verifies the self-signature of a PKCS#10 certificate signing request.

Parses the CSR from PEM or DER, then checks that its signature is valid
against its own embedded public key.

#### Parameters

##### input

[`CsrSource`](#csrsource)

#### Returns

`Promise`\<[`VerifyRequestResult`](#verifyrequestresult)\>

#### Example

```ts
import { verifyCertificateSigningRequest } from 'micro509';

const result =
  await verifyCertificateSigningRequest(csrPem);
if (result.ok) {
  console.log(
    'subject:',
    result.value.subject.values.commonName,
  );
}
```
