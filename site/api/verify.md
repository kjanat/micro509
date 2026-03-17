[micro509](modules.md) / verify

# verify

Canonical advanced verification domain surface.
Owns chain validation, service identity, policy, and name-constraint APIs.

## Interfaces

### ConstrainedPolicy

Defined in: [verify/policy.ts:33](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L33)

One policy OID that survives RFC 5280 / RFC 9618 processing.

#### Properties

##### policyIdentifier

> `readonly` **policyIdentifier**: `string`

Defined in: [verify/policy.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L35)

Dotted-decimal OID of the surviving policy.

##### policyQualifiers?

> `readonly` `optional` **policyQualifiers**: readonly [`PolicyQualifierInfo`](micro509.md#policyqualifierinfo)[]

Defined in: [verify/policy.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L37)

Qualifier info (CPS URIs, user notices) attached to this policy, if any.

---

### MatchServiceIdentityFailureDetails

Defined in: [verify/identity.ts:77](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L77)

Diagnostic context attached to an identity-matching failure.

#### Properties

##### actual?

> `readonly` `optional` **actual**: `string`

Defined in: [verify/identity.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L83)

Comma-joined presented identifiers (from SAN) that were compared.

##### commonNameFallbackReason?

> `readonly` `optional` **commonNameFallbackReason**: `"disabled"` \| `"suppressed_by_presented_identifier"` \| `"common_name_missing"` \| `"common_name_mismatch"`

Defined in: [verify/identity.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L87)

Explains why CN fallback was not used or failed.

##### expected?

> `readonly` `optional` **expected**: `string`

Defined in: [verify/identity.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L81)

The reference identifier the caller asked to verify.

##### presentedIdentifierTypes?

> `readonly` `optional` **presentedIdentifierTypes**: readonly (`"uri"` \| `"dns"` \| `"srv"`)[]

Defined in: [verify/identity.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L85)

SAN types that were present, relevant to CN-fallback suppression logic.

##### subjectCommonName?

> `readonly` `optional` **subjectCommonName**: `string`

Defined in: [verify/identity.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L79)

CN of the certificate that was being matched, if present.

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

Policies that also satisfy the caller's [`PolicyValidationInput.initialPolicySet`](micro509.md#initialpolicyset).

## Type Aliases

### MatchableServiceIdentityInput

> **MatchableServiceIdentityInput** = [`ServiceIdentityInput`](micro509.md#serviceidentityinput)

Defined in: [verify/identity.ts:65](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L65)

Alias for the full identity union accepted by matching functions.

---

### MatchServiceIdentityEvaluation

> **MatchServiceIdentityEvaluation** = [`Result`](micro509.md#result)\<`void`, [`MatchServiceIdentityFailure`](micro509.md#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:126](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L126)

Void-valued result type used internally during identity evaluation.

---

### MatchServiceIdentityFailureResult

> **MatchServiceIdentityFailureResult** = [`ErrorResult`](micro509.md#errorresult)\<[`MatchServiceIdentityErrorCode`](micro509.md#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](#matchserviceidentityfailuredetails), [`MatchServiceIdentityFailure`](micro509.md#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L110)

Failure branch of [`MatchServiceIdentityResult`](micro509.md#matchserviceidentityresult) with structured error details.
