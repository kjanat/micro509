[micro509](modules.md) / revocation

# revocation

Canonical revocation domain surface.
Owns CRL, OCSP, and revocation orchestration APIs.

## Interfaces

### CertificateRevocationListMaterial

Defined in: [revocation/crl.ts:145](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L145)

Encoded CRL in multiple serialisation formats, returned by [`createCertificateRevocationList`](#createcertificaterevocationlist).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/crl.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L151)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/crl.ts:147](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L147)

Raw DER bytes of the signed CRL.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/crl.ts:149](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L149)

PEM-encoded CRL (`-----BEGIN X509 CRL-----`).

---

### CheckCertificateRevocationAgainstCrlFailure

Defined in: [revocation/crl.ts:345](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L345)

Failure detail for [`checkCertificateRevocationAgainstCrl`](#checkcertificaterevocationagainstcrl).

#### Extends

- [`Micro509Error`](result.md#micro509error)\<[`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode), [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1)\>

#### Properties

##### code

> `readonly` **code**: [`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1)

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

Defined in: [revocation/crl.ts:351](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L351)

Always `false` for failures.

---

### CheckCertificateRevocationAgainstCrlFailureDetails

Defined in: [revocation/crl.ts:339](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L339)

Structured details attached to a [`CheckCertificateRevocationAgainstCrlFailure`](#checkcertificaterevocationagainstcrlfailure).

#### Properties

##### reason?

> `readonly` `optional` **reason**: [`CrlApplicabilityFailureReason`](#crlapplicabilityfailurereason)

Defined in: [revocation/crl.ts:341](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L341)

Why the CRL was non-applicable, when the error code is `non_applicable`.

---

### CheckCertificateRevocationAgainstCrlGoodValue

Defined in: [revocation/crl.ts:355](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L355)

Success value when the certificate is not found in the CRL.

#### Properties

##### crl

> `readonly` **crl**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:359](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L359)

The validated CRL that was checked.

##### status

> `readonly` **status**: `"good"`

Defined in: [revocation/crl.ts:357](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L357)

Certificate is not revoked.

---

### CheckCertificateRevocationAgainstCrlInput

Defined in: [revocation/crl.ts:292](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L292)

Input for [`checkCertificateRevocationAgainstCrl`](#checkcertificaterevocationagainstcrl).

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/crl.ts:302](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L302)

Evaluation time. Defaults to `new Date()`.

##### certificate

> `readonly` **certificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:294](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L294)

Certificate whose revocation status to check.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/crl.ts:304](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L304)

Clock-skew tolerance in milliseconds for freshness checks.

##### crl

> `readonly` **crl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:298](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L298)

Complete (base) CRL to check against.

##### deltaCrl?

> `readonly` `optional` **deltaCrl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:300](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L300)

Optional delta CRL for more recent revocation information.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:296](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L296)

Issuer of `certificate` — also expected signer of the CRL.

---

### CheckCertificateRevocationAgainstCrlRevokedValue

Defined in: [revocation/crl.ts:363](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L363)

Success value when the certificate is found as revoked in the CRL.

#### Properties

##### crl

> `readonly` **crl**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:367](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L367)

The validated CRL that contained the revocation entry.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:371](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L371)

CRLReason from the entry, if present.

##### revocationDate

> `readonly` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:369](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L369)

When the CA declared this certificate revoked.

##### status

> `readonly` **status**: `"revoked"`

Defined in: [revocation/crl.ts:365](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L365)

Certificate is revoked.

---

### CheckCertificateRevocationFailureDetails

Defined in: [revocation/revocation.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L131)

Diagnostic details attached to an `unknown` revocation result.

#### Properties

##### checkedSources

> `readonly` **checkedSources**: readonly [`RevocationEvidenceKind`](#revocationevidencekind)[]

Defined in: [revocation/revocation.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L133)

Which evidence kinds were attempted (`'crl'`, `'ocsp'`, or both).

##### indeterminateEvidence

> `readonly` **indeterminateEvidence**: readonly [`RevocationIndeterminateEvidence`](#revocationindeterminateevidence)[]

Defined in: [revocation/revocation.ts:135](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L135)

Per-evidence explanations of why no definitive answer was reached.

---

### CheckCertificateRevocationInput

Defined in: [revocation/revocation.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L83)

Input for [`checkCertificateRevocation`](#checkcertificaterevocation).

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/revocation.ts:91](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L91)

Evaluation time. Defaults to `new Date()`.

##### certificate

> `readonly` **certificate**: [`RevocationCertificateSource`](#revocationcertificatesource)

Defined in: [revocation/revocation.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L85)

Certificate whose revocation status to determine.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/revocation.ts:93](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L93)

Clock-skew tolerance in milliseconds.

##### evidence?

> `readonly` `optional` **evidence**: readonly [`RevocationEvidenceInput`](#revocationevidenceinput)[]

Defined in: [revocation/revocation.ts:89](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L89)

CRL and/or OCSP evidence to evaluate. Returns `unknown` if empty.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`RevocationCertificateSource`](#revocationcertificatesource)

Defined in: [revocation/revocation.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L87)

Issuer of `certificate`.

---

### ConfiguredOcspResponder

Defined in: [revocation/revocation.ts:32](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L32)

A manually-configured OCSP responder endpoint.

#### Properties

##### responderCertificate?

> `readonly` `optional` **responderCertificate**: [`ConfiguredOcspResponderCertificate`](#configuredocsprespondercertificate)

Defined in: [revocation/revocation.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L36)

Known responder certificate — skips embedded-certificate discovery.

##### uri

> `readonly` **uri**: `string`

Defined in: [revocation/revocation.ts:34](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L34)

OCSP responder URI (typically `http://...`).

---

### CreateCertificateRevocationListInput

Defined in: [revocation/crl.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L119)

Input for [`createCertificateRevocationList`](#createcertificaterevocationlist).

#### Properties

##### baseCrlNumber?

> `readonly` `optional` **baseCrlNumber**: `number`

Defined in: [revocation/crl.ts:135](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L135)

If set, marks this CRL as a delta CRL referencing the given base CRL number.

##### crlNumber?

> `readonly` `optional` **crlNumber**: `number`

Defined in: [revocation/crl.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L133)

Monotonically-increasing CRL sequence number (CRLNumber extension).

##### freshestCrlDistributionPoints?

> `readonly` `optional` **freshestCrlDistributionPoints**: readonly [`DistributionPoint`](x509.md#distributionpoint-6)[]

Defined in: [revocation/crl.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L139)

Freshest CRL distribution points — tells relying parties where to find delta CRLs.

##### issuer

> `readonly` **issuer**: [`NameInput`](x509.md#nameinput)

Defined in: [revocation/crl.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L121)

Distinguished name of the CRL issuer (typically the signing CA).

##### issuerPublicKey?

> `readonly` `optional` **issuerPublicKey**: `CryptoKey`

Defined in: [revocation/crl.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L125)

Issuer public key — used to embed an Authority Key Identifier extension.

##### issuingDistributionPoint?

> `readonly` `optional` **issuingDistributionPoint**: [`IssuingDistributionPoint`](x509.md#issuingdistributionpoint)

Defined in: [revocation/crl.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L137)

Issuing distribution point extension — scopes this CRL to a subset of certificates.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/crl.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L129)

Planned next issuance. Omit for an open-ended CRL.

##### revokedCertificates?

> `readonly` `optional` **revokedCertificates**: readonly [`RevokedCertificateInput`](#revokedcertificateinput)[]

Defined in: [revocation/crl.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L131)

Certificates to list as revoked in this CRL.

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [revocation/crl.ts:123](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L123)

Private key used to sign the CRL. Algorithm is inferred from the key.

##### thisUpdate?

> `readonly` `optional` **thisUpdate**: `Date`

Defined in: [revocation/crl.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L127)

Issuance timestamp. Defaults to `new Date()`.

---

### CreateOcspRequestInput

Defined in: [revocation/ocsp.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L81)

Input for [`createOcspRequest`](#createocsprequest).

#### Properties

##### hashAlgorithm?

> `readonly` `optional` **hashAlgorithm**: [`OcspHashAlgorithm`](#ocsphashalgorithm)

Defined in: [revocation/ocsp.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L85)

Hash algorithm for CertID computation. Defaults to `'SHA-1'`.

##### nonce?

> `readonly` `optional` **nonce**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L87)

Random nonce for replay protection. Omit to skip the nonce extension.

##### requests

> `readonly` **requests**: readonly [`CreateOcspRequestItemInput`](#createocsprequestiteminput)[]

Defined in: [revocation/ocsp.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L83)

One or more certificates to query (batched into a single OCSP request).

---

### CreateOcspRequestItemInput

Defined in: [revocation/ocsp.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L71)

One certificate whose status to query in an OCSP request.
Used as an element of [`CreateOcspRequestInput.requests`](#requests).

#### Extended by

- [`CreateOcspSingleResponseInput`](#createocspsingleresponseinput)

#### Properties

##### certificate

> `readonly` **certificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:73](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L73)

Certificate whose revocation status is being queried.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L75)

Issuer of `certificate` — needed to compute the CertID hash.

---

### CreateOcspResponseInput

Defined in: [revocation/ocsp.ts:222](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L222)

Input for [`createOcspResponse`](#createocspresponse).

#### Properties

##### hashAlgorithm?

> `readonly` `optional` **hashAlgorithm**: [`OcspHashAlgorithm`](#ocsphashalgorithm)

Defined in: [revocation/ocsp.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L234)

Hash algorithm for CertID computation. Defaults to `'SHA-1'`.

##### includedCertificates?

> `readonly` `optional` **includedCertificates**: readonly [`OcspCertificateSource`](#ocspcertificatesource)[]

Defined in: [revocation/ocsp.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L236)

Extra certificates to embed in the response (e.g. the responder's issuer chain).

##### nonce?

> `readonly` `optional` **nonce**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:232](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L232)

Nonce to echo back for replay protection.

##### producedAt?

> `readonly` `optional` **producedAt**: `Date`

Defined in: [revocation/ocsp.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L230)

Timestamp for the `producedAt` field. Defaults to `new Date()`.

##### responses

> `readonly` **responses**: readonly [`CreateOcspSingleResponseInput`](#createocspsingleresponseinput)[]

Defined in: [revocation/ocsp.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L228)

Per-certificate status entries to include in the BasicOCSPResponse.

##### signerCertificate

> `readonly` **signerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:226](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L226)

Certificate of the OCSP responder — used to build the responder ID (by key hash).

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [revocation/ocsp.ts:224](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L224)

Private key used to sign the response. Algorithm is inferred from the key.

---

### CreateOcspSingleResponseInput

Defined in: [revocation/ocsp.ts:206](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L206)

One certificate's status entry for [`CreateOcspResponseInput.responses`](#responses).
Extends [`CreateOcspRequestItemInput`](#createocsprequestiteminput) with status and timing fields.

#### Extends

- [`CreateOcspRequestItemInput`](#createocsprequestiteminput)

#### Properties

##### certificate

> `readonly` **certificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:73](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L73)

Certificate whose revocation status is being queried.

###### Inherited from

[`CreateOcspRequestItemInput`](#createocsprequestiteminput).[`certificate`](#certificate-2)

##### certStatus

> `readonly` **certStatus**: [`OcspCertStatus`](#ocspcertstatus)

Defined in: [revocation/ocsp.ts:208](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L208)

Status to assert for this certificate.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L75)

Issuer of `certificate` — needed to compute the CertID hash.

###### Inherited from

[`CreateOcspRequestItemInput`](#createocsprequestiteminput).[`issuerCertificate`](#issuercertificate-2)

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/ocsp.ts:212](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L212)

End of the validity window. Omit for open-ended assertions.

##### revocationReasonCode?

> `readonly` `optional` **revocationReasonCode**: `number`

Defined in: [revocation/ocsp.ts:216](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L216)

CRLReason integer code (only meaningful when `certStatus` is `'revoked'`).

##### revokedAt?

> `readonly` `optional` **revokedAt**: `Date`

Defined in: [revocation/ocsp.ts:214](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L214)

Revocation time (required when `certStatus` is `'revoked'`). Defaults to `thisUpdate`.

##### thisUpdate?

> `readonly` `optional` **thisUpdate**: `Date`

Defined in: [revocation/ocsp.ts:210](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L210)

Start of the validity window for this status assertion. Defaults to `new Date()`.

---

### OcspRequestMaterial

Defined in: [revocation/ocsp.ts:93](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L93)

Encoded OCSP request in multiple serialisation formats, returned by [`createOcspRequest`](#createocsprequest).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/ocsp.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L99)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/ocsp.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L95)

Raw DER bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/ocsp.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L97)

PEM-encoded request (`-----BEGIN OCSP REQUEST-----`).

---

### OcspResponderCandidate

Defined in: [revocation/revocation.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L40)

One candidate OCSP responder resolved by [`resolveOcspResponderCandidates`](#resolveocsprespondercandidates).

#### Properties

##### responderCertificate?

> `readonly` `optional` **responderCertificate**: [`ConfiguredOcspResponderCertificate`](#configuredocsprespondercertificate)

Defined in: [revocation/revocation.ts:46](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L46)

Pre-known responder certificate, if available.

##### source

> `readonly` **source**: [`OcspResponderSource`](#ocsprespondersource)

Defined in: [revocation/revocation.ts:42](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L42)

Whether this candidate came from configuration or the certificate's AIA extension.

##### uri

> `readonly` **uri**: `string`

Defined in: [revocation/revocation.ts:44](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L44)

OCSP responder URI.

---

### OcspResponseMaterial

Defined in: [revocation/ocsp.ts:242](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L242)

Encoded OCSP response in multiple serialisation formats, returned by [`createOcspResponse`](#createocspresponse).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/ocsp.ts:248](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L248)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/ocsp.ts:244](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L244)

Raw DER bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/ocsp.ts:246](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L246)

PEM-encoded response (`-----BEGIN OCSP RESPONSE-----`).

---

### ParsedCertificateRevocationList

Defined in: [revocation/crl.ts:174](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L174)

Decoded X.509 CRL, returned by [`parseCertificateRevocationListDer`](#parsecertificaterevocationlistder)
and [`parseCertificateRevocationListPem`](#parsecertificaterevocationlistpem).

#### Properties

##### authorityKeyIdentifier?

> `readonly` `optional` **authorityKeyIdentifier**: `string`

Defined in: [revocation/crl.ts:194](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L194)

Hex-encoded Authority Key Identifier, if the extension is present.

##### baseCrlNumber?

> `readonly` `optional` **baseCrlNumber**: `number`

Defined in: [revocation/crl.ts:198](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L198)

Delta CRL indicator — present only on delta CRLs, referencing the base CRL number.

##### crlNumber?

> `readonly` `optional` **crlNumber**: `number`

Defined in: [revocation/crl.ts:196](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L196)

CRLNumber extension value — monotonically increasing sequence number.

##### freshestCrlDistributionPoints?

> `readonly` `optional` **freshestCrlDistributionPoints**: readonly [`ParsedDistributionPoint`](x509.md#parseddistributionpoint)[]

Defined in: [revocation/crl.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L202)

Freshest CRL extension — points to delta CRL locations.

##### issuer

> `readonly` **issuer**: [`ParsedName`](x509.md#parsedname)

Defined in: [revocation/crl.ts:182](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L182)

CRL issuer distinguished name.

##### issuerPublicKeyAlgorithmOid?

> `readonly` `optional` **issuerPublicKeyAlgorithmOid**: `string`

Defined in: [revocation/crl.ts:190](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L190)

OID of the issuer's public key algorithm, when available.

##### issuerPublicKeyParametersOid?

> `readonly` `optional` **issuerPublicKeyParametersOid**: `string`

Defined in: [revocation/crl.ts:192](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L192)

OID of the issuer's public key parameters (e.g. named curve), when available.

##### issuingDistributionPoint?

> `readonly` `optional` **issuingDistributionPoint**: [`ParsedIssuingDistributionPoint`](x509.md#parsedissuingdistributionpoint)

Defined in: [revocation/crl.ts:200](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L200)

Issuing distribution point extension — scopes this CRL to a certificate subset.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/crl.ts:186](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L186)

End of the CRL validity window. Absent if the CA does not commit to a schedule.

##### revokedCertificates

> `readonly` **revokedCertificates**: readonly [`ParsedRevokedCertificate`](#parsedrevokedcertificate)[]

Defined in: [revocation/crl.ts:204](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L204)

All revoked certificate entries (empty array if none).

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [revocation/crl.ts:188](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L188)

OID of the algorithm used to sign this CRL.

##### signatureValue

> `readonly` **signatureValue**: `Uint8Array`

Defined in: [revocation/crl.ts:180](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L180)

Raw signature bytes from the CRL outer wrapper.

##### tbsCertListDer

> `readonly` **tbsCertListDer**: `Uint8Array`

Defined in: [revocation/crl.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L178)

DER-encoded TBSCertList — the signed payload for signature verification.

##### thisUpdate

> `readonly` **thisUpdate**: `Date`

Defined in: [revocation/crl.ts:184](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L184)

Start of the CRL validity window.

##### version

> `readonly` **version**: `number`

Defined in: [revocation/crl.ts:176](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L176)

CRL version (1 = v1, 2 = v2 with extensions).

---

### ParsedOcspCertId

Defined in: [revocation/ocsp.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L106)

Decoded OCSP CertID — identifies a certificate by hashed issuer name,
hashed issuer key, and serial number.

#### Properties

##### hashAlgorithmOid

> `readonly` **hashAlgorithmOid**: `string`

Defined in: [revocation/ocsp.ts:108](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L108)

OID of the hash algorithm used for the name and key hashes.

##### issuerKeyHashHex

> `readonly` **issuerKeyHashHex**: `string`

Defined in: [revocation/ocsp.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L112)

Hex-encoded hash of the issuer's SubjectPublicKey BIT STRING content.

##### issuerNameHashHex

> `readonly` **issuerNameHashHex**: `string`

Defined in: [revocation/ocsp.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L110)

Hex-encoded hash of the issuer's distinguished name DER.

##### serialNumberHex

> `readonly` **serialNumberHex**: `string`

Defined in: [revocation/ocsp.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L114)

Hex-encoded serial number of the certificate.

---

### ParsedOcspRequest

Defined in: [revocation/ocsp.ts:120](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L120)

Decoded OCSP request, returned by [`parseOcspRequestDer`](#parseocsprequestder) / [`parseOcspRequestPem`](#parseocsprequestpem).

#### Properties

##### nonce?

> `readonly` `optional` **nonce**: `string`

Defined in: [revocation/ocsp.ts:124](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L124)

Hex-encoded nonce extension value, if present.

##### requests

> `readonly` **requests**: readonly [`ParsedOcspCertId`](#parsedocspcertid)[]

Defined in: [revocation/ocsp.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L122)

CertIDs of the certificates being queried.

---

### ParsedOcspResponse

Defined in: [revocation/ocsp.ts:179](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L179)

Decoded OCSP response, returned by [`parseOcspResponseDer`](#parseocspresponseder) / [`parseOcspResponsePem`](#parseocspresponsepem).

When `responseStatus` is not `'successful'`, most fields are absent.

#### Properties

##### certificates?

> `readonly` `optional` **certificates**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [revocation/ocsp.ts:199](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L199)

Certificates embedded in the response (typically the responder's chain).

##### nonce?

> `readonly` `optional` **nonce**: `string`

Defined in: [revocation/ocsp.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L197)

Hex-encoded nonce, if the response echoed one.

##### producedAt?

> `readonly` `optional` **producedAt**: `Date`

Defined in: [revocation/ocsp.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L193)

Timestamp when the responder produced this response.

##### responderId?

> `readonly` `optional` **responderId**: [`ParsedOcspResponderId`](#parsedocspresponderid)

Defined in: [revocation/ocsp.ts:187](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L187)

How the responder identifies itself.

##### responseDataDer?

> `readonly` `optional` **responseDataDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:185](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L185)

DER-encoded ResponseData — the signed payload for signature verification.

##### responses?

> `readonly` `optional` **responses**: readonly [`ParsedOcspSingleResponse`](#parsedocspsingleresponse)[]

Defined in: [revocation/ocsp.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L195)

Per-certificate status entries.

##### responseStatus

> `readonly` **responseStatus**: [`OcspResponseStatus`](#ocspresponsestatus)

Defined in: [revocation/ocsp.ts:181](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L181)

Overall response status. Only `'successful'` carries a BasicOCSPResponse body.

##### responseTypeOid?

> `readonly` `optional` **responseTypeOid**: `string`

Defined in: [revocation/ocsp.ts:183](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L183)

OID of the response type (normally `id-pkix-ocsp-basic`).

##### signatureAlgorithmOid?

> `readonly` `optional` **signatureAlgorithmOid**: `string`

Defined in: [revocation/ocsp.ts:189](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L189)

OID of the algorithm used to sign this response.

##### signatureValue?

> `readonly` `optional` **signatureValue**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:191](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L191)

Raw signature bytes.

---

### ParsedOcspSingleResponse

Defined in: [revocation/ocsp.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L141)

Status of one certificate inside an OCSP BasicResponse.

#### Properties

##### certId

> `readonly` **certId**: [`ParsedOcspCertId`](#parsedocspcertid)

Defined in: [revocation/ocsp.ts:143](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L143)

Which certificate this status applies to.

##### certStatus

> `readonly` **certStatus**: [`OcspCertStatus`](#ocspcertstatus)

Defined in: [revocation/ocsp.ts:145](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L145)

Responder's verdict: `good`, `revoked`, or `unknown`.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/ocsp.ts:149](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L149)

End of the validity window. Absent if the responder does not commit to a schedule.

##### revocationReasonCode?

> `readonly` `optional` **revocationReasonCode**: `number`

Defined in: [revocation/ocsp.ts:153](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L153)

CRLReason integer (only for `certStatus === 'revoked'`).

##### revokedAt?

> `readonly` `optional` **revokedAt**: `Date`

Defined in: [revocation/ocsp.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L151)

When the certificate was revoked (only for `certStatus === 'revoked'`).

##### thisUpdate

> `readonly` **thisUpdate**: `Date`

Defined in: [revocation/ocsp.ts:147](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L147)

Start of the validity window for this status assertion.

---

### ParsedRevokedCertificate

Defined in: [revocation/crl.ts:157](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L157)

A single revoked-certificate entry decoded from a CRL.

#### Properties

##### certificateIssuer?

> `readonly` `optional` **certificateIssuer**: readonly [`SubjectAltName`](x509.md#subjectaltname)[]

Defined in: [revocation/crl.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L167)

Indirect-CRL certificate issuer override (RFC 5280 §5.3.3).

##### invalidityDate?

> `readonly` `optional` **invalidityDate**: `Date`

Defined in: [revocation/crl.ts:165](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L165)

When the key or certificate actually became suspect, if present.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:163](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L163)

RFC 5280 CRLReason, if the entry carries one.

##### revocationDate

> `readonly` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:161](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L161)

When the CA declared this certificate revoked.

##### serialNumberHex

> `readonly` **serialNumberHex**: `string`

Defined in: [revocation/crl.ts:159](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L159)

Hex-encoded serial number of the revoked certificate.

---

### ResolveOcspResponderCandidatesInput

Defined in: [revocation/revocation.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L50)

Input for [`resolveOcspResponderCandidates`](#resolveocsprespondercandidates).

#### Properties

##### certificate

> `readonly` **certificate**: [`RevocationCertificateSource`](#revocationcertificatesource)

Defined in: [revocation/revocation.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L52)

Certificate whose AIA extension will be inspected for OCSP URIs.

##### configuredResponders?

> `readonly` `optional` **configuredResponders**: readonly [`ConfiguredOcspResponder`](#configuredocspresponder)[]

Defined in: [revocation/revocation.ts:54](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L54)

Manually-configured responders — checked before AIA-derived ones.

---

### RevocationCheckGoodValue

Defined in: [revocation/revocation.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L151)

Certificate is not revoked according to the checked evidence.

#### Properties

##### message

> `readonly` **message**: `string`

Defined in: [revocation/revocation.ts:157](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L157)

Human-readable diagnostic message.

##### source

> `readonly` **source**: [`RevocationEvidenceKind`](#revocationevidencekind)

Defined in: [revocation/revocation.ts:155](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L155)

Which evidence kind confirmed the good status.

##### status

> `readonly` **status**: `"good"`

Defined in: [revocation/revocation.ts:153](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L153)

Certificate is not revoked.

---

### RevocationCheckRevokedValue

Defined in: [revocation/revocation.ts:161](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L161)

Certificate is revoked according to the checked evidence.

#### Properties

##### message

> `readonly` **message**: `string`

Defined in: [revocation/revocation.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L167)

Human-readable diagnostic message.

##### revocationReason?

> `readonly` `optional` **revocationReason**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/revocation.ts:171](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L171)

CRL reason string (from CRL evidence).

##### revocationReasonCode?

> `readonly` `optional` **revocationReasonCode**: `number`

Defined in: [revocation/revocation.ts:173](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L173)

CRL reason integer code (from OCSP evidence).

##### revokedAt?

> `readonly` `optional` **revokedAt**: `Date`

Defined in: [revocation/revocation.ts:169](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L169)

When the certificate was revoked (from CRL entry or OCSP response).

##### source

> `readonly` **source**: [`RevocationEvidenceKind`](#revocationevidencekind)

Defined in: [revocation/revocation.ts:165](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L165)

Which evidence kind reported the revocation.

##### status

> `readonly` **status**: `"revoked"`

Defined in: [revocation/revocation.ts:163](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L163)

Certificate is revoked.

---

### RevocationCheckUnknownValue

Defined in: [revocation/revocation.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L139)

Revocation status could not be determined from the provided evidence.

#### Properties

##### code

> `readonly` **code**: [`CheckCertificateRevocationErrorCode`](#checkcertificaterevocationerrorcode)

Defined in: [revocation/revocation.ts:143](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L143)

Why revocation status is unknown.

##### details

> `readonly` **details**: [`CheckCertificateRevocationFailureDetails`](#checkcertificaterevocationfailuredetails)

Defined in: [revocation/revocation.ts:147](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L147)

What evidence was attempted and why each failed.

##### message

> `readonly` **message**: `string`

Defined in: [revocation/revocation.ts:145](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L145)

Human-readable diagnostic message.

##### status

> `readonly` **status**: `"unknown"`

Defined in: [revocation/revocation.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L141)

Status is indeterminate.

---

### RevocationCrlEvidenceInput

Defined in: [revocation/revocation.ts:58](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L58)

CRL-based revocation evidence for [`CheckCertificateRevocationInput.evidence`](#evidence).

#### Properties

##### crl

> `readonly` **crl**: [`CrlSource`](#crlsource)

Defined in: [revocation/revocation.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L62)

Complete (base) CRL.

##### deltaCrl?

> `readonly` `optional` **deltaCrl**: [`CrlSource`](#crlsource)

Defined in: [revocation/revocation.ts:64](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L64)

Optional delta CRL for more recent revocation information.

##### kind

> `readonly` **kind**: `"crl"`

Defined in: [revocation/revocation.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L60)

Discriminator for the CRL evidence variant.

---

### RevocationIndeterminateEvidence

Defined in: [revocation/revocation.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L119)

One piece of evidence that failed to produce a definitive revocation answer.

#### Properties

##### code

> `readonly` **code**: [`RevocationIndeterminateReasonCode`](#revocationindeterminatereasoncode)

Defined in: [revocation/revocation.ts:123](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L123)

Machine-readable reason code.

##### message

> `readonly` **message**: `string`

Defined in: [revocation/revocation.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L125)

Human-readable explanation.

##### reason?

> `readonly` `optional` **reason**: [`CrlApplicabilityFailureReason`](#crlapplicabilityfailurereason)

Defined in: [revocation/revocation.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L127)

CRL-specific applicability failure reason, when `source` is `'crl'`.

##### source

> `readonly` **source**: [`RevocationEvidenceKind`](#revocationevidencekind)

Defined in: [revocation/revocation.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L121)

Whether this evidence was CRL or OCSP.

---

### RevocationOcspEvidenceInput

Defined in: [revocation/revocation.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L68)

OCSP-based revocation evidence for [`CheckCertificateRevocationInput.evidence`](#evidence).

#### Properties

##### kind

> `readonly` **kind**: `"ocsp"`

Defined in: [revocation/revocation.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L70)

Discriminator for the OCSP evidence variant.

##### request?

> `readonly` `optional` **request**: [`OcspRequestSource`](#ocsprequestsource)

Defined in: [revocation/revocation.ts:74](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L74)

Original OCSP request — enables nonce and coverage checks.

##### responderCertificate?

> `readonly` `optional` **responderCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/revocation.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L76)

Explicit responder certificate — overrides embedded certificate discovery.

##### response

> `readonly` **response**: `string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`ParsedOcspResponse`](#parsedocspresponse)

Defined in: [revocation/revocation.ts:72](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L72)

OCSP response to validate.

---

### RevokedCertificateInput

Defined in: [revocation/crl.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L88)

Single revoked certificate entry for [`createCertificateRevocationList`](#createcertificaterevocationlist).

#### Properties

##### invalidityDate?

> `readonly` `optional` **invalidityDate**: `Date`

Defined in: [revocation/crl.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L96)

When the key or certificate became suspect — may predate `revocationDate`.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L94)

RFC 5280 CRLReason code. Omit for `unspecified`.

##### revocationDate?

> `readonly` `optional` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L92)

When the certificate was revoked. Defaults to `thisUpdate` of the CRL.

##### serialNumber

> `readonly` **serialNumber**: `Uint8Array`

Defined in: [revocation/crl.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L90)

DER-encoded certificate serial number to revoke.

---

### ValidateCertificateRevocationListFailure

Defined in: [revocation/crl.ts:264](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L264)

Failure detail for [`validateCertificateRevocationList`](#validatecertificaterevocationlist).

Possible codes: `signature_invalid`, `issuer_mismatch`, `stale_crl`, `crl_sign_not_permitted`.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`

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

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/crl.ts:269](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L269)

Always `false` for failures.

---

### ValidateCertificateRevocationListInput

Defined in: [revocation/crl.ts:248](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L248)

Input for [`validateCertificateRevocationList`](#validatecertificaterevocationlist).

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/crl.ts:254](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L254)

Evaluation time for freshness checks. Defaults to `new Date()`.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/crl.ts:256](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L256)

Tolerance in milliseconds for clock skew when checking `thisUpdate`/`nextUpdate`.

##### crl

> `readonly` **crl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:250](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L250)

The CRL to validate.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:252](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L252)

Certificate of the CA that should have signed the CRL.

---

### ValidateOcspResponseFailure

Defined in: [revocation/ocsp.ts:298](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L298)

Failure detail for [`validateOcspResponse`](#validateocspresponse).

Possible codes: `response_status_invalid`, `signature_invalid`,
`responder_id_mismatch`, `nonce_mismatch`, `request_mismatch`,
`issuer_mismatch`, `responder_chain_invalid`, `ocsp_signing_missing`,
`stale_response`.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"` \| `"issuer_mismatch"` \| `"response_status_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`

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

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/ocsp.ts:311](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L311)

Always `false` for failures.

---

### ValidateOcspResponseInput

Defined in: [revocation/ocsp.ts:273](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L273)

Input for [`validateOcspResponse`](#validateocspresponse).

#### Properties

##### allowChainedResponderCertificate?

> `readonly` `optional` **allowChainedResponderCertificate**: `boolean`

Defined in: [revocation/ocsp.ts:283](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L283)

When `true`, allows delegated responder chain validation beyond direct issuance.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/ocsp.ts:285](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L285)

Evaluation time for freshness checks. Defaults to `new Date()`.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/ocsp.ts:287](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L287)

Clock-skew tolerance in milliseconds for `thisUpdate`/`nextUpdate`/`producedAt`.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:277](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L277)

Certificate of the CA that issued the target certificate.

##### request?

> `readonly` `optional` **request**: [`OcspRequestSource`](#ocsprequestsource)

Defined in: [revocation/ocsp.ts:279](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L279)

Original request — enables nonce and request-coverage checks.

##### responderCertificate?

> `readonly` `optional` **responderCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:281](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L281)

Explicit responder certificate — overrides embedded certificate discovery.

##### response

> `readonly` **response**: `string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`ParsedOcspResponse`](#parsedocspresponse)

Defined in: [revocation/ocsp.ts:275](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L275)

The OCSP response to validate.

---

### VerifyCertificateRevocationListFailure

Defined in: [revocation/crl.ts:227](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L227)

Failure detail when CRL signature verification fails.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"signature_invalid"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"`

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

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/crl.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L229)

Always `false` for failures.

---

### VerifyOcspResponseFailure

Defined in: [revocation/ocsp.ts:252](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L252)

Failure detail when OCSP response signature verification fails.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"signature_invalid"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"`

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

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/ocsp.ts:254](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L254)

Always `false` for failures.

## Type Aliases

### CheckCertificateRevocationAgainstCrlErrorCode

> **CheckCertificateRevocationAgainstCrlErrorCode** = `"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"` \| `"non_applicable"`

Defined in: [revocation/crl.ts:308](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L308)

Error codes that [`checkCertificateRevocationAgainstCrl`](#checkcertificaterevocationagainstcrl) may return.

---

### CheckCertificateRevocationAgainstCrlResult

> **CheckCertificateRevocationAgainstCrlResult** = \{ `ok`: `true`; `value`: [`CheckCertificateRevocationAgainstCrlValue`](#checkcertificaterevocationagainstcrlvalue); \} \| [`ErrorResult`](result.md#errorresult)\<[`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode), [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1), [`CheckCertificateRevocationAgainstCrlFailure`](#checkcertificaterevocationagainstcrlfailure)\>

Defined in: [revocation/crl.ts:385](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L385)

Result of [`checkCertificateRevocationAgainstCrl`](#checkcertificaterevocationagainstcrl).

On success `value.status` is `'good'` or `'revoked'`.
On failure the CRL could not be validated or was non-applicable.

---

### CheckCertificateRevocationAgainstCrlValue

> **CheckCertificateRevocationAgainstCrlValue** = [`CheckCertificateRevocationAgainstCrlGoodValue`](#checkcertificaterevocationagainstcrlgoodvalue) \| [`CheckCertificateRevocationAgainstCrlRevokedValue`](#checkcertificaterevocationagainstcrlrevokedvalue)

Defined in: [revocation/crl.ts:375](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L375)

Discriminated union of `good` and `revoked` outcomes.

---

### CheckCertificateRevocationErrorCode

> **CheckCertificateRevocationErrorCode** = `"revocation_evidence_missing"` \| `"revocation_status_unknown"`

Defined in: [revocation/revocation.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L97)

Error codes that [`checkCertificateRevocation`](#checkcertificaterevocation) may surface inside an `unknown` result.

---

### CheckCertificateRevocationResult

> **CheckCertificateRevocationResult** = [`Result`](result.md#result)\<[`CheckCertificateRevocationValue`](#checkcertificaterevocationvalue), `never`\>

Defined in: [revocation/revocation.ts:186](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L186)

Result of [`checkCertificateRevocation`](#checkcertificaterevocation). Always succeeds (`ok: true`) —
the `value.status` discriminator carries the actual outcome.

---

### CheckCertificateRevocationValue

> **CheckCertificateRevocationValue** = [`RevocationCheckGoodValue`](#revocationcheckgoodvalue) \| [`RevocationCheckRevokedValue`](#revocationcheckrevokedvalue) \| [`RevocationCheckUnknownValue`](#revocationcheckunknownvalue)

Defined in: [revocation/revocation.ts:177](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L177)

Discriminated union of `good`, `revoked`, and `unknown` revocation outcomes.

---

### ConfiguredOcspResponderCertificate

> **ConfiguredOcspResponderCertificate** = `string` \| `Uint8Array`

Defined in: [revocation/revocation.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L29)

PEM or DER bytes of a pre-configured OCSP responder certificate.

---

### CrlApplicabilityFailureReason

> **CrlApplicabilityFailureReason** = `"certificate_scope_mismatch"` \| `"delta_crl_incompatible"` \| `"delta_crl_unsupported"` \| `"distribution_point_mismatch"` \| `"indirect_crl_unsupported"` \| `"issuer_mismatch"` \| `"reasons_mismatch"`

Defined in: [revocation/crl.ts:316](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L316)

Structured reason why a CRL was deemed non-applicable to a given certificate.

---

### CrlCertificateSource

> **CrlCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [revocation/crl.ts:224](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L224)

PEM string, DER bytes, or already-parsed certificate.

---

### CrlSource

> **CrlSource** = `string` \| `Uint8Array` \| [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:222](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L222)

PEM string, DER bytes, or already-parsed CRL.

---

### OcspCertificateSource

> **OcspCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [revocation/ocsp.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L63)

PEM string, DER bytes, or already-parsed certificate.

---

### OcspCertStatus

> **OcspCertStatus** = `"good"` \| `"revoked"` \| `"unknown"`

Defined in: [revocation/ocsp.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L128)

RFC 6960 certificate status reported by the responder for a single CertID.

---

### OcspHashAlgorithm

> **OcspHashAlgorithm** = `"SHA-1"` \| `"SHA-256"`

Defined in: [revocation/ocsp.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L61)

Hash algorithm used to compute OCSP CertID fields. SHA-1 is the RFC 6960 default.

---

### OcspRequestSource

> **OcspRequestSource** = `string` \| `Uint8Array` \| [`ParsedOcspRequest`](#parsedocsprequest)

Defined in: [revocation/ocsp.ts:65](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L65)

PEM string, DER bytes, or already-parsed OCSP request.

---

### OcspResponderSource

> **OcspResponderSource** = `"configured"` \| `"authorityInfoAccess"`

Defined in: [revocation/revocation.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L27)

Where the OCSP responder URI came from.

---

### OcspResponseStatus

> **OcspResponseStatus** = `"successful"` \| `"malformedRequest"` \| `"internalError"` \| `"tryLater"` \| `"sigRequired"` \| `"unauthorized"`

Defined in: [revocation/ocsp.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L130)

RFC 6960 overall response status — anything other than `'successful'` means the response body is absent or unusable.

---

### ParsedOcspResponderId

> **ParsedOcspResponderId** = \{ `name`: [`ParsedName`](x509.md#parsedname); `type`: `"byName"`; \} \| \{ `keyHashHex`: `string`; `type`: `"byKeyHash"`; \}

Defined in: [revocation/ocsp.ts:160](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L160)

How the OCSP responder identifies itself — either by distinguished name or
by SHA-1 hash of its public key.

#### Type Declaration

\{ `name`: [`ParsedName`](x509.md#parsedname); `type`: `"byName"`; \}

##### name

> `readonly` **name**: [`ParsedName`](x509.md#parsedname)

Parsed distinguished name of the responder.

##### type

> `readonly` **type**: `"byName"`

Responder identified by its certificate subject name.

\{ `keyHashHex`: `string`; `type`: `"byKeyHash"`; \}

##### keyHashHex

> `readonly` **keyHashHex**: `string`

Hex-encoded SHA-1 hash of the responder's SubjectPublicKey content.

##### type

> `readonly` **type**: `"byKeyHash"`

Responder identified by public-key hash.

---

### RevocationCertificateSource

> **RevocationCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](x509.md#parsedcertificate)

Defined in: [revocation/revocation.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L25)

PEM string, DER bytes, or already-parsed certificate.

---

### RevocationEvidenceInput

> **RevocationEvidenceInput** = [`RevocationCrlEvidenceInput`](#revocationcrlevidenceinput) \| [`RevocationOcspEvidenceInput`](#revocationocspevidenceinput)

Defined in: [revocation/revocation.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L80)

Discriminated union of CRL and OCSP evidence inputs.

---

### RevocationEvidenceKind

> **RevocationEvidenceKind** = `"crl"` \| `"ocsp"`

Defined in: [revocation/revocation.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L23)

Which revocation mechanism produced the evidence.

---

### RevocationIndeterminateReasonCode

> **RevocationIndeterminateReasonCode** = `"certificate_status_missing"` \| `"certificate_status_unknown"` \| `"crl_sign_not_permitted"` \| `"issuer_mismatch"` \| `"non_applicable"` \| `"nonce_mismatch"` \| `"ocsp_signing_missing"` \| `"request_mismatch"` \| `"responder_id_mismatch"` \| `"responder_chain_invalid"` \| `"response_status_invalid"` \| `"signature_invalid"` \| `"stale_crl"` \| `"stale_response"`

Defined in: [revocation/revocation.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L102)

Why a particular piece of evidence could not produce a definitive `good`/`revoked` answer.

---

### RevocationReason

> **RevocationReason** = `"unspecified"` \| `"keyCompromise"` \| `"cACompromise"` \| `"affiliationChanged"` \| `"superseded"` \| `"cessationOfOperation"` \| `"certificateHold"` \| `"removeFromCRL"` \| `"privilegeWithdrawn"` \| `"aACompromise"`

Defined in: [revocation/crl.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L104)

RFC 5280 §5.3.1 CRLReason code values.

`removeFromCRL` is used in delta CRLs to un-hold a certificate.

---

### RevocationStatus

> **RevocationStatus** = `"good"` \| `"revoked"` \| `"unknown"`

Defined in: [revocation/revocation.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L20)

Unified revocation outcome across CRL and OCSP evidence.

---

### ValidateCertificateRevocationListResult

> **ValidateCertificateRevocationListResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \} \| [`ErrorResult`](result.md#errorresult)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`, `Record`\<`never`, `never`\>, [`ValidateCertificateRevocationListFailure`](#validatecertificaterevocationlistfailure)\>

Defined in: [revocation/crl.ts:277](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L277)

Result of [`validateCertificateRevocationList`](#validatecertificaterevocationlist).

On success, the CRL has passed signature, issuer, key-usage, and freshness checks.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Validated and parsed CRL.

[`ErrorResult`](result.md#errorresult)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`, `Record`\<`never`, `never`\>, [`ValidateCertificateRevocationListFailure`](#validatecertificaterevocationlistfailure)\>

---

### ValidateOcspResponseResult

> **ValidateOcspResponseResult** = \{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \} \| [`ErrorResult`](result.md#errorresult)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`, `Record`\<`never`, `never`\>, [`ValidateOcspResponseFailure`](#validateocspresponsefailure)\>

Defined in: [revocation/ocsp.ts:320](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L320)

Result of [`validateOcspResponse`](#validateocspresponse).

On success, the response has passed status, signature, responder binding,
freshness, nonce, and request-coverage checks.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedOcspResponse`](#parsedocspresponse)

Fully validated OCSP response.

[`ErrorResult`](result.md#errorresult)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`, `Record`\<`never`, `never`\>, [`ValidateOcspResponseFailure`](#validateocspresponsefailure)\>

---

### VerifyCertificateRevocationListResult

> **VerifyCertificateRevocationListResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \} \| [`ErrorResult`](result.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyCertificateRevocationListFailure`](#verifycertificaterevocationlistfailure)\>

Defined in: [revocation/crl.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L237)

Result of [`verifyCertificateRevocationList`](#verifycertificaterevocationlist).

On success, `value` is the parsed CRL whose signature has been verified.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Parsed CRL with a verified signature.

[`ErrorResult`](result.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyCertificateRevocationListFailure`](#verifycertificaterevocationlistfailure)\>

---

### VerifyOcspResponseResult

> **VerifyOcspResponseResult** = \{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \} \| [`ErrorResult`](result.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyOcspResponseFailure`](#verifyocspresponsefailure)\>

Defined in: [revocation/ocsp.ts:262](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L262)

Result of [`verifyOcspResponse`](#verifyocspresponse).

On success, `value` is the parsed response whose signature has been verified.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedOcspResponse`](#parsedocspresponse)

Parsed response with a verified signature.

[`ErrorResult`](result.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyOcspResponseFailure`](#verifyocspresponsefailure)\>

## Functions

### checkCertificateRevocation()

> **checkCertificateRevocation**(`input`): `Promise`\<[`CheckCertificateRevocationResult`](#checkcertificaterevocationresult)\>

Defined in: [revocation/revocation.ts:273](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L273)

Evaluates all provided CRL and OCSP evidence to determine the certificate's
revocation status. Returns the first `revoked` if any, else the first `good`,
else `unknown` with diagnostic details about each indeterminate evidence.

#### Parameters

##### input

[`CheckCertificateRevocationInput`](#checkcertificaterevocationinput)

#### Returns

`Promise`\<[`CheckCertificateRevocationResult`](#checkcertificaterevocationresult)\>

#### Example

```ts
import { checkCertificateRevocation } from 'micro509';

const result = await checkCertificateRevocation({
  certificate: leafPem,
  issuerCertificate: caPem,
  evidence: [{ kind: 'crl', crl: crlPem }],
});
if (result.ok && result.value.status === 'revoked') {
  console.log('revoked at', result.value.revokedAt);
}
```

---

### checkCertificateRevocationAgainstCrl()

> **checkCertificateRevocationAgainstCrl**(`input`): `Promise`\<[`CheckCertificateRevocationAgainstCrlResult`](#checkcertificaterevocationagainstcrlresult)\>

Defined in: [revocation/crl.ts:695](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L695)

End-to-end revocation check: validates the CRL (and optional delta CRL),
verifies applicability via distribution-point and scope matching, then
resolves the certificate's revocation status.

Returns `good` if the serial is absent, `revoked` with date/reason if present,
or an error if the CRL cannot be validated or is non-applicable.

#### Parameters

##### input

[`CheckCertificateRevocationAgainstCrlInput`](#checkcertificaterevocationagainstcrlinput)

#### Returns

`Promise`\<[`CheckCertificateRevocationAgainstCrlResult`](#checkcertificaterevocationagainstcrlresult)\>

#### Example

```ts
import { checkCertificateRevocationAgainstCrl } from 'micro509';

const result = await checkCertificateRevocationAgainstCrl({
  certificate: leafPem,
  issuerCertificate: caPem,
  crl: crlPem,
});
if (result.ok && result.value.status === 'revoked') {
  console.log('revoked on', result.value.revocationDate);
}
```

---

### createCertificateRevocationList()

> **createCertificateRevocationList**(`input`): `Promise`\<[`CertificateRevocationListMaterial`](#certificaterevocationlistmaterial)\>

Defined in: [revocation/crl.ts:420](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L420)

Signs and encodes an X.509 v2 CRL.

Embeds Authority Key Identifier, CRLNumber, delta CRL indicator,
issuing distribution point, and freshest-CRL extensions as configured.

#### Parameters

##### input

[`CreateCertificateRevocationListInput`](#createcertificaterevocationlistinput)

#### Returns

`Promise`\<[`CertificateRevocationListMaterial`](#certificaterevocationlistmaterial)\>

#### Example

```ts
import { createCertificateRevocationList } from 'micro509';

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Example CA' },
  signerPrivateKey: caPrivateKey,
  issuerPublicKey: caPublicKey,
  thisUpdate: new Date('2025-01-01'),
  nextUpdate: new Date('2025-02-01'),
  crlNumber: 42,
  revokedCertificates: [
    {
      serialNumber: revokedSerial,
      reasonCode: 'keyCompromise',
    },
  ],
});
// crl.pem, crl.der, crl.base64
```

---

### createOcspRequest()

> **createOcspRequest**(`input`): `Promise`\<[`OcspRequestMaterial`](#ocsprequestmaterial)\>

Defined in: [revocation/ocsp.ts:356](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L356)

Builds a DER-encoded OCSP request containing one or more CertID entries
and an optional nonce extension.

#### Parameters

##### input

[`CreateOcspRequestInput`](#createocsprequestinput)

#### Returns

`Promise`\<[`OcspRequestMaterial`](#ocsprequestmaterial)\>

#### Example

```ts
import { createOcspRequest } from 'micro509';

const req = await createOcspRequest({
  requests: [
    { certificate: leafPem, issuerCertificate: caPem },
  ],
  hashAlgorithm: 'SHA-256',
  nonce: crypto.getRandomValues(new Uint8Array(16)),
});
// POST req.der to the OCSP responder URI
```

---

### createOcspResponse()

> **createOcspResponse**(`input`): `Promise`\<[`OcspResponseMaterial`](#ocspresponsematerial)\>

Defined in: [revocation/ocsp.ts:523](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L523)

Signs and encodes an OCSP BasicResponse with a `successful` status.

The responder is identified by key hash (SHA-1 of the signer's SubjectPublicKey).
Use `includedCertificates` to embed the responder's chain for relying parties.

#### Parameters

##### input

[`CreateOcspResponseInput`](#createocspresponseinput)

#### Returns

`Promise`\<[`OcspResponseMaterial`](#ocspresponsematerial)\>

#### Example

```ts
import { createOcspResponse } from 'micro509';

const resp = await createOcspResponse({
  signerPrivateKey: responderPrivateKey,
  signerCertificate: responderCertPem,
  responses: [
    {
      certificate: leafPem,
      issuerCertificate: caPem,
      certStatus: 'good',
      thisUpdate: new Date('2025-01-01'),
      nextUpdate: new Date('2025-01-08'),
    },
  ],
  nonce: requestNonce,
});
// resp.der, resp.pem, resp.base64
```

---

### getCertificateOcspResponderUris()

> **getCertificateOcspResponderUris**(`certificate`): readonly `string`[]

Defined in: [revocation/revocation.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L195)

Extracts OCSP responder URIs from the certificate's Authority Information Access extension.

#### Parameters

##### certificate

[`RevocationCertificateSource`](#revocationcertificatesource)

#### Returns

readonly `string`[]

---

### isCertificateRevoked()

> **isCertificateRevoked**(`certificateSerialNumber`, `crl`): `boolean`

Defined in: [revocation/crl.ts:825](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L825)

Quick serial-number lookup — returns `true` if the serial appears in the
CRL's revoked entries. Does **not** validate the CRL or check applicability.

#### Parameters

##### certificateSerialNumber

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### crl

[`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

#### Returns

`boolean`

---

### parseCertificateRevocationListDer()

> **parseCertificateRevocationListDer**(`der`): [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:466](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L466)

Decodes a DER-encoded X.509 CRL into a structured [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist).

Does not verify the signature — call [`verifyCertificateRevocationList`](#verifycertificaterevocationlist) or
[`validateCertificateRevocationList`](#validatecertificaterevocationlist) for that.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

---

### parseCertificateRevocationListPem()

> **parseCertificateRevocationListPem**(`pem`): [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:573](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L573)

Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

#### Example

```ts
import { parseCertificateRevocationListPem } from 'micro509';

const crl = parseCertificateRevocationListPem(pemString);
console.log(
  crl.issuer.values.commonName,
  crl.revokedCertificates.length,
);
```

---

### parseOcspRequestDer()

> **parseOcspRequestDer**(`der`): [`ParsedOcspRequest`](#parsedocsprequest)

Defined in: [revocation/ocsp.ts:386](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L386)

Decodes a DER-encoded OCSP request into a structured [`ParsedOcspRequest`](#parsedocsprequest).

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedOcspRequest`](#parsedocsprequest)

---

### parseOcspRequestPem()

> **parseOcspRequestPem**(`pem`): [`ParsedOcspRequest`](#parsedocsprequest)

Defined in: [revocation/ocsp.ts:408](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L408)

Decodes a PEM-encoded OCSP request (`-----BEGIN OCSP REQUEST-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedOcspRequest`](#parsedocsprequest)

---

### parseOcspResponseDer()

> **parseOcspResponseDer**(`der`): [`ParsedOcspResponse`](#parsedocspresponse)

Defined in: [revocation/ocsp.ts:413](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L413)

Decodes a DER-encoded OCSP response into a structured [`ParsedOcspResponse`](#parsedocspresponse). Does not verify the signature.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedOcspResponse`](#parsedocspresponse)

---

### parseOcspResponsePem()

> **parseOcspResponsePem**(`pem`): [`ParsedOcspResponse`](#parsedocspresponse)

Defined in: [revocation/ocsp.ts:492](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L492)

Decodes a PEM-encoded OCSP response (`-----BEGIN OCSP RESPONSE-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedOcspResponse`](#parsedocspresponse)

#### Example

```ts
import { parseOcspResponsePem } from 'micro509';

const resp = parseOcspResponsePem(pemString);
if (resp.responseStatus === 'successful') {
  for (const entry of resp.responses ?? []) {
    console.log(
      entry.certId.serialNumberHex,
      entry.certStatus,
    );
  }
}
```

---

### resolveOcspResponderCandidates()

> **resolveOcspResponderCandidates**(`input`): readonly [`OcspResponderCandidate`](#ocsprespondercandidate)[]

Defined in: [revocation/revocation.ts:215](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L215)

Merges configured OCSP responders with those discovered from the certificate's
AIA extension. Configured responders take priority; duplicates are deduplicated by URI.

#### Parameters

##### input

[`ResolveOcspResponderCandidatesInput`](#resolveocsprespondercandidatesinput)

#### Returns

readonly [`OcspResponderCandidate`](#ocsprespondercandidate)[]

---

### validateCertificateRevocationList()

> **validateCertificateRevocationList**(`input`): `Promise`\<[`ValidateCertificateRevocationListResult`](#validatecertificaterevocationlistresult)\>

Defined in: [revocation/crl.ts:617](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L617)

Full CRL validation: issuer name match, authority key identifier match,
cRLSign key-usage check, signature verification, and `thisUpdate`/`nextUpdate`
freshness check (with optional clock-skew tolerance).

#### Parameters

##### input

[`ValidateCertificateRevocationListInput`](#validatecertificaterevocationlistinput)

#### Returns

`Promise`\<[`ValidateCertificateRevocationListResult`](#validatecertificaterevocationlistresult)\>

---

### validateOcspResponse()

> **validateOcspResponse**(`input`): `Promise`\<[`ValidateOcspResponseResult`](#validateocspresponseresult)\>

Defined in: [revocation/ocsp.ts:643](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L643)

Full OCSP response validation: response status check, signature verification,
responder ID binding (byName or byKeyHash), delegated-responder chain and
ocspSigning EKU checks, `producedAt`/`thisUpdate`/`nextUpdate` freshness,
nonce match, and request-coverage completeness.

#### Parameters

##### input

[`ValidateOcspResponseInput`](#validateocspresponseinput)

#### Returns

`Promise`\<[`ValidateOcspResponseResult`](#validateocspresponseresult)\>

#### Example

```ts
import { validateOcspResponse } from 'micro509';

const result = await validateOcspResponse({
  response: ocspResponseDer,
  issuerCertificate: caPem,
  request: ocspRequestDer,
});
if (result.ok) {
  const entry = result.value.responses?.[0];
  console.log(entry?.certStatus); // 'good' | 'revoked' | 'unknown'
}
```

---

### verifyCertificateRevocationList()

> **verifyCertificateRevocationList**(`crl`, `issuerCertificate`): `Promise`\<[`VerifyCertificateRevocationListResult`](#verifycertificaterevocationlistresult)\>

Defined in: [revocation/crl.ts:583](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L583)

Verifies the CRL signature against the issuer certificate's public key.

Does **not** check issuer name match, key-usage, or freshness — use
[`validateCertificateRevocationList`](#validatecertificaterevocationlist) for full validation.

#### Parameters

##### crl

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### issuerCertificate

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`VerifyCertificateRevocationListResult`](#verifycertificaterevocationlistresult)\>

---

### verifyOcspResponse()

> **verifyOcspResponse**(`response`, `signerCertificate`): `Promise`\<[`VerifyOcspResponseResult`](#verifyocspresponseresult)\>

Defined in: [revocation/ocsp.ts:592](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L592)

Verifies the OCSP response signature against the given signer certificate.

Does **not** check responder binding, freshness, or nonce — use
[`validateOcspResponse`](#validateocspresponse) for full validation.

#### Parameters

##### response

`string` | `Uint8Array`\<`ArrayBufferLike`\> | [`ParsedOcspResponse`](#parsedocspresponse)

##### signerCertificate

[`OcspCertificateSource`](#ocspcertificatesource)

#### Returns

`Promise`\<[`VerifyOcspResponseResult`](#verifyocspresponseresult)\>
