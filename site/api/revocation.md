[micro509](modules.md) / revocation

# revocation

Canonical revocation domain surface.
Owns CRL, OCSP, and revocation orchestration APIs.

## Interfaces

### CertificateRevocationListMaterial

Defined in: [revocation/crl.ts:147](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L147)

Encoded CRL in multiple serialisation formats, returned by [`createCertificateRevocationList`](micro509.md#createcertificaterevocationlist).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/crl.ts:153](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L153)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/crl.ts:149](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L149)

Raw DER bytes of the signed CRL.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/crl.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L151)

PEM-encoded CRL (`-----BEGIN X509 CRL-----`).

---

### CheckCertificateRevocationAgainstCrlFailure

Defined in: [revocation/crl.ts:351](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L351)

Failure detail for [`checkCertificateRevocationAgainstCrl`](micro509.md#checkcertificaterevocationagainstcrl).

#### Extends

- [`Micro509Error`](micro509.md#micro509error)\<[`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode), [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1)\>

#### Properties

##### code

> `readonly` **code**: [`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`code`](micro509.md#code-5)

##### details?

> `readonly` `optional` **details**: [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`details`](micro509.md#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`message`](micro509.md#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/crl.ts:357](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L357)

Always `false` for failures.

---

### CheckCertificateRevocationAgainstCrlFailureDetails

Defined in: [revocation/crl.ts:345](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L345)

Structured details attached to a [`CheckCertificateRevocationAgainstCrlFailure`](#checkcertificaterevocationagainstcrlfailure).

#### Properties

##### reason?

> `readonly` `optional` **reason**: [`CrlApplicabilityFailureReason`](#crlapplicabilityfailurereason)

Defined in: [revocation/crl.ts:347](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L347)

Why the CRL was non-applicable, when the error code is `non_applicable`.

---

### CheckCertificateRevocationAgainstCrlGoodValue

Defined in: [revocation/crl.ts:361](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L361)

Success value when the certificate is not found in the CRL.

#### Properties

##### crl

> `readonly` **crl**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:365](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L365)

The validated CRL that was checked.

##### status

> `readonly` **status**: `"good"`

Defined in: [revocation/crl.ts:363](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L363)

Certificate is not revoked.

---

### CheckCertificateRevocationAgainstCrlInput

Defined in: [revocation/crl.ts:298](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L298)

Input for [`checkCertificateRevocationAgainstCrl`](micro509.md#checkcertificaterevocationagainstcrl).

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/crl.ts:308](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L308)

Evaluation time. Defaults to `new Date()`.

##### certificate

> `readonly` **certificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:300](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L300)

Certificate whose revocation status to check.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/crl.ts:310](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L310)

Clock-skew tolerance in milliseconds for freshness checks.

##### crl

> `readonly` **crl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:304](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L304)

Complete (base) CRL to check against.

##### deltaCrl?

> `readonly` `optional` **deltaCrl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:306](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L306)

Optional delta CRL for more recent revocation information.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:302](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L302)

Issuer of `certificate` — also expected signer of the CRL.

---

### CheckCertificateRevocationAgainstCrlRevokedValue

Defined in: [revocation/crl.ts:369](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L369)

Success value when the certificate is found as revoked in the CRL.

#### Properties

##### crl

> `readonly` **crl**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:373](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L373)

The validated CRL that contained the revocation entry.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:377](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L377)

CRLReason from the entry, if present.

##### revocationDate

> `readonly` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:375](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L375)

When the CA declared this certificate revoked.

##### status

> `readonly` **status**: `"revoked"`

Defined in: [revocation/crl.ts:371](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L371)

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

Input for [`checkCertificateRevocation`](micro509.md#checkcertificaterevocation).

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

Defined in: [revocation/crl.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L121)

Input for [`createCertificateRevocationList`](micro509.md#createcertificaterevocationlist).

#### Properties

##### baseCrlNumber?

> `readonly` `optional` **baseCrlNumber**: `number`

Defined in: [revocation/crl.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L137)

If set, marks this CRL as a delta CRL referencing the given base CRL number.

##### crlNumber?

> `readonly` `optional` **crlNumber**: `number`

Defined in: [revocation/crl.ts:135](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L135)

Monotonically-increasing CRL sequence number (CRLNumber extension).

##### freshestCrlDistributionPoints?

> `readonly` `optional` **freshestCrlDistributionPoints**: readonly [`DistributionPoint`](micro509.md#distributionpoint-2)[]

Defined in: [revocation/crl.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L141)

Freshest CRL distribution points — tells relying parties where to find delta CRLs.

##### issuer

> `readonly` **issuer**: [`NameInput`](micro509.md#nameinput)

Defined in: [revocation/crl.ts:123](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L123)

Distinguished name of the CRL issuer (typically the signing CA).

##### issuerPublicKey?

> `readonly` `optional` **issuerPublicKey**: `CryptoKey`

Defined in: [revocation/crl.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L127)

Issuer public key — used to embed an Authority Key Identifier extension.

##### issuingDistributionPoint?

> `readonly` `optional` **issuingDistributionPoint**: [`IssuingDistributionPoint`](micro509.md#issuingdistributionpoint)

Defined in: [revocation/crl.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L139)

Issuing distribution point extension — scopes this CRL to a subset of certificates.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/crl.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L131)

Planned next issuance. Omit for an open-ended CRL.

##### revokedCertificates?

> `readonly` `optional` **revokedCertificates**: readonly [`RevokedCertificateInput`](#revokedcertificateinput)[]

Defined in: [revocation/crl.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L133)

Certificates to list as revoked in this CRL.

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [revocation/crl.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L125)

Private key used to sign the CRL. Algorithm is inferred from the key.

##### thisUpdate?

> `readonly` `optional` **thisUpdate**: `Date`

Defined in: [revocation/crl.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L129)

Issuance timestamp. Defaults to `new Date()`.

---

### CreateOcspRequestInput

Defined in: [revocation/ocsp.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L87)

Input for [`createOcspRequest`](micro509.md#createocsprequest).

#### Properties

##### hashAlgorithm?

> `readonly` `optional` **hashAlgorithm**: [`OcspHashAlgorithm`](#ocsphashalgorithm)

Defined in: [revocation/ocsp.ts:91](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L91)

Hash algorithm for CertID computation. Defaults to `'SHA-1'`.

##### nonce?

> `readonly` `optional` **nonce**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:93](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L93)

Random nonce for replay protection. Omit to skip the nonce extension.

##### requests

> `readonly` **requests**: readonly [`CreateOcspRequestItemInput`](#createocsprequestiteminput)[]

Defined in: [revocation/ocsp.ts:89](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L89)

One or more certificates to query (batched into a single OCSP request).

---

### CreateOcspRequestItemInput

Defined in: [revocation/ocsp.ts:77](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L77)

One certificate whose status to query in an OCSP request.
Used as an element of [`CreateOcspRequestInput.requests`](#requests).

#### Extended by

- [`CreateOcspSingleResponseInput`](#createocspsingleresponseinput)

#### Properties

##### certificate

> `readonly` **certificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L79)

Certificate whose revocation status is being queried.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L81)

Issuer of `certificate` — needed to compute the CertID hash.

---

### CreateOcspResponseInput

Defined in: [revocation/ocsp.ts:236](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L236)

Input for [`createOcspResponse`](micro509.md#createocspresponse).

#### Properties

##### hashAlgorithm?

> `readonly` `optional` **hashAlgorithm**: [`OcspHashAlgorithm`](#ocsphashalgorithm)

Defined in: [revocation/ocsp.ts:248](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L248)

Hash algorithm for CertID computation. Defaults to `'SHA-1'`.

##### includedCertificates?

> `readonly` `optional` **includedCertificates**: readonly [`OcspCertificateSource`](#ocspcertificatesource)[]

Defined in: [revocation/ocsp.ts:250](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L250)

Extra certificates to embed in the response (e.g. the responder's issuer chain).

##### nonce?

> `readonly` `optional` **nonce**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:246](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L246)

Nonce to echo back for replay protection.

##### producedAt?

> `readonly` `optional` **producedAt**: `Date`

Defined in: [revocation/ocsp.ts:244](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L244)

Timestamp for the `producedAt` field. Defaults to `new Date()`.

##### responses

> `readonly` **responses**: readonly [`CreateOcspSingleResponseInput`](#createocspsingleresponseinput)[]

Defined in: [revocation/ocsp.ts:242](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L242)

Per-certificate status entries to include in the BasicOCSPResponse.

##### signerCertificate

> `readonly` **signerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:240](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L240)

Certificate of the OCSP responder — used to build the responder ID (by key hash).

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [revocation/ocsp.ts:238](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L238)

Private key used to sign the response. Algorithm is inferred from the key.

---

### CreateOcspSingleResponseInput

Defined in: [revocation/ocsp.ts:220](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L220)

One certificate's status entry for [`CreateOcspResponseInput.responses`](#responses).
Extends [`CreateOcspRequestItemInput`](#createocsprequestiteminput) with status and timing fields.

#### Extends

- [`CreateOcspRequestItemInput`](#createocsprequestiteminput)

#### Properties

##### certificate

> `readonly` **certificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L79)

Certificate whose revocation status is being queried.

###### Inherited from

[`CreateOcspRequestItemInput`](#createocsprequestiteminput).[`certificate`](#certificate-2)

##### certStatus

> `readonly` **certStatus**: [`OcspCertStatus`](#ocspcertstatus)

Defined in: [revocation/ocsp.ts:222](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L222)

Status to assert for this certificate.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L81)

Issuer of `certificate` — needed to compute the CertID hash.

###### Inherited from

[`CreateOcspRequestItemInput`](#createocsprequestiteminput).[`issuerCertificate`](#issuercertificate-2)

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/ocsp.ts:226](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L226)

End of the validity window. Omit for open-ended assertions.

##### revocationReasonCode?

> `readonly` `optional` **revocationReasonCode**: `number`

Defined in: [revocation/ocsp.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L230)

CRLReason integer code (only meaningful when `certStatus` is `'revoked'`).

##### revokedAt?

> `readonly` `optional` **revokedAt**: `Date`

Defined in: [revocation/ocsp.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L228)

Revocation time (required when `certStatus` is `'revoked'`). Defaults to `thisUpdate`.

##### thisUpdate?

> `readonly` `optional` **thisUpdate**: `Date`

Defined in: [revocation/ocsp.ts:224](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L224)

Start of the validity window for this status assertion. Defaults to `new Date()`.

---

### OcspRequestMaterial

Defined in: [revocation/ocsp.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L99)

Encoded OCSP request in multiple serialisation formats, returned by [`createOcspRequest`](micro509.md#createocsprequest).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/ocsp.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L105)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/ocsp.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L101)

Raw DER bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/ocsp.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L103)

PEM-encoded request (`-----BEGIN OCSP REQUEST-----`).

---

### OcspResponderCandidate

Defined in: [revocation/revocation.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L40)

One candidate OCSP responder resolved by [`resolveOcspResponderCandidates`](micro509.md#resolveocsprespondercandidates).

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

Defined in: [revocation/ocsp.ts:256](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L256)

Encoded OCSP response in multiple serialisation formats, returned by [`createOcspResponse`](micro509.md#createocspresponse).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [revocation/ocsp.ts:262](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L262)

Base64-encoded DER (no PEM armour).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [revocation/ocsp.ts:258](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L258)

Raw DER bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [revocation/ocsp.ts:260](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L260)

PEM-encoded response (`-----BEGIN OCSP RESPONSE-----`).

---

### ParsedCertificateRevocationList

Defined in: [revocation/crl.ts:176](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L176)

Decoded X.509 CRL, returned by [`parseCertificateRevocationListDer`](micro509.md#parsecertificaterevocationlistder)
and [`parseCertificateRevocationListPem`](micro509.md#parsecertificaterevocationlistpem).

#### Properties

##### authorityKeyIdentifier?

> `readonly` `optional` **authorityKeyIdentifier**: `string`

Defined in: [revocation/crl.ts:200](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L200)

Hex-encoded Authority Key Identifier, if the extension is present.

##### baseCrlNumber?

> `readonly` `optional` **baseCrlNumber**: `number`

Defined in: [revocation/crl.ts:204](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L204)

Delta CRL indicator — present only on delta CRLs, referencing the base CRL number.

##### crlNumber?

> `readonly` `optional` **crlNumber**: `number`

Defined in: [revocation/crl.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L202)

CRLNumber extension value — monotonically increasing sequence number.

##### der?

> `readonly` `optional` **der**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/crl.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L178)

Original DER bytes when this object came from [`parseCertificateRevocationListDer`](micro509.md#parsecertificaterevocationlistder) or PEM parsing.

##### freshestCrlDistributionPoints?

> `readonly` `optional` **freshestCrlDistributionPoints**: readonly [`ParsedDistributionPoint`](micro509.md#parseddistributionpoint)[]

Defined in: [revocation/crl.ts:208](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L208)

Freshest CRL extension — points to delta CRL locations.

##### issuer

> `readonly` **issuer**: [`ParsedName`](micro509.md#parsedname)

Defined in: [revocation/crl.ts:186](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L186)

CRL issuer distinguished name.

##### issuerPublicKeyAlgorithmOid?

> `readonly` `optional` **issuerPublicKeyAlgorithmOid**: `string`

Defined in: [revocation/crl.ts:196](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L196)

OID of the issuer's public key algorithm, when available.

##### issuerPublicKeyParametersOid?

> `readonly` `optional` **issuerPublicKeyParametersOid**: `string`

Defined in: [revocation/crl.ts:198](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L198)

OID of the issuer's public key parameters (e.g. named curve), when available.

##### issuingDistributionPoint?

> `readonly` `optional` **issuingDistributionPoint**: [`ParsedIssuingDistributionPoint`](micro509.md#parsedissuingdistributionpoint)

Defined in: [revocation/crl.ts:206](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L206)

Issuing distribution point extension — scopes this CRL to a certificate subset.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/crl.ts:190](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L190)

End of the CRL validity window. Absent if the CA does not commit to a schedule.

##### revokedCertificates

> `readonly` **revokedCertificates**: readonly [`ParsedRevokedCertificate`](#parsedrevokedcertificate)[]

Defined in: [revocation/crl.ts:210](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L210)

All revoked certificate entries (empty array if none).

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [revocation/crl.ts:194](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L194)

Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`).

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [revocation/crl.ts:192](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L192)

OID of the algorithm used to sign this CRL.

##### signatureValue

> `readonly` **signatureValue**: `Uint8Array`

Defined in: [revocation/crl.ts:184](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L184)

Raw signature bytes from the CRL outer wrapper.

##### tbsCertListDer

> `readonly` **tbsCertListDer**: `Uint8Array`

Defined in: [revocation/crl.ts:182](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L182)

DER-encoded TBSCertList — the signed payload for signature verification.

##### thisUpdate

> `readonly` **thisUpdate**: `Date`

Defined in: [revocation/crl.ts:188](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L188)

Start of the CRL validity window.

##### version

> `readonly` **version**: `number`

Defined in: [revocation/crl.ts:180](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L180)

CRL version (1 = v1, 2 = v2 with extensions).

---

### ParsedOcspCertId

Defined in: [revocation/ocsp.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L112)

Decoded OCSP CertID — identifies a certificate by hashed issuer name,
hashed issuer key, and serial number.

#### Properties

##### hashAlgorithmName

> `readonly` **hashAlgorithmName**: `string`

Defined in: [revocation/ocsp.ts:116](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L116)

Human-readable hash algorithm name (e.g. `"SHA-256"`).

##### hashAlgorithmOid

> `readonly` **hashAlgorithmOid**: `string`

Defined in: [revocation/ocsp.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L114)

OID of the hash algorithm used for the name and key hashes.

##### issuerKeyHashHex

> `readonly` **issuerKeyHashHex**: `string`

Defined in: [revocation/ocsp.ts:120](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L120)

Hex-encoded hash of the issuer's SubjectPublicKey BIT STRING content.

##### issuerNameHashHex

> `readonly` **issuerNameHashHex**: `string`

Defined in: [revocation/ocsp.ts:118](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L118)

Hex-encoded hash of the issuer's distinguished name DER.

##### serialNumberHex

> `readonly` **serialNumberHex**: `string`

Defined in: [revocation/ocsp.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L122)

Hex-encoded serial number of the certificate.

---

### ParsedOcspRequest

Defined in: [revocation/ocsp.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L128)

Decoded OCSP request, returned by [`parseOcspRequestDer`](micro509.md#parseocsprequestder) / [`parseOcspRequestPem`](micro509.md#parseocsprequestpem).

#### Properties

##### der?

> `readonly` `optional` **der**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L130)

Original DER bytes when this object came from [`parseOcspRequestDer`](micro509.md#parseocsprequestder) or PEM parsing.

##### nonce?

> `readonly` `optional` **nonce**: `string`

Defined in: [revocation/ocsp.ts:134](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L134)

Hex-encoded nonce extension value, if present.

##### requests

> `readonly` **requests**: readonly [`ParsedOcspCertId`](#parsedocspcertid)[]

Defined in: [revocation/ocsp.ts:132](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L132)

CertIDs of the certificates being queried.

---

### ParsedOcspResponse

Defined in: [revocation/ocsp.ts:189](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L189)

Decoded OCSP response, returned by [`parseOcspResponseDer`](micro509.md#parseocspresponseder) / [`parseOcspResponsePem`](micro509.md#parseocspresponsepem).

When `responseStatus` is not `'successful'`, most fields are absent.

#### Properties

##### certificates?

> `readonly` `optional` **certificates**: readonly [`ParsedCertificate`](micro509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [revocation/ocsp.ts:213](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L213)

Certificates embedded in the response (typically the responder's chain).

##### der?

> `readonly` `optional` **der**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:191](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L191)

Original DER bytes when this object came from [`parseOcspResponseDer`](micro509.md#parseocspresponseder) or PEM parsing.

##### nonce?

> `readonly` `optional` **nonce**: `string`

Defined in: [revocation/ocsp.ts:211](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L211)

Hex-encoded nonce, if the response echoed one.

##### producedAt?

> `readonly` `optional` **producedAt**: `Date`

Defined in: [revocation/ocsp.ts:207](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L207)

Timestamp when the responder produced this response.

##### responderId?

> `readonly` `optional` **responderId**: [`ParsedOcspResponderId`](#parsedocspresponderid)

Defined in: [revocation/ocsp.ts:199](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L199)

How the responder identifies itself.

##### responseDataDer?

> `readonly` `optional` **responseDataDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L197)

DER-encoded ResponseData — the signed payload for signature verification.

##### responses?

> `readonly` `optional` **responses**: readonly [`ParsedOcspSingleResponse`](#parsedocspsingleresponse)[]

Defined in: [revocation/ocsp.ts:209](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L209)

Per-certificate status entries.

##### responseStatus

> `readonly` **responseStatus**: [`OcspResponseStatus`](#ocspresponsestatus)

Defined in: [revocation/ocsp.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L193)

Overall response status. Only `'successful'` carries a BasicOCSPResponse body.

##### responseTypeOid?

> `readonly` `optional` **responseTypeOid**: `string`

Defined in: [revocation/ocsp.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L195)

OID of the response type (normally `id-pkix-ocsp-basic`).

##### signatureAlgorithmName?

> `readonly` `optional` **signatureAlgorithmName**: `string`

Defined in: [revocation/ocsp.ts:203](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L203)

Human-readable signature algorithm name.

##### signatureAlgorithmOid?

> `readonly` `optional` **signatureAlgorithmOid**: `string`

Defined in: [revocation/ocsp.ts:201](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L201)

OID of the algorithm used to sign this response.

##### signatureValue?

> `readonly` `optional` **signatureValue**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [revocation/ocsp.ts:205](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L205)

Raw signature bytes.

---

### ParsedOcspSingleResponse

Defined in: [revocation/ocsp.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L151)

Status of one certificate inside an OCSP BasicResponse.

#### Properties

##### certId

> `readonly` **certId**: [`ParsedOcspCertId`](#parsedocspcertid)

Defined in: [revocation/ocsp.ts:153](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L153)

Which certificate this status applies to.

##### certStatus

> `readonly` **certStatus**: [`OcspCertStatus`](#ocspcertstatus)

Defined in: [revocation/ocsp.ts:155](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L155)

Responder's verdict: `good`, `revoked`, or `unknown`.

##### nextUpdate?

> `readonly` `optional` **nextUpdate**: `Date`

Defined in: [revocation/ocsp.ts:159](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L159)

End of the validity window. Absent if the responder does not commit to a schedule.

##### revocationReasonCode?

> `readonly` `optional` **revocationReasonCode**: `number`

Defined in: [revocation/ocsp.ts:163](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L163)

CRLReason integer (only for `certStatus === 'revoked'`).

##### revokedAt?

> `readonly` `optional` **revokedAt**: `Date`

Defined in: [revocation/ocsp.ts:161](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L161)

When the certificate was revoked (only for `certStatus === 'revoked'`).

##### thisUpdate

> `readonly` **thisUpdate**: `Date`

Defined in: [revocation/ocsp.ts:157](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L157)

Start of the validity window for this status assertion.

---

### ParsedRevokedCertificate

Defined in: [revocation/crl.ts:159](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L159)

A single revoked-certificate entry decoded from a CRL.

#### Properties

##### certificateIssuer?

> `readonly` `optional` **certificateIssuer**: readonly [`SubjectAltName`](micro509.md#subjectaltname)[]

Defined in: [revocation/crl.ts:169](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L169)

Indirect-CRL certificate issuer override (RFC 5280 §5.3.3).

##### invalidityDate?

> `readonly` `optional` **invalidityDate**: `Date`

Defined in: [revocation/crl.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L167)

When the key or certificate actually became suspect, if present.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:165](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L165)

RFC 5280 CRLReason, if the entry carries one.

##### revocationDate

> `readonly` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:163](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L163)

When the CA declared this certificate revoked.

##### serialNumberHex

> `readonly` **serialNumberHex**: `string`

Defined in: [revocation/crl.ts:161](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L161)

Hex-encoded serial number of the revoked certificate.

---

### ResolveOcspResponderCandidatesInput

Defined in: [revocation/revocation.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L50)

Input for [`resolveOcspResponderCandidates`](micro509.md#resolveocsprespondercandidates).

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

Defined in: [revocation/crl.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L90)

Single revoked certificate entry for [`createCertificateRevocationList`](micro509.md#createcertificaterevocationlist).

#### Properties

##### invalidityDate?

> `readonly` `optional` **invalidityDate**: `Date`

Defined in: [revocation/crl.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L98)

When the key or certificate became suspect — may predate `revocationDate`.

##### reasonCode?

> `readonly` `optional` **reasonCode**: [`RevocationReason`](#revocationreason-1)

Defined in: [revocation/crl.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L96)

RFC 5280 CRLReason code. Omit for `unspecified`.

##### revocationDate?

> `readonly` `optional` **revocationDate**: `Date`

Defined in: [revocation/crl.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L94)

When the certificate was revoked. Defaults to `thisUpdate` of the CRL.

##### serialNumber

> `readonly` **serialNumber**: `Uint8Array`

Defined in: [revocation/crl.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L92)

DER-encoded certificate serial number to revoke.

---

### ValidateCertificateRevocationListFailure

Defined in: [revocation/crl.ts:270](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L270)

Failure detail for [`validateCertificateRevocationList`](micro509.md#validatecertificaterevocationlist).

Possible codes: `signature_invalid`, `issuer_mismatch`, `stale_crl`, `crl_sign_not_permitted`.

#### Extends

- [`Micro509Error`](micro509.md#micro509error)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`code`](micro509.md#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`details`](micro509.md#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`message`](micro509.md#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/crl.ts:275](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L275)

Always `false` for failures.

---

### ValidateCertificateRevocationListInput

Defined in: [revocation/crl.ts:254](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L254)

Input for [`validateCertificateRevocationList`](micro509.md#validatecertificaterevocationlist).

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/crl.ts:260](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L260)

Evaluation time for freshness checks. Defaults to `new Date()`.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/crl.ts:262](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L262)

Tolerance in milliseconds for clock skew when checking `thisUpdate`/`nextUpdate`.

##### crl

> `readonly` **crl**: [`CrlSource`](#crlsource)

Defined in: [revocation/crl.ts:256](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L256)

The CRL to validate.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`CrlCertificateSource`](#crlcertificatesource)

Defined in: [revocation/crl.ts:258](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L258)

Certificate of the CA that should have signed the CRL.

---

### ValidateOcspResponseFailure

Defined in: [revocation/ocsp.ts:312](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L312)

Failure detail for [`validateOcspResponse`](micro509.md#validateocspresponse).

Possible codes: `response_status_invalid`, `signature_invalid`,
`responder_id_mismatch`, `nonce_mismatch`, `request_mismatch`,
`issuer_mismatch`, `responder_chain_invalid`, `ocsp_signing_missing`,
`stale_response`.

#### Extends

- [`Micro509Error`](micro509.md#micro509error)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"` \| `"issuer_mismatch"` \| `"response_status_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`code`](micro509.md#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`details`](micro509.md#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`message`](micro509.md#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/ocsp.ts:325](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L325)

Always `false` for failures.

---

### ValidateOcspResponseInput

Defined in: [revocation/ocsp.ts:287](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L287)

Input for [`validateOcspResponse`](micro509.md#validateocspresponse).

#### Properties

##### allowChainedResponderCertificate?

> `readonly` `optional` **allowChainedResponderCertificate**: `boolean`

Defined in: [revocation/ocsp.ts:297](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L297)

When `true`, allows delegated responder chain validation beyond direct issuance.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [revocation/ocsp.ts:299](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L299)

Evaluation time for freshness checks. Defaults to `new Date()`.

##### clockSkewMs?

> `readonly` `optional` **clockSkewMs**: `number`

Defined in: [revocation/ocsp.ts:301](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L301)

Clock-skew tolerance in milliseconds for `thisUpdate`/`nextUpdate`/`producedAt`.

##### issuerCertificate

> `readonly` **issuerCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:291](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L291)

Certificate of the CA that issued the target certificate.

##### request?

> `readonly` `optional` **request**: [`OcspRequestSource`](#ocsprequestsource)

Defined in: [revocation/ocsp.ts:293](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L293)

Original request — enables nonce and request-coverage checks.

##### responderCertificate?

> `readonly` `optional` **responderCertificate**: [`OcspCertificateSource`](#ocspcertificatesource)

Defined in: [revocation/ocsp.ts:295](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L295)

Explicit responder certificate — overrides embedded certificate discovery.

##### response

> `readonly` **response**: `string` \| `Uint8Array`\<`ArrayBufferLike`\> \| [`ParsedOcspResponse`](#parsedocspresponse)

Defined in: [revocation/ocsp.ts:289](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L289)

The OCSP response to validate.

---

### VerifyCertificateRevocationListFailure

Defined in: [revocation/crl.ts:233](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L233)

Failure detail when CRL signature verification fails.

#### Extends

- [`Micro509Error`](micro509.md#micro509error)\<`"signature_invalid"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`code`](micro509.md#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`details`](micro509.md#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`message`](micro509.md#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/crl.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L235)

Always `false` for failures.

---

### VerifyOcspResponseFailure

Defined in: [revocation/ocsp.ts:266](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L266)

Failure detail when OCSP response signature verification fails.

#### Extends

- [`Micro509Error`](micro509.md#micro509error)\<`"signature_invalid"`\>

#### Properties

##### code

> `readonly` **code**: `"signature_invalid"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`code`](micro509.md#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`details`](micro509.md#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](micro509.md#micro509error).[`message`](micro509.md#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [revocation/ocsp.ts:268](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L268)

Always `false` for failures.

## Type Aliases

### CheckCertificateRevocationAgainstCrlErrorCode

> **CheckCertificateRevocationAgainstCrlErrorCode** = `"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"` \| `"non_applicable"`

Defined in: [revocation/crl.ts:314](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L314)

Error codes that [`checkCertificateRevocationAgainstCrl`](micro509.md#checkcertificaterevocationagainstcrl) may return.

---

### CheckCertificateRevocationAgainstCrlResult

> **CheckCertificateRevocationAgainstCrlResult** = \{ `ok`: `true`; `value`: [`CheckCertificateRevocationAgainstCrlValue`](#checkcertificaterevocationagainstcrlvalue); \} \| [`ErrorResult`](micro509.md#errorresult)\<[`CheckCertificateRevocationAgainstCrlErrorCode`](#checkcertificaterevocationagainstcrlerrorcode), [`CheckCertificateRevocationAgainstCrlFailureDetails`](#checkcertificaterevocationagainstcrlfailuredetails-1), [`CheckCertificateRevocationAgainstCrlFailure`](#checkcertificaterevocationagainstcrlfailure)\>

Defined in: [revocation/crl.ts:391](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L391)

Result of [`checkCertificateRevocationAgainstCrl`](micro509.md#checkcertificaterevocationagainstcrl).

On success `value.status` is `'good'` or `'revoked'`.
On failure the CRL could not be validated or was non-applicable.

---

### CheckCertificateRevocationAgainstCrlValue

> **CheckCertificateRevocationAgainstCrlValue** = [`CheckCertificateRevocationAgainstCrlGoodValue`](#checkcertificaterevocationagainstcrlgoodvalue) \| [`CheckCertificateRevocationAgainstCrlRevokedValue`](#checkcertificaterevocationagainstcrlrevokedvalue)

Defined in: [revocation/crl.ts:381](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L381)

Discriminated union of `good` and `revoked` outcomes.

---

### CheckCertificateRevocationErrorCode

> **CheckCertificateRevocationErrorCode** = `"revocation_evidence_missing"` \| `"revocation_status_unknown"`

Defined in: [revocation/revocation.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L97)

Error codes that [`checkCertificateRevocation`](micro509.md#checkcertificaterevocation) may surface inside an `unknown` result.

---

### CheckCertificateRevocationResult

> **CheckCertificateRevocationResult** = [`Result`](micro509.md#result)\<[`CheckCertificateRevocationValue`](#checkcertificaterevocationvalue), `never`\>

Defined in: [revocation/revocation.ts:186](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L186)

Result of [`checkCertificateRevocation`](micro509.md#checkcertificaterevocation). Always succeeds (`ok: true`) —
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

Defined in: [revocation/crl.ts:322](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L322)

Structured reason why a CRL was deemed non-applicable to a given certificate.

---

### CrlCertificateSource

> **CrlCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](micro509.md#parsedcertificate)

Defined in: [revocation/crl.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L230)

PEM string, DER bytes, or already-parsed certificate.

---

### CrlSource

> **CrlSource** = `string` \| `Uint8Array` \| [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L228)

PEM string, DER bytes, or already-parsed CRL.

---

### OcspCertificateSource

> **OcspCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](micro509.md#parsedcertificate)

Defined in: [revocation/ocsp.ts:69](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L69)

PEM string, DER bytes, or already-parsed certificate.

---

### OcspCertStatus

> **OcspCertStatus** = `"good"` \| `"revoked"` \| `"unknown"`

Defined in: [revocation/ocsp.ts:138](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L138)

RFC 6960 certificate status reported by the responder for a single CertID.

---

### OcspHashAlgorithm

> **OcspHashAlgorithm** = `"SHA-1"` \| `"SHA-256"`

Defined in: [revocation/ocsp.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L67)

Hash algorithm used to compute OCSP CertID fields. SHA-1 is the RFC 6960 default.

---

### OcspRequestSource

> **OcspRequestSource** = `string` \| `Uint8Array` \| [`ParsedOcspRequest`](#parsedocsprequest)

Defined in: [revocation/ocsp.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L71)

PEM string, DER bytes, or already-parsed OCSP request.

---

### OcspResponderSource

> **OcspResponderSource** = `"configured"` \| `"authorityInfoAccess"`

Defined in: [revocation/revocation.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L27)

Where the OCSP responder URI came from.

---

### OcspResponseStatus

> **OcspResponseStatus** = `"successful"` \| `"malformedRequest"` \| `"internalError"` \| `"tryLater"` \| `"sigRequired"` \| `"unauthorized"`

Defined in: [revocation/ocsp.ts:140](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L140)

RFC 6960 overall response status — anything other than `'successful'` means the response body is absent or unusable.

---

### ParsedOcspResponderId

> **ParsedOcspResponderId** = \{ `name`: [`ParsedName`](micro509.md#parsedname); `type`: `"byName"`; \} \| \{ `keyHashHex`: `string`; `type`: `"byKeyHash"`; \}

Defined in: [revocation/ocsp.ts:170](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L170)

How the OCSP responder identifies itself — either by distinguished name or
by SHA-1 hash of its public key.

#### Type Declaration

\{ `name`: [`ParsedName`](micro509.md#parsedname); `type`: `"byName"`; \}

##### name

> `readonly` **name**: [`ParsedName`](micro509.md#parsedname)

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

> **RevocationCertificateSource** = `string` \| `Uint8Array` \| [`ParsedCertificate`](micro509.md#parsedcertificate)

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

Defined in: [revocation/crl.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L106)

RFC 5280 §5.3.1 CRLReason code values.

`removeFromCRL` is used in delta CRLs to un-hold a certificate.

---

### RevocationStatus

> **RevocationStatus** = `"good"` \| `"revoked"` \| `"unknown"`

Defined in: [revocation/revocation.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L20)

Unified revocation outcome across CRL and OCSP evidence.

---

### ValidateCertificateRevocationListResult

> **ValidateCertificateRevocationListResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \} \| [`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`, `Record`\<`never`, `never`\>, [`ValidateCertificateRevocationListFailure`](#validatecertificaterevocationlistfailure)\>

Defined in: [revocation/crl.ts:283](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L283)

Result of [`validateCertificateRevocationList`](micro509.md#validatecertificaterevocationlist).

On success, the CRL has passed signature, issuer, key-usage, and freshness checks.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Validated and parsed CRL.

[`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"` \| `"issuer_mismatch"` \| `"stale_crl"` \| `"crl_sign_not_permitted"`, `Record`\<`never`, `never`\>, [`ValidateCertificateRevocationListFailure`](#validatecertificaterevocationlistfailure)\>

---

### ValidateOcspResponseResult

> **ValidateOcspResponseResult** = \{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \} \| [`ErrorResult`](micro509.md#errorresult)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`, `Record`\<`never`, `never`\>, [`ValidateOcspResponseFailure`](#validateocspresponsefailure)\>

Defined in: [revocation/ocsp.ts:334](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L334)

Result of [`validateOcspResponse`](micro509.md#validateocspresponse).

On success, the response has passed status, signature, responder binding,
freshness, nonce, and request-coverage checks.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedOcspResponse`](#parsedocspresponse)

Fully validated OCSP response.

[`ErrorResult`](micro509.md#errorresult)\<`"response_status_invalid"` \| `"signature_invalid"` \| `"responder_id_mismatch"` \| `"nonce_mismatch"` \| `"request_mismatch"` \| `"issuer_mismatch"` \| `"responder_chain_invalid"` \| `"ocsp_signing_missing"` \| `"stale_response"`, `Record`\<`never`, `never`\>, [`ValidateOcspResponseFailure`](#validateocspresponsefailure)\>

---

### VerifyCertificateRevocationListResult

> **VerifyCertificateRevocationListResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \} \| [`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyCertificateRevocationListFailure`](#verifycertificaterevocationlistfailure)\>

Defined in: [revocation/crl.ts:243](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L243)

Result of [`verifyCertificateRevocationList`](micro509.md#verifycertificaterevocationlist).

On success, `value` is the parsed CRL whose signature has been verified.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedCertificateRevocationList`](#parsedcertificaterevocationlist)

Parsed CRL with a verified signature.

[`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyCertificateRevocationListFailure`](#verifycertificaterevocationlistfailure)\>

---

### VerifyOcspResponseResult

> **VerifyOcspResponseResult** = \{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \} \| [`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyOcspResponseFailure`](#verifyocspresponsefailure)\>

Defined in: [revocation/ocsp.ts:276](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L276)

Result of [`verifyOcspResponse`](micro509.md#verifyocspresponse).

On success, `value` is the parsed response whose signature has been verified.

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedOcspResponse`](#parsedocspresponse); \}

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: [`ParsedOcspResponse`](#parsedocspresponse)

Parsed response with a verified signature.

[`ErrorResult`](micro509.md#errorresult)\<`"signature_invalid"`, `Record`\<`never`, `never`\>, [`VerifyOcspResponseFailure`](#verifyocspresponsefailure)\>
