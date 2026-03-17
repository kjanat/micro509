[micro509](modules.md) / micro509

# micro509

Stable root import for `micro509`.\
Re-exports the common certificate, parsing, verification, revocation, key, and PKCS
workflows from one package entrypoint.

Reach for this module when you want the default workflow-first package surface.
Use domain entrypoints such as `micro509/x509`, `micro509/verify`, and
`micro509/revocation` when you need exhaustive advanced types.

The root export is organized around common PKI flows:

- create certificates, CSRs, CRLs, OCSP responses, PKCS#7, and PFX artifacts
- parse DER or PEM inputs into typed certificate and request shapes
- verify certificate chains, service identities, CRLs, OCSP, and signed data
- import, export, generate, and encrypt key material with WebCrypto-safe algorithms
- work with the common extension inputs, revocation evidence, and validation results

Advanced PKCS#12 MAC plumbing, signature profile tuning, and other domain-specific helper
types stay in their owner domains instead of being headlined here.

## Examples

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  verifyCertificateChain,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'example.com' },
  algorithm: { kind: 'ecdsa', namedCurve: 'P-256' },
});

const parsed = parseCertificatePem(certificate.pem);
// parsed.subject.values.commonName === 'example.com'

const result = await verifyCertificateChain({
  leaf: certificate.pem,
  roots: [certificate.pem],
  allowSelfSignedLeaf: true,
});
// result.ok === true
```

```ts
import {
  generateKeyPair,
  parseCertificateSigningRequestPem,
  createCertificateSigningRequest,
} from 'micro509';

const keyPair = await generateKeyPair({
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'example.com' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
});

const parsed = parseCertificateSigningRequestPem(csr.pem);
// parsed.subject.values.commonName === 'example.com'
```

## Interfaces

### AuthorityInformationAccess

Defined in: [x509/extensions.ts:610](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L610)

A single entry in the Authority Information Access extension (RFC 5280 §4.2.2.1).

#### Properties

##### method

> `readonly` **method**: `"ocsp"` \| `"caIssuers"` \| \{ `type`: `"oid"`; `value`: `string`; \}

Defined in: [x509/extensions.ts:612](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L612)

Access method (`'ocsp'`, `'caIssuers'`, or custom OID).

##### uri

> `readonly` **uri**: `string`

Defined in: [x509/extensions.ts:620](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L620)

URI where the resource can be fetched.

---

### BasicConstraints

Defined in: [x509/extensions.ts:251](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L251)

RFC 5280 §4.2.1.9 Basic Constraints.

A certificate with `ca: true` may issue other certificates; `pathLength`
limits how many additional CAs may appear below it in the chain.

#### Properties

##### ca

> `readonly` **ca**: `boolean`

Defined in: [x509/extensions.ts:253](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L253)

Whether this certificate belongs to a CA. End-entity certs set this to `false`.

##### pathLength?

> `readonly` `optional` **pathLength**: `number`

Defined in: [x509/extensions.ts:255](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L255)

Maximum number of intermediate CA certificates allowed below this CA. Only valid when `ca` is `true`.

---

### BuildCandidatePathInput

Defined in: [verify/verify.ts:227](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L227)

Input for [`buildCandidatePath`](#buildcandidatepath).

#### Extended by

- [`ValidateForCaInput`](#validateforcainput)
- [`ValidateForCodeSigningInput`](#validateforcodesigninginput)
- [`ValidateForTlsClientInput`](#validatefortlsclientinput)
- [`ValidateForTlsServerInput`](#validatefortlsserverinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L237)

Validation time. Defaults to `new Date()`.

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:231](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L231)

Intermediate CA certificates available for path building. Order does not matter.

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L229)

End-entity certificate to verify.

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:233](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L233)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L235)

Bare trust anchors to try when no root certificate matches.

---

### CandidatePath

Defined in: [verify/verify.ts:241](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L241)

A signature-verified certification path from leaf to root, before constraint validation.

#### Properties

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:245](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L245)

Full chain in leaf-to-root order (includes both leaf and root).

##### leaf

> `readonly` **leaf**: [`ParsedCertificate`](#parsedcertificate)

Defined in: [verify/verify.ts:243](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L243)

Parsed end-entity certificate.

##### root

> `readonly` **root**: [`ParsedCertificate`](#parsedcertificate)

Defined in: [verify/verify.ts:247](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L247)

Trusted root that terminates the path.

---

### CategorizedPemBlocks

Defined in: [pem/pem.ts:26](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L26)

PEM blocks grouped by their label into well-known PKI categories.
Blocks that don't match any known label land in [`others`](#others).

#### Properties

##### certificateRequests

> `readonly` **certificateRequests**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:30](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L30)

Blocks with label `CERTIFICATE REQUEST`.

##### certificates

> `readonly` **certificates**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:28](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L28)

Blocks with label `CERTIFICATE`.

##### others

> `readonly` **others**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L36)

Blocks whose label doesn't match any of the above categories.

##### privateKeys

> `readonly` **privateKeys**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:32](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L32)

Blocks with label `PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`.

##### publicKeys

> `readonly` **publicKeys**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:34](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L34)

Blocks with label `PUBLIC KEY`.

---

### CertificateExtensionsInput

Defined in: [x509/extensions.ts:382](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L382)

Input for `createCertificate`, `createSelfSignedCertificate`,
and `createCertificateSigningRequest`.

Every field is optional. Omitted extensions are not encoded. Built-in
extensions (SKI, AKI, basicConstraints defaults) are handled automatically
by the builder.

#### Properties

##### authorityInfoAccess?

> `readonly` `optional` **authorityInfoAccess**: readonly [`AuthorityInformationAccess`](#authorityinformationaccess)[]

Defined in: [x509/extensions.ts:402](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L402)

Authority Information Access — OCSP responder and CA issuer URIs.

##### basicConstraints?

> `readonly` `optional` **basicConstraints**: [`BasicConstraints`](#basicconstraints)

Defined in: [x509/extensions.ts:388](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L388)

Basic Constraints (CA flag + optional pathLength). Defaults to `{ ca: false }` for certs.

##### certificatePolicies?

> `readonly` `optional` **certificatePolicies**: [`CertificatePolicies`](#certificatepolicies-3)

Defined in: [x509/extensions.ts:394](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L394)

Certificate Policies with optional qualifiers.

##### crlDistributionPoints?

> `readonly` `optional` **crlDistributionPoints**: readonly [`DistributionPoint`](#distributionpoint-2)[]

Defined in: [x509/extensions.ts:404](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L404)

CRL Distribution Points — where to check revocation status.

##### customExtensions?

> `readonly` `optional` **customExtensions**: readonly [`CustomExtension`](x509.md#customextension)[]

Defined in: [x509/extensions.ts:406](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L406)

Arbitrary extensions not covered by the built-in fields.

##### extendedKeyUsage?

> `readonly` `optional` **extendedKeyUsage**: readonly [`ExtendedKeyUsage`](#extendedkeyusage-3)[]

Defined in: [x509/extensions.ts:390](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L390)

Extended Key Usage purposes (serverAuth, clientAuth, etc.).

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: [`InhibitAnyPolicy`](#inhibitanypolicy-1)

Defined in: [x509/extensions.ts:400](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L400)

Inhibit anyPolicy skip-certs threshold.

##### keyUsage?

> `readonly` `optional` **keyUsage**: readonly [`KeyUsage`](#keyusage-3)[]

Defined in: [x509/extensions.ts:386](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L386)

Key Usage flags (digitalSignature, keyCertSign, etc.).

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`NameConstraints`](#nameconstraints-1)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>

Defined in: [x509/extensions.ts:392](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L392)

Name Constraints — permitted and/or excluded subtrees.

##### policyConstraints?

> `readonly` `optional` **policyConstraints**: [`PolicyConstraints`](#policyconstraints-3)

Defined in: [x509/extensions.ts:398](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L398)

Policy Constraints (requireExplicitPolicy / inhibitPolicyMapping thresholds).

##### policyMappings?

> `readonly` `optional` **policyMappings**: [`PolicyMappings`](#policymappings-3)

Defined in: [x509/extensions.ts:396](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L396)

Policy Mappings between issuer and subject policy domains.

##### subjectAltNames?

> `readonly` `optional` **subjectAltNames**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/extensions.ts:384](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L384)

Subject Alternative Names (dns, ip, email, uri, srv, directoryName).

---

### CertificateMaterial

Defined in: [x509/certificate.ts:155](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L155)

Encoded certificate material in common interchange formats.

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [x509/certificate.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L167)

Base64 encoding of [`der`](#der) without PEM armor.

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [x509/certificate.ts:159](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L159)

DER-encoded certificate bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [x509/certificate.ts:163](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L163)

PEM-encoded certificate.

---

### CreateCertificateInput

Defined in: [x509/certificate.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L67)

Input for [`createCertificate`](#createcertificate).

#### Properties

##### extensions?

> `readonly` `optional` **extensions**: [`CertificateExtensionsInput`](#certificateextensionsinput)

Defined in: [x509/certificate.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L104)

X.509 extensions to encode into the certificate.

##### issuer

> `readonly` **issuer**: [`NameInput`](#nameinput)

Defined in: [x509/certificate.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L71)

Issuer distinguished name.

##### issuerPublicKey?

> `readonly` `optional` **issuerPublicKey**: `CryptoKey`

Defined in: [x509/certificate.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L90)

Issuer public key.

Provide this when extension builders need issuer key material, such as
authority key identifier derivation.

##### publicKey

> `readonly` **publicKey**: `CryptoKey`

Defined in: [x509/certificate.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L79)

Subject public key to encode into the certificate.

##### serialNumber?

> `readonly` `optional` **serialNumber**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/certificate.ts:100](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L100)

DER integer bytes for the certificate serial number.

When omitted, a random positive 16-byte serial number is generated.

##### signature?

> `readonly` `optional` **signature**: [`SignatureProfileInput`](x509.md#signatureprofileinput)

Defined in: [x509/certificate.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L111)

Signature algorithm override.

When omitted, the library selects a compatible profile from the signing
key.

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [x509/certificate.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L83)

Private key used to sign the certificate.

##### subject

> `readonly` **subject**: [`NameInput`](#nameinput)

Defined in: [x509/certificate.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L75)

Subject distinguished name.

##### validity?

> `readonly` `optional` **validity**: [`ValidityInput`](#validityinput)

Defined in: [x509/certificate.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L94)

Validity window configuration.

---

### CreateCsrInput

Defined in: [x509/csr.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L36)

Input for [`createCertificateSigningRequest`](#createcertificatesigningrequest).

#### Properties

##### extensions?

> `readonly` `optional` **extensions**: [`CertificateExtensionsInput`](#certificateextensionsinput)

Defined in: [x509/csr.ts:44](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L44)

Requested X.509v3 extensions to include in the CSR attributes.

##### publicKey

> `readonly` **publicKey**: `CryptoKey`

Defined in: [x509/csr.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L40)

WebCrypto public key to embed in the CSR's SubjectPublicKeyInfo.

##### signature?

> `readonly` `optional` **signature**: [`SignatureProfileInput`](x509.md#signatureprofileinput)

Defined in: [x509/csr.ts:46](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L46)

Override the signature algorithm profile (hash, salt length, etc.).

##### signerPrivateKey

> `readonly` **signerPrivateKey**: `CryptoKey`

Defined in: [x509/csr.ts:42](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L42)

WebCrypto private key used to self-sign the CSR (proves key possession).

##### subject

> `readonly` **subject**: [`NameInput`](#nameinput)

Defined in: [x509/csr.ts:38](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L38)

Distinguished name for the CSR subject (e.g. `{ commonName: 'example.com' }`).

---

### CreatePfxInput

Defined in: [pkcs/pfx.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L84)

Input for [`createPfx`](#createpfx).

#### Properties

##### certificates?

> `readonly` `optional` **certificates**: readonly [`PfxCertificateBagInput`](#pfxcertificatebaginput)[]

Defined in: [pkcs/pfx.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L86)

Certificates to include as certBag entries.

##### encryption?

> `readonly` `optional` **encryption**: [`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L90)

PBES2 encryption settings for the key-bag ContentInfo. Omit for unencrypted.

##### mac?

> `readonly` `optional` **mac**: [`Pkcs12MacOptions`](pkcs.md#pkcs12macoptions)

Defined in: [pkcs/pfx.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L92)

PKCS#12 MAC integrity settings. Omit to skip MAC generation.

##### privateKeys?

> `readonly` `optional` **privateKeys**: readonly [`PfxPrivateKeyBagInput`](#pfxprivatekeybaginput)[]

Defined in: [pkcs/pfx.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L88)

Private keys to include as keyBag entries.

---

### CreateSelfSignedCertificateInput

Defined in: [x509/certificate.ts:117](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L117)

Input for [`createSelfSignedCertificate`](#createselfsignedcertificate).

#### Properties

##### algorithm?

> `readonly` `optional` **algorithm**: [`KeyAlgorithmInput`](#keyalgorithminput)

Defined in: [x509/certificate.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L127)

Key generation parameters.

Ignored when `keyPair` is provided.

##### extensions?

> `readonly` `optional` **extensions**: [`CertificateExtensionsInput`](#certificateextensionsinput)

Defined in: [x509/certificate.ts:145](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L145)

X.509 extensions to encode into the certificate.

##### keyPair?

> `readonly` `optional` **keyPair**: [`KeyPairMaterial`](#keypairmaterial)

Defined in: [x509/certificate.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L133)

Existing key pair to reuse for both subject and issuer.

When omitted, a new key pair is generated.

##### serialNumber?

> `readonly` `optional` **serialNumber**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/certificate.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L141)

DER integer bytes for the certificate serial number.

##### signature?

> `readonly` `optional` **signature**: [`SignatureProfileInput`](x509.md#signatureprofileinput)

Defined in: [x509/certificate.ts:149](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L149)

Signature algorithm override.

##### subject

> `readonly` **subject**: [`NameInput`](#nameinput)

Defined in: [x509/certificate.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L121)

Subject distinguished name used as both subject and issuer.

##### validity?

> `readonly` `optional` **validity**: [`ValidityInput`](#validityinput)

Defined in: [x509/certificate.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L137)

Validity window configuration.

---

### CsrMaterial

Defined in: [x509/csr.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L50)

DER, PEM, and base64 encodings of a CSR produced by [`createCertificateSigningRequest`](#createcertificatesigningrequest).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [x509/csr.ts:56](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L56)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [x509/csr.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L52)

Raw DER-encoded PKCS#10 CertificationRequest.

##### pem

> `readonly` **pem**: `string`

Defined in: [x509/csr.ts:54](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L54)

PEM-armored CSR (`-----BEGIN CERTIFICATE REQUEST-----`).

---

### DecodedExtensionValue

Defined in: [x509/parse.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L235)

A successfully decoded extension value paired with its OID and criticality.

#### Type Parameters

##### TValue

`TValue`

#### Properties

##### critical

> `readonly` **critical**: `boolean`

Defined in: [x509/parse.ts:239](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L239)

Whether the extension was marked critical in the certificate.

##### oid

> `readonly` **oid**: `string`

Defined in: [x509/parse.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L237)

Dotted-decimal OID of the decoded extension.

##### value

> `readonly` **value**: `TValue`

Defined in: [x509/parse.ts:241](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L241)

Typed value produced by the [`ExtensionDecoder`](#extensiondecoder).

---

### DistributionPointName

Defined in: [x509/extensions.ts:154](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L154)

Name component of a CRL Distribution Point (RFC 5280 §4.2.1.13).

Supply exactly one of `fullName` or `relativeName`.

#### Properties

##### fullName?

> `readonly` `optional` **fullName**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/extensions.ts:156](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L156)

Absolute [`GeneralName`](#generalname)(s) identifying the distribution point (usually a URI).

##### relativeName?

> `readonly` `optional` **relativeName**: [`RelativeDistinguishedNameInput`](#relativedistinguishednameinput)

Defined in: [x509/extensions.ts:158](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L158)

Name relative to the issuer's DN; mutually exclusive with `fullName`.

---

### DnsServiceIdentityInput

Defined in: [verify/identity.ts:18](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L18)

DNS hostname reference identifier.

#### Properties

##### allowCommonNameFallback?

> `readonly` `optional` **allowCommonNameFallback**: `boolean`

Defined in: [verify/identity.ts:28](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L28)

When `true`, falls back to the subject CN if the SAN extension has no
dns/uri/srv entries. Suppressed when any supported SAN type is present.

###### Default

```ts
false;
```

##### type

> `readonly` **type**: `"dns"`

Defined in: [verify/identity.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L20)

Discriminant for DNS hostname matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L22)

The hostname to match (e.g. `"mail.example.com"`). Wildcard labels in the certificate are handled internally.

---

### EcKeyAlgorithmInput

Defined in: [keys/keys.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L61)

ECDSA variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### kind

> `readonly` **kind**: `"ecdsa"`

Defined in: [keys/keys.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L63)

Discriminant selecting ECDSA key generation.

##### namedCurve?

> `readonly` `optional` **namedCurve**: [`EcNamedCurve`](#ecnamedcurve)

Defined in: [keys/keys.ts:65](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L65)

NIST curve. Defaults to `'P-256'`.

---

### Ed25519KeyAlgorithmInput

Defined in: [keys/keys.ts:69](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L69)

Ed25519 variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### kind

> `readonly` **kind**: `"ed25519"`

Defined in: [keys/keys.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L71)

Discriminant selecting Ed25519 key generation.

---

### EkuCheckFailure

Defined in: [verify/verify.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L111)

Failure from [`checkExtendedKeyUsage`](#checkextendedkeyusage) with the chain index of the certificate that failed.

#### Extends

- [`Micro509Error`](#micro509error)\<`"leaf_eku_missing"` \| `"intermediate_eku_constraint"`\>

#### Properties

##### code

> `readonly` **code**: `"intermediate_eku_constraint"` \| `"leaf_eku_missing"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### index

> `readonly` **index**: `number`

Defined in: [verify/verify.ts:116](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L116)

Zero-based index into the chain of the certificate that lacks the required EKU.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L114)

Always `false` for failures.

---

### ErrorResult

Defined in: [result/result.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L29)

Failed result with a flattened code/message/details surface for ergonomic matching.

#### Extended by

- [`IndexedErrorResult`](#indexederrorresult)

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails`

##### TError

`TError` _extends_ [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L39)

Machine-readable failure reason, mirrored from `error.code`.

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L43)

Optional structured context for the failure.

##### error

> `readonly` **error**: `TError`

Defined in: [result/result.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L37)

Structured error payload.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L41)

Human-readable diagnostic, mirrored from `error.message`.

##### ok

> `readonly` **ok**: `false`

Defined in: [result/result.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L35)

Always `false` for failures.

---

### ExtensionDecoder

Defined in: [x509/parse.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L193)

User-supplied decoder for a single extension OID.

Register with [`ParseOptions.decoders`](#decoders) or [`ParseOptions.decoderMap`](#decodermap)
to decode custom extensions during parsing.

#### Type Parameters

##### TValue

`TValue`

#### Properties

##### oid

> `readonly` **oid**: `string`

Defined in: [x509/parse.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L195)

OID this decoder handles.

#### Methods

##### decode()

> **decode**(`extension`): `TValue`

Defined in: [x509/parse.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L197)

Decode the raw [`ParsedExtension`](#parsedextension) into a typed value.

###### Parameters

###### extension

[`ParsedExtension`](#parsedextension)

###### Returns

`TValue`

---

### GeneralSubtree

Defined in: [x509/extensions.ts:529](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L529)

A single subtree entry in a Name Constraints permitted/excluded list.

#### Type Parameters

##### TForm

`TForm` _extends_ [`ParsedNameConstraintForm`](#parsednameconstraintform) = \{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}

#### Properties

##### base

> `readonly` **base**: `TForm`

Defined in: [x509/extensions.ts:554](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L554)

The name form that defines this constraint boundary.

---

### ImportEcPublicKeyInput

Defined in: [keys/keys.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L111)

ECDSA variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### kind

> `readonly` **kind**: `"ecdsa"`

Defined in: [keys/keys.ts:113](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L113)

Discriminant selecting ECDSA import.

##### namedCurve

> `readonly` **namedCurve**: [`EcNamedCurve`](#ecnamedcurve)

Defined in: [keys/keys.ts:115](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L115)

NIST curve the key belongs to. Required for EC import.

---

### ImportEd25519PublicKeyInput

Defined in: [keys/keys.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L119)

Ed25519 variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### kind

> `readonly` **kind**: `"ed25519"`

Defined in: [keys/keys.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L121)

Discriminant selecting Ed25519 import.

---

### ImportRsaPublicKeyInput

Defined in: [keys/keys.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L101)

RSA variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### hash?

> `readonly` `optional` **hash**: [`RsaHash`](#rsahash)

Defined in: [keys/keys.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L105)

Hash algorithm. Defaults to `'SHA-256'`.

##### kind

> `readonly` **kind**: `"rsa"`

Defined in: [keys/keys.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L103)

Discriminant selecting RSA import.

##### scheme?

> `readonly` `optional` **scheme**: [`RsaScheme`](#rsascheme)

Defined in: [keys/keys.ts:107](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L107)

Signature padding scheme. Defaults to `'pkcs1-v1_5'`.

---

### IndexedErrorResult

Defined in: [result/result.ts:47](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L47)

Like [ErrorResult](#errorresult) but also carries an index into the collection that was being processed.

#### Extends

- [`ErrorResult`](#errorresult)\<`TCode`, `TDetails`, `TError`\>

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails`

##### TError

`TError` _extends_ [`IndexedMicro509Error`](#indexedmicro509error)\<`TCode`, `TDetails`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L39)

Machine-readable failure reason, mirrored from `error.code`.

###### Inherited from

[`ErrorResult`](#errorresult).[`code`](#code-1)

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L43)

Optional structured context for the failure.

###### Inherited from

[`ErrorResult`](#errorresult).[`details`](#details-1)

##### error

> `readonly` **error**: `TError`

Defined in: [result/result.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L37)

Structured error payload.

###### Inherited from

[`ErrorResult`](#errorresult).[`error`](#error)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:53](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L53)

Zero-based position of the failing item in the input collection.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L41)

Human-readable diagnostic, mirrored from `error.message`.

###### Inherited from

[`ErrorResult`](#errorresult).[`message`](#message-1)

##### ok

> `readonly` **ok**: `false`

Defined in: [result/result.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L35)

Always `false` for failures.

###### Inherited from

[`ErrorResult`](#errorresult).[`ok`](#ok-1)

---

### IndexedMicro509Error

Defined in: [result/result.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L67)

Like [Micro509Error](#micro509error) but includes a positional index for collection-processing APIs.

#### Extends

- [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

#### Extended by

- [`VerifyChainFailure`](#verifychainfailure)

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L70)

Zero-based position of the failing item in the input collection.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

---

### InhibitAnyPolicy

Defined in: [x509/extensions.ts:369](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L369)

RFC 5280 §4.2.1.14 Inhibit anyPolicy.

After `skipCerts` additional certificates in the path, the special
anyPolicy OID is no longer considered a match.

#### Properties

##### skipCerts

> `readonly` **skipCerts**: `number`

Defined in: [x509/extensions.ts:371](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L371)

Number of additional certificates before anyPolicy stops being valid.

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

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

---

### IpServiceIdentityInput

Defined in: [verify/identity.ts:32](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L32)

IP address reference identifier.

#### Properties

##### type

> `readonly` **type**: `"ip"`

Defined in: [verify/identity.ts:34](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L34)

Discriminant for IP address matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L36)

IPv4 or IPv6 address string. Normalized before comparison.

---

### KeyPairMaterial

Defined in: [keys/keys.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L81)

Key pair with convenience export helpers. Returned by [`generateKeyPair`](#generatekeypair).

#### Properties

##### privateKey

> `readonly` **privateKey**: `CryptoKey`

Defined in: [keys/keys.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L85)

The WebCrypto private key (extractable, `sign` usage).

##### publicKey

> `readonly` **publicKey**: `CryptoKey`

Defined in: [keys/keys.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L83)

The WebCrypto public key (extractable, `verify` usage).

#### Methods

##### exportPkcs8Der()

> **exportPkcs8Der**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:91](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L91)

Export the private key as DER-encoded PKCS#8 PrivateKeyInfo.

###### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

##### exportPkcs8Pem()

> **exportPkcs8Pem**(): `Promise`\<`string`\>

Defined in: [keys/keys.ts:93](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L93)

Export the private key as PEM-encoded PKCS#8 PrivateKeyInfo.

###### Returns

`Promise`\<`string`\>

##### exportPrivateJwk()

> **exportPrivateJwk**(): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L97)

Export the private key as a JSON Web Key.

###### Returns

`Promise`\<`JsonWebKey`\>

##### exportPublicJwk()

> **exportPublicJwk**(): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L95)

Export the public key as a JSON Web Key.

###### Returns

`Promise`\<`JsonWebKey`\>

##### exportSpkiDer()

> **exportSpkiDer**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L87)

Export the public key as DER-encoded SubjectPublicKeyInfo.

###### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

##### exportSpkiPem()

> **exportSpkiPem**(): `Promise`\<`string`\>

Defined in: [keys/keys.ts:89](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L89)

Export the public key as PEM-encoded SubjectPublicKeyInfo.

###### Returns

`Promise`\<`string`\>

---

### LegacyPemEncryptionOptions

Defined in: [keys/keys.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L137)

Options for OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM encryption (PKCS#1/SEC1).

#### Properties

##### cipher?

> `readonly` `optional` **cipher**: `"AES-128-CBC"` \| `"AES-192-CBC"` \| `"AES-256-CBC"`

Defined in: [keys/keys.ts:143](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L143)

AES-CBC cipher. Defaults to `'AES-256-CBC'`.

##### iv?

> `readonly` `optional` **iv**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [keys/keys.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L141)

16-byte initialization vector. Random when omitted.

##### password

> `readonly` **password**: `string`

Defined in: [keys/keys.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L139)

Passphrase used to derive the encryption key.

---

### MatchServiceIdentityFailure

Defined in: [verify/identity.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L95)

A failed identity-matching attempt.

#### Extends

- [`Micro509Error`](#micro509error)\<[`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](verify.md#matchserviceidentityfailuredetails)\>

#### Properties

##### code

> `readonly` **code**: [`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: [`MatchServiceIdentityFailureDetails`](verify.md#matchserviceidentityfailuredetails)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/identity.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L98)

Always `false` for failures.

---

### MatchServiceIdentityInput

Defined in: [verify/identity.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L129)

Input for [`matchServiceIdentity`](#matchserviceidentity).

#### Properties

##### certificate

> `readonly` **certificate**: [`ParsedCertificate`](#parsedcertificate)

Defined in: [verify/identity.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L131)

The parsed leaf certificate to check.

##### serviceIdentity

> `readonly` **serviceIdentity**: [`ServiceIdentityInput`](#serviceidentityinput)

Defined in: [verify/identity.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L133)

The reference identifier the client wants to verify.

---

### MatchServiceIdentitySuccess

Defined in: [verify/identity.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L102)

A successful identity match (the certificate covers the requested name).

#### Properties

##### ok

> `readonly` **ok**: `true`

Defined in: [verify/identity.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L104)

Always `true` for success.

##### value

> `readonly` **value**: `undefined`

Defined in: [verify/identity.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L106)

No payload on success — the match itself is the signal.

---

### Micro509Error

Defined in: [result/result.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L57)

Base error shape carried by all failure results in the library.

#### Extended by

- [`VerifyCertificateRevocationListFailure`](revocation.md#verifycertificaterevocationlistfailure)
- [`ValidateCertificateRevocationListFailure`](revocation.md#validatecertificaterevocationlistfailure)
- [`CheckCertificateRevocationAgainstCrlFailure`](revocation.md#checkcertificaterevocationagainstcrlfailure)
- [`VerifyOcspResponseFailure`](revocation.md#verifyocspresponsefailure)
- [`ValidateOcspResponseFailure`](revocation.md#validateocspresponsefailure)
- [`ParsePfxFailure`](#parsepfxfailure)
- [`ParsePkcs7Failure`](#parsepkcs7failure)
- [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)
- [`IndexedMicro509Error`](#indexedmicro509error)
- [`EkuCheckFailure`](#ekucheckfailure)
- [`MatchServiceIdentityFailure`](#matchserviceidentityfailure)
- [`VerifyRequestFailure`](#verifyrequestfailure)

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

---

### NameAttribute

Defined in: [x509/name.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L133)

Single name attribute within a distinguished name.

RFC 5280 / X.501 call this structure an `AttributeTypeAndValue`.

#### See

[RFC 5280 Appendix A.1](https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1)
[`encodeName`](x509.md#encodename) places each attribute in its own single-attribute RDN.\
[`encodeRelativeDistinguishedName`](x509.md#encoderelativedistinguishedname) packs several attributes into one RDN.

#### Properties

##### type

> `readonly` **type**: [`NameFieldKey`](#namefieldkey)

Defined in: [x509/name.ts:135](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L135)

Which attribute type this pair represents.

##### value

> `readonly` **value**: `string`

Defined in: [x509/name.ts:137](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L137)

The string value for this attribute (encoding chosen per field definition).

---

### NameConstraints

Defined in: [x509/extensions.ts:563](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L563)

RFC 5280 §4.2.1.10 Name Constraints.

A CA certificate may restrict the namespace of all subject names in
subsequent certificates in the path.

#### Type Parameters

##### TForm

`TForm` _extends_ [`ParsedNameConstraintForm`](#parsednameconstraintform) = \{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}

#### Properties

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<`TForm`\>[]

Defined in: [x509/extensions.ts:590](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L590)

Names that MUST NOT fall within these subtrees. Takes precedence over permitted.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<`TForm`\>[]

Defined in: [x509/extensions.ts:588](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L588)

Names that MUST fall within these subtrees to be valid.

---

### NameObject

Defined in: [x509/name.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L97)

Convenience object form of an X.501 distinguished name.

Populated fields are emitted in the order defined by
`NAME_OBJECT_ORDER`.\
Each populated field becomes its own single-attribute RDN.

For caller-controlled ordering, pass a [`NameAttribute`](#nameattribute) array to [`encodeName`](x509.md#encodename).\
For multi-valued RDNs, use [`encodeRelativeDistinguishedName`](x509.md#encoderelativedistinguishedname).

#### Properties

##### commonName?

> `readonly` `optional` **commonName**: `string`

Defined in: [x509/name.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L99)

Subject or issuer common name (CN).

##### country?

> `readonly` `optional` **country**: `string`

Defined in: [x509/name.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L105)

ISO 3166 two-letter country code (C). Must be exactly 2 characters.

##### emailAddress?

> `readonly` `optional` **emailAddress**: `string`

Defined in: [x509/name.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L121)

RFC 822 email address. Encoded as IA5String, not UTF-8.

##### givenName?

> `readonly` `optional` **givenName**: `string`

Defined in: [x509/name.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L119)

First / given name (GN).

##### locality?

> `readonly` `optional` **locality**: `string`

Defined in: [x509/name.ts:107](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L107)

City or locality (L).

##### organization?

> `readonly` `optional` **organization**: `string`

Defined in: [x509/name.ts:113](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L113)

Organization name (O).

##### organizationalUnit?

> `readonly` `optional` **organizationalUnit**: `string`

Defined in: [x509/name.ts:115](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L115)

Organizational unit (OU). Deprecated in modern CA practice.

##### serialNumber?

> `readonly` `optional` **serialNumber**: `string`

Defined in: [x509/name.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L103)

Device or entity serial number — not the certificate serial.

##### state?

> `readonly` `optional` **state**: `string`

Defined in: [x509/name.ts:109](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L109)

State or province (ST).

##### street?

> `readonly` `optional` **street**: `string`

Defined in: [x509/name.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L111)

Street address.

##### surname?

> `readonly` `optional` **surname**: `string`

Defined in: [x509/name.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L101)

Subject surname (SN).

##### title?

> `readonly` `optional` **title**: `string`

Defined in: [x509/name.ts:117](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L117)

Job title or functional designation.

---

### ParsedBitFlags

Defined in: [internal/x509/extension-bits.ts:21](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/x509/extension-bits.ts#L21)

Decoded BIT STRING flags with DER conformance metadata.

`flags` contains the recognized flag values with any non-zero padding bits
masked out. `nonZeroPadding` is `true` when the original BIT STRING encoding
had non-zero bits in positions that DER (X.690 §11.2.2) requires to be zero.
Verification layers can use this signal to reject non-conformant encodings.

#### Type Parameters

##### T

`T` _extends_ `string`

#### Properties

##### flags

> `readonly` **flags**: readonly `T`[]

Defined in: [internal/x509/extension-bits.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/x509/extension-bits.ts#L23)

Decoded flag values, padding bits masked.

##### nonZeroPadding

> `readonly` **nonZeroPadding**: `boolean`

Defined in: [internal/x509/extension-bits.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/x509/extension-bits.ts#L25)

`true` when the original encoding had non-zero padding bits (DER violation).

---

### ParsedCertificate

Defined in: [x509/parse.ts:265](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L265)

A fully decoded X.509 certificate.

Built-in extensions (basicConstraints, keyUsage, etc.) are decoded into
typed fields automatically.\
Supply [`ParseOptions`](#parseoptions) to also decode custom extensions.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Properties

##### authorityInfoAccess?

> `readonly` `optional` **authorityInfoAccess**: readonly [`AuthorityInformationAccess`](#authorityinformationaccess)[]

Defined in: [x509/parse.ts:321](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L321)

Decoded Authority Information Access — OCSP and CA Issuer URIs (RFC 5280 §4.2.2.1).

##### authorityKeyIdentifier?

> `readonly` `optional` **authorityKeyIdentifier**: `string`

Defined in: [x509/parse.ts:331](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L331)

Hex-encoded Authority Key Identifier (RFC 5280 §4.2.1.1).

##### basicConstraints?

> `readonly` `optional` **basicConstraints**: [`BasicConstraints`](#basicconstraints)

Defined in: [x509/parse.ts:303](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L303)

Decoded Basic Constraints (RFC 5280 §4.2.1.9).

##### certificatePolicies?

> `readonly` `optional` **certificatePolicies**: [`CertificatePolicies`](#certificatepolicies-3)

Defined in: [x509/parse.ts:313](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L313)

Decoded Certificate Policies (RFC 5280 §4.2.1.4).

##### crlDistributionPoints?

> `readonly` `optional` **crlDistributionPoints**: readonly [`ParsedDistributionPoint`](#parseddistributionpoint)[]

Defined in: [x509/parse.ts:323](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L323)

Decoded CRL Distribution Points (RFC 5280 §4.2.1.13).

##### decodedExtensionMap?

> `readonly` `optional` **decodedExtensionMap**: [`DecodedExtensionMap`](#decodedextensionmap-2)\<`TMap`\>

Defined in: [x509/parse.ts:327](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L327)

Custom-decoded extensions from [`ParseOptions.decoderMap`](#decodermap), keyed by map key.

##### decodedExtensions?

> `readonly` `optional` **decodedExtensions**: readonly [`DecodedExtensionValue`](#decodedextensionvalue)\<`unknown`\>[]

Defined in: [x509/parse.ts:325](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L325)

Custom-decoded extensions from [`ParseOptions.decoders`](#decoders).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [x509/parse.ts:267](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L267)

Complete DER encoding of the certificate (copied from the input).

##### extendedKeyUsage?

> `readonly` `optional` **extendedKeyUsage**: readonly [`ExtendedKeyUsage`](#extendedkeyusage-3)[]

Defined in: [x509/parse.ts:307](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L307)

Decoded Extended Key Usage purposes (RFC 5280 §4.2.1.12).

##### extensions

> `readonly` **extensions**: readonly [`ParsedExtension`](#parsedextension)[]

Defined in: [x509/parse.ts:301](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L301)

All extensions as raw [`ParsedExtension`](#parsedextension)s, in certificate order.

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: [`InhibitAnyPolicy`](#inhibitanypolicy-1)

Defined in: [x509/parse.ts:319](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L319)

Decoded Inhibit anyPolicy (RFC 5280 §4.2.1.14).

##### issuer

> `readonly` **issuer**: [`ParsedName`](#parsedname)

Defined in: [x509/parse.ts:279](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L279)

Distinguished name of the certificate issuer.

##### keyUsage?

> `readonly` `optional` **keyUsage**: [`ParsedBitFlags`](#parsedbitflags)\<[`KeyUsage`](#keyusage-3)\>

Defined in: [x509/parse.ts:305](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L305)

Decoded Key Usage bit flags (RFC 5280 §4.2.1.3).

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`NameConstraints`](#nameconstraints-1)\<[`ParsedNameConstraintForm`](#parsednameconstraintform)\>

Defined in: [x509/parse.ts:311](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L311)

Decoded Name Constraints (RFC 5280 §4.2.1.10).

##### notAfter

> `readonly` **notAfter**: `Date`

Defined in: [x509/parse.ts:285](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L285)

End of the certificate validity period.

##### notBefore

> `readonly` **notBefore**: `Date`

Defined in: [x509/parse.ts:283](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L283)

Start of the certificate validity period.

##### policyConstraints?

> `readonly` `optional` **policyConstraints**: [`PolicyConstraints`](#policyconstraints-3)

Defined in: [x509/parse.ts:317](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L317)

Decoded Policy Constraints (RFC 5280 §4.2.1.11).

##### policyMappings?

> `readonly` `optional` **policyMappings**: [`PolicyMappings`](#policymappings-3)

Defined in: [x509/parse.ts:315](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L315)

Decoded Policy Mappings (RFC 5280 §4.2.1.5).

##### publicKeyAlgorithmName

> `readonly` **publicKeyAlgorithmName**: `string`

Defined in: [x509/parse.ts:295](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L295)

Human-readable public key algorithm name (e.g. `"EC P-256"`).

##### publicKeyAlgorithmOid

> `readonly` **publicKeyAlgorithmOid**: `string`

Defined in: [x509/parse.ts:293](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L293)

OID of the subject's public key algorithm (e.g. `"1.2.840.10045.2.1"` for EC).

##### publicKeyAlgorithmParametersDer?

> `readonly` `optional` **publicKeyAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/parse.ts:297](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L297)

DER-encoded parameters for the public key algorithm. Absent when implicit.

##### publicKeyParametersOid?

> `readonly` `optional` **publicKeyParametersOid**: `string`

Defined in: [x509/parse.ts:299](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L299)

OID of the named curve or other key sub-parameter, when present.

##### serialNumberHex

> `readonly` **serialNumberHex**: `string`

Defined in: [x509/parse.ts:271](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L271)

Hex-encoded serial number assigned by the issuing CA.

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [x509/parse.ts:289](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L289)

Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`).

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [x509/parse.ts:287](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L287)

OID of the algorithm used to sign this certificate (e.g. `"1.2.840.113549.1.1.11"` for SHA-256 with RSA).

##### signatureAlgorithmParametersDer?

> `readonly` `optional` **signatureAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/parse.ts:291](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L291)

DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters.

##### signatureValue

> `readonly` **signatureValue**: `Uint8Array`

Defined in: [x509/parse.ts:277](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L277)

Raw signature bytes (BIT STRING content, padding removed).

##### subject

> `readonly` **subject**: [`ParsedName`](#parsedname)

Defined in: [x509/parse.ts:281](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L281)

Distinguished name of the certificate subject.

##### subjectAltNames?

> `readonly` `optional` **subjectAltNames**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/parse.ts:309](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L309)

Decoded Subject Alternative Names (RFC 5280 §4.2.1.6).

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [x509/parse.ts:329](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L329)

Hex-encoded Subject Key Identifier (RFC 5280 §4.2.1.2).

##### subjectPublicKeyInfoDer

> `readonly` **subjectPublicKeyInfoDer**: `Uint8Array`

Defined in: [x509/parse.ts:275](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L275)

DER encoding of the SubjectPublicKeyInfo, used for key import.

##### tbsCertificateDer

> `readonly` **tbsCertificateDer**: `Uint8Array`

Defined in: [x509/parse.ts:273](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L273)

DER encoding of the TBSCertificate, used for signature verification.

##### version

> `readonly` **version**: `number`

Defined in: [x509/parse.ts:269](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L269)

X.509 version number (1, 2, or 3). Almost always 3.

---

### ParsedCertificateSigningRequest

Defined in: [x509/parse.ts:340](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L340)

A fully decoded PKCS#10 Certificate Signing Request.

Extension fields mirror [`ParsedCertificate`](#parsedcertificate) but come from the
CSR's extensionRequest attribute rather than the v3 extensions block.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Properties

##### authorityInfoAccess?

> `readonly` `optional` **authorityInfoAccess**: readonly [`AuthorityInformationAccess`](#authorityinformationaccess)[]

Defined in: [x509/parse.ts:388](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L388)

Decoded Authority Information Access from the extensionRequest attribute.

##### basicConstraints?

> `readonly` `optional` **basicConstraints**: [`BasicConstraints`](#basicconstraints)

Defined in: [x509/parse.ts:370](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L370)

Decoded Basic Constraints from the extensionRequest attribute.

##### certificatePolicies?

> `readonly` `optional` **certificatePolicies**: [`CertificatePolicies`](#certificatepolicies-3)

Defined in: [x509/parse.ts:380](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L380)

Decoded Certificate Policies from the extensionRequest attribute.

##### certificationRequestInfoDer

> `readonly` **certificationRequestInfoDer**: `Uint8Array`

Defined in: [x509/parse.ts:346](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L346)

DER encoding of the CertificationRequestInfo, used for signature verification.

##### crlDistributionPoints?

> `readonly` `optional` **crlDistributionPoints**: readonly [`ParsedDistributionPoint`](#parseddistributionpoint)[]

Defined in: [x509/parse.ts:390](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L390)

Decoded CRL Distribution Points from the extensionRequest attribute.

##### decodedExtensionMap?

> `readonly` `optional` **decodedExtensionMap**: [`DecodedExtensionMap`](#decodedextensionmap-2)\<`TMap`\>

Defined in: [x509/parse.ts:394](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L394)

Custom-decoded extensions from [`ParseOptions.decoderMap`](#decodermap).

##### decodedExtensions?

> `readonly` `optional` **decodedExtensions**: readonly [`DecodedExtensionValue`](#decodedextensionvalue)\<`unknown`\>[]

Defined in: [x509/parse.ts:392](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L392)

Custom-decoded extensions from [`ParseOptions.decoders`](#decoders).

##### extendedKeyUsage?

> `readonly` `optional` **extendedKeyUsage**: readonly [`ExtendedKeyUsage`](#extendedkeyusage-3)[]

Defined in: [x509/parse.ts:374](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L374)

Decoded Extended Key Usage from the extensionRequest attribute.

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: [`InhibitAnyPolicy`](#inhibitanypolicy-1)

Defined in: [x509/parse.ts:386](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L386)

Decoded Inhibit anyPolicy from the extensionRequest attribute.

##### keyUsage?

> `readonly` `optional` **keyUsage**: [`ParsedBitFlags`](#parsedbitflags)\<[`KeyUsage`](#keyusage-3)\>

Defined in: [x509/parse.ts:372](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L372)

Decoded Key Usage from the extensionRequest attribute.

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`NameConstraints`](#nameconstraints-1)\<[`ParsedNameConstraintForm`](#parsednameconstraintform)\>

Defined in: [x509/parse.ts:378](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L378)

Decoded Name Constraints from the extensionRequest attribute.

##### policyConstraints?

> `readonly` `optional` **policyConstraints**: [`PolicyConstraints`](#policyconstraints-3)

Defined in: [x509/parse.ts:384](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L384)

Decoded Policy Constraints from the extensionRequest attribute.

##### policyMappings?

> `readonly` `optional` **policyMappings**: [`PolicyMappings`](#policymappings-3)

Defined in: [x509/parse.ts:382](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L382)

Decoded Policy Mappings from the extensionRequest attribute.

##### publicKeyAlgorithmName

> `readonly` **publicKeyAlgorithmName**: `string`

Defined in: [x509/parse.ts:362](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L362)

Human-readable public key algorithm name (e.g. `"EC P-256"`).

##### publicKeyAlgorithmOid

> `readonly` **publicKeyAlgorithmOid**: `string`

Defined in: [x509/parse.ts:360](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L360)

OID of the subject's public key algorithm.

##### publicKeyAlgorithmParametersDer?

> `readonly` `optional` **publicKeyAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/parse.ts:364](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L364)

DER-encoded parameters for the public key algorithm.

##### publicKeyParametersOid?

> `readonly` `optional` **publicKeyParametersOid**: `string`

Defined in: [x509/parse.ts:366](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L366)

OID of the named curve or other key sub-parameter, when present.

##### requestedExtensions

> `readonly` **requestedExtensions**: readonly [`ParsedExtension`](#parsedextension)[]

Defined in: [x509/parse.ts:368](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L368)

All requested extensions as raw [`ParsedExtension`](#parsedextension)s.

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [x509/parse.ts:356](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L356)

Human-readable signature algorithm name (e.g. `"ECDSA with SHA-256"`).

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [x509/parse.ts:354](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L354)

OID of the algorithm used to sign this CSR.

##### signatureAlgorithmParametersDer?

> `readonly` `optional` **signatureAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [x509/parse.ts:358](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L358)

DER-encoded parameters for the signature algorithm. Absent for algorithms with no parameters.

##### signatureValue

> `readonly` **signatureValue**: `Uint8Array`

Defined in: [x509/parse.ts:350](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L350)

Raw signature bytes (BIT STRING content, padding removed).

##### subject

> `readonly` **subject**: [`ParsedName`](#parsedname)

Defined in: [x509/parse.ts:352](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L352)

Distinguished name the requester wants on the certificate.

##### subjectAltNames?

> `readonly` `optional` **subjectAltNames**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/parse.ts:376](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L376)

Decoded Subject Alternative Names from the extensionRequest attribute.

##### subjectPublicKeyInfoDer

> `readonly` **subjectPublicKeyInfoDer**: `Uint8Array`

Defined in: [x509/parse.ts:348](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L348)

DER encoding of the SubjectPublicKeyInfo.

##### version

> `readonly` **version**: `number`

Defined in: [x509/parse.ts:344](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L344)

PKCS#10 version number (always 1).

---

### ParsedDistributionPoint

Defined in: [x509/parse.ts:147](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L147)

A decoded DistributionPoint from the CRL Distribution Points extension.

#### Properties

##### crlIssuer?

> `readonly` `optional` **crlIssuer**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/parse.ts:153](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L153)

Entity that signed the CRL, when different from the certificate issuer.

##### distributionPoint?

> `readonly` `optional` **distributionPoint**: [`ParsedDistributionPointName`](#parseddistributionpointname)

Defined in: [x509/parse.ts:149](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L149)

Where to fetch the CRL — a fullName URI or relativeName.

##### reasons?

> `readonly` `optional` **reasons**: [`ParsedBitFlags`](#parsedbitflags)\<[`DistributionPointReason`](x509.md#distributionpointreason)\>

Defined in: [x509/parse.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L151)

Revocation reason subset this distribution point covers. Absent means all reasons.

---

### ParsedDistributionPointName

Defined in: [x509/parse.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L139)

The name component of a CRL Distribution Point (RFC 5280 §4.2.1.13).
Exactly one of `fullName` or `relativeName` will be present.

#### Properties

##### fullName?

> `readonly` `optional` **fullName**: readonly [`SubjectAltName`](#subjectaltname)[]

Defined in: [x509/parse.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L141)

Absolute GeneralName(s) identifying the distribution point.

##### relativeName?

> `readonly` `optional` **relativeName**: [`ParsedRelativeDistinguishedName`](#parsedrelativedistinguishedname)

Defined in: [x509/parse.ts:143](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L143)

Name relative to the CRL issuer's distinguished name.

---

### ParsedExtension

Defined in: [x509/parse.ts:176](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L176)

A raw X.509v3 extension before type-specific decoding.

#### Properties

##### critical

> `readonly` **critical**: `boolean`

Defined in: [x509/parse.ts:180](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L180)

Whether a validator MUST reject the certificate if it cannot process this extension.

##### oid

> `readonly` **oid**: `string`

Defined in: [x509/parse.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L178)

Dotted-decimal OID identifying this extension.

##### valueDer

> `readonly` **valueDer**: `Uint8Array`

Defined in: [x509/parse.ts:182](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L182)

DER-encoded OCTET STRING payload (extnValue).

##### valueHex

> `readonly` **valueHex**: `string`

Defined in: [x509/parse.ts:184](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L184)

Hex-encoded form of `valueDer` for display and comparison.

---

### ParsedIssuingDistributionPoint

Defined in: [x509/parse.ts:160](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L160)

Decoded Issuing Distribution Point CRL extension (RFC 5280 §5.2.5).
Constrains which certificates a CRL covers (scope, reasons, indirection).

#### Properties

##### distributionPoint?

> `readonly` `optional` **distributionPoint**: [`ParsedDistributionPointName`](#parseddistributionpointname)

Defined in: [x509/parse.ts:162](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L162)

Where to fetch this CRL, if specified.

##### indirectCrl?

> `readonly` `optional` **indirectCrl**: `boolean`

Defined in: [x509/parse.ts:170](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L170)

When true, this CRL may contain entries from CAs other than the issuer. Default false.

##### onlyContainsAttributeCerts?

> `readonly` `optional` **onlyContainsAttributeCerts**: `boolean`

Defined in: [x509/parse.ts:172](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L172)

When true, this CRL only covers attribute certificates. Default false.

##### onlyContainsCACerts?

> `readonly` `optional` **onlyContainsCACerts**: `boolean`

Defined in: [x509/parse.ts:166](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L166)

When true, this CRL only covers CA certificates. Default false.

##### onlyContainsUserCerts?

> `readonly` `optional` **onlyContainsUserCerts**: `boolean`

Defined in: [x509/parse.ts:164](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L164)

When true, this CRL only covers end-entity certificates. Default false.

##### onlySomeReasons?

> `readonly` `optional` **onlySomeReasons**: [`ParsedBitFlags`](#parsedbitflags)\<[`DistributionPointReason`](x509.md#distributionpointreason)\>

Defined in: [x509/parse.ts:168](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L168)

Limits the CRL to these revocation reasons. Absent means all reasons.

---

### ParsedName

Defined in: [x509/parse.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L114)

An X.501 Distinguished Name decoded from an issuer or subject field.

Provides three views of the same data: ordered RDNs, a flat attribute
list, and a convenience key-value map for well-known fields.

#### Properties

##### attributes

> `readonly` **attributes**: readonly [`ParsedNameAttribute`](#parsednameattribute)[]

Defined in: [x509/parse.ts:120](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L120)

Flat list of every attribute across all RDNs, in encounter order.

##### derHex

> `readonly` **derHex**: `string`

Defined in: [x509/parse.ts:116](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L116)

Hex-encoded DER of the complete Name SEQUENCE, usable for byte-exact comparisons.

##### rdns

> `readonly` **rdns**: readonly [`ParsedRelativeDistinguishedName`](#parsedrelativedistinguishedname)[]

Defined in: [x509/parse.ts:118](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L118)

Ordered list of RelativeDistinguishedNames, preserving multi-valued RDN structure.

##### values

> `readonly` **values**: `Partial`\<`Record`\<[`NameFieldKey`](#namefieldkey), `string`\>\>

Defined in: [x509/parse.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L122)

First-occurrence map of well-known fields (CN, O, OU, etc.) for quick lookups.

---

### ParsedNameAttribute

Defined in: [x509/parse.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L97)

A single decoded name attribute from an X.501 RelativeDistinguishedName.

RFC 5280 / X.501 call this structure an `AttributeTypeAndValue`.

#### See

[RFC 5280 Appendix A.1](https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1)

#### Properties

##### key?

> `readonly` `optional` **key**: [`NameFieldKey`](#namefieldkey)

Defined in: [x509/parse.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L101)

Friendly key when the OID maps to a well-known field (CN, O, etc.).

##### oid

> `readonly` **oid**: `string`

Defined in: [x509/parse.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L99)

Dotted-decimal OID of the attribute type (e.g. `"2.5.4.3"` for CN).

##### value

> `readonly` **value**: `string`

Defined in: [x509/parse.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L105)

Decoded string content of the attribute value.

##### valueTag

> `readonly` **valueTag**: `number`

Defined in: [x509/parse.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L103)

ASN.1 tag of the value encoding (UTF8String = 0x0c, PrintableString = 0x13, etc.).

---

### ParsedPfx

Defined in: [pkcs/pfx.ts:172](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L172)

Fully decoded PFX container returned by [`parsePfxDer`](#parsepfxder) / [`parsePfxPem`](#parsepfxpem).

#### Properties

##### bags

> `readonly` **bags**: readonly [`ParsedPfxBag`](#parsedpfxbag)[]

Defined in: [pkcs/pfx.ts:174](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L174)

All SafeBags in the PFX, including unknown types.

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pfx.ts:176](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L176)

Convenience: only the parsed certificates extracted from certBag entries.

##### macData?

> `readonly` `optional` **macData**: [`ParsedPkcs12MacData`](pkcs.md#parsedpkcs12macdata)

Defined in: [pkcs/pfx.ts:180](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L180)

MAC verification metadata, present when the PFX includes a MacData block.

##### privateKeys

> `readonly` **privateKeys**: readonly `Uint8Array`\<`ArrayBufferLike`\>[]

Defined in: [pkcs/pfx.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L178)

Convenience: raw PKCS#8 DER of each private key extracted from keyBag entries.

---

### ParsedPfxAttribute

Defined in: [pkcs/pfx.ts:117](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L117)

A single PKCS#12 bag attribute as decoded by [`parsePfxDer`](#parsepfxder).

#### Properties

##### oid

> `readonly` **oid**: `string`

Defined in: [pkcs/pfx.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L119)

Dotted-decimal OID identifying this attribute type.

##### valuesHex

> `readonly` **valuesHex**: readonly `string`[]

Defined in: [pkcs/pfx.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L121)

Hex-encoded DER of each attribute value.

---

### ParsedPfxBagAttributes

Defined in: [pkcs/pfx.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L125)

Decoded bag attributes for a single SafeBag inside a PFX.

#### Properties

##### entries

> `readonly` **entries**: readonly [`ParsedPfxAttribute`](#parsedpfxattribute)[]

Defined in: [pkcs/pfx.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L127)

All raw attributes as OID + hex-encoded values.

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L129)

Decoded BMPString friendly-name attribute, if present.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `string`

Defined in: [pkcs/pfx.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L131)

Hex-encoded localKeyId attribute, if present.

---

### ParsedPkcs7SignedData

Defined in: [pkcs/pkcs7.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L96)

Decoded PKCS#7 SignedData content, including certificates and signer info.

#### Properties

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pkcs7.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L112)

Certificates included in the SignedData certificate set.

##### contentTypeOid

> `readonly` **contentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:100](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L100)

Outer ContentInfo type OID (always `pkcs7-signedData`).

##### der?

> `readonly` `optional` **der**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L98)

Original DER bytes when this object came from [`parsePkcs7SignedDataDer`](#parsepkcs7signeddatader) or PEM parsing.

##### digestAlgorithmNames

> `readonly` **digestAlgorithmNames**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L106)

Human-readable digest algorithm names declared in `digestAlgorithms`.

##### digestAlgorithmOids

> `readonly` **digestAlgorithmOids**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L104)

OIDs of digest algorithms declared in `digestAlgorithms`.

##### encapsulatedContent?

> `readonly` `optional` **encapsulatedContent**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L110)

Raw encapsulated content bytes. Absent in degenerate (certs-only) bags.

##### encapsulatedContentTypeOid

> `readonly` **encapsulatedContentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:108](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L108)

OID of the encapsulated content type (e.g. `pkcs7-data`).

##### signerInfos

> `readonly` **signerInfos**: readonly [`ParsedPkcs7SignerInfo`](#parsedpkcs7signerinfo)[]

Defined in: [pkcs/pkcs7.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L114)

Decoded signer info entries. Empty for degenerate cert bags.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L102)

SignedData version number.

---

### ParsedPkcs7SignerInfo

Defined in: [pkcs/pkcs7.ts:66](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L66)

A single SignerInfo decoded from a PKCS#7 SignedData structure.

#### Properties

##### digestAlgorithmName

> `readonly` **digestAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L78)

Human-readable digest algorithm name (e.g. `"SHA-256"`).

##### digestAlgorithmOid

> `readonly` **digestAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L76)

OID of the digest algorithm used to hash the content.

##### hasSignedAttrs

> `readonly` **hasSignedAttrs**: `boolean`

Defined in: [pkcs/pkcs7.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L90)

Whether this SignerInfo includes authenticated (signed) attributes.

##### issuer?

> `readonly` `optional` **issuer**: [`ParsedName`](#parsedname)

Defined in: [pkcs/pkcs7.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L70)

Parsed issuer distinguished name, if present (issuerAndSerialNumber signer identifier).

##### serialNumberHex?

> `readonly` `optional` **serialNumberHex**: `string`

Defined in: [pkcs/pkcs7.ts:72](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L72)

Hex-encoded serial number used to locate the signer certificate, if present.

##### signature

> `readonly` **signature**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L88)

Raw signature bytes.

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L82)

Human-readable signature algorithm name.

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L80)

OID of the algorithm used to produce the signature.

##### signatureAlgorithmParametersDer?

> `readonly` `optional` **signatureAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L84)

Raw DER of the signature AlgorithmIdentifier parameters, if present.

##### signatureHex

> `readonly` **signatureHex**: `string`

Defined in: [pkcs/pkcs7.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L86)

Hex-encoded raw signature bytes.

##### signedAttrsDer?

> `readonly` `optional` **signedAttrsDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L92)

Raw DER of signedAttrs with original IMPLICIT [0] tag (0xa0). Present only when `hasSignedAttrs` is true.

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [pkcs/pkcs7.ts:74](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L74)

Hex-encoded SubjectKeyIdentifier used to locate the signer certificate, if present.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L68)

CMS SignerInfo version (typically 1 for issuerAndSerialNumber).

---

### ParsedRelativeDistinguishedName

Defined in: [x509/parse.ts:126](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L126)

A single RelativeDistinguishedName SET from an X.501 Name.

#### Properties

##### attributes

> `readonly` **attributes**: readonly [`ParsedNameAttribute`](#parsednameattribute)[]

Defined in: [x509/parse.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L130)

Attributes within this RDN (usually one, but multi-valued RDNs are legal).

##### derHex

> `readonly` **derHex**: `string`

Defined in: [x509/parse.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L128)

Hex-encoded DER of this RDN SET element.

##### values

> `readonly` **values**: `Partial`\<`Record`\<[`NameFieldKey`](#namefieldkey), `string`\>\>

Defined in: [x509/parse.ts:132](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L132)

First-occurrence map of well-known fields within this RDN.

---

### ParseOptions

Defined in: [x509/parse.ts:251](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L251)

Options for [`parseCertificateDer`](#parsecertificateder), [`parseCertificatePem`](#parsecertificatepem),
and CSR parse functions.

Supply custom extension decoders to have their results included in the parsed output alongside
the built-in extensions.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Properties

##### decoderMap?

> `readonly` `optional` **decoderMap**: `TMap`

Defined in: [x509/parse.ts:255](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L255)

Named decoder map; decoded values appear in `decodedExtensionMap` keyed by map key.

##### decoders?

> `readonly` `optional` **decoders**: readonly [`ExtensionDecoder`](#extensiondecoder)\<`unknown`\>[]

Defined in: [x509/parse.ts:253](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L253)

Array of decoders; decoded values appear in `decodedExtensions`.

---

### ParsePfxFailure

Defined in: [pkcs/pfx.ts:191](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L191)

Error payload for a failed PFX parse.

#### Extends

- [`Micro509Error`](#micro509error)\<[`ParsePfxErrorCode`](#parsepfxerrorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePfxErrorCode`](#parsepfxerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pfx.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L193)

Always `false` for failures.

---

### ParsePfxOptions

Defined in: [pkcs/pfx.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L99)

Options for [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

#### Properties

##### macPassword?

> `readonly` `optional` **macPassword**: `string`

Defined in: [pkcs/pfx.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L103)

Separate password for MAC verification. Falls back to `password` when omitted.

##### password?

> `readonly` `optional` **password**: `string`

Defined in: [pkcs/pfx.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L101)

Password used to decrypt PBES2-encrypted ContentInfo entries. Also used for MAC verification when `macPassword` is omitted.

---

### ParsePkcs7Failure

Defined in: [pkcs/pkcs7.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L125)

Error payload for a failed PKCS#7 parse.

#### Extends

- [`Micro509Error`](#micro509error)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pkcs7.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L127)

Always `false` for failures.

---

### Pbes2EncryptionOptions

Defined in: [internal/crypto/pbes2.ts:33](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L33)

Input for `encryptPbes2`.

#### Properties

##### encryption?

> `readonly` `optional` **encryption**: [`Pbes2EncryptionScheme`](#pbes2encryptionscheme)

Defined in: [internal/crypto/pbes2.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L43)

AES key size. Default: `'aes256-cbc'`.

##### iterations?

> `readonly` `optional` **iterations**: `number`

Defined in: [internal/crypto/pbes2.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L37)

PBKDF2 iteration count. Default: `100_000`.

##### iv?

> `readonly` `optional` **iv**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [internal/crypto/pbes2.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L41)

AES-CBC initialization vector. Default: 16 cryptographically random bytes.

##### password

> `readonly` **password**: `string`

Defined in: [internal/crypto/pbes2.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L35)

Password fed to PBKDF2 for key derivation.

##### prf?

> `readonly` `optional` **prf**: [`Pbes2Prf`](#pbes2prf)

Defined in: [internal/crypto/pbes2.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L45)

PBKDF2 PRF. Default: `'hmac-sha256'`.

##### salt?

> `readonly` `optional` **salt**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [internal/crypto/pbes2.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L39)

PBKDF2 salt. Default: 16 cryptographically random bytes.

---

### PemBlock

Defined in: [pem/pem.ts:13](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L13)

A single decoded PEM block with its label, decoded DER bytes, and original PEM text.

#### Properties

##### bytes

> `readonly` **bytes**: `Uint8Array`

Defined in: [pem/pem.ts:17](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L17)

Decoded DER content of this block.

##### label

> `readonly` **label**: `string`

Defined in: [pem/pem.ts:15](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L15)

RFC 7468 label between the `BEGIN` / `END` markers (e.g. `"CERTIFICATE"`).

##### pem

> `readonly` **pem**: `string`

Defined in: [pem/pem.ts:19](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L19)

The original PEM text including `BEGIN`/`END` lines.

---

### PfxBagAttributesInput

Defined in: [pkcs/pfx.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L60)

Optional metadata attached to a certificate or key bag inside a PFX.

#### Properties

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L62)

Human-readable label stored as a BMPString attribute.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pfx.ts:64](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L64)

Opaque identifier linking a certificate bag to its corresponding key bag.

---

### PfxCertificateBagInput

Defined in: [pkcs/pfx.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L68)

A certificate to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:72](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L72)

Optional bag-level attributes (friendly name, local key ID).

##### certificate

> `readonly` **certificate**: [`PfxCertificateSource`](#pfxcertificatesource)

Defined in: [pkcs/pfx.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L70)

Certificate as PEM text or DER bytes.

---

### PfxMaterial

Defined in: [pkcs/pfx.ts:107](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L107)

DER, PEM, and base64 encodings of a PFX container produced by [`createPfx`](#createpfx).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pfx.ts:113](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L113)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pfx.ts:109](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L109)

Raw DER-encoded PFX bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pfx.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L111)

PEM-armored PFX (`-----BEGIN PKCS12-----`).

---

### PfxPrivateKeyBagInput

Defined in: [pkcs/pfx.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L76)

A private key to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L80)

Optional bag-level attributes (friendly name, local key ID).

##### privateKey

> `readonly` **privateKey**: [`PfxPrivateKeySource`](#pfxprivatekeysource)

Defined in: [pkcs/pfx.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L78)

Private key as a WebCrypto `CryptoKey` or raw PKCS#8 DER bytes.

---

### Pkcs7CertBag

Defined in: [pkcs/pkcs7.ts:56](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L56)

DER, PEM, and base64 encodings of a PKCS#7 certificate bag.

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pkcs7.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L62)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:58](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L58)

Raw DER-encoded PKCS#7 structure.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pkcs7.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L60)

PEM-armored PKCS#7 (`-----BEGIN PKCS7-----`).

---

### PolicyConstraints

Defined in: [x509/extensions.ts:356](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L356)

RFC 5280 §4.2.1.11 Policy Constraints.

At least one field must be present. Values are certificate-count
thresholds measured from the current certificate toward the end entity.

#### Properties

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `number`

Defined in: [x509/extensions.ts:360](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L360)

After this many certificates, policy mapping is no longer allowed.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `number`

Defined in: [x509/extensions.ts:358](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L358)

After this many certificates, an acceptable policy must be in the path.

---

### PolicyInformation

Defined in: [x509/extensions.ts:259](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L259)

A single certificate policy: an OID plus optional qualifiers.

#### Properties

##### policyIdentifier

> `readonly` **policyIdentifier**: `string`

Defined in: [x509/extensions.ts:261](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L261)

Dotted-decimal OID of the policy (e.g. `"2.23.140.1.2.1"` for DV).

##### policyQualifiers?

> `readonly` `optional` **policyQualifiers**: readonly [`PolicyQualifierInfo`](#policyqualifierinfo)[]

Defined in: [x509/extensions.ts:263](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L263)

Optional CPS URIs or user notices attached to this policy.

---

### PolicyMapping

Defined in: [x509/extensions.ts:335](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L335)

Maps a policy OID in the issuer's domain to an equivalent OID in the subject's domain.

#### Properties

##### issuerDomainPolicy

> `readonly` **issuerDomainPolicy**: `string`

Defined in: [x509/extensions.ts:337](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L337)

Policy OID as defined by the issuing CA. Must not be anyPolicy.

##### subjectDomainPolicy

> `readonly` **subjectDomainPolicy**: `string`

Defined in: [x509/extensions.ts:339](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L339)

Equivalent policy OID in the subject CA's domain. Must not be anyPolicy.

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

### RsaKeyAlgorithmInput

Defined in: [keys/keys.ts:49](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L49)

RSA variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### hash?

> `readonly` `optional` **hash**: [`RsaHash`](#rsahash)

Defined in: [keys/keys.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L55)

Hash algorithm for the key. Defaults to `'SHA-256'`.

##### kind

> `readonly` **kind**: `"rsa"`

Defined in: [keys/keys.ts:51](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L51)

Discriminant selecting RSA key generation.

##### modulusLength?

> `readonly` `optional` **modulusLength**: `2048` \| `3072` \| `4096`

Defined in: [keys/keys.ts:53](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L53)

RSA modulus size in bits. Defaults to `2048`.

##### scheme?

> `readonly` `optional` **scheme**: [`RsaScheme`](#rsascheme)

Defined in: [keys/keys.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L57)

Signature padding scheme. Defaults to `'pkcs1-v1_5'`.

---

### SelfSignedCertificateResult

Defined in: [x509/certificate.ts:173](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L173)

Result returned by [`createSelfSignedCertificate`](#createselfsignedcertificate).

#### Properties

##### certificate

> `readonly` **certificate**: [`CertificateMaterial`](#certificatematerial)

Defined in: [x509/certificate.ts:177](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L177)

Encoded certificate outputs.

##### keyPair

> `readonly` **keyPair**: [`KeyPairMaterial`](#keypairmaterial)

Defined in: [x509/certificate.ts:181](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L181)

Key pair used to issue the certificate.

---

### SrvServiceIdentityInput

Defined in: [verify/identity.ts:48](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L48)

SRV-ID reference identifier (RFC 4985).

#### Properties

##### type

> `readonly` **type**: `"srv"`

Defined in: [verify/identity.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L50)

Discriminant for SRV-ID matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L52)

SRV name in `_service.domain` form (e.g. `"_imap.example.com"`).

---

### TrustAnchor

Defined in: [verify/verify.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L128)

Bare trust anchor — subject identity and public key material without a
full certificate. Used when the root CA certificate is unavailable but
its key is known. Build from a certificate with [`trustAnchorFromCertificate`](#trustanchorfromcertificate).

#### Properties

##### publicKeyAlgorithmOid

> `readonly` **publicKeyAlgorithmOid**: `string`

Defined in: [verify/verify.ts:134](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L134)

OID of the public key algorithm (e.g. `1.2.840.10045.2.1` for EC).

##### publicKeyParametersOid?

> `readonly` `optional` **publicKeyParametersOid**: `string`

Defined in: [verify/verify.ts:136](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L136)

OID of the key parameters, when algorithm-specific (e.g. named curve OID for EC).

##### subject

> `readonly` **subject**: [`ParsedName`](#parsedname)

Defined in: [verify/verify.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L130)

Parsed subject distinguished name. Used for semantic issuer matching (RFC 5280 §7.1).

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [verify/verify.ts:138](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L138)

Hex-encoded subject key identifier for AKI matching.

##### subjectPublicKeyInfoDer

> `readonly` **subjectPublicKeyInfoDer**: `Uint8Array`

Defined in: [verify/verify.ts:132](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L132)

DER-encoded SubjectPublicKeyInfo used to verify signatures from this anchor.

---

### UriServiceIdentityInput

Defined in: [verify/identity.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L40)

URI-ID reference identifier (RFC 6125 §6.5). Scheme and host are matched.

#### Properties

##### type

> `readonly` **type**: `"uri"`

Defined in: [verify/identity.ts:42](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L42)

Discriminant for URI-ID matching.

##### value

> `readonly` **value**: `string`

Defined in: [verify/identity.ts:44](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L44)

Full URI whose scheme and reg-name will be compared.

---

### ValidateCandidatePathInput

Defined in: [verify/verify.ts:263](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L263)

Input for [`validateCandidatePath`](#validatecandidatepath).

#### Extends

- [`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### allowSelfSignedLeaf?

> `readonly` `optional` **allowSelfSignedLeaf**: `boolean`

Defined in: [verify/verify.ts:277](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L277)

When `true`, allows a self-signed leaf that is also the root. Defaults to `false`.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:273](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L273)

Validation time. Defaults to `new Date()`.

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:271](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L271)

Pre-built certificate chain in leaf-to-root order.

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:269](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L269)

Nested name constraint overrides (takes precedence over flat fields).

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:267](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L267)

Nested policy validation overrides (takes precedence over flat fields).

##### purpose?

> `readonly` `optional` **purpose**: [`VerifyPurpose`](#verifypurpose)

Defined in: [verify/verify.ts:275](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L275)

Leaf purpose constraint to enforce.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

---

### ValidateCandidatePathSuccess

Defined in: [verify/verify.ts:281](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L281)

Success payload from [`validateCandidatePath`](#validatecandidatepath).

#### Properties

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](verify.md#policyvalidationoutcome)

Defined in: [verify/verify.ts:283](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L283)

Final RFC 9618-constrained policy outputs for this validated path.

---

### ValidateForCaInput

Defined in: [verify/verify.ts:428](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L428)

Input for [`validateForCa`](#validateforca). Enforces `basicConstraints.ca` on the leaf.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L237)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:231](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L231)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L229)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:435](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L435)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:433](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L433)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:233](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L233)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L235)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForCodeSigningInput

Defined in: [verify/verify.ts:418](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L418)

Input for [`validateForCodeSigning`](#validateforcodesigning). Enforces `codeSigning` EKU.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L237)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:231](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L231)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L229)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:425](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L425)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:423](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L423)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:233](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L233)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L235)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForTlsClientInput

Defined in: [verify/verify.ts:408](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L408)

Input for [`validateForTlsClient`](#validatefortlsclient). Enforces `clientAuth` EKU.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:237](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L237)

Validation time. Defaults to `new Date()`.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:231](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L231)

Intermediate CA certificates available for path building. Order does not matter.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L229)

End-entity certificate to verify.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:415](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L415)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:413](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L413)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:233](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L233)

Trusted root CA certificates. At least one root or trust anchor must be supplied.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L235)

Bare trust anchors to try when no root certificate matches.

###### Inherited from

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidateForTlsServerInput

Defined in: [verify/verify.ts:385](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L385)

Input for [`validateForTlsServer`](#validatefortlsserver). Enforces `serverAuth` EKU and optional DNS/IP identity matching.

#### Extends

- [`BuildCandidatePathInput`](#buildcandidatepathinput).[`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:402](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L402)

Validation time. Defaults to `new Date()`.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`at`](#at)

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:396](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L396)

Intermediate CA certificates.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`intermediates`](#intermediates)

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:394](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L394)

End-entity certificate to verify.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`leaf`](#leaf)

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:392](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L392)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:390](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L390)

Nested policy validation overrides.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:398](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L398)

Trusted root CA certificates.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`roots`](#roots)

##### serviceIdentity?

> `readonly` `optional` **serviceIdentity**: [`VerifyServiceIdentityInput`](#verifyserviceidentityinput)

Defined in: [verify/verify.ts:404](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L404)

DNS/IP identity to match against the leaf's SAN.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:400](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L400)

Bare trust anchors.

###### Overrides

[`BuildCandidatePathInput`](#buildcandidatepathinput).[`trustAnchors`](#trustanchors)

---

### ValidityInput

Defined in: [x509/certificate.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L45)

Configures the certificate validity window.

If `notAfter` is omitted, it is derived from `notBefore` plus `days`. If both
`notAfter` and `days` are omitted, the certificate is valid for 30 days.

#### Properties

##### days?

> `readonly` `optional` **days**: `number`

Defined in: [x509/certificate.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L61)

Number of days to add to `notBefore` when `notAfter` is omitted.

##### notAfter?

> `readonly` `optional` **notAfter**: `Date`

Defined in: [x509/certificate.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L57)

End of the validity window.

Must be later than `notBefore`.

##### notBefore?

> `readonly` `optional` **notBefore**: `Date`

Defined in: [x509/certificate.ts:51](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L51)

Start of the validity window.

Defaults to the current time.

---

### VerifiedCertificateChain

Defined in: [verify/verify.ts:335](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L335)

Fully verified certificate chain returned on success from [`verifyCertificateChain`](#verifycertificatechain).

#### Properties

##### chain

> `readonly` **chain**: readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [verify/verify.ts:339](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L339)

Full chain in leaf-to-root order.

##### leaf

> `readonly` **leaf**: [`ParsedCertificate`](#parsedcertificate)

Defined in: [verify/verify.ts:337](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L337)

Parsed end-entity certificate.

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](verify.md#policyvalidationoutcome)

Defined in: [verify/verify.ts:343](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L343)

Final RFC 5280 §6 / RFC 9618 constrained policy outputs for this validated path.

##### root

> `readonly` **root**: [`ParsedCertificate`](#parsedcertificate)

Defined in: [verify/verify.ts:341](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L341)

Trusted root that terminates the path.

---

### VerifyCertificateChainInput

Defined in: [verify/verify.ts:309](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L309)

Input for [`verifyCertificateChain`](#verifycertificatechain). Combines path-building, validation, and identity options.

#### Extends

- [`PolicyValidationInput`](#policyvalidationinput).[`InitialNameConstraintsInput`](#initialnameconstraintsinput)

#### Properties

##### allowSelfSignedLeaf?

> `readonly` `optional` **allowSelfSignedLeaf**: `boolean`

Defined in: [verify/verify.ts:331](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L331)

When `true`, allows a self-signed leaf. Defaults to `false`.

##### at?

> `readonly` `optional` **at**: `Date`

Defined in: [verify/verify.ts:325](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L325)

Validation time. Defaults to `new Date()`.

##### excludedSubtrees?

> `readonly` `optional` **excludedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:22](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L22)

Subtrees that no subsequent subject name may fall within. Default: none.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`excludedSubtrees`](#excludedsubtrees)

##### inhibitAnyPolicy?

> `readonly` `optional` **inhibitAnyPolicy**: `boolean`

Defined in: [verify/policy.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L29)

When `true`, the anyPolicy OID is not treated as matching all policies. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitAnyPolicy`](#inhibitanypolicy-4)

##### inhibitPolicyMapping?

> `readonly` `optional` **inhibitPolicyMapping**: `boolean`

Defined in: [verify/policy.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L27)

When `true`, policy mappings in CA certificates are ignored. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`inhibitPolicyMapping`](#inhibitpolicymapping-1)

##### initialPolicySet?

> `readonly` `optional` **initialPolicySet**: readonly `string`[] \| `"any"`

Defined in: [verify/policy.ts:23](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L23)

OIDs the relying party considers acceptable, or `'any'` to accept
whatever the chain asserts. Default: `'any'`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`initialPolicySet`](#initialpolicyset)

##### intermediates?

> `readonly` `optional` **intermediates**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:319](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L319)

Intermediate CA certificates available for path building.

##### leaf

> `readonly` **leaf**: [`CertificateSource`](#certificatesource)

Defined in: [verify/verify.ts:317](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L317)

End-entity certificate to verify.

##### nameConstraints?

> `readonly` `optional` **nameConstraints**: [`InitialNameConstraintsInput`](#initialnameconstraintsinput)

Defined in: [verify/verify.ts:315](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L315)

Nested name constraint overrides.

##### permittedSubtrees?

> `readonly` `optional` **permittedSubtrees**: readonly [`GeneralSubtree`](#generalsubtree)\<\{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}\>[]

Defined in: [verify/name-constraints.ts:20](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/name-constraints.ts#L20)

Subtrees within which all subsequent subject names must fall. Default: unconstrained.

###### Inherited from

[`InitialNameConstraintsInput`](#initialnameconstraintsinput).[`permittedSubtrees`](#permittedsubtrees)

##### policy?

> `readonly` `optional` **policy**: [`PolicyValidationInput`](#policyvalidationinput)

Defined in: [verify/verify.ts:313](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L313)

Nested policy validation overrides.

##### purpose?

> `readonly` `optional` **purpose**: [`VerifyPurpose`](#verifypurpose)

Defined in: [verify/verify.ts:327](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L327)

Leaf purpose constraint to enforce during validation.

##### requireExplicitPolicy?

> `readonly` `optional` **requireExplicitPolicy**: `boolean`

Defined in: [verify/policy.ts:25](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/policy.ts#L25)

When `true`, the chain must assert at least one acceptable policy. Default: `false`.

###### Inherited from

[`PolicyValidationInput`](#policyvalidationinput).[`requireExplicitPolicy`](#requireexplicitpolicy-1)

##### roots

> `readonly` **roots**: readonly [`CertificateSource`](#certificatesource)[]

Defined in: [verify/verify.ts:321](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L321)

Trusted root CA certificates.

##### serviceIdentity?

> `readonly` `optional` **serviceIdentity**: [`VerifyServiceIdentityInput`](#verifyserviceidentityinput)

Defined in: [verify/verify.ts:329](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L329)

DNS/IP/URI/SRV identity to match against the leaf's SAN.

##### trustAnchors?

> `readonly` `optional` **trustAnchors**: readonly [`TrustAnchor`](#trustanchor)[]

Defined in: [verify/verify.ts:323](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L323)

Bare trust anchors to try when no root certificate matches.

---

### VerifyChainFailure

Defined in: [verify/verify.ts:216](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L216)

A chain verification failure with its error code, human message, chain index, and diagnostic details.

#### Extends

- [`IndexedMicro509Error`](#indexedmicro509error)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails)\>

#### Properties

##### code

> `readonly` **code**: [`VerifyErrorCode`](#verifyerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`IndexedMicro509Error`](#indexedmicro509error).[`code`](#code-3)

##### details?

> `readonly` `optional` **details**: [`VerifyFailureDetails`](#verifyfailuredetails)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`IndexedMicro509Error`](#indexedmicro509error).[`details`](#details-3)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L70)

Zero-based position of the failing item in the input collection.

###### Inherited from

[`IndexedMicro509Error`](#indexedmicro509error).[`index`](#index-2)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`IndexedMicro509Error`](#indexedmicro509error).[`message`](#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:219](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L219)

Always `false` for failures.

---

### VerifyFailureDetails

Defined in: [verify/verify.ts:194](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L194)

Diagnostic context attached to every [`VerifyChainFailure`](#verifychainfailure). All fields are optional; presence depends on the error code.

#### Properties

##### actual?

> `readonly` `optional` **actual**: `string`

Defined in: [verify/verify.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L202)

The value actually found.

##### chainCommonNames?

> `readonly` `optional` **chainCommonNames**: readonly `string`[]

Defined in: [verify/verify.ts:204](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L204)

CNs of every certificate in the chain, leaf-first. Present on `no_trusted_root`.

##### commonNameFallbackReason?

> `readonly` `optional` **commonNameFallbackReason**: `"disabled"` \| `"suppressed_by_presented_identifier"` \| `"common_name_missing"` \| `"common_name_mismatch"`

Defined in: [verify/verify.ts:208](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L208)

Why the CN-fallback path was not taken. Set on `common_name_fallback_suppressed`.

##### expected?

> `readonly` `optional` **expected**: `string`

Defined in: [verify/verify.ts:200](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L200)

The value the verifier expected (e.g. a validity window bound or SKI).

##### issuerCommonName?

> `readonly` `optional` **issuerCommonName**: `string`

Defined in: [verify/verify.ts:198](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L198)

CN of the issuer of the offending certificate.

##### presentedIdentifierTypes?

> `readonly` `optional` **presentedIdentifierTypes**: readonly (`"uri"` \| `"dns"` \| `"srv"`)[]

Defined in: [verify/verify.ts:206](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L206)

SAN identifier types the leaf actually presents. Set on identity-match failures.

##### subjectCommonName?

> `readonly` `optional` **subjectCommonName**: `string`

Defined in: [verify/verify.ts:196](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L196)

CN of the certificate that triggered the failure.

---

### VerifyPkcs7SignedDataFailure

Defined in: [pkcs/pkcs7.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L151)

Error payload for a failed [`verifyPkcs7SignedData`](#verifypkcs7signeddata) call.

#### Extends

- [`Micro509Error`](#micro509error)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode) \| `"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pkcs7.ts:160](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L160)

Always `false` for failures.

---

### VerifyRequestFailure

Defined in: [verify/verify.ts:359](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L359)

Failure from [`verifyCertificateSigningRequest`](#verifycertificatesigningrequest).

#### Extends

- [`Micro509Error`](#micro509error)\<`"signature_invalid"` \| `"unsupported_signature_algorithm_parameters"`, [`VerifyFailureDetails`](#verifyfailuredetails)\>

#### Properties

##### code

> `readonly` **code**: `"unsupported_signature_algorithm_parameters"` \| `"signature_invalid"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-5)

##### details?

> `readonly` `optional` **details**: [`VerifyFailureDetails`](#verifyfailuredetails)

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-5)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-5)

##### ok

> `readonly` **ok**: `false`

Defined in: [verify/verify.ts:365](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L365)

Always `false` for failures.

## Type Aliases

### BuildCandidatePathResult

> **BuildCandidatePathResult** = \{ `ok`: `true`; `value`: [`CandidatePath`](#candidatepath); \} \| [`IndexedErrorResult`](#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:251](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L251)

Result of [`buildCandidatePath`](#buildcandidatepath). On success, contains the [`CandidatePath`](#candidatepath).

---

### CertificatePolicies

> **CertificatePolicies** = readonly `object`[]

Defined in: [x509/extensions.ts:267](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L267)

RFC 5280 §4.2.1.4 — array of policy OIDs with optional qualifiers.

---

### CertificateSource

> **CertificateSource** = `string` \| `Uint8Array`

Defined in: [verify/verify.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L78)

PEM string or DER bytes for a certificate. PEM may contain multiple blocks.

---

### CsrSource

> **CsrSource** = `string` \| `Uint8Array`

Defined in: [verify/verify.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L80)

PEM string or DER bytes for a certificate signing request.

---

### DecodedExtensionMap

> **DecodedExtensionMap**\<`TMap`\> = `{ [TKey in keyof TMap]?: TMap[TKey] extends ExtensionDecoder<infer TValue> ? DecodedExtensionValue<TValue> : never }`

Defined in: [x509/parse.ts:228](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L228)

Inferred result type when decoding extensions via an [`ExtensionDecoderMap`](#extensiondecodermap).

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap)

---

### DistributionPoint

> **DistributionPoint** = \{ `crlIssuer?`: readonly [`GeneralName`](#generalname)[]; `distributionPoint`: [`DistributionPointName`](#distributionpointname); `reasons?`: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]; \} \| \{ `crlIssuer`: readonly [`GeneralName`](#generalname)[]; `distributionPoint?`: [`DistributionPointName`](#distributionpointname); `reasons?`: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]; \}

Defined in: [x509/extensions.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L167)

Input for a single CRL Distribution Point (RFC 5280 §4.2.1.13).

At least one of `distributionPoint` or `crlIssuer` must be provided.
The union enforces this constraint at the type level.

#### Type Declaration

\{ `crlIssuer?`: readonly [`GeneralName`](#generalname)[]; `distributionPoint`: [`DistributionPointName`](#distributionpointname); `reasons?`: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]; \}

##### crlIssuer?

> `readonly` `optional` **crlIssuer**: readonly [`GeneralName`](#generalname)[]

Entity that signed the CRL, when different from the cert issuer.

##### distributionPoint

> `readonly` **distributionPoint**: [`DistributionPointName`](#distributionpointname)

Where to fetch the CRL (fullName or relativeName).

##### reasons?

> `readonly` `optional` **reasons**: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]

Revocation reason subset. Absent means all reasons.

\{ `crlIssuer`: readonly [`GeneralName`](#generalname)[]; `distributionPoint?`: [`DistributionPointName`](#distributionpointname); `reasons?`: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]; \}

##### crlIssuer

> `readonly` **crlIssuer**: readonly [`GeneralName`](#generalname)[]

Entity that signed the CRL. Required when `distributionPoint` is absent.

##### distributionPoint?

> `readonly` `optional` **distributionPoint**: [`DistributionPointName`](#distributionpointname)

Where to fetch the CRL. Optional when `crlIssuer` is present.

##### reasons?

> `readonly` `optional` **reasons**: readonly [`DistributionPointReason`](x509.md#distributionpointreason)[]

Revocation reason subset. Absent means all reasons.

---

### EcNamedCurve

> **EcNamedCurve** = `"P-256"` \| `"P-384"` \| `"P-521"`

Defined in: [keys/keys.ts:46](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L46)

NIST elliptic curve for ECDSA keys.

---

### EkuCheckPurpose

> **EkuCheckPurpose** = `"serverAuth"` \| `"clientAuth"` \| `"codeSigning"` \| `"emailProtection"` \| `"timeStamping"` \| `"ocspSigning"`

Defined in: [verify/verify.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L90)

Extended key usage purpose checked by [`checkExtendedKeyUsage`](#checkextendedkeyusage).

---

### EkuCheckResult

> **EkuCheckResult** = \{ `ok`: `true`; `value`: `undefined`; \} \| [`IndexedErrorResult`](#indexederrorresult)\<`"leaf_eku_missing"` \| `"intermediate_eku_constraint"`, `Record`\<`never`, `never`\>, [`EkuCheckFailure`](#ekucheckfailure)\>

Defined in: [verify/verify.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L99)

Result of [`checkExtendedKeyUsage`](#checkextendedkeyusage). Success carries no value; failure identifies the offending certificate.

---

### EncryptedPkcs8Options

> **EncryptedPkcs8Options** = [`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

Defined in: [keys/keys.ts:134](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L134)

PBES2 encryption options for [`exportEncryptedPkcs8Der`](#exportencryptedpkcs8der) and [`exportEncryptedPkcs8Pem`](#exportencryptedpkcs8pem).

---

### ExtendedKeyUsage

> **ExtendedKeyUsage** = `"serverAuth"` \| `"clientAuth"` \| `"codeSigning"` \| `"emailProtection"` \| `"timeStamping"` \| `"ocspSigning"` \| \{ `type`: `"oid"`; `value`: `string`; \}

Defined in: [x509/extensions.ts:641](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L641)

Extended Key Usage — either a well-known purpose string or a custom OID.

---

### ExtensionDecoderMap

> **ExtensionDecoderMap** = `Record`\<`string`, [`ExtensionDecoder`](#extensiondecoder)\<`unknown`\>\>

Defined in: [x509/parse.ts:225](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L225)

String-keyed map of [`ExtensionDecoder`](#extensiondecoder)s, used with [`ParseOptions.decoderMap`](#decodermap).

---

### GeneralName

> **GeneralName** = [`SubjectAltName`](#subjectaltname)

Defined in: [x509/extensions.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L133)

Alias for [`SubjectAltName`](#subjectaltname) — used where RFC 5280 says "GeneralName".

---

### IssuingDistributionPoint

> **IssuingDistributionPoint** = [`IssuingDistributionPointBase`](x509.md#issuingdistributionpointbase) \| [`IssuingDistributionPointForUserCerts`](x509.md#issuingdistributionpointforusercerts) \| [`IssuingDistributionPointForCaCerts`](x509.md#issuingdistributionpointforcacerts) \| [`IssuingDistributionPointForAttributeCerts`](x509.md#issuingdistributionpointforattributecerts)

Defined in: [x509/extensions.ts:239](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L239)

Input for the Issuing Distribution Point CRL extension (RFC 5280 §5.2.5).

The union enforces that at most one of the `onlyContains*` flags is true.

---

### KeyAlgorithmInput

> **KeyAlgorithmInput** = [`RsaKeyAlgorithmInput`](#rsakeyalgorithminput) \| [`EcKeyAlgorithmInput`](#eckeyalgorithminput) \| [`Ed25519KeyAlgorithmInput`](#ed25519keyalgorithminput)

Defined in: [keys/keys.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L75)

Input for [`generateKeyPair`](#generatekeypair). Selects algorithm family and parameters.

---

### KeyUsage

> **KeyUsage** = `"digitalSignature"` \| `"nonRepudiation"` \| `"keyEncipherment"` \| `"dataEncipherment"` \| `"keyAgreement"` \| `"keyCertSign"` \| `"cRLSign"` \| `"encipherOnly"` \| `"decipherOnly"`

Defined in: [x509/extensions.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L68)

RFC 5280 §4.2.1.3 Key Usage bit flag.

Each value corresponds to one bit in the KeyUsage BIT STRING.

#### See

[RFC 5280 §4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)

---

### MatchServiceIdentityErrorCode

> **MatchServiceIdentityErrorCode** = `"subject_alt_name_mismatch"` \| `"common_name_fallback_suppressed"` \| `"service_identity_service_mismatch"` \| `"service_identity_type_unsupported"`

Defined in: [verify/identity.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L70)

Discriminant codes for identity-matching failures.

---

### MatchServiceIdentityResult

> **MatchServiceIdentityResult** = [`MatchServiceIdentitySuccess`](#matchserviceidentitysuccess) \| [`ErrorResult`](#errorresult)\<[`MatchServiceIdentityErrorCode`](#matchserviceidentityerrorcode), [`MatchServiceIdentityFailureDetails`](verify.md#matchserviceidentityfailuredetails), [`MatchServiceIdentityFailure`](#matchserviceidentityfailure)\>

Defined in: [verify/identity.ts:117](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L117)

Result of matching a reference identifier against a certificate's presented identifiers.

---

### NameConstraintForm

> **NameConstraintForm** = \{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \}

Defined in: [x509/extensions.ts:428](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L428)

A name form used as a constraint base in namEConstraints.
Distinct from [`SubjectAltName`](#subjectaltname) because IP constraints carry
address + mask bytes (8 for IPv4, 32 for IPv6) rather than bare addresses.

#### Type Declaration

\{ `type`: `"dns"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"dns"`

DNS domain constraint (dNSName [2]).

##### value

> `readonly` **value**: `string`

Domain suffix, e.g. `".example.com"` or `"example.com"`.

\{ `type`: `"email"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"email"`

Email constraint (rfc822Name [1]).

##### value

> `readonly` **value**: `string`

Email domain or full address pattern.

\{ `type`: `"uri"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"uri"`

URI constraint (uniformResourceIdentifier [6]).

##### value

> `readonly` **value**: `string`

Host or domain component of a URI.

\{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \}

##### addressBytes

> `readonly` **addressBytes**: `Uint8Array`

Network address bytes (4 for IPv4, 16 for IPv6).

##### maskBytes

> `readonly` **maskBytes**: `Uint8Array`

Subnet mask bytes (same length as addressBytes).

##### type

> `readonly` **type**: `"ip"`

IP range constraint (iPAddress [7]).

\{ `derHex`: `string`; `type`: `"directoryName"`; \}

##### derHex

> `readonly` **derHex**: `string`

Hex-encoded DER of the Name SEQUENCE.

##### type

> `readonly` **type**: `"directoryName"`

Directory name constraint (directoryName [4]).

---

### NameFieldKey

> **NameFieldKey** = `"commonName"` \| `"surname"` \| `"serialNumber"` \| `"country"` \| `"locality"` \| `"state"` \| `"street"` \| `"organization"` \| `"organizationalUnit"` \| `"title"` \| `"givenName"` \| `"emailAddress"`

Defined in: [x509/name.ts:73](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L73)

Union of recognized X.501 attribute type shorthand names.

Each key maps to an OID + ASN.1 string encoding in `NAME_FIELD_DEFINITIONS`.

---

### NameInput

> **NameInput** = [`NameObject`](#nameobject) \| readonly [`NameAttribute`](#nameattribute)[]

Defined in: [x509/name.ts:146](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L146)

Input for [`encodeName`](x509.md#encodename).

Accepts either a [`NameObject`](#nameobject) convenience shape or an ordered array of [`NameAttribute`](#nameattribute) pairs.\
Both forms encode one attribute per RDN.

---

### ParsedNameConstraintForm

> **ParsedNameConstraintForm** = \{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `addressBytes`: `Uint8Array`; `maskBytes`: `Uint8Array`; `type`: `"ip"`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \} \| \{ `type`: `"otherName"`; `value`: `Uint8Array`; \} \| \{ `type`: `"x400Address"`; `value`: `Uint8Array`; \} \| \{ `type`: `"ediPartyName"`; `value`: `Uint8Array`; \} \| \{ `type`: `"registeredID"`; `value`: `string`; \}

Defined in: [x509/extensions.ts:489](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L489)

Union of supported and unsupported name constraint forms as produced by parsing.

---

### ParsedPfxBag

> **ParsedPfxBag** = \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `certificate`: [`ParsedCertificate`](#parsedcertificate); `kind`: `"certificate"`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"privateKey"`; `pkcs8Der`: `Uint8Array`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"unknown"`; `valueDer`: `Uint8Array`; \}

Defined in: [pkcs/pfx.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L139)

Discriminated union of SafeBag types decoded from a PFX container.

Use `kind` to narrow: `'certificate'` | `'privateKey'` | `'unknown'`.

#### Type Declaration

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `certificate`: [`ParsedCertificate`](#parsedcertificate); `kind`: `"certificate"`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### certificate

> `readonly` **certificate**: [`ParsedCertificate`](#parsedcertificate)

Parsed certificate from the certBag.

##### kind

> `readonly` **kind**: `"certificate"`

Bag contains an X.509 certificate.

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"privateKey"`; `pkcs8Der`: `Uint8Array`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### kind

> `readonly` **kind**: `"privateKey"`

Bag contains a PKCS#8 private key.

##### pkcs8Der

> `readonly` **pkcs8Der**: `Uint8Array`

Raw DER-encoded PKCS#8 PrivateKeyInfo.

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"unknown"`; `valueDer`: `Uint8Array`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### kind

> `readonly` **kind**: `"unknown"`

Bag type not recognized by this library.

##### valueDer

> `readonly` **valueDer**: `Uint8Array`

Raw DER of the unrecognized bag value.

---

### ParsePfxErrorCode

> **ParsePfxErrorCode** = `"malformed"` \| `"invalid_password"` \| `"password_required"`

Defined in: [pkcs/pfx.ts:188](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L188)

Error codes returned by [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

---

### ParsePfxResult

> **ParsePfxResult** = \{ `ok`: `true`; `value`: [`ParsedPfx`](#parsedpfx); \} \| [`ErrorResult`](#errorresult)\<[`ParsePfxErrorCode`](#parsepfxerrorcode), `Record`\<`never`, `never`\>, [`ParsePfxFailure`](#parsepfxfailure)\>

Defined in: [pkcs/pfx.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L197)

Success-or-failure result from [`parsePfxDer`](#parsepfxder) / [`parsePfxPem`](#parsepfxpem).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPfx`](#parsedpfx); \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: [`ParsedPfx`](#parsedpfx)

Decoded PFX container.

[`ErrorResult`](#errorresult)\<[`ParsePfxErrorCode`](#parsepfxerrorcode), `Record`\<`never`, `never`\>, [`ParsePfxFailure`](#parsepfxfailure)\>

---

### ParsePkcs7CertBagResult

> **ParsePkcs7CertBagResult** = \{ `ok`: `true`; `value`: readonly [`ParsedCertificate`](#parsedcertificate)[]; \} \| [`ErrorResult`](#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

Defined in: [pkcs/pkcs7.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L141)

Success-or-failure result from [`parsePkcs7CertBagDer`](#parsepkcs7certbagder) / [`parsePkcs7CertBagPem`](#parsepkcs7certbagpem).

#### Type Declaration

\{ `ok`: `true`; `value`: readonly [`ParsedCertificate`](#parsedcertificate)[]; \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: readonly [`ParsedCertificate`](#parsedcertificate)[]

Parsed certificates from the cert bag.

[`ErrorResult`](#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

---

### ParsePkcs7ErrorCode

> **ParsePkcs7ErrorCode** = `"malformed"` \| `"not_signed_data"`

Defined in: [pkcs/pkcs7.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L122)

Error codes for PKCS#7 parse failures.

---

### ParsePkcs7SignedDataResult

> **ParsePkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

Defined in: [pkcs/pkcs7.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L131)

Success-or-failure result from [`parsePkcs7SignedDataDer`](#parsepkcs7signeddatader) / [`parsePkcs7SignedDataPem`](#parsepkcs7signeddatapem).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

Decoded SignedData.

[`ErrorResult`](#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

---

### Pbes2EncryptionScheme

> **Pbes2EncryptionScheme** = `"aes128-cbc"` \| `"aes192-cbc"` \| `"aes256-cbc"`

Defined in: [internal/crypto/pbes2.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L27)

AES-CBC key sizes supported by this PBES2 implementation.

---

### Pbes2Prf

> **Pbes2Prf** = `"hmac-sha1"` \| `"hmac-sha256"`

Defined in: [internal/crypto/pbes2.ts:30](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L30)

PBKDF2 pseudo-random function choices. `hmac-sha1` is the RFC default; `hmac-sha256` is preferred.

---

### PfxCertificateSource

> **PfxCertificateSource** = `string` \| `Uint8Array`

Defined in: [pkcs/pfx.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L55)

PEM string or DER bytes for a certificate to include in a PFX bag.

---

### PfxEncryptionOptions

> **PfxEncryptionOptions** = [`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L96)

PBES2 encryption settings for PFX key-bag protection. Alias of [`Pbes2EncryptionOptions`](#pbes2encryptionoptions).

---

### PfxPrivateKeySource

> **PfxPrivateKeySource** = `CryptoKey` \| `Uint8Array`

Defined in: [pkcs/pfx.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L57)

A WebCrypto private key or raw PKCS#8 DER bytes for a PFX key bag.

---

### Pkcs7CertificateSource

> **Pkcs7CertificateSource** = `string` \| `Uint8Array`

Defined in: [pkcs/pkcs7.ts:53](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L53)

PEM text (may contain multiple CERTIFICATE blocks) or raw DER bytes.

---

### PolicyMappings

> **PolicyMappings** = readonly `object`[]

Defined in: [x509/extensions.ts:343](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L343)

RFC 5280 §4.2.1.5 — array of issuer-to-subject policy OID pairs.

---

### PolicyQualifierInfo

> **PolicyQualifierInfo** = [`CpsPolicyQualifierInfo`](x509.md#cpspolicyqualifierinfo) \| [`UserNoticePolicyQualifierInfo`](x509.md#usernoticepolicyqualifierinfo) \| [`CustomPolicyQualifierInfo`](x509.md#custompolicyqualifierinfo)

Defined in: [x509/extensions.ts:329](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L329)

Discriminated union of all supported policy qualifier types.

---

### PrivateKeyImportInput

> **PrivateKeyImportInput** = [`PublicKeyImportInput`](#publickeyimportinput)

Defined in: [keys/keys.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L131)

Algorithm descriptor for private key import functions. Same shape as [`PublicKeyImportInput`](#publickeyimportinput).

---

### PublicKeyImportInput

> **PublicKeyImportInput** = [`ImportRsaPublicKeyInput`](#importrsapublickeyinput) \| [`ImportEcPublicKeyInput`](#importecpublickeyinput) \| [`ImportEd25519PublicKeyInput`](#imported25519publickeyinput)

Defined in: [keys/keys.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L125)

Algorithm descriptor for public key import functions.

---

### RelativeDistinguishedNameInput

> **RelativeDistinguishedNameInput** = readonly [`NameAttribute`](#nameattribute)[]

Defined in: [x509/name.ts:156](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/name.ts#L156)

Input for [`encodeRelativeDistinguishedName`](x509.md#encoderelativedistinguishedname).

Each entry becomes one name attribute inside the RDN's `SET OF`.\
Use this shape for multi-valued RDNs.

#### See

[RFC 5280 Appendix A.1](https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1)

---

### Result

> **Result**\<`TValue`, `TError`\> = \{ `ok`: `true`; `value`: `TValue`; \} \| \{ `error`: `TError`; `ok`: `false`; \}

Defined in: [result/result.ts:14](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L14)

Discriminated `ok` union: either `{ ok: true; value }` or `{ ok: false; error }`.

Every fallible public API in micro509 returns a specialization of this type.

#### Type Parameters

##### TValue

`TValue`

##### TError

`TError`

#### Type Declaration

\{ `ok`: `true`; `value`: `TValue`; \}

##### ok

> `readonly` **ok**: `true`

Operation succeeded.

##### value

> `readonly` **value**: `TValue`

Successful payload.

\{ `error`: `TError`; `ok`: `false`; \}

##### error

> `readonly` **error**: `TError`

Structured error payload.

##### ok

> `readonly` **ok**: `false`

Operation failed.

---

### RsaHash

> **RsaHash** = `"SHA-256"` \| `"SHA-384"` \| `"SHA-512"`

Defined in: [keys/keys.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L40)

Hash algorithm paired with an RSA key.

---

### RsaScheme

> **RsaScheme** = `"pkcs1-v1_5"` \| `"pss"`

Defined in: [keys/keys.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L43)

RSA signature padding scheme.

---

### ServiceIdentityInput

> **ServiceIdentityInput** = [`DnsServiceIdentityInput`](#dnsserviceidentityinput) \| [`IpServiceIdentityInput`](#ipserviceidentityinput) \| [`UriServiceIdentityInput`](#uriserviceidentityinput) \| [`SrvServiceIdentityInput`](#srvserviceidentityinput)

Defined in: [verify/identity.ts:56](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L56)

Discriminated union of all supported reference identifier types.

---

### ServiceIdentityType

> **ServiceIdentityType** = [`ServiceIdentityInput`](#serviceidentityinput)\[`"type"`\]

Defined in: [verify/identity.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L63)

The `type` discriminant values of [`ServiceIdentityInput`](#serviceidentityinput).

---

### SubjectAltName

> **SubjectAltName** = \{ `type`: `"dns"`; `value`: `string`; \} \| \{ `type`: `"ip"`; `value`: `string`; \} \| \{ `type`: `"email"`; `value`: `string`; \} \| \{ `type`: `"uri"`; `value`: `string`; \} \| \{ `type`: `"srv"`; `value`: `string`; \} \| \{ `derHex`: `string`; `type`: `"directoryName"`; \} \| \{ `tag`: `number`; `type`: `"unknown"`; `value`: `Uint8Array`; \}

Defined in: [x509/extensions.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/extensions.ts#L86)

RFC 5280 §4.2.1.6 Subject Alternative Name / GeneralName.

Discriminated union keyed on `type`.

The `'unknown'` variant preserves unrecognized [`GeneralName`](#generalname) tags for round-trip fidelity.

#### Type Declaration

\{ `type`: `"dns"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"dns"`

DNS hostname (dNSName [2]).

##### value

> `readonly` **value**: `string`

Fully-qualified domain name, e.g. `"example.com"`.

\{ `type`: `"ip"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"ip"`

IP address (iPAddress [7]).

##### value

> `readonly` **value**: `string`

Dotted-decimal IPv4 or colon-hex IPv6 string.

\{ `type`: `"email"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"email"`

Email address (rfc822Name [1]).

##### value

> `readonly` **value**: `string`

RFC 822 mailbox, e.g. `"admin@example.com"`.

\{ `type`: `"uri"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"uri"`

URI (uniformResourceIdentifier [6]).

##### value

> `readonly` **value**: `string`

Absolute URI string.

\{ `type`: `"srv"`; `value`: `string`; \}

##### type

> `readonly` **type**: `"srv"`

SRV-ID otherName (id-on-dnsSRV).

##### value

> `readonly` **value**: `string`

SRV service name, e.g. `"_imaps.example.com"`.

\{ `derHex`: `string`; `type`: `"directoryName"`; \}

##### derHex

> `readonly` **derHex**: `string`

Hex-encoded DER of the Name SEQUENCE.

##### type

> `readonly` **type**: `"directoryName"`

X.500 directory name (directoryName [4]).

\{ `tag`: `number`; `type`: `"unknown"`; `value`: `Uint8Array`; \}

##### tag

> `readonly` **tag**: `number`

ASN.1 context tag number.

##### type

> `readonly` **type**: `"unknown"`

Unrecognized [`GeneralName`](#generalname) tag, preserved as raw bytes.

##### value

> `readonly` **value**: `Uint8Array`

Raw content bytes of the element.

---

### ValidateCandidatePathResult

> **ValidateCandidatePathResult** = \{ `ok`: `true`; `policyValidation`: [`PolicyValidationOutcome`](verify.md#policyvalidationoutcome); `value`: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess); \} \| [`IndexedErrorResult`](#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:295](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L295)

Result of [`validateCandidatePath`](#validatecandidatepath).

#### Type Declaration

\{ `ok`: `true`; `policyValidation`: [`PolicyValidationOutcome`](verify.md#policyvalidationoutcome); `value`: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess); \}

##### ok

> `readonly` **ok**: `true`

##### policyValidation

> `readonly` **policyValidation**: [`PolicyValidationOutcome`](verify.md#policyvalidationoutcome)

Shorthand duplicate of `value.policyValidation` for internal forwarding.

##### value

> `readonly` **value**: [`ValidateCandidatePathSuccess`](#validatecandidatepathsuccess)

[`IndexedErrorResult`](#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

---

### VerifyChainResult

> **VerifyChainResult** = \{ `ok`: `true`; `value`: [`VerifiedCertificateChain`](#verifiedcertificatechain); \} \| [`IndexedErrorResult`](#indexederrorresult)\<[`VerifyErrorCode`](#verifyerrorcode), [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyChainFailure`](#verifychainfailure)\>

Defined in: [verify/verify.ts:347](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L347)

Result of [`verifyCertificateChain`](#verifycertificatechain). On success, contains the [`VerifiedCertificateChain`](#verifiedcertificatechain).

---

### VerifyErrorCode

> **VerifyErrorCode** = `"no_trusted_root"` \| `"issuer_not_found"` \| `"signature_invalid"` \| `"certificate_expired"` \| `"ca_required"` \| `"key_cert_sign_required"` \| `"path_length_exceeded"` \| `"authority_key_identifier_mismatch"` \| `"extended_key_usage_invalid"` \| `"subject_alt_name_mismatch"` \| `"common_name_fallback_suppressed"` \| `"self_signed_leaf_not_allowed"` \| `"unrecognized_critical_extension"` \| `"intermediate_eku_constraint"` \| `"policy_processing_not_implemented"` \| `"explicit_policy_required"` \| `"initial_policy_set_not_satisfied"` \| `"initial_name_constraints_not_implemented"` \| `"unsupported_name_constraints"` \| `"name_constraints_violated"` \| `"unsupported_signature_algorithm_parameters"`

Defined in: [verify/verify.ts:170](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L170)

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

### VerifyPkcs7SignedDataResult

> **VerifyPkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](#errorresult)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)\>

Defined in: [pkcs/pkcs7.ts:164](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L164)

Success-or-failure result from [`verifyPkcs7SignedData`](#verifypkcs7signeddata).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \}

##### ok

> `readonly` **ok**: `true`

Verification succeeded.

##### value

> `readonly` **value**: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

The verified SignedData structure.

[`ErrorResult`](#errorresult)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)\>

---

### VerifyPurpose

> **VerifyPurpose** = `"serverAuth"` \| `"clientAuth"` \| `"ca"`

Defined in: [verify/verify.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L87)

High-level purpose applied during path validation to enforce leaf constraints.

---

### VerifyRequestResult

> **VerifyRequestResult** = \{ `ok`: `true`; `value`: [`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest); \} \| [`ErrorResult`](#errorresult)\<`"signature_invalid"` \| `"unsupported_signature_algorithm_parameters"`, [`VerifyFailureDetails`](#verifyfailuredetails), [`VerifyRequestFailure`](#verifyrequestfailure)\>

Defined in: [verify/verify.ts:369](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L369)

Result of [`verifyCertificateSigningRequest`](#verifycertificatesigningrequest). On success, contains the parsed CSR.

---

### VerifyServiceIdentityInput

> **VerifyServiceIdentityInput** = [`DnsServiceIdentityInput`](#dnsserviceidentityinput) \| [`IpServiceIdentityInput`](#ipserviceidentityinput)

Defined in: [verify/identity.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L67)

Subset of identities usable for TLS server verification (DNS and IP only).

## Functions

### buildCandidatePath()

> **buildCandidatePath**(`input`): `Promise`\<[`BuildCandidatePathResult`](#buildcandidatepathresult)\>

Defined in: [verify/verify.ts:613](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L613)

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

### categorizePemBlocks()

> **categorizePemBlocks**(`input`): [`CategorizedPemBlocks`](#categorizedpemblocks)

Defined in: [pem/pem.ts:115](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L115)

Groups PEM blocks by label into well-known PKI categories
(certificates, CSRs, private keys, public keys, and everything else).
Accepts either raw PEM text or pre-split [`PemBlock`](#pemblock) entries.

#### Parameters

##### input

`string` | readonly [`PemBlock`](#pemblock)[]

#### Returns

[`CategorizedPemBlocks`](#categorizedpemblocks)

---

### checkCertificateRevocation()

> **checkCertificateRevocation**(`input`): `Promise`\<[`CheckCertificateRevocationResult`](revocation.md#checkcertificaterevocationresult)\>

Defined in: [revocation/revocation.ts:278](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L278)

Evaluates all provided CRL and OCSP evidence to determine the certificate's
revocation status. Returns the first `revoked` if any, else the first `good`,
else `unknown` with diagnostic details about each indeterminate evidence.

#### Parameters

##### input

[`CheckCertificateRevocationInput`](revocation.md#checkcertificaterevocationinput)

#### Returns

`Promise`\<[`CheckCertificateRevocationResult`](revocation.md#checkcertificaterevocationresult)\>

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

> **checkCertificateRevocationAgainstCrl**(`input`): `Promise`\<[`CheckCertificateRevocationAgainstCrlResult`](revocation.md#checkcertificaterevocationagainstcrlresult)\>

Defined in: [revocation/crl.ts:714](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L714)

End-to-end revocation check: validates the CRL (and optional delta CRL),
verifies applicability via distribution-point and scope matching, then
resolves the certificate's revocation status.

Returns `good` if the serial is absent, `revoked` with date/reason if present,
or an error if the CRL cannot be validated or is non-applicable.

#### Parameters

##### input

[`CheckCertificateRevocationAgainstCrlInput`](revocation.md#checkcertificaterevocationagainstcrlinput)

#### Returns

`Promise`\<[`CheckCertificateRevocationAgainstCrlResult`](revocation.md#checkcertificaterevocationagainstcrlresult)\>

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

### checkExtendedKeyUsage()

> **checkExtendedKeyUsage**(`chain`, `purpose`): [`EkuCheckResult`](#ekucheckresult)

Defined in: [verify/verify.ts:1008](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1008)

Standalone EKU check against a verified certificate chain.
Validates that the leaf has the requested purpose and that
intermediate CA EKU constraints (if present) permit it.

#### Parameters

##### chain

readonly [`ParsedCertificate`](#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

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

### createCertificate()

> **createCertificate**(`input`): `Promise`\<[`CertificateMaterial`](#certificatematerial)\>

Defined in: [x509/certificate.ts:244](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L244)

Create an X.509 certificate signed by `input.signerPrivateKey`.

The certificate encodes `input.subject`, `input.publicKey`, and any supplied
extensions. When `serialNumber` is omitted, a random positive serial number is
generated. When `validity` is omitted, the certificate is valid from now for
30 days.

#### Parameters

##### input

[`CreateCertificateInput`](#createcertificateinput)

Issuer, subject, key, validity, and extension settings.

#### Returns

`Promise`\<[`CertificateMaterial`](#certificatematerial)\>

The encoded certificate material.

#### Example

```ts
const certificate = await createCertificate({
  issuer: { commonName: 'Example Root CA' },
  subject: { commonName: 'example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: issuerKeys.privateKey,
  issuerPublicKey: issuerKeys.publicKey,
});
```

---

### createCertificateRevocationList()

> **createCertificateRevocationList**(`input`): `Promise`\<[`CertificateRevocationListMaterial`](revocation.md#certificaterevocationlistmaterial)\>

Defined in: [revocation/crl.ts:426](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L426)

Signs and encodes an X.509 v2 CRL.

Embeds Authority Key Identifier, CRLNumber, delta CRL indicator,
issuing distribution point, and freshest-CRL extensions as configured.

#### Parameters

##### input

[`CreateCertificateRevocationListInput`](revocation.md#createcertificaterevocationlistinput)

#### Returns

`Promise`\<[`CertificateRevocationListMaterial`](revocation.md#certificaterevocationlistmaterial)\>

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

### createCertificateSigningRequest()

> **createCertificateSigningRequest**(`input`): `Promise`\<[`CsrMaterial`](#csrmaterial)\>

Defined in: [x509/csr.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/csr.ts#L83)

Creates a PKCS#10 Certificate Signing Request signed with the given private key.

The CSR embeds the public key's SPKI, the subject name, and any requested extensions
as attributes. The signature proves possession of the private key.

#### Parameters

##### input

[`CreateCsrInput`](#createcsrinput)

#### Returns

`Promise`\<[`CsrMaterial`](#csrmaterial)\>

#### Example

```ts
import { createCertificateSigningRequest } from 'micro509';

const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify'],
);
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'example.com' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
  extensions: {
    subjectAltNames: [
      { type: 'dns', value: 'example.com' },
    ],
  },
});
console.log(csr.pem);
```

---

### createOcspRequest()

> **createOcspRequest**(`input`): `Promise`\<[`OcspRequestMaterial`](revocation.md#ocsprequestmaterial)\>

Defined in: [revocation/ocsp.ts:370](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L370)

Builds a DER-encoded OCSP request containing one or more CertID entries
and an optional nonce extension.

#### Parameters

##### input

[`CreateOcspRequestInput`](revocation.md#createocsprequestinput)

#### Returns

`Promise`\<[`OcspRequestMaterial`](revocation.md#ocsprequestmaterial)\>

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

> **createOcspResponse**(`input`): `Promise`\<[`OcspResponseMaterial`](revocation.md#ocspresponsematerial)\>

Defined in: [revocation/ocsp.ts:606](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L606)

Signs and encodes an OCSP BasicResponse with a `successful` status.

The responder is identified by key hash (SHA-1 of the signer's SubjectPublicKey).
Use `includedCertificates` to embed the responder's chain for relying parties.

#### Parameters

##### input

[`CreateOcspResponseInput`](revocation.md#createocspresponseinput)

#### Returns

`Promise`\<[`OcspResponseMaterial`](revocation.md#ocspresponsematerial)\>

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

### createPfx()

> **createPfx**(`input`): `Promise`\<[`PfxMaterial`](#pfxmaterial)\>

Defined in: [pkcs/pfx.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L229)

Builds a PKCS#12/PFX archive containing certificates and/or private keys.

When `encryption` is provided, the key-bag ContentInfo is PBES2-encrypted.
When `mac` is provided, a PKCS#12 MAC integrity block is appended.

#### Parameters

##### input

[`CreatePfxInput`](#createpfxinput)

#### Returns

`Promise`\<[`PfxMaterial`](#pfxmaterial)\>

#### Example

```ts
import { createPfx } from 'micro509';

const pfx = await createPfx({
  certificates: [{ certificate: certPem }],
  privateKeys: [{ privateKey: keyPair.privateKey }],
  encryption: { password: 's3cret' },
  mac: { password: 's3cret' },
});
// pfx.der, pfx.pem, pfx.base64
```

---

### createPkcs7CertBagDer()

> **createPkcs7CertBagDer**(`certificates`): `Uint8Array`

Defined in: [pkcs/pkcs7.ts:190](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L190)

Creates a degenerate PKCS#7 SignedData structure containing only certificates (no signers).

Returns the raw DER encoding. Use [`createPkcs7CertBagPem`](#createpkcs7certbagpem) for PEM + base64.

#### Parameters

##### certificates

readonly [`Pkcs7CertificateSource`](#pkcs7certificatesource)[]

#### Returns

`Uint8Array`

---

### createPkcs7CertBagPem()

> **createPkcs7CertBagPem**(`certificates`): [`Pkcs7CertBag`](#pkcs7certbag)

Defined in: [pkcs/pkcs7.ts:205](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L205)

Creates a degenerate PKCS#7 SignedData certificate bag and returns DER, PEM, and base64 forms.

#### Parameters

##### certificates

readonly [`Pkcs7CertificateSource`](#pkcs7certificatesource)[]

#### Returns

[`Pkcs7CertBag`](#pkcs7certbag)

---

### createSelfSignedCertificate()

> **createSelfSignedCertificate**(`input`): `Promise`\<[`SelfSignedCertificateResult`](#selfsignedcertificateresult)\>

Defined in: [x509/certificate.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/certificate.ts#L202)

Create a self-signed certificate.

Reuses `input.keyPair` when provided; otherwise generates a new key pair from
`input.algorithm`. The returned certificate uses `input.subject` as both
issuer and subject.

#### Parameters

##### input

[`CreateSelfSignedCertificateInput`](#createselfsignedcertificateinput)

Certificate subject, key, validity, and extension settings.

#### Returns

`Promise`\<[`SelfSignedCertificateResult`](#selfsignedcertificateresult)\>

The certificate plus the key pair used to sign it.

#### Example

```ts
const { certificate, keyPair } =
  await createSelfSignedCertificate({
    subject: { commonName: 'example.com' },
    algorithm: { kind: 'ecdsa', namedCurve: 'P-256' },
  });
```

---

### decodeExtension()

> **decodeExtension**\<`TValue`\>(`extensions`, `decoder`): `TValue` \| `undefined`

Defined in: [x509/parse.ts:794](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L794)

Decode a single extension using a custom [`ExtensionDecoder`](#extensiondecoder).

#### Type Parameters

##### TValue

`TValue`

#### Parameters

##### extensions

readonly [`ParsedExtension`](#parsedextension)[]

Extension list to search.

##### decoder

[`ExtensionDecoder`](#extensiondecoder)\<`TValue`\>

Decoder whose OID will be matched.

#### Returns

`TValue` \| `undefined`

The decoded value, or `undefined` if the extension is absent.

---

### decodeExtensionMap()

> **decodeExtensionMap**\<`TMap`\>(`extensions`, `decoderMap`): [`DecodedExtensionMap`](#decodedextensionmap-2)\<`TMap`\>

Defined in: [x509/parse.ts:836](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L836)

Decode all matching extensions using a named [`ExtensionDecoderMap`](#extensiondecodermap).

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap)

#### Parameters

##### extensions

readonly [`ParsedExtension`](#parsedextension)[]

Extension list to search.

##### decoderMap

`TMap`

Named decoders. Results are keyed by the same map keys.

#### Returns

[`DecodedExtensionMap`](#decodedextensionmap-2)\<`TMap`\>

---

### decodeExtensions()

> **decodeExtensions**(`extensions`, `decoders`): readonly [`DecodedExtensionValue`](#decodedextensionvalue)\<`unknown`\>[]

Defined in: [x509/parse.ts:811](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L811)

Decode all matching extensions using an array of [`ExtensionDecoder`](#extensiondecoder)s.

#### Parameters

##### extensions

readonly [`ParsedExtension`](#parsedextension)[]

Extension list to search.

##### decoders

readonly [`ExtensionDecoder`](#extensiondecoder)\<`unknown`\>[]

Decoders to apply. Only matching OIDs produce output.

#### Returns

readonly [`DecodedExtensionValue`](#decodedextensionvalue)\<`unknown`\>[]

---

### defineExtensionDecoder()

> **defineExtensionDecoder**\<`TValue`\>(`decoder`): [`ExtensionDecoder`](#extensiondecoder)\<`TValue`\>

Defined in: [x509/parse.ts:206](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L206)

Identity helper that narrows the type of a custom [`ExtensionDecoder`](#extensiondecoder) literal.

#### Type Parameters

##### TValue

`TValue`

#### Parameters

##### decoder

[`ExtensionDecoder`](#extensiondecoder)\<`TValue`\>

Decoder definition to return unchanged.

#### Returns

[`ExtensionDecoder`](#extensiondecoder)\<`TValue`\>

The same decoder, properly typed.

---

### defineExtensionDecoderMap()

> **defineExtensionDecoderMap**\<`TMap`\>(`decoderMap`): `TMap`

Defined in: [x509/parse.ts:218](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L218)

Identity helper that narrows the type of a custom [`ExtensionDecoderMap`](#extensiondecodermap) literal.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap)

#### Parameters

##### decoderMap

`TMap`

Map of named decoders to return unchanged.

#### Returns

`TMap`

The same map, properly typed.

---

### exportBinaryBase64()

> **exportBinaryBase64**(`key`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:312](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L312)

Export a key as raw base64: SPKI for public keys, PKCS#8 for private keys.

#### Parameters

##### key

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedPkcs1Pem()

> **exportEncryptedPkcs1Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:268](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L268)

Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`LegacyPemEncryptionOptions`](#legacypemencryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedPkcs8Der()

> **exportEncryptedPkcs8Der**(`privateKey`, `options`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:235](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L235)

Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportEncryptedPkcs8Pem()

> **exportEncryptedPkcs8Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:245](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L245)

Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedSec1Pem()

> **exportEncryptedSec1Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:291](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L291)

Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`LegacyPemEncryptionOptions`](#legacypemencryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportPkcs1Der()

> **exportPkcs1Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:253](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L253)

Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportPkcs1Pem()

> **exportPkcs1Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:263](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L263)

Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportPkcs8Der()

> **exportPkcs8Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:207](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L207)

Export a private key as DER-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportPkcs8Pem()

> **exportPkcs8Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L230)

Export a private key as a PEM-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportPrivateJwk()

> **exportPrivateJwk**(`privateKey`): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:225](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L225)

Export a private key as a JSON Web Key.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`JsonWebKey`\>

---

### exportPublicJwk()

> **exportPublicJwk**(`publicKey`): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:220](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L220)

Export a public key as a JSON Web Key.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`JsonWebKey`\>

#### Example

```ts
const keys = await generateKeyPair({
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
const jwk = await exportPublicJwk(keys.publicKey);
```

---

### exportSec1Der()

> **exportSec1Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:276](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L276)

Export an EC private key as DER-encoded SEC 1 ECPrivateKey. Throws for non-EC keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportSec1Pem()

> **exportSec1Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:286](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L286)

Export an EC private key as PEM-encoded SEC 1 ECPrivateKey.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportSpkiDer()

> **exportSpkiDer**(`publicKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L202)

Export a public key as DER-encoded SubjectPublicKeyInfo.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportSpkiPem()

> **exportSpkiPem**(`publicKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:307](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L307)

Export a public key as PEM-encoded SubjectPublicKeyInfo.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

#### Example

```ts
const keys = await generateKeyPair();
const pem = await exportSpkiPem(keys.publicKey);
```

---

### findExtension()

> **findExtension**(`extensions`, `oid`): [`ParsedExtension`](#parsedextension) \| `undefined`

Defined in: [x509/parse.ts:780](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L780)

Find a raw extension by OID within a parsed extension list.

#### Parameters

##### extensions

readonly [`ParsedExtension`](#parsedextension)[]

Extension list from a [`ParsedCertificate`](#parsedcertificate) or CSR.

##### oid

`string`

Dotted-decimal OID to look up.

#### Returns

[`ParsedExtension`](#parsedextension) \| `undefined`

The matching extension, or `undefined` if not present.

---

### generateKeyPair()

> **generateKeyPair**(`algorithm?`): `Promise`\<[`KeyPairMaterial`](#keypairmaterial)\>

Defined in: [keys/keys.ts:160](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L160)

Generate an asymmetric key pair for signing and verification.

#### Parameters

##### algorithm?

[`KeyAlgorithmInput`](#keyalgorithminput) = `...`

#### Returns

`Promise`\<[`KeyPairMaterial`](#keypairmaterial)\>

#### Example

```ts
const ecKeys = await generateKeyPair({
  kind: 'ecdsa',
  namedCurve: 'P-384',
});
const rsaKeys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 4096,
});
const edKeys = await generateKeyPair({ kind: 'ed25519' });

// Default: ECDSA P-256
const keys = await generateKeyPair();
const pem = await keys.exportPkcs8Pem();
```

---

### getCertificateOcspResponderUris()

> **getCertificateOcspResponderUris**(`certificate`): readonly `string`[]

Defined in: [revocation/revocation.ts:195](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L195)

Extracts OCSP responder URIs from the certificate's Authority Information Access extension.

#### Parameters

##### certificate

[`RevocationCertificateSource`](revocation.md#revocationcertificatesource)

#### Returns

readonly `string`[]

---

### importEncryptedPkcs1Pem()

> **importEncryptedPkcs1Pem**(`pem`, `password`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:470](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L470)

Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importEncryptedPkcs8Der()

> **importEncryptedPkcs8Der**(`der`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:405](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L405)

Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### password

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importEncryptedPkcs8Pem()

> **importEncryptedPkcs8Pem**(`pem`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:445](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L445)

Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const key = await importEncryptedPkcs8Pem(pem, 'secret', {
  kind: 'rsa',
});
```

---

### importEncryptedSec1Pem()

> **importEncryptedSec1Pem**(`pem`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:510](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L510)

Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs1Der()

> **importPkcs1Der**(`der`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:454](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L454)

Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.

#### Parameters

##### der

`Uint8Array`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs1Pem()

> **importPkcs1Pem**(`pem`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:462](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L462)

Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey (`RSA PRIVATE KEY` label).

#### Parameters

##### pem

`string`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Base64()

> **importPkcs8Base64**(`base64`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:480](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L480)

Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).

#### Parameters

##### base64

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Der()

> **importPkcs8Der**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:365](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L365)

Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Pem()

> **importPkcs8Pem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:397](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L397)

Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### pem

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const key = await importPkcs8Pem(pemString, {
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
```

---

### importPrivateJwk()

> **importPrivateJwk**(`jwk`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:543](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L543)

Import a private signing key from a JSON Web Key.

#### Parameters

##### jwk

`JsonWebKey`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: '...',
  y: '...',
  d: '...',
};
const key = await importPrivateJwk(jwk, {
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
```

---

### importPublicJwk()

> **importPublicJwk**(`jwk`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:520](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L520)

Import a public verification key from a JSON Web Key.

#### Parameters

##### jwk

`JsonWebKey`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSec1Der()

> **importSec1Der**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:494](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L494)

Import an EC private key from DER-encoded SEC 1 ECPrivateKey.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSec1Pem()

> **importSec1Pem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:502](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L502)

Import an EC private key from PEM-encoded SEC 1 ECPrivateKey (`EC PRIVATE KEY` label).

#### Parameters

##### pem

`string`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiBase64()

> **importSpkiBase64**(`base64`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:351](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L351)

Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).

#### Parameters

##### base64

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiDer()

> **importSpkiDer**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:323](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L323)

Import a public key from DER-encoded SubjectPublicKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiPem()

> **importSpkiPem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:343](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L343)

Import a public key from PEM-encoded SubjectPublicKeyInfo.

#### Parameters

##### pem

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### isCertificateRevoked()

> **isCertificateRevoked**(`certificateSerialNumber`, `crl`): `boolean`

Defined in: [revocation/crl.ts:852](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L852)

Quick serial-number lookup — returns `true` if the serial appears in the
CRL's revoked entries. Does **not** validate the CRL or check applicability.

#### Parameters

##### certificateSerialNumber

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### crl

[`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist)

#### Returns

`boolean`

---

### matchCertificateServiceIdentity()

> **matchCertificateServiceIdentity**(`rawCertificate`, `serviceIdentity`): [`MatchServiceIdentityResult`](#matchserviceidentityresult)

Defined in: [verify/identity.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L178)

Compares a reference identifier against a certificate's SAN entries.

Supports DNS (with wildcard matching), IP, URI-ID, and SRV-ID.
For DNS, optionally falls back to subject CN when no SAN of a supported type is present.

#### Parameters

##### rawCertificate

[`ParsedCertificate`](#parsedcertificate)

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

Defined in: [verify/identity.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/identity.ts#L151)

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

### parseCertificateChainPem()

> **parseCertificateChainPem**\<`TMap`\>(`pemBundle`, `options?`): readonly [`ParsedCertificate`](#parsedcertificate)\<`TMap`\>[]

Defined in: [x509/parse.ts:628](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L628)

Decode a PEM bundle containing one or more certificates.

Non-CERTIFICATE blocks (e.g. private keys) are silently skipped.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Parameters

##### pemBundle

`string`

PEM text that may contain multiple CERTIFICATE blocks.

##### options?

[`ParseOptions`](#parseoptions)\<`TMap`\>

Custom extension decoders to apply during parsing.

#### Returns

readonly [`ParsedCertificate`](#parsedcertificate)\<`TMap`\>[]

---

### parseCertificateDer()

> **parseCertificateDer**\<`TMap`\>(`der`, `options?`): [`ParsedCertificate`](#parsedcertificate)\<`TMap`\>

Defined in: [x509/parse.ts:416](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L416)

Decode a DER-encoded X.509 certificate into a [`ParsedCertificate`](#parsedcertificate).

All built-in extensions (basicConstraints, keyUsage, subjectAltNames, etc.)
are decoded automatically.\
Pass [`ParseOptions`](#parseoptions) to also decode custom extensions.

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Parameters

##### der

`Uint8Array`

Raw DER bytes of an X.509 certificate.

##### options?

[`ParseOptions`](#parseoptions)\<`TMap`\>

Custom extension decoders to apply during parsing.

#### Returns

[`ParsedCertificate`](#parsedcertificate)\<`TMap`\>

#### Example

```ts
import { parseCertificateDer } from 'micro509';

const cert = parseCertificateDer(derBytes);
console.log(cert.subject.values.commonName); // "example.com"
console.log(cert.keyUsage); // ["digitalSignature", "keyEncipherment"]
```

---

### parseCertificatePem()

> **parseCertificatePem**\<`TMap`\>(`pem`, `options?`): [`ParsedCertificate`](#parsedcertificate)\<`TMap`\>

Defined in: [x509/parse.ts:589](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L589)

Decode a PEM-encoded X.509 certificate into a [`ParsedCertificate`](#parsedcertificate).

Expects a single `-----BEGIN CERTIFICATE-----` block. For bundles
containing multiple certificates, use [`parseCertificateChainPem`](#parsecertificatechainpem).

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Parameters

##### pem

`string`

PEM string with a CERTIFICATE block.

##### options?

[`ParseOptions`](#parseoptions)\<`TMap`\>

Custom extension decoders to apply during parsing.

#### Returns

[`ParsedCertificate`](#parsedcertificate)\<`TMap`\>

#### Example

```ts
import { parseCertificatePem } from 'micro509';

const cert = parseCertificatePem(pemString);
console.log(cert.issuer.values.organization); // "Let's Encrypt"
console.log(cert.notAfter); // Date
```

---

### parseCertificateRevocationListDer()

> **parseCertificateRevocationListDer**(`der`): [`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:472](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L472)

Decodes a DER-encoded X.509 CRL into a structured [`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist).

Does not verify the signature — call [`verifyCertificateRevocationList`](#verifycertificaterevocationlist) or
[`validateCertificateRevocationList`](#validatecertificaterevocationlist) for that.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist)

---

### parseCertificateRevocationListPem()

> **parseCertificateRevocationListPem**(`pem`): [`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist)

Defined in: [revocation/crl.ts:527](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L527)

Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedCertificateRevocationList`](revocation.md#parsedcertificaterevocationlist)

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

### parseCertificateSigningRequestDer()

> **parseCertificateSigningRequestDer**\<`TMap`\>(`der`, `options?`): [`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest)\<`TMap`\>

Defined in: [x509/parse.ts:641](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L641)

Decode a DER-encoded PKCS#10 CSR into a [`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest).

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Parameters

##### der

`Uint8Array`

Raw DER bytes of a PKCS#10 certificate signing request.

##### options?

[`ParseOptions`](#parseoptions)\<`TMap`\>

Custom extension decoders to apply during parsing.

#### Returns

[`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest)\<`TMap`\>

---

### parseCertificateSigningRequestPem()

> **parseCertificateSigningRequestPem**\<`TMap`\>(`pem`, `options?`): [`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest)\<`TMap`\>

Defined in: [x509/parse.ts:767](https://github.com/kjanat/ts-x509/blob/vitepress/src/x509/parse.ts#L767)

Decode a PEM-encoded PKCS#10 CSR into a [`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest).

#### Type Parameters

##### TMap

`TMap` _extends_ [`ExtensionDecoderMap`](#extensiondecodermap) = `Record`\<`never`, `never`\>

#### Parameters

##### pem

`string`

PEM string with a CERTIFICATE REQUEST block.

##### options?

[`ParseOptions`](#parseoptions)\<`TMap`\>

Custom extension decoders to apply during parsing.

#### Returns

[`ParsedCertificateSigningRequest`](#parsedcertificatesigningrequest)\<`TMap`\>

---

### parseOcspRequestDer()

> **parseOcspRequestDer**(`der`): [`ParsedOcspRequest`](revocation.md#parsedocsprequest)

Defined in: [revocation/ocsp.ts:400](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L400)

Decodes a DER-encoded OCSP request into a structured [`ParsedOcspRequest`](revocation.md#parsedocsprequest).

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedOcspRequest`](revocation.md#parsedocsprequest)

---

### parseOcspRequestPem()

> **parseOcspRequestPem**(`pem`): [`ParsedOcspRequest`](revocation.md#parsedocsprequest)

Defined in: [revocation/ocsp.ts:468](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L468)

Decodes a PEM-encoded OCSP request (`-----BEGIN OCSP REQUEST-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedOcspRequest`](revocation.md#parsedocsprequest)

---

### parseOcspResponseDer()

> **parseOcspResponseDer**(`der`): [`ParsedOcspResponse`](revocation.md#parsedocspresponse)

Defined in: [revocation/ocsp.ts:473](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L473)

Decodes a DER-encoded OCSP response into a structured [`ParsedOcspResponse`](revocation.md#parsedocspresponse). Does not verify the signature.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsedOcspResponse`](revocation.md#parsedocspresponse)

---

### parseOcspResponsePem()

> **parseOcspResponsePem**(`pem`): [`ParsedOcspResponse`](revocation.md#parsedocspresponse)

Defined in: [revocation/ocsp.ts:575](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L575)

Decodes a PEM-encoded OCSP response (`-----BEGIN OCSP RESPONSE-----`).

#### Parameters

##### pem

`string`

#### Returns

[`ParsedOcspResponse`](revocation.md#parsedocspresponse)

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

### parsePfxDer()

> **parsePfxDer**(`der`, `options?`): `Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

Defined in: [pkcs/pfx.ts:290](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L290)

Decodes a DER-encoded PKCS#12/PFX container into its constituent bags.

Returns a result union — check `ok` before accessing `value`.
Encrypted containers require `options.password`. MAC verification uses
`options.macPassword` (falls back to `options.password`).

#### Parameters

##### der

`Uint8Array`

##### options?

[`ParsePfxOptions`](#parsepfxoptions)

#### Returns

`Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

#### Example

```ts
import { parsePfxDer } from 'micro509';

const result = await parsePfxDer(pfxBytes, {
  password: 's3cret',
});
if (result.ok) {
  console.log(result.value.certificates.length);
}
```

---

### parsePfxPem()

> **parsePfxPem**(`pem`, `options?`): `Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

Defined in: [pkcs/pfx.ts:371](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L371)

Decodes a PEM-armored PKCS#12/PFX container. Expects exactly one `PKCS12` block.

Delegates to [`parsePfxDer`](#parsepfxder) after PEM decoding.

#### Parameters

##### pem

`string`

##### options?

[`ParsePfxOptions`](#parsepfxoptions)

#### Returns

`Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

#### Example

```ts
import { parsePfxPem } from 'micro509';

const result = await parsePfxPem(pfxPemString, {
  password: 's3cret',
});
if (result.ok) {
  console.log(result.value.privateKeys.length);
}
```

---

### parsePkcs7CertBagDer()

> **parsePkcs7CertBagDer**(`der`): [`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

Defined in: [pkcs/pkcs7.ts:221](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L221)

Parses a DER-encoded PKCS#7 cert bag, returning the contained certificates.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7CertBagPem()

> **parsePkcs7CertBagPem**(`pem`): [`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

Defined in: [pkcs/pkcs7.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L230)

Parses a PEM-armored PKCS#7 cert bag. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7SignedDataDer()

> **parsePkcs7SignedDataDer**(`der`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:251](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L251)

Decodes a DER-encoded PKCS#7 ContentInfo expecting `signedData` content type.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### parsePkcs7SignedDataPem()

> **parsePkcs7SignedDataPem**(`pem`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:345](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L345)

Decodes a PEM-armored PKCS#7 SignedData. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### pemDecode()

> **pemDecode**(`label`, `pem`): `Uint8Array`

Defined in: [pem/pem.ts:58](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L58)

Extracts and base64-decodes the DER content from a PEM string.
Throws if the `BEGIN`/`END` markers don't match `label`.

#### Parameters

##### label

`string`

Expected PEM type label.

##### pem

`string`

PEM-encoded text (may contain `\r`).

#### Returns

`Uint8Array`

---

### pemEncode()

> **pemEncode**(`label`, `der`): `string`

Defined in: [pem/pem.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L45)

Wraps DER bytes in a PEM envelope with 64-character base64 lines.

#### Parameters

##### label

`string`

PEM type label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).

##### der

`Uint8Array`

Raw DER-encoded content.

#### Returns

`string`

---

### resolveOcspResponderCandidates()

> **resolveOcspResponderCandidates**(`input`): readonly [`OcspResponderCandidate`](revocation.md#ocsprespondercandidate)[]

Defined in: [revocation/revocation.ts:220](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/revocation.ts#L220)

Merges configured OCSP responders with those discovered from the certificate's
AIA extension. Configured responders take priority; duplicates are deduplicated by URI.

#### Parameters

##### input

[`ResolveOcspResponderCandidatesInput`](revocation.md#resolveocsprespondercandidatesinput)

#### Returns

readonly [`OcspResponderCandidate`](revocation.md#ocsprespondercandidate)[]

---

### splitPemBlocks()

> **splitPemBlocks**(`input`): readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L82)

Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns
them as parsed [`PemBlock`](#pemblock) entries. Handles concatenated PEM files
and ignores non-PEM text between blocks.

#### Parameters

##### input

`string`

#### Returns

readonly [`PemBlock`](#pemblock)[]

---

### trustAnchorFromCertificate()

> **trustAnchorFromCertificate**(`certificate`): [`TrustAnchor`](#trustanchor)

Defined in: [verify/verify.ts:1053](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1053)

Extracts a [`TrustAnchor`](#trustanchor) from a parsed certificate, copying the subject, SPKI, and key identifiers.

#### Parameters

##### certificate

[`ParsedCertificate`](#parsedcertificate)

#### Returns

[`TrustAnchor`](#trustanchor)

---

### validateCandidatePath()

> **validateCandidatePath**(`input`): `Promise`\<[`ValidateCandidatePathResult`](#validatecandidatepathresult)\>

Defined in: [verify/verify.ts:808](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L808)

Validates a pre-built certificate chain for time, constraints, policy, and
optionally leaf purpose. Wrap the result of [`buildCandidatePath`](#buildcandidatepath).

#### Parameters

##### input

[`ValidateCandidatePathInput`](#validatecandidatepathinput)

#### Returns

`Promise`\<[`ValidateCandidatePathResult`](#validatecandidatepathresult)\>

---

### validateCertificateRevocationList()

> **validateCertificateRevocationList**(`input`): `Promise`\<[`ValidateCertificateRevocationListResult`](revocation.md#validatecertificaterevocationlistresult)\>

Defined in: [revocation/crl.ts:600](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L600)

Full CRL validation: issuer name match, authority key identifier match,
cRLSign key-usage check, signature verification, and `thisUpdate`/`nextUpdate`
freshness check (with optional clock-skew tolerance).

#### Parameters

##### input

[`ValidateCertificateRevocationListInput`](revocation.md#validatecertificaterevocationlistinput)

#### Returns

`Promise`\<[`ValidateCertificateRevocationListResult`](revocation.md#validatecertificaterevocationlistresult)\>

---

### validateForCa()

> **validateForCa**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:1187](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1187)

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

Defined in: [verify/verify.ts:1167](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1167)

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

Defined in: [verify/verify.ts:1147](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1147)

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

Defined in: [verify/verify.ts:1117](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L1117)

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

### validateOcspResponse()

> **validateOcspResponse**(`input`): `Promise`\<[`ValidateOcspResponseResult`](revocation.md#validateocspresponseresult)\>

Defined in: [revocation/ocsp.ts:762](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L762)

Full OCSP response validation: response status check, signature verification,
responder ID binding (byName or byKeyHash), delegated-responder chain and
ocspSigning EKU checks, `producedAt`/`thisUpdate`/`nextUpdate` freshness,
nonce match, and request-coverage completeness.

#### Parameters

##### input

[`ValidateOcspResponseInput`](revocation.md#validateocspresponseinput)

#### Returns

`Promise`\<[`ValidateOcspResponseResult`](revocation.md#validateocspresponseresult)\>

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

### verifyCertificateChain()

> **verifyCertificateChain**(`input`): `Promise`\<[`VerifyChainResult`](#verifychainresult)\>

Defined in: [verify/verify.ts:859](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L859)

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

### verifyCertificateRevocationList()

> **verifyCertificateRevocationList**(`crl`, `issuerCertificate`): `Promise`\<[`VerifyCertificateRevocationListResult`](revocation.md#verifycertificaterevocationlistresult)\>

Defined in: [revocation/crl.ts:537](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/crl.ts#L537)

Verifies the CRL signature against the issuer certificate's public key.

Does **not** check issuer name match, key-usage, or freshness — use
[`validateCertificateRevocationList`](#validatecertificaterevocationlist) for full validation.

#### Parameters

##### crl

`string` | `Uint8Array`\<`ArrayBufferLike`\>

##### issuerCertificate

`string` | `Uint8Array`\<`ArrayBufferLike`\>

#### Returns

`Promise`\<[`VerifyCertificateRevocationListResult`](revocation.md#verifycertificaterevocationlistresult)\>

---

### verifyCertificateSigningRequest()

> **verifyCertificateSigningRequest**(`input`): `Promise`\<[`VerifyRequestResult`](#verifyrequestresult)\>

Defined in: [verify/verify.ts:928](https://github.com/kjanat/ts-x509/blob/vitepress/src/verify/verify.ts#L928)

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

---

### verifyOcspResponse()

> **verifyOcspResponse**(`response`, `signerCertificate`): `Promise`\<[`VerifyOcspResponseResult`](revocation.md#verifyocspresponseresult)\>

Defined in: [revocation/ocsp.ts:675](https://github.com/kjanat/ts-x509/blob/vitepress/src/revocation/ocsp.ts#L675)

Verifies the OCSP response signature against the given signer certificate.

Does **not** check responder binding, freshness, or nonce — use
[`validateOcspResponse`](#validateocspresponse) for full validation.

#### Parameters

##### response

`string` | `Uint8Array`\<`ArrayBufferLike`\> | [`ParsedOcspResponse`](revocation.md#parsedocspresponse)

##### signerCertificate

[`OcspCertificateSource`](revocation.md#ocspcertificatesource)

#### Returns

`Promise`\<[`VerifyOcspResponseResult`](revocation.md#verifyocspresponseresult)\>

---

### verifyPkcs7SignedData()

> **verifyPkcs7SignedData**(`input`): `Promise`\<[`VerifyPkcs7SignedDataResult`](#verifypkcs7signeddataresult)\>

Defined in: [pkcs/pkcs7.ts:379](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L379)

Verifies all signer signatures in a PKCS#7 SignedData structure.

Accepts PEM text, raw DER, or an already-parsed [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata).
For each signer, locates the matching certificate in the embedded set and
verifies the signature (including signed-attribute digest checks per RFC 5652 Section 5.4).

#### Parameters

##### input

`string` | `Uint8Array`\<`ArrayBufferLike`\> | [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

#### Returns

`Promise`\<[`VerifyPkcs7SignedDataResult`](#verifypkcs7signeddataresult)\>

#### Example

```ts
import { verifyPkcs7SignedData } from 'micro509';

const result = await verifyPkcs7SignedData(pkcs7Pem);
if (result.ok) {
  console.log('all signers verified');
}
```
