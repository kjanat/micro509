# API Reference

This document maps the stable public package surface.

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use the domain entrypoints when you want exhaustive advanced types or a narrower import.

## Package entrypoints

| Subpath               | Purpose                                                     |
| --------------------- | ----------------------------------------------------------- |
| `micro509`            | curated workflow-first root import                          |
| `micro509/x509`       | canonical certificate, CSR, name, extension, and parse APIs |
| `micro509/verify`     | canonical verification, identity, policy, and path helpers  |
| `micro509/revocation` | canonical CRL, OCSP, and revocation orchestration APIs      |
| `micro509/pkcs`       | canonical PFX, PKCS#7, and PKCS#12 MAC APIs                 |
| `micro509/keys`       | canonical key generation plus import and export helpers     |
| `micro509/pem`        | canonical PEM split, decode, and encode helpers             |
| `micro509/result`     | canonical shared `Result` types and constructors            |

The file-shaped compatibility subpaths are gone. Import each workflow from its
owner domain.

## Result model

Verification and validation APIs return result objects:

- success: `{ ok: true, value }`
- failure: `{ ok: false, error }`

Most failure objects also mirror `code`, `message`, and domain fields at the top level for migration convenience, but `error` is the canonical payload.

Raw certificate, CSR, CRL, and OCSP parse entrypoints still throw on malformed DER or PEM. Container-oriented helpers like PFX and PKCS#7 parsing return typed failures instead.

## Root exports by area

The root module keeps the common workflows close at hand, but leaves owner-only
advanced seams in their domain modules.

### Certificate

Primary functions:

- `createCertificate()`
- `createSelfSignedCertificate()`

Primary types:

- `CreateCertificateInput`
- `CreateSelfSignedCertificateInput`
- `CertificateMaterial`
- `SelfSignedCertificateResult`
- `ValidityInput`

Notes:

- supports RSA PKCS#1 v1.5, RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, and Ed25519 signers
- `signature` input is optional; current defaults stay stable unless you request an explicit RSA-PSS profile

### CSR

Primary functions:

- `createCertificateSigningRequest()`

Primary types:

- `CreateCsrInput`
- `CsrMaterial`

### Parse

Primary functions:

- `parseCertificateDer()`
- `parseCertificatePem()`
- `parseCertificateChainPem()`
- `parseCertificateSigningRequestDer()`
- `parseCertificateSigningRequestPem()`
- `findExtension()`
- `decodeExtension()`
- `decodeExtensions()`
- `decodeExtensionMap()`
- `defineExtensionDecoder()`
- `defineExtensionDecoderMap()`

Primary types:

- `ParsedCertificate`
- `ParsedCertificateSigningRequest`
- `ParsedExtension`
- `ParsedName`
- `ParseOptions`
- `ExtensionDecoder`
- `ExtensionDecoderMap`
- `DecodedExtensionMap`

Notes:

- parsed certs and CSRs expose typed convenience fields for shipped extensions
- raw `AlgorithmIdentifier` parameter DER is preserved for signature and SPKI metadata when present

### Verify

Canonical advanced home: `micro509/verify`

Primary functions:

- `verifyCertificateChain()`
- `verifyCertificateSigningRequest()`
- `buildCandidatePath()`
- `validateCandidatePath()`
- `validateForTlsServer()`
- `validateForTlsClient()`
- `validateForCodeSigning()`
- `validateForCa()`
- `checkExtendedKeyUsage()`
- `trustAnchorFromCertificate()`

Primary types:

- `VerifyCertificateChainInput`
- `VerifyChainResult`
- `VerifyRequestResult`
- `VerifyErrorCode`
- `VerifyFailureDetails`
- `VerifiedCertificateChain`
- `CandidatePath`
- `TrustAnchor`
- `VerifyPurpose`

Notes:

- chain verification is async and WebCrypto-based
- revocation orchestration is separate; use `micro509/revocation` when you need CRL and OCSP evidence handling
- service-identity matching, policy knobs, and initial name-constraint inputs are owned by this domain

### Identity

Primary functions:

- `matchServiceIdentity()`
- `matchCertificateServiceIdentity()`

Primary types:

- `MatchServiceIdentityInput`
- `MatchServiceIdentityResult`
- `MatchServiceIdentityErrorCode`
- `ServiceIdentityInput`
- `VerifyServiceIdentityInput`

Notes:

- shipped identity forms include DNS-ID, IP-ID, URI-ID, and SRV-ID
- wildcard, IDNA, and opt-in DNS CN compatibility are supported

### Revocation

Canonical advanced home: `micro509/revocation`

Primary functions:

- `checkCertificateRevocation()`
- `getCertificateOcspResponderUris()`
- `resolveOcspResponderCandidates()`
- `createCertificateRevocationList()`
- `parseCertificateRevocationListPem()`
- `validateCertificateRevocationList()`
- `createOcspRequest()`
- `parseOcspResponsePem()`
- `validateOcspResponse()`

Primary types:

- `CheckCertificateRevocationInput`
- `CheckCertificateRevocationResult`
- `RevocationEvidenceInput`
- `RevocationStatus`
- `OcspResponderCandidate`
- `ParsedCertificateRevocationList`
- `ParsedOcspResponse`

Notes:

- combines CRL and OCSP evidence into a higher-level result model

### CRL

Primary functions:

- `createCertificateRevocationList()`
- `parseCertificateRevocationListDer()`
- `parseCertificateRevocationListPem()`
- `validateCertificateRevocationList()`
- `verifyCertificateRevocationList()`
- `checkCertificateRevocationAgainstCrl()`
- `isCertificateRevoked()`

Primary types:

- `CreateCertificateRevocationListInput`
- `CertificateRevocationListMaterial`
- `ParsedCertificateRevocationList`
- `ValidateCertificateRevocationListInput`
- `ValidateCertificateRevocationListResult`
- `VerifyCertificateRevocationListResult`
- `CheckCertificateRevocationAgainstCrlInput`
- `CheckCertificateRevocationAgainstCrlResult`

### OCSP

Primary functions:

- `createOcspRequest()`
- `createOcspResponse()`
- `parseOcspRequestDer()`
- `parseOcspRequestPem()`
- `parseOcspResponseDer()`
- `parseOcspResponsePem()`
- `validateOcspResponse()`
- `verifyOcspResponse()`

Primary types:

- `CreateOcspRequestInput`
- `CreateOcspResponseInput`
- `OcspRequestMaterial`
- `OcspResponseMaterial`
- `ParsedOcspRequest`
- `ParsedOcspResponse`
- `ValidateOcspResponseInput`
- `ValidateOcspResponseResult`
- `VerifyOcspResponseResult`

### Keys

Canonical advanced home: `micro509/keys`

Primary functions:

- `generateKeyPair()`
- `importSpkiDer()` / `importSpkiPem()` / `importSpkiBase64()`
- `importPkcs8Der()` / `importPkcs8Pem()` / `importPkcs8Base64()`
- `importPkcs1Der()` / `importPkcs1Pem()`
- `importSec1Der()` / `importSec1Pem()`
- `importPublicJwk()` / `importPrivateJwk()`
- `importEncryptedPkcs8Der()` / `importEncryptedPkcs8Pem()`
- `importEncryptedPkcs1Pem()` / `importEncryptedSec1Pem()`
- `exportSpkiDer()` / `exportSpkiPem()`
- `exportPkcs8Der()` / `exportPkcs8Pem()`
- `exportPkcs1Der()` / `exportPkcs1Pem()`
- `exportSec1Der()` / `exportSec1Pem()`
- `exportPublicJwk()` / `exportPrivateJwk()`
- `exportEncryptedPkcs8Der()` / `exportEncryptedPkcs8Pem()`
- `exportEncryptedPkcs1Pem()` / `exportEncryptedSec1Pem()`
- `exportBinaryBase64()`

Primary types:

- `KeyAlgorithmInput`
- `RsaKeyAlgorithmInput`
- `EcKeyAlgorithmInput`
- `Ed25519KeyAlgorithmInput`
- `KeyPairMaterial`
- `PublicKeyImportInput`
- `PrivateKeyImportInput`
- `ImportRsaPublicKeyInput`
- `ImportEcPublicKeyInput`
- `ImportEd25519PublicKeyInput`
- `EncryptedPkcs8Options`
- `LegacyPemEncryptionOptions`
- `RsaScheme`

Notes:

- RSA key inputs support `scheme: 'pkcs1-v1_5' | 'pss'`
- ECDSA key inputs support `P-256`, `P-384`, and `P-521`
- encrypted PKCS#8 and PFX use PBES2 AES-CBC with PBKDF2 HMAC-SHA1/HMAC-SHA256
- encrypted traditional PEM supports AES-128-CBC, AES-192-CBC, and AES-256-CBC for RSA and EC private keys

### PEM

Canonical advanced home: `micro509/pem`

Primary functions:

- `splitPemBlocks()`
- `categorizePemBlocks()`
- `pemDecode()`
- `pemEncode()`

Primary types:

- `PemBlock`
- `CategorizedPemBlocks`

Notes:

- raw base64 helpers are internal-only; the public PEM surface stays focused on PEM boundaries

### PKCS

Canonical advanced home: `micro509/pkcs`

Keep advanced PKCS#12 MAC plumbing off the root import; document and import it
through the PKCS domain.

Primary functions:

- `createPfx()`
- `parsePfxDer()`
- `parsePfxPem()`
- `createPkcs7CertBagDer()`
- `createPkcs7CertBagPem()`
- `parsePkcs7CertBagDer()`
- `parsePkcs7CertBagPem()`
- `parsePkcs7SignedDataDer()`
- `parsePkcs7SignedDataPem()`
- `createPkcs12MacData()`
- `parsePkcs12MacData()`
- `verifyPkcs7SignedData()`

Primary types:

- `CreatePfxInput`
- `PfxMaterial`
- `ParsedPfx`
- `ParsePfxResult`
- `ParsePfxFailure`
- `ParsePfxErrorCode`
- `Pkcs7CertBag`
- `Pkcs12MacOptions`
- `ParsedPkcs12MacData`
- `ParsedPkcs7SignedData`
- `ParsedPkcs7SignerInfo`
- `ParsePkcs7CertBagResult`
- `ParsePkcs7SignedDataResult`
- `VerifyPkcs7SignedDataResult`

### Policy

Primary types:

- `PolicyValidationInput`
- `PolicyValidationOutcome`
- `ConstrainedPolicy`

### Extensions and names

Primary types:

- `CertificateExtensionsInput`
- `BasicConstraints`
- `KeyUsage`
- `ExtendedKeyUsage`
- `SubjectAltName`
- `AuthorityInformationAccess`
- `DistributionPoint`
- `NameConstraints`
- `PolicyInformation`
- `PolicyMappings`
- `PolicyConstraints`
- `InhibitAnyPolicy`
- `GeneralName`
- `GeneralSubtree`
- `NameInput`
- `NameAttribute`
- `RelativeDistinguishedNameInput`
- `InitialNameConstraintsInput`

Notes:

- root exports include the common extension and name input types even though the exhaustive advanced surface lives in `micro509/x509`
- initial name-constraint inputs are canonically owned by `micro509/verify`

### Shared result types

Canonical advanced home: `micro509/result`

Primary types:

- `Result`
- `Micro509Error`
- `IndexedMicro509Error`

Primary functions:

- none at root; import the helper constructors from `micro509/result`

## Examples

Minimal examples live in [`README.md`].

For deeper scope notes and standards boundaries, see [`docs/PKIX-SCOPE.md`].

[`README.md`]: ../README.md
[`docs/PKIX-SCOPE.md`]: ./PKIX-SCOPE.md
