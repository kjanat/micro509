# API Reference

This document maps the stable public package surface.

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use subpaths when you want a narrower entrypoint.

## Package entrypoints

| Subpath                     | Purpose                                                     |
| --------------------------- | ----------------------------------------------------------- |
| `micro509`                  | root barrel with the full public API                        |
| `micro509/x509`             | canonical certificate, CSR, name, extension, and parse APIs |
| `micro509/certificate`      | certificate creation helpers                                |
| `micro509/crl`              | CRL create, parse, validate, verify, and revocation lookup  |
| `micro509/csr`              | CSR creation helpers                                        |
| `micro509/extensions`       | certificate and CSR extension input types                   |
| `micro509/identity`         | service identity matching                                   |
| `micro509/keys`             | canonical key generation plus import and export helpers     |
| `micro509/name`             | distinguished-name input types                              |
| `micro509/name-constraints` | initial name-constraint input types                         |
| `micro509/ocsp`             | OCSP create, parse, validate, and verify helpers            |
| `micro509/parse`            | cert and CSR parse plus extension decode helpers            |
| `micro509/pem`              | canonical PEM split, decode, and encode helpers             |
| `micro509/pfx`              | PKCS#12/PFX create and parse helpers                        |
| `micro509/pkcs12-mac`       | PKCS#12 MAC helpers                                         |
| `micro509/pkcs7`            | PKCS#7 cert bag and signedData parse helpers                |
| `micro509/policy`           | policy-validation input and output types                    |
| `micro509/result`           | canonical shared `Result` types and constructors            |
| `micro509/revocation`       | higher-level revocation orchestration helpers               |
| `micro509/verify`           | chain, CSR, purpose, and path validation helpers            |

## Result model

Verification and validation APIs return result objects:

- success: `{ ok: true, value }`
- failure: `{ ok: false, error }`

Most failure objects also mirror `code`, `message`, and domain fields at the top level for migration convenience, but `error` is the canonical payload.

Raw certificate, CSR, CRL, and OCSP parse entrypoints still throw on malformed DER or PEM. Container-oriented helpers like PFX and PKCS#7 parsing return typed failures instead.

## Root exports by area

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
- `SignatureProfileInput`

Notes:

- supports RSA PKCS#1 v1.5, RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, and Ed25519 signers
- `signature` input is optional; current defaults stay stable unless you request an explicit RSA-PSS profile

### CSR

Primary functions:

- `createCertificateSigningRequest()`

Primary types:

- `CreateCsrInput`
- `CsrMaterial`
- `SignatureProfileInput`

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

Primary functions:

- `checkCertificateRevocation()`
- `getCertificateOcspResponderUris()`
- `resolveOcspResponderCandidates()`

Primary types:

- `CheckCertificateRevocationInput`
- `CheckCertificateRevocationResult`
- `RevocationEvidenceInput`
- `RevocationStatus`
- `OcspResponderCandidate`

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

### PFX

Primary functions:

- `createPfx()`
- `parsePfxDer()`
- `parsePfxPem()`

Primary types:

- `CreatePfxInput`
- `PfxMaterial`
- `ParsedPfx`
- `ParsePfxResult`
- `ParsePfxFailure`
- `ParsePfxErrorCode`

### PKCS#12 MAC

Primary functions:

- `createPkcs12MacData()`
- `parsePkcs12MacData()`

Primary types:

- `Pkcs12MacOptions`
- `ParsedPkcs12MacData`

### PKCS#7

Primary functions:

- `createPkcs7CertBagDer()`
- `createPkcs7CertBagPem()`
- `parsePkcs7CertBagDer()`
- `parsePkcs7CertBagPem()`
- `parsePkcs7SignedDataDer()`
- `parsePkcs7SignedDataPem()`
- `verifyPkcs7SignedData()`

Primary types:

- `Pkcs7CertBag`
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

### Shared result types

Canonical advanced home: `micro509/result`

Primary types:

- `Result`
- `Micro509Error`
- `IndexedMicro509Error`

Primary functions:

- `successResult()`
- `errorResult()`
- `micro509Error()`
- `indexedMicro509Error()`
- `indexedErrorResult()`

## Examples

Minimal examples live in [`README.md`].

For deeper scope notes and standards boundaries, see [`docs/PKIX-SCOPE.md`].

[`README.md`]: ../README.md
[`docs/PKIX-SCOPE.md`]: ./PKIX-SCOPE.md
