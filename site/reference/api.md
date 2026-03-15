# API Surface

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use domain entrypoints for exhaustive advanced types or a narrower import.

## Package entrypoints

| Subpath               | Purpose                                           |
| --------------------- | ------------------------------------------------- |
| `micro509`            | Curated workflow-first root import                |
| `micro509/x509`       | Certificate, CSR, name, extension, and parse APIs |
| `micro509/verify`     | Verification, identity, policy, and path helpers  |
| `micro509/revocation` | CRL, OCSP, and revocation orchestration APIs      |
| `micro509/pkcs`       | PFX, PKCS#7, and PKCS#12 MAC APIs                 |
| `micro509/keys`       | Key generation, import, and export helpers        |
| `micro509/pem`        | PEM split, decode, and encode helpers             |
| `micro509/result`     | Shared `Result` types and constructors            |

## Result model

Verification and validation APIs return result objects:

- Success: `{ ok: true, value }`
- Failure: `{ ok: false, error }`

Most failure objects also mirror `code`, `message`, and domain fields at the top level for convenience, but `error` is the canonical payload.

Raw certificate, CSR, CRL, and OCSP parse entrypoints throw on malformed DER or PEM. Container-oriented helpers like PFX and PKCS#7 parsing return typed failures instead.

## Certificate

| Export                             | Kind     |
| ---------------------------------- | -------- |
| `createCertificate()`              | function |
| `createSelfSignedCertificate()`    | function |
| `CreateCertificateInput`           | type     |
| `CreateSelfSignedCertificateInput` | type     |
| `CertificateMaterial`              | type     |
| `SelfSignedCertificateResult`      | type     |
| `ValidityInput`                    | type     |

## CSR

| Export                              | Kind     |
| ----------------------------------- | -------- |
| `createCertificateSigningRequest()` | function |
| `CreateCsrInput`                    | type     |
| `CsrMaterial`                       | type     |

## Parse

| Export                                | Kind     |
| ------------------------------------- | -------- |
| `parseCertificateDer()`               | function |
| `parseCertificatePem()`               | function |
| `parseCertificateChainPem()`          | function |
| `parseCertificateSigningRequestDer()` | function |
| `parseCertificateSigningRequestPem()` | function |
| `findExtension()`                     | function |
| `decodeExtension()`                   | function |
| `decodeExtensions()`                  | function |
| `decodeExtensionMap()`                | function |
| `defineExtensionDecoder()`            | function |
| `defineExtensionDecoderMap()`         | function |
| `ParsedCertificate`                   | type     |
| `ParsedCertificateSigningRequest`     | type     |
| `ParsedExtension`                     | type     |
| `ParsedName`                          | type     |
| `ParseOptions`                        | type     |
| `ExtensionDecoder`                    | type     |
| `ExtensionDecoderMap`                 | type     |
| `DecodedExtensionMap`                 | type     |

## Verify

| Export                              | Kind     |
| ----------------------------------- | -------- |
| `verifyCertificateChain()`          | function |
| `verifyCertificateSigningRequest()` | function |
| `buildCandidatePath()`              | function |
| `validateCandidatePath()`           | function |
| `validateForTlsServer()`            | function |
| `validateForTlsClient()`            | function |
| `validateForCodeSigning()`          | function |
| `validateForCa()`                   | function |
| `checkExtendedKeyUsage()`           | function |
| `trustAnchorFromCertificate()`      | function |
| `matchServiceIdentity()`            | function |
| `matchCertificateServiceIdentity()` | function |
| `VerifyCertificateChainInput`       | type     |
| `VerifyChainResult`                 | type     |
| `VerifyErrorCode`                   | type     |
| `VerifyFailureDetails`              | type     |
| `VerifiedCertificateChain`          | type     |
| `TrustAnchor`                       | type     |
| `VerifyPurpose`                     | type     |
| `ServiceIdentityInput`              | type     |

## Revocation

| Export                                | Kind     |
| ------------------------------------- | -------- |
| `checkCertificateRevocation()`        | function |
| `createCertificateRevocationList()`   | function |
| `parseCertificateRevocationListPem()` | function |
| `validateCertificateRevocationList()` | function |
| `verifyCertificateRevocationList()`   | function |
| `isCertificateRevoked()`              | function |
| `createOcspRequest()`                 | function |
| `parseOcspResponsePem()`              | function |
| `validateOcspResponse()`              | function |

## Keys

| Export                                                          | Kind     |
| --------------------------------------------------------------- | -------- |
| `generateKeyPair()`                                             | function |
| `importSpkiDer()` / `importSpkiPem()` / `importSpkiBase64()`    | function |
| `importPkcs8Der()` / `importPkcs8Pem()` / `importPkcs8Base64()` | function |
| `importPkcs1Der()` / `importPkcs1Pem()`                         | function |
| `importSec1Der()` / `importSec1Pem()`                           | function |
| `importPublicJwk()` / `importPrivateJwk()`                      | function |
| `importEncryptedPkcs8Der()` / `importEncryptedPkcs8Pem()`       | function |
| `importEncryptedPkcs1Pem()` / `importEncryptedSec1Pem()`        | function |
| `exportSpkiDer()` / `exportSpkiPem()`                           | function |
| `exportPkcs8Der()` / `exportPkcs8Pem()`                         | function |
| `exportPkcs1Der()` / `exportPkcs1Pem()`                         | function |
| `exportSec1Der()` / `exportSec1Pem()`                           | function |
| `exportPublicJwk()` / `exportPrivateJwk()`                      | function |
| `exportEncryptedPkcs8Der()` / `exportEncryptedPkcs8Pem()`       | function |
| `KeyAlgorithmInput`                                             | type     |
| `KeyPairMaterial`                                               | type     |
| `EncryptedPkcs8Options`                                         | type     |

## PKCS

| Export                                                    | Kind     |
| --------------------------------------------------------- | -------- |
| `createPfx()`                                             | function |
| `parsePfxDer()` / `parsePfxPem()`                         | function |
| `createPkcs7CertBagDer()` / `createPkcs7CertBagPem()`     | function |
| `parsePkcs7CertBagDer()` / `parsePkcs7CertBagPem()`       | function |
| `parsePkcs7SignedDataDer()` / `parsePkcs7SignedDataPem()` | function |
| `verifyPkcs7SignedData()`                                 | function |
| `CreatePfxInput`                                          | type     |
| `ParsedPfx`                                               | type     |
| `ParsePfxResult`                                          | type     |

## PEM

| Export                  | Kind     |
| ----------------------- | -------- |
| `pemDecode()`           | function |
| `pemEncode()`           | function |
| `splitPemBlocks()`      | function |
| `categorizePemBlocks()` | function |
| `PemBlock`              | type     |
| `CategorizedPemBlocks`  | type     |

## Result

| Export                 | Kind |
| ---------------------- | ---- |
| `Result`               | type |
| `Micro509Error`        | type |
| `IndexedMicro509Error` | type |
