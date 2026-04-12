# API Reference

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

### Revocation

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

### PEM

Primary functions:

- `splitPemBlocks()`
- `categorizePemBlocks()`
- `pemDecode()`
- `pemEncode()`

Primary types:

- `PemBlock`
- `CategorizedPemBlocks`

### PKCS

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

Primary types: `PolicyValidationInput`, `PolicyValidationOutcome`, `ConstrainedPolicy`

### Extensions and names

See `micro509/x509` for the exhaustive extension and name type surface.
Root exports include common types: `CertificateExtensionsInput`, `BasicConstraints`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectAltName`, `NameInput`, `NameConstraints`, `GeneralName`, etc.

### Shared result types

Primary types: `Result`, `Micro509Error`, `IndexedMicro509Error` — import constructors from `micro509/result`.
