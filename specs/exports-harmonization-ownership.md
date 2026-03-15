# Exports Harmonization Symbol Ownership Matrix

This inventory assigns every current public symbol one owner domain before file
moves begin. `micro509` stays the default documented import, but root is treated
as convenience only, never as canonical ownership.

## Root Inventory

- `micro509` currently mirrors the file-shaped subpaths from `./certificate`,
  `./crl`, `./csr`, `./extensions`, `./identity`, `./keys`, `./name`,
  `./name-constraints`, `./ocsp`, `./parse`, `./pem`, `./pfx`, `./pkcs7`,
  `./pkcs12-mac`, `./policy`, `./result`, `./revocation`, and `./verify`.
- Canonical ownership lives in the target domains below. Root keeps only curated
  workflow re-exports in the later `redesign-root-barrel` task.
- Current root-only symbol:
  - `SignatureProfileInput` -> owner `x509`; keep public, move off root, do not
    treat as a standalone product seam.

## Ownership Matrix

### `x509`

#### `./certificate` -> `micro509/x509`

- `keep`: `ValidityInput`, `CreateCertificateInput`,
  `CreateSelfSignedCertificateInput`, `CertificateMaterial`,
  `SelfSignedCertificateResult`, `createCertificate`,
  `createSelfSignedCertificate`

#### `./csr` -> `micro509/x509`

- `keep`: `CreateCsrInput`, `CsrMaterial`,
  `createCertificateSigningRequest`

#### `./extensions` -> `micro509/x509`

- `keep`: `KeyUsage`, `SubjectAltName`, `GeneralName`,
  `DistributionPointReason`, `DistributionPointName`, `DistributionPoint`,
  `IssuingDistributionPointBase`, `IssuingDistributionPointForUserCerts`,
  `IssuingDistributionPointForCaCerts`,
  `IssuingDistributionPointForAttributeCerts`, `IssuingDistributionPoint`,
  `BasicConstraints`, `PolicyInformation`, `CertificatePolicies`,
  `CpsPolicyQualifierInfo`, `PolicyNoticeReference`,
  `UserNoticePolicyQualifierInfo`, `CustomPolicyQualifierInfo`,
  `PolicyQualifierInfo`, `PolicyMapping`, `PolicyMappings`,
  `PolicyConstraints`, `InhibitAnyPolicy`, `CertificateExtensionsInput`,
  `CustomExtension`, `NameConstraintForm`,
  `UnsupportedNameConstraintForm`, `ParsedNameConstraintForm`,
  `GeneralSubtree`, `NameConstraints`, `KnownAuthorityInfoAccessMethod`,
  `CustomAuthorityInfoAccessMethod`, `AuthorityInfoAccessMethod`,
  `AuthorityInformationAccess`, `KnownExtendedKeyUsage`,
  `CustomExtendedKeyUsage`, `ExtendedKeyUsage`,
  `buildCertificateExtensions`, `buildRequestedExtensions`,
  `encodeExtension`, `encodeBasicConstraints`, `encodeKeyUsage`,
  `encodeSubjectAltName`, `encodeExtendedKeyUsage`,
  `encodeAuthorityInfoAccess`, `encodeCrlDistributionPoints`,
  `encodeNameConstraints`, `encodeCertificatePolicies`,
  `encodePolicyMappings`, `encodePolicyConstraints`,
  `encodeInhibitAnyPolicy`, `getExtendedKeyUsageOid`,
  `parseExtendedKeyUsageOid`, `getAuthorityInfoAccessMethodOid`,
  `parseAuthorityInfoAccessMethodOid`, `buildSubjectKeyIdentifier`

#### `./name` -> `micro509/x509`

- `keep`: `NameFieldKey`, `NameObject`, `NameAttribute`, `NameInput`,
  `RelativeDistinguishedNameInput`, `encodeName`,
  `encodeRelativeDistinguishedName`

#### `./parse` -> `micro509/x509`

- `keep`: `ParsedNameAttribute`, `ParsedName`,
  `ParsedRelativeDistinguishedName`, `ParsedDistributionPointName`,
  `ParsedDistributionPoint`, `ParsedIssuingDistributionPoint`,
  `ParsedExtension`, `ExtensionDecoder`, `defineExtensionDecoder`,
  `defineExtensionDecoderMap`, `ExtensionDecoderMap`, `DecodedExtensionMap`,
  `DecodedExtensionValue`, `ParseOptions`, `ParsedCertificate`,
  `ParsedCertificateSigningRequest`, `parseCertificateDer`,
  `parseCertificatePem`, `parseCertificateChainPem`,
  `parseCertificateSigningRequestDer`, `parseCertificateSigningRequestPem`,
  `findExtension`, `decodeExtension`, `decodeExtensions`,
  `decodeExtensionMap`, `parseBasicConstraints`, `parseKeyUsage`,
  `parseExtendedKeyUsage`, `parseCertificatePolicies`,
  `parsePolicyMappings`, `parsePolicyConstraints`,
  `parseInhibitAnyPolicy`, `parseSubjectAltNames`,
  `parseAuthorityInfoAccess`, `parseCrlDistributionPoints`,
  `parseNameConstraints`, `parseAuthorityKeyIdentifier`

### `verify`

#### `./identity` -> `micro509/verify`

- `keep`: `DnsServiceIdentityInput`, `IpServiceIdentityInput`,
  `UriServiceIdentityInput`, `SrvServiceIdentityInput`,
  `ServiceIdentityInput`, `ServiceIdentityType`,
  `MatchableServiceIdentityInput`, `VerifyServiceIdentityInput`,
  `MatchServiceIdentityErrorCode`, `MatchServiceIdentityFailureDetails`,
  `MatchServiceIdentityFailure`, `MatchServiceIdentitySuccess`,
  `MatchServiceIdentityFailureResult`, `MatchServiceIdentityResult`,
  `MatchServiceIdentityEvaluation`, `MatchServiceIdentityInput`,
  `matchServiceIdentity`, `matchCertificateServiceIdentity`

#### `./name-constraints` -> `micro509/verify`

- `keep`: `InitialNameConstraintsInput`

#### `./policy` -> `micro509/verify`

- `keep`: `PolicyValidationInput`, `ConstrainedPolicy`,
  `PolicyValidationOutcome`

#### `./verify` -> `micro509/verify`

- `keep`: `CertificateSource`, `CsrSource`, `VerifyPurpose`,
  `EkuCheckPurpose`, `EkuCheckResult`, `EkuCheckFailure`, `TrustAnchor`,
  `VerifyErrorCode`, `VerifyFailureDetails`, `VerifyChainFailure`,
  `BuildCandidatePathInput`, `CandidatePath`, `BuildCandidatePathResult`,
  `ValidateCandidatePathInput`, `ValidateCandidatePathSuccess`,
  `ValidateCandidatePathResult`, `VerifyCertificateChainInput`,
  `VerifiedCertificateChain`, `VerifyChainResult`, `VerifyRequestFailure`,
  `VerifyRequestResult`, `ValidateForTlsServerInput`,
  `ValidateForTlsClientInput`, `ValidateForCodeSigningInput`,
  `ValidateForCaInput`, `buildCandidatePath`, `validateCandidatePath`,
  `verifyCertificateChain`, `verifyCertificateSigningRequest`,
  `checkExtendedKeyUsage`, `trustAnchorFromCertificate`,
  `validateForTlsServer`, `validateForTlsClient`,
  `validateForCodeSigning`, `validateForCa`

### `revocation`

#### `./crl` -> `micro509/revocation`

- `keep`: `RevokedCertificateInput`, `RevocationReason`,
  `CreateCertificateRevocationListInput`,
  `CertificateRevocationListMaterial`, `ParsedRevokedCertificate`,
  `ParsedCertificateRevocationList`, `CrlSource`, `CrlCertificateSource`,
  `VerifyCertificateRevocationListFailure`,
  `VerifyCertificateRevocationListResult`,
  `ValidateCertificateRevocationListInput`,
  `ValidateCertificateRevocationListFailure`,
  `ValidateCertificateRevocationListResult`,
  `CheckCertificateRevocationAgainstCrlInput`,
  `CheckCertificateRevocationAgainstCrlErrorCode`,
  `CrlApplicabilityFailureReason`,
  `CheckCertificateRevocationAgainstCrlFailureDetails`,
  `CheckCertificateRevocationAgainstCrlFailure`,
  `CheckCertificateRevocationAgainstCrlGoodValue`,
  `CheckCertificateRevocationAgainstCrlRevokedValue`,
  `CheckCertificateRevocationAgainstCrlValue`,
  `CheckCertificateRevocationAgainstCrlResult`,
  `createCertificateRevocationList`, `parseCertificateRevocationListDer`,
  `parseCertificateRevocationListPem`, `verifyCertificateRevocationList`,
  `validateCertificateRevocationList`,
  `checkCertificateRevocationAgainstCrl`, `isCertificateRevoked`

#### `./ocsp` -> `micro509/revocation`

- `keep`: `OcspHashAlgorithm`, `OcspCertificateSource`,
  `OcspRequestSource`, `CreateOcspRequestItemInput`,
  `CreateOcspRequestInput`, `OcspRequestMaterial`, `ParsedOcspCertId`,
  `ParsedOcspRequest`, `OcspCertStatus`, `OcspResponseStatus`,
  `ParsedOcspSingleResponse`, `ParsedOcspResponderId`,
  `ParsedOcspResponse`, `CreateOcspSingleResponseInput`,
  `CreateOcspResponseInput`, `OcspResponseMaterial`,
  `VerifyOcspResponseFailure`, `VerifyOcspResponseResult`,
  `ValidateOcspResponseInput`, `ValidateOcspResponseFailure`,
  `ValidateOcspResponseResult`, `createOcspRequest`,
  `parseOcspRequestDer`, `parseOcspRequestPem`, `parseOcspResponseDer`,
  `parseOcspResponsePem`, `createOcspResponse`, `verifyOcspResponse`,
  `validateOcspResponse`

#### `./revocation` -> `micro509/revocation`

- `keep`: `RevocationStatus`, `RevocationEvidenceKind`,
  `RevocationCertificateSource`, `OcspResponderSource`,
  `ConfiguredOcspResponderCertificate`, `ConfiguredOcspResponder`,
  `OcspResponderCandidate`, `ResolveOcspResponderCandidatesInput`,
  `RevocationCrlEvidenceInput`, `RevocationOcspEvidenceInput`,
  `RevocationEvidenceInput`, `CheckCertificateRevocationInput`,
  `CheckCertificateRevocationErrorCode`,
  `RevocationIndeterminateReasonCode`,
  `RevocationIndeterminateEvidence`,
  `CheckCertificateRevocationFailureDetails`, `RevocationCheckUnknownValue`,
  `RevocationCheckGoodValue`, `RevocationCheckRevokedValue`,
  `CheckCertificateRevocationValue`, `CheckCertificateRevocationResult`,
  `getCertificateOcspResponderUris`, `resolveOcspResponderCandidates`,
  `checkCertificateRevocation`

### `pkcs`

#### `./pfx` -> `micro509/pkcs`

- `keep`: `PfxCertificateSource`, `PfxPrivateKeySource`,
  `PfxBagAttributesInput`, `PfxCertificateBagInput`,
  `PfxPrivateKeyBagInput`, `CreatePfxInput`, `PfxEncryptionOptions`,
  `ParsePfxOptions`, `PfxMaterial`, `ParsedPfxAttribute`,
  `ParsedPfxBagAttributes`, `ParsedPfxBag`, `ParsedPfx`,
  `ParsePfxErrorCode`, `ParsePfxFailure`, `ParsePfxResult`, `createPfx`,
  `parsePfxDer`, `parsePfxPem`

#### `./pkcs12-mac` -> `micro509/pkcs`

- `keep`: `Pkcs12MacOptions`, `ParsedPkcs12MacData`,
  `createPkcs12MacData`, `parsePkcs12MacData`
- note: keep public only as advanced PKCS plumbing; do not headline it at root.

#### `./pkcs7` -> `micro509/pkcs`

- `keep`: `Pkcs7CertificateSource`, `Pkcs7CertBag`,
  `ParsedPkcs7SignerInfo`, `ParsedPkcs7SignedData`, `ParsePkcs7ErrorCode`,
  `ParsePkcs7Failure`, `ParsePkcs7SignedDataResult`,
  `ParsePkcs7CertBagResult`, `VerifyPkcs7SignedDataFailure`,
  `VerifyPkcs7SignedDataResult`, `createPkcs7CertBagDer`,
  `createPkcs7CertBagPem`, `parsePkcs7CertBagDer`, `parsePkcs7CertBagPem`,
  `parsePkcs7SignedDataDer`, `parsePkcs7SignedDataPem`,
  `verifyPkcs7SignedData`

### `keys`

#### `./keys` -> `micro509/keys`

- `keep`: `RsaHash`, `RsaScheme`, `EcNamedCurve`,
  `RsaKeyAlgorithmInput`, `EcKeyAlgorithmInput`,
  `Ed25519KeyAlgorithmInput`, `KeyAlgorithmInput`, `KeyPairMaterial`,
  `ImportRsaPublicKeyInput`, `ImportEcPublicKeyInput`,
  `ImportEd25519PublicKeyInput`, `PublicKeyImportInput`,
  `PrivateKeyImportInput`, `EncryptedPkcs8Options`,
  `LegacyPemEncryptionOptions`, `generateKeyPair`, `exportSpkiDer`,
  `exportPkcs8Der`, `exportPublicJwk`, `exportPrivateJwk`,
  `exportPkcs8Pem`, `exportEncryptedPkcs8Der`,
  `exportEncryptedPkcs8Pem`, `exportPkcs1Der`, `exportPkcs1Pem`,
  `exportEncryptedPkcs1Pem`, `exportSec1Der`, `exportSec1Pem`,
  `exportEncryptedSec1Pem`, `exportSpkiPem`, `exportBinaryBase64`,
  `importSpkiDer`, `importSpkiPem`, `importSpkiBase64`, `importPkcs8Der`,
  `importPkcs8Pem`, `importEncryptedPkcs8Der`,
  `importEncryptedPkcs8Pem`, `importPkcs1Der`, `importPkcs1Pem`,
  `importEncryptedPkcs1Pem`, `importPkcs8Base64`, `importSec1Der`,
  `importSec1Pem`, `importEncryptedSec1Pem`, `importPublicJwk`,
  `importPrivateJwk`
- `internalize`: `getCrypto`, `wrapKeyPair`

### `pem`

#### `./pem` -> `micro509/pem`

- `keep`: `PemBlock`, `CategorizedPemBlocks`, `pemEncode`, `pemDecode`,
  `splitPemBlocks`, `categorizePemBlocks`
- `internalize`: `base64Encode`, `base64Decode`

### `result`

#### `./result` -> `micro509/result`

- `keep`: `ErrorResult`, `IndexedErrorResult`, `IndexedMicro509Error`,
  `Micro509Error`, `Result`, `errorResult`, `indexedErrorResult`,
  `indexedMicro509Error`, `micro509Error`, `successResult`

## High-Risk Renames And Removals

- Remove file-shaped public homes and merge them into domains:
  `./certificate`, `./csr`, `./extensions`, `./name`, `./parse`,
  `./identity`, `./policy`, `./name-constraints`, `./crl`, `./ocsp`,
  `./pfx`, `./pkcs7`, `./pkcs12-mac`.
- Keep `./verify`, `./revocation`, `./keys`, `./pem`, and `./result`, but make
  them canonical domains rather than incidental filenames.
- Move current root-only `SignatureProfileInput` under `x509`; root can still
  re-export it later if workflow curation proves it necessary.
- Internalize obvious implementation helpers before public folder moves:
  `getCrypto`, `wrapKeyPair`, `base64Encode`, `base64Decode`.
- Keep `./package.json` npm-only; remove it from JSR when export generation is
  centralized.
