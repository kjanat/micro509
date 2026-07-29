# Sync and Async APIs

One rule decides a function's timing across the whole library: pure DER/PEM
decoding and in-memory transformation is synchronous; anything that touches
WebCrypto (digest, sign, verify, key import/export/generation, PBES2) is
asynchronous and must be awaited.

## Per entrypoint

| Entrypoint            | Synchronous                                                                                                                                 | Asynchronous                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `micro509/der`        | everything                                                                                                                                  | —                                                                                 |
| `micro509/pem`        | everything                                                                                                                                  | —                                                                                 |
| `micro509/result`     | everything                                                                                                                                  | —                                                                                 |
| `micro509/x509`       | parsing, `encode*`/`decode*`, DN comparison and text helpers, `subjectKeyIdentifier`, source normalizers                                    | `create*`, `certificateFingerprint`, `getSubjectPublicKey*`, private-key matching |
| `micro509/verify`     | `matchServiceIdentity`, `matchCertificateServiceIdentity`, `checkExtendedKeyUsage`, `isSelfIssuedCertificate`, `trustAnchorFromCertificate` | chain verification, candidate-path building and validation, CSR verification      |
| `micro509/revocation` | `parse*`, `isCertificateRevoked`, `revocationReasonFromCode`, `hasOcspNoCheckExtension`, responder-URI discovery                            | CRL/OCSP creation, signature verification, validation, `check*` orchestration     |
| `micro509/keys`       | `inspectEncryptedPkcs8Der`, `parsePbes2AlgorithmIdentifier`                                                                                 | every import/export/generation function, RSA-OAEP                                 |
| `micro509/pkcs`       | `parsePkcs7SignedData*`, `parsePkcs7CertBag*`                                                                                               | SignedData creation and verification, PFX creation and parsing, PKCS#12 MAC       |
| `micro509/crypto`     | `ecdsaSignatureDerToRaw`, `ecdsaSignatureRawToDer`                                                                                          | `signData`, `verifySignature`                                                     |

PFX parsing is asynchronous even without an encrypted payload, and
`subjectKeyIdentifier` is synchronous despite being a digest: it uses the
library's own SHA-1, since WebCrypto has no synchronous hash.

## `micro509/x509` in detail

| Functions                                                              | Timing | Why                                               |
| ---------------------------------------------------------------------- | :----: | ------------------------------------------------- |
| `parseCertificate*`, `parseCertificateSigningRequest*`                 |  sync  | Pure PEM/DER decoding                             |
| `parseCertificateChainPem`, `parseCertificate(s)FromSource`            |  sync  | Pure PEM/DER decoding                             |
| `encode*`, `build*`, `decode*`, `findExtension`, and name text helpers |  sync  | Pure transformation of in-memory data             |
| `compareDistinguishedNames`, `canonicalDnKey`, IP helpers              |  sync  | Pure transformation of in-memory data             |
| `subjectKeyIdentifier`                                                 |  sync  | Library-internal SHA-1                            |
| `certificateFingerprint`                                               | async  | WebCrypto digest                                  |
| `createCertificate`, `createSelfSignedCertificate`                     | async  | WebCrypto key export, key generation, and signing |
| `createCertificateSigningRequest`                                      | async  | WebCrypto key export and signing                  |
| `getSubjectPublicKey`, `getSubjectPublicKeyOrThrow`                    | async  | WebCrypto key import                              |
| `certificateMatchesPrivateKey`, `matchCertificatePrivateKey`           | async  | WebCrypto key derivation and export               |

Every other function exported from `micro509/x509` is synchronous.

::: warning Await the operation, not the `Result`
`parseCertificatePem(pem)` returns a `ParseCertificateResult` immediately.
JavaScript permits `await parseCertificatePem(pem)`, but the `await` has no
effect.

`certificateFingerprint(pem)` returns a `Promise<CertificateFingerprint>`.
In untyped JavaScript, destructuring it without `await` reads the Promise object,
so `colonHex` is `undefined`. TypeScript rejects that destructuring when the
library types are intact.
:::

```ts
const parsed = parseCertificatePem(pem); // ParseCertificateResult, available now
const fingerprint = await certificateFingerprint(pem); // CertificateFingerprint
```
