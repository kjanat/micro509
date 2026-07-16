# Sync and Async APIs

The X.509 entrypoint combines synchronous DER/PEM helpers with operations backed
by WebCrypto. Async functions return a `Promise` and must be awaited; sync
functions return their value or `Result` directly.

## Execution model

| Functions                                                              | Timing | Why                                               |
| ---------------------------------------------------------------------- | :----: | ------------------------------------------------- |
| `parseCertificate*`, `parseCertificateSigningRequest*`                 |  sync  | Pure PEM/DER decoding                             |
| `parseCertificateChainPem`                                             |  sync  | Pure PEM/DER decoding                             |
| `encode*`, `build*`, `decode*`, `findExtension`, and name text helpers |  sync  | Pure transformation of in-memory data             |
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
