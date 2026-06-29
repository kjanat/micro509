# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-06-29

Typed-error rework: trust-boundary functions (which consume untrusted
external input) now return a `Result` as the strict, correct default,
with an explicit `unwrap()` escape hatch. Typed-config constructors keep
throwing (a bad config is a programmer error, not a runtime condition).

### Added

- `unwrap(result)` / `unwrapOr(result, fallback)` and the `ResultError`
  class (root + `micro509/result`): the explicit escape hatch for callers
  who have already validated input or prefer exceptions. `unwrap` throws a
  `ResultError` carrying the structured `code`.
- `failureResult(code, message, details?)` factory in `micro509/result`:
  one source of truth for the `{ ok, error, code, message }` shape.

### Changed (BREAKING)

- `parseCertificateDer`, `parseCertificatePem`,
  `parseCertificateSigningRequestDer`, `parseCertificateSigningRequestPem`
  now return a `Result` (`{ ok, value }` / `{ ok, error: { code:
'malformed' } }`) instead of throwing. Wrap with `unwrap(...)` for the
  previous throw-on-error behavior.
- All 16 key `import*` functions now return a `Result` instead of
  throwing. Non-encrypted failures use code `'malformed'`; encrypted
  imports distinguish a typed `'invalid_password'` from `'malformed'`.
  `export*` and `generateKeyPair` are unchanged (no untrusted input).

## [0.2.0] - 2026-06-29

### Added

- PKCS#7 / CMS `SignedData` creation (`createPkcs7SignedDataDer`,
  `createPkcs7SignedDataPem`): sign content with one or more signers via the
  RFC 5652 §5.4 signed-attributes flow (`contentType` + `messageDigest`),
  producing attached SignedData that round-trips through
  `verifyPkcs7SignedData`. The content digest is selected per signer key:
  SHA-256 for ECDSA P-256 and RSA-SHA256, SHA-384 for P-384, and SHA-512
  for P-521 and Ed25519 (the latter per RFC 8419). Returns a typed result
  (`no_signers` / `invalid_signer_certificate` / `unsupported_signer_key`)
  for caller-correctable input.

## [0.1.1] - 2026-06-29

Maintenance release — release-pipeline fixes only, no library changes.

### Fixed

- Publish workflow is gated on the test suite, authenticates npm via OIDC
  trusted publishing, and emits correct JSR/npm release URLs.

## [0.1.0] - 2026-06-29

Initial prerelease. API may change before 1.0.

### Added

- X.509 certificate and CSR creation, parsing, and self-signing.
- Certificate chain verification with typed results (21 error codes, failing
  certificate index, structured failure details) and RFC 6125 service-identity
  matching (DNS, IPv6, URI-ID, SRV-ID, explicit CN opt-in).
- Revocation: CRL create/parse/verify/status and OCSP request building plus
  response parsing and responder-authorization checks.
- PKCS#7 / CMS `SignedData` parsing and signer-signature verification.
- PFX / PKCS#12 create and parse (PBES2, PKCS#12 KDF, HMAC-SHA-256 MAC).
- PEM handling and key import/export (PKCS#8, SPKI, JWK, PKCS#1, SEC1) with
  generation for RSA, ECDSA (`P-256`/`P-384`/`P-521`), and Ed25519.
- Zero runtime dependencies, WebCrypto-native, tree-shakeable subpath exports;
  runs on Node, Bun, Deno, browsers, and Cloudflare Workers.

[0.3.0]: https://github.com/kjanat/ts-x509/releases/tag/v0.3.0
[0.2.0]: https://github.com/kjanat/ts-x509/releases/tag/v0.2.0
[0.1.1]: https://github.com/kjanat/ts-x509/releases/tag/v0.1.1
[0.1.0]: https://github.com/kjanat/ts-x509/releases/tag/v0.1.0
