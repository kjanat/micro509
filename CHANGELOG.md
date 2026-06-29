# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PKCS#7 / CMS `SignedData` creation (`createPkcs7SignedDataDer`,
  `createPkcs7SignedDataPem`): sign content with one or more signers via the
  RFC 5652 §5.4 signed-attributes flow (`contentType` + `messageDigest`),
  producing attached SignedData that round-trips through
  `verifyPkcs7SignedData`. The content digest is derived per signer key
  (ECDSA P-256/384/521, RSA, Ed25519 → SHA-512 per RFC 8419).

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

[0.1.1]: https://github.com/kjanat/ts-x509/releases/tag/v0.1.1
[0.1.0]: https://github.com/kjanat/ts-x509/releases/tag/v0.1.0
