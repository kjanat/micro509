# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Conformance

- PKITS sweep completed: the harness runs the full NIST PKITS suite — all
  224 test procedures across sections 4.1–4.16, expanded to 249 runs
  including every documented subtest variation — and every manifest
  expectation was verified against the official PKITS document, now
  vendored as `docs/rfc/pkits.txt`. 4.1.4/4.1.5 (DSA chains) are
  expected-fail per the WebCrypto algorithm boundary. RFC 5280 path
  validation and RFC 9618 policy validation are now claimed `complete`.

### Changed

- Name constraints now fail closed for unsupported GeneralName forms per
  RFC 5280 §4.2.1.10. A critical `nameConstraints` extension imposing
  `otherName`, `x400Address`, `ediPartyName`, or `registeredID`
  constraints rejects a subsequent certificate **only when a SAN of that
  form actually appears** (`unsupported_name_constraints`); previously any
  such chain was rejected outright, even when the constrained form never
  occurred. SRV-ID and unknown-tag SANs now participate in that fail-closed
  check — they were previously skipped. Unsupported forms in non-critical
  extensions are ignored, and supported forms in the same extension are
  still enforced.

## [0.5.0] - 2026-07-03

OCSP responder authorization, URI/SRV service identities, and a
`best-available` revocation preference that actually compares evidence
freshness.

### Changed

- `policy.prefer: 'best-available'` (the default) now genuinely picks the
  freshest evidence: when CRL and OCSP both yield a validated `good`
  verdict, the source with the later `thisUpdate` is reported (an applied
  delta CRL counts as its own `thisUpdate`; ties favor OCSP). Previously
  `'best-available'` behaved identically to `'ocsp'`. Fail-closed
  combination is unchanged — a validated `revoked` verdict from either
  source still always wins.

- `RevocationSource` gained `thisUpdate` — the timestamp of the evidence
  backing the verdict (OCSP single-response entry or freshest contributing
  CRL), i.e. the value `'best-available'` compares. `signerCertificate` for
  a multi-CRL `good` verdict is now the freshest contributing CRL's signer
  rather than the last one processed, so it always matches the reported
  freshness.

### Added

- URI-ID and SRV-ID service identities are now accepted by the verification
  helpers: `VerifyServiceIdentityInput` widened to the full
  `ServiceIdentityInput` union, so
  `verifyCertificateChain({ serviceIdentity })` and `validateForTlsServer`
  match `{ type: 'uri' | 'srv' }` alongside DNS/IP. An SRV service-label
  mismatch surfaces as `subject_alt_name_mismatch` with the matcher's
  details.

- OCSP responder authorization completed (RFC 6960 §4.2.2.2):
  - `trustedResponderCertificates` on `validateOcspResponse()` and
    `trustedOcspResponders` on `checkChainRevocation()` /
    `verifyCertificateChain({ revocation })` — criterion-1 local responder
    configuration; a matching signer skips delegated issuance/EKU checks and
    is consulted during responder discovery.
  - Delegated responder revocation policy (§4.2.2.2.1):
    `responderRevocationPolicy` = `'honor-nocheck'` (default) /
    `'require-evidence'` / `'skip'` with `responderRevocationCrls` as
    evidence; chain orchestration reuses its CRLs automatically. New
    failure codes `responder_revoked` and `responder_revocation_unknown`.
  - `hasOcspNoCheckExtension()` — parses `id-pkix-ocsp-nocheck`.
  - Delegated responder chains now validate at the caller-supplied `at`
    (historical-time validation) instead of always at the current time.

## [0.4.0] - 2026-07-03

OCSP joins chain-level revocation, and the npm package no longer ships
broken Bun export conditions.

### Added

- OCSP evidence is now consumed by chain-level revocation:
  `checkChainRevocation()` (and `verifyCertificateChain({ revocation })`)
  validates caller-supplied `ocspResponses` — signature, responder binding
  and authorization, freshness — and combines them with CRL evidence. A
  validated `revoked` verdict from either source always denies, regardless
  of `policy.prefer` (fail-closed). Delegated responder certificates can be
  supplied via `extraCertificates`.
- `VERIFY_ERROR_CODES`: runtime array of every `VerifyErrorCode`, exported
  from the root and `micro509/verify`. The docs error-code table is now
  test-enforced against it.
- CI now builds, validates the npm tarball against the published exports
  map, and smoke-tests the dist output under Node and Deno.

### Changed (BREAKING)

- `VerifyErrorCode`: renamed `initial_name_constraints_not_implemented` →
  `unsupported_initial_name_constraints` (it reports unsupported/malformed
  initial-name-constraint forms, not a missing feature). Removed
  `policy_processing_not_implemented`, which no code path emitted.

### Fixed

- npm packaging: the published `exports` map retained the dev-only
  `bun → ./src/*.ts` conditions while the tarball ships only `dist/`,
  breaking Bun consumers installing from npm (`npm publish` does not apply
  `publishConfig.exports`). The publish workflow now rewrites `exports`
  from `publishConfig.exports` before publishing, and CI fails if any
  published export target is missing from the tarball.

## [0.3.0] - 2026-07-02

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
- `createPfx`, `createPkcs7CertBagDer`, and `createPkcs7CertBagPem` now
  return a `Result` (code `'invalid_certificate'`) instead of throwing
  on a malformed certificate source — matching `createPkcs7SignedData`.
  Pure typed-config constructors (`createCertificate`,
  `createSelfSignedCertificate`, `createCertificateRevocationList`, …)
  still throw: a bad config is a programmer error, not a runtime result.

### Changed

- Canonical docs site is now `micro509.kjanat.dev` (was `micro509.kjanat.com`,
  which stays live as a mirror). `homepage` and all documentation links point at
  the `.dev` domain.
- GitHub repository renamed `kjanat/ts-x509` → `kjanat/micro509` to match the
  published package name. `repository.url` updated; old URLs redirect.

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

[Unreleased]: https://github.com/kjanat/micro509/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/kjanat/micro509/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kjanat/micro509/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kjanat/micro509/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kjanat/micro509/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kjanat/micro509/releases/tag/v0.1.0
