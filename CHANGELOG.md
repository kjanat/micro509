# Changelog

<!--
Release checklist — every box, every release:
- [ ] Move [Unreleased] entries under a new `## [X.Y.Z] - YYYY-MM-DD` header + intro line
- [ ] Bump version in package.json AND jsr.json
- [ ] Bump the `micro509` range in examples/vite/package.json — StackBlitz installs it from npm
- [ ] Link definitions at the BOTTOM of this file: add [X.Y.Z] compare link, repoint [Unreleased]
- [ ] Signed tag on the release commit: git tag -s vX.Y.Z -m "vX.Y.Z — summary"
- [ ] Push master + tag, gh release create with milestone notes
- [ ] Verify npm dist-tag latest + JSR after the publish workflow
-->

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Extension encoders reject input RFC 5280 forbids rather than emitting
  non-conformant DER: an empty `keyUsage` (§4.2.1.3), `extendedKeyUsage`
  (§4.2.1.12), `authorityInfoAccess`/`cRLDistributionPoints` (§4.2.2.1,
  §4.2.1.13) or `nameConstraints` (§4.2.1.10) SEQUENCE, a duplicate certificate
  policy OID (§4.2.1.4), a `DisplayText` outside SIZE (1..200) (§4.2.1.4), and an
  IP name constraint whose address and mask do not total 8 or 32 octets
  (§4.2.1.10). Each previously encoded a structure the library's own parser, or
  OpenSSL, rejects.
  (https://github.com/kjanat/micro509/pull/79)

## [0.13.0] - 2026-07-23

A public `micro509/der` entrypoint, and RFC-conformance fixes across path
validation: name constraints, issuer chaining, CRL issuer paths,
distinguished-name comparison, and policy node sets.

### Added

- `micro509/der` exposes the DER reader, writer, and value decoders that back
  every built-in parser. `defineExtensionDecoder` hands a consumer `valueDer` and
  expects raw DER back from `encode`, and nothing in the public API could read or
  write those bytes, so a custom extension needed a second ASN.1 library.
  Readers and decoders take untrusted bytes and come in pairs: `decodeDerInteger`
  returns a `Result`, `decodeDerIntegerOrThrow` throws. Writers take typed input
  and throw, matching `encodeName` and `pemEncode`.
  (https://github.com/kjanat/micro509/issues/63)
- `bmpString` and `universalString` encode the two string types that already
  decoded, so a PKCS#12 `friendlyName` can now be written as well as read. Both
  reject lone surrogates, and `bmpString` rejects code points above U+FFFF.
- `decodeBitString` returns a BIT STRING's payload with its unused-bit count.
  `extractBitStringValue` rejects a non-zero count, which excluded KeyUsage, the
  most common BIT STRING in a certificate. Unused trailing bits are returned as
  encoded, matching how the extension decoders already treat non-conformant
  certificates.

### Changed

- `decodeIntegerNumber` accepts a non-negative, minimally encoded INTEGER up to
  `Number.MAX_SAFE_INTEGER` and rejects above it. Negative and non-minimal
  encodings are still rejected, as before. It stopped at 6 bytes while
  `integerFromNumber` encoded any non-negative safe integer, so values from 2^47
  up encoded and would not decode.
  The old limit cited 48 bits as the safe-integer boundary; that boundary is 53.
  A 7- or 8-byte INTEGER inside a certificate that previously threw now parses.

### Security

- Name constraints reject a URI SAN whose authority has no FQDN host (an IP
  literal, a single-label host such as `localhost`, or no authority at all)
  when a uniformResourceIdentifier constraint applies, per RFC 5280 §4.2.1.10.
  Such a URI previously slipped past the
  constraint. Email constraint matching now compares the local part
  case-sensitively and only the host case-insensitively (RFC 5280 §7.5, as
  replaced by RFC 9549 §7.5.1), so `admin@example.com` no longer matches
  `ADMIN@example.com` and widens the permitted subtrees.
  (https://github.com/kjanat/micro509/pull/71)
- `validateCandidatePath` compares each certificate's issuer DN against the
  candidate issuer's subject DN, per RFC 5280 §6.1.3(a)(4). It verified only the
  signature, so a leaf whose issuer DN was unrelated to the signing CA validated
  as ok on the pre-built-path API. `buildChainInternal` already compared them,
  so `verifyCertificateChain` was unaffected.
  (https://github.com/kjanat/micro509/pull/72)
- CRL evidence validates the CRL issuer's own certification path to the trust
  anchor before trusting its verdict (RFC 5280 §6.3.3(f)). A forged
  indirect-CRL signer whose subject DN collided with a chain certificate was
  accepted on a name match, its signature never checked against a trusted key,
  so a forged empty CRL reported a revoked certificate as `good`. Each
  candidate CRL issuer runs the full pipeline as one step (signature, then
  §6.3.3(f) path, then signer revocation), so an unusable candidate no longer
  shadows a later authorized one, and the signer's path is validated against a
  pool that includes the validated chain intermediates, so a delegated signer
  issued by a chain CA authorizes. Without these, a genuine revoked CRL became
  `crl_signer_not_authorized` and soft-fail allowed the revoked certificate.
  (https://github.com/kjanat/micro509/pull/73)
- Distinguished name comparison implements the RFC 4518 string-preparation
  profile that RFC 5280 §7.1 requires, against the frozen Unicode 3.2 repertoire
  RFC 4518 §2.1 fixes: the Map, Normalize, Prohibit, and Insignificant Space
  steps with the complete RFC 3454 Appendix B.2 case fold and Table A.1
  unassigned set. The old NFKC-plus-lowercase shortcut left ignorable code
  points in place (so an excluded subtree failed to exclude a name carrying a
  SOFT HYPHEN), folded with `toLowerCase` alone (so `Straße` did not equal
  `STRASSE`), and delegated the repertoire to the running Unicode version. That
  last part let a code point unassigned in 3.2 slip through: U+1D2C normalized
  to `a` and matched `CN=a`, U+2F868 used the Unicode 4.0 NFKC correction, and
  U+10A0 took a post-3.2 fold. The A.1 unassigned set, the B.2 fold, and the
  five CJK NFKC corrections are generated from the vendored RFC 3454 and guarded
  by a test that re-derives them from the RFC text. BMPString and UniversalString
  values are prepared alongside UTF8String and PrintableString. `domainComponent`
  compares as `caseIgnoreIA5Match` (RFC 4519), requiring the IA5String tag and
  ASCII, so a UTF8String or non-ASCII value no longer matches an IA5String one;
  `DC=Example` chains to `DC=example`. Bare-anchor selection confirms the
  anchor's subject equals the certificate's issuer rather than trusting the
  canonical-key bucket. RFC 4518 and RFC 3454 are vendored under `docs/rfc/`.
  (https://github.com/kjanat/micro509/pull/74)
- Certificate policy validation computes the RFC 9618 §5.5(g)
  `valid_policy_node_set` correctly: the nodes at any depth whose valid_policy
  is not anyPolicy and whose single parent is an anyPolicy node, plus a depth-n
  anyPolicy node. It previously took depth-n nodes tracing back to the depth-0
  anyPolicy root, which diverges under policy mapping. A CA that mapped
  `1.2.3.4` to `1.2.3.5` reported `authorityConstrainedPolicies` of `1.2.3.5`
  where the spec requires `1.2.3.4` (NIST PKITS 4.10.1), so a chain validated
  against the mapped policy instead of the authority's. `userConstrainedPolicies`
  now follows §5.5(g)(5)-(6) from the corrected set. Policy validation also
  processes the terminal certificate when a bare trust anchor is used: a path
  built to an out-of-band anchor ends at a real CA, and skipping it let a leaf
  policy satisfy `initialPolicySet` even when that CA omitted or contradicted
  the policy. `authorityConstrainedPolicies` now aggregates each policy's
  qualifiers from its node, ancestors, and descendants per §5.5(g)(4)(ii)
  rather than reporting one arbitrary node's set.
  (https://github.com/kjanat/micro509/pull/75)

## [0.12.0] - 2026-07-21

Text rendering for subject alternative names and distinguished names, and
runnable docs examples that survive client-side navigation.

### Added

- `subjectAltNameToString(name, options?)` renders one `SubjectAltName` as text.
  Printing a SAN is the most ordinary thing to do with one after parsing, and it
  took a hand-written narrowing in every consumer: `dns`/`ip`/`email`/`uri`/`srv`
  carry a `string` value, `directoryName` carries only `derHex` and has no `value`
  at all, and `unknown` carries a `Uint8Array` that stringifies itself as
  `192,0,2,1` inside a `join()`. A `directoryName` now renders as an RFC 4514
  distinguished name (`CN=Example CA,O=Acme\, Inc.,C=US`), falling back to its hex
  when the DER does not decode, and an `unknown` renders as hex. Pass
  `{ prefix: true }` for the `openssl x509 -text` labels (`DNS:`, `IP Address:`,
  `DirName:`), or call `subjectAltNameLabel(name)` for the label alone. Companion
  `distinguishedNameToString(name)` and `relativeDistinguishedNameToString(rdn)`
  render a parsed subject or issuer, which until now had no public renderer either.
  Exported from the root and `micro509/x509`, with the `SubjectAltNameTextOptions`
  type. (https://github.com/kjanat/micro509/issues/50)

- The docs site serves a permalink for the newest release. `/v0.11.0/…` used to
  404 while 0.11.0 sat at the root, then silently come into existence as an
  archive one release later, so a link to the root changed meaning on every
  release. The build now emits a `_redirects` file sending `/v<latest>/*` to the
  root with a 302; once the next release takes the root, the rule disappears and
  the same URL serves the archived copy. Temporary on purpose: browsers cache a
  301 past the release that makes it wrong.

### Fixed

- Runnable examples now execute the version of the page they run on after
  client-side navigation. Each page shipped its own `<script type="importmap">`,
  which the browser reads once per document, so navigating from the landing page
  to an archived version and pressing Run resolved `micro509` against the entry
  page's map and imported the wrong release; only a hard refresh picked up the
  right one. Every page now ships one identical map: top-level imports for the
  root version and a scope per version prefix. Scopes match the URL of the
  importing module, and the injected example module inherits the document URL,
  so resolution follows the page at run time with no map swapping. `run
site:import-maps` now verifies the map is identical on every page and each
  scope binds its own version, and `run site:live-examples` replays the failing
  flow: enter at the root, navigate client-side to an archive, run its example,
  and require every import to carry that archive's version.

### Changed

- The X.509 reference now identifies every asynchronous operation in one place
  and explains the split: PEM/DER parsing and transformation are synchronous,
  while hashing, signing, and key operations backed by WebCrypto return promises.
  The API summaries for `parseCertificatePem` and `certificateFingerprint` make
  their return timing explicit, avoiding a no-op `await` on the parser or reading
  properties from an unawaited fingerprint promise.
  (https://github.com/kjanat/micro509/issues/51)
- The docs site no longer co-hosts the library: each version's runnable examples
  import it from a CDN, bound to the version that page documents. A release imports
  what it published, from jsDelivr, whose `+esm` builds arrive bundled — one request
  where esm.sh's module graph took thirty-nine, and a third of the time to load.
  `/next/` imports a pkg.pr.new build of the deployed commit, which only esm.sh can
  serve, bundled with `?standalone`. The co-hosted copy put the library's own file
  layout in the site's URL space, where `x509/fingerprint.js` matched an EasyPrivacy
  rule blocking that path on every domain (`/fingerprint.js^$domain=~github.com`).
  Content blockers refused it, and because it is a static import of the root entry,
  every example on the site died for readers running one.
- CI gates the docs site on its examples actually working: `run site:import-maps`
  checks every version's map names its own library and that every URL in it resolves,
  and `run site:live-examples` clicks Run in a real browser with a content blocker
  simulated — a headless browser has none, and would have passed while the bug above
  was live.
- Materializing an archived version's pages now repairs a runnable example the tag
  shipped with a syntax error, so its Run button executes valid code. Each `<LiveCode>`
  block is parsed, and one missing the brace that closes a block gets it restored at
  the position the TypeScript parser expects. Nine `guide/getting-started` examples
  across v0.3.0 through v0.9.0 were affected. The archived page then differs from the
  code that release published. (https://github.com/kjanat/micro509/issues/53)

## [0.11.0] - 2026-07-13

Certificate fingerprinting and private-key ownership checks for certificate
inspection, intake, and issuance workflows.

### Added

- `certificateFingerprint(certificate, algorithm?)` computes the standard
  certificate fingerprint — a hash over the DER encoding, the identifier
  `openssl x509 -fingerprint` and TLS UIs display. It accepts the same
  `string | Uint8Array | ParsedCertificate` source union as the verification
  APIs and returns `{ bytes, hex, colonHex }`: the raw digest, lowercase hex
  with no separators, and uppercase colon-separated hex (openssl style). It
  defaults to SHA-256; SHA-1/384/512 are also supported for legacy interop
  (older certificate pinning, PGP-adjacent tooling). Exported from the root and
  `micro509/x509` as `certificateFingerprint`, with `CertificateFingerprint`,
  `CertificateFingerprintAlgorithm`, and `CertificateFingerprintSource` types.
  Interop with `openssl x509 -fingerprint` verified across all four algorithms.
  (https://github.com/kjanat/micro509/issues/45)
- `certificateMatchesPrivateKey(certificate, privateKey)` checks whether an
  uploaded private key belongs to a certificate — the first thing any
  key-intake or issuance endpoint must do. It derives the public half of the
  private key, exports it as SubjectPublicKeyInfo DER, and byte-compares it
  against the certificate's own SPKI (the canonical, algorithm-agnostic
  ownership test), returning a plain `boolean`. `certificate` accepts a PEM
  string, DER bytes, or an already-parsed `ParsedCertificate`; a private key of
  a different type simply produces different SPKI and returns `false`.
  `matchCertificatePrivateKey` is the `Result`-returning companion: `ok: true`
  on a match, or a typed failure carrying `key_mismatch`, `key_type_mismatch`,
  `malformed_certificate`, or `unsupported_private_key` — so trust boundaries
  get the reason (and no thrown errors on untrusted input). The error-code
  union is exported as `MatchCertificatePrivateKeyErrorCode`.
  (https://github.com/kjanat/micro509/issues/46)

## [0.10.0] - 2026-07-13

Detached PKCS#7 / CMS signatures — the form git x509 commit signing and S/MIME
rely on — and algorithm inference across every private-key import family.

### Added

- `createPkcs7SignedData` accepts `detached: true` to omit `eContent` from
  `encapContentInfo` (RFC 5652 §5.2 detached form), and
  `verifyPkcs7SignedData` accepts an options bag with `content` to supply the
  externally-held bytes when verifying a detached signature — the shape git
  x509 commit signing (`gpg.format=x509`) and S/MIME detached signatures use.
  The error-code union is now exported as `VerifyPkcs7SignedDataErrorCode`, the
  options as `VerifyPkcs7SignedDataOptions`. Interop with `openssl cms`
  verified in both directions.
  (https://github.com/kjanat/micro509/issues/40)
- The private-key import families infer the algorithm from the container when
  the `algorithm` parameter is omitted, mirroring the existing SPKI behavior;
  passing it still asserts and fails typed on mismatch:
  - `importPkcs8Der/Pem/Base64(+OrThrow)` and
    `importEncryptedPkcs8Der/Pem(+OrThrow)` read the PKCS#8
    `privateKeyAlgorithm` (RSA defaults to `pkcs1-v1_5`/`SHA-256`, as with
    SPKI inference).
  - `importSec1Der/Pem(+OrThrow)` and `importEncryptedSec1Pem(+OrThrow)` read
    the RFC 5915 `parameters [0]` named curve; a SEC 1 key without one still
    requires the explicit curve.
  - `importPublicJwk`/`importPrivateJwk`(+`OrThrow`) read `kty`, `crv`, and
    `alg` (`RS*`/`PS*`/`RSA-OAEP-256/384/512` select the RSA scheme and hash).
    (https://github.com/kjanat/micro509/issues/41)

### Fixed

- `createPkcs7SignedData` returns the typed `'invalid_signer_certificate'` /
  `'invalid_certificate'` (new code) failures for malformed signer and
  additional-certificate inputs instead of rejecting the promise. Each
  `additionalCertificates` value is structurally validated as a real X.509
  certificate, so malformed DER also returns `'invalid_certificate'`.

### Changed

- **BREAKING** — `verifyPkcs7SignedData` reports a SignedData that carries no
  `eContent` as `'detached_content_required'`; the `'content_missing'` code is
  gone. Such a message is not malformed, it is a detached signature awaiting
  its external content, and it is now only a failure when no `content` option
  is supplied. Rename any match on `'content_missing'`; matches against the
  exported `VerifyPkcs7SignedDataErrorCode` union fail to typecheck until you
  do.
- `exportSec1Der`/`exportSec1Pem`/`exportEncryptedSec1Pem` always embed the
  RFC 5915 `parameters [0]` named curve (WebCrypto's inner ECPrivateKey omits
  it; OpenSSL writes it), so exported SEC 1 keys are self-describing and
  re-import without an explicit curve.
- Preserve public API behavior while decomposing DER, parsing, verification,
  revocation, PKCS#7, and API-documentation flows into focused helpers that
  satisfy the stricter cognitive-complexity limit. (https://github.com/kjanat/micro509/pull/39)

## [0.9.0] - 2026-07-06

RSA-OAEP encryption support across the whole key lifecycle: generate, import,
derive, encrypt, decrypt.

### Added

- `RsaScheme` accepts `'oaep'`: `generateKeyPair`, the SPKI / PKCS#8 / JWK
  import functions, and `derivePublicKey` produce `RSA-OAEP` keys with
  `encrypt`/`decrypt` usages when the scheme is `'oaep'` (signature schemes
  keep `sign`/`verify`).
  (https://github.com/kjanat/micro509/pull/36)
- `encryptRsaOaep` / `decryptRsaOaep` (and their `…OrThrow` siblings) encrypt
  and decrypt small messages with an RSA-OAEP key pair, with an optional OAEP
  `label` bound to the ciphertext. Failures are typed:
  `'invalid_key' | 'message_too_long'` on encrypt,
  `'invalid_key' | 'decryption_failed'` on decrypt — ciphertext-level
  decryption failures are deliberately opaque (no padding-oracle detail).
- `RsaSignatureScheme` narrows `RsaScheme` to the signature schemes
  (`'pkcs1-v1_5' | 'pss'`), so certificate signature verification can never
  silently accept an OAEP key.

## [0.8.0] - 2026-07-05

Key/certificate import ergonomics and validation hardening — every API
finding from the OpenSSL differential fuzzer, shipped in one release.

### Added

- The `keys` and `x509` domain barrels (and the root barrel) re-export the 20
  `OrThrow` siblings that were implemented and documented but unreachable from
  the published package — 16 key-import variants (`importSpkiDerOrThrow`,
  `importPkcs8PemOrThrow`, …) and 4 certificate/CSR parsers
  (`parseCertificateDerOrThrow`, …). A conventions test now fails whenever a
  barrel exposes a function while omitting its `OrThrow` sibling.
  (https://github.com/kjanat/micro509/issues/26)
- `derivePublicKey(privateKey)` derives the matching public `CryptoKey` from
  an imported (or generated) private key, so a private key loaded via
  `importPkcs8*`/`importPkcs1*`/`importSec1*`/`importPrivateJwk` can go
  straight to `exportSpkiDer`/`exportSpkiPem` without hand-rolling JWK
  surgery. Supports RSA, ECDSA, and Ed25519.
  (https://github.com/kjanat/micro509/issues/19)
- `importSpkiDer`, `importSpkiPem`, `importSpkiBase64` (and their `…OrThrow`
  variants) now accept an optional algorithm argument. A SubjectPublicKeyInfo
  already encodes its algorithm OID — and the EC curve OID — so when no hint is
  given the algorithm is inferred straight from the DER, letting callers import
  keys whose type isn't known ahead of time. Passing an explicit algorithm is
  unchanged and still asserts the key matches it.
  (https://github.com/kjanat/micro509/issues/20)
- `getSubjectPublicKey(parsed)` / `getSubjectPublicKeyOrThrow(parsed)` import
  the subject public key of a parsed certificate or CSR as a WebCrypto
  `CryptoKey`, inferring the algorithm (and EC curve) from the embedded
  SubjectPublicKeyInfo — callers no longer hand-roll the
  `publicKeyAlgorithmOid` → import-algorithm mapping.
  (https://github.com/kjanat/micro509/issues/21)

### Fixed

- `importPrivateJwk` / `importPrivateJwkOrThrow` now validate the JWK against
  the requested algorithm before handing it to WebCrypto, matching what
  `importPublicJwk` already did: `kty`/`crv` must match the requested
  `kind`/`curve`, the private material the kind implies must be present
  (`d` everywhere, plus `n`/`e`/`p`/`q`/`dp`/`dq`/`qi` for RSA), and
  symmetric (`k`) or multi-prime (`oth`) material is rejected.
  Wrong-algorithm and public-only JWKs previously surfaced as opaque
  WebCrypto errors instead of the library's `'malformed'` failures.
  (https://github.com/kjanat/micro509/issues/23)
- `importSec1Der` / `importSec1Pem` / `importEncryptedSec1Pem` (and their
  `…OrThrow` variants) trusted the caller's `curve` without reading the SEC 1
  ECPrivateKey itself. The RFC 5915 `parameters [0]` field (OpenSSL always
  writes it) is now parsed and cross-checked: a curve mismatch fails with
  `SEC 1 private key curve does not match requested import algorithm`, and
  bytes that are not an ECPrivateKey fail with `Malformed SEC 1 private key` —
  instead of both surfacing as WebCrypto's opaque "Malformed PKCS#8" error.
  Keys without the optional parameters field import as before.
  (https://github.com/kjanat/micro509/issues/22)

## [0.7.2] - 2026-07-04

Error-classification fix for encrypted-key imports with a wrong password.

### Fixed

- `importEncryptedPkcs8Der` / `importEncryptedPkcs8Pem` reported
  `'malformed'` instead of `'invalid_password'` roughly once per 256
  wrong-password attempts: AES-CBC padding is unauthenticated, so a wrong
  key occasionally "decrypts" to random bytes that pass the padding check,
  and the resulting PKCS#8 parse failure was misclassified. Decrypted
  plaintext that is not a PrivateKeyInfo now reports `'invalid_password'`.
- `parsePfx` had the same wrong-password tail (reporting `'malformed'`),
  plus the reverse: structurally malformed EncryptedData could report
  `'invalid_password'`. Classification now keys on the decryption failure
  itself instead of error-message prefixes.

## [0.7.1] - 2026-07-04

ECDSA signature-encoding bug fix — re-issue any ECDSA-signed artifacts
that fail external verification.

### Fixed

- ECDSA signing embedded an invalid signature roughly once per 256
  signatures: WebCrypto's raw `r || s` output was detected by sniffing the
  first byte for the DER SEQUENCE tag, so a raw signature whose `r` began
  with `0x30` was emitted unconverted. OpenSSL rejects such certificates
  and CRLs with a signature failure (micro509's own verifier masked the
  bug by making the mirror-image guess). Detection is now by exact raw
  length. Affects all ECDSA-signed artifacts from previous releases —
  re-issue anything that fails external verification.

## [0.7.0] - 2026-07-04

Pre-1.0 API freeze cleanup: one coherent breaking pass over vocabulary,
error-handling doctrine, type shapes, and export surface, so 1.0 can freeze
a surface with no known regrets. Every rename is in the migration table
below.

### Changed (BREAKING)

- **Revocation defaults to hard-fail once enabled.** Revocation checking
  remains opt-in (no evidence supplied ⇒ no check), but once `revocation`
  is passed, `policy.mode` now defaults to `'hard-fail'`: indeterminate
  status **denies**. Opt back into the old behavior explicitly with
  `policy: { mode: 'soft-fail' }`. Mental model: no revocation input → no
  check; revocation input → revocation matters.

- **Vocabulary unified.** The CRL/OCSP discriminant is `kind` everywhere
  (was a `kind`/`source`/`type` mix); the verifier-level can't-tell status
  is `'indeterminate'` everywhere (was `'unknown'` in standalone checks vs
  `'indeterminate'` in chain checks). Protocol-level reason codes that
  quote RFC 6960's `unknown` certificate status keep the word
  (`ocsp_status_unknown`, `certificate_status_unknown`,
  `responder_revocation_unknown`), as does `OcspCertStatus`.

- **Result doctrine completed.** The last public parsers consuming
  untrusted input that still threw now return a typed `Result`
  (`code: 'malformed'`): CRL, OCSP request/response, PKCS#12 MacData, and
  the PEM primitives. Each has an `*OrThrow` twin (same convention as the
  x509 parsers since 0.3.0).

- **Illegal states made unrepresentable.** `ParsedPkcs7SignerInfo`
  discriminates on `hasSignedAttrs` (when `true`, `signedAttrsDer` is
  guaranteed); `CertificateRevocationStatus` is a discriminated union
  (good/revoked always carry `source`, revoked always carries `revocationInfo`,
  indeterminate always carries `indeterminateReasons`); `BasicConstraints` rejects
  `{ ca: false, pathLength }` at compile time; `ParsedPkcs12MacData.valid`
  (optional boolean tri-state) became
  `verification: 'valid' | 'invalid' | 'unchecked'`; `ParsedName.values`
  is a readonly map; `ValidateCandidatePathResult` lost its duplicate
  top-level `policyValidation`.

- **pkcs7 creators match the rest of the library.** `createPkcs7CertBag`
  and `createPkcs7SignedData` return a `Result` whose value is
  `{ der, pem, base64 }` material like every other creator (check `.ok`,
  then read `.value`); the `Der`/`Pem` variants are gone.

- **Signature-only verifiers say so.** `verifyOcspResponseSignature` /
  `verifyCertificateRevocationListSignature` check the signature only —
  the bare `verify*` names read as full validation, which is
  `validateOcspResponse` / `validateCertificateRevocationList`.
  (`verifyCertificateSigningRequest` and `verifyPkcs7SignedData` keep
  their names: each is the complete operation for its object.)

- **Export surface curated.** `micro509/revocation` and `micro509/verify`
  list every export explicitly (no `export type *`); dead aliases removed
  (`MatchableServiceIdentityInput`, `VerifyServiceIdentityInput`,
  `MatchServiceIdentityEvaluation` — use `ServiceIdentityInput`);
  `rethrowIfInvariant` (internal control flow) left `micro509/result`;
  `Pbes2EncryptionOptions`/`Pbes2EncryptionScheme`/`Pbes2Prf` left the
  public barrels (`EncryptedPkcs8Options` and `PfxEncryptionOptions` are
  the canonical names); the duplicate `CertificateSource` alias on the
  revocation subpath (which collided with the root-exported verify type
  under a different shape) is gone — chain inputs use
  `RevocationCertificateSource`. `IssuingDistributionPoint*` types moved
  from the x509 surface to `micro509/revocation` (they are CRL types; the
  root still exports them).

#### Migration table

| 0.6.0                                                          | 0.7.0                                                      |
| -------------------------------------------------------------- | ---------------------------------------------------------- |
| `RevocationStatus` `'unknown'`                                 | `'indeterminate'`                                          |
| `RevocationCheckUnknownValue`                                  | `RevocationCheckIndeterminateValue`                        |
| `revocation_status_unknown`                                    | `revocation_status_indeterminate`                          |
| `RevocationSource.type`                                        | `RevocationSource.kind`                                    |
| `RevocationCheck{Good,Revoked}Value.source`                    | `.kind`                                                    |
| `RevocationIndeterminateEvidence.source`                       | `.kind`                                                    |
| `revocationInfo.date`                                          | `revocationInfo.revocationDate`                            |
| `policy.mode` default `'soft-fail'`                            | `'hard-fail'`                                              |
| `verifyOcspResponse`                                           | `verifyOcspResponseSignature`                              |
| `verifyCertificateRevocationList`                              | `verifyCertificateRevocationListSignature`                 |
| `parseCertificateRevocationList{Der,Pem}` (throwing)           | Result-returning; `*OrThrow` for the old behavior          |
| `parseOcsp{Request,Response}{Der,Pem}` (throwing)              | Result-returning; `*OrThrow` for the old behavior          |
| `parsePkcs12MacData` (throwing)                                | Result-returning; `parsePkcs12MacDataOrThrow`              |
| `pemDecode` / `splitPemBlocks` / `categorizePemBlocks`         | Result-returning; `*OrThrow` for the old behavior          |
| `ParsedPkcs12MacData.valid?: boolean`                          | `verification: 'valid' \| 'invalid' \| 'unchecked'`        |
| `createPkcs7CertBag{Der,Pem}`                                  | `createPkcs7CertBag` (Result of `{ der, pem, base64 }`)    |
| `createPkcs7SignedData{Der,Pem}`                               | `createPkcs7SignedData` (Result of `{ der, pem, base64 }`) |
| `Pkcs7CertBag`                                                 | `Pkcs7CertBagMaterial`                                     |
| `Import{Rsa,Ec,Ed25519}PublicKeyInput`                         | `Import{Rsa,Ec,Ed25519}KeyInput`                           |
| PBES2 option `encryption: 'aes256-cbc'`                        | `cipher: 'AES-256-CBC'`                                    |
| PBES2 option `prf: 'hmac-sha256'`                              | `prf: 'HMAC-SHA-256'`                                      |
| `trustedResponderCertificates` (validateOcspResponse)          | `trustedOcspResponders`                                    |
| `delta_crl_unsupported` / `indirect_crl_unsupported`           | `unsupported_delta_crl` / `unsupported_indirect_crl`       |
| `service_identity_type_unsupported`                            | `unsupported_service_identity_type`                        |
| `service_identity_service_mismatch`                            | `service_identity_mismatch`                                |
| `VerifyServiceIdentityInput` / `MatchableServiceIdentityInput` | `ServiceIdentityInput`                                     |
| `VerifyOcspResponse{Result,Failure}`                           | `VerifyOcspResponseSignature{Result,Failure}`              |
| `VerifyCertificateRevocationList{Result,Failure}`              | `VerifyCertificateRevocationListSignature{Result,Failure}` |

### Added

- Runtime code arrays `REVOCATION_INDETERMINATE_REASON_CODES` and
  `REVOCATION_INDETERMINATE_REASONS` (the `VERIFY_ERROR_CODES` pattern);
  their unions now derive from the arrays.
- The root entry point exports every type reachable from public signatures
  that were previously subpath-only (MacData, policy-validation outcome,
  identity failure details, revocation error codes/failure payloads, and
  the new `Parse*Result` / `Pem*Result` types).
- `Pkcs7CertificateSource` and `PfxCertificateSource` accept an
  already-parsed `ParsedCertificate` (parity with the revocation source
  unions).
- Documented error-code stability policy: unions may gain members in
  minor releases — treat them as non-exhaustive.
- CI now smoke-tests the two previously untested runtime claims: Cloudflare
  Workers (real workerd via wrangler's test harness) and browsers (headless
  Chromium via Playwright, loading the built `dist/` output). All five
  supported runtimes are now exercised in CI.

### Fixed

- Manual `npm publish` outside the release workflow now fails via a
  `prepublishOnly` guard: only the workflow rewrites the dev-only
  `bun → ./src/*.ts` export conditions, so a raw publish would ship an
  exports map pointing at files missing from the dist-only tarball.

## [0.6.0] - 2026-07-04

Full standards surface claimed complete: all four RFC status rows — 5280,
6960, 6125, 9618 — now read `complete`, backed by the full NIST PKITS
suite and RFC-exact name-constraint handling.

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

[Unreleased]: https://github.com/kjanat/micro509/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/kjanat/micro509/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/kjanat/micro509/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kjanat/micro509/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kjanat/micro509/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kjanat/micro509/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kjanat/micro509/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/kjanat/micro509/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/kjanat/micro509/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/kjanat/micro509/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kjanat/micro509/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kjanat/micro509/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kjanat/micro509/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kjanat/micro509/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kjanat/micro509/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kjanat/micro509/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kjanat/micro509/releases/tag/v0.1.0
