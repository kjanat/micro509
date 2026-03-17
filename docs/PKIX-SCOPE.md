# PKIX validation scope and roadmap

This file is the canonical support boundary, claim-language guide, and
forward-work backlog for the PKIX-facing surface.

## Standards status

| Area                       | Status    | Notes                                                                                                                                                                                                                                                          |
| -------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 5280 path validation   | `partial` | core path validation, supported-form name constraints, initial subtree inputs, RFC 9618 policy processing, malformed-DER coverage, and broad PKITS harness coverage ship; revocation stays a separate API and broader conformance evidence is still incomplete |
| RFC 6960 OCSP              | `partial` | request/response parsing, signature checks, responder binding/authorization, nonce/request matching, freshness checks, and full request coverage ship; local responder-policy acceptance is still incomplete                                                   |
| RFC 6125 service identity  | `partial` | `matchServiceIdentity()` ships DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in CN-compat checks; verification helpers still wire DNS/IP identities only                                                                                              |
| RFC 9618 policy validation | `partial` | RFC 9618-style policy state, enforcement, outputs, and broad PKITS harness coverage ship; broader conformance evidence is still incomplete                                                                                                                     |

Current conformance evidence:

- [`test/pkits.test.ts`](../test/pkits.test.ts),
- [`test/policy.test.ts`](../test/policy.test.ts),
- [`test/name-constraints.test.ts`](../test/name-constraints.test.ts),
- [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts),
- [`test/identity-fixtures.test.ts`](../test/identity-fixtures.test.ts),
- [`test/revocation.test.ts`](../test/revocation.test.ts),
- [`test/malformed-der.test.ts`](../test/malformed-der.test.ts), and
- [`test/differential.test.ts`](../test/differential.test.ts).

## 1. Define the boundary up front

- [x] Treat **certification path validation** as a function over a
      **prospective certification path** plus validation inputs, not as
      “build whatever chain you can find and hope for the best.”\
       RFC 5280 Section 6.1.1 defines the algorithm in terms of a candidate path
      and nine inputs. (IETF Datatracker[^rfc5280])
- [x] Keep **path building/discovery** separate from **path validation**.
- [x] Keep **service identity matching** separate from **path validation**.
- [x] Keep **revocation** separate from **path validation**.

## 2. Required inputs for RFC 5280-style path validation

- [x] Prospective certification path.
- [x] Validation time.
- [x] Trust anchor information: trusted issuer name,
      trusted public key algorithm,
      trusted public key, and optional trusted key parameters.
- [x] User-initial-policy-set.
- [x] Initial policy-mapping inhibit flag.
- [x] Initial explicit-policy flag.
- [x] Initial anyPolicy-inhibit flag.
- [x] Initial permitted subtrees.
- [x] Initial excluded subtrees. (IETF Datatracker[^rfc5280])

## 3. Core certificate/path checks

- [x] Parse DER strictly enough to reject malformed certificates.
- [x] Verify issuer/subject chaining across the candidate path.
- [x] Verify each certificate signature using the evolving working public key.
- [x] Check validity time (`notBefore` / `notAfter`) against the chosen validation time.
- [x] Enforce `basicConstraints` for CA certificates.
- [x] Enforce `pathLenConstraint` where applicable.
- [x] Enforce `keyUsage`, especially `keyCertSign` for CAs used to sign subordinate certs.
- [x] Process self-issued vs non-self-issued certs correctly for path length and name constraints.
- [x] Reject the path if any required path-processing step fails. (IETF Datatracker[^rfc5280])

## 4. Extension handling

- [x] Parse and preserve all extensions, including unknown ones.
- [x] Reject certificates containing an **unsupported critical extension** or a
      critical extension whose contents cannot be processed.
- [x] Process recognized non-critical extensions when relevant to path processing.
- [x] Expose raw extension data so callers can layer application-specific policy on top. (IETF Datatracker[^rfc5280])

## 5. Name constraints

- [x] Support `nameConstraints` on CA certificates.
- [x] Support initial permitted/excluded subtrees as validator inputs.
- [x] Apply constraints across supported name forms, not just DNS SANs.
- [x] Handle self-issued certificates correctly when evaluating constraints.
      (IETF Datatracker[^rfc5280])

Current GeneralName matrix for `nameConstraints`:

| Form                        | Parser role                             | Validator role                         | Status    |
| --------------------------- | --------------------------------------- | -------------------------------------- | --------- |
| `rfc822Name` / `dNSName`    | decode to typed email/DNS values        | enforce                                | `partial` |
| `uniformResourceIdentifier` | decode to typed URI values              | enforce host-based matching            | `partial` |
| `iPAddress`                 | decode to address+mask bytes            | enforce                                | `partial` |
| `directoryName`             | preserve structured DN payload          | enforce with RFC 5280 semantic compare | `partial` |
| `otherName`                 | do not silently discard in final design | fail closed if critical                | `not yet` |
| `x400Address`               | do not silently discard in final design | fail closed if critical                | `not yet` |
| `ediPartyName`              | do not silently discard in final design | fail closed if critical                | `not yet` |
| `registeredID`              | do not silently discard in final design | fail closed if critical                | `not yet` |

- Parser responsibility: preserve enough tag/type information that validation can make a deterministic supported-vs-unsupported decision.
- Validator responsibility: enforce supported forms and reject critical under-enforced cases instead of silently widening trust.

## 6. Certificate policy processing

- [x] Support `certificatePolicies`.
- [x] Support `policyConstraints`.
- [x] Support `policyMappings`.
- [x] Support `inhibitAnyPolicy`.
- [x] Use the **RFC 9618** update rather than the older RFC 5280 policy-tree
      algorithm, because RFC 9618 replaced it with an equivalent, more efficient
      algorithm to avoid worst-case exponential blowups and DoS risk.
      (IETF Datatracker[^rfc9618])
- [x] Keep public wording at `partial` until broader conformance evidence lands.

## 7. Trust-anchor model

- [x] Accept trust anchors as structured input, not only as “root cert PEM”.
- [x] Allow trust anchor info to come from a self-signed certificate as a
      convenience, but treat the trust anchor as out-of-band trust input.
- [x] Do not assume every self-signed cert is a trust anchor.
      (IETF Datatracker[^rfc5280])

## 8. Application/service identity checks

- [x] Keep hostname/service-name matching in a separate API from path validation.
- [x] For currently supported identity types (`dNSName`, `iPAddress`), match `subjectAltName` entries of the corresponding type first.
- [x] `matchServiceIdentity()` supports `dNSName`, `iPAddress`, URI-ID, and SRV-ID matching with wildcard and IDNA coverage.
- [x] Only support CN fallback as an explicit compatibility mode, because RFC 6125 treats CN-ID usage as existing practice and prefers `subjectAltName`; CN comparison is deprecated. (IETF Datatracker[^rfc6125])
- [x] Make wildcard behavior explicit and test it hard.

Focused RFC 6125 identity fixtures live in [`test/identity-fixtures.test.ts`](../test/identity-fixtures.test.ts).

## 9. EKU / purpose checks

- [x] Keep EKU checks separate from raw path validity.
- [x] Allow callers to request purposes such as `serverAuth`, `clientAuth`, etc.
- [x] Distinguish “certificate is path-valid” from “certificate is acceptable for this application”.

## 10. OCSP support checklist

- [x] Build `CertID` from issuer name hash, issuer key hash, serial number, and hash algorithm.
- [x] Discover the responder from AIA `id-ad-ocsp` or let callers provide a responder URL explicitly.
- [x] Parse and verify `BasicOCSPResponse`.
- [x] Check that the response fully and correctly refers to the requested certificate set.
- [x] Validate the OCSP response signature.
- [ ] Validate responder authorization exhaustively.
  - [ ] Land RFC 6960 Section 4.2.2.2 criterion 1: explicit local signer acceptance scoped to the certificate / issuing CA in question, not only embedded-certificate discovery or caller-picked signer input. Sources: [`docs/rfc/rfc6960.txt`](./rfc/rfc6960.txt), [`src/revocation/ocsp.ts`](../src/revocation/ocsp.ts), [`src/revocation/revocation.ts`](../src/revocation/revocation.ts).
  - [ ] Decide and enforce responder-certificate revocation policy (`id-pkix-ocsp-nocheck`, CA-signaled CRL/AIA pointers, or caller-local policy) during OCSP validation. Sources: [`docs/rfc/rfc6960.txt`](./rfc/rfc6960.txt), [`src/revocation/ocsp.ts`](../src/revocation/ocsp.ts).
  - [ ] Add fixture coverage for configured-responder accept/reject, responder-cert revocation policy, and historical-time validation so this claim is earned by tests. Sources: [`test/ocsp.test.ts`](../test/ocsp.test.ts), [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts), [`test/differential.test.ts`](../test/differential.test.ts).
- [x] Enforce response freshness using `thisUpdate` / `nextUpdate` and configurable clock skew.
- [x] Return `good`, `revoked`, and `unknown` distinctly.
- [x] Support optional nonce handling if you want replay binding between request and response. RFC 9654 defines the updated nonce extension details. (IETF Datatracker[^rfc6960])

## 11. OCSP responder authorization rules

- [ ] Accept an OCSP response signer if it matches local OCSP responder configuration for the certificate in question.
  - [ ] Add an explicit validation input that binds trusted responder certificate(s) to one or more issuer CAs / target-certificate scopes; current `configuredResponders` only resolves URIs and optional responder certificates for orchestration. Sources: RFC 6960 Section 4.2.2.2 item 1, [`src/revocation/revocation.ts`](../src/revocation/revocation.ts), [`test/revocation.test.ts`](../test/revocation.test.ts).
  - [ ] Thread that local responder policy through [`validateOcspResponse()`](../src/revocation/ocsp.ts) and revocation orchestration before falling back to issuer-cert or delegated-responder rules. Sources: [`src/revocation/ocsp.ts`](../src/revocation/ocsp.ts), [`src/revocation/revocation.ts`](../src/revocation/revocation.ts).
  - [ ] Add positive and negative fixtures proving a locally authorized signer is accepted only for the configured issuer scope. Sources: [`test/ocsp.test.ts`](../test/ocsp.test.ts), [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts), [`test/revocation.test.ts`](../test/revocation.test.ts).
- [x] Accept it if the signer is the issuing CA certificate itself.
- [x] Accept it if the signer cert contains EKU `id-kp-OCSPSigning` **and** was issued directly by the CA that issued the target certificate.
- [x] Reject the response if the signer certificate meets none of those conditions.
- [ ] Decide and document how you will handle revocation checking of the responder certificate; RFC 6960 allows CA signaling for that and also leaves room for local policy. (IETF Datatracker[^rfc6960])
  - [ ] Parse and expose `id-pkix-ocsp-nocheck` so callers can distinguish a CA-signaled no-recheck responder cert from the absence of policy. Sources: RFC 6960 Section 4.2.2.2.1, [`docs/rfc/rfc6960.txt`](./rfc/rfc6960.txt), [`src/x509/extensions.ts`](../src/x509/extensions.ts), [`src/x509/parse.ts`](../src/x509/parse.ts).
  - [ ] Define validator policy knobs for responder-cert revocation: honor `nocheck`, require CRL/OCSP evidence, or allow caller-local override when the CA gives no method. Sources: RFC 6960 Section 4.2.2.2.1, [`src/revocation/ocsp.ts`](../src/revocation/ocsp.ts), [`src/revocation/revocation.ts`](../src/revocation/revocation.ts).
  - [ ] Add fixtures for each policy branch and document the shipped default so partial RFC 6960 wording stays honest. Sources: [`test/ocsp.test.ts`](../test/ocsp.test.ts), [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts).
  - [ ] Pass caller evaluation time through delegated responder chain validation so responder authorization is checked at the same instant as the OCSP response. Sources: [`src/revocation/ocsp.ts`](../src/revocation/ocsp.ts), [`src/verify/verify.ts`](../src/verify/verify.ts).

Focused OCSP auth/completeness/freshness fixtures live in [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts).

## 12. CRL support checklist

- [x] Treat CRL validation as a separate revocation subsystem.
- [x] Parse CRLs and CRL extensions.
- [x] Verify CRL signatures and issuer linkage.
- [x] Enforce CRL time/freshness semantics.
- [x] Parse CRL distribution points and enforce distribution-point scope during
      CRL applicability; CRL discovery/fetch hooks are not shipped.
- [x] Add delta CRL handling only if you actually want to live in that swamp. RFC 5280 defines CRL validation separately from path validation. (IETF Datatracker[^rfc5280])

## 13. API design checklist

- [x] Keep path building separate from path validation.
- [x] Keep service identity matching in a separate API from path validation.
- [x] Keep revocation checking separate from path validation.
- [x] Expose structured validation inputs instead of hiding policy/name-constraint knobs.
- [x] Return typed failure reasons for currently implemented path-validation, CRL, and OCSP checks.
- [x] Distinguish hard validation failure from revocation status `unknown` in
      revocation orchestration; chain, CRL, and OCSP validators still return
      binary success/failure results.

## 14. Test/conformance checklist

- [x] Add fixed RFC-style test vectors for builders, parsers, and validators.
- [x] Add round-trip tests for certs, CSRs, names, and extensions.
- [x] Add a PKITS harness for shipped path-validation claims and gap reporting. See [`docs/PKITS-HARNESS.md`](./PKITS-HARNESS.md) and [`test/pkits.test.ts`](../test/pkits.test.ts).
- [x] Add malformed DER / fuzz tests.
- [x] Differential-test against at least one mature implementation. See [`docs/DIFF-HARNESS.md`](./DIFF-HARNESS.md) and [`test/differential.test.ts`](../test/differential.test.ts).
- [x] Run the validator against **NIST PKITS** as a gap-report harness, which NIST describes as a comprehensive X.509 path validation test suite for relying parties. (NIST Computer Security Resource Center[^x-509-path-validation])

## Recommended claim language

### Safe to claim now

- candidate chain validation with typed failures and RFC 9618 policy outcomes
- signature / time / issuer / CA / key usage / path length / name-constraint checks
- separate revocation orchestration plus focused CRL / OCSP fixture coverage
- `matchServiceIdentity()` for DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in DNS CN compatibility
- certificate / CSR algorithm surface: RSA PKCS#1 v1.5, constrained RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, and Ed25519
- encrypted private-key interop surface: PBES2 AES-128/192/256-CBC with PBKDF2 HMAC-SHA1/HMAC-SHA256, plus traditional PEM AES-128/192/256-CBC
- typed parse/build APIs

### Do **_not_** claim until implemented

- full RFC 5280 path validation
- full certificate policy validation
- full name-constraint validation
- full RFC 6960 OCSP compliance
- full revocation checking
- full WebCrypto algorithm parity
- `DSA`, `Ed448`, `ECDH`, `X25519`, `RSA-OAEP`, or generic symmetric-crypto API support

### Honest wording

- “Validates candidate certificate paths with configurable trust anchors and typed results.”
- “Revocation is a separate API; `matchServiceIdentity()` handles shipped RFC 6125 identifier matching, while verification helpers currently compose DNS/IP identity checks on top of path validation.”
- “RFC 5280 path validation is partial: supported-form name constraints, initial subtree inputs, and RFC 9618 policy processing ship, but revocation stays separate and broader conformance evidence is still incomplete.” (IETF Datatracker[^rfc5280])
- “Certificate and CSR signing support covers RSA PKCS#1 v1.5, constrained RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, and Ed25519; encrypted key-container interop is limited to the shipped AES-CBC + PBKDF2 profiles.”

### Shipped algorithm constraints

- Keep `RSA-PSS` support limited to the shipped parameter profile: `MGF1` only, matching digest and MGF hash, `trailerField` absent or `1`, and typed validation failures for unsupported-but-well-formed params instead of silent fallback.
- Keep builder defaults explicit: omitted `RSA-PSS` `saltLength` means digest-size salt, and emitted `AlgorithmIdentifier` values stay explicit rather than relying on ASN.1 defaults.
- Treat `P-521` as a first-class ECDSA curve in the current key/sign/verify surface, not as a precedent for broad WebCrypto-parity claims.
- Keep encrypted-key interop limited to PBES2 PBKDF2 HMAC-SHA1/HMAC-SHA256 with AES-128/192/256-CBC plus traditional PEM AES-128/192/256-CBC until docs and fixtures expand.
- Do not widen scope just because WebCrypto exposes an algorithm; `DSA`, `Ed448`, `X25519`, `ECDH`, `RSA-OAEP`, `AES`, and `HMAC` still need a PKI-specific product reason, docs, and tests before they belong here.
- Regression coverage for this surface should keep `RSA-PSS` negative parameter cases, `P-521` end-to-end flows, and encrypted-key compatibility locked down. See [`test/verify.test.ts`](../test/verify.test.ts), [`test/certificate.test.ts`](../test/certificate.test.ts), [`test/csr.test.ts`](../test/csr.test.ts), [`test/keys.test.ts`](../test/keys.test.ts), [`test/internals.test.ts`](../test/internals.test.ts), and [`test/differential.test.ts`](../test/differential.test.ts).

The main monster under the bed is simple: **once you say “full RFC 5280,” you've signed up for policy processing, name constraints, critical-extension behavior, trust-anchor semantics, and revocation integration - not just signatures and dates.** (IETF Datatracker[^rfc5280])

## 15. Forward work

### Immediate priorities

- [ ] OCSP response signer validation against explicit local responder configuration
- [ ] CMS `signedData` generation, not only parse/verify

### Path validation / PKIX completeness

- [ ] Preserve unsupported constrained `GeneralName` forms through parse and validation so critical unsupported `nameConstraints` fail closed instead of disappearing.
  - [ ] Keep `otherName`, `x400Address`, `ediPartyName`, and `registeredID` distinguishable from supported forms at the parse boundary.
  - [ ] Keep builder scope separate from parse/validate fail-closed behavior.
  - Sources: [`docs/rfc/rfc5280.txt`](./rfc/rfc5280.txt), [`src/x509/parse.ts`](../src/x509/parse.ts), [`src/verify/verify.ts`](../src/verify/verify.ts), [`test/name-constraints.test.ts`](../test/name-constraints.test.ts).
- [ ] Finish semantic `directoryName` comparison so subtree checks do not depend on raw DER equality or DER-prefix shortcuts.
  - [ ] Compare ordered RDN sequences semantically, with RFC 4518-style string prep for the shipped string types.
  - [ ] Add regressions for mixed `PrintableString`/`UTF8String`, Unicode normalization, case/space normalization, multi-valued RDN reordering, and subtree suffix matching.
  - Sources: [`docs/rfc/rfc5280.txt`](./rfc/rfc5280.txt), [`src/x509/parse.ts`](../src/x509/parse.ts), [`src/verify/verify.ts`](../src/verify/verify.ts), [`test/name-constraints.test.ts`](../test/name-constraints.test.ts).
- [ ] Broaden conformance evidence before any RFC 5280 / RFC 9618 claim moves past `partial`.
  - [x] Run broad NIST PKITS harness coverage from the mirrored BoringSSL corpus.
  - [ ] Keep policy and name-constraint claim unlocks tied to fixture-backed regressions and differential evidence.
  - Sources: [`docs/PKITS-HARNESS.md`](./PKITS-HARNESS.md), [`test/pkits.test.ts`](../test/pkits.test.ts), [`test/policy.test.ts`](../test/policy.test.ts), [`test/differential.test.ts`](../test/differential.test.ts).

### Revocation / status

- [ ] OCSP response signer validation against explicit local responder configuration
- [ ] OCSP responder revocation policy handling
- [ ] OCSP request/response builders with richer extension support
- [ ] CRL distribution point discovery / fetch hooks
- [ ] Richer CRL entry extensions

### CMS / PKCS / container interop

- [ ] CMS/PKCS#7 detached content support
- [ ] CMS signer certificate selection helpers
- [ ] PKCS#12/PFX encrypted certificate safe bags
- [ ] Broader PKCS#12 algorithms and compatibility modes
- [ ] Traditional PEM encryption algorithms beyond AES-128/192/256-CBC

### API / DX

- [ ] Zero-config decoder-map inference helpers for even tighter typing
- [ ] Higher-level cert/CSR/CRL/OCSP fixtures for tests and demos
- [ ] Decide whether verification convenience helpers should stay DNS/IP-only or grow URI-ID / SRV-ID composition on top of `matchServiceIdentity()`.

### Refactor priorities (pre-1.0)

Items ranked by how much existing code must change - not just new code added.

#### 1. Distinguish hard failure from "status unknown" - L, potentially breaking

Changes Result union shapes in `verify.ts`, `crl.ts`, `ocsp.ts`. Every
consumer pattern-matching on `result.ok` is affected. Touches
`VerifyChainResult`, `ValidateCandidatePathResult`,
`ValidateCertificateRevocationListResult`, and
`ValidateOcspResponseResult`.

**Open question:** third variant `{ ok: "partial" }`, or keep binary `ok`
with `severity` field on failures?

#### 2. CMS signedData generation - M

~200 lines new in `pkcs7.ts` but must invert the signed-attributes verify
flow (`verifySignedAttrs`). Mirrors existing parsing types for round-trip
consistency. Moderate coupling through `signing.ts`.

#### 3. Explicit local OCSP responder policy hooks - M

Most OCSP auth checks ship now, but the remaining gap is explicit local
responder-policy acceptance and the follow-on story for responder revocation.
This likely lands in `ocsp.ts` and `revocation.ts` without widening the pure
validation boundary into network behavior.

### Nice-to-have monsters

- [ ] AIA / CRL / OCSP network client helpers kept separate from pure validation
- [ ] Certificate transparency / SCT parsing
- [ ] Timestamp / TSA structures
- [ ] More complete CMS / ASN.1 utility coverage if the library grows beyond PKIX core

[^rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280 "RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"

[^rfc9618]: https://datatracker.ietf.org/doc/html/rfc9618 "RFC 9618 - Updates to X.509 Policy Validation"

[^rfc6125]: https://datatracker.ietf.org/doc/html/rfc6125 "RFC 6125 - Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)"

[^rfc6960]: https://datatracker.ietf.org/doc/html/rfc6960 "RFC 6960 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP"

[^x-509-path-validation]: https://csrc.nist.gov/projects/pki-testing/x-509-path-validation-test-suite "X.509 Path Validation Test Suite - Public Key Infrastructure Testing | CSRC"
