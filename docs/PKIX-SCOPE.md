# PKIX validation scope checklist

## Standards status

| Area                       | Status    | Notes                                                                                                                                                                                                        |
| -------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| RFC 5280 path validation   | `partial` | core path validation, policy inputs/processing, and initial subtree inputs ship; full revocation integration and complete PKITS coverage are not complete yet                                                |
| RFC 6960 OCSP              | `partial` | request/response parsing, signature checks, responder binding/authorization, nonce/request matching, freshness checks, and full request coverage ship; local responder-policy acceptance is still incomplete |
| RFC 6125 service identity  | `partial` | `matchServiceIdentity()` ships DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in CN-compat checks; verification helpers still wire DNS/IP identities only                                            |
| RFC 9618 policy validation | `partial` | RFC 9618-style policy state, enforcement, outputs, and focused PKITS coverage ship; broader conformance evidence is still incomplete                                                                         |

## 1. Define the boundary up front

- [x] Treat **certification path validation** as a function over a **prospective certification path** plus validation inputs, not as “build whatever chain you can find and hope for the best.”
      RFC 5280 Section 6.1.1 defines the algorithm in terms of a candidate path and nine inputs. (IETF Datatracker[^rfc5280])
- [x] Keep **path building/discovery** separate from **path validation**.
- [ ] Keep **service identity matching** separate from **path validation**.
- [x] Keep **revocation** separate from **path validation**.

## 2. Required inputs for RFC 5280-style path validation

- [x] Prospective certification path.
- [x] Validation time.
- [x] Trust anchor information: trusted issuer name, trusted public key algorithm,
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
- [ ] Reject the path if any required path-processing step fails. (IETF Datatracker[^rfc5280])

## 4. Extension handling

- [x] Parse and preserve all extensions, including unknown ones.
- [x] Reject certificates containing an **unsupported critical extension** or a critical extension whose contents cannot be processed.
- [x] Process recognized non-critical extensions when relevant to path processing.
- [x] Expose raw extension data so callers can layer application-specific policy on top. (IETF Datatracker[^rfc5280])

## 5. Name constraints

- [x] Support `nameConstraints` on CA certificates.
- [x] Support initial permitted/excluded subtrees as validator inputs.
- [x] Apply constraints across supported name forms, not just DNS SANs.
- [x] Handle self-issued certificates correctly when evaluating constraints. (IETF Datatracker[^rfc5280])

Current GeneralName matrix for `nameConstraints`:

| Form                        | Parser role                                 | Validator role                           | Status    |
| --------------------------- | ------------------------------------------- | ---------------------------------------- | --------- |
| `rfc822Name` / `dNSName`    | decode to typed email/DNS values            | enforce                                  | `partial` |
| `uniformResourceIdentifier` | decode to typed URI values                  | enforce host-based matching              | `partial` |
| `iPAddress`                 | decode to address+mask bytes                | enforce                                  | `partial` |
| `directoryName`             | preserve DN payload for later structured DN | enforce today, but semantic compare lags | `partial` |
| `otherName`                 | do not silently discard in final design     | fail closed if critical                  | `not yet` |
| `x400Address`               | do not silently discard in final design     | fail closed if critical                  | `not yet` |
| `ediPartyName`              | do not silently discard in final design     | fail closed if critical                  | `not yet` |
| `registeredID`              | do not silently discard in final design     | fail closed if critical                  | `not yet` |

- Parser responsibility: preserve enough tag/type information that validation can make a deterministic supported-vs-unsupported decision.
- Validator responsibility: enforce supported forms and reject critical under-enforced cases instead of silently widening trust.

## 6. Certificate policy processing

- [x] Support `certificatePolicies`.
- [x] Support `policyConstraints`.
- [x] Support `policyMappings`.
- [x] Support `inhibitAnyPolicy`.
- [x] Use the **RFC 9618** update rather than the older RFC 5280 policy-tree algorithm, because RFC 9618 replaced it with an equivalent, more efficient algorithm to avoid worst-case exponential blowups and DoS risk. (IETF Datatracker[^rfc9618])
- [x] Keep public wording at `partial` until broader conformance evidence lands.

## 7. Trust-anchor model

- [x] Accept trust anchors as structured input, not only as “root cert PEM”.
- [x] Allow trust anchor info to come from a self-signed certificate as a convenience, but treat the trust anchor as out-of-band trust input.
- [x] Do not assume every self-signed cert is a trust anchor. (IETF Datatracker[^rfc5280])

## 8. Application/service identity checks

- [ ] Keep hostname/service-name matching in a separate API from path validation.
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
- [x] Enforce response freshness using `thisUpdate` / `nextUpdate` and configurable clock skew.
- [x] Return `good`, `revoked`, and `unknown` distinctly.
- [x] Support optional nonce handling if you want replay binding between request and response. RFC 9654 defines the updated nonce extension details. (IETF Datatracker[^rfc6960])

## 11. OCSP responder authorization rules

- [ ] Accept an OCSP response signer if it matches local OCSP responder configuration for the certificate in question.
- [x] Accept it if the signer is the issuing CA certificate itself.
- [x] Accept it if the signer cert contains EKU `id-kp-OCSPSigning` **and** was issued directly by the CA that issued the target certificate.
- [x] Reject the response if the signer certificate meets none of those conditions.
- [ ] Decide and document how you will handle revocation checking of the responder certificate; RFC 6960 allows CA signaling for that and also leaves room for local policy. (IETF Datatracker[^rfc6960])

Focused OCSP auth/completeness/freshness fixtures live in [`test/ocsp-fixtures.test.ts`](../test/ocsp-fixtures.test.ts).

## 12. CRL support checklist

- [x] Treat CRL validation as a separate revocation subsystem.
- [x] Parse CRLs and CRL extensions.
- [x] Verify CRL signatures and issuer linkage.
- [x] Enforce CRL time/freshness semantics.
- [ ] Support distribution points if you want network-assisted revocation.
- [ ] Add delta CRL handling only if you actually want to live in that swamp. RFC 5280 defines CRL validation separately from path validation. (IETF Datatracker[^rfc5280])

## 13. API design checklist

- [x] Keep path building separate from path validation.
- [ ] Keep service identity matching in a separate API from path validation.
- [x] Keep revocation checking separate from path validation.
- [x] Expose structured validation inputs instead of hiding policy/name-constraint knobs.
- [x] Return typed failure reasons for currently implemented path-validation, CRL, and OCSP checks.
- [ ] Distinguish hard validation failure from “status unknown / not checked”.

## 14. Test/conformance checklist

- [ ] Add fixed RFC-style test vectors for builders, parsers, and validators.
- [x] Add round-trip tests for certs, CSRs, names, and extensions.
- [x] Add a focused PKITS harness for shipped path-validation claims. See [`docs/PKITS-HARNESS.md`](./PKITS-HARNESS.md) and [`test/pkits.test.ts`](../test/pkits.test.ts).
- [ ] Add malformed DER / fuzz tests.
- [x] Differential-test against at least one mature implementation. See [`docs/DIFF-HARNESS.md`](./DIFF-HARNESS.md) and [`test/differential.test.ts`](../test/differential.test.ts).
- [ ] Run the validator against **NIST PKITS**, which NIST describes as a comprehensive X.509 path validation test suite for relying parties. (NIST Computer Security Resource Center[^x-509-path-validation])

## Recommended claim language

### Safe to claim now

- candidate chain validation
- signature / time / issuer / CA / key usage / path length checks
- basic DNS/IP SAN + EKU matching
- typed parse/build APIs

### Do **_not_** claim until implemented

- full RFC 5280 path validation
- full certificate policy validation
- full name-constraint validation
- full RFC 6960 OCSP compliance
- full revocation checking

### Honest wording

- “Validates candidate certificate paths with configurable trust anchors and typed results.”
- “Revocation is a separate API; `matchServiceIdentity()` handles shipped RFC 6125 identifier matching, while verification helpers currently compose DNS/IP identity checks on top of path validation.”
- “Advanced RFC 5280 features such as policy processing and full name-constraint handling are not yet complete.” (IETF Datatracker[^rfc5280])

The main monster under the bed is simple: **once you say “full RFC 5280,” you’ve signed up for policy processing, name constraints, critical-extension behavior, and trust-anchor semantics — not just signatures and dates.** (IETF Datatiracker[^rfc5280])

[^rfc5280]: https://datatracker.ietf.org/doc/html/rfc5280 "RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"

[^rfc9618]: https://datatracker.ietf.org/doc/html/rfc9618 "RFC 9618 - Updates to X.509 Policy Validation"

[^rfc6125]: https://datatracker.ietf.org/doc/html/rfc6125 "RFC 6125 - Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)"

[^rfc6960]: https://datatracker.ietf.org/doc/html/rfc6960 "RFC 6960 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP"

[^x-509-path-validation]: https://csrc.nist.gov/projects/pki-testing/x-509-path-validation-test-suite "X.509 Path Validation Test Suite - Public Key Infrastructure Testing | CSRC"
