# Future work

Implementation-ready master plan: `specs/full-standards-compliance.md`.

## Immediate ultra-savage moves

- [ ] CMS `signedData` generation, not only parse/verify
- [ ] OCSP responder cert selection by responderID, not only best-effort included-cert / chain resolution
- [ ] Full `distributionPoint` / `issuingDistributionPoint` structured object models across certificate parsing, not only CRL-side URI-focused shortcuts

## Path validation / PKIX completeness

- [x] Separate candidate path building from path validation more explicitly in the public API
- [x] Structured trust-anchor input model, not only convenience via root certificates
- [x] Unsupported critical extension rejection during candidate path validation
- [x] Self-issued handling for name-constraint / path-processing edge cases
- [x] Name constraints support
- [ ] Initial permitted/excluded subtree validator inputs
- [ ] Certificate policy processing
- [ ] RFC 9618-style policy validation algorithm if policy validation is implemented
- [ ] Malformed DER / fuzz corpus
- [ ] Differential tests against mature implementations
- [ ] NIST PKITS coverage

## Revocation / status

- [ ] OCSP response signer validation against explicit local responder configuration
- [ ] OCSP responder revocation policy handling
- [ ] OCSP request/response builders with richer extension support
- [x] OCSP response freshness clock-skew configuration
- [x] CRL freshness / nextUpdate policy helpers
- [ ] CRL distribution point discovery / fetch hooks
- [ ] Delta CRL application logic, not only parsing
- [ ] Richer CRL entry extensions

## CMS / PKCS / container interop

- [x] CMS/PKCS#7 signature verification over signed attributes where applicable
- [ ] CMS/PKCS#7 detached content support
- [ ] CMS signer certificate selection helpers
- [ ] PKCS#12/PFX encrypted certificate safe bags
- [ ] Broader PKCS#12 algorithms and compatibility modes
- [ ] Traditional PEM encryption algorithm variants beyond current support

## API / DX

- [ ] Zero-config decoder-map inference helpers for even tighter typing
- [ ] Higher-level cert/CSR/CRL/OCSP fixtures for tests and demos
- [x] More explicit validation profiles: raw path-valid, TLS server, TLS client, OCSP responder, CA, etc.
- [x] Better failure typing for revocation / container / CMS subsystems
- [ ] Browser examples and runtime matrix docs

## Refactor priorities (pre-1.0)

Items ranked by how much existing code must change — not just new code added.

### 1. Certificate policy processing — XL

Invasive changes to `verify.ts` (policy state threaded through
`validateCandidatePath`, new state in recursive `search()`), `parse.ts`
(4 new extension parsers for `certificatePolicies`, `policyConstraints`,
`policyMappings`, `inhibitAnyPolicy`), `extensions.ts` (4 new types +
encoders). New `VerifyErrorCode` variants, new fields on
`ValidateCandidatePathInput` + all profile inputs. ~20+ `return failure()`
sites affected.

**Open question:** skip straight to RFC 9618 algorithm, or implement
RFC 5280 §6.1 tree first then replace?

### 2. Full distributionPoint / IDP structured models — L, breaking

`crlDistributionPoints: readonly string[]` → structured `DistributionPoint[]`
across `ParsedCertificate`, `CertificateExtensionsInput`, CRL parsing.
Rewrites `parseCrlDistributionPoints()` (parse.ts), `encodeCrlDistributionPoints()`
(extensions.ts), `parseIssuingDistributionPoint()` (crl.ts). Only item that
is clearly a **breaking type change**.

**Open question:** parallel `crlDistributionPointUris` compat field, or
clean break?

### 3. Distinguish hard failure from "status unknown" — L, potentially breaking

Changes Result union shapes in `verify.ts`, `crl.ts`, `ocsp.ts`. Every
consumer pattern-matching on `result.ok` is affected. Touches
`VerifyChainResult`, `ValidateCandidatePathResult`, `ValidateCrlResult`,
`ValidateOcspResult`.

**Open question:** third variant `{ ok: "partial" }`, or keep binary `ok`
with `severity` field on failures?

### 4. CMS signedData generation — M

~200 lines new in `pkcs7.ts` but must invert the signed-attributes verify
flow (`verifySignedAttrs`). Mirrors existing parsing types for round-trip
consistency. Moderate coupling through `signing.ts`.

### 5. Initial permitted/excluded subtree inputs — M

Widens 6+ input interfaces (`ValidateCandidatePathInput`,
`VerifyCertificateChainInput`, 4 profile inputs). Seeds
`AccumulatedNameConstraints` in `checkNameConstraints()` (verify.ts).
Purely additive optional fields — non-breaking.

## Nice-to-have monsters

- [ ] AIA / CRL / OCSP network client helpers kept separate from pure validation
- [ ] Certificate transparency / SCT parsing
- [ ] Timestamp / TSA structures
- [ ] More complete CMS / ASN.1 utility coverage if the library grows beyond PKIX core
