# Future work

Implementation-ready master plan: [`specs/full-standards-compliance.md`].

## Immediate ultra-savage moves

- [ ] CMS `signedData` generation, not only parse/verify
- [ ] OCSP response signer validation against explicit local responder configuration
- [ ] OCSP responder revocation policy handling

## Path validation / PKIX completeness

- [x] Separate candidate path building from path validation more explicitly in the public API
- [x] Structured trust-anchor input model, not only convenience via root certificates
- [x] Unsupported critical extension rejection during candidate path validation
- [x] Self-issued handling for name-constraint / path-processing edge cases
- [x] Name constraints support
- [x] Initial permitted/excluded subtree validator inputs
- [x] Certificate policy processing
- [x] RFC 9618-style policy validation algorithm
- [x] Malformed DER / fuzz corpus
- [x] Differential tests against mature implementations
- [x] Focused PKITS coverage for shipped claims

## Revocation / status

- [ ] OCSP response signer validation against explicit local responder configuration
- [ ] OCSP responder revocation policy handling
- [ ] OCSP request/response builders with richer extension support
- [x] OCSP response freshness clock-skew configuration
- [x] CRL freshness / nextUpdate policy helpers
- [ ] CRL distribution point discovery / fetch hooks
- [x] Delta CRL application logic
- [ ] Richer CRL entry extensions

## CMS / PKCS / container interop

- [x] RSA-PSS certificate / CSR sign and verify support
- [x] ECDSA `P-521` key, cert, and CSR support
- [x] PBES2 AES-128/192/256-CBC plus PBKDF2 HMAC-SHA1/HMAC-SHA256 interop
- [x] Traditional PEM AES-128/192/256-CBC interop for RSA and EC private keys
- [x] CMS/PKCS#7 signature verification over signed attributes where applicable
- [ ] CMS/PKCS#7 detached content support
- [ ] CMS signer certificate selection helpers
- [ ] PKCS#12/PFX encrypted certificate safe bags
- [ ] Broader PKCS#12 algorithms and compatibility modes
- [ ] Traditional PEM encryption algorithms beyond AES-128/192/256-CBC

## API / DX

- [ ] Zero-config decoder-map inference helpers for even tighter typing
- [ ] Higher-level cert/CSR/CRL/OCSP fixtures for tests and demos
- [x] More explicit validation profiles: raw path-valid, TLS server, TLS client, OCSP responder, CA, etc.
- [x] Better failure typing for revocation / container / CMS subsystems
- [x] Browser examples and runtime matrix docs

## Refactor priorities (pre-1.0)

Items ranked by how much existing code must change — not just new code added.

### 1. Distinguish hard failure from "status unknown" — L, potentially breaking

Changes Result union shapes in `verify.ts`, `crl.ts`, `ocsp.ts`. Every
consumer pattern-matching on `result.ok` is affected. Touches
`VerifyChainResult`, `ValidateCandidatePathResult`, `ValidateCrlResult`,
`ValidateOcspResult`.

**Open question:** third variant `{ ok: "partial" }`, or keep binary `ok`
with `severity` field on failures?

### 2. CMS signedData generation — M

~200 lines new in `pkcs7.ts` but must invert the signed-attributes verify
flow (`verifySignedAttrs`). Mirrors existing parsing types for round-trip
consistency. Moderate coupling through `signing.ts`.

### 3. Explicit local OCSP responder policy hooks — M

Most OCSP auth checks ship now, but the remaining gap is explicit local
responder-policy acceptance and the follow-on story for responder revocation.
This likely lands in `ocsp.ts` and `revocation.ts` without widening the pure
validation boundary into network behavior.

## Nice-to-have monsters

- [ ] AIA / CRL / OCSP network client helpers kept separate from pure validation
- [ ] Certificate transparency / SCT parsing
- [ ] Timestamp / TSA structures
- [ ] More complete CMS / ASN.1 utility coverage if the library grows beyond PKIX core

[`specs/full-standards-compliance.md`]: ../specs/full-standards-compliance.md
