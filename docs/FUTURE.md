# Future work

## Immediate ultra-savage moves

- [ ] CMS `signedData` generation, not only parse/verify
- [ ] OCSP responder cert selection by responderID, not only best-effort included-cert / chain resolution
- [ ] Full `distributionPoint` / `issuingDistributionPoint` structured object models across certificate parsing, not only CRL-side URI-focused shortcuts

## Path validation / PKIX completeness

- [ ] Separate candidate path building from path validation more explicitly in the public API
- [x] Structured trust-anchor input model, not only convenience via root certificates
- [x] Unsupported critical extension rejection during candidate path validation
- [x] Self-issued handling for name-constraint / path-processing edge cases
- [ ] Name constraints support
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

- [ ] CMS/PKCS#7 signature verification over signed attributes where applicable
- [ ] CMS/PKCS#7 detached content support
- [ ] CMS signer certificate selection helpers
- [ ] PKCS#12/PFX encrypted certificate safe bags
- [ ] Broader PKCS#12 algorithms and compatibility modes
- [ ] Traditional PEM encryption algorithm variants beyond current support

## API / DX

- [ ] Zero-config decoder-map inference helpers for even tighter typing
- [ ] Higher-level cert/CSR/CRL/OCSP fixtures for tests and demos
- [ ] More explicit validation profiles: raw path-valid, TLS server, TLS client, OCSP responder, CA, etc.
- [ ] Better failure typing for revocation / container / CMS subsystems
- [ ] Browser examples and runtime matrix docs

## Nice-to-have monsters

- [ ] AIA / CRL / OCSP network client helpers kept separate from pure validation
- [ ] Certificate transparency / SCT parsing
- [ ] Timestamp / TSA structures
- [ ] More complete CMS / ASN.1 utility coverage if the library grows beyond PKIX core
