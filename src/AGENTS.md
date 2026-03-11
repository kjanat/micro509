# src/ — Module Map

20 flat modules, no subdirectories. 13 are public (re-exported via `index.ts`), 7 are internal.

## PUBLIC MODULES

| Module           | Lines | Exports                                     | Domain                                                                |
| ---------------- | ----- | ------------------------------------------- | --------------------------------------------------------------------- |
| `keys.ts`        | 666   | ~45 (12 types, ~33 fns)                     | Key gen, import/export: PKCS#1/8, SEC1, SPKI, JWK, encrypted variants |
| `verify.ts`      | 1337  | 32 (22 types, 10 fns)                       | Path build/validate split, profiles, CN fallback, trust anchors, EKU  |
| `ocsp.ts`        | 798   | 26 (13 types, 13 fns)                       | OCSP request/response create, parse, verify, validate                 |
| `parse.ts`       | 785   | 22 (10 types, 12 fns)                       | Certificate/CSR DER+PEM parsing, extension decoding framework         |
| `crl.ts`         | 758   | 16 (9 types, 7 fns)                         | CRL create, parse, verify, validate, revocation check                 |
| `extensions.ts`  | 537   | 12 types (public) + 13 internal builder fns | Extension types + ASN.1 encoding (builders NOT public)                |
| `pfx.ts`         | 618   | 16 (13 types, 3 fns)                        | PKCS#12/PFX bundle create and parse (Result return types)             |
| `pkcs7.ts`       | 460   | 13 (7 types, 6 fns)                         | PKCS#7 SignedData parse, cert bag create/parse (Result return types)  |
| `certificate.ts` | 147   | 7 (5 types, 2 fns)                          | `createCertificate`, `createSelfSignedCertificate`                    |
| `pkcs12-mac.ts`  | 226   | 4 (2 types, 2 fns)                          | PKCS#12 MAC creation and parsing                                      |
| `name.ts`        | 116   | 4 types                                     | X.500 DistinguishedName types (`NameInput`, `NameObject`, etc.)       |
| `pem.ts`         | 96    | 6 (2 types, 4 fns)                          | PEM encode/decode/split/categorize                                    |
| `csr.ts`         | 73    | 3 (2 types, 1 fn)                           | `createCertificateSigningRequest`                                     |

## INTERNAL MODULES (not in index.ts)

| Module                     | Role                                                                         | Consumed By                                           |
| -------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------- |
| `der.ts` (293)             | DER/TLV encoding + decoding primitives                                       | Every module that creates or parses ASN.1             |
| `asn1.ts` (125)            | Higher-level ASN.1 decode utilities (`childrenOf`, `decodeObjectIdentifier`) | `parse.ts`, `crl.ts`, `ocsp.ts`, `pfx.ts`, `pkcs7.ts` |
| `sig-verify.ts` (231)      | Signature verification: OID → algorithm mapping, raw verify                  | `verify.ts`, `crl.ts`, `ocsp.ts`, `pkcs7.ts`          |
| `pbes2.ts` (185)           | PBES2/PBKDF2 encrypt/decrypt for PKCS#8 keys                                 | `keys.ts` (encrypted key import/export)               |
| `signing.ts` (124)         | `CryptoKey` → WebCrypto algorithm params for signing                         | `certificate.ts`, `crl.ts`, `csr.ts`, `ocsp.ts`       |
| `oids.ts` (63)             | OID constant map (`as const satisfies Record<string, string>`)               | Every module that references OIDs                     |
| `extensions.ts` (builders) | `buildCertificateExtensions`, `encodeExtension`, etc.                        | `certificate.ts`, `csr.ts`, `crl.ts`                  |

## DEPENDENCY FLOW

```
certificate.ts ──┐
csr.ts ──────────┤──→ signing.ts ──→ der.ts ──→ oids.ts
crl.ts ──────────┤──→ extensions.ts (builders)
ocsp.ts ─────────┘──→ asn1.ts

verify.ts ──→ sig-verify.ts ──→ der.ts ──→ oids.ts
parse.ts ──→ asn1.ts ──→ der.ts
keys.ts ──→ pbes2.ts ──→ der.ts
pfx.ts ──→ pkcs12-mac.ts ──→ der.ts
pkcs7.ts ──→ asn1.ts ──→ der.ts
```

## COMPLEXITY HOTSPOTS (>500 lines)

All 7 large files follow the same pattern: type definitions at top, public functions in middle, private helpers at bottom.

- **`verify.ts`** (1337) — most complex control flow; `buildCandidatePath`/`validateCandidatePath` split, 4 profile fns, CN fallback, trust-anchor/constraint checks
- **`ocsp.ts`** (798) — dual create+parse surfaces; SHA-1 for cert ID (standard), SHA-256 for signing
- **`parse.ts`** (785) — generic extension decoder framework via `defineExtensionDecoder`/`defineExtensionDecoderMap`
- **`crl.ts`** (758) — full lifecycle: create → DER/PEM parse → verify signature → validate (issuer+freshness) → check revocation
- **`keys.ts`** (666) — widest API surface; `opensslBytesToKey()` uses MD5 (legacy PEM compat only)
- **`pfx.ts`** (618) — PKCS#12 create+parse; Result return types; password-based encryption via `pbes2.ts`
- **`extensions.ts`** (537) — strict IP address validation (IPv4/IPv6), OID format regex, exhaustive `never` switch

## WHERE NEW CODE GOES

- New certificate/CSR field → `extensions.ts` (type + builder)
- New key format → `keys.ts` (import/export pair)
- New verification check → `verify.ts` (add error code to `VerifyErrorCode` union)
- New ASN.1 structure → `der.ts` (encoding) + `asn1.ts` (decoding)
- New algorithm support → `signing.ts` + `sig-verify.ts` (both)
- New public export → `index.ts` barrel + the source module
