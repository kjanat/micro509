# WebCrypto PKI Algorithm Expansion - Implementation Spec

**Status:** Largely implemented; kept for regression scope and historical context
**Effort:** L
**Date:** 2026-03-13

**Role:** document the exact algorithm-expansion intent, negative cases, and
fixture matrix behind the shipped `RSA-PSS`, `P-521`, and encrypted-key interop
surface.

**Use:** treat [`docs/PKIX-SCOPE.md`](../docs/PKIX-SCOPE.md) as the canonical
current claim language. This spec remains useful mainly for constraints,
negative-fixture planning, and historical design rationale.

## Problem Statement

**Who:** maintainers and adopters who need `micro509` to interoperate with more real-world PKI artifacts without giving up browser/edge portability or strict validation behavior.

**What:** this spec covered the expansion from the original narrow signing
matrix to the now-shipped `RSA-PSS`, `ECDSA P-521`, and wider encrypted-key
interop surface.

**Why it matters:** this is one of the cheapest adoption wins available. Supporting the missing WebCrypto-aligned PKI algorithms increases real-world interop while preserving the project's core posture: ESM-only, WebCrypto-first, strict typed failures, and no silent validation weakening.

**Original evidence:**

- `src/sig-verify.ts` rejects anything outside RSA PKCS#1 v1.5, ECDSA `P-256`/`P-384`, and `Ed25519`.
- `src/signing.ts` cannot emit `RSA-PSS` `AlgorithmIdentifier` values and rejects `P-521` signer keys.
- `src/parse.ts` preserves only `AlgorithmIdentifier` OIDs plus optional OID-valued params, which blocks structured algorithms like `RSASSA-PSS`.
- MDN Web Crypto docs show `RSA-PSS` as a supported signing/import algorithm and `P-521` as a supported ECDSA curve in `EcKeyGenParams` and `EcKeyImportParams`.

## Discovery Summary

- The highest-leverage architectural blocker was `AlgorithmIdentifier`
  parameter loss in `src/parse.ts`.
- `P-521` was a low-churn expansion because the current ECDSA implementation
  already had the right structure for one more named curve and one more
  signature OID.
- `RSA-PSS` was not free, but it fit the repo well because WebCrypto supports
  it directly and the main missing work was parameter modeling plus validation.
- "Available in WebCrypto" was not sufficient scope by itself. `X25519`,
  `ECDH`, `RSA-OAEP`, `AES`, and `HMAC` still do not slot cleanly into the
  repo's current cert/CSR signing and verification abstractions, so they remain
  out of scope for this slice.
- `DSA` and `Ed448` remain unreasonable scope adds for this repo's browser-safe
  core.

## Recommendation

Expand the repo's PKI algorithm surface to match the low-cost, signature-relevant WebCrypto subset:

1. Add structured `AlgorithmIdentifier` parameter preservation to parse results.
2. Add `RSA-PSS` certificate and CSR verification.
3. Add `RSA-PSS` certificate and CSR creation with an explicit, typed signing-profile input.
4. Add `ECDSA P-521` end-to-end across key generation, import, sign, verify, cert creation, and CSR creation.
5. Widen encrypted private-key interop where the needed WebCrypto primitives already exist and the current key APIs can absorb them cheaply.
6. Do not add a broad compat mode. Accept more valid encodings and algorithms by default while keeping validation semantics strict by default.

## Scope And Deliverables

| Deliverable                                                    | Effort | Depends On         |
| -------------------------------------------------------------- | ------ | ------------------ |
| D0. Lock claim language for new algorithm support              | S      | -                  |
| D1. Preserve raw `AlgorithmIdentifier` params in parse results | M      | -                  |
| D2. Add `RSA-PSS` verify support for certs and CSRs            | M      | D1                 |
| D3. Add `RSA-PSS` create/sign support for certs and CSRs       | M      | D1                 |
| D4. Add `ECDSA P-521` support end-to-end                       | M      | -                  |
| D5. Widen encrypted private-key import/export compatibility    | M      | -                  |
| D6. Add fixtures, docs, and regression coverage                | M      | D1, D2, D3, D4, D5 |

## Non-Goals

- No `DSA` support.
- No `Ed448` support.
- No `X25519`, `ECDH`, `RSA-OAEP`, `AES`, or `HMAC` public-key feature expansion in this pass.
- No generalized "support every WebCrypto algorithm" policy.
- No relaxed name-constraint, critical-extension, or trust-anchor behavior.
- No global `legacyCompatibility` or `compatMode` switch.
- No Node-only crypto branches or OpenSSL-only fallback behavior.

## Locked Architectural Decisions

| Chose                                                            | Over                                              | Because                                                       |
| ---------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| Add only PKI-signature-relevant WebCrypto algorithms             | Add every WebCrypto algorithm with docs parity    | The repo is a PKI library, not a generic crypto façade        |
| Raw params DER on parse outputs plus targeted structured parsers | Huge public `AlgorithmIdentifier` ADT now         | Minimal churn, enough power for `RSA-PSS`, future-safe enough |
| Explicit signing-profile input for `RSA-PSS` builders            | Magical inference from `CryptoKey.algorithm` only | `saltLength` must be controlled and encoded deterministically |
| Keep validation strict, no compat flag                           | One global legacy toggle                          | Avoid hidden trust widening and policy drift                  |
| Include `P-521` now                                              | Defer until after `RSA-PSS`                       | `P-521` is genuinely low-cost and fits current architecture   |

## Data Model

### Parse Outputs

```ts
export interface ParsedCertificate {
  readonly signatureAlgorithmOid: string;
  readonly signatureAlgorithmParametersDer?: Uint8Array;
  readonly publicKeyAlgorithmOid: string;
  readonly publicKeyParametersOid?: string;
  readonly publicKeyAlgorithmParametersDer?: Uint8Array;
}

export interface ParsedCertificateSigningRequest {
  readonly signatureAlgorithmOid: string;
  readonly signatureAlgorithmParametersDer?: Uint8Array;
  readonly publicKeyAlgorithmOid: string;
  readonly publicKeyParametersOid?: string;
  readonly publicKeyAlgorithmParametersDer?: Uint8Array;
}
```

Rules:

- Existing OID fields stay unchanged for backward compatibility.
- Raw params DER is exposed whenever the ASN.1 params element exists, not only when the repo understands it.
- Structured `RSA-PSS` parsing is implemented as a focused helper on top of raw DER.

### Key Inputs

```ts
export type RsaSignatureScheme = 'pkcs1-v1_5' | 'pss';

export interface RsaKeyAlgorithmInput {
  readonly kind: 'rsa';
  readonly scheme?: RsaSignatureScheme;
  readonly modulusLength?: 2048 | 3072 | 4096;
  readonly hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface ImportRsaPublicKeyInput {
  readonly kind: 'rsa';
  readonly scheme?: RsaSignatureScheme;
  readonly hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface ImportEcPublicKeyInput {
  readonly kind: 'ecdsa';
  readonly namedCurve: 'P-256' | 'P-384' | 'P-521';
}
```

Rules:

- `scheme` defaults to `'pkcs1-v1_5'` for backward compatibility.
- `scheme: 'pss'` maps to WebCrypto `RSA-PSS` import/generation.
- `P-521` is added as a first-class curve everywhere current ECDSA curve unions appear.

### Signing Profile Inputs

```ts
export type SignatureProfileInput =
  | { readonly kind?: 'auto' }
  | {
      readonly kind: 'rsa-pss';
      readonly saltLength?: number;
    };

export interface CreateCertificateInput {
  readonly issuer: NameInput;
  readonly subject: NameInput;
  readonly publicKey: CryptoKey;
  readonly signerPrivateKey: CryptoKey;
  readonly issuerPublicKey?: CryptoKey;
  readonly validity?: ValidityInput;
  readonly serialNumber?: Uint8Array;
  readonly extensions?: CertificateExtensionsInput;
  readonly signature?: SignatureProfileInput;
}

export interface CreateCsrInput {
  readonly subject: NameInput;
  readonly publicKey: CryptoKey;
  readonly signerPrivateKey: CryptoKey;
  readonly extensions?: CertificateExtensionsInput;
  readonly signature?: SignatureProfileInput;
}
```

Rules:

- Omitted `signature` means current behavior for existing algorithms.
- For `RSA-PSS` keys, omitted `saltLength` defaults to the digest size in bytes.
- `RSA-PSS` builder flow always encodes explicit parameters rather than relying on ASN.1 defaults.

### Internal `RSA-PSS` Parameter Shape

```ts
interface ParsedRsassaPssParameters {
  readonly hash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  readonly mgfHash: 'SHA-256' | 'SHA-384' | 'SHA-512';
  readonly saltLength: number;
  readonly trailerField: 1;
}
```

Rules:

- MVP support is limited to `MGF1`.
- `mgfHash` must equal `hash`.
- `trailerField` must be absent or `1`.
- Unsupported-but-well-formed params fail as typed validation failures, not malformed DER parse failures.

## API / Interface Contract

### Parse Boundary

- `src/parse.ts`
  - preserve raw params DER for signature and SPKI `AlgorithmIdentifier` values.
  - add focused `RSA-PSS` parameter parsing helper used by verify and tests.
  - keep throwing on malformed ASN.1.

### Signature Verify

- `src/sig-verify.ts`
  - add `RSA-PSS` support for supported parameter profiles.
  - add `P-521` support with `ecdsaWithSHA512` and `secp521r1` OIDs.
  - extend RSA key import config to choose `RSASSA-PKCS1-v1_5` vs `RSA-PSS` by intended verify scheme.

### Certificate / CSR Builders

- `src/signing.ts`
  - add `RSA-PSS` signing profile resolution.
  - add explicit `AlgorithmIdentifier` encoding for `RSASSA-PSS`.
  - add `P-521` mapping to `ecdsaWithSHA512` and correct raw signature width.
- `src/certificate.ts` and `src/csr.ts`
  - thread optional `signature` input through to signing helpers.

### Key APIs

- `src/keys.ts`
  - add `scheme?: 'pkcs1-v1_5' | 'pss'` for RSA generation/import.
  - add `P-521` to ECDSA curve unions.
  - keep export helpers stable.

### Verify Error Surface

- `src/verify.ts`
  - add `unsupported_signature_algorithm_parameters` to `VerifyErrorCode`.
  - use it when cert/CSR signature params are well-formed but outside the shipped `RSA-PSS` profile.

### Encrypted Key Interop

- `src/pbes2.ts`
  - support PBKDF2 PRF `HMAC-SHA1` and `HMAC-SHA256`.
  - support `AES-128-CBC`, `AES-192-CBC`, and `AES-256-CBC`.
- `src/keys.ts`
  - support traditional PEM `AES-128-CBC`, `AES-192-CBC`, and `AES-256-CBC` for RSA/EC private keys.

## Deliverables (Ordered)

### D0. Lock Claim Language For New Algorithm Support

**Goal:** docs say exactly what ships and do not imply full WebCrypto parity.

**Files likely touched:** `README.md`, `docs/PKIX-SCOPE.md`

**Acceptance criteria:**

- [ ] docs describe the new surface as `RSA-PSS`, `ECDSA P-521`, and key-container interop expansion only.
- [ ] docs do not imply `DSA`, `Ed448`, or non-PKI WebCrypto algorithm support.

### D1. Preserve Raw `AlgorithmIdentifier` Params In Parse Results

**Goal:** unblock structured signature algorithms without forcing a public parse-model rewrite.

**Files likely touched:** `src/parse.ts`, `test/parse.test.ts`, `test/internals.test.ts`

**Acceptance criteria:**

- [ ] parsed certs and CSRs expose raw signature/SPKI params DER when present.
- [ ] existing fields and current tests remain compatible.

### D2. Add `RSA-PSS` Verify Support For Certs And CSRs

**Goal:** accept valid `RSA-PSS`-signed certs and CSRs.

**Files likely touched:** `src/oids.ts`, `src/sig-verify.ts`, `src/verify.ts`, `test/verify.test.ts`, `test/internals.test.ts`

**Acceptance criteria:**

- [ ] `verifyCertificateChain()` accepts `RSA-PSS`-signed chains for supported params.
- [ ] `verifyCertificateSigningRequest()` accepts `RSA-PSS`-signed CSRs for supported params.
- [ ] unsupported `RSA-PSS` params fail with `unsupported_signature_algorithm_parameters`.

### D3. Add `RSA-PSS` Create/Sign Support For Certs And CSRs

**Goal:** let builders emit standards-complete `RSA-PSS` signatures with deterministic params.

**Files likely touched:** `src/signing.ts`, `src/certificate.ts`, `src/csr.ts`, `src/oids.ts`, `test/certificate.test.ts`, `test/csr.test.ts`

**Acceptance criteria:**

- [ ] cert and CSR builders can sign with `RSA-PSS` keys.
- [ ] emitted `AlgorithmIdentifier` includes explicit `RSA-PSS` parameters.
- [ ] omitted `saltLength` defaults to digest size.
- [ ] generated artifacts verify with `micro509` and OpenSSL oracle coverage where practical.

### D4. Add `ECDSA P-521` Support End-To-End

**Goal:** make `P-521` a first-class ECDSA option anywhere the current repo supports `P-256` and `P-384`.

**Files likely touched:** `src/oids.ts`, `src/keys.ts`, `src/signing.ts`, `src/sig-verify.ts`, `test/keys.test.ts`, `test/certificate.test.ts`, `test/verify.test.ts`

**Acceptance criteria:**

- [ ] key generation supports `P-521`.
- [ ] SPKI/PKCS#8/SEC1 import paths support `P-521`.
- [ ] cert and CSR builders can sign with `P-521` keys.
- [ ] verification accepts `ecdsaWithSHA512` with `secp521r1` SPKI.

### D5. Widen Encrypted Private-Key Import/Export Compatibility

**Goal:** improve low-cost encrypted-key interop using already-available WebCrypto primitives.

**Files likely touched:** `src/pbes2.ts`, `src/keys.ts`, `test/keys.test.ts`

**Acceptance criteria:**

- [ ] PBES2 supports `AES-128-CBC` / `AES-192-CBC` / `AES-256-CBC`.
- [ ] PBES2 supports PBKDF2 PRF `HMAC-SHA1` and `HMAC-SHA256`.
- [ ] traditional PEM supports `AES-128-CBC` / `AES-192-CBC` / `AES-256-CBC`.
- [ ] unsupported schemes like `3DES` still reject explicitly.

### D6. Add Fixtures, Docs, And Regression Coverage

**Goal:** keep scope claims honest and prevent silent interop regressions.

**Files likely touched:** `README.md`, `docs/PKIX-SCOPE.md`, `test/verify.test.ts`, `test/keys.test.ts`, `test/certificate.test.ts`, `test/csr.test.ts`, `test/differential.test.ts`

**Acceptance criteria:**

- [ ] fixtures cover positive and negative `RSA-PSS` cases.
- [ ] fixtures cover `P-521` keygen/import/sign/verify.
- [ ] fixtures cover widened encrypted-key compatibility.
- [ ] docs and tests agree on support boundaries.

## Acceptance Criteria

- [ ] Existing RSA PKCS#1 v1.5, `P-256`, `P-384`, and `Ed25519` behavior remains unchanged.
- [ ] `RSA-PSS` parse/verify/sign support ships for the constrained parameter profile only.
- [ ] `ECDSA P-521` ships anywhere current ECDSA key/sign/verify support exists.
- [ ] Builder APIs stay backward compatible for current callers that omit `signature` inputs.
- [ ] No unsupported critical extension or name-constraint behavior becomes more permissive.
- [ ] The repo still does not claim full WebCrypto parity or full legacy-PKI compatibility.

## Test Strategy

| Layer        | What                                  | How                                                                                 |
| ------------ | ------------------------------------- | ----------------------------------------------------------------------------------- |
| Unit         | raw alg-param preservation            | parser fixture assertions in `test/parse.test.ts`                                   |
| Unit         | `RSA-PSS` param decode and validation | focused helper coverage in `test/internals.test.ts`                                 |
| Unit         | `P-521` mapping                       | key/sign/verify helper coverage in `test/keys.test.ts` and `test/internals.test.ts` |
| Integration  | `RSA-PSS` cert chain verify           | positive/negative fixtures in `test/verify.test.ts`                                 |
| Integration  | `RSA-PSS` CSR verify and create       | `test/csr.test.ts` and `test/verify.test.ts`                                        |
| Integration  | `P-521` cert/CSR create and verify    | `test/certificate.test.ts`, `test/csr.test.ts`, `test/verify.test.ts`               |
| Integration  | encrypted-key interop                 | fixture coverage in `test/keys.test.ts`                                             |
| Differential | oracle sanity                         | OpenSSL-backed checks where OpenSSL behavior is stable and comparable               |

Minimum fixture matrix:

- `RSA-PSS` positive: SHA-256, SHA-384, SHA-512
- `RSA-PSS` negative: unsupported MGF hash, unsupported trailer field, malformed params, mismatched SPKI import scheme
- `P-521` positive: keygen, PKCS#8 import, SEC1 import, cert sign/verify, CSR sign/verify
- Encrypted-key positive: PBES2 AES-128/192/256 with PRF SHA-1 and SHA-256; traditional PEM AES-128/192/256
- Encrypted-key negative: unsupported encryption schemes still reject with explicit errors

## Risks And Mitigations

| Risk                                                              | Likelihood | Impact | Mitigation                                                                              |
| ----------------------------------------------------------------- | ---------- | ------ | --------------------------------------------------------------------------------------- |
| `RSA-PSS` parameter handling drifts from emitted builder behavior | M          | H      | share one internal parameter model for encode + verify                                  |
| WebCrypto runtime variance on newer algorithms                    | M          | H      | keep supported profile narrow and add Bun/Node/browser-oriented coverage where possible |
| Scope creep into every WebCrypto algorithm                        | H          | M      | lock non-goals and explain why non-signature algorithms are separate work               |
| Backward-compat break in RSA key imports                          | M          | H      | default RSA `scheme` to `'pkcs1-v1_5'` and preserve current call patterns               |
| Docs overclaim more than shipped                                  | M          | H      | land docs in same slice and tie claims to fixtures                                      |

## Trade-Offs Made

| Chose                                 | Over                              | Because                                                     |
| ------------------------------------- | --------------------------------- | ----------------------------------------------------------- |
| `RSA-PSS` plus `P-521`                | only `RSA-PSS`                    | `P-521` is low-cost enough to include now                   |
| explicit `signature` builder input    | hidden `RSA-PSS` defaults only    | callers need deterministic and inspectable signing behavior |
| raw params DER + focused parsers      | full public ASN.1 algebraic model | enough power now, less public churn                         |
| keep non-signature WebCrypto algs out | chase full MDN surface            | current repo abstractions are sign/verify-centric           |

## Success Metrics

- `RSA-PSS` cert and CSR fixtures pass for all three shipped hashes.
- `P-521` ships without widening the API beyond one curve union expansion and RSA scheme selection.
- 0 regressions in current verify, certificate, CSR, and key suites.
- docs and tests both describe the exact same algorithm matrix.

## Open Questions

- None. This spec intentionally bounds "free WebCrypto support" to PKI-signature-relevant additions plus low-cost key-container interop.
