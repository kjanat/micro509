# Architecture Notes

This document captures the cross-cutting patterns already visible in the
`micro509` source layout and is kept aligned with shipped behavior.

## Module Topology

`src/index.ts` is the root public barrel. Domain-owned public workflows and
types live under `src/x509/`, `src/verify/`, `src/revocation/`, `src/keys/`,
`src/pem/`, `src/pkcs/`, and `src/result/`, while implementation-only helpers
live under `src/internal/**`.

- `src/index.ts` contains the curated workflow-first root surface.
- `src/*/` contains domain-owned public workflows, types, and re-export barrels.
- `src/internal/**` contains low-level and cross-domain primitives.
- `src/result/result.ts` is the canonical typed failure model used across domains
  via `src/result/index.ts` and explicit imports.

## Shared Utility Spine

### ASN.1 + OID layer

- `src/internal/asn1/asn1.ts` and `src/internal/asn1/der.ts` provide value parsing
  and encode/decode primitives for all DER-using features.
- `src/internal/asn1/oids.ts` is the central OID catalog used by every module
  that needs algorithm and extension dispatch.
- This pair is imported by parsing, certificate/CSR builders, revocation, PKIX
  extensions, PKCS flows, and cryptographic verify/sign helpers.

### Shared transforms

- `src/internal/shared/base64.ts` is the singular helper for PEM-safe base64
  conversions.
- `src/internal/shared/ip.ts` centralizes IP literal parsing and matching used in
  name matching, name constraints, CRL parsing, and extension decoding.
- Both are intentionally imported from many domains instead of reimplemented.

### Cryptography internals

- `src/internal/crypto/signing.ts` and `src/internal/crypto/sig-verify.ts` form
  the pair for sign/verify algorithm dispatch.
- `src/internal/crypto/ecdsa.ts`, `src/internal/crypto/rsa-pss.ts`, and
  `src/internal/crypto/pbes2.ts` carry algorithm/format-specific parsing and
  validation rules.
- `src/internal/crypto/hash.ts` contains shared digest primitives.
- `src/internal/crypto/webcrypto.ts` encapsulates WebCrypto availability and
  backend plumbing.

### X.509 extension/model utilities

- `src/internal/x509/extension-registry.ts` owns extension registration and type
  selection.
- `src/internal/x509/extension-bits.ts` centralizes bit-string interpretation for
  common extension fields.
- `src/internal/x509/name-fields.ts` centralizes DN field metadata.
- `src/x509/extensions.ts` and parse/verify layers consume these registry and bit
  helpers for consistency.

### Verification engines

- `src/internal/verify/verify-path.ts` and
  `src/internal/verify/policy-engine.ts` contain the major policy and
  constraint processing.
- `src/internal/verify/name-constraints-engine.ts` isolates name-constraints state
  and matching.
- The top-level `src/verify/verify.ts` composes these engines with result
  handling and high-level orchestration.

### Cross-domain result discipline

- `src/result/result.ts` defines `Result`, `Micro509Error`, and constructor
  helpers.
- Domains keep returning plain result objects instead of throwing on recoverable
  parse/validation outcomes.
- Most consumers import these types directly from `#micro509/result/result.ts` even
  when they are not exported from their top-level domain barrel.

## Concrete Import Conventions

- Public files prefer `#micro509/internal/*` imports for non-public helpers.
- Public leaf modules should not import from sibling or root domain barrels.
- Public barrels are thin re-export aggregators and should keep contract
  stability centralized in sibling files.
- Algorithm extensions usually need both `internal/crypto/signing.ts` and
  `internal/crypto/sig-verify.ts`, plus OID mapping updates.

## Suggested Follow-up

1. Keep this doc in lockstep when moving any utility into or out of
   `src/internal`.
2. Update docs if/when verification semantics are split further (for example,
   if `verify.ts` decomposes into additional staged files).
3. Add a small dependency-map test comment or CI check if import-direction drift
   reappears.
