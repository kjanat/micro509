# `src/revocation/` - Revocation Domain

CRL and OCSP evidence collection, parsing, and proof checks.

## OVERVIEW

`revocation` owns revocation input handling and verification semantics.

## STRUCTURE

```tree
revocation/
|- crl.ts           # CRL parsing + lifecycle
|- ocsp.ts          # OCSP request/response lifecycle
|- revocation.ts    # revocation orchestration
|- index.ts         # domain barrel
```

## WHERE TO LOOK

| Task                   | File            | Notes                                   |
| ---------------------- | --------------- | --------------------------------------- |
| CRL lifecycle          | `crl.ts`        | parse, create, validate, verify         |
| OCSP lifecycle         | `ocsp.ts`       | request/create, parse, validate, verify |
| Evidence orchestration | `revocation.ts` | top-level check and responder selection |

## CONVENTIONS

- Keep protocol-specific parse/encode in `crl.ts` and `ocsp.ts`, selection logic in
  `revocation.ts`.
- Return structured error codes for `indeterminate`, `good`, and `revoked` states.
- Preserve existing harness-backed behavior contracts when touching time-based
  logic.

## ANTI-PATTERNS

- Do not treat revocation transport failures as hard certificate failures.
- Do not move revocation semantics into parser-only modules.
