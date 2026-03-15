# `src/internal/shared/` - Shared Helpers

Cross-domain primitives used by parser, identity, verify, and revocation paths.

## OVERVIEW

`internal/shared` holds low-level helpers with intentionally narrow scope that are
reused by multiple internal modules.

## STRUCTURE

```tree
internal/shared/
|- base64.ts    # base64 encode/decode without line folding
`- ip.ts         # IPv4/IPv6 normalization and match helpers
```

## WHERE TO LOOK

| Task            | File        | Notes                                        |
| --------------- | ----------- | -------------------------------------------- |
| Base64 encoding | `base64.ts` | PEM/cert payload transforms                  |
| IP matching     | `ip.ts`     | canonicalization used by SAN and constraints |

## CONVENTIONS

- Keep helpers pure and deterministic.
- Keep input validation local to helper entrypoints.
- Do not add heavyweight algorithms in this directory; keep helpers cross-domain
  but small.

## ANTI-PATTERNS

- Do not implement domain-specific policies in shared helpers.
- Do not silently normalize malformed inputs for callers that should fail
  explicitly.
