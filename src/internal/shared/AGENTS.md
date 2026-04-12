# `src/internal/shared/` - Cross-Domain Primitives

Pure helpers reused across multiple domains when logic is too small for a dedicated public owner.

## OVERVIEW

`internal/shared` is the narrow common layer for base64, DN normalization helpers, and IP address parsing used by keys, X.509, verify, and revocation code.

## STRUCTURE

```tree
shared/
├── base64.ts  # binary/text codec helpers
├── dn.ts      # DN string/token normalization helpers
├── ip.ts      # IPv4/IPv6 parsing and canonicalization helpers
└── README.md  # minimal intent note
```

## WHERE TO LOOK

| Need             | File        | Notes                                                   |
| ---------------- | ----------- | ------------------------------------------------------- |
| Base64 encoding  | `base64.ts` | shared codec used by PEM, keys, and containers          |
| DN helper logic  | `dn.ts`     | shared name-string processing, not full X.500 ownership |
| IP normalization | `ip.ts`     | verifier and SAN/IP matching support                    |

## CONVENTIONS

- Keep this directory pure, deterministic, and dependency-light.
- Only place logic here if at least two domains genuinely share it and no stronger owner exists.
- Preserve wire-level behavior; tiny helper changes here can fan out into parse, verify, and test fixtures.
- If a helper starts encoding protocol policy, move it to the owning domain or engine.

## ANTI-PATTERNS

- Do not turn `shared/` into a catch-all misc bucket.
- Do not move X.509 policy, revocation semantics, or crypto profile rules here.
- Do not duplicate helper logic already owned by `internal/asn1`, `internal/crypto`, or `internal/x509`.
