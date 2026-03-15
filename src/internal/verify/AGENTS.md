# `src/internal/verify/` - Verification Engines

Core engines for chain semantics used by the public verification entrypoint.

## OVERVIEW

`internal/verify` owns policy evaluation, name constraints, and candidate-chain
search mechanics that are shared across certificate and revocation checks.

## STRUCTURE

```tree
internal/verify/
|- verify-path.ts         # chain search and trust-anchor matching
|- policy-engine.ts       # RFC 9618 policy graph evaluation
`- name-constraints-engine.ts # RFC 5280 name constraints state and checks
```

## WHERE TO LOOK

| Task             | File                         | Notes                                             |
| ---------------- | ---------------------------- | ------------------------------------------------- |
| Path traversal   | `verify-path.ts`             | issuer lookup, ranking, partial-chain diagnostics |
| Policy graph     | `policy-engine.ts`           | policy state transitions and failures             |
| Name constraints | `name-constraints-engine.ts` | constraint subset accumulation and matching       |

## CONVENTIONS

- Keep candidate exploration deterministic and bounded by public time/depth bounds.
- Return structured failures from internal engines instead of generic boolean flags.
- Keep RFC-facing algorithm names near the function that emits the corresponding
  result code.

## ANTI-PATTERNS

- Do not merge parsing and chain policy in the same helper.
- Do not add one-off policy branches outside the exported validation state model.
- Do not bypass engine outputs with ad-hoc checks in public `verify` layers.
