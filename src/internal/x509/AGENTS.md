# `src/internal/x509/` - X.509 Metadata Internals

Extension registry and name metadata shared by parser and builder boundaries.

## OVERVIEW

`internal/x509` centralizes extension registry metadata and DN field rules so
`src/x509` can keep surface logic stable.

## STRUCTURE

```tree
internal/x509/
|- extension-registry.ts  # extension decode/encode dispatch and accumulators
|- extension-bits.ts      # bit-string encoding/decoding helpers
`- name-fields.ts         # DN OID and string-encoder metadata
```

## WHERE TO LOOK

| Task               | File                    | Notes                                      |
| ------------------ | ----------------------- | ------------------------------------------ |
| Extension dispatch | `extension-registry.ts` | central table and parse/apply policy       |
| Bit flags          | `extension-bits.ts`     | canonical bit order for key usages/reasons |
| DN metadata        | `name-fields.ts`        | OID + encoder map for distinguished names  |

## CONVENTIONS

- Keep registry rows exhaustive and explicit for supported extensions.
- Keep bit-order arrays private and deterministic to prevent wire drift.
- Keep name metadata close to encoding/decoding call-sites to avoid mismatched DN
  behavior.

## ANTI-PATTERNS

- Do not add extension-specific fallback decoding outside the registry table.
- Do not diverge canonical bit ordering from existing parsed/written profiles.
- Do not add public compatibility branches in these internals without a public API
  surface change.
