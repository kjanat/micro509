# `src/pem/` - PEM Domain

Boundary parsing and normalization for PEM blocks.

## OVERVIEW

`pem` owns block category detection and strict PEM encode/decode boundaries.

## STRUCTURE

```tree
pem/
|- pem.ts    # block split/classify + encode/decode helpers
`- index.ts  # domain barrel
```

## WHERE TO LOOK

| Task                 | File     | Notes                               |
| -------------------- | -------- | ----------------------------------- |
| Parse/encode         | `pem.ts` | core block parsing + reconstruction |
| Block classification | `pem.ts` | grouped PEM block typing            |

## CONVENTIONS

- Keep PEM parsing/formatting in `pem.ts` only.
- Return deterministic block categorization before caller-level branching.

## ANTI-PATTERNS

- Do not duplicate PEM splitting logic in other modules.
- Do not normalize malformed PEM payloads silently.
