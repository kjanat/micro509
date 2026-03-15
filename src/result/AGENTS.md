# `src/result/` - Result Domain

Shared typed error/ok algebra used across public and internal modules.

## OVERVIEW

`result` centralizes invariant-safe returns used everywhere else in the
repository.

## STRUCTURE

```tree
result/
`- result.ts    # ADT constructors, indexed errors, typed outcomes
`- index.ts     # domain barrel
```

## WHERE TO LOOK

| Task            | File        | Notes                                   |
| --------------- | ----------- | --------------------------------------- |
| Shared ADT      | `result.ts` | `Result`, `Micro509Error`, constructors |
| Barrel contract | `index.ts`  | stable domain alias for imports         |

## CONVENTIONS

- Use result constructors over exceptions for expected domain failures.
- Keep error namespaces typed and exhaustive at call sites.

## ANTI-PATTERNS

- Do not return raw string errors in new code.
- Do not widen `Result` without callers handling the new branch.
