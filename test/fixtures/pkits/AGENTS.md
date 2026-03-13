# test/fixtures/pkits/ - PKITS Fixture Map

Vendored PKITS corpus for the focused path-validation harness.

## OVERVIEW

This directory is not a general fixture area. It exists to preserve the imported PKITS certificate corpus and the naming contract used by `test/pkits.test.ts`.

## STRUCTURE

```tree
pkits/
`- certs/   # vendored `.crt` inputs loaded by filename stem
```

## WHERE TO LOOK

| Need                | Location                | Notes                                                 |
| ------------------- | ----------------------- | ----------------------------------------------------- |
| Harness owner       | `test/pkits.test.ts`    | table-driven subset, fixed validation time            |
| Scope and non-goals | `docs/PKITS-HARNESS.md` | shipped subset only                                   |
| Fixture corpus      | `certs/*.crt`           | upstream-style names are part of the harness contract |

## LOCAL CONVENTIONS

- Keep upstream-style certificate filenames stable; the harness loads by exact stem.
- Treat the corpus as vendored input data, not handcrafted test fixtures.
- Add or remove files only with a matching harness/docs change.
- Preserve the fixed PKITS validation-time assumption owned by `test/pkits.test.ts`.

## ANTI-PATTERNS

- Do not rename fixtures to match local style.
- Do not rewrite certificate bytes or convert formats casually.
- Do not add unrelated fixtures here; create another corpus directory if provenance/rules differ.
- Do not expand support claims just because a certificate file exists here.
