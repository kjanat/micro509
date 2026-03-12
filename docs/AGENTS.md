# docs/ - Docs Map

Status docs and harness docs live here. This directory defines what the project claims, not just how it works.

## OVERVIEW

`docs/` is small but high-leverage: `PKIX-SCOPE.md` sets support boundaries, and harness docs tie prose claims to concrete tests.

## WHERE TO LOOK

| Task                          | File               | Notes                                                 |
| ----------------------------- | ------------------ | ----------------------------------------------------- |
| Support boundary              | `PKIX-SCOPE.md`    | canonical claim language and partial/full scope lines |
| Roadmap                       | `FUTURE.md`        | backlog and future surfaces                           |
| PKITS harness contract        | `PKITS-HARNESS.md` | shipped PKITS subset and fixed validation time        |
| Differential harness contract | `DIFF-HARNESS.md`  | OpenSSL oracle scope and non-goals                    |
| RFC source text               | `rfc/*.txt`        | vendored references only                              |

## LOCAL CONVENTIONS

- Keep docs aligned with shipped behavior and current tests.
- Harness docs should point at owning test files.
- Prefer exact scope language over marketing language.
- `docs/rfc/` is reference material; project-authored edits belong in the markdown docs, not vendored RFC text.

## ANTI-PATTERNS

- Do not claim full RFC 5280, RFC 6960, or revocation coverage unless tests and implementation truly support it.
- Do not let docs drift from `test/pkits.test.ts` or `test/differential.test.ts`.
- Do not rewrite vendored RFC files for local commentary.
