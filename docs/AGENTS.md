# `docs/` - Docs Map

Status docs and harness docs live here.\
This directory defines what the project claims, not just how it works.

## OVERVIEW

[`docs/`][docs] is small but high-leverage:
[`PKIX-SCOPE.md`] sets support boundaries and the roadmap, and harness docs tie prose claims to
concrete tests, while
[`ARCHITECTURE.md`] captures cross-cutting module conventions and utility
ownership.

## WHERE TO LOOK

| Task                          | File                 | Notes                                                 |
| ----------------------------- | -------------------- | ----------------------------------------------------- |
| Support boundary              | [`PKIX-SCOPE.md`]    | canonical claim language and partial/full scope lines |
| Architecture conventions      | [`ARCHITECTURE.md`]  | cross-cutting utility ownership and import patterns   |
| Roadmap + support boundary    | [`PKIX-SCOPE.md`]    | canonical claims, partial/full scope, backlog         |
| PKITS harness contract        | [`PKITS-HARNESS.md`] | shipped PKITS subset and fixed validation time        |
| Differential harness contract | [`DIFF-HARNESS.md`]  | OpenSSL oracle scope and non-goals                    |
| RFC source text               | [`rfc/*.txt`][rfc]   | vendored references only                              |

## LOCAL CONVENTIONS

- Keep docs aligned with shipped behavior and current tests.
- Harness docs should point at owning test files.
- Prefer exact scope language over marketing language.
- [`docs/rfc/`][rfc] is reference material; project-authored edits belong in the
  Markdown docs, not vendored RFC text.

## ANTI-PATTERNS

- Do not claim full RFC 5280, RFC 6960, or revocation coverage\
  _unless_ tests and implementation truly support it.
- Do not let docs drift from [`test/pkits.test.ts`][pkits.test.ts] or
  [`test/differential.test.ts`][differential.test.ts].
- Do not rewrite vendored [RFC files][rfc] for local commentary.

[docs]: ../docs/
[`PKIX-SCOPE.md`]: ./PKIX-SCOPE.md
[`ARCHITECTURE.md`]: ./ARCHITECTURE.md
[`PKITS-HARNESS.md`]: ./PKITS-HARNESS.md
[`DIFF-HARNESS.md`]: ./DIFF-HARNESS.md
[rfc]: ../docs/rfc/
[pkits.test.ts]: ../test/pkits.test.ts
[differential.test.ts]: ../test/differential.test.ts
