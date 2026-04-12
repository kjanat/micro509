# test/ - Test Map

Feature-oriented Bun suites plus shared helpers, oracle adapters, and vendored PKITS fixtures.

## OVERVIEW

Tests mirror source domains with one main `*.test.ts` per feature area.\
Coverage mixes public API checks, intentional internal probes, fixed fixtures, and differential
checks against OpenSSL.

## STRUCTURE

```tree
test/
├── *.test.ts              # feature suites
├── helpers.ts             # shared DER/cert builders and fixture utilities
├── oracles/openssl.ts     # normalized OpenSSL wrapper
└── fixtures/pkits/certs/  # vendored PKITS certificates
```

## WHERE TO LOOK

| Task                      | File                                            | Notes                                     |
| ------------------------- | ----------------------------------------------- | ----------------------------------------- |
| Shared helpers            | `helpers.ts`                                    | common DER helpers and synthetic builders |
| Chain validation coverage | `verify.test.ts`                                | largest spec-like suite                   |
| CRL coverage              | `crl.test.ts`, `revocation.test.ts`             | direct CRL semantics and orchestration    |
| OCSP coverage             | `ocsp.test.ts`, `ocsp-fixtures.test.ts`         | parser/validator plus focused fixtures    |
| Identity coverage         | `identity.test.ts`, `identity-fixtures.test.ts` | RFC 6125 semantics and fixture corpus     |
| Parse hardening           | `parse.test.ts`, `malformed-der.test.ts`        | malformed input and parser boundaries     |
| Differential interop      | `differential.test.ts`                          | compares normalized results to OpenSSL    |
| PKITS subset              | `pkits.test.ts`                                 | fixed-time conformance subset             |
| Internal-only checks      | `internals.test.ts`                             | safe place for `#micro509/*.ts` internals |

## LOCAL CONVENTIONS

- Use `bun:test` directly; no mocking framework.
- Prefer real keys/certs/CRLs/OCSP payloads, often synthesized in-process.
- Assert typed result objects and error codes, not human-readable strings.
- Internal imports through `#micro509/internal/*` are acceptable when validating low-level
  invariants.
- Shared helpers belong in `helpers.ts`; OpenSSL process wrappers belong in `oracles/`.
- Differential tests compare normalized semantics only, never exact CLI stderr/stdout.
- PKITS cases run at fixed `2011-04-15T00:00:00Z`; do not casually change harness time.

## ANTI-PATTERNS

- No mocks.
- No `await expect()`.
- Do not overfit to OpenSSL text output.
- Do not hide expected failure reasons behind generic booleans when a typed code exists.
- Do not drop vendored PKITS naming; upstream-style names are part of the harness contract.
