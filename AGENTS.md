# PROJECT KNOWLEDGE BASE

**Last updated:** 2026-03-15

## OVERVIEW

`micro509` is a zero-dependency TypeScript X.509/PKI library.
It is ESM-only, functional, strict-typed, and Bun-first in tooling.

PRERELEASE. NO DOWNSTREAM USERS.

## STRUCTURE

```tree
ts-x509/
├── src/               # domain barrels + public modules
│   ├── x509/          # cert + CSR + extension + parse APIs
│   ├── verify/        # chain validation + policy + identity checks
│   ├── revocation/    # CRL/OCSP lifecycles
│   ├── keys/          # key import/export and generation
│   ├── pem/           # PEM encode/decode boundary
│   ├── pkcs/          # PKCS-7 and PKCS#12 workflows
│   ├── result/        # shared result/error algebra
│   └── internal/      # implementation-only modules
│       ├── asn1/
│       ├── crypto/
│       ├── shared/
│       ├── verify/
│       └── x509/
├── test/              # feature suites, helpers, oracle adapters, PKITS fixtures
├── docs/              # scope statements, harness docs, vendored RFC text
├── site/              # VitePress docs site + generated API pages
├── .github/actions/   # reusable CI setup/release validation actions
├── specs/             # long-lived implementation planning docs
├── comparisons/       # competitor notes
├── dist/              # generated build output
└── .opencode/         # local agent workflow state
```

## WHERE TO LOOK

| Task                              | Location                                                   | Notes                                                |
| --------------------------------- | ---------------------------------------------------------- | ---------------------------------------------------- |
| Public API surface                | `src/index.ts`                                             | root barrel for `micro509`                           |
| Domain entrypoints                | `src/x509/`, `src/verify/`, `src/revocation/`, `src/keys/` | domain-specific high-level entry surfaces            |
| Package entry routing             | `package.json`                                             | `exports`, `imports`, scripts                        |
| Chain validation                  | `src/verify/verify.ts`                                     | candidate path building, policy composition          |
| Certificate/CSR parsing           | `src/x509/parse.ts`                                        | DER/PEM parse boundary + extension decoding          |
| Revocation                        | `src/revocation/crl.ts`, `src/revocation/ocsp.ts`          | CRL + OCSP creation, parse, validate, verify         |
| Key import/export                 | `src/keys/keys.ts`                                         | PKCS#1/8, SEC1, SPKI, JWK flows                      |
| Extension model/builders          | `src/x509/extensions.ts`                                   | typed extension schema and encoder helpers           |
| Test helpers and internals probes | `test/helpers.ts`, `test/internals.test.ts`                | shared DER helpers, internal probing through imports |
| Differential oracle               | `test/differential.test.ts`, `test/oracles/openssl.ts`     | normalized semantics against OpenSSL                 |
| PKITS coverage                    | `test/pkits.test.ts`, `docs/PKITS-HARNESS.md`              | fixed-time conformance subset                        |
| Standards scope                   | `docs/PKIX-SCOPE.md`                                       | claim boundaries                                     |
| Docs site                         | `site/.vitepress/config.ts`, `site/guide/`, `site/api/`    | VitePress config, authored guides, generated API     |
| Reusable CI actions               | `.github/actions/`                                         | shared setup + release version validation            |

## CONVENTIONS

- Domain entrypoints own feature ownership; concrete lifecycle modules do implementation.
- `src/*/` barrels are re-export-only unless local file owners expand naturally.
- `.ts` import extensions are used across source.
- Import boundaries: public leaf modules may use `#micro509/internal/*`, not sibling barrels.
- Return typed result unions for expected failures; throw only for invariants.
- `readonly` and exhaustive ADTs with `never` checks.

## ANTI-PATTERNS (THIS PROJECT)

Avoid the following in this project:

- `any`
- Non-null assertions `!`
- `as Type`; use `as const` and `as const satisfies` only
- Classes or default exports
- Mocks in tests
- `eslint-disable` or `@ts-ignore`
- `await expect()` in tests
- Over-claiming RFC support outside `docs/PKIX-SCOPE.md`
- Editing `docs/rfc` — it is vendored text, not project prose

## CODE MAP

| Symbol                    | Type          | Location            | Refs                                      |
| ------------------------- | ------------- | ------------------- | ----------------------------------------- |
| `src/index.ts`            | barrel export | root surface        | Re-exports all stable API slices          |
| `src/x509/index.ts`       | domain barrel | X.509 feature slice | Certificate, CSR, parse, extension APIs   |
| `src/verify/index.ts`     | domain barrel | verification slice  | Path, policy, identity, name constraints  |
| `src/revocation/index.ts` | domain barrel | revocation slice    | CRL/OCSP orchestration                    |
| `src/result/result.ts`    | result ADT    | shared model        | central `Result`/`Micro509Error` contract |

## COMMANDS

```bash
bun bd                 # fast build to dist/
bun build              # full tsdown build
bun typecheck          # tsgo type-check
bun test               # bun test --coverage
bun lint               # biome lint
bun fmt                # dprint fmt
bun test:pkits
bun test:differential
```

## NOTES

- Repo name is `ts-x509`; package name is `micro509`.
- `dist/` and `node_modules/` are generated output, not source of truth.
- `docs/deno/`, `site/api/`, and `site/.vitepress/cache/` are generated; document or edit their inputs instead.
- `package.json` `exports` are generated by tooling; edit source + build inputs, not output.
