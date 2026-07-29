# PROJECT KNOWLEDGE BASE

**Last updated:** 2026-07-23

## OVERVIEW

`micro509` is a zero-dependency TypeScript X.509/PKI library.
It is ESM-only, functional, strict-typed, and Bun-first in tooling.

PRERELEASE. NO DOWNSTREAM USERS.

## POSITIONING (WHY THIS LIBRARY)

The practical middle for X.509/PKI in JavaScript: modern workflows, pure
WebCrypto, zero dependencies, and typed results so callers act on failures.
Verification is the headline surface. `verifyCertificateChain` returns a
discriminated `Result` with a typed error code, the failing certificate index,
and structured `details`.

`Result` versus throw follows where the input originates:

- Untrusted runtime input returns `Result<T, Micro509Error>` with a stable error
  code. This covers parse (`src/x509/parse.ts`), verify, key import
  (`src/keys/keys.ts`), PEM/PKCS boundaries, and revocation.
- Builder construction input is developer-supplied. `createCertificate`,
  `createSelfSignedCertificate`, and the `encode*` extension helpers return their
  material directly and throw on invalid config (empty `keyUsage`, duplicate
  policy OID). Routing these through `Result` would force the whole builder API
  to become `Result`-returning. Keep them as throws.
- A builder throw is a `ResultError` carrying a stable `code`, thrown via
  `throwMicro509Error` (`src/result/result.ts`). Detect it with `isResultError`
  and branch on `error.code`. Codes are per-operation unions co-located with the
  builder (`ExtensionEncoderErrorCode`, `CrlEncoderErrorCode`,
  `NameEncoderErrorCode`, `CreateCertificateErrorCode`). Only builder _config_
  validation carries a code; DER decode guards and `_exhaustive` invariants stay
  bare `throw new Error`.

## STRUCTURE

```tree
micro509/
├── src/               # domain barrels + public modules
│   ├── x509/          # cert + CSR + extension + parse APIs
│   ├── verify/        # chain validation + policy + identity checks
│   ├── revocation/    # CRL/OCSP lifecycles
│   ├── keys/          # key import/export and generation
│   ├── crypto/        # detached sign/verify + ECDSA signature encoding
│   ├── der/           # public DER encode/decode surface (micro509/der)
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
├── packages/          # workspace tooling (doc-render, VitePress plugins)
├── examples/          # runnable consumers (browser, vite)
├── scripts/           # build, smoke, and doc-render helper scripts
├── .github/actions/   # reusable CI setup/release validation actions
├── comparisons/       # competitor notes
├── dist/              # generated build output
└── .opencode/         # local agent workflow state
```

## WHERE TO LOOK

| Task                              | Location                                                                  | Notes                                                |
| --------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------- |
| Public API surface                | `src/index.ts`                                                            | root barrel for `micro509`                           |
| Domain entrypoints                | `src/x509/`, `src/verify/`, `src/revocation/`, `src/keys/`, `src/crypto/` | domain-specific high-level entry surfaces            |
| Package entry routing             | `package.json`                                                            | `exports`, `imports`, scripts                        |
| Chain validation                  | `src/verify/verify.ts`                                                    | candidate path building, policy composition          |
| Certificate/CSR parsing           | `src/x509/parse.ts`                                                       | DER/PEM parse boundary + extension decoding          |
| Revocation                        | `src/revocation/crl.ts`, `src/revocation/ocsp.ts`                         | CRL + OCSP creation, parse, validate, verify         |
| Key import/export                 | `src/keys/keys.ts`                                                        | PKCS#1/8, SEC1, SPKI, JWK flows                      |
| DER codec surface                 | `src/der/der.ts`                                                          | public DER encode/decode (`micro509/der`)            |
| Extension model/builders          | `src/x509/extensions.ts`                                                  | typed extension schema and encoder helpers           |
| Test helpers and internals probes | `test/helpers.ts`, `test/internals.test.ts`                               | shared DER helpers, internal probing through imports |
| Standards scope                   | `docs/PKIX-SCOPE.md`                                                      | claim boundaries                                     |
| Docs site                         | `site/.vitepress/config.ts`, `site/guide/`, `site/api/`                   | VitePress config, authored guides, generated API     |
| Reusable CI actions               | `.github/actions/`                                                        | shared setup + release version validation            |

## CONVENTIONS

- Domain entrypoints own feature ownership; concrete lifecycle modules do implementation.
- `src/*/` barrels are re-export-only unless local file owners expand naturally.
- Relative imports use `.ts` extensions; `#micro509/*` subpath imports are extensionless (the `imports` map supplies `.ts`).
- Import boundaries: public leaf modules may use `#micro509/internal/*`, not sibling barrels.
- Return typed result unions for expected failures; throw only for invariants.
- `readonly` and exhaustive ADTs with `never` checks.
- Keep complexity-reduction helpers beside their owning codec, engine, or
  lifecycle module so behavior and failure mapping remain locally traceable.

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
- Committing or un-ignoring `docs/itu/**`; ITU-T source is redistribution-restricted and stays gitignored (`.gitignore`)

## CODE MAP

| Symbol                    | Type          | Location            | Refs                                      |
| ------------------------- | ------------- | ------------------- | ----------------------------------------- |
| `src/index.ts`            | barrel export | root surface        | Re-exports all stable API slices          |
| `src/x509/index.ts`       | domain barrel | X.509 feature slice | Certificate, CSR, parse, extension APIs   |
| `src/verify/index.ts`     | domain barrel | verification slice  | Path, policy, identity, name constraints  |
| `src/revocation/index.ts` | domain barrel | revocation slice    | CRL/OCSP orchestration                    |
| `src/der/index.ts`        | domain barrel | DER slice           | public DER encode/decode surface          |
| `src/result/result.ts`    | result ADT    | shared model        | central `Result`/`Micro509Error` contract |

## COMMANDS

```bash
bun bd                 # tsdown build to dist/
bun build              # tsdown build (same command as bd)
bun typecheck          # tsc across src, other, regular, and site configs
bun test               # bun test --concurrent (test:coverage for coverage)
bun test:pkits         # NIST PKITS conformance suite
bun test:differential  # OpenSSL differential (set DIFFERENTIAL_OPENSSL=1)
bun docs:lint          # deno doc lint on public exports (CI gate)
bun lint               # biome lint
bun fmt                # dprint fmt
```

## NOTES

- Repo and package name are both `micro509` (local checkout dir may still be `ts-x509`).
- `dist/` and `node_modules/` are generated output, not source of truth.
- `docs/deno/`, `site/api/`, and `site/.vitepress/cache/` are generated; document or edit their inputs instead.
- `docs/` text sources: `docs/rfc/` is vendored IETF RFC text (read-only reference); `docs/itu/` is gitignored ITU-T source that must never be tracked. `docs/PKIX-SCOPE.md` is the authored scope statement.
- `packages/` holds workspace tooling (doc-render, VitePress plugins) and is excluded from the coverage gate (`bunfig.toml` `coveragePathIgnorePatterns`).
- `package.json` `exports` are generated by tooling; edit source + build inputs, not output.
