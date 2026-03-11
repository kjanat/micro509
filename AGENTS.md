# PROJECT KNOWLEDGE BASE

**Generated:** 2026-03-11 **Commit:** a660a9b **Branch:** master

## OVERVIEW

`micro509` — zero-dependency TypeScript X.509/PKI library (certs, CSRs, CRLs, OCSP, PKCS#7/12, PFX). ESM-only, functional (no classes), async only where WebCrypto requires it. ~175 public exports through single barrel `src/index.ts`.

## STRUCTURE

```
ts-x509/
├── src/            # 20 flat modules — all PKI domain code (no subdirs)
├── test/           # Single monolithic test file (2014 lines)
├── docs/           # FUTURE.md (roadmap), PKIX-SCOPE.md (RFC 5280 compliance)
└── comparisons/    # Competitive analysis (@peculiar/x509)
```

## WHERE TO LOOK

| Task                         | Location                              | Notes                                                    |
| ---------------------------- | ------------------------------------- | -------------------------------------------------------- |
| Public API surface           | `src/index.ts`                        | Barrel re-exports from 13 of 20 modules                  |
| Key generation/import/export | `src/keys.ts`                         | Largest surface (~45 exports), PKCS#1/8, SEC1, SPKI, JWK |
| Certificate create/parse     | `src/certificate.ts`, `src/parse.ts`  | Create + DER/PEM parsing                                 |
| Chain/CSR verification       | `src/verify.ts`                       | Discriminated union results with error codes             |
| CRL lifecycle                | `src/crl.ts`                          | Create, parse, verify, revocation check                  |
| OCSP request/response        | `src/ocsp.ts`                         | Create, parse, verify, validate                          |
| PFX/PKCS#12                  | `src/pfx.ts`, `src/pkcs12-mac.ts`     | Create and parse PFX bundles                             |
| PKCS#7 cert bags             | `src/pkcs7.ts`                        | SignedData parse, cert bag create/parse                  |
| DER/ASN.1 internals          | `src/der.ts`, `src/asn1.ts`           | NOT public — encoding/decoding primitives                |
| OID registry                 | `src/oids.ts`                         | NOT public — `as const satisfies Record<string, string>` |
| Signing internals            | `src/signing.ts`, `src/sig-verify.ts` | NOT public — key-to-algorithm mapping                    |
| Encryption internals         | `src/pbes2.ts`                        | NOT public — PBES2/PBKDF2 for encrypted keys             |
| Roadmap                      | `docs/FUTURE.md`                      | Planned features and backlog                             |
| RFC compliance               | `docs/PKIX-SCOPE.md`                  | What is/isn't implemented per RFC 5280                   |

## CONVENTIONS

- **Tabs** for indentation, LF line endings, single quotes in TS
- **dprint** as sole formatter — no ESLint, no Prettier, no Biome
- **Max TS strictness**: `strict` + `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes`
- **No `any`, no `!` non-null, no `as` type assertions** — `as const` and `as const satisfies` are the only permitted assertion forms
- **`.ts` import extensions** everywhere — `rewriteRelativeImportExtensions` rewrites to `.js` on emit
- **`readonly` properties** pervasively on all interfaces
- **Discriminated unions** for results: `{ ok: true; value: T } | { ok: false; code: string; message: string }`
- **No default exports** anywhere
- **`Record<never, never>`** as empty-map generic default
- **Exhaustive switches** via `const _exhaustive: never = value` pattern
- **Throws** for invariant violations; returns Result unions for expected failures

## ANTI-PATTERNS (THIS PROJECT)

- **Never use `any`** — strict mode + `noUncheckedIndexedAccess` makes it unnecessary
- **Never use `!` non-null assertion** — use explicit `undefined` checks and throws
- **Never use `as Type`** — only `as const` / `as const satisfies` are allowed
- **No classes** — entire library is functional
- **No mocking in tests** — tests use real WebCrypto, Node's `X509Certificate` as oracle
- **No `eslint-disable` or `@ts-ignore`** — zero instances in codebase
- **Only AES-256-CBC** for traditional PEM encryption (rejects other ciphers)
- **Only PBES2/PBKDF2** for PKCS#8 encryption
- **Only RSASSA-PKCS1-v1_5, ECDSA (P-256/P-384), Ed25519** for signing
- **Only SHA-256/384/512** for RSA hashing

## COMMANDS

```bash
bun --bun run build     # tsc → dist/ (ESM .js + .d.ts)
bun --bun run check     # tsc --noEmit (full type-check)
bun --bun run typecheck # tsgo --noEmit (native TS compiler preview)
bun --bun run test      # vitest run (single-pass)
bun --bun run fmt       # dprint fmt
```

## NOTES

- **Repo name ≠ package name**: repo is `ts-x509`, npm package is `micro509`
- **Dual typecheck**: `tsc` (5.9) and `tsgo` (native preview 7.0) — both must pass
- **`DOM` in tsconfig lib**: needed for WebCrypto types (`SubtleCrypto`, `CryptoKey`)
- **Bun** is package manager (`bun.lock`), but Volta pins Node 25.8.0 as fallback
- **No CI** — no `.github/workflows/`; all checks are local
- **Single test file** covers all 20 modules — helpers defined inline at bottom
- **7 internal modules** (`asn1`, `der`, `oids`, `pbes2`, `sig-verify`, `signing`, + extension builders) are NOT re-exported from `index.ts`
- **MD5** used only in `opensslBytesToKey()` for legacy PEM compat — not a general concern
- **SHA-1** used for Subject Key Identifier (RFC 5280 mandate) and OCSP cert ID (standard)
