# Public API, Exports, And Src Unflattening - Implementation Spec

**Status:** Ready for task breakdown
**Effort:** XL
**Date:** 2026-03-15

## Problem Statement

**Who:** maintainers and first adopters who need `micro509` to feel coherent, stable, and easy to learn before first npm and JSR publish.

**What:** the package currently exposes a hybrid, file-shaped public API while `src/` is flat and mixes public entrypoints with internal helpers, engines, and low-level primitives.

**Why it matters:** if the first publish bakes in file-level subpaths and ambiguous type ownership, later cleanup becomes breaking, noisy, and expensive. Deno/JSR docs already exposed the cost: public modules leak transitive internal types and force awkward re-export sprawl.

**Evidence:** `package.json` and `jsr.json` currently mirror many file-level subpaths; `src/index.ts` is a broad barrel but not the sole public home; `src/parse.ts`, `src/verify.ts`, `src/crl.ts`, `src/ocsp.ts`, `src/extensions.ts`, and `src/keys.ts` are large domain hubs; doc lint forced public modules to re-export many transitive types just to satisfy tooling.

## Discovery Summary

- The current API shape is effectively hybrid and muddy: root exports a lot, subpaths export a lot, and canonical ownership of many types is unclear.
- The flat `src/*.ts` layout now hides abstraction levels more than it helps; user-facing domains and implementation helpers sit at the same rank.
- The real domain seams are already visible:
  - X.509 authoring, parsing, extensions, and names
  - Verification, identity, policy, and name constraints
  - Revocation: CRL, OCSP, orchestration
  - PKCS containers
  - Keys and crypto
  - Encoding/shared primitives
- Current public subpaths are too fine-grained. They mirror source files instead of product domains.
- Pre-1.0 is the right time to prefer the correct architecture over minimizing churn.

## Recommendation

Make one deliberate pre-publish clean break:

1. Move from a file-shaped public API to a **domain-shaped public API**.
2. Keep `micro509` as the **canonical documented import**, but make it a curated workflow barrel rather than a kitchen-sink mirror of all files.
3. Replace most current fine-grained subpaths with a small set of stable domain entrypoints.
4. Unflatten `src/` into public domain folders plus an explicit `internal/` tree.
5. Give every public symbol **one domain owner**. Root may re-export it for convenience, but root is not the owner.
6. Stop treating source layout as public contract. Public entrypoints should map to curated domain barrels, not arbitrary implementation files.

This is intentionally a broad refactor. The package is unpublished; this is the cheapest moment to fix the API model instead of papering over it.

## Locked Architectural Decisions

| Chose                                               | Over                                     | Because                                                |
| --------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------ |
| Root-first docs and examples                        | Subpath-first docs                       | Most consumers want one obvious starting import        |
| Domain subpaths                                     | File-level subpaths                      | Domains survive refactors better than filenames        |
| Curated root barrel                                 | Exhaustive root barrel                   | Root docs should teach workflows, not dump every type  |
| Explicit `src/internal/**` boundary                 | Flat source tree                         | Internal code must be easy to move without export debt |
| Hard clean break now                                | Compatibility shims before first publish | There is no downstream ecosystem to preserve yet       |
| Generated export manifests from one source of truth | Hand-maintained duplicated export maps   | npm and JSR drift is too easy otherwise                |

## Target Public API Philosophy

### Root (`micro509`)

The root module is the default documented entrypoint.

It exports:

- high-value workflow functions
- the top-level input/result types those workflows need
- a curated set of shared domain types that are common in normal usage

It does **not** try to be the canonical home for every advanced type.

### Domain entrypoints

Domain entrypoints are the stable exhaustive homes for advanced consumers.

Recommended public entrypoints:

- `micro509`
- `micro509/x509`
- `micro509/verify`
- `micro509/revocation`
- `micro509/pkcs`
- `micro509/keys`
- `micro509/pem`
- `micro509/result`

Recommended platform-specific exception:

- keep `micro509/package.json` in npm exports only
- do **not** export `./package.json` from JSR

Additional surface decisions:

- keep `micro509/pem` as a permanent public entrypoint because PEM is a real PKI boundary concern across certificates, CSRs, CRLs, keys, and PKCS containers
- do not promote PKCS#12 MAC as a first-class standalone surface; keep it under `micro509/pkcs` as advanced PKCS#12 plumbing only

## Target Export Matrix

| Current export       | Target         | Action                                    |
| -------------------- | -------------- | ----------------------------------------- |
| `.`                  | `.`            | keep, redesign as curated workflow barrel |
| `./certificate`      | `./x509`       | merge                                     |
| `./csr`              | `./x509`       | merge                                     |
| `./extensions`       | `./x509`       | merge                                     |
| `./name`             | `./x509`       | merge                                     |
| `./parse`            | `./x509`       | merge                                     |
| `./verify`           | `./verify`     | keep, expand to full verify domain        |
| `./identity`         | `./verify`     | merge                                     |
| `./policy`           | `./verify`     | merge                                     |
| `./name-constraints` | `./verify`     | merge                                     |
| `./crl`              | `./revocation` | merge                                     |
| `./ocsp`             | `./revocation` | merge                                     |
| `./revocation`       | `./revocation` | keep                                      |
| `./pfx`              | `./pkcs`       | merge                                     |
| `./pkcs7`            | `./pkcs`       | merge                                     |
| `./pkcs12-mac`       | `./pkcs`       | merge                                     |
| `./keys`             | `./keys`       | keep                                      |
| `./pem`              | `./pem`        | keep                                      |
| `./result`           | `./result`     | keep                                      |
| `./package.json`     | npm-only       | remove from JSR                           |

## Target Module Layout

```text
src/
  index.ts

  x509/
    index.ts
    certificate.ts
    csr.ts
    parse.ts
    extensions.ts
    name.ts

  verify/
    index.ts
    verify.ts
    identity.ts
    policy.ts
    name-constraints.ts

  revocation/
    index.ts
    crl.ts
    ocsp.ts
    revocation.ts

  pkcs/
    index.ts
    pfx.ts
    pkcs7.ts
    pkcs12-mac.ts

  keys/
    index.ts
    keys.ts

  pem/
    index.ts
    pem.ts

  result/
    index.ts
    result.ts

  internal/
    asn1/
      asn1.ts
      der.ts
      oids.ts
    crypto/
      hash.ts
      signing.ts
      sig-verify.ts
      pbes2.ts
      ecdsa.ts
      rsa-pss.ts
    x509/
      extension-registry.ts
      extension-bits.ts
      name-fields.ts
    verify/
      verify-path.ts
      policy-engine.ts
      name-constraints-engine.ts
      validation.ts
    shared/
      ip.ts
```

Notes:

- Public folders own supported domains.
- `src/internal/**` is the only place implementation-only helpers live.
- Barrels contain re-exports only; no behavior.
- File moves should preserve domain ownership, not current filename prestige.

## Public Ownership Rules

1. Every public symbol has one domain owner: `x509`, `verify`, `revocation`, `pkcs`, `keys`, `pem`, or `result`.
2. Root may re-export owner-domain symbols, but root does not own them.
3. Public modules may import from `src/internal/**`.
4. Internal modules may not import public barrels.
5. Public leaf modules may not import sibling `index.ts` barrels.
6. Tests that need internals must import through an explicit internal alias such as `#micro509/internal/*`, not by depending on incidental public paths.

## Root Barrel Policy

`src/index.ts` should export the common workflows only.

Include at root:

- certificate and CSR creation entrypoints
- parse entrypoints
- verification entrypoints
- revocation orchestration entrypoints
- key generation/import/export entrypoints
- PKCS container entrypoints commonly needed by application code
- the direct input/result/value types needed for those workflows

Do not feature PKCS#12 MAC primitives in root docs or normal examples.

Leave exhaustive advanced types to domain entrypoints.

That keeps root docs usable while still making `micro509` the right default import for most consumers.

## Manifest Strategy

Add one source-of-truth export definition, for example:

- the `entry` map in `tsdown.config.ts`
- or a tiny shared `build/public-entrypoints.ts` imported by `tsdown.config.ts`

Generate from it:

- `package.json` `exports` via tsdown
- `jsr.json` `exports` via a small generator script driven by the same entry map
- optional doc/test assertions for parity

Implementation preference:

- if tsdown config ergonomics stay clean, treat `tsdown.config.ts` as the canonical entrypoint definition and generate JSR exports from it
- if the config starts carrying too much transformation logic, extract just the entry map to a shared module and import it from both tsdown and the JSR generator

Platform rules:

- npm export map includes `./package.json`
- JSR export map omits `./package.json`
- no other intentional divergence is allowed

## Scope And Deliverables

| Deliverable                                                                                                | Effort | Depends On     |
| ---------------------------------------------------------------------------------------------------------- | ------ | -------------- |
| D1. Build a symbol ownership inventory for the current public surface                                      | M      | -              |
| D2. Create new domain folders, `internal/` tree, and internal import aliases                               | M      | D1             |
| D3. Move implementation files into domain/internal locations without changing behavior                     | L      | D2             |
| D4. Create curated domain `index.ts` barrels and remove file-shaped public ownership                       | L      | D3             |
| D5. Redesign root `index.ts` as workflow-first curated barrel                                              | M      | D4             |
| D6. Replace current export maps with domain entrypoints and generate JSR exports from the tsdown entry map | M      | D4             |
| D7. Rework docs/examples around root-first plus domain-advanced guidance                                   | M      | D5, D6         |
| D8. Move tests and internal imports onto explicit internal aliases                                         | M      | D3             |
| D9. Final validation: build, typecheck, doc lint, publish dry-run, and export parity checks                | M      | D5, D6, D7, D8 |

## Non-Goals

- No compatibility aliases for the current fine-grained subpaths.
- No public low-level ASN.1 or DER product surface in this refactor.
- No attempt to preserve one-to-one source-file-to-export mapping.
- No new RFC scope claims.
- No runtime behavior expansion beyond what the structural refactor requires.
- No first-class standalone PKCS#12 MAC story in root or primary PKCS docs.

## Migration Plan

### Phase 1 - Surface Inventory

1. Enumerate every current public symbol from root and all current subpaths.
2. Assign each symbol one target owner domain.
3. Mark symbols as:
   - keep public
   - move public home
   - root-only convenience re-export
   - internalize
   - drop entirely

### Phase 2 - Internalization First

1. Create target folder structure.
2. Move known implementation-only files into `src/internal/**` first:
   - `verify-path.ts`
   - `policy-engine.ts`
   - `name-constraints-engine.ts`
   - `extension-registry.ts`
   - `extension-bits.ts`
   - `name-fields.ts`
   - `ecdsa.ts`
   - `rsa-pss.ts`
   - `hash.ts`
   - `asn1.ts`
   - `der.ts`
   - `oids.ts`
   - `ip.ts`
3. Rewrite imports so public leaves point downward into internal modules.

### Phase 3 - Domain Public Modules

1. Move current public leaves into domain folders.
2. Keep behavior and top-level exported symbols stable while files move.
3. Add domain `index.ts` files that are exhaustive, canonical public homes.

### Phase 4 - Root Redesign

1. Replace the current root mega-barrel with a workflow-first curated barrel.
2. Remove advanced type soup from root where it does not help ordinary users.
3. Make all examples use root unless they are explicitly teaching a domain entrypoint.

### Phase 5 - Exports Cutover

1. Replace file-level npm/JSR exports with domain entrypoints.
2. Make `./package.json` npm-only.
3. Generate JSR exports from the same tsdown entry map used for npm build entries.
4. Add a parity check so npm and JSR exports cannot silently drift.

### Phase 6 - Test And Docs Cleanup

1. Update tests to import internals only through `#micro509/internal/*`.
2. Regenerate and lint docs against the surviving public entrypoints only.
3. Remove any stale examples or docs that mention dropped fine-grained subpaths.

## Acceptance Criteria

- No public export path maps directly to implementation helper files under `src/internal/**`.
- `package.json` and `jsr.json` expose the same public domain entrypoints, except npm-only `./package.json`.
- Current file-shaped public subpaths are removed.
- `src/index.ts` is a curated workflow barrel, not an exhaustive mirror of all public types.
- Every public symbol has one canonical owner domain.
- `deno doc --lint` passes for root and every surviving public domain entrypoint.
- `bun typecheck`, `bun build`, `bun test`, and `deno publish --dry-run` pass after the refactor.
- Test-only internal imports go through an explicit internal alias.
- No public leaf imports a public barrel.

## Test Strategy

| Layer       | What                    | How                                                                          |
| ----------- | ----------------------- | ---------------------------------------------------------------------------- |
| Unit        | import graph boundaries | add a structural check or lint rule for forbidden barrel/internal directions |
| Unit        | export parity           | generate or assert npm/JSR entrypoint parity                                 |
| Unit        | root barrel curation    | add snapshot/assertion for allowed root exports                              |
| Integration | docs surface            | run `deno doc --lint` for root plus each public domain entrypoint            |
| Integration | packaging               | run `bun build`, `publint`, and `deno publish --dry-run`                     |
| Integration | behavior                | run current test suites after import rewrites                                |

## Risks And Mitigations

| Risk                                                      | Likelihood | Impact | Mitigation                                                                       |
| --------------------------------------------------------- | ---------- | ------ | -------------------------------------------------------------------------------- |
| Import cycles introduced by new barrels                   | Medium     | High   | enforce leaf->internal only, never leaf->barrel                                  |
| Public/internal bleed continues through test imports      | High       | Medium | create explicit internal alias and ban other internal import styles              |
| Docs regress because root becomes too sparse or too broad | Medium     | Medium | define root barrel policy up front and test docs on root plus domain entrypoints |
| npm/JSR exports drift again                               | Medium     | High   | generate both manifests from one source definition                               |
| Large file moves obscure behavior regressions             | Medium     | High   | move internals first, keep behavior unchanged, run full checks after each phase  |

## Trade-offs Made

| Chose                                                     | Over                                            | Because                                                        |
| --------------------------------------------------------- | ----------------------------------------------- | -------------------------------------------------------------- |
| `./x509` / `./verify` / `./revocation` / `./pkcs` domains | many narrow file-level subpaths                 | consumers think in workflows and domains, not source filenames |
| curated root barrel                                       | exhaustive root barrel                          | root docs should stay readable                                 |
| explicit internal tree                                    | implicit internal helpers beside public modules | abstraction level must be visible in the tree                  |
| drop old subpaths now                                     | transition aliases                              | prepublish is the cheapest time to break                       |
| npm-only `./package.json`                                 | mirrored JSR export                             | it is packaging metadata, not a JSR consumer surface           |
| keep `./pem`                                              | fold PEM fully into root                        | PEM is small but a legitimate recurring PKI boundary task      |
| de-emphasize PKCS#12 MAC                                  | promote it as a first-class surface             | most users want PFX workflows, not raw MAC plumbing            |

## Success Metrics

- A new user can follow root docs and complete common flows without choosing among many subpaths.
- An advanced user can infer the right import home from domain names alone.
- Public modules stop needing awkward transitive type re-export chains just to satisfy Deno doc tooling.
- Internal moves after first publish can happen inside `src/internal/**` without changing public exports.

## Open Questions

- None.
