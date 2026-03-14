# Contributing

Thanks for working on `micro509`.

This repo is small on purpose. Keep changes tight, typed, and honest about
scope.

## Read this first

Before changing behavior, read:

- `README.md`
- `docs/PKIX-SCOPE.md`
- `docs/API.md` if you are changing the public API surface

Then read the files for the area you are touching:

- certificates and CSRs: `src/certificate.ts`, `src/csr.ts`, `src/parse.ts`
- chain validation: `src/verify.ts`, `src/verify-path.ts`, `src/identity.ts`
- revocation: `src/crl.ts`, `src/ocsp.ts`, `src/revocation.ts`
- keys and signing: `src/keys.ts`, `src/signing.ts`, `src/sig-verify.ts`, `src/pbes2.ts`
- extensions and names: `src/extensions.ts`, `src/extension-registry.ts`, `src/name.ts`, `src/name-constraints-engine.ts`

## Setup

- use Bun for installs and local checks
- use a runtime with WebCrypto globals available
- install deps with `bun install`

## Normal workflow

1. Read the relevant scope and source files first.
2. Make the smallest change that actually solves the problem.
3. Add or update tests with the code change.
4. Run the relevant checks locally.
5. Update docs only if shipped behavior or supported scope changed.

Do not bundle unrelated cleanup into behavior changes.

## Local checks

Run these before opening a PR:

```bash
bun typecheck
bun test
bun lint
bun fmt
```

Useful focused commands:

```bash
bun bd
bun build
bun test test/pkits.test.ts
bun test test/differential.test.ts
```

## Code rules

- ESM-only
- WebCrypto-first
- zero runtime dependencies
- keep `src/` flat unless there is a very strong reason not to
- tabs, LF, single quotes
- use `.ts` relative import extensions in source
- no `any`
- no non-null assertions
- no `as Type`; only `as const` and `as const satisfies`
- no classes
- no default exports

Model expected failures as typed result unions. Throw for malformed input and
internal invariants.

## Scope and standards discipline

This repo deliberately ships partial standards support.

- do not claim full RFC 5280, RFC 6960, or revocation coverage unless code and tests actually prove it
- keep `docs/PKIX-SCOPE.md` aligned with shipped behavior
- do not widen README claims without matching tests
- treat harness docs as contract docs, not marketing copy

If you change support boundaries, update both docs and tests in the same change.

## API and module discipline

- keep parse tolerance separate from validation policy
- if you add or change an algorithm, review both `src/signing.ts` and `src/sig-verify.ts`
- if you add or change a public API, review `src/index.ts` and `docs/API.md`
- if you change extension parsing, review `src/parse.ts`, `src/extensions.ts`, and `src/extension-registry.ts`
- keep user-facing docs about using the package, not about internal build machinery

## Test expectations

- no mocks
- prefer real certs, CSRs, CRLs, OCSP payloads, and fixtures
- assert typed result codes and structured details, not human-readable message text
- add semantic tests, not just shape tests
- use focused fixtures for edge cases
- failing tests are acceptable when they expose a real bug
- internal imports through `#micro509/*.ts` are fine when testing low-level behavior intentionally

Public claims are backed by test coverage. If your change alters a claim, update
the tests that justify it.

## Commits

- use conventional commits; prefer `type(scope): subject`
- wrap commit body lines at about 72 columns
- write the body around why the change exists, not just what moved

## Before opening a PR

Make sure:

- the change is bounded
- tests and docs match the new behavior
- scope claims are still accurate
- the PR description explains the user-visible impact and any standards-boundary change
