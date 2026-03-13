# Pre-1.0 Architecture Cleanup - Implementation Spec

**Status:** Ready for task breakdown
**Effort:** XL
**Date:** 2026-03-13

## Problem Statement

**Who:** maintainers and first adopters who need `micro509` to be safe, understandable, and pleasant to integrate before the API ossifies.

**What:** the library currently concentrates too much risk in `verify.ts`, duplicates built-in extension knowledge across parse/build paths, spreads low-level DER handling across multiple modules, and exposes inconsistent result unions across public APIs.

**Why it matters:** these are pre-1.0 architectural foot-guns. If they survive first release, later fixes become more expensive, more breaking, and harder to validate.

**Evidence:** `src/verify.ts` mixes path orchestration with policy and name-constraint engines; `src/parse.ts` and `src/extensions.ts` duplicate built-in extension semantics; `src/der.ts` is permissive and low-level DER helpers are reimplemented elsewhere; `verify`, `identity`, `crl`, `ocsp`, `revocation`, `pfx`, and `pkcs7` all expose different result patterns.

## Discovery Summary

- `src/verify.ts` already contains two mostly self-contained subsystems: policy processing and name-constraint validation.
- `src/validation.ts` is a temporary internal compatibility shim, not a strong domain boundary.
- The best near-term extension registry scope is certificate + CSR extensions only; CRL and OCSP extension handling should stay bespoke in this cleanup.
- Core parse APIs should keep throwing on malformed input, but malformed-input rejection should become stricter and centralized.
- Public entrypoints can stay easy to discover even if internal implementation moves into nested domain folders.

## Recommendation

Make one deliberate pre-1.0 clean break:

1. Introduce a shared public result model.
2. Re-home public types to domain modules and remove `src/validation.ts` from the public export surface.
3. Harden the DER spine first so every later refactor sits on stricter parse primitives.
4. Extract the policy and name-constraints engines out of `verify.ts`.
5. Replace the built-in cert/CSR extension switch + duplicated builders with a cert/CSR extension registry.
6. Normalize public APIs around domain-owned inputs and result shapes.

This is intentionally broader than a pure internal refactor. Pre-1.0 is the right time to pay the churn cost.

## Scope And Deliverables

| Deliverable                                                                               | Effort | Depends On     |
| ----------------------------------------------------------------------------------------- | ------ | -------------- |
| D1. Add shared result and error primitives                                                | M      | -              |
| D2. Re-home public types to domain modules and demote `validation.ts` to an internal shim | M      | D1             |
| D3. Harden and centralize the DER spine                                                   | L      | -              |
| D4. Extract the policy engine from `verify.ts`                                            | M      | D2             |
| D5. Extract the name-constraints engine from `verify.ts`                                  | L      | D2, D3         |
| D6. Add a cert/CSR extension registry                                                     | L      | D3             |
| D7. Rewire cert/CSR parse and builder paths to use the registry                           | L      | D6             |
| D8. Redesign verify + identity public inputs/results around domain boundaries             | L      | D1, D2, D4, D5 |
| D9. Redesign CRL, OCSP, revocation, PFX, and PKCS7 public result surfaces                 | XL     | D1, D3         |
| D10. Update exports, tests, and docs for the clean break                                  | M      | D7, D8, D9     |

## Non-Goals

- No CRL or OCSP extension registry in this pass.
- No new RFC support claims beyond behavior already covered or explicitly added by follow-up work.
- No conversion of core parse APIs from throwing to typed parse-result unions.
- No runtime/network fetching behavior.
- No Node-only branches or `Buffer`-style escape hatches in core parsing/validation logic.

## Locked Architectural Decisions

| Chose                                                      | Over                                           | Because                                                                                                            |
| ---------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Shared `Result<T, E>` for all public non-parse result APIs | Per-module custom unions                       | Consumers should learn one success/error contract                                                                  |
| Domain-owned public types                                  | Keep `src/validation.ts` as a shared bucket    | The current bucket leaks unrelated concerns across module boundaries                                               |
| Cert/CSR-only extension registry                           | Global cert/CSR/CRL/OCSP registry              | Cert/CSR already share structure; CRL/OCSP do not yet justify the blast radius                                     |
| Strict throwing parse boundaries                           | Convert all parsing to typed result unions now | Malformed byte rejection belongs at the decode boundary and the full union conversion is too wide for this cleanup |
| Nested internal modules, stable public facades             | Keep every implementation file flat            | Internal structure should reflect domain seams without forcing public entrypoint churn                             |

## Target Module Layout

```text
src/
  core/
    der.ts
    result.ts
  verify/
    policy-engine.ts
    name-constraints-engine.ts
  extensions/
    registry.ts
  result.ts
  policy.ts
  name-constraints.ts
  verify.ts
  parse.ts
  extensions.ts
  identity.ts
  revocation.ts
```

Notes:

- `src/core/*` holds implementation-only primitives.
- `src/verify/*` and `src/extensions/*` hold implementation engines.
- top-level domain modules remain the public facades and primary package entrypoints.

## Data Model

### Shared Result Model

```ts
export type Result<T, E> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

export interface Micro509Error<TCode extends string, TDetails = Record<never, never>> {
  readonly code: TCode;
  readonly message: string;
  readonly details?: TDetails;
}

export interface IndexedMicro509Error<
  TCode extends string,
  TDetails = Record<never, never>,
> extends Micro509Error<TCode, TDetails> {
  readonly index?: number;
}
```

### Verify-Domain Inputs

```ts
export interface PolicyRequirements {
  readonly initialPolicySet?: readonly string[] | 'any';
  readonly requireExplicitPolicy?: boolean;
  readonly inhibitPolicyMapping?: boolean;
  readonly inhibitAnyPolicy?: boolean;
}

export interface InitialNameConstraints {
  readonly permittedSubtrees?: readonly GeneralSubtree[];
  readonly excludedSubtrees?: readonly GeneralSubtree[];
}

export interface ValidateCandidatePathInput {
  readonly chain: readonly ParsedCertificate[];
  readonly at?: Date;
  readonly purpose?: VerifyPurpose;
  readonly allowSelfSignedLeaf?: boolean;
  readonly policy?: PolicyRequirements;
  readonly nameConstraints?: InitialNameConstraints;
}
```

### Policy Outputs

```ts
export interface ConstrainedPolicy {
  readonly policyIdentifier: string;
  readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}

export interface PolicyEvaluation {
  readonly authorityConstrainedPolicies: readonly ConstrainedPolicy[];
  readonly userConstrainedPolicies: readonly ConstrainedPolicy[];
}
```

### Extension Registry

```ts
interface ExtensionDefinition<TParsed, TInput = TParsed> {
  readonly oid: string;
  readonly contexts: readonly ('certificate' | 'csr')[];
  readonly defaultCritical?: boolean | ((value: TInput) => boolean);
  decode(valueDer: Uint8Array): TParsed;
  encode(value: TInput): Uint8Array;
  applyParsed(accumulator: KnownParsedExtensionAccumulator, value: TParsed): void;
}
```

### DER Spine Requirements

The DER spine must provide:

- safe integer guards for encoded lengths and INTEGER creation
- full-input-consumption checks at top-level parse entrypoints
- bounded depth tracking for nested element walks
- rejection of long-form overflow and non-minimal length encodings
- shared helpers for reconstructed IMPLICIT `directoryName` and similar low-level structure rebuilds

## API / Interface Contract

### Parse APIs

- `parseCertificateDer`, `parseCertificateSigningRequestDer`, `parseCertificateRevocationListDer`, `parseOcspRequestDer`, and `parseOcspResponseDer` continue to throw on malformed input.
- stricter malformed input rejection is intentional API behavior change.
- parse APIs must reject trailing DER data, overflowed lengths, and over-depth nesting.

### Verify APIs

- verify-facing policy and name-constraint inputs move from flat mixed fields into nested `policy` and `nameConstraints` objects.
- `verify.ts` becomes orchestration only: path building, signature/time/basic-constraints checks, policy engine composition, name-constraints engine composition, identity composition.
- verify-facing results return `Result<..., VerifyError>` with failure metadata under `error`.

### Identity APIs

- `matchServiceIdentity(...)` returns `Result<void, IdentityError>`.
- `verify.ts` adapts identity errors at the composition seam instead of duplicating matcher logic.

### Revocation / Container APIs

- `crl`, `ocsp`, `revocation`, `pfx`, and `pkcs7` public result surfaces adopt the shared `Result<T, E>` model.
- status-bearing outcomes such as revocation move into `value` payloads instead of top-level mixed unions.

### Extension APIs

- cert and CSR built-in extension encode/decode logic comes from one registry definition source.
- registry support does not imply verifier support for critical-extension processing.
- CRL and OCSP extension handling remain domain-local for now.

## Implementation Plan

### Phase 1 - Foundations

1. Add `src/result.ts` and `src/core/result.ts` primitives.
2. Re-home public types to `src/policy.ts`, `src/name-constraints.ts`, `src/identity.ts`, and `src/revocation.ts`.
3. Remove `src/validation.ts` from public exports after import sites are updated; keep only as a temporary internal shim if needed.
4. Harden the DER spine and push all raw-DER entrypoints through stricter top-level checks.

### Phase 2 - Verify Decomposition

5. Extract the policy engine to `src/verify/policy-engine.ts`.
6. Extract the name-constraints engine to `src/verify/name-constraints-engine.ts`.
7. Redesign verify-facing inputs and outputs around nested domain objects and shared result primitives.

### Phase 3 - Extension Unification

8. Add `src/extensions/registry.ts` and migrate built-in cert/CSR extension definitions.
9. Rewire `src/parse.ts` built-in decode dispatch to use the registry.
10. Rewire `src/extensions.ts`, `src/certificate.ts`, and `src/csr.ts` to use the same registry for built-in extension encoding.

### Phase 4 - Public Surface Cleanup

11. Migrate CRL, OCSP, revocation, PFX, and PKCS7 result unions to the shared result model.
12. Update barrels, package entry config if needed, tests, and docs.

## Acceptance Criteria

- `src/verify.ts` no longer contains policy graph implementation details.
- `src/verify.ts` no longer contains name-form matcher or directoryName subtree engine logic.
- `src/parse.ts` no longer uses a large built-in extension OID switch for certificate/CSR extension decoding.
- built-in certificate and CSR extension encoding/decoding share one registry definition source.
- `src/validation.ts` is no longer a public export surface and every exported type has a domain-owned home.
- all public non-parse result-returning APIs use `Result<T, E>`.
- malformed top-level DER with trailing bytes, overflowed lengths, or excessive nesting is rejected deterministically.
- existing behavioral suites pass after the intentional public API updates are applied to tests.

## Test Strategy

| Layer       | What                                                      | How                                                                                                                         |
| ----------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Unit        | DER length/depth/input-consumption rules                  | add focused cases in `test/internals.test.ts` and `test/malformed-der.test.ts`                                              |
| Unit        | policy graph transitions and pruning                      | add focused internal tests plus keep `test/policy.test.ts`                                                                  |
| Unit        | name-constraints matchers and directoryName subtree logic | add focused internal tests plus keep `test/verify.test.ts` coverage                                                         |
| Unit        | cert/CSR extension round-trips                            | add parser + builder round-trip cases per built-in extension                                                                |
| Integration | verify public clean break                                 | update and run `test/verify.test.ts` and `test/identity.test.ts`                                                            |
| Integration | revocation/container public clean break                   | update and run `test/crl.test.ts`, `test/ocsp.test.ts`, `test/pfx.test.ts`, `test/pkcs7.test.ts`, `test/revocation.test.ts` |
| Regression  | full repo validation                                      | run `bun typecheck`, `bun test`, `bun lint`                                                                                 |

## Risks & Mitigations

| Risk                                                                                           | Likelihood | Impact | Mitigation                                                                                        |
| ---------------------------------------------------------------------------------------------- | ---------- | ------ | ------------------------------------------------------------------------------------------------- |
| Result harmonization touches too many public tests at once                                     | High       | High   | land shared primitives first, then migrate module families in separate steps                      |
| DER hardening rejects inputs old code silently accepted                                        | High       | Medium | treat stricter rejection as intentional, add explicit malformed regressions                       |
| Extension registry accidentally conflates builder policy, parser support, and verifier support | Medium     | High   | keep verifier allowlists separate and encode context metadata explicitly                          |
| Fully deleting `validation.ts` too early creates circular-import risk                          | Medium     | Medium | keep public types thin and engines internal; retain a non-exported shim until deletion is trivial |
| Policy/name-constraint extraction causes hidden behavior drift                                 | Medium     | High   | preserve existing tests first, then add direct engine tests before public API reshaping           |

## Trade-offs Made

| Chose                     | Over                                            | Because                                                                    |
| ------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------- |
| broad pre-1.0 clean break | piecemeal internal-only refactor                | now is the only cheap time to fix public seams too                         |
| throwing parse boundaries | typed parse unions everywhere                   | malformed byte rejection is a parse concern, not a validation concern      |
| cert/CSR-only registry    | one registry for every extension-bearing format | immediate payoff is highest where encode/decode duplication already exists |
| nested domain inputs      | flat verify input objects                       | policy and name-constraints are real subdomains with different lifecycles  |

## Success Metrics

- maintainers can reason about policy and name-constraints as isolated engines.
- new built-in cert/CSR extensions only need one definition source.
- consumers see one consistent result model across public non-parse APIs.
- malformed DER handling becomes stricter, centralized, and test-covered.
- public type ownership is obvious from module names.

## Rollback Plan

- each deliverable should land as its own commit or small series.
- if the public clean break becomes too noisy, keep the new internal engines and shared result primitives, then postpone the final API churn to a later branch before release.
- do not keep `validation.ts` public long-term; if rollback is needed, revert the export-surface change cleanly instead of duplicating source-of-truth types.

## Handoff Summary

This spec is ready for task breakdown into a PRD. Recommended execution order is:

1. shared result primitives
2. public type re-home
3. DER spine hardening
4. policy engine extraction
5. name-constraints extraction
6. cert/CSR extension registry
7. verify + identity clean break
8. CRL/OCSP/revocation/PFX/PKCS7 result migration
9. exports/docs/regression
