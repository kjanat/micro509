# Full Standards Compliance and DX Plan - Implementation Spec

**Status:** Active reference; early phases partly implemented
**Effort:** XL
**Date:** 2026-03-12

**Role:** keep the deeper design notes and task sequencing for the remaining
standards-compliance gaps.

**Use:** treat [`docs/PKIX-SCOPE.md`](../docs/PKIX-SCOPE.md) as the canonical
current support matrix and claim language. This spec is intentionally deeper and
partly historical.

## Problem Statement

**Who:** maintainers and consumers who need strict PKIX behavior without giving up DX, edge/web portability, or tree-shakeable imports.

**What:** `micro509` already has strong core PKI behavior, but it is still
partial against `RFC 5280`, `RFC 6960`, `RFC 6125`, and `RFC 9618`.

**Why it matters:** a library that claims standards compliance but accepts invalid chains, OCSP responders, or identity matches is harder to trust than a smaller, honest library. Full compliance work also risks bloating the root entry and hurting runtime/import DX unless package boundaries are locked first.

**Evidence:** current code still has partial name-constraint support, partial
CRL processing scope, incomplete OCSP local-responder and responder-revocation
policy handling, incomplete RFC 6125 integration in verification helpers, and
broader conformance evidence that is still incomplete.

## Discovery Summary

- Existing strengths: strong candidate path building, trust-anchor model,
  signature/time/CA/pathLen/AKI-SKI checks, RFC 9618-style policy processing,
  extracted identity and revocation domains, pure WebCrypto runtime, and stable
  domain entrypoints.
- Main gaps: incomplete CRL processing, incomplete exhaustive OCSP responder
  authorization and responder-cert policy, incomplete RFC 6125 integration in
  verification helpers, incomplete support for unsupported/under-enforced
  name-constraint forms, and incomplete conformance evidence.
- Architectural risk: remaining standards work still spans validation,
  revocation, and docs claims; keep the shipped domain boundaries intact so new
  behavior does not leak back into a monolithic root-only surface.

## Recommendation

Take a standards-first but regret-aware path:

1. Remove overclaims immediately.
2. Lock public API boundaries so path validation, service identity, and revocation are distinct concepts.
3. Add the missing RFC 5280 input/state surface.
4. Complete name comparison/name constraints and policy support.
5. Implement RFC 9618 directly instead of building the old RFC 5280 policy tree first.
6. Finish CRL correctness before claiming full revocation.
7. Harden OCSP after the revocation model is explicit.
8. Complete RFC 6125 identity matching on the new identity boundary.
9. Ship subpath exports and unbundled ESM so full compliance does not wreck DX.
10. Unlock standards claims only behind conformance gates.

## Scope And Deliverables

| Deliverable                                                         | Effort | Depends On         |
| ------------------------------------------------------------------- | ------ | ------------------ |
| D0. Remove overclaims and publish a compliance matrix               | S      | -                  |
| D1. Lock API and package boundaries                                 | M      | D0                 |
| D2. Add missing RFC 5280 validation inputs and state plumbing       | M      | D1                 |
| D3. Complete RFC 5280 name comparison and name constraints          | L      | D2                 |
| D4. Add policy-related extension types, OIDs, builders, and parsers | L      | D2                 |
| D5. Implement RFC 9618 policy validation                            | XL     | D4                 |
| D6. Implement full CRL processing scope                             | XL     | D2, D4             |
| D7. Harden OCSP responder auth, binding, and completeness           | L      | D1, D6             |
| D8. Extract and complete RFC 6125 identity matching                 | L      | D1, D3             |
| D9. Ship DX/tree-shaking/package improvements                       | M      | D1                 |
| D10. Add conformance gates and unlock claims                        | L      | D5, D6, D7, D8, D9 |

## Non-Goals

- Node-only runtime branches, `Buffer`, `fs`, or OpenSSL-shell helpers in core validation paths.
- Implicit network fetching inside pure validation APIs.
- Certificate Transparency, TSA, LDAP, or CMS beyond existing roadmap items.
- Implementing the old RFC 5280 policy-tree algorithm before RFC 9618.
- Preserving unsupported deep imports into `dist/`.

## Locked Architectural Decisions

| Chose                                           | Over                                                    | Because                                                                |
| ----------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------- |
| Separate path, identity, and revocation APIs    | Keep all checks inside `verify.ts` convenience wrappers | Standards boundaries are real; coupling here already caused overclaims |
| RFC 9618 directly                               | RFC 5280 policy tree then later rewrite                 | Avoids churn and worst-case complexity baggage                         |
| ESM-only, WebCrypto-only, platform-neutral core | Node-specific fallback branches                         | Preserves edge/web compatibility and keeps runtime model simple        |
| Curated root barrel plus stable subpath exports | Root barrel only                                        | Keeps DX while restoring real tree-shaking and import-cost control     |
| Structured distribution point and policy models | URI/string shortcuts                                    | Full RFC semantics need structured data, not lossy projections         |

## Data Model

### Public API Shapes

```ts
interface PolicyValidationInput {
  readonly initialPolicySet?: readonly string[] | 'any';
  readonly requireExplicitPolicy?: boolean;
  readonly inhibitPolicyMapping?: boolean;
  readonly inhibitAnyPolicy?: boolean;
}

interface InitialNameConstraintsInput {
  readonly permittedSubtrees?: readonly GeneralSubtree[];
  readonly excludedSubtrees?: readonly GeneralSubtree[];
}

interface ServiceIdentityInput {
  readonly type: 'dns' | 'ip' | 'uri' | 'srv';
  readonly value: string;
  readonly allowCommonNameFallback?: boolean;
}

interface DistributionPointName {
  readonly fullName?: readonly GeneralName[];
  readonly relativeName?: readonly ParsedName;
}

interface DistributionPoint {
  readonly distributionPoint?: DistributionPointName;
  readonly reasons?: readonly RevocationReason[];
  readonly crlIssuer?: readonly GeneralName[];
}

interface PolicyInformation {
  readonly policyIdentifier: string;
  readonly policyQualifiers?: readonly PolicyQualifierInfo[];
}
```

### Planned Result Shapes

- `validateCandidatePath()` remains a pure path-valid / path-invalid API.
- `matchServiceIdentity()` becomes the only API that evaluates RFC 6125 identity rules.
- revocation-facing APIs expose explicit certificate status (`good`, `revoked`, `unknown`) instead of forcing callers to infer unknown from transport or validation failure.
- `ParsedCertificate`, CRL, and OCSP parse results gain structured RFC objects rather than URI-only or omitted fields.

## API / Interface Contract

### Boundary Changes

- `src/verify.ts`
  - keep path building and path validation public.
  - remove `dnsName`, `ipAddress`, and `allowCommonNameFallback` from raw path-validation input.
  - keep convenience TLS/profile wrappers, but route them through the new identity module.
- new `src/identity.ts`
  - export `matchServiceIdentity()` and typed identity-match result/failure codes.
  - own RFC 6125 logic for DNS-ID, URI-ID, SRV-ID, IP-ID, and CN fallback compatibility mode.
- new `src/revocation.ts`
  - expose high-level revocation orchestration separately from path validation.
  - compose OCSP and CRL outcomes without hiding unknown/indeterminate states.
- package shape
  - keep `micro509` root barrel.
  - add stable subpath exports: `micro509/verify`, `micro509/identity`, `micro509/ocsp`, `micro509/crl`, `micro509/parse`, `micro509/extensions`, `micro509/keys`, `micro509/pem`, `micro509/pfx`, `micro509/pkcs7`, `micro509/pkcs12-mac`, `micro509/certificate`, `micro509/csr`, `micro509/name`.
    - Note! These are automatically set in package.json, depending on the entrypoints in "../tsdown.config.ts". Use the tsdown skill and if needed search though their src with opensrc to figyre out the details. Do NOT edit the exports in package.json manually, "bun bd" WILL overwrite it.

### Spike Notes - tsdown multi-entry exports

- Use a named `entry` object in `tsdown.config.ts` for stable public subpaths, eg `index: 'src/index.ts'`, `verify: 'src/verify.ts'`, `identity: 'src/identity.ts'`.
- Keep `exports: true`; tsdown derives `package.json` export entries from the configured entry names and generated output files.
- Keep `./package.json` as an explicit export, but treat the rest of `package.json` export metadata as generated build output. tsdown does this automatically.
- Split the work in two steps: first add the multi-entry map for stable subpaths, then enable preserved-module output in the later `preserve-module-build` task.

### Spike Notes - RFC 5280 directoryName comparison

- `directoryName` constraint checks cannot rely on `derHex` equality or DER-prefix subtree checks; RFC 5280 section 7.1 requires semantic DN comparison.
- Compare DNs as ordered sequences of RDNs; compare each RDN as an unordered set of AVAs with the same cardinality.
- For `DirectoryString` AVAs, use RFC 4518 string preparation as stored values: map with case folding, normalize with NFKC, apply prohibited-code-point checks, then compress insignificant spaces.
- Initial implementation target is `PrintableString` and `UTF8String`; `TeletexString`, `BMPString`, and `UniversalString` stay explicitly unsupported until modeled and tested.
- Future compare helpers should be named around intent, eg `prepareNameCompareString()`, `compareNameAttributeValue()`, `compareRelativeDistinguishedNames()`, `compareDistinguishedNames()`, and `isWithinDirectoryNameSubtree()`.
- `ParsedName` needs RDN-aware data for semantic comparison; keep `derHex` for round-trip/debug use, but add structured `rdns`/AVA metadata instead of reparsing display strings.
- Fixture plan for follow-up tasks: mixed `PrintableString`/`UTF8String` equality, case and space normalization, Unicode normalization, multi-valued RDN AVA reordering, exact-DN order sensitivity, subtree suffix matching, and regression coverage proving semantic compare replaces DER-prefix behavior.

### Architecture Notes - GeneralName support matrix for name constraints

- Split responsibilities cleanly:
  - parser owns tag-family preservation, typed decoding for supported forms, and explicit classification of unsupported forms.
  - validator owns RFC 5280 enforcement for supported forms and fail-closed handling when a critical `nameConstraints` extension carries an unsupported constrained form.
  - builder inputs can stay limited to the supported set; unsupported-form handling is a parse/validate concern.
- Support matrix for constrained `GeneralName` forms:

| Form                        | Parser target                         | Validator target                           | Notes                                        |
| --------------------------- | ------------------------------------- | ------------------------------------------ | -------------------------------------------- |
| `rfc822Name`                | decode to `email`                     | enforce                                    | already modeled                              |
| `dNSName`                   | decode to `dns`                       | enforce                                    | already modeled                              |
| `uniformResourceIdentifier` | decode to `uri`                       | enforce                                    | host-only matching per RFC 5280              |
| `iPAddress`                 | decode to address+mask bytes          | enforce                                    | reject non-8/non-32-byte constraint payloads |
| `directoryName`             | preserve structured DN data plus DER  | enforce after semantic RFC 5280 comparison | current DER-prefix shortcut must be removed  |
| `otherName`                 | preserve as explicit unsupported form | fail closed if critical                    | future RFC-specific handling can narrow this |
| `x400Address`               | preserve as explicit unsupported form | fail closed if critical                    | no silent drop                               |
| `ediPartyName`              | preserve as explicit unsupported form | fail closed if critical                    | no silent drop                               |
| `registeredID`              | preserve as explicit unsupported form | fail closed if critical                    | no silent drop                               |

- Current code is still between states: it decodes the supported set above, but unsupported constrained forms are not preserved yet. The follow-up `fail-closed-unsupported-nc` task must close that gap before full RFC 5280 claims.
- `subjectAltName` parsing can continue to expose unknown SAN entries for round-trip/debug use, but name-constraint parsing must not silently erase unsupported constrained forms because that weakens validator semantics.

### Spike Notes - RFC 9618 policy engine

- Model policy processing as a depth-indexed DAG, not a tree. Internal state should be a nullable `validPolicyGraph` plus the three RFC counters already threaded through validation state: `explicitPolicy`, `policyMapping`, and `inhibitAnyPolicy`.
- Each graph node should be keyed by `(depth, validPolicy)` so there is at most one node for a policy OID at a given depth. Store: `validPolicy`, `qualifierSet`, `expectedPolicySet`, and parent/child links as sets of node keys. That matches RFC 9618 section 5.2 and prevents duplicate subtrees.
- Represent the graph by depth for linear-time updates, eg `readonly nodesByDepth: readonly Map<string, PolicyGraphNode>[]`, plus a root `anyPolicy` node at depth 0 with `expectedPolicySet = { anyPolicy }`.
- When processing certificate `i`, apply RFC 9618 section 5.3 in this order: (1) exact policy matches against parent `expectedPolicySet`; (2) fallback creation from the depth `i-1` `anyPolicy` node when no exact match exists; (3) `anyPolicy` expansion when the certificate asserts `anyPolicy` and it is not inhibited for this step; (4) prune orphaned nodes recursively; (5) if the certificate lacks `certificatePolicies`, set the graph to `NULL`.
- `explicitPolicy` handling stays output-oriented: after policy processing for a certificate, fail if `explicitPolicy` is exhausted and the graph is `NULL`. At path end, success requires either `explicitPolicy > 0` or a non-empty `userConstrainedPolicySet`; do not depend on the deprecated RFC 5280 `valid_policy_tree` output.
- `policyMappings` handling should mutate `expectedPolicySet`, not clone path state. For each `issuerDomainPolicy` at depth `i`: if mapping is allowed and a node for that policy exists, replace its `expectedPolicySet` with the mapped subject policies; if only an `anyPolicy` node exists, synthesize one node for the issuer policy under that `anyPolicy` path; if mapping is inhibited, delete the node for that issuer policy and prune newly orphaned ancestors.
- `anyPolicy` should remain a first-class node, but only one per depth. Its `expectedPolicySet` is always `{ anyPolicy }`, and non-root `anyPolicy` nodes may only descend from the previous depth's `anyPolicy` node. Mixed parentage from both `anyPolicy` and concrete policies is invalid and should be unrepresentable in the graph type.
- Final outputs should be sets, not graph dumps. Derive `authorityConstrainedPolicySet` from leaf nodes whose parent list is exactly the depth-`n-1` `anyPolicy` node, plus the depth-`n` `anyPolicy` node if present. Then derive `userConstrainedPolicySet` by intersecting with the caller's initial policy set and filling via final `anyPolicy` qualifiers per RFC 9618 section 5.5.
- Qualifier handling should stay lazy. Preserve per-node qualifier sets so public results can include them later, but keep the implementation free to skip qualifier aggregation until `expose-policy-outcomes` needs it.
- Implementation split for later tasks: `add-policy-input-types` only introduces caller inputs; `add-policy-oids-and-types` / parse/build tasks make extension data available; `implement-policy-state` builds the graph and set transitions; `enforce-policy-constraints` / `enforce-policy-mappings` consume the same state machine rather than layering a second algorithm.
- Fixture plan for follow-up tasks: direct-policy intersection, `anyPolicy` fallback, explicit-policy-required with empty result, inhibited `anyPolicy`, allowed vs inhibited mappings, self-issued counter edge cases, and worst-case Cartesian mapping chains to prove graph growth stays linear.

### Spike Notes - full CRL applicability semantics

- Current CRL parsing is lossy for scope checks: `ParsedDistributionPoint.fullNameUris` and `issuingDistributionPointUri` keep URI projections only, so relative names, `crlIssuer`, reasons masks, and most issuing-distribution-point flags are not representable today.
- Use a clean-break structured model. Certificate-side `DistributionPoint` should keep `distributionPoint?: { fullName?: readonly GeneralName[]; relativeName?: ParsedName }`, `reasons?: readonly RevocationReason[]`, and `crlIssuer?: readonly GeneralName[]`. CRL-side `IssuingDistributionPoint` should keep `distributionPoint?: { fullName?: readonly GeneralName[]; relativeName?: ParsedName }`, `onlyContainsUserCerts?: boolean`, `onlyContainsCACerts?: boolean`, `onlySomeReasons?: readonly RevocationReason[]`, `indirectCrl?: boolean`, and `onlyContainsAttributeCerts?: boolean`.
- Keep delta-CRL data separate from scope data. `baseCrlNumber` and freshest/issuing distribution-point structures should compose, but delta processing should not overload the certificate distribution-point model or fall back to URI-only shortcuts.
- CRL applicability must run before revocation status decisions. A candidate CRL is applicable only if: issuer selection is valid for direct vs indirect CRLs; the signer certificate matches issuer rules and has `cRLSign`; the certificate's distribution point matches the CRL's issuing-distribution-point scope; the relevant reasons intersection is non-empty; and the CRL covers the certificate type (user CA vs end-entity) that the IDP flags allow.
- Distribution-point matching rules need explicit cases: absent certificate DP means only full-scope CRLs apply; `distributionPoint.fullName` matches against CRL IDP full names; `relativeName` is resolved against the certificate issuer or CRL issuer as RFC 5280 requires; `crlIssuer` changes which CRL issuer names are acceptable and becomes mandatory input for indirect CRLs.
- Indirect CRL handling needs entry-level issuer state. When IDP says `indirectCRL`, revoked entries may carry `certificateIssuer`; the effective issuer for each entry persists until another `certificateIssuer` appears, and entries without one inherit the previous effective issuer rather than the CRL issuer automatically.
- Delta CRL merge rules must reject scope drift. Complete and delta CRLs must agree on issuer, AKI, issuing-distribution-point scope, and numbering expectations; `removeFromCRL` is only meaningful for certificates on hold and only when merging delta entries into the complete-CRL view.
- Public revocation results should distinguish `non_applicable` from signature, freshness, or parsing failures so revocation orchestration can keep searching other evidence instead of collapsing everything into a generic invalid/stale bucket.
- Fixture plan for follow-up tasks: full CRL with no DP restrictions; certificate DP full-name match and mismatch; relative-name DP resolution; reasons-mask overlap vs disjoint failure; IDP `onlyContainsUserCerts` vs CA certificate mismatch; indirect CRL with `certificateIssuer` rollover; delta + complete merge with `removeFromCRL`; mismatched delta scope rejection; CRL signer missing `cRLSign`; and fresh-but-non-applicable CRL rejection.

## Deliverables (Ordered)

### D0. Remove Overclaims And Publish Compliance Matrix

**Goal:** docs say exactly what ships now.

**Files likely touched:** `README.md`, `docs/PKIX-SCOPE.md`

**Changes:**

- replace broad OCSP and API-separation claims with precise, current wording.
- change claim language from subsystem-wide labels (`OCSP support`) to standards-accurate labels (`basic OCSP request/response helpers`, `partial OCSP validation`, `partial DNS/IP identity matching`).
- add one short matrix: `implemented`, `partial`, `not yet` for RFC 5280 / 6960 / 6125 / 9618 areas.

**Acceptance criteria:**

- [ ] every checked item in `docs/PKIX-SCOPE.md` has a corresponding implementation and test.
- [ ] README feature bullets do not imply stricter OCSP responder auth or broader identity support than shipped.
- [ ] `docs/PKIX-SCOPE.md` points readers at this spec for full implementation sequencing.

### D1. Lock API And Package Boundaries

**Goal:** prevent future standards work from deepening the current path/identity/revocation coupling or bloating the root entry.

**Files likely touched:** `src/verify.ts`, `src/index.ts`, `package.json`, `tsdown.config.ts`, new `src/identity.ts`, new `src/revocation.ts`, `README.md`

**Changes:**

- introduce dedicated identity API.
- keep revocation separate from raw path validation.
- add subpath exports and preserve module boundaries in package output.
- add `sideEffects: false` if confirmed true.

**Acceptance criteria:**

- [ ] raw path validation can run without hostname/IP inputs.
- [ ] identity matching has a stable public API of its own.
- [ ] package exports allow domain imports without deep-importing `dist/`.
- [ ] build output remains ESM-only and platform-neutral.

### D2. Add Missing RFC 5280 Validation Inputs And State Plumbing

**Goal:** make the validator capable of representing the full RFC 5280 section 6 input surface.

**Files likely touched:** `src/verify.ts`, `src/index.ts`, `test/verify.test.ts`

**Changes:**

- add `initialPolicySet`, `requireExplicitPolicy`, `inhibitPolicyMapping`, `inhibitAnyPolicy`, `permittedSubtrees`, and `excludedSubtrees` to public validation inputs.
- thread those values through candidate-path validation state.
- add typed failure codes for policy/name-constraint setup and enforcement failures.

**Acceptance criteria:**

- [ ] all RFC 5280 section 6.1.1 inputs are representable in public types.
- [ ] defaults are explicit and documented.
- [ ] validation failures distinguish policy vs name-constraint vs trust-anchor vs signature/time failures.

### D3. Complete RFC 5280 Name Comparison And Name Constraints

**Goal:** finish path-processing semantics for names instead of relying on best-effort matching.

**Files likely touched:** `src/parse.ts`, `src/extensions.ts`, `src/verify.ts`, `test/parse.test.ts`, `test/verify.test.ts`

**Changes:**

- stop silently dropping unsupported constrained name forms when that would under-enforce a critical constraint.
- implement semantically correct `directoryName` comparison per RFC 5280 section 7.
- honor initial permitted/excluded subtree inputs.
- explicitly define supported and rejected GeneralName forms.

**Acceptance criteria:**

- [ ] self-issued handling still passes for pathLen/name-constraint edge cases.
- [ ] directoryName constraints no longer rely on raw DER prefix equality.
- [ ] unsupported critical name-constraint content fails closed.
- [ ] tests cover email, DNS, URI, IP, and directoryName constraints, plus negative cases.

### D4. Add Policy Extension Surface

**Goal:** make policy inputs first-class parse/build data before algorithm work starts.

**Files likely touched:** `src/oids.ts`, `src/extensions.ts`, `src/parse.ts`, `test/parse.test.ts`, `test/certificate.test.ts`

**Changes:**

- add OIDs, TS types, builders, and parsers for `certificatePolicies`, `policyMappings`, `policyConstraints`, and `inhibitAnyPolicy`.
- keep raw extension preservation.
- reject malformed encodings and `anyPolicy` misuse where RFC rules require it.

**Acceptance criteria:**

- [ ] all four policy-related extensions round-trip through create/parse flows.
- [ ] invalid policy encodings fail parse/build predictably.
- [ ] parsed certificates expose structured policy data needed by the RFC 9618 engine.

### D5. Implement RFC 9618 Policy Validation

**Goal:** ship policy processing that is standards-correct and fit to claim.

**Files likely touched:** `src/verify.ts`, `src/parse.ts`, `src/extensions.ts`, `src/oids.ts`, `test/verify.test.ts`, `docs/PKIX-SCOPE.md`

**Changes:**

- implement RFC 9618 policy graph/set algorithm directly.
- process policy mappings, explicit-policy requirements, `anyPolicy` inhibition, and policy constraints.
- expose final constrained policy outcome or typed failure details.

**Acceptance criteria:**

- [ ] policy-aware validation rejects chains that current code would incorrectly accept.
- [ ] explicit-policy, inhibit-any-policy, and policy-mapping behaviors each have positive and negative tests.
- [ ] algorithm avoids exponential tree behavior and is documented as RFC 9618-based.

### D6. Implement Full CRL Processing Scope

**Goal:** move from basic CRL signature/freshness validation to full RFC 5280 CRL semantics.

**Files likely touched:** `src/extensions.ts`, `src/parse.ts`, `src/crl.ts`, `src/index.ts`, `test/crl.test.ts`, `test/parse.test.ts`

**Changes:**

- replace URI-only certificate CRL DP shortcuts with structured distribution point objects.
- make that CRL distribution-point model change a clean break; do not keep a temporary URI-only compat alias.
- parse and enforce issuing-distribution-point scope, reasons masks, indirect CRLs, delta CRLs, and `removeFromCRL` semantics.
- enforce issuer `cRLSign` usage where required.
- expose explicit revocation outcomes and CRL applicability results.

**Acceptance criteria:**

- [ ] complete CRLs, delta CRLs, and indirect CRLs have direct test coverage.
- [ ] non-applicable CRLs are rejected as non-applicable, not treated as fresh enough evidence.
- [ ] revocation helpers can distinguish revoked, not revoked, and insufficient evidence.

### D7. Harden OCSP Responder Auth, Binding, And Completeness

**Goal:** make OCSP validation strict enough to claim real RFC 6960 support.

**Files likely touched:** `src/ocsp.ts`, `src/verify.ts`, `src/index.ts`, `test/ocsp.test.ts`, `README.md`, `docs/PKIX-SCOPE.md`

**Changes:**

- parse and enforce `ResponderID` by-name and by-key-hash.
- require direct issuance and `id-kp-OCSPSigning` for delegated responders unless explicit local policy says otherwise.
- validate `producedAt` in addition to `thisUpdate` / `nextUpdate`.
- require full request/response coverage for multi-cert requests.
- ensure supported inputs never throw inside validation.

**Acceptance criteria:**

- [ ] same-subject/different-key responder certs fail when `ResponderID` does not bind.
- [ ] delegated responders without direct issuance or `ocspSigning` fail.
- [ ] multi-cert requests fail if any requested `CertID` is omitted.
- [ ] `ParsedCertificate` and DER/PEM inputs all go through the same validation semantics.

### D8. Extract And Complete RFC 6125 Identity Matching

**Goal:** finish service identity matching on a clean boundary.

**Files likely touched:** new `src/identity.ts`, `src/verify.ts`, `src/parse.ts`, `src/extensions.ts`, `src/oids.ts`, `src/index.ts`, `test/verify.test.ts`, `test/parse.test.ts`, `README.md`

**Changes:**

- move hostname/service-name checks out of raw path validation.
- support DNS-ID, IP-ID, URI-ID, and SRV-ID explicitly.
- add IDNA normalization rules and explicit wildcard constraints.
- make CN fallback an explicit compatibility mode only when no supported presented identifier of the relevant type exists.

**Acceptance criteria:**

- [ ] DNS-ID, IP-ID, URI-ID, and SRV-ID each have explicit public input types and tests.
- [ ] IDNs normalize correctly before comparison.
- [ ] CN fallback is disabled by default and suppressed when supported SAN identifiers are present.

### D9. Ship DX / Tree-Shaking / Package Improvements

**Goal:** keep the library pleasant to use even after adding the missing RFC surface.

**Files likely touched:** `package.json`, `tsdown.config.ts`, `src/index.ts`, `README.md`

**Changes:**

- add stable subpath exports.
- switch package output to preserve module boundaries instead of a single bundled entry.
- document runtime support matrix for Node, Bun, Deno, browsers, and workers.

**Acceptance criteria:**

- [ ] consumers can import domain-specific modules without pulling the root entry.
- [ ] package remains edge/web compatible with no Node-only runtime dependency.
- [ ] README documents runtime prerequisites and import patterns.

### D10. Add Conformance Gates And Unlock Claims

**Goal:** claims become earned, not aspirational.

**Files likely touched:** `test/verify.test.ts`, `test/crl.test.ts`, `test/ocsp.test.ts`, new fixture directories as needed, `README.md`, `docs/PKIX-SCOPE.md`

**Changes:**

- add RFC-derived fixtures, malformed DER corpus, PKITS coverage, and differential tests against at least one mature implementation.
- define claim unlock rules for `partial`, `feature-complete`, and `standards-complete` wording.

**Acceptance criteria:**

- [ ] PKITS coverage exists for the path-validation areas the library claims.
- [ ] OCSP/CRL edge cases have fixture-backed tests.
- [ ] README and scope docs only advertise behavior proven by tests.

## Test Strategy

| Layer       | What                                                                                      | How                                                                       |
| ----------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Unit        | extension encoders/decoders, name comparison, responder binding, policy state transitions | deterministic fixture tests in `test/*.test.ts`                           |
| Integration | full cert/CRL/OCSP flows across public APIs                                               | end-to-end DER/PEM round-trips and validation scenarios                   |
| Conformance | RFC 5280 path validation, RFC 6960 OCSP, RFC 6125 identity semantics                      | PKITS, RFC-derived fixtures, differential tests vs mature implementations |
| Runtime     | Node, Bun, Deno, browser, worker compatibility                                            | scripted smoke matrix using WebCrypto-only paths                          |

## Risks And Mitigations

| Risk                                                   | Likelihood | Impact | Mitigation                                                                              |
| ------------------------------------------------------ | ---------- | ------ | --------------------------------------------------------------------------------------- |
| stricter standards checks reject inputs accepted today | High       | High   | call out intentional tightening in release notes and docs                               |
| package/API boundary cleanup causes breaking changes   | High       | High   | stage through wrappers, subpath exports, and explicit migration docs                    |
| policy and CRL work balloons in complexity             | High       | High   | isolate policy and revocation state machines behind dedicated modules and fixtures      |
| DX regresses as feature count grows                    | Medium     | High   | keep curated root barrel, add subpaths, preserve pure modules, document import guidance |
| edge/web parity regresses through Node-only helpers    | Medium     | High   | keep WebCrypto-first architecture and ban Node builtins from core paths                 |

## Compatibility Notes

- `validateCandidatePath()` is expected to lose service-identity fields; wrappers keep ergonomic TLS entry points.
- revocation-facing result shapes may become richer to represent `unknown` cleanly.
- CRL distribution points move from URI shortcuts to structured objects as a clean break.
- stricter OCSP responder auth, policy validation, and name constraints will intentionally fail more inputs than current releases.
- package consumers should migrate from root-only imports to domain subpaths where size/import cost matters.

## Success Metrics

- every user-facing standards claim maps to passing tests and one documented subsystem boundary.
- root DX stays intact while subpath imports exist for tree-shaking-sensitive consumers.
- the package remains WebCrypto-only and runs in modern browsers, workers, Bun, Deno, and modern Node.
- `docs/PKIX-SCOPE.md` can honestly mark RFC 5280 / 6960 / 6125 items complete only after the corresponding conformance gates pass.

## Open Questions

- None. This spec assumes pre-1.0 breaking changes are acceptable, uses a clean break for the CRL distribution-point model, and adds a dedicated `src/revocation.ts` boundary.

---

_Spec approved for task decomposition._
