# Chain Revocation API Design

**Date**: 2026-03-18
**Status**: Approved
**Author**: Claude + Human collaboration

## Problem Statement

The PKITS test harness implements significant RFC 5280 §6.3 CRL validation logic that should be in the library:

1. **Chain-level revocation orchestration** — checking all certs in a validated chain
2. **CRL issuer discovery** — finding indirect CRL signers from a certificate pool
3. **Delta CRL pairing** — matching delta CRLs to base CRLs
4. **Reason coverage tracking** — ensuring all revocation reasons are covered
5. **CRL signer revocation validation** — verifying CRL signers aren't revoked (PKITS 4.4.21)

Consumers currently must hand-roll this logic, creating a "pit of failure" instead of a "pit of success."

## Design Goals

- **One-shot API** for 90% of users: validate chain + check revocation in one call
- **Composable API** for advanced users: separate chain validation from revocation
- **Clean separation** of evaluation findings vs policy decisions
- **Rich diagnostics** for debugging revocation failures
- **Deduplication** of code shared between library modules

## API Design

### Integrated API (on `verifyCertificateChain`)

```typescript
interface VerifyCertificateChainInput {
  // ... existing fields ...

  /** Optional revocation checking. */
  revocation?: ChainRevocationInput;
}

interface ChainRevocationInput {
  crls?: readonly CrlSource[];
  ocspResponses?: readonly OcspResponseSource[];
  /** Extra certs for CRL issuer / delegated responder discovery. */
  extraCertificates?: readonly CertificateSource[];
  policy?: RevocationPolicy;
}

interface RevocationPolicy {
  /** 'soft-fail': indeterminate → allow. 'hard-fail': indeterminate → deny. */
  mode?: 'soft-fail' | 'hard-fail';
  /** Evidence preference. */
  prefer?: 'ocsp' | 'crl' | 'best-available';
}
```

When revocation fails with `mode: 'hard-fail'`, the result includes distinct error codes:

- `certificate_revoked`
- `revocation_indeterminate`
- `revocation_evidence_invalid`

### Standalone API (new export)

```typescript
export async function checkChainRevocation(
  input: CheckChainRevocationInput,
): Promise<CheckChainRevocationResult>;

interface CheckChainRevocationInput {
  /** Validated certificate chain (leaf first, root last). */
  chain: readonly ParsedCertificate[];
  /** Extra certs for indirect CRL issuers / delegated OCSP responders. */
  extraCertificates?: readonly CertificateSource[];
  crls?: readonly CrlSource[];
  ocspResponses?: readonly OcspResponseSource[];
  at?: Date;
  policy?: RevocationPolicy;
}

interface CheckChainRevocationResult {
  ok: true;
  value: CheckChainRevocationValue;
}

interface CheckChainRevocationValue {
  /** Policy decision derived from findings. */
  decision: 'allow' | 'deny';

  /** Summary for quick inspection. */
  summary: {
    revokedCertificates: readonly ParsedCertificate[];
    indeterminateCertificates: readonly ParsedCertificate[];
  };

  /** Per-certificate detailed findings. */
  certificates: readonly CertificateRevocationStatus[];

  /** Execution errors (evidence we couldn't evaluate). */
  executionErrors?: readonly RevocationExecutionError[];
}

interface CertificateRevocationStatus {
  certificate: ParsedCertificate;
  status: 'good' | 'revoked' | 'indeterminate';
  source?: RevocationSource;
  indeterminateReasons?: readonly RevocationIndeterminateReason[];
  revocationInfo?: { date: Date; reason?: RevocationReason };
}

interface RevocationSource {
  type: 'crl' | 'ocsp';
  signerCertificate?: ParsedCertificate;
  evidenceIdentifier?: string;
}
```

## Internal Architecture

### New Module: `src/revocation/chain.ts`

```
src/revocation/
├── index.ts          # re-exports
├── crl.ts            # existing primitives
├── ocsp.ts           # existing primitives
├── revocation.ts     # existing single-cert orchestration
└── chain.ts          # NEW: chain-level orchestration
```

**`chain.ts` responsibilities:**

1. Iterate chain (skip trust anchor)
2. Match CRLs/OCSP to certs via distribution points
3. Discover CRL issuers from `extraCertificates`
4. Validate CRL signer not revoked (recursive, memoized)
5. Track reason coverage across CRLs
6. Pair delta CRLs with base CRLs
7. Apply policy to produce `allow | deny`

### Evidence Evaluation Pipeline

```
Stage 1: COLLECT candidate evidence (match by distribution points, AIA)
Stage 2: VALIDATE evidence structurally & temporally (parse, signatures, freshness)
Stage 3: DISCOVER & VALIDATE evidence signer (find signer, check authorization)
Stage 4: CHECK signer revocation (recursive with cycle detection → indeterminate)
Stage 5: EVALUATE target cert against trusted evidence (serial lookup)
Stage 6: AGGREGATE coverage & APPLY policy (finding + policy → decision)
```

### CRL Signer Validation (4.4.21 Fix)

Uses state machine with memoization:

```typescript
type SignerValidationState =
  | 'visiting' // Cycle detection
  | 'resolved-valid'
  | 'resolved-revoked'
  | 'resolved-indeterminate';
```

**Critical**: Cycle detection yields `indeterminate`, not `valid`. A cert graph cannot bless itself.

### Trust Anchor Handling

Trust anchor (last cert in chain) is never revocation-checked — it's the trust base.

## Error Handling

### Two Channels

1. **Evaluation outcomes** (valid results):
   - `good` / `revoked` / `indeterminate` + reasons

2. **Execution errors** (code failures):
   - Parse failures, unsupported extensions, internal errors

### Indeterminate Reasons (Granular)

```typescript
type RevocationIndeterminateReason =
  // Evidence not found
  | 'no_applicable_crl'
  | 'no_applicable_ocsp'
  // Scope issues
  | 'distribution_point_mismatch'
  | 'issuer_name_mismatch'
  | 'reason_scope_mismatch'
  | 'indirect_crl_scope_mismatch'
  | 'reason_coverage_incomplete'
  // Signer trust issues
  | 'crl_signer_not_found'
  | 'crl_signer_not_authorized'
  | 'crl_signer_revoked' // ← 4.4.21
  | 'crl_signer_indeterminate'
  | 'ocsp_responder_not_found'
  | 'ocsp_responder_not_authorized'
  | 'ocsp_responder_revoked'
  | 'ocsp_responder_indeterminate'
  // Freshness
  | 'crl_expired'
  | 'ocsp_response_expired'
  // OCSP specific
  | 'ocsp_status_unknown';
```

## Code Deduplication

### New Shared Module: `src/internal/x509/name-parsing.ts`

Consolidates duplicated parsing functions:

| Function                     | Currently In               | Copies |
| ---------------------------- | -------------------------- | ------ |
| `parseName`                  | parse.ts, crl.ts, pkcs7.ts | 3      |
| `parseGeneralName`           | parse.ts, crl.ts           | 2      |
| `parseGeneralNames`          | parse.ts, crl.ts           | 2      |
| `parseDistributionPointName` | parse.ts, crl.ts           | 2      |

### Remove Private Duplicates in `crl.ts`

| Private in crl.ts           | Import from     |
| --------------------------- | --------------- |
| `compareNameAttributeValue` | `dn.ts`         |
| `isDirectoryStringTag`      | `dn.ts`         |
| `prepareNameCompareString`  | `dn.ts`         |
| `buildSubjectKeyIdentifier` | `extensions.ts` |
| `encodeExtension`           | `extensions.ts` |

### Consolidate `isSelfIssued`

Currently 3 copies. Keep export in `verify-path.ts`, import elsewhere.

## Testing Strategy

### Simplified PKITS Harness

After refactor, `evaluatePkitsRevocation` becomes ~10 lines:

```typescript
async function evaluatePkitsRevocation(
  chain: readonly ParsedCertificate[],
  crlNames: readonly string[],
): Promise<boolean> {
  const crls = await Promise.all(crlNames.map(readPkitsParsedCrl));

  const result = await checkChainRevocation({
    chain,
    crls,
    extraCertificates: await loadAllPkitsCertificates(),
    policy: { mode: 'hard-fail' },
    at: PKITS_VALIDATION_TIME,
  });

  return result.value.decision === 'allow';
}
```

### New Unit Tests

- `test/chain-revocation.test.ts` — unit tests for `checkChainRevocation`
- Focus on: delta CRL pairing, indirect CRL discovery, signer revocation (4.4.21), reason coverage

### PKITS Validation

- 4.4.21 must pass after implementation
- All existing passing tests must remain passing

## Documentation Updates

1. **README.md** — Add chain revocation to feature list
2. **docs/PKIX-SCOPE.md** — Update CRL coverage status
3. **src/revocation/chain.ts** — Comprehensive JSDoc
4. **CHANGELOG.md** — Document new API

## Success Criteria

1. PKITS 4.4.21 passes
2. All 246 currently-passing PKITS tests still pass
3. `checkChainRevocation` exported and documented
4. `verifyCertificateChain` accepts `revocation` option
5. Code duplication reduced (shared parsing module)
6. Test harness simplified to ~10 lines
