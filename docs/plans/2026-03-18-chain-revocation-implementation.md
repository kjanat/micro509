# Chain Revocation API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `checkChainRevocation` and integrate revocation checking into `verifyCertificateChain` per the [design document](./2026-03-18-chain-revocation-api-design.md).

**Architecture:** New `src/revocation/chain.ts` module with 6-stage pipeline (collect → validate → discover → check signer → evaluate → aggregate). Memoized state machine for CRL signer revocation to handle cycles. Policy layer converts findings to decisions.

**Tech Stack:** TypeScript, bun:test, existing micro509 primitives (CRL/OCSP parsing, DN comparison)

---

## Phase 1: Types & Scaffolding

### Task 1.1: Define Core Types

**Files:**
- Create: `src/revocation/chain.ts`

**Step 1: Create the type definitions file**

```typescript
/**
 * Chain-level revocation orchestration.
 * Evaluates CRL/OCSP evidence for an entire validated certificate chain.
 * @module
 */

import type { ParsedCertificate } from '#micro509/x509/parse.ts';
import type { CrlSource, RevocationReason } from './crl.ts';
import type { OcspResponseSource } from './ocsp.ts';

// ---------------------------------------------------------------------------
// Input Types
// ---------------------------------------------------------------------------

/** PEM, DER, or parsed certificate. */
export type CertificateSource = string | Uint8Array | ParsedCertificate;

/** PEM, DER, or parsed OCSP response. */
export type OcspResponseSource = string | Uint8Array;

/** Revocation checking policy. */
export interface RevocationPolicy {
  /** 'soft-fail': indeterminate → allow. 'hard-fail': indeterminate → deny. Default: 'soft-fail'. */
  readonly mode?: 'soft-fail' | 'hard-fail';
  /** Evidence preference order. Default: 'best-available'. */
  readonly prefer?: 'ocsp' | 'crl' | 'best-available';
}

/** Input for {@linkcode checkChainRevocation}. */
export interface CheckChainRevocationInput {
  /** Validated certificate chain (leaf first, root last). */
  readonly chain: readonly ParsedCertificate[];
  /** CRLs to evaluate. */
  readonly crls?: readonly CrlSource[];
  /** OCSP responses to evaluate. */
  readonly ocspResponses?: readonly OcspResponseSource[];
  /** Extra certs for indirect CRL issuers / delegated OCSP responders. */
  readonly extraCertificates?: readonly CertificateSource[];
  /** Evaluation time. Defaults to `new Date()`. */
  readonly at?: Date;
  /** Revocation policy. */
  readonly policy?: RevocationPolicy;
}

// ---------------------------------------------------------------------------
// Output Types
// ---------------------------------------------------------------------------

/** Granular reasons for indeterminate status. */
export type RevocationIndeterminateReason =
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
  | 'crl_signer_revoked'
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

/** Where the revocation evidence came from. */
export interface RevocationSource {
  readonly type: 'crl' | 'ocsp';
  readonly signerCertificate?: ParsedCertificate;
  readonly evidenceIdentifier?: string;
}

/** Per-certificate revocation status. */
export interface CertificateRevocationStatus {
  readonly certificate: ParsedCertificate;
  readonly status: 'good' | 'revoked' | 'indeterminate';
  readonly source?: RevocationSource;
  readonly indeterminateReasons?: readonly RevocationIndeterminateReason[];
  readonly revocationInfo?: {
    readonly date: Date;
    readonly reason?: RevocationReason;
  };
}

/** Execution errors (code failures, not evaluation outcomes). */
export interface RevocationExecutionError {
  readonly kind: 'parse_error' | 'unsupported_extension' | 'internal_error';
  readonly message: string;
  readonly evidenceIdentifier?: string;
}

/** Successful result value. */
export interface CheckChainRevocationValue {
  /** Policy decision derived from findings. */
  readonly decision: 'allow' | 'deny';
  /** Summary for quick inspection. */
  readonly summary: {
    readonly revokedCertificates: readonly ParsedCertificate[];
    readonly indeterminateCertificates: readonly ParsedCertificate[];
  };
  /** Per-certificate detailed findings. */
  readonly certificates: readonly CertificateRevocationStatus[];
  /** Execution errors (evidence we couldn't evaluate). */
  readonly executionErrors?: readonly RevocationExecutionError[];
}

/** Result type for {@linkcode checkChainRevocation}. */
export type CheckChainRevocationResult = {
  readonly ok: true;
  readonly value: CheckChainRevocationValue;
};
```

**Step 2: Export types from index**

Add to `src/revocation/index.ts`:

```typescript
export type * from './chain.ts';
```

**Step 3: Commit**

```bash
git add src/revocation/chain.ts src/revocation/index.ts
git commit -m "feat(revocation): add chain revocation type definitions"
```

---

### Task 1.2: Add Stub Function

**Files:**
- Modify: `src/revocation/chain.ts`
- Create: `test/chain-revocation.test.ts`

**Step 1: Write the failing test**

```typescript
import { describe, expect, it } from 'bun:test';
import { checkChainRevocation } from 'micro509';

describe('checkChainRevocation', () => {
  it('returns allow for empty chain', async () => {
    const result = await checkChainRevocation({ chain: [] });
    expect(result.ok).toBe(true);
    expect(result.value.decision).toBe('allow');
    expect(result.value.certificates).toEqual([]);
  });
});
```

**Step 2: Run test to verify it fails**

```bash
bun test test/chain-revocation.test.ts
```

Expected: FAIL — `checkChainRevocation` not exported

**Step 3: Write minimal implementation**

Add to `src/revocation/chain.ts`:

```typescript
/**
 * Checks revocation status for all certificates in a validated chain.
 *
 * Evaluates CRL and OCSP evidence against each certificate (except the trust
 * anchor), applies the revocation policy, and returns a unified decision.
 */
export async function checkChainRevocation(
  input: CheckChainRevocationInput,
): Promise<CheckChainRevocationResult> {
  const { chain, policy } = input;
  const mode = policy?.mode ?? 'soft-fail';

  // Empty chain → allow
  if (chain.length === 0) {
    return {
      ok: true,
      value: {
        decision: 'allow',
        summary: { revokedCertificates: [], indeterminateCertificates: [] },
        certificates: [],
      },
    };
  }

  // TODO: Implement full pipeline
  return {
    ok: true,
    value: {
      decision: 'allow',
      summary: { revokedCertificates: [], indeterminateCertificates: [] },
      certificates: [],
    },
  };
}
```

**Step 4: Export from index**

Add to `src/revocation/index.ts`:

```typescript
export { checkChainRevocation } from './chain.ts';
```

**Step 5: Run test to verify it passes**

```bash
bun test test/chain-revocation.test.ts
```

Expected: PASS

**Step 6: Commit**

```bash
git add src/revocation/chain.ts src/revocation/index.ts test/chain-revocation.test.ts
git commit -m "feat(revocation): add checkChainRevocation stub"
```

---

## Phase 2: Per-Certificate Evaluation

### Task 2.1: Skip Trust Anchor

**Files:**
- Modify: `test/chain-revocation.test.ts`
- Modify: `src/revocation/chain.ts`

**Step 1: Write the failing test**

Use real PKITS fixtures:

```typescript
import { readFile } from 'node:fs/promises';
import { parseCertificateDer, checkChainRevocation } from 'micro509';

async function loadPkitsCert(name: string) {
  const der = await readFile(
    new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url),
  );
  return parseCertificateDer(new Uint8Array(der));
}

describe('checkChainRevocation', () => {
  it('skips trust anchor (last cert in chain)', async () => {
    const root = await loadPkitsCert('TrustAnchorRootCertificate');
    const result = await checkChainRevocation({ chain: [root] });

    expect(result.ok).toBe(true);
    // Trust anchor not checked — returns allow with empty certificates
    expect(result.value.decision).toBe('allow');
    expect(result.value.certificates).toHaveLength(0);
  });

  it('returns indeterminate for non-anchor certs without evidence', async () => {
    const root = await loadPkitsCert('TrustAnchorRootCertificate');
    const goodCa = await loadPkitsCert('GoodCACert');

    const result = await checkChainRevocation({ chain: [goodCa, root] });

    expect(result.ok).toBe(true);
    // No CRLs provided → indeterminate for goodCa
    expect(result.value.certificates).toHaveLength(1);
    expect(result.value.certificates[0].status).toBe('indeterminate');
    expect(result.value.certificates[0].indeterminateReasons).toContain('no_applicable_crl');
  });
});
```

**Step 2: Run test to verify it fails**

```bash
bun test test/chain-revocation.test.ts
```

Expected: FAIL — certificates array empty/wrong

**Step 3: Implement trust anchor skip logic**

```typescript
export async function checkChainRevocation(
  input: CheckChainRevocationInput,
): Promise<CheckChainRevocationResult> {
  const { chain, policy } = input;
  const mode = policy?.mode ?? 'soft-fail';

  if (chain.length === 0) {
    return {
      ok: true,
      value: {
        decision: 'allow',
        summary: { revokedCertificates: [], indeterminateCertificates: [] },
        certificates: [],
      },
    };
  }

  // Skip trust anchor (last cert) — it's the trust base
  const certsToCheck = chain.slice(0, -1);
  const certificates: CertificateRevocationStatus[] = [];
  const revokedCertificates: ParsedCertificate[] = [];
  const indeterminateCertificates: ParsedCertificate[] = [];

  for (const cert of certsToCheck) {
    // TODO: Evaluate evidence
    const status: CertificateRevocationStatus = {
      certificate: cert,
      status: 'indeterminate',
      indeterminateReasons: ['no_applicable_crl', 'no_applicable_ocsp'],
    };
    certificates.push(status);
    indeterminateCertificates.push(cert);
  }

  // Apply policy
  const hasRevoked = revokedCertificates.length > 0;
  const hasIndeterminate = indeterminateCertificates.length > 0;
  const decision: 'allow' | 'deny' =
    hasRevoked ? 'deny' :
    hasIndeterminate && mode === 'hard-fail' ? 'deny' :
    'allow';

  return {
    ok: true,
    value: {
      decision,
      summary: { revokedCertificates, indeterminateCertificates },
      certificates,
    },
  };
}
```

**Step 4: Run test to verify it passes**

```bash
bun test test/chain-revocation.test.ts
```

**Step 5: Commit**

```bash
git add src/revocation/chain.ts test/chain-revocation.test.ts
git commit -m "feat(revocation): skip trust anchor, return indeterminate without evidence"
```

---

### Task 2.2: Match CRLs to Certificates

**Files:**
- Modify: `test/chain-revocation.test.ts`
- Modify: `src/revocation/chain.ts`

**Step 1: Write the failing test**

```typescript
import { parseCertificateRevocationListDer } from 'micro509';

async function loadPkitsCrl(name: string) {
  const der = await readFile(
    new URL(`./fixtures/pkits/crls/${name}.crl`, import.meta.url),
  );
  return parseCertificateRevocationListDer(new Uint8Array(der));
}

it('evaluates good status when CRL covers cert and serial not listed', async () => {
  const root = await loadPkitsCert('TrustAnchorRootCertificate');
  const goodCa = await loadPkitsCert('GoodCACert');
  const crl = await loadPkitsCrl('TrustAnchorRootCRL');

  const result = await checkChainRevocation({
    chain: [goodCa, root],
    crls: [crl],
    at: new Date('2011-04-15T00:00:00Z'),
  });

  expect(result.ok).toBe(true);
  expect(result.value.certificates).toHaveLength(1);
  expect(result.value.certificates[0].status).toBe('good');
  expect(result.value.decision).toBe('allow');
});
```

**Step 2: Run test to verify it fails**

```bash
bun test test/chain-revocation.test.ts
```

Expected: FAIL — status is 'indeterminate'

**Step 3: Implement CRL matching logic**

Import and use existing `checkCertificateRevocationAgainstCrl`:

```typescript
import { checkCertificateRevocationAgainstCrl, parseCertificateRevocationListFromSource } from './crl.ts';

async function evaluateCertificateRevocation(
  cert: ParsedCertificate,
  issuer: ParsedCertificate,
  input: CheckChainRevocationInput,
): Promise<CertificateRevocationStatus> {
  const { crls = [], at = new Date() } = input;
  const indeterminateReasons: RevocationIndeterminateReason[] = [];

  // Try CRLs
  for (const crlSource of crls) {
    const crl = typeof crlSource === 'object' && 'issuer' in crlSource
      ? crlSource
      : await parseCertificateRevocationListFromSource(crlSource);

    const result = checkCertificateRevocationAgainstCrl({
      certificate: cert,
      issuer,
      crl,
      at,
    });

    if (result.ok) {
      if (result.value.status === 'revoked') {
        return {
          certificate: cert,
          status: 'revoked',
          source: { type: 'crl', signerCertificate: issuer },
          revocationInfo: {
            date: result.value.revocationDate,
            reason: result.value.reason,
          },
        };
      }
      if (result.value.status === 'good') {
        return {
          certificate: cert,
          status: 'good',
          source: { type: 'crl', signerCertificate: issuer },
        };
      }
    }
  }

  // No applicable evidence
  if (crls.length === 0) {
    indeterminateReasons.push('no_applicable_crl');
  }

  return {
    certificate: cert,
    status: 'indeterminate',
    indeterminateReasons,
  };
}
```

Update main function to use `evaluateCertificateRevocation` and pass the issuer (next cert in chain).

**Step 4: Run test to verify it passes**

```bash
bun test test/chain-revocation.test.ts
```

**Step 5: Commit**

```bash
git add src/revocation/chain.ts test/chain-revocation.test.ts
git commit -m "feat(revocation): match CRLs to certificates using existing primitives"
```

---

### Task 2.3: Detect Revoked Certificates

**Files:**
- Modify: `test/chain-revocation.test.ts`

**Step 1: Write the failing test**

```typescript
it('returns revoked status and denies when cert is on CRL', async () => {
  const root = await loadPkitsCert('TrustAnchorRootCertificate');
  const revokedCa = await loadPkitsCert('RevokedsubCACert');
  const goodCa = await loadPkitsCert('GoodCACert');
  const crl = await loadPkitsCrl('GoodCACRL');

  // Chain: revokedCa → goodCa → root
  // revokedCa is revoked by GoodCACRL
  const result = await checkChainRevocation({
    chain: [revokedCa, goodCa, root],
    crls: [crl, await loadPkitsCrl('TrustAnchorRootCRL')],
    at: new Date('2011-04-15T00:00:00Z'),
  });

  expect(result.ok).toBe(true);
  expect(result.value.decision).toBe('deny');
  expect(result.value.summary.revokedCertificates).toHaveLength(1);
  expect(result.value.certificates[0].status).toBe('revoked');
});
```

**Step 2: Run test to verify it fails or passes**

If existing implementation handles this via `checkCertificateRevocationAgainstCrl`, test may pass. If not, implement.

**Step 3: Verify and commit**

```bash
bun test test/chain-revocation.test.ts
git add test/chain-revocation.test.ts
git commit -m "test(revocation): verify revoked certificate detection"
```

---

## Phase 3: CRL Signer Validation (4.4.21 Fix)

### Task 3.1: Discover Indirect CRL Issuers

**Files:**
- Modify: `src/revocation/chain.ts`
- Modify: `test/chain-revocation.test.ts`

**Step 1: Write the failing test**

Use PKITS 4.14 (indirect CRL) fixtures:

```typescript
it('discovers indirect CRL issuer from extraCertificates', async () => {
  const root = await loadPkitsCert('TrustAnchorRootCertificate');
  const indirectCrlIssuer = await loadPkitsCert('indirectCRLCA1Cert');
  const indirectCrlCa = await loadPkitsCert('indirectCRLCA2Cert');
  // ... setup chain and indirect CRL

  const result = await checkChainRevocation({
    chain: [/* leaf, ca, root */],
    crls: [/* indirect CRL */],
    extraCertificates: [indirectCrlIssuer],
    at: new Date('2011-04-15T00:00:00Z'),
  });

  expect(result.value.certificates[0].source?.signerCertificate?.subject.raw)
    .toEqual(indirectCrlIssuer.subject.raw);
});
```

**Step 2: Implement extraCertificates discovery**

Add logic to search `extraCertificates` for CRL signer when `crl.authorityKeyIdentifier` doesn't match the chain issuer.

**Step 3: Run tests and commit**

---

### Task 3.2: Memoized CRL Signer Revocation Check

**Files:**
- Modify: `src/revocation/chain.ts`

**Step 1: Write the failing test (4.4.21)**

```typescript
it('PKITS 4.4.21: denies when CRL signer is revoked', async () => {
  // Load the specific PKITS 4.4.21 fixtures
  const root = await loadPkitsCert('TrustAnchorRootCertificate');
  // ... setup chain where CRL signer cert is itself revoked

  const result = await checkChainRevocation({
    chain: [/* ... */],
    crls: [/* CRL signed by revoked cert, CRL revoking that signer */],
    at: new Date('2011-04-15T00:00:00Z'),
    policy: { mode: 'hard-fail' },
  });

  expect(result.value.decision).toBe('deny');
  expect(result.value.certificates[0].indeterminateReasons)
    .toContain('crl_signer_revoked');
});
```

**Step 2: Implement memoized state machine**

```typescript
type SignerValidationState =
  | 'visiting'
  | 'resolved-valid'
  | 'resolved-revoked'
  | 'resolved-indeterminate';

const signerValidationCache = new Map<string, SignerValidationState>();

async function validateCrlSigner(
  signer: ParsedCertificate,
  input: CheckChainRevocationInput,
  cache: Map<string, SignerValidationState>,
): Promise<SignerValidationState> {
  const key = signer.fingerprint;
  const cached = cache.get(key);

  if (cached === 'visiting') {
    // Cycle detected → indeterminate (can't bless itself)
    return 'resolved-indeterminate';
  }
  if (cached !== undefined) {
    return cached;
  }

  cache.set(key, 'visiting');

  // Check if signer is in the validated chain (trusted)
  const isInChain = input.chain.some(c => c.fingerprint === key);
  if (isInChain) {
    cache.set(key, 'resolved-valid');
    return 'resolved-valid';
  }

  // Check signer's revocation status recursively
  // ... (use existing CRL evaluation, but need signer's issuer)

  cache.set(key, 'resolved-valid'); // or revoked/indeterminate
  return 'resolved-valid';
}
```

**Step 3: Run tests and commit**

---

## Phase 4: Integrate with verifyCertificateChain

### Task 4.1: Add revocation Option

**Files:**
- Modify: `src/verify/verify.ts`

**Step 1: Write the failing test**

```typescript
import { verifyCertificateChain } from 'micro509';

it('verifyCertificateChain with revocation option', async () => {
  const result = await verifyCertificateChain({
    leaf: /* ... */,
    roots: [root],
    revocation: {
      crls: [crl],
      policy: { mode: 'hard-fail' },
    },
  });

  expect(result.ok).toBe(true);
});
```

**Step 2: Extend VerifyCertificateChainInput**

```typescript
export interface VerifyCertificateChainInput
  extends PolicyValidationInput,
    InitialNameConstraintsInput {
  // ... existing fields ...

  /** Optional revocation checking. */
  readonly revocation?: ChainRevocationInput;
}

export interface ChainRevocationInput {
  readonly crls?: readonly CrlSource[];
  readonly ocspResponses?: readonly OcspResponseSource[];
  readonly extraCertificates?: readonly CertificateSource[];
  readonly policy?: RevocationPolicy;
}
```

**Step 3: Call checkChainRevocation after path validation**

```typescript
// In verifyCertificateChain, after validateCandidatePath succeeds:
if (input.revocation !== undefined) {
  const revocationResult = await checkChainRevocation({
    chain: buildResult.value.chain,
    ...input.revocation,
    at: input.at,
  });

  if (revocationResult.value.decision === 'deny') {
    const firstRevoked = revocationResult.value.summary.revokedCertificates[0];
    if (firstRevoked) {
      return verifyFailureResult({
        ok: false,
        error: {
          code: 'certificate_revoked',
          message: `Certificate revoked: ${firstRevoked.subject.text}`,
        },
      });
    }
    // Indeterminate with hard-fail
    return verifyFailureResult({
      ok: false,
      error: {
        code: 'revocation_indeterminate',
        message: 'Revocation status indeterminate',
      },
    });
  }
}
```

**Step 4: Run tests and commit**

---

## Phase 5: Code Deduplication

### Task 5.1: Create Shared name-parsing Module

**Files:**
- Create: `src/internal/x509/name-parsing.ts`
- Modify: `src/x509/parse.ts`
- Modify: `src/revocation/crl.ts`
- Modify: `src/pkcs/pkcs7.ts`

**Step 1: Extract parseName and related functions**

Move from `parse.ts`:
- `parseName`
- `parseGeneralName`
- `parseGeneralNames`
- `parseDistributionPointName`

**Step 2: Update imports in all consumers**

**Step 3: Run all tests**

```bash
bun test
```

**Step 4: Commit**

```bash
git add src/internal/x509/name-parsing.ts src/x509/parse.ts src/revocation/crl.ts src/pkcs/pkcs7.ts
git commit -m "refactor: extract shared name-parsing module"
```

---

### Task 5.2: Remove Duplicates in crl.ts

**Files:**
- Modify: `src/revocation/crl.ts`

**Step 1: Replace private duplicates with imports**

| Private in crl.ts           | Import from     |
| --------------------------- | --------------- |
| `compareNameAttributeValue` | `dn.ts`         |
| `isDirectoryStringTag`      | `dn.ts`         |
| `prepareNameCompareString`  | `dn.ts`         |
| `buildSubjectKeyIdentifier` | `extensions.ts` |
| `encodeExtension`           | `extensions.ts` |

**Step 2: Run tests and commit**

---

## Phase 6: PKITS Harness Simplification

### Task 6.1: Replace evaluatePkitsRevocation

**Files:**
- Modify: `test/pkits.test.ts`

**Step 1: Replace complex harness logic with library call**

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

**Step 2: Run PKITS tests**

```bash
bun test test/pkits.test.ts
```

**Step 3: Verify 4.4.21 passes**

**Step 4: Commit**

```bash
git add test/pkits.test.ts
git commit -m "refactor(test): simplify PKITS harness using checkChainRevocation"
```

---

## Success Criteria Checklist

- [ ] PKITS 4.4.21 passes
- [ ] All 246 previously-passing PKITS tests still pass
- [ ] `checkChainRevocation` exported from `micro509`
- [ ] `verifyCertificateChain` accepts `revocation` option
- [ ] Shared `name-parsing.ts` module created
- [ ] Code duplication reduced in `crl.ts`
- [ ] Test harness simplified to ~10 lines
- [ ] JSDoc on all public types and functions
- [ ] CHANGELOG updated

---

## Execution Notes

**Dependencies between tasks:**
- Phase 1 → Phase 2 → Phase 3 (sequential)
- Phase 4 can start after Phase 2
- Phase 5 can run in parallel with Phase 3-4
- Phase 6 requires Phase 3 complete

**Estimated commits:** 10-15

**Risk areas:**
- CRL signer memoization cycle detection
- Indirect CRL issuer discovery matching PKITS expectations
- Delta CRL pairing (defer to later if complex)
