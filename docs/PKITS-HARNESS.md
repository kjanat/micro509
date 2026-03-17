# PKITS Harness

Broad PKITS gap-report coverage lives in [`test/pkits.test.ts`].

- Source fixtures: vendored from BoringSSL's mirrored NIST PKITS corpus under [`test/fixtures/pkits/certs/`] and [`test/fixtures/pkits/crls/`].
- Upstream metadata: vendored under [`test/fixtures/pkits/upstream/`]. The local manifest is generated into [`test/fixtures/pkits/manifest.ts`].
- Runtime: `bun test test/pkits.test.ts`
- Validation time: all cases run at `2011-04-15T00:00:00Z`, matching the PKITS publication-time convention used by BoringSSL's harness.
- Scope: the harness now mirrors BoringSSL's testcase breadth, including CRL-driven sections, but it is still a gap-report harness, not a conformance claim.
- Revocation shape: revocation-focused PKITS sections run as a two-step harness here - path validation first, then CRL evaluation through `micro509` revocation APIs.

## Coverage shape

- Source of truth: [`test/fixtures/pkits/manifest.ts`] is generated from BoringSSL's `pkits_testcases-inl.h`.
- Breadth: all emitted BoringSSL PKITS cases are represented locally, including policy subparts and revocation-heavy sections.
- Assertion style: this harness is bool-first today. It checks whether each case validates overall under local APIs, while leaving exact error-code and policy-output matching to dedicated suites and future tightening.

## Syncing fixtures

- Run `bash test/fixtures/pkits/download.sh` to sync the full cert + CRL corpus and regenerate the manifest.
- The sync script requires `gh`, `curl`, and `bun`.

## Policy OIDs used by PKITS

- `anyPolicy` -> `2.5.29.32.0`
- `NIST test policy 1` -> `2.16.840.1.101.3.2.1.48.1`
- `NIST test policy 2` -> `2.16.840.1.101.3.2.1.48.2`
- `NIST test policy 3` -> `2.16.840.1.101.3.2.1.48.3`
- `NIST test policy 4` -> `2.16.840.1.101.3.2.1.48.4`
- `NIST test policy 5` -> `2.16.840.1.101.3.2.1.48.5`
- `NIST test policy 6` -> `2.16.840.1.101.3.2.1.48.6`

[`test/fixtures/pkits/certs/`]: ../test/fixtures/pkits/certs/
[`test/fixtures/pkits/crls/`]: ../test/fixtures/pkits/crls/
[`test/fixtures/pkits/manifest.ts`]: ../test/fixtures/pkits/manifest.ts
[`test/fixtures/pkits/upstream/`]: ../test/fixtures/pkits/upstream/
[`test/pkits.test.ts`]: ../test/pkits.test.ts
