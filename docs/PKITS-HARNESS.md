# PKITS Harness

Focused PKITS coverage lives in [`test/pkits.test.ts`].

- Source fixtures: vendored from BoringSSL's mirrored NIST PKITS corpus under [`test/fixtures/pkits/certs/`].
- Scope: only shipped path-validation claims today - signature/path basics, RFC 9618 policy handling, and RFC 5280 name constraints.
- Runtime: `bun test test/pkits.test.ts`
- Validation time: all cases run at `2011-04-15T00:00:00Z`, matching the PKITS publication-time convention used by BoringSSL's harness.
- Revocation: PKITS CRLs are not wired into this harness yet; revocation remains covered by the dedicated CRL/OCSP suites until broader conformance work lands.

## Included cases

| PKITS   | Area                            | Expected | Notes                                                                                 |
| ------- | ------------------------------- | -------- | ------------------------------------------------------------------------------------- |
| 4.1.1   | Signature/path basics           | pass     | sanity check for the harness input shape                                              |
| 4.6.5   | Basic constraints / path length | fail     | expects `path_length_exceeded`                                                        |
| 4.9.1   | `requireExplicitPolicy`         | pass     | exercises certificate-driven explicit-policy countdown                                |
| 4.10.12 | policy mappings                 | pass     | seeds `initialPolicySet = { NIST test policy 1 }`                                     |
| 4.10.13 | policy mappings                 | fail     | seeds `initialPolicySet = { NIST test policy 2 }`, expects `explicit_policy_required` |
| 4.11.4  | `inhibitPolicyMapping`          | pass     | checks mapped-policy survival through an intermediate chain                           |
| 4.12.3  | `inhibitAnyPolicy`              | fail     | sets initial inhibit-any-policy, expects `explicit_policy_required`                   |
| 4.13.21 | name constraints                | pass     | RFC822-constrained leaf path                                                          |
| 4.13.28 | name constraints                | fail     | combined `directoryName` + `rfc822Name`, expects `name_constraints_violated`          |

## Policy OIDs used by PKITS

- `NIST test policy 1` -> `2.16.840.1.101.3.2.1.48.1`
- `NIST test policy 2` -> `2.16.840.1.101.3.2.1.48.2`
- `NIST test policy 4` -> `2.16.840.1.101.3.2.1.48.4`

Those symbolic names come from BoringSSL's PKITS harness and map directly onto the OIDs above in [`test/pkits.test.ts`].

[`test/fixtures/pkits/certs/`]: ../test/fixtures/pkits/certs/
[`test/pkits.test.ts`]: ../test/pkits.test.ts
