# Independent JWT migration fixtures

The corpus is [site/assets/fixtures/jose-migration.json](../../site/assets/fixtures/jose-migration.json).
The runnable consumer recipe is [test/jose-migration-fixtures.test.ts](../../test/jose-migration-fixtures.test.ts).

It contains 21 synthetic cases, public verification keys, expected verdicts and
claims, a fixed verification clock (`1900000000` seconds), generation provenance
and a micro509-produced reverse token. No private keys or production credentials
are stored. The fixture identities use reserved `.example` names. Do not use
these tokens or public keys as production trust.

Most tokens are signed with jose 5.10.0. Deliberate duplicate/padded header cases
are signed over their exact bytes with WebCrypto rather than placeholder
signatures; the generator records this provenance. The PS256 rejection case has
a real signature, which a separate test verifies with PS256 enabled. The
unsecured `none` case is deliberate. Both libraries can use the same platform
crypto provider: these fixtures establish independent JOSE serialization,
parsing, claim policy and integration behavior, not provider diversity.

To use this in a consumer suite:

1. Keep micro509 in production dependencies and add the independent oracle in
   development dependencies: `bun add -d 'jose-v5@npm:jose@5.10.0'`.
2. Copy the JSON corpus and test into your test directory. Change `#micro509/*`
   imports to `micro509/*`, and change the JSON import to `./jose-migration.json`.
3. Replace the call to `verifyJwt` with your integration boundary when testing
   middleware, retaining the independent fixture tokens and fixed clock.
4. Run `bun test path/to/jose-migration-fixtures.test.ts`. Retain both directions;
   switching both the fixture signer and verifier to micro509 removes the
   independent comparison.

Cases cover Unicode, tampered payload/signature, a genuinely different signing
key, unknown issuer, audience mismatch, missing/expired claims, exact expiry and
not-before boundaries, future iat, schema-only failures, unsupported PS256,
unsecured tokens, malformed segments/base64url/UTF-8, duplicate JSON and padding.
The valid Unicode claims must reach the application as `café 🦊`; never decode a
payload with `JSON.parse(atob(...))`.

The test deliberately records differences: micro509 requires exp and rejects
future iat by default, and refuses duplicates and padded base64url. jose's default
policy accepts the corresponding independently signed fixtures. The policy
alignment test demonstrates the explicit opt-outs in micro509 and the matching
`requiredClaims`/`maxTokenAge` checks in jose. Do not change expected acceptance to
rejection simply to make a migration green.

The primary and secondary keys are generated once per regeneration and reused
within this synthetic corpus. Wrong-key cases use a distinct secondary key;
this is not a global production key cache. Runtime-generated test suites may
similarly share a pair per suite, but must isolate trust and lifecycle in real
applications.

Regenerate in the repository with:

```sh
bun install --frozen-lockfile
bun scripts/generate-jose-migration-fixtures.ts
bunx kfmt site/assets/fixtures/jose-migration.json
bun test test/jose-migration-fixtures.test.ts
```

Regeneration creates new ephemeral keys and signatures while keeping the clock,
scenario semantics and expected claims fixed. Review fixture deltas and run the
independent verifier after regeneration. The production package publishes
`dist/`; neither fixtures nor oracle dependencies become runtime dependencies.
