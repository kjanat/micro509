---
sidebarTitle: Migrate from jose
outline: [2, 3]
---

# Migrate from jose

This guide describes the implementation in this change set, including the new
algorithm, JWE, key-import and JWKS APIs. These additions are **not a claim about
the published 0.17.1 package**. Check the version/preview you install against the
[capability matrix](../reference/algorithms.md). The reusable independent corpus
is generated with jose 5.10.0; the repository also retains its jose 6 interop
suite. Keep an independent implementation in development dependencies during a
migration, rather than replacing both fixture signer and verifier together.

## Check the cryptographic profile first

| Operation                                     | Implemented profile                                                                                            |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Compact signed JWS/JWT, local and remote JWKS | RS256, RS384, RS512, ES256 (P-256), ES384 (P-384)                                                              |
| Compact encrypted JWE                         | RSA-OAEP-512 plus A256GCM, one recipient, all headers protected                                                |
| Outside this implementation                   | PS256, ES512, EdDSA, unsecured JWT acceptance, JSON JWS/JWE serialization, compression and critical extensions |

RSA signing keys require the matching SHA-256/384/512 hash and at least 2048 bits;
ECDSA keys require the exact curve and fixed-width raw signatures. JWE requires
an RSA-OAEP/SHA-512 key and explicit `alg` **and** `enc` allowlists. The generic key
and signature APIs support primitives beyond these JOSE profiles. Preserve your
accepted-token contract explicitly; turning acceptance tests into rejection tests
does not demonstrate equivalent behavior.

## Map operations, then choose policy

| jose operation                                              | micro509 operation                                                       | Migration consequence                                                                                                                                                     |
| ----------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new SignJWT(...).sign(key)`                                | `signJwt({ privateKey, algorithm, header, claims })`                     | Functional input; set NumericDates explicitly. Default `typ` is `JWT`.                                                                                                    |
| `jwtVerify(token, key, options)`                            | `verifyJwt(token, options)`                                              | Expected failures are Results; algorithm, type, issuer/audience and key source are explicit.                                                                              |
| `decodeProtectedHeader` / `decodeJwt`                       | `parseCompactJws` / `decodeJwtUnverified`                                | Parse the complete bounded serialization; returned fields remain unauthenticated.                                                                                         |
| `generateKeyPair`, `exportJWK`, `importPKCS8`, `importSPKI` | Existing [key/signing helpers](./jose-integration.md#map-key-operations) | Descriptors select RSA scheme/hash. Helpers take their own typed arguments.                                                                                               |
| Private PEM format dispatch                                 | `importPrivateKeyPem`                                                    | One unencrypted PKCS#1/PKCS#8/SEC1 block; bundles/encrypted input are explicit failures. [Import diagnostics](./keys.md#handle-import-diagnostics) preserve stage/reason. |
| `createLocalJWKSet`                                         | `parseJwks(raw)` then `createJwksKeyResolver`                            | Preserve original text/bytes and reuse the resolver for that trusted snapshot.                                                                                            |
| Already parsed JWK object                                   | `validateJwks(unknown)`                                                  | Owns a bounded JSON-data snapshot; cannot recover duplicate members or invalid original UTF-8.                                                                            |
| `createRemoteJWKSet`                                        | `createRemoteJwksKeyResolver`                                            | Opt-in HTTP lifecycle; use [application-owned cache composition](./jose-cache.md) only when you already own it.                                                           |
| `CompactEncrypt` / `compactDecrypt`                         | `encryptCompactJwe` / `decryptCompactJwe`                                | Both return Results. See the [executable JWE recipe](./jose-jwe.md) for exact key/policy options.                                                                         |
| `base64url.encode` / `decode`                               | `base64UrlEncode` / `base64UrlDecode`                                    | Byte conversion only; decoding returns `undefined` for noncanonical/invalid input.                                                                                        |

The public base64url decoder rejects padding, whitespace, invalid characters,
impossible lengths and nonzero trailing bits. Empty input yields empty bytes.
Encode/decode text explicitly with `TextEncoder`/`TextDecoder`; a successful byte
conversion does not verify a token. [Run the codec example](./jose.md#encode-and-decode-base64url).

| Policy              | jose `jwtVerify`                         | micro509 `verifyJwt`                                                         |
| ------------------- | ---------------------------------------- | ---------------------------------------------------------------------------- |
| Expiration required | Not by default                           | Default `requiredClaims: ['exp']`; an explicit list replaces it.             |
| Future `iat`        | Checked when `maxTokenAge` is configured | Rejected by default; `futureIssuedAt: 'allow'` is an explicit policy choice. |
| Maximum age         | `maxTokenAge`, seconds/duration text     | `maxAgeSeconds`, positive seconds, requiring `iat`.                          |
| Clock               | `currentDate: Date`                      | `claims.now: () => Date`                                                     |
| Clock tolerance     | Seconds/duration text                    | `clockToleranceSeconds`, 0–600 seconds, default 0; applies to exp/nbf/iat.   |
| Issuer/audience     | Optional checks                          | Explicit expectations or explicit `{ unchecked: true }`.                     |
| Token type          | Optional `typ`                           | Explicit `tokenType`, including an explicit unchecked option.                |

Future-iat rejection is the library's default application policy, not a universal
claim that every future timestamp is invalid. Choose the intended policy rather
than silently inheriting another library's defaults.

## Run the migration check here

This LiveCode block verifies actual independently signed corpus tokens with a
fixed clock. The displayed jose verdicts come from the corpus's expected results;
[the consumer test](https://github.com/kjanat/micro509/blob/master/test/jose-migration-fixtures.test.ts)
executes **both libraries**, including the reverse micro509-to-jose direction.
The browser example itself needs only micro509 and the public fixture JSON.

<LiveCode data-output="deterministic">

```ts
import { importPublicJwk } from 'micro509/keys';
import { verifyJwt } from 'micro509/jose';
import { unwrap } from 'micro509/result';

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
const data: unknown = await (
  await fetch(new URL('/fixtures/jose-migration.json', import.meta.url))
).json();
if (
  !record(data) ||
  !record(data.keys) ||
  !record(data.keys.primary) ||
  !Array.isArray(data.cases)
)
  throw new Error('invalid corpus');
const jwk = data.keys.primary;
if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string')
  throw new Error('invalid fixture key');
const key = unwrap(
  await importPublicJwk(
    { kty: 'RSA', n: jwk.n, e: jwk.e },
    { kind: 'rsa', hash: 'SHA-256' },
  ),
);
const fixtures: readonly unknown[] = data.cases;
const options = {
  key,
  algorithms: ['RS256'],
  tokenType: 'JWT',
  claims: {
    issuer: 'https://issuer.example',
    audience: 'api://orders',
    now: () => new Date(1_900_000_000_000),
  },
} as const;
for (const id of [
  'valid-unicode',
  'missing-exp',
  'future-iat',
  'wrong-key',
  'signed-unsupported-PS256',
]) {
  const fixture = fixtures.find((value) => record(value) && value.id === id);
  if (
    !record(fixture) ||
    typeof fixture.token !== 'string' ||
    typeof fixture.micro !== 'string' ||
    typeof fixture.joseAccepts !== 'boolean'
  )
    throw new Error('missing case');
  const result = await verifyJwt(fixture.token, options);
  const verdict = result.ok ? 'ok' : result.code;
  if (verdict !== fixture.micro) throw new Error(`unexpected ${id}`);
  if (result.ok && result.value.claims.name !== 'café 🦊')
    throw new Error('Unicode mismatch');
  console.log(
    id,
    'micro509:',
    verdict,
    'independent jose expectation:',
    fixture.joseAccepts,
  );
  if (id === 'missing-exp' || id === 'future-iat') {
    const explicit = await verifyJwt(fixture.token, {
      ...options,
      claims: {
        ...options.claims,
        ...(id === 'missing-exp'
          ? { requiredClaims: [] }
          : { futureIssuedAt: 'allow' as const }),
      },
    });
    if (!explicit.ok) throw new Error(explicit.code);
    console.log('Explicit policy:', id, 'accepted');
  }
}
```

</LiveCode>

Copy the [independent corpus and consumer recipe](https://github.com/kjanat/micro509/tree/master/examples/jose-migration)
into the migrating application's suite. It includes tampered payload/signature,
wrong-key, issuer/audience and exp/iat/nbf boundaries, malformed encodings,
duplicate JSON, real signed unsupported-algorithm and unsecured-token cases.
The wrong-key fixture uses a separate key; never use a newly micro509-generated
token as your only test of a newly micro509-backed verifier. Both libraries may
use the same WebCrypto provider, so this checks independent JOSE behavior rather
than provider diversity.

## Preserve the authentication and application boundaries

Use `decodeJwtUnverified` only to look up an exact entry in configured trust.
Do not derive trusted URLs or accepted algorithms from token fields. Verify the
original token and pass **verified** `result.value.claims` into a runtime schema;
never return a payload separately decoded with `atob`. Run the complete
[Unicode/schema integration recipe](./jose-integration.md#route-to-configured-trust-then-validate-verified-claims).

Decoding checks serialization/JSON without validating registered-claim types:
`exp: 'not-a-number'` or `iss: 123` can decode but will fail `verifyJwt` as
`invalid_claim`. Unknown critical headers, duplicate members, noncanonical
base64url, invalid UTF-8, unencoded/detached JWS and nested JWTs have deliberate
refusals. JWE returns plaintext bytes and authenticated headers; it does not
establish sender identity or validate a nested JWT.

Verification/import/JWE failures are Results. Handle stable codes such as
`missing_claim`, `issuer_mismatch`, `audience_mismatch`, `expired`,
`issued_in_future`, `key_not_found` and JWE `decryption_failed`, rather than
message text. `signJwt`/`signCompactJws` take developer construction input and
throw coded `ResultError` exceptions for invalid signing configuration. Ordinary
key-import stage/reason details survive both Results and OrThrow/unwrap.

Default JOSE bounds are 32,768 token characters, 4,096 header bytes, 16,384
payload bytes, 1,024 signature/encrypted-CEK bytes, JSON depth 16 and 2,048 nodes.
JWKS has separate bounds. Preserve raw JWKS text in durable storage, keep local
resolvers per trusted source/snapshot, and replace them when keys rotate or are
removed; [the cache recipe](./jose-cache.md) makes those lifetimes executable.
