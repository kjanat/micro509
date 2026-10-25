---
outline: [2, 3]
---

# JOSE

`micro509/jose` signs and verifies compact JWS and JWT with RS256, resolves
keys from a JWK Set, and optionally reads that set from a trusted URL. It uses
WebCrypto only and has no runtime dependencies. Importing it makes no network
request.

Supported: compact serialization, `RS256`, RSA keys of at least 2048 bits. Not
supported: JWE, JSON serialization, nested JWTs, `b64: false`, detached
payloads, `crit` extensions, `none`, HMAC and the other JWS algorithms.

## Sign and verify a JWT

`verifyJwt` needs three explicit policies: the algorithms to accept, the token
type, and the claims. Nothing is read from the token to decide them.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509/keys';
import { signJwt, verifyJwt } from 'micro509/jose';

const keys = await generateKeyPair({ kind: 'rsa' });
const now = Math.floor(Date.now() / 1000);

const token = await signJwt({
  privateKey: keys.privateKey,
  algorithm: 'RS256',
  header: { kid: 'demo-1' },
  claims: {
    iss: 'https://issuer.example',
    aud: 'api://orders',
    exp: now + 300,
  },
});

const result = await verifyJwt(token, {
  algorithms: ['RS256'],
  key: keys.publicKey,
  tokenType: 'JWT',
  claims: { issuer: 'https://issuer.example', audience: 'api://orders' },
});

if (!result.ok) throw new Error(result.code);
console.log(`\
token:  ${token}
kid:    ${result.value.header.kid}
claims: ${JSON.stringify(result.value.claims)}`);
```

</LiveCode>

`VerifiedJwt` carries `verified: true`, the protected header, every claim and the
validated `registered` claims. `decodeJwtUnverified` returns an `UnverifiedJwt`
with `verified: false`. Use it only to route a token before verifying it.

### Claims policy

| Option                  | Meaning                                                                   |
| ----------------------- | ------------------------------------------------------------------------- |
| `issuer`                | Required. A string, an array of accepted values, or `{ unchecked: true }` |
| `audience`              | Required. Any listed value may match. `{ unchecked: true }` skips it      |
| `requiredClaims`        | Claims that must be present. Default `['exp']`                            |
| `now`                   | Clock returning a `Date`. Default is the system time                      |
| `clockToleranceSeconds` | 0 to 600, applied to `exp`, `nbf` and `iat`. Default 0                    |
| `maxAgeSeconds`         | Oldest accepted age from `iat`. Requires `iat`                            |
| `futureIssuedAt`        | `'reject'` (default) or `'allow'` for an `iat` after the clock            |

Time claims must be JSON numbers. Strings are never coerced. A token is expired
when the clock is at or after `exp` and not yet valid before `nbf`
(RFC 7519 §4.1.4, §4.1.5). Application authorization stays with the caller.

### Token types

`tokenType` is a media type compared case-insensitively with `application/`
restored (RFC 7515 §4.1.9), `{ absent: true }`, or `{ unchecked: true }`. Use
one profile per token use, for example `'at+jwt'` for access tokens and `'JWT'`
for ID tokens, so a token of one kind is refused where another is expected
(RFC 8725 §3.11, §3.12).

## Strict parsing

Compact JWS requires exactly three canonical base64url segments and a UTF-8
JSON header without duplicate member names. Its payload is bytes. JWT also
requires a UTF-8 JSON payload without duplicate member names. Header and payload sizes, JSON depth and JSON size are bounded by
`JoseLimits`. Override them with `limits`. Each limit must be a positive safe
integer (`maxJsonDepth` at most 64), otherwise the call returns
`invalid_options`. Failures carry a stable code and never contain the token.

`verifyJwt` and `verifyCompactJws` copy their options, including the claims
policy, before the first `await`. A key resolver that throws, or returns
something other than a resolution, yields `key_resolution_failed` and its
message is never reported. The claims clock must return a valid `Date`.
Otherwise the call returns `invalid_options`.

## Local JWK Sets

<LiveCode>

```ts
import { exportPublicJwk, generateKeyPair } from 'micro509/keys';
import {
  createJwksKeyResolver,
  parseJwks,
  signCompactJws,
  verifyCompactJws,
} from 'micro509/jose';

const current = await generateKeyPair({ kind: 'rsa' });
const retired = await generateKeyPair({ kind: 'rsa' });

const jwks = parseJwks(
  JSON.stringify({
    keys: [
      {
        ...(await exportPublicJwk(current.publicKey)),
        kid: 'current',
        use: 'sig',
      },
      {
        ...(await exportPublicJwk(retired.publicKey)),
        kid: 'retired',
        use: 'sig',
      },
    ],
  }),
);
if (!jwks.ok) throw new Error(jwks.code);

const key = createJwksKeyResolver(jwks.value);
const payload = new TextEncoder().encode('hello');

for (const kid of ['current', 'unknown']) {
  const token = await signCompactJws({
    privateKey: current.privateKey,
    algorithm: 'RS256',
    payload,
    header: { kid },
  });
  const result = await verifyCompactJws(token, {
    algorithms: ['RS256'],
    key,
    tokenType: { absent: true },
  });
  console.log('Token:', token);
  console.log('Verification result:', result);
  if (result.ok) {
    console.log(
      'Verified payload:',
      new TextDecoder().decode(result.value.payload),
    );
  }
}
```

</LiveCode>

Selection filters by `kid`, key type, `use`, `key_ops`, `alg` and RSA
parameters. Zero matches is `key_not_found`, matches that all fail the other
checks is `key_unsuitable`, and several matches is `ambiguous_key`. A token
without `kid` therefore verifies only against a set with one usable key. Entries
this module does not use stay in the parsed set as `unsupported` and are never
selected (RFC 7517 §5). Every entry and the document expose all their members in
`members`, including `x5c` and key material the module does not read. `jku`, `x5u`, `jwk` and `x5c` headers are ignored.

Pass your own function as `key` to resolve keys another way. It receives the
unauthenticated header, the admitted algorithm and the `kid`.

## Remote JWK Sets

```ts
import { createRemoteJwksKeyResolver, verifyJwt } from 'micro509/jose';

const key = createRemoteJwksKeyResolver({
  url: 'https://issuer.example/.well-known/jwks.json',
});

const result = await verifyJwt(token, {
  algorithms: ['RS256'],
  key,
  tokenType: 'JWT',
  claims: { issuer: 'https://issuer.example', audience: 'api://orders' },
  signal: AbortSignal.timeout(10_000),
});
```

The URL comes from your configuration and must be `https`, or `http` on a
loopback host. Create one resolver per issuer. Each has its own cache.

| Behaviour           | Rule                                                                                                                                                                                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First use           | Fetches the set. Nothing is requested before                                                                                                                                                                                                            |
| Freshness           | Lifetime from `Cache-Control: max-age`, else `Expires`, else `defaultTtlMs` (10 min), less the response age (`Date`, `Age`, transit delay), capped at `maxTtlMs`. `no-store` and `no-cache` leave none: the set serves the verification that fetched it |
| Expired set         | Never reused, including when the refresh fails                                                                                                                                                                                                          |
| Cooldown            | After a fetch starts, the next one waits `cooldownMs` (30 s). A token whose set is not fresh then gets `jwks_unavailable`, an unknown `kid` gets `key_not_found`. Unknown values are never cached                                                       |
| Failed fetch        | Counts as an attempt. A still-fresh set stays usable                                                                                                                                                                                                    |
| Concurrent requests | Share one fetch. Cancelling the last waiter aborts it                                                                                                                                                                                                   |
| Rotation            | A refresh replaces the whole set, so a removed key stops verifying at the next refresh. Rotate to a new `kid`                                                                                                                                           |
| Bounds              | `timeoutMs` (5 s, whole response, enforced even if the transport ignores the abort signal), `maxResponseBytes` (64 KiB, enforced while streaming), `maxKeys` (32)                                                                                       |
| Redirects           | Refused unless `redirects.maxRedirects` is set. Each hop must be `https` or loopback, carry no credentials, and pass `redirects.allow` (default same origin)                                                                                            |
| Headers             | `headers` go only to the configured origin                                                                                                                                                                                                              |
| Transport           | `transport` replaces `fetch` for proxies, egress control or fixtures                                                                                                                                                                                    |

DNS answers and the addresses a hostname resolves to are not visible to this
module. Enforce egress rules in the transport or the network. Browsers hide
redirect targets, so redirects fail there.

## Errors

Verification returns `{ ok: false, code, message, details? }`. `details` holds
names and short identifiers such as `alg`, `kid`, `claim`, `crit` and `status`.

| Code                                                                                     | Meaning                                           |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `token_too_large`, `malformed_token`                                                     | Size or segment structure                         |
| `invalid_encoding`, `invalid_utf8`, `invalid_json`, `duplicate_member`                   | Segment content                                   |
| `limit_exceeded`                                                                         | A configured size, depth or node bound            |
| `invalid_header`, `invalid_payload`                                                      | Header or payload is not the required JSON object |
| `unsupported_critical_header`, `unsupported_unencoded_payload`, `unsupported_nested_jwt` | Features outside the supported profile            |
| `invalid_options`                                                                        | Unusable verification options                     |
| `unsigned_token`, `algorithm_not_allowed`, `token_type_mismatch`                         | Policy refusals before any key is used            |
| `key_not_found`, `ambiguous_key`, `key_unsuitable`, `key_resolution_failed`              | Key selection and resolver failures               |
| `jwks_unavailable`, `jwks_malformed`, `aborted`                                          | Remote JWK Set retrieval                          |
| `invalid_signature`                                                                      | Signature does not verify                         |
| `missing_claim`, `invalid_claim`, `issuer_mismatch`, `audience_mismatch`                 | Claims                                            |
| `expired`, `not_yet_valid`, `issued_in_future`, `token_too_old`                          | Time claims                                       |

Signing and resolver construction throw a `ResultError` (see `isResultError`)
with codes `unsupported_algorithm`, `incompatible_key`, `invalid_header`,
`invalid_claims` and `invalid_remote_jwks_config`.
