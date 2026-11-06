---
sidebarTitle: JWTs and JWKS
outline: [2, 3]
---

# Sign and verify JWTs

Use `micro509/jose` to sign JWTs with RS256, RS384, RS512, ES256 and ES384 and verify their signatures, issuer,
audience and expiry. Verification accepts a public `CryptoKey`, a local JWK Set
(JWKS), or a resolver that fetches an issuer's JWKS.

A JWT carries JSON claims. Its JWS signature covers the encoded header and claims.
A JWKS is a JSON document of public keys, usually identified by a `kid`.
Successful verification returns the authenticated claims for your application to
use in its authorization decisions.

## Choose your verification inputs

Supply these values from your application's configuration:

| Input              | Example                                        | Purpose                                                     |
| ------------------ | ---------------------------------------------- | ----------------------------------------------------------- |
| Allowed algorithms | `['RS256']`                                    | Restricts the accepted signature algorithm.                 |
| Issuer             | `https://issuer.example`                       | Identifies the issuer you expect.                           |
| Audience           | `api://orders`                                 | Identifies the application the token is intended for.       |
| Token type         | `'JWT'` or `'at+jwt'`                          | Selects the token profile accepted by this application.     |
| Key source         | Public key, local JWKS, or configured JWKS URL | Supplies the key trusted to verify that issuer's signature. |

The token's `alg`, `iss` and key-location headers do not choose these settings.
Use the token profile specified by your issuer. Distinct token uses may need
separate types, audiences and claim policies even when they share signing keys.

## Verify the same JWT three ways

This runnable example signs one demo token, prints the token and public JWKS,
and verifies it with each key source. The header's `kid: 'demo-1'` selects the
matching entry in the JWKS. All three paths apply the same issuer, audience,
token type and expiry checks.

For the remote-resolver path, a small custom transport serves the demo JWKS as
an HTTP `Response` in memory. This makes the complete example runnable here
without an external issuer. The resolver still performs key selection, caching
and real signature verification. [Connecting to your issuer](#connect-to-your-issuer)
explains how to use its HTTPS endpoint.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509/keys';
import {
  createJwksKeyResolver,
  createRemoteJwksKeyResolver,
  parseJwks,
  signJwt,
  verifyJwt,
} from 'micro509/jose';

const keys = await generateKeyPair({ kind: 'rsa' });
const issuer = 'https://issuer.example';
const audience = 'api://orders';
const now = Math.floor(Date.now() / 1000);
const token = await signJwt({
  privateKey: keys.privateKey,
  algorithm: 'RS256',
  header: { kid: 'demo-1' },
  claims: { iss: issuer, aud: audience, sub: 'demo-user', exp: now + 300 },
});
const publicJwks = {
  keys: [
    {
      ...(await keys.exportPublicJwk()),
      kid: 'demo-1',
      use: 'sig',
      alg: 'RS256',
    },
  ],
};
console.log('JWT:', token);
console.log('Public JWKS:\n' + JSON.stringify(publicJwks, null, 2));

const parsed = parseJwks(JSON.stringify(publicJwks));
if (!parsed.ok) throw new Error(parsed.code);
const local = createJwksKeyResolver(parsed.value);
let requests = 0;
const remote = createRemoteJwksKeyResolver({
  url: `${issuer}/.well-known/jwks.json`,
  // Demo transport. Omit this property to fetch a real issuer's HTTPS URL.
  transport: async (url) => {
    requests++;
    console.log('JWKS request:', url);
    return new Response(JSON.stringify(publicJwks), {
      headers: {
        'content-type': 'application/json',
        'cache-control': 'max-age=300',
      },
    });
  },
});

const policy = {
  algorithms: ['RS256'],
  tokenType: 'JWT',
  claims: { issuer, audience },
} as const;
for (const [label, key] of [
  ['Direct key', keys.publicKey],
  ['Local JWKS', local],
  ['Remote JWKS', remote],
] as const) {
  const result = await verifyJwt(token, { ...policy, key });
  console.log(label, result);
  if (!result.ok) throw new Error(`${label}: ${result.code}`);
  console.log(`${label} claims:`, result.value.claims);
}

// Reuse the resolver for subsequent requests to use its cached JWKS.
console.log(
  'Cached verification:',
  await verifyJwt(token, { ...policy, key: remote }),
);
console.log('JWKS requests after two remote verifications:', requests);

// A valid signature does not make this token valid for a different audience.
const rejected = await verifyJwt(token, {
  ...policy,
  key: remote,
  claims: { issuer, audience: 'api://another-service' },
});
console.log('Wrong audience (expected audience_mismatch):', rejected);
```

</LiveCode>

The three successful results should contain the same `sub`, `iss`, `aud` and
`exp` claims. Two verifications through the remote resolver should make one JWKS
request. The final result should be `audience_mismatch`, despite using the same
token and signing key.

`result.value.claims` contains all claims. `result.value.registered` contains
the validated registered claims, and `result.value.header` contains the protected
header. `decodeJwtUnverified` only reads a token's contents. Use `verifyJwt` before
acting on those claims.

## Connect to your issuer

Configure one `createRemoteJwksKeyResolver` per issuer at application startup.
Use the issuer's documented JWKS URL and omit the demo's `transport` property.
The resolver uses `fetch`. Pass the received compact JWT string to `verifyJwt`
with that resolver as `key`, as in the example above.

For an HTTP API, obtain the token from the request's `Authorization: Bearer …`
header. Your issuer and audience come from configuration. Reuse the resolver
across requests so its key cache and refresh cooldown can work.

| Situation                                 | Resolver behavior                                                                 |
| ----------------------------------------- | --------------------------------------------------------------------------------- |
| First verification                        | Fetches the JWKS when verification reaches key resolution.                        |
| Another request within freshness lifetime | Uses the cached set.                                                              |
| Unknown `kid`                             | Attempts a refresh if the cooldown permits it. Otherwise returns `key_not_found`. |
| Expired cached set                        | Requires a refresh. If it cannot fetch a fresh set, returns `jwks_unavailable`.   |
| Key rotation                              | A refresh replaces the set. Publish a new key with a new `kid`.                   |

The default fetch deadline is 5 seconds, response limit is 64 KiB, key limit is
32, and refresh cooldown is 30 seconds. The cooldown suppresses new fetches,
so a request can fail during that interval. It does not wait for a scheduled retry.
Pass `signal: AbortSignal.timeout(10_000)` to `verifyJwt` to bound how long a
particular caller waits.

<details>
<summary>HTTP caching, redirects and custom transports</summary>

Freshness follows `Cache-Control: max-age`, then `Expires`, then `defaultTtlMs`
(10 minutes). Response age is subtracted and the result is capped at `maxTtlMs`
(24 hours). A `no-store` or `no-cache` response serves the verification that fetched
it and supplies no fresh cached set for later calls. An expired set is never used
after a failed refresh.

Fetches use `cache: 'no-store'` so the resolver's refresh reaches the issuer even
when a browser HTTP cache would consider its response fresh. Custom transports
must honor that mode. Concurrent callers share one fetch. Cancelling the last
waiter aborts it.

URLs must use HTTPS, or HTTP on loopback. Redirects are refused by default.
Explicitly allowed redirects must satisfy the scheme and destination policy.
Browsers hide manual redirect targets, so they cannot follow this redirect path.
Configured headers are sent only to the original origin. Use `transport` for
proxies or network egress rules, including DNS/address restrictions.

See [`RemoteJwksConfig`](../api/jose.md) for the full configuration surface.

</details>

## Handle rejected tokens

A JOSE verification failure has `result.code` at the top level:
`{ ok: false, code, message, details? }`. The examples print that result so you can
inspect the code and details. In an application, handle the relevant category:

| Codes                                                           | Application response                                                           |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `expired`, `not_yet_valid`, `issued_in_future`, `token_too_old` | Reject the token under the configured time policy.                             |
| `issuer_mismatch`, `audience_mismatch`, `token_type_mismatch`   | Reject a token for a different issuer, application or token profile.           |
| `invalid_signature`, malformed-token codes                      | Reject the token.                                                              |
| `key_not_found`, `key_unsuitable`, `ambiguous_key`              | Check the issuer's key publication and your key-selection configuration.       |
| `jwks_unavailable`, `jwks_malformed`, `aborted`                 | Handle the key-source failure or cancellation. Verification has not succeeded. |
| `invalid_options`                                               | Fix your application's verification settings.                                  |

Use [JOSE error codes](../reference/errors.md#joseerrorcode) for the complete list.
Signing and resolver construction throw a `ResultError` for invalid configuration.

## Adjust claims policy

`exp` is required by default. Present `exp`, `nbf` and `iat` values must be JSON
numbers. Expiry is reached when the verification time is at or after `exp`.

| Option in `claims`      | Default and use                                                                              |
| ----------------------- | -------------------------------------------------------------------------------------------- |
| `issuer`, `audience`    | Required. Accept a configured string or list of strings.                                     |
| `requiredClaims`        | `['exp']`. Add claims your token profile requires. Supplying a list replaces this default.   |
| `clockToleranceSeconds` | `0`. Accepts 0–600 seconds for time checks.                                                  |
| `maxAgeSeconds`         | Omitted. When supplied, also requires `iat`.                                                 |
| `futureIssuedAt`        | `'reject'`. Use `'allow'` only when your token profile permits it.                           |
| `now`                   | Current time. Supply a function returning a valid `Date` for a controlled verification time. |

The API also exposes `{ unchecked: true }` for issuer, audience and token-type
policies when an application deliberately delegates those checks. The examples
use explicit expected values. `tokenType: { absent: true }` requires the `typ`
header to be absent.

## Sign and verify raw JWS data

Use compact JWS for a signed byte payload. This separate API verifies the signature
and header policy. It does not apply JWT claim checks to the payload.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509/keys';
import { signCompactJws, verifyCompactJws } from 'micro509/jose';

const keys = await generateKeyPair({ kind: 'rsa' });
const token = await signCompactJws({
  privateKey: keys.privateKey,
  algorithm: 'RS256',
  payload: new TextEncoder().encode('Order 42: ready to ship'),
});
const result = await verifyCompactJws(token, {
  algorithms: ['RS256'],
  key: keys.publicKey,
  tokenType: { absent: true },
});
console.log('Compact JWS:', token);
console.log('Verification:', result);
if (result.ok)
  console.log('Payload:', new TextDecoder().decode(result.value.payload));
```

</LiveCode>

## Validate an already parsed JWKS

Use `parseJwks(rawTextOrBytes)` for keys received over a transport: it rejects duplicate
JSON members and invalid UTF-8 before information is lost. Use `validateJwks(value)`
when a trusted integration already supplies a JavaScript object. Both produce the
same `Jwks` representation for `createJwksKeyResolver`.

Object validation copies plain JSON data, without invoking getters or `toJSON`.
It rejects cycles, custom prototypes, accessors, sparse arrays and non-JSON values.
The copy is detached from subsequent input mutations. Depth, node and key-count
bounds still apply; `maxBytes` measures the compact JSON data's UTF-8 spelling,
not the lost original response size. An object cannot reveal duplicate members
that `JSON.parse` already discarded. Keep raw bytes when that check matters.

<LiveCode data-output="deterministic">

```ts
import { parseJwks, validateJwks } from 'micro509/jose';

const original = { keys: [{ kty: 'oct', k: 'AA', kid: 'inspection-only' }] };
const checked = validateJwks(original);
if (!checked.ok) throw new Error(checked.code);
original.keys.length = 0;
if (checked.value.keys.length !== 1) throw new Error('snapshot changed');
console.log('Owned snapshot keys:', checked.value.keys.length);
const duplicate = '{"keys":[],"keys":[]}';
if (parseJwks(duplicate).ok) throw new Error('duplicate accepted');
console.log(
  'Duplicate lost by JSON.parse:',
  validateJwks(JSON.parse(duplicate)).ok,
);
```

</LiveCode>

## Encode and decode base64url

`base64UrlEncode(bytes)` produces canonical unpadded base64url.
`base64UrlDecode(text)` returns bytes, or `undefined` for padding, whitespace,
invalid characters, impossible lengths or nonzero trailing bits. Empty input
round-trips as an empty string/array. These are byte codecs, not UTF-8 decoders
or token verification; use `TextEncoder`/`TextDecoder` explicitly for text.

<LiveCode>

```ts
import { base64UrlEncode, base64UrlDecode } from 'micro509/jose';

const bytes = crypto.getRandomValues(new Uint8Array(32));
const encoded = base64UrlEncode(bytes);
const decoded = base64UrlDecode(encoded);
console.log('URL-safe:', encoded);
console.log('Round-trip bytes:', decoded?.length);
console.log('Padding rejected:', base64UrlDecode(encoded + '=') === undefined);
```

</LiveCode>

## Choose an algorithm and matching key

The algorithm is explicit when signing, and the verifier accepts only its caller's
non-empty `algorithms` list. Adding library support does not expand an existing
`['RS256']` policy. RSA keys are bound to their hash at generation/import; an
RS256 key cannot be reused for RS384 by changing only the token option.

| Algorithm | Key                     | Hash    | Signature encoding   |
| --------- | ----------------------- | ------- | -------------------- |
| RS256     | RSA, at least 2048 bits | SHA-256 | RSA signature octets |
| RS384     | RSA, at least 2048 bits | SHA-384 | RSA signature octets |
| RS512     | RSA, at least 2048 bits | SHA-512 | RSA signature octets |
| ES256     | ECDSA P-256             | SHA-256 | 64-byte raw R \|\| S |
| ES384     | ECDSA P-384             | SHA-384 | 96-byte raw R \|\| S |

These profiles follow [RFC 7518 §§3.3–3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3).
ECDSA JWS signatures never use ASN.1 DER or the generic verifier's encoding retry.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509/keys';
import { signJwt, verifyJwt } from 'micro509/jose';

const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
const token = await signJwt({
  algorithm: 'ES256',
  privateKey: keys.privateKey,
  claims: {
    iss: 'https://issuer.example',
    aud: 'orders',
    exp: Math.floor(Date.now() / 1000) + 300,
  },
});
const result = await verifyJwt(token, {
  algorithms: ['ES256'],
  key: keys.publicKey,
  tokenType: 'JWT',
  claims: { issuer: 'https://issuer.example', audience: 'orders' },
});
console.log('ES256 token:', token);
console.log('Verified:', result.ok);
```

</LiveCode>

Local and remote JWKS resolvers select RSA or EC keys by the admitted algorithm,
`kid`, `alg`, `use` and `key_ops`. EC JWKs need `crv` and full-width `x` and `y`;
compressed points are unsupported. Off-curve points are excluded before ambiguity
checks. Resolvers keep imports separate for each
algorithm, even when RSA key material is shared. Reuse a resolver across calls.
When importing a selected entry yourself, pass its admitted algorithm to
`importJwkEntry(entry, 'ES256')`; the omitted-argument default remains RS256.
An incompatible key yields `key_unsuitable`, a refused algorithm yields
`algorithm_not_allowed`, and a failed signature yields `invalid_signature`.
Signing input errors throw coded `ResultError`s as documented above.

## Supported formats

The module implements compact JWS and JWT with RS256/384/512 and ES256/384. JWE, JSON JWS serialization, nested JWTs, detached or unencoded
payloads, critical-header extensions and other signature algorithms are unsupported.
Parsing checks canonical base64url, UTF-8, duplicate JSON members and size/depth
limits. Configure these bounds through [`JoseLimits`](../api/jose.md).

Continue with the [JOSE API reference](../api/jose.md),
[public-key import](./keys.md#import-and-export), or
[certificate-chain verification](./verification.md) for X.509 trust validation.
