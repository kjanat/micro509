---
sidebarTitle: JWT application recipes
outline: [2, 3]
---

# JWT keys, signing and application claims

Use the existing key helpers directly; JOSE does not require a fluent compatibility
class, a duration-string parser or another `crypto.subtle` key wrapper. For API
behavioral differences, use the migration guide; for encrypted state, see
[compact JWE](./jose-jwe.md).

## Map key operations

| jose operation              | Existing micro509 operation                                                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `generateKeyPair('RS256')`  | [`generateKeyPair({ kind: 'rsa', scheme: 'pkcs1-v1_5', hash: 'SHA-256' })`](../api/fn/generateKeyPair)                                                     |
| `exportJWK(key)`            | [`exportPublicJwk(publicKey)`](../api/fn/exportPublicJwk), [`exportPrivateJwk(privateKey)`](../api/fn/exportPrivateJwk), or the pair's convenience methods |
| `importPKCS8(pem, 'RS256')` | [`importPkcs8Pem(pem, descriptor)`](../api/fn/importPkcs8Pem); [`importPrivateKeyPem`](../api/fn/importPrivateKeyPem) also dispatches PKCS#1/SEC1 labels   |
| `importSPKI(pem, 'RS256')`  | [`importSpkiPem(pem, descriptor)`](../api/fn/importSpkiPem)                                                                                                |
| Private/public PEM export   | [`exportPkcs8Pem`](../api/fn/exportPkcs8Pem), [`exportPkcs1Pem`](../api/fn/exportPkcs1Pem), [`exportSpkiPem`](../api/fn/exportSpkiPem)                     |

RS256 means RSA, PKCS#1 v1.5 **signature** padding and SHA-256. JOSE requires at
least 2048-bit RSA here. `rsaEncryption` PEM does not bind the scheme/hash;
use an explicit descriptor for other profiles. General key generation/import
also supports primitives beyond the [implemented JOSE profiles](../reference/algorithms.md#jose-signatures).

## Generate, export, import and sign functionally

This uses a fixed clock for reproducibility. In production inject a clock and
compute NumericDates explicitly in **seconds**. `signJwt` defaults `typ` to `JWT`;
it inserts no `iat`, `nbf` or `exp`. Signing throws coded configuration errors;
verification and key import return Results.

<LiveCode>

```ts
import {
  generateKeyPair,
  exportPkcs1Pem,
  exportPkcs8Pem,
  exportPublicJwk,
  importPrivateKeyPem,
  importSpkiPem,
} from 'micro509/keys';
import { signJwt, verifyJwt } from 'micro509/jose';
import { unwrap } from 'micro509/result';

const descriptor = {
  kind: 'rsa',
  scheme: 'pkcs1-v1_5',
  hash: 'SHA-256',
} as const;
// Suite-scoped fixtures may reuse this pair; a wrong-key test needs a different pair.
const primary = await generateKeyPair(descriptor);
const secondary = await generateKeyPair(descriptor);
const publicJwk = {
  ...(await exportPublicJwk(primary.publicKey)),
  kid: 'key-1',
  use: 'sig',
  alg: 'RS256',
};
const pkcs8 = await exportPkcs8Pem(primary.privateKey);
const pkcs1 = await exportPkcs1Pem(primary.privateKey);
const privateKey = unwrap(await importPrivateKeyPem(pkcs1, descriptor));
const samePrivateKey = unwrap(await importPrivateKeyPem(pkcs8, descriptor));
const publicKey = unwrap(
  await importSpkiPem(await primary.exportSpkiPem(), descriptor),
);
const clock = () => 1_900_000_000;
const iat = clock();
const token = await signJwt({
  privateKey,
  algorithm: 'RS256',
  header: { kid: publicJwk.kid },
  claims: {
    iss: 'https://issuer.example',
    aud: 'api://orders',
    iat,
    nbf: iat,
    exp: iat + 300,
  },
});
const options = {
  key: publicKey,
  algorithms: ['RS256'],
  tokenType: 'JWT',
  claims: {
    issuer: 'https://issuer.example',
    audience: 'api://orders',
    now: () => new Date(clock() * 1000),
  },
} as const;
const verified = unwrap(await verifyJwt(token, options));
if (verified.header.typ !== 'JWT') throw new Error('unexpected typ');
const wrong = await verifyJwt(token, { ...options, key: secondary.publicKey });
if (wrong.ok || wrong.code !== 'invalid_signature')
  throw new Error('wrong key accepted');
console.log('Public JWK:', JSON.stringify(publicJwk));
console.log('JWT:', token);
console.log(
  'PKCS8 import:',
  samePrivateKey.algorithm.name,
  'wrong key:',
  wrong.code,
);
```

</LiveCode>

This fixture-key reuse belongs to the suite, not to a global production cache.
Keep a separate secondary key, and retain the
[independent migration corpus](https://github.com/kjanat/micro509/tree/master/examples/jose-migration)
so replacing both signer and verifier cannot hide integration regressions.

## Route to configured trust, then validate verified claims

Unverified decoding can suggest an issuer lookup. The lookup must be exact and
must select preconfigured algorithms, issuer/audience/type and key source.
Never construct a JWKS URL from token `iss`, `jku` or `x5u`. Pass the **original
compact token** into `verifyJwt`, and only pass `result.value.claims` to the
application schema. `JSON.parse(atob(payload))` corrupts Unicode and duplicates
an unauthenticated decoding boundary.

This runnable example reads the independently signed synthetic corpus; its fixture
loader also checks the JSON shape without a cast. The schema validator checks
missing/mistyped custom claims at runtime. Generic type arguments alone do not.

<LiveCode data-output="deterministic">

```ts
import type { JsonObject, VerifyJwtErrorCode } from 'micro509/jose';
import { decodeJwtUnverified, verifyJwt } from 'micro509/jose';
import { importPublicJwk } from 'micro509/keys';
import { unwrap } from 'micro509/result';

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
const source: unknown = await (
  await fetch(new URL('/fixtures/jose-migration.json', import.meta.url))
).json();
if (
  !record(source) ||
  !record(source.keys) ||
  !record(source.keys.primary) ||
  !Array.isArray(source.cases)
)
  throw new Error('invalid corpus');
const publicJwk = source.keys.primary;
if (
  publicJwk.kty !== 'RSA' ||
  typeof publicJwk.n !== 'string' ||
  typeof publicJwk.e !== 'string'
)
  throw new Error('invalid fixture key');
const entries: readonly unknown[] = source.cases;
function token(id: string): string {
  const entry = entries.find((value) => record(value) && value.id === id);
  if (!record(entry) || typeof entry.token !== 'string')
    throw new Error('missing fixture');
  return entry.token;
}
const publicKey = unwrap(
  await importPublicJwk(
    { kty: 'RSA', n: publicJwk.n, e: publicJwk.e },
    { kind: 'rsa', hash: 'SHA-256' },
  ),
);
const trusted = new Map([
  [
    'https://issuer.example',
    {
      issuer: 'https://issuer.example',
      audience: 'api://orders',
      key: publicKey,
      algorithms: ['RS256'] as const,
      tokenType: 'JWT',
    },
  ],
]);
interface AppClaims {
  readonly name: string;
  readonly roles: readonly string[];
}
function applicationClaims(claims: JsonObject): AppClaims | undefined {
  if (typeof claims.name !== 'string' || !Array.isArray(claims.roles))
    return undefined;
  const roles: string[] = [];
  for (const role of claims.roles) {
    if (typeof role !== 'string') return undefined;
    roles.push(role);
  }
  return { name: claims.name, roles };
}
type Authentication =
  | { readonly ok: true; readonly claims: AppClaims }
  | {
      readonly ok: false;
      readonly reason:
        | VerifyJwtErrorCode
        | 'untrusted_issuer'
        | 'application_schema';
    };
async function authenticate(compact: string): Promise<Authentication> {
  const candidate = decodeJwtUnverified(compact);
  if (!candidate.ok) return { ok: false, reason: candidate.code };
  const issuer = candidate.value.claims.iss;
  const config = typeof issuer === 'string' ? trusted.get(issuer) : undefined;
  if (config === undefined) return { ok: false, reason: 'untrusted_issuer' };
  const verified = await verifyJwt(compact, {
    key: config.key,
    algorithms: config.algorithms,
    tokenType: config.tokenType,
    claims: {
      issuer: config.issuer,
      audience: config.audience,
      now: () => new Date(1_900_000_000_000),
    },
  });
  if (!verified.ok) return { ok: false, reason: verified.code };
  const claims = applicationClaims(verified.value.claims);
  return claims === undefined
    ? { ok: false, reason: 'application_schema' }
    : { ok: true, claims };
}
const valid = await authenticate(token('valid-unicode'));
if (!valid.ok || valid.claims.name !== 'café 🦊')
  throw new Error('Unicode/schema regression');
console.log('Verified application name:', valid.claims.name);
for (const [id, expected] of [
  ['invalid-base64url', 'invalid_encoding'],
  ['untrusted-issuer', 'untrusted_issuer'],
  ['wrong-key', 'invalid_signature'],
  ['tampered-signature', 'invalid_signature'],
  ['schema-missing-roles', 'application_schema'],
  ['schema-mistyped-roles', 'application_schema'],
] as const) {
  const result = await authenticate(token(id));
  if (result.ok || result.reason !== expected)
    throw new Error(`unexpected ${id}`);
  console.log(id, result.reason);
}
```

</LiveCode>

Cryptographic and registered-claim verification establish authenticity for the
configured issuer; the application schema establishes usable field types.
Authorization still decides whether this identity and its roles may perform a
particular operation. For multiple configured issuers, use separate trust/source
entries and [cache resolver snapshots](./jose-cache.md) by that configured identity.
