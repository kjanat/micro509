---
sidebarTitle: Application JWKS caches
outline: [2, 3]
---

# Verify with an application-owned JWKS cache

Use `createRemoteJwksKeyResolver` when micro509 should own HTTP freshness,
coalescing, cooldown and conditional requests. This recipe is for an application
that **already** owns its KV/database/origin refresh service. It composes that
service with `parseJwks` and `createJwksKeyResolver`; it does not reimplement HTTP.

Keep original response text/bytes in the shared cache. Parse those bytes before
creating a resolver: `JSON.stringify(JSON.parse(raw))` cannot recover duplicate
members. Legacy object entries may use `validateJwks`, with its explicitly weaker
lexical guarantees. Never serialize imported `CryptoKey` objects into arbitrary KV.

## Keep two cache layers

| Layer                    | Contents and lifetime                                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Application shared cache | Original JWKS text/bytes plus authoritative expiry; your existing service refreshes it from a configured source.      |
| Process/worker isolate   | Validated set, resolver and its imported CryptoKeys for the current source snapshot. Reused within this isolate only. |

This example has a two-entry LRU, a 60-second local maximum age, a one-second
unknown-kid refresh cooldown, single-flight refreshes, and explicit invalidation.
Trust comes from a bounded static configuration keyed by issuer **and configured
source identity**, never from `kid` or a token-supplied URL. Replace the resolver
when the raw snapshot changes; removed keys disappear with it. A failed refresh
fails closed and discards the local snapshot; expired shared data is not reused.
Invalidation also prevents an older in-flight load from reinstalling its snapshot.
A verification already underway can finish under the snapshot it acquired.

The `readRaw(config, force)` adapter must preserve raw bytes and, when `force` is
true, ask the application's refresh service to bypass its old shared entry. Its
expiry must reflect authoritative freshness, not the time an old KV value was
read. Production adapters also bound transport time, response bytes and parallel
origin work; the library parser independently bounds document/key size.

## Execute the cache lifecycle

The in-memory raw store here is a controlled fixture for the shared-cache service.
It uses real RSA signatures and two different signing keys. A production adapter
replaces `readRaw`; it does not change the verification/trust boundary.

<LiveCode data-output="deterministic">

```ts
import type { JwsKeyResolver, VerifyJwtOptions } from 'micro509/jose';
import {
  createJwksKeyResolver,
  parseJwks,
  signJwt,
  verifyJwt,
} from 'micro509/jose';
import { generateKeyPair } from 'micro509/keys';

const TTL = 60_000;
const COOLDOWN = 1_000;
const CAPACITY = 2;
let now = 1_900_000_000_000;
const primary = await generateKeyPair({ kind: 'rsa' });
const secondary = await generateKeyPair({ kind: 'rsa' });
const jwks = async (pair: typeof primary, kid: string) =>
  JSON.stringify({
    keys: [
      { ...(await pair.exportPublicJwk()), kid, use: 'sig', alg: 'RS256' },
    ],
  });
interface Config {
  readonly id: string;
  readonly issuer: string;
  readonly source: string;
  readonly audience: string;
}
const trusted = new Map<string, Config>(
  ['a', 'b', 'c'].map((name) => {
    const issuer = `https://issuer-${name}.example`;
    return [
      issuer,
      {
        id: `${issuer}/source-v1`,
        issuer,
        source: `${issuer}/configured-jwks`,
        audience: 'api://orders',
      },
    ];
  }),
);
interface Raw {
  readonly text: string;
  readonly expiresAt: number;
}
const shared = new Map<string, Raw>();
for (const config of trusted.values())
  shared.set(config.source, {
    text: await jwks(
      config.issuer.includes('issuer-b') ? secondary : primary,
      'shared',
    ),
    expiresAt: now + TTL,
  });
let reads = 0;
let unavailable = false;
async function readRaw(config: Config, _force: boolean): Promise<Raw> {
  reads++;
  await Promise.resolve(); // Real asynchronous shared-store boundary; concurrent callers can coalesce.
  if (unavailable) throw new Error('fixture refresh unavailable');
  const raw = shared.get(config.source);
  if (raw === undefined) throw new Error('missing fixture source');
  return raw;
}
interface Snapshot {
  readonly text: string;
  readonly expiresAt: number;
  readonly resolver: JwsKeyResolver;
}
type Read =
  | { readonly ok: true; readonly value: Snapshot }
  | {
      readonly ok: false;
      readonly code:
        | 'jwks_unavailable'
        | 'jwks_malformed'
        | 'limit_exceeded'
        | 'invalid_options';
    };
const local = new Map<string, Snapshot>();
const pending = new Map<string, Promise<Read>>();
const generations = new Map<string, number>();
const nextRefresh = new Map<string, number>();
let resolverCreations = 0;
function invalidate(config: Config): void {
  generations.set(config.id, (generations.get(config.id) ?? 0) + 1);
  local.delete(config.id);
  pending.delete(config.id);
  nextRefresh.delete(config.id);
}
function retain(id: string, snapshot: Snapshot): void {
  local.delete(id);
  local.set(id, snapshot);
  while (local.size > CAPACITY) {
    const oldest = local.keys().next().value;
    if (oldest !== undefined) local.delete(oldest);
  }
}
async function snapshot(config: Config, force = false): Promise<Read> {
  const existing = pending.get(config.id);
  if (existing !== undefined) return existing;
  const previous = local.get(config.id);
  if (!force && previous !== undefined && previous.expiresAt > now) {
    retain(config.id, previous);
    return { ok: true, value: previous };
  }
  const generation = generations.get(config.id) ?? 0;
  nextRefresh.set(config.id, now + COOLDOWN);
  const task = (async (): Promise<Read> => {
    try {
      const raw = await readRaw(config, force);
      if ((generations.get(config.id) ?? 0) !== generation)
        return { ok: false, code: 'jwks_unavailable' };
      if (!Number.isFinite(raw.expiresAt) || raw.expiresAt <= now) {
        local.delete(config.id);
        return { ok: false, code: 'jwks_unavailable' };
      }
      const parsed = parseJwks(raw.text);
      if (!parsed.ok) {
        local.delete(config.id);
        return { ok: false, code: parsed.code };
      }
      const value = {
        text: raw.text,
        expiresAt: Math.min(raw.expiresAt, now + TTL),
        resolver:
          previous?.text === raw.text
            ? previous.resolver
            : createJwksKeyResolver(parsed.value),
      };
      if (value.resolver !== previous?.resolver) resolverCreations++;
      retain(config.id, value);
      return { ok: true, value };
    } catch {
      if ((generations.get(config.id) ?? 0) === generation)
        local.delete(config.id);
      return { ok: false, code: 'jwks_unavailable' };
    }
  })();
  pending.set(config.id, task);
  try {
    return await task;
  } finally {
    if (pending.get(config.id) === task) pending.delete(config.id);
  }
}
async function verify(compact: string, issuer: string) {
  const config = trusted.get(issuer);
  if (config === undefined)
    return { ok: false, code: 'issuer_mismatch' } as const;
  const current = await snapshot(config);
  if (!current.ok) return current;
  const options: VerifyJwtOptions = {
    algorithms: ['RS256'],
    key: current.value.resolver,
    tokenType: 'JWT',
    claims: {
      issuer: config.issuer,
      audience: config.audience,
      now: () => new Date(now),
    },
  };
  const result = await verifyJwt(compact, options);
  if (result.ok || result.code !== 'key_not_found') return result;
  // One configured refresh for unknown kid; never refresh for bad signatures or claim failures.
  if (!pending.has(config.id) && now < (nextRefresh.get(config.id) ?? 0))
    return result;
  const refreshed = await snapshot(config, true);
  if (!refreshed.ok) return refreshed;
  return await verifyJwt(compact, {
    ...options,
    key: refreshed.value.resolver,
  });
}
const issue = (pair: typeof primary, issuer: string, kid: string) =>
  signJwt({
    privateKey: pair.privateKey,
    algorithm: 'RS256',
    header: { kid },
    claims: { iss: issuer, aud: 'api://orders', exp: now / 1000 + 3600 },
  });
const issuerA = 'https://issuer-a.example';
const issuerB = 'https://issuer-b.example';
const configA = trusted.get(issuerA);
if (configA === undefined) throw new Error('missing config');
const old = await issue(primary, issuerA, 'shared');
const pair = await Promise.all([verify(old, issuerA), verify(old, issuerA)]);
if (pair.some((result) => !result.ok) || reads !== 1 || resolverCreations !== 1)
  throw new Error('snapshot reuse failed');
console.log('Repeated verification, one shared read:', reads);
const tokenB = await issue(secondary, issuerB, 'shared');
if (!(await verify(tokenB, issuerB)).ok || (await verify(old, issuerB)).ok)
  throw new Error('issuer isolation failed');
console.log('Same kid, isolated issuers: passed');
now += COOLDOWN + 1;
shared.set(configA.source, {
  text: await jwks(secondary, 'rotated'),
  expiresAt: now + TTL,
});
const rotated = await issue(secondary, issuerA, 'rotated');
const rotation = await Promise.all([
  verify(rotated, issuerA),
  verify(rotated, issuerA),
]);
if (rotation.some((result) => !result.ok) || (await verify(old, issuerA)).ok)
  throw new Error('rotation/removal failed');
console.log('Unknown kid refresh and old key removal: passed');
// A third configured issuer exercises the two-entry capacity bound.
const issuerC = 'https://issuer-c.example';
if (
  !(await verify(await issue(primary, issuerC, 'shared'), issuerC)).ok ||
  local.size > CAPACITY
)
  throw new Error('capacity bound failed');
console.log('Local entries bounded:', local.size);
now += TTL + 1;
unavailable = true;
const failed = await verify(rotated, issuerA);
if (failed.ok || failed.code !== 'jwks_unavailable')
  throw new Error('stale fallback');
console.log('Expired snapshot and failed refresh:', failed.code);
unavailable = false;
for (const text of ['not JSON', '{"keys":[],"keys":[]}']) {
  shared.set(configA.source, { text, expiresAt: now + TTL });
  invalidate(configA);
  const bad = await verify(rotated, issuerA);
  if (bad.ok || bad.code !== 'jwks_malformed')
    throw new Error('malformed JWKS accepted');
}
console.log('Malformed and duplicate-member text: refused');
```

</LiveCode>

Each isolate starts with empty local maps and may disappear at any time. Your
shared service owns persistence and cross-isolate freshness; local single-flight
and cooldown apply only within this process. Coordinate distributed refreshes in
that service if needed. Keep configuration and metadata maps bounded too; this
example's metadata is limited by its three static configurations. Avoid retaining
old resolver handles elsewhere after rotation or invalidation.
