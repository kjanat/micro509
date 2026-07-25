# `src/internal/` - Implementation Spine

Non-public internals for codecs, cryptography, and verification engines.

## OVERVIEW

`src/internal/` hosts reusable low-level spines consumed by all domains.
Public barrels are the root `src/*.ts` files and never live here.

## STRUCTURE

```tree
internal/
├── asn1/    # DER/ASN.1 primitives, OID catalog
├── crypto/  # signature, hashing, encryption helpers
├── shared/  # base64 + DN + IP helpers with cross-domain use
├── verify/  # policy/path/constraint engines
└── x509/    # extension/name metadata helpers
```

## WHERE TO LOOK

| Need                     | Location  | Notes                                             |
| ------------------------ | --------- | ------------------------------------------------- |
| ASN.1 and OID core       | `asn1/`   | DER encoding/parsing + OID resolution             |
| Crypto dispatch          | `crypto/` | algorithm/profile/sign/verify plumbing            |
| Cross-domain utilities   | `shared/` | base64 + DN + IP helpers (pure, deterministic)    |
| Name / extension helpers | `x509/`   | registry + field metadata + bit and name decoding |
| Verification engines     | `verify/` | high-complexity policy/name-constraint/path logic |

## CONVENTIONS

- Internal modules may be imported broadly, but should not be exported through
  root API barrels unless requested by API changes.
- Keep import direction inward: public leaf → internal.
- Avoid public barrel dependence inside internal modules.
- `shared/` helpers must stay pure and deterministic; do not add domain-specific
  policy logic there.
- Keep parser limits explicit when traversing nested structures.
- Use integer and length helpers from `asn1/` instead of local reimplementation.
- Register new OIDs in `asn1/oids.json` under their registration arc; consume
  them as `OIDS.<name>`. Never inline a dotted-decimal literal in source.
- New certificate extensions get an `ExtensionDefinition` in
  `x509/extension-registry.ts` (decode/encode/assertProfile/applyParsed +
  accumulator field), not ad-hoc decoding at call sites.
- `assertProfile` is required. It receives the decoded value and the extension's
  criticality, and delegates payload rules to the encoder that owns them. It runs
  only in builders, over a `customExtensions` entry carrying a known OID, so a raw
  value meets the same bar as the typed input. Parsing stays tolerant and never
  calls it.
- An extension whose criticality RFC 5280 fixes calls `assertExtensionCriticality`
  from its `assertProfile`, and its `defaultCritical` must agree; a test in
  `test/internals.test.ts` runs every definition's hook at its own default.
- Compare OIDs canonically. `validateOid` returns the canonical spelling, and
  `getExtendedKeyUsageOid` / `getAuthorityInfoAccessMethodOid` resolve to it, so a
  redundant-leading-zero alias cannot dodge a rule keyed on OID equality.
- `x509/general-name.ts` is the only GeneralName decoder; certificate and CRL
  parsing both consume it so the two layers cannot drift on an alternative.
- Keep sign/verify dispatch symmetric in `signing.ts` and `sig-verify.ts`.
- Preserve wire-level behavior in `shared/` helpers; tiny changes can fan out.
- If a helper starts encoding protocol policy, move it to the owning domain or engine.
- Keep complexity-reduction helpers in the codec or engine that owns their
  invariants; a lint-driven extraction is not by itself a reason for a new bucket.

## ANTI-PATTERNS

- Do not add public-level compatibility comments in internal modules.
- Do not copy utility logic that already exists in another internal bucket.
- Do not introduce new ad-hoc DER decoding inside domain modules.
