# `src/internal/` - Implementation Spine

Non-public internals for codecs, cryptography, and verification engines.

## OVERVIEW

`src/internal/` hosts reusable low-level spines consumed by all domains.
Public barrels should stay in domain folders.

## STRUCTURE

```tree
internal/
├── asn1/    # DER/ASN.1 primitives, OID catalog
├── crypto/  # signature, hashing, encryption helpers
├── shared/  # base64 + ip helpers with cross-domain use
├── verify/  # policy/path/constraint engines
└── x509/    # extension/name metadata helpers
```

## WHERE TO LOOK

| Need                     | Location  | Notes                                             |
| ------------------------ | --------- | ------------------------------------------------- |
| ASN.1 and OID core       | `asn1/`   | DER encoding/parsing + OID resolution             |
| Crypto dispatch          | `crypto/` | algorithm/profile/sign/verify plumbing            |
| Cross-domain utilities   | `shared/` | base64 + DN + IP helpers (pure, deterministic)    |
| Name / extension helpers | `x509/`   | registry + field metadata + bit decoding          |
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
- Keep sign/verify dispatch symmetric in `signing.ts` and `sig-verify.ts`.
- Preserve wire-level behavior in `shared/` helpers; tiny changes can fan out.
- If a helper starts encoding protocol policy, move it to the owning domain or engine.

## ANTI-PATTERNS

- Do not add public-level compatibility comments in internal modules.
- Do not copy utility logic that already exists in another internal bucket.
- Do not introduce new ad-hoc DER decoding inside domain modules.
