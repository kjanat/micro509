# `src/internal/asn1/` - ASN.1 Spine

Low-level TLV and OID utilities for all parser surfaces.

## OVERVIEW

`internal/asn1` is the canonical encoding foundation for certificate, key,
CRL, and OCSP workflows.

## STRUCTURE

```tree
asn1/
|- asn1.ts    # TLV readers/writers
|- der.ts     # DER-specific conversions and guards
`- oids.ts    # OID symbol map and algorithm registry
```

## WHERE TO LOOK

| Need        | File                | Notes                                           |
| ----------- | ------------------- | ----------------------------------------------- |
| DER parsing | `der.ts`, `asn1.ts` | all non-string binary parsing roots             |
| OID lookup  | `oids.ts`           | algorithm and extension dispatch across domains |

## CONVENTIONS

- Keep parser limits explicit when traversing nested structures.
- Use integer and length helpers from this module instead of local reimplementation.

## ANTI-PATTERNS

- Do not introduce new ad-hoc DER decoding inside domain modules.
