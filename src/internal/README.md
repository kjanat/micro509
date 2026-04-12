# Internal Layout

This tree is the implementation-only home for helper modules, engines, and
low-level primitives.

Rules:

- keep public API ownership in domain leaves, not here
- let public leaves import downward into `src/internal/**`
- never import public barrels from internal modules
- use `#micro509/internal/*` for tests and source once an internal file exists

Current buckets:

- `asn1/` - ASN.1, DER, OID helpers
- `crypto/` - signing, hashing, PBES2, and algorithm helpers
- `x509/` - extension and name support helpers
- `verify/` - path, policy, and validation engines
- `shared/` - cross-domain helpers with no public ownership
