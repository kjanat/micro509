# `src/` - Module Map

Public domain entrypoints are one-level buckets, implementation details stay in
`src/internal/`.

## OVERVIEW

`src/` is the library boundary. High-level workflow ownership is in domain
barrels under `x509`, `verify`, `revocation`, `keys`, `pem`, `pkcs`, and
`result`.

## WHERE TO LOOK

| Area               | File/dir                          | Notes                                               |
| ------------------ | --------------------------------- | --------------------------------------------------- |
| Package root       | `index.ts`                        | all stable package exports                          |
| Domain entrypoints | `x509/`, `verify/`, `revocation/` | re-export-only in most cases                        |
| Key APIs           | `keys/`                           | import/export, generation, encryption options       |
| PEM boundary       | `pem/`                            | encode/decode and block classification              |
| PKCS workflows     | `pkcs/`                           | PFX and PKCS#7 data lifecycles                      |
| Result model       | `result/`                         | shared typed `Result` and error constructors        |
| Internal spine     | `internal/`                       | ASN.1, crypto, shared helpers, verification engines |

## LOCAL CONVENTIONS

- Keep APIs by domain barrel; add files inside existing domain unless the domain
  model clearly needs a new public ownership file.
- Public API additions need both module export and barrel review.
- Internal helpers are not re-exported from public barrels unless they define API
  state.
- `src/internal/**` is implementation-only; tests and source should use
  `#micro509/internal/*` imports when they exist.
- Public leaf modules import from `internal` but must not import sibling public
  domain barrels.
- Validation semantics belong to `verify`; parse semantics belong to `x509`.
- PEM parsing/formatting lives only in `pem/pem.ts`; do not duplicate splitting
  logic in other modules.
- Key import/export must not silently fall back between schemes; fail with
  concrete error values. Keep WebCrypto assumptions and legacy compatibility
  options explicit and typed in `keys/keys.ts`.
- Do not return raw string errors in new result code; do not widen `Result`
  without callers handling the new branch.

## HOTSPOTS

- `src/verify/verify.ts` - core candidate path and policy composition control.
- `src/revocation/ocsp.ts` and `src/revocation/crl.ts` - largest revocation
  control-flow surface.
- `src/x509/parse.ts` and `src/x509/extensions.ts` - parse boundary and
  extension codec hub.
- `src/keys/keys.ts` - broadest API with legacy compatibility matrix.

## ANTI-PATTERNS

Avoid the following:

- Adding public-facing APIs under `src/internal/**`
- Splitting existing domain owners unless scope requires a new RFC-facing module
- Adding parse-tolerant behavior in validation layers
- Bypassing result ADTs with `throw` for expected domain failures
- Silently normalizing malformed PEM payloads
- Treating revocation transport failures as hard certificate failures
- Moving revocation semantics into parser-only modules
- Placing path-constraint or trust logic in X.509 domain files
- Adding ad-hoc extension decoding outside `extensions.ts`
