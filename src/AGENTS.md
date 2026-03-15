# src/ - Module Map

Flat module layer. Public modules and internal support files currently live
side-by-side while the exports-harmonization refactor scaffolds the target
domain layout.

## OVERVIEW

`src/` is one-level-deep by design. Large domain files usually own a full lifecycle instead of splitting by subfeature.

## WHERE TO LOOK

| Area               | File                                      | Notes                                                            |
| ------------------ | ----------------------------------------- | ---------------------------------------------------------------- |
| Root exports       | `index.ts`                                | package root barrel                                              |
| Certificate create | `certificate.ts`                          | create + self-signed create                                      |
| CSR create         | `csr.ts`                                  | CSR builder only                                                 |
| Parse boundary     | `parse.ts`                                | certificate/CSR DER+PEM parse, extension decoding                |
| Path validation    | `verify.ts`                               | path build + validate, policy, constraints, identity composition |
| Revocation by CRL  | `crl.ts`, `revocation.ts`                 | CRL lifecycle and orchestration                                  |
| OCSP               | `ocsp.ts`                                 | request/response create + parse + verify + validate              |
| Key material       | `keys.ts`                                 | keygen and key import/export                                     |
| Container formats  | `pfx.ts`, `pkcs7.ts`, `pkcs12-mac.ts`     | PKCS#12/PFX, PKCS#7, MAC helpers                                 |
| Extension schema   | `extensions.ts`                           | typed extension inputs plus ASN.1 encoders                       |
| ASN.1 internals    | `der.ts`, `asn1.ts`, `oids.ts`            | shared low-level spine                                           |
| Crypto internals   | `signing.ts`, `sig-verify.ts`, `pbes2.ts` | algorithm mapping, verify, PBES2                                 |

## LOCAL CONVENTIONS

- Keep new code in an existing domain file unless a new RFC surface clearly merits a new top-level module.
- Public API additions need both source export and `index.ts` barrel review.
- Internal helper modules are not re-exported just because tests use them.
- Large files follow a common shape: public types first, public functions next, private helpers last.
- `verify.ts` owns validation semantics; `parse.ts` owns input decoding semantics; do not blur that boundary.
- If an algorithm is added, update both `signing.ts` and `sig-verify.ts`.
- Staged domain barrels live in `src/x509/`, `src/verify/`, `src/revocation/`,
  `src/pkcs/`, `src/keys/`, `src/pem/`, and `src/result/`; keep them as
  re-export-only scaffolding until the real file moves land.
- Implementation-only modules belong under `src/internal/**`; tests and source
  should prefer `#micro509/internal/*` over incidental flat-file imports once an
  internal home exists.
- Public leaf modules may import `src/internal/**` directly, but must not import
  public barrels such as `src/index.ts` or sibling domain `index.ts` files.

## HOTSPOTS

- `verify.ts` - biggest control-flow surface; path, policy, name constraints, identity hooks.
- `crl.ts` - full CRL lifecycle in one file.
- `parse.ts` - parse boundary and extension decoder framework.
- `ocsp.ts` - request/response lifecycle plus responder validation.
- `extensions.ts` - typed schema hub for cert/CSR/CRL builders.
- `keys.ts` - broadest API width; legacy compatibility lives here.

## ANTI-PATTERNS

- Do not add new public subdirectories beyond the staged domain layout without a
  matching exports decision.
- Do not expose internal helpers from `index.ts` unless the package API truly expands.
- Do not mix parse-time tolerance with validation-time policy; reject malformed input early.
- Do not add one-off assertion shortcuts that violate repo typing bans.
