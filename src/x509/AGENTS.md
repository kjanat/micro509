# `src/x509/` - X.509 Domain

Creation, parsing, names, and extension workflows for certificates and CSRs.

## OVERVIEW

`x509` owns lifecycle APIs that map raw material into typed domain objects and
extension data.

## STRUCTURE

```tree
x509/
├── certificate.ts  # certificate creation
├── csr.ts          # CSR creation
├── name.ts         # X.500 name encoding and helpers
├── extensions.ts   # extension schema + encoder/decoder map
├── parse.ts        # certificate/CSR parse boundary
└── index.ts        # domain barrel
```

## WHERE TO LOOK

| Task                 | File             | Notes                                    |
| -------------------- | ---------------- | ---------------------------------------- |
| Certificate creation | `certificate.ts` | create self-signed + issuer-bound certs  |
| CSR workflows        | `csr.ts`         | create request + subject payload shaping |
| Name shaping         | `name.ts`        | DN attribute registry + encode path      |
| Parse boundary       | `parse.ts`       | DER/PEM parsers, extension decode path   |
| Extension rules      | `extensions.ts`  | extension registry + encode/decode map   |

## CONVENTIONS

- Parsing and encoding live in `parse.ts` / `extensions.ts`; keep policy in
  `verify`.
- Expose shared types from `extensions.ts` and keep high-level workflow types in
  `certificate.ts` and `csr.ts`.
- Keep public extension additions in one place and add decoder/encoder tests at
  domain boundary.

## HOTSPOTS

- `parse.ts`, `extensions.ts` are high-complexity modules with many extension
  branches.
- `certificate.ts` is main builder surface for cert flows.

## ANTI-PATTERNS

- Do not place path-constraint or trust logic in X.509 domain files.
- Do not add ad-hoc extension decoding outside `extensions.ts`.
