# API Reference

Use the domain pages when you know the area you want.
Use the root import page when you want the stable `micro509` package surface.

## Choose a surface

| Need                                             | Start here                               |
| ------------------------------------------------ | ---------------------------------------- |
| Common workflows from the stable package surface | `import { ... } from 'micro509'`         |
| Certificate creation, parsing, and extensions    | [`micro509/x509`](/api/x509)             |
| Chain validation, identity, and policy           | [`micro509/verify`](/api/verify)         |
| CRL, OCSP, and revocation orchestration          | [`micro509/revocation`](/api/revocation) |
| Key generation, import, and export               | [`micro509/keys`](/api/keys)             |
| PEM block handling                               | [`micro509/pem`](/api/pem)               |
| PKCS#7 and PKCS#12                               | [`micro509/pkcs`](/api/pkcs)             |
| Result helpers and error primitives              | [`micro509/result`](/api/result)         |

## Stable root import

The root `micro509` entrypoint re-exports the common workflow-first surface.
Reach for the domain entrypoints when you need exhaustive advanced types.

## Root Import

- [`micro509`](/api/micro509) - stable root import surface
