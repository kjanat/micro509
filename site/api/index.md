# API Reference

Reach for a domain entrypoint when you know the area you want, or the root
`micro509` import for the stable, workflow-first package surface. The root
re-exports the common surface; the domain entrypoints expose exhaustive
advanced types. Each row links to its API page, and to the matching narrative
guide where one exists.

## Choose a surface

| Need                                                              | Module                                   | Guide                               |
| ----------------------------------------------------------------- | ---------------------------------------- | ----------------------------------- |
| [Common workflows from the stable package surface](/api/micro509) | [`micro509`](/api/micro509)              |                                     |
| [Certificate creation, parsing, and extensions](/api/x509)        | [`micro509/x509`](/api/x509)             | [Certificates](/guide/certificates) |
| [Chain validation, identity, and policy](/api/verify)             | [`micro509/verify`](/api/verify)         | [Verification](/guide/verification) |
| [CRL, OCSP, and revocation orchestration](/api/revocation)        | [`micro509/revocation`](/api/revocation) | [Revocation](/guide/revocation)     |
| [Key generation, import, and export](/api/keys)                   | [`micro509/keys`](/api/keys)             | [Keys](/guide/keys)                 |
| [PEM block handling](/api/pem)                                    | [`micro509/pem`](/api/pem)               | [PKCS (PEM utilities)](/guide/pkcs) |
| [PKCS#7 and PKCS#12](/api/pkcs)                                   | [`micro509/pkcs`](/api/pkcs)             | [PKCS](/guide/pkcs)                 |
| [Result helpers and error primitives](/api/result)                | [`micro509/result`](/api/result)         |                                     |

The root [`micro509`](/api/micro509) import is the stable starting point; drop
to a domain module above when you need its advanced types.
