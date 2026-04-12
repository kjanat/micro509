# `src/keys/` - Key Material Surface

WebCrypto-first key generation plus import/export for RSA, ECDSA, Ed25519, and encrypted private-key containers.

## OVERVIEW

`keys` owns the public key boundary: generate keys, move between PKCS#1/8, SEC1, SPKI, PEM, and JWK, and keep algorithm assumptions explicit.

## STRUCTURE

```tree
keys/
├── keys.ts   # main API surface and format conversions
└── index.ts  # domain barrel
```

## WHERE TO LOOK

| Task                      | File      | Notes                                                    |
| ------------------------- | --------- | -------------------------------------------------------- |
| Key generation            | `keys.ts` | RSA, ECDSA, Ed25519 generation entrypoints               |
| Public-key import/export  | `keys.ts` | SPKI, PEM, JWK, PKCS#1 flows                             |
| Private-key import/export | `keys.ts` | PKCS#8, SEC1, encrypted PEM, JWK                         |
| PBES2 options             | `keys.ts` | re-exports typed encryption options from internal crypto |

## CONVENTIONS

- Keep format conversion and key-shape validation here; lower-level ASN.1 and crypto profile checks stay in `src/internal/**`.
- Make caller intent explicit with discriminated input types; do not infer key family from weak hints.
- Keep PEM handling at the `#micro509/pem` boundary instead of re-implementing block splitting locally.
- When adding compatibility options, thread them through typed inputs and typed failures, not booleans without context.

## ANTI-PATTERNS

- Do not silently fall back between PKCS#1, PKCS#8, SEC1, SPKI, and JWK.
- Do not default-accept unsupported hash, curve, or signature-scheme combinations.
- Do not leak raw parser errors when a domain-level result or typed input error should exist.
