# `src/keys/` - Key Domain

Keypair, import, export, and encryption utilities.

## OVERVIEW

`keys` owns stable key flows used by all key material entrypoints.

## STRUCTURE

```tree
keys/
|- keys.ts    # generation + import/export + encryption
`- index.ts   # domain barrel
```

## WHERE TO LOOK

| Task               | File      | Notes                                            |
| ------------------ | --------- | ------------------------------------------------ |
| Key generation     | `keys.ts` | generate key pair and algorithm input validation |
| Import/Export      | `keys.ts` | PKCS#1/8, SEC1, SPKI, JWK pipelines              |
| Encryption options | `keys.ts` | PBKDF2 and PBES2 profile handling                |

## CONVENTIONS

- Keep WebCrypto assumptions centralized in key algorithms.
- Keep legacy compatibility options explicit and typed.
- Any new format branch must return explicit typed failure paths.

## ANTI-PATTERNS

- Do not add silent fallback between schemes; fail with concrete error values.
- Do not bypass result-based failures for recoverable import errors.
