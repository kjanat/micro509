# `src/internal/crypto/` - Crypto Spine

Algorithm mapping, signing, verification, and format-specific parsing helpers.

## OVERVIEW

`internal/crypto` centralizes algorithm behavior used by public key generation,
X.509 builders, and revocation/signature checks.

## STRUCTURE

```tree
crypto/
├── crypto.ts      # helper entrypoints for WebCrypto integration
├── ecdsa.ts       # curve/hash profile support checks
├── hash.ts        # digest helpers
├── pbes2.ts       # password-based encryption profile logic
├── rsa-pss.ts     # RSA-PSS parameter decode/validate
├── signing.ts     # public signing profile mapping
├── sig-verify.ts  # verification profile mapping
└── webcrypto.ts   # backend availability checks
```

## WHERE TO LOOK

| Task                       | File                                 | Notes                                     |
| -------------------------- | ------------------------------------ | ----------------------------------------- |
| Signature profiles         | `signing.ts`, `sig-verify.ts`        | shared dispatch for all sign/verify flows |
| Algorithm-specific parsing | `ecdsa.ts`, `rsa-pss.ts`, `pbes2.ts` | strict algorithm profile handling         |
| WebCrypto boundary         | `webcrypto.ts`                       | runtime checks + adapter behavior         |

## CONVENTIONS

- Keep algorithm profile checks colocated with algorithm-specific modules.
- Keep sign/verify dispatch symmetric in `signing.ts` and `sig-verify.ts`.

## ANTI-PATTERNS

- Do not widen accepted hash/scheme combinations without updating tests.
- Do not add default-accept behavior for unsupported profiles.
