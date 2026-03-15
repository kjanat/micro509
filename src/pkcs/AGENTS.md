# `src/pkcs/` - PKCS Domain

Container-format lifecycles and authenticated data helpers.

## OVERVIEW

`pkcs` owns the public workflows for PKCS#7 bags, PKCS#12/PFX, and PBES2
container auth flows.

## STRUCTURE

```tree
pkcs/
|- pfx.ts         # PFX + PBES2 parse/encode/create
|- pkcs7.ts       # PKCS#7 signed-data flows
|- pkcs12-mac.ts  # MAC helper and compatibility surface
`- index.ts       # domain barrel
```

## WHERE TO LOOK

| Task            | File            | Notes                                        |
| --------------- | --------------- | -------------------------------------------- |
| PFX lifecycle   | `pfx.ts`        | parse/create/verify and compatibility checks |
| PKCS#7 handling | `pkcs7.ts`      | cert bag parsing and signer metadata         |
| MAC helpers     | `pkcs12-mac.ts` | password-based MAC rules                     |

## CONVENTIONS

- Keep algorithm compatibility checks near container-specific modules.
- Route container-specific parsing through `result`-based error contracts.
- Validate protocol invariants before exposing friendly construction helpers.

## ANTI-PATTERNS

- Do not mix PBES2 envelope encoding logic into PKCS#7 helpers.
- Do not weaken type surface when adding legacy compatibility flags.
