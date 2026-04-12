# `src/verify/` - Verification Domain

Chain construction, policy evaluation, and service identity checks.

## OVERVIEW

`verify` composes parsing, policy, and constraint engines into public trust
decisions.

## STRUCTURE

```tree
verify/
├── verify.ts           # chain candidate + result orchestration
├── identity.ts         # service identity input/types + matcher
├── name-constraints.ts # domain-specific name constraint API types
├── policy.ts           # policy-related public surfaces
└── index.ts            # domain barrel
```

## WHERE TO LOOK

| Task              | File                  | Notes                                |
| ----------------- | --------------------- | ------------------------------------ |
| Chain validation  | `verify.ts`           | build/validate candidate paths       |
| Identity matching | `identity.ts`         | DNS/IP/SRV/URI match rules           |
| Name constraints  | `name-constraints.ts` | explicit input/shape for constraints |
| Policy helpers    | `policy.ts`           | policy engine-facing types           |

## CONVENTIONS

- Keep orchestration public in `verify.ts`, domain logic in `src/internal/verify/*`.
- Use typed result objects and error codes for policy failures.
- Identity matching follows project RFC mappings and harness expectations.

## ANTI-PATTERNS

- Do not parse DER in verification entry files unless already parsed upstream.
- Do not merge policy and parsing concerns in the same function.
- Do not bypass internal engines to add direct ad-hoc checks.
