# `docs/` - Standards And Scope

Authored support claims plus the vendored standards corpus used to verify them.

## STRUCTURE

```tree
docs/
├── PKIX-SCOPE.md  # canonical support boundary and evidence links
├── rfc/           # unmodified RFC Editor text plus NIST PKITS text
├── itu/           # local, gitignored ITU-T references; redistribution restricted
└── CLAUDE.md      # delegates agent guidance to this file
```

Generated Deno API documentation may appear under `docs/deno/`; edit source
JSDoc and regenerate it rather than editing generated pages.

## WHERE TO LOOK

| Need                    | Location                      | Notes                                       |
| ----------------------- | ----------------------------- | ------------------------------------------- |
| Support claims and gaps | `PKIX-SCOPE.md`               | source of truth mirrored by README and site |
| RFC text                | `rfc/rfc<number>.txt`         | fetched verbatim from RFC Editor            |
| PKITS specification     | `rfc/pkits.txt`               | upstream NIST fixture documentation         |
| RFC fetcher             | `scripts/fetch-rfc.bun.ts`    | run with `bun rfc <number>`                 |
| RFC status guard        | `test/rfc/rfc-status.test.ts` | live RFC Editor index, daily cache          |
| Per-RFC conformance     | `test/rfc/*.test.ts`          | section-quoted behavioral evidence          |
| PKITS execution         | `test/pkits.test.ts`          | fixed-time path-validation harness          |

## CURRENT BASELINES

| Domain              | Current RFCs               | Legacy or supporting text                  |
| ------------------- | -------------------------- | ------------------------------------------ |
| PKIX validation     | RFC 5280, 6818, 9549, 9618 | NIST PKITS                                 |
| Service identity    | RFC 9525                   | RFC 6125 only for opt-in CN compatibility  |
| OCSP                | RFC 6960, 9919             | RFC 5019 legacy lightweight profile        |
| RSA                 | RFC 4055, 5756, 8017       | RFC 3447 superseded PKCS #1 text           |
| Safe curves         | RFC 8410, 9295             | RFC 5912 ASN.1 object classes              |
| PEM                 | RFC 7468                   | RFC 1421 and RFC 822 frozen legacy headers |
| PKCS containers     | RFC 5652, 7292, 8018       | RFC 2315 and 5208 legacy formats           |
| International email | RFC 9598                   | RFC 6531 and RFC 5321 terminology          |

## CONVENTIONS

- Fetch or refresh RFC text with `bun rfc <number>`; never hand-edit it.
- Keep an obsolete RFC when a legacy format is defined against that exact text.
- Vendor the current successor beside every retained obsolete RFC.
- Cite current RFCs in source unless behavior is deliberately pinned to frozen
  legacy text listed in `PINNED_TO_SUPERSEDED`.
- Add pinned exceptions only in `test/rfc/rfc-status.test.ts`, with the owning
  specification and section explaining why the old text remains normative.
- Quote the exact RFC sentence in conformance tests and group tests by section.
- Keep `PKIX-SCOPE.md`, README standards status, and site standards claims aligned.
- Treat RFC "updates" and "obsoletes" differently; inspect replacement text
  before changing behavior or citations.

## ANTI-PATTERNS

- Editing `rfc/*.txt` or `rfc/pkits.txt` as project prose.
- Removing frozen legacy RFCs solely because the RFC Editor marks them obsolete.
- Silencing `rfc-status.test.ts` without a real normative pin.
- Claiming complete RFC support without test-backed behavior.
- Committing or unignoring `itu/**`; its source is redistribution-restricted.
