# `docs/` - Standards And Scope

Authored support claims plus the standards corpus used to verify them.

## STRUCTURE

```tree
docs/
├── PKIX-SCOPE.md   # canonical support boundary and evidence links
├── SPEC-TOOLING.md # research CLI, output contracts and operational limits
├── rfc/           # unmodified RFC Editor text plus NIST PKITS text
├── itu/           # local, gitignored ITU-T references; redistribution restricted
├── w3c/           # W3C WebCrypto and WHATWG Web IDL rendered to text
├── ms/            # local, gitignored Microsoft Open Specifications text
├── idna/          # frozen IANA IDNA2008 and Unicode 12.0.0 tables
└── CLAUDE.md       # delegates agent guidance to this file
```

Generated Deno API documentation may appear under `docs/deno/`; edit source
JSDoc and regenerate it rather than editing generated pages.

## WHERE TO LOOK

| Need                          | Location                                                      | Notes                                                                               |
| ----------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Support claims and gaps       | `PKIX-SCOPE.md`                                               | Source of truth mirrored by README and site                                         |
| Research procedure            | `.claude/skills/spec-lookup/SKILL.md`                         | Canonical policy, corpus restrictions and worked example; delegate to `spec-lookup` |
| CLI reference                 | `SPEC-TOOLING.md`                                             | Commands, JSON contracts, citation mapping, cache and gate limitations              |
| Reader and research commands  | `scripts/spec/`                                               | `bun spec list`, `census`, `status`, `headings`, `read`, `search`                   |
| Spec fetcher                  | `scripts/fetch-spec.bun.ts`                                   | `bun spec fetch rfc/itu/w3c/ms`; all four legacy package aliases remain supported   |
| RFC text                      | `rfc/rfc<number>.txt`                                         | Fetched verbatim from RFC Editor                                                    |
| PKITS specification           | `rfc/pkits.txt`                                               | NIST fixture documentation and test policy                                          |
| Microsoft Open Specifications | `ms/<DOC>/<DOC>-v<date>.txt`                                  | Current PDF through `pdftotext -layout`; versioned local text, never tracked        |
| RFC status guard              | `test/rfc/rfc-status.test.ts`                                 | Live XML index with daily cache; owns explicit legacy citation pins                 |
| Research regression tests     | `test/spec-research.test.ts`, `test/spec-ms-research.test.ts` | Local HTTP/cache tests and real CLI/MS integration                                  |
| Reader and gate tests         | `test/spec-reader.test.ts`, `test/spec-lookup-gate.test.ts`   | Existing format parsers and supported routing, including MS                         |
| Per-RFC conformance           | `test/rfc/*.test.ts`                                          | Section-quoted behavioral evidence                                                  |
| PKITS execution               | `test/pkits.test.ts`                                          | Fixed-time path-validation harness                                                  |

## PROJECT BASELINES

This table records the project's reference set, not a live currency guarantee.
Use `bun spec status <rfc> ... --refresh` and inspect successor text before a
current-standards claim. `PKIX-SCOPE.md` still defines support; metadata does
not change it. Inspect non-RFC status in the official source catalogues.

| Domain              | Project RFCs               | Legacy or supporting text                  |
| ------------------- | -------------------------- | ------------------------------------------ |
| PKIX validation     | RFC 5280, 6818, 9549, 9618 | NIST PKITS                                 |
| Service identity    | RFC 9525                   | RFC 6125 only for opt-in CN compatibility  |
| OCSP                | RFC 6960, 9654, 9919       | RFC 5019 legacy lightweight profile        |
| RSA                 | RFC 4055, 5756, 8017       | RFC 3447 superseded PKCS #1 text           |
| Safe curves         | RFC 8410, 9295             | RFC 5912 ASN.1 object classes              |
| PEM                 | RFC 7468                   | RFC 1421 and RFC 822 frozen legacy headers |
| PKCS containers     | RFC 5652, 7292, 8018, 9879 | RFC 2315 and 5208 legacy formats           |
| International email | RFC 9598                   | RFC 6531 and RFC 5321 terminology          |
| IDNA                | RFC 5890-5893, 8753        | RFC 3492 Punycode, RFC 5895 mapping        |

## CONVENTIONS

- The skill owns the research procedure. Do not maintain another checklist here.
- `census` scans the indexed corpus completely; `search` is a bounded excerpt
  lookup. Inspect authored scope and unindexed material separately.
- Fetch through `bun spec fetch`; the legacy `bun rfc`, `bun itu`, `bun w3c`
  and `bun ms` aliases remain compatible. Never hand-edit upstream text.
- ITU Word conversion retains revision markers; inspect struck and underlined
  text. The skill owns source restrictions, and the CLI reference covers conversion.
- Keep an obsolete RFC when a legacy format pins that exact text and vendor
  the current successor beside it for comparison.
- Cite current RFCs in source unless behavior is deliberately pinned to frozen
  legacy text listed in `PINNED_TO_SUPERSEDED`.
- Add pinned exceptions only in `test/rfc/rfc-status.test.ts`, with the owning
  specification and section explaining why the old text remains normative.
- Quote the exact RFC sentence in conformance tests and group tests by section.
  Verify wording with `read --raw --lines` or JSON source mappings.
- Keep `PKIX-SCOPE.md`, README standards status and site standards claims aligned.
- Inspect update, replacement, profile and erratum scope before changing behavior.

## ANTI-PATTERNS

- Editing `rfc/*.txt` or `rfc/pkits.txt` as project prose.
- Removing frozen legacy RFCs solely because the RFC Editor marks them obsolete.
- Silencing `rfc-status.test.ts` without a real normative pin.
- Claiming complete RFC support without test-backed behavior.
- Committing or unignoring `itu/**` or `ms/**`; keep their source local.
- Reproducing ITU text verbatim in tracked/public output.
- Treating failed status retrieval as proof of no updates or errata.
- Calling the hook a security sandbox or granting a read through a shell comment.
