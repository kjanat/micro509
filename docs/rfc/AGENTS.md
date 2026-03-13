# docs/rfc/ - Vendored RFC Map

Vendored standards text only. Reference material, not project-authored prose.

## OVERVIEW

`docs/rfc/` holds frozen RFC source text used for local lookup while implementing or scoping behavior.

## WHERE TO LOOK

| Need | File | Notes |
| ---- | ---- | ----- |
| PKIX path validation baseline | `rfc5280.txt` | certificate/profile rules and validation language |
| Service identity matching | `rfc6125.txt` | DNS/IP identity reference |
| OCSP baseline | `rfc6960.txt` | request/response and responder rules |
| Policy processing updates | `rfc9618.txt` | RFC 5280 policy updates referenced by current work |

## LOCAL CONVENTIONS

- Treat filenames and contents as vendored upstream artifacts.
- Put project commentary in sibling markdown docs, not inline here.
- When scope changes, update `docs/PKIX-SCOPE.md` or harness docs first; refresh vendored RFC text only when the source artifact changes.

## ANTI-PATTERNS

- Do not edit these files for style, wording, or local annotation.
- Do not cite vendored text as shipped support by itself; claims still come from implementation plus tests.
- Do not mix draft notes, TODOs, or repo-specific decisions into this directory.
