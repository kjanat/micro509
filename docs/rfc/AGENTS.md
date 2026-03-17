# docs/rfc/ - Vendored RFC Map

Vendored standards text only. Reference material, not project-authored prose.

## OVERVIEW

`docs/rfc/` holds frozen RFC source text used for local lookup while implementing or scoping behavior.

## WHERE TO LOOK

| Need                          | File          | Notes                                              |
| ----------------------------- | ------------- | -------------------------------------------------- |
| PKIX path validation baseline | `rfc5280.txt` | certificate/profile rules and validation language  |
| Service identity matching     | `rfc6125.txt` | DNS/IP identity reference                          |
| OCSP baseline                 | `rfc6960.txt` | request/response and responder rules               |
| Policy processing updates     | `rfc9618.txt` | RFC 5280 policy updates referenced by current work |
| RSA PKIX algorithm rules      | `rfc4055.txt` | RSA PKCS#1 v1.5, RSA-PSS, and OAEP identifiers     |
| RSA parameter update          | `rfc5756.txt` | updates RFC 4055 SPKI and OAEP/PSS parameter rules |
| DSA/ECDSA SHA-2 identifiers   | `rfc5758.txt` | SHA-224/256/384/512 signature OIDs and ASN.1       |
| PKIX clarification update     | `rfc6818.txt` | RFC 5280 clarifications for policy and validation  |
| I18N update to RFC 5280       | `rfc9549.txt` | current IDN and internationalized email updates    |
| Intl email certificates       | `rfc9598.txt` | current SmtpUTF8Mailbox and matching rules         |
| Revocation not published      | `rfc9608.txt` | `noRevAvail` extension and path validation update  |

## LOCAL CONVENTIONS

- Treat filenames and contents as vendored upstream artifacts.
- Put project commentary in sibling Markdown docs, not inline here.
- When scope changes, update `docs/PKIX-SCOPE.md` or harness docs first; refresh vendored RFC text only when the source artifact changes.
- Prefer current RFCs over obsoleted ones when both exist in local notes or citations.

## ANTI-PATTERNS

- Do not edit these files for style, wording, or local annotation.
- Do not cite vendored text as shipped support by itself; claims still come from implementation plus tests.
- Do not mix draft notes, TODOs, or repo-specific decisions into this directory.
