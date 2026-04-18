# `docs/` - Docs Map

Status docs and harness docs live here.\
This directory defines what the project claims, not just how it works.

## OVERVIEW

[`docs/`][docs] is small but high-leverage:
[`PKIX-SCOPE.md`] sets support boundaries, and harness docs tie prose claims to
concrete tests.

## WHERE TO LOOK

| Area             | File              | Notes                                                 |
| ---------------- | ----------------- | ----------------------------------------------------- |
| Support boundary | [`PKIX-SCOPE.md`] | canonical claim language and partial/full scope lines |

## STANDARDS MAPPING

| Need                          | Standard | Notes                                              |
| ----------------------------- | -------- | -------------------------------------------------- |
| PKIX path validation baseline | RFC 5280 | certificate/profile rules and validation language  |
| Service identity matching     | RFC 6125 | DNS/IP identity reference                          |
| OCSP baseline                 | RFC 6960 | request/response and responder rules               |
| Policy processing updates     | RFC 9618 | RFC 5280 policy updates referenced by current work |
| RSA PKIX algorithm rules      | RFC 4055 | RSA PKCS#1 v1.5, RSA-PSS, and OAEP identifiers     |
| RSA parameter update          | RFC 5756 | updates RFC 4055 SPKI and OAEP/PSS parameter rules |
| DSA/ECDSA SHA-2 identifiers   | RFC 5758 | SHA-224/256/384/512 signature OIDs and ASN.1       |
| PKIX clarification update     | RFC 6818 | RFC 5280 clarifications for policy and validation  |
| I18N update to RFC 5280       | RFC 9549 | current IDN and internationalized email updates    |
| Intl email certificates       | RFC 9598 | current SmtpUTF8Mailbox and matching rules         |
| Revocation not published      | RFC 9608 | `noRevAvail` extension and path validation update  |

## LOCAL CONVENTIONS

- Keep docs aligned with shipped behavior and current tests.
- Harness docs should point at owning test files.
- Prefer exact scope language over marketing language.
- [`docs/rfc/`][rfc] is reference material; project-authored edits belong in the
  Markdown docs, not vendored RFC text.

## ANTI-PATTERNS

- Do not claim full RFC 5280, RFC 6960, or revocation coverage\
  _unless_ tests and implementation truly support it.
- Do not let docs drift from [`test/pkits.test.ts`][pkits.test.ts] or
  [`test/differential.test.ts`][differential.test.ts].
- Do not rewrite vendored [RFC files][rfc] for local commentary.

[docs]: ../docs/
[`PKIX-SCOPE.md`]: ./PKIX-SCOPE.md
[`PKITS-HARNESS.md`]: ./PKITS-HARNESS.md
[`DIFF-HARNESS.md`]: ./DIFF-HARNESS.md
[rfc]: ../docs/rfc/
[pkits.test.ts]: ../test/pkits.test.ts
[differential.test.ts]: ../test/differential.test.ts
