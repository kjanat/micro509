---
name: spec-lookup
description: Use before answering, recommending, justifying, or implementing anything that turns on what a standard says (RFC, ITU-T X.501/X.509/X.520/X.660/X.680/X.690, W3C WebCrypto, NIST PKITS). Searches the entire vendored docs/ corpus broadly before reading, reads whole regions instead of hit lines, cites verbatim with section and line, and separates text that governs from text that is only analogous. Also provides a ready subagent prompt that carries these rules. Invoke on any question of what the spec says, whether something is required or allowed, which default is correct, or a review finding that names an RFC.
---

# spec-lookup

Every spec claim in this repo is grounded in the vendored text under `docs/`.
Never predetermine which document answers the question. The document you
expect is rarely the only one that speaks, and it is often not the newest.

## Corpus

| Path                         | What it is                                                                                                                                                       |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/rfc/rfc<n>.txt`        | Verbatim RFC Editor text. Refresh with `bun rfc <n>`.                                                                                                             |
| `docs/rfc/pkits.txt`         | NIST PKITS specification. Its section prose states relying-party practice and the configurable local-policy escape hatches explicitly.                             |
| `docs/itu/**/*.txt`          | ITU-T X.501, X.509 (plus corrigenda and amendments), X.520, X.660, X.680, X.690. Redistribution-restricted: read locally, paraphrase in tracked files and public text, never paste verbatim. |
| `docs/w3c/WebCryptoAPI/`     | W3C WebCrypto.                                                                                                                                                    |
| `docs/PKIX-SCOPE.md`         | The project's own support claims and design decisions. Check it so a spec-driven change does not silently contradict a documented decision.                       |

Current baselines per domain are listed in `docs/AGENTS.md`. Treat "updates"
and "obsoletes" differently: an updating RFC changes the base text and wins.

## Ensure the corpus is present and current (before any search)

The vendored copy can be missing a document or lag behind the RFC Editor.
Ground the answer in current governing text, never a stale or absent file.

1. **List every document the question could touch** — base specs, likely
   updaters, and profiles. The caller names the topics or documents; the
   lookup expands the set.
2. **Confirm each is vendored.** For any RFC missing under `docs/rfc/`, fetch
   it: `bun rfc <n>` (defined in `package.json`, runs
   `scripts/fetch-rfc.bun.ts`). ITU-T and W3C documents are not fetchable by
   that script; if one is absent, say so rather than inventing its content.
3. **Verify currency online.** For every RFC you will cite, read its
   `Updates:` / `Obsoletes:` header and confirm against the live RFC Editor
   index (the repo tracks this in `test/rfc/rfc-status.test.ts`) plus a web
   search that nothing newer updates or obsoletes it.
4. **Fetch the successors.** If a governing document has an updating or
   obsoleting RFC that is not vendored, `bun rfc <n>` it and read it too. A
   MUST in an obsoleted RFC does not govern once a newer one has changed it.

Only once the needed documents are present and confirmed current do you search.

## Procedure

1. **Census the whole corpus first.** `bun spec search "<terms>" --context 2`
   searches every vendored document and reports each match with its
   enclosing section and its true line number in the file. Do not name a
   file; the search already covers all of `docs/`. This is the step that
   surfaces the document you did not know about. `bun spec list` shows every
   document with its id, title, date, and Updates/Obsoletes relations.
2. **Outline the documents that hit.** `bun spec headings <id> --depth 4`
   shows the section structure so you read the right section rather than a
   window around a line.
3. **Read whole sections, not lines.** `bun spec read <id> <section>` prints
   one entire section, de-wrapped and free of page headers and footers
   (`--raw` keeps the original lines). A hit line is not an answer. The
   sentence that changes the meaning is usually above the hit: a heading, an
   "obsolete" marker, a conditional. Raw `rg`/`cat` on `docs/` is gated to
   the spec-lookup agent and is the fallback only for a format the reader
   does not parse.
4. **Follow the update graph.** Read each RFC's `Updates:` / `Obsoletes:`
   header, then search the corpus for documents that update *it*. The newest
   governing text wins. Note when a document is a profile (for example
   RFC 5019 and RFC 9919 profile OCSP) rather than the base specification.
5. **Cross-check ITU-T X.509 and its corrigenda** for the same concept. Note
   where it agrees with, extends, or is silent relative to the RFC.
6. **Check PKITS section prose** for relying-party practice. It frequently
   states the local-policy override the RFC leaves implicit.
7. **Separate governing from analogous.** A MUST in an OCSP profile does not
   govern CRLs. Say "analogous" when that is what it is, then find the base
   text that actually applies, and say "unspecified" when the governing text
   is silent.
8. **Cite verbatim.** Document, section, line number, exact sentence.
   Explain it in plain language in one or two sentences. Then implement.

## Delegating the search

When the question spans several documents, hand a subagent this prompt
verbatim and fill the two placeholders. Give it `subagent_type:
spec-lookup`. It may fetch RFCs (`bun rfc <n>`) and search the web to
confirm document status, but must not edit source, tests, or config, and
must not commit. A fetched RFC joins the corpus and stays in `docs/rfc/`.
Name the documents or topics you expect it to cover; it ensures each is
present and current before searching. Do not run a source writer in the
same worktree at the same time.

```text
Spec research in the micro509 repo at the current project root. Ground every claim in the vendored text under docs/. You MAY run `bun rfc <n>` to fetch a missing or superseded RFC and MAY use web search to confirm a document's status; do NOT edit source, tests, or config, and do NOT commit. A fetched RFC joins the corpus and stays in docs/rfc/.

QUESTION: <the exact question>
TERMS: <the search terms, including synonyms and field names>

Follow this procedure exactly and report each step's evidence:
0. Presence and currency first. List every document the question could touch (base specs, likely updaters, profiles). Fetch each RFC missing from docs/rfc/ with `bun rfc <n>`. For every RFC you will cite, read its Updates:/Obsoletes: header and confirm via web search plus the RFC Editor index that nothing newer updates or obsoletes it; fetch and read any governing successor. Report what you fetched and each document's status. ITU-T and W3C files are not fetchable by `bun rfc`; note if one is absent rather than inventing content.
1. Census the entire corpus: `bun spec search "<TERMS>" --context 2` (every vendored document, each match with its enclosing section and true line number). Do not pre-pick a document. `bun spec list` gives every id, title, and Updates/Obsoletes relation. Also search docs/PKIX-SCOPE.md for the project's own claims.
2. Outline each document that hit: `bun spec headings <id> --depth 4`.
3. Read whole sections with `bun spec read <id> <section>` (`--raw` for original lines). Never conclude from a hit line or a preview. Raw `rg`/`cat` on docs/ is the fallback only for a format the reader does not parse.
4. For every RFC you cite, read its Updates:/Obsoletes: header and search docs/ for documents that update it. Report which text is newest and governing.
5. Cross-check ITU-T X.509 and its corrigenda under docs/itu/. Paraphrase ITU text; do not quote it verbatim.
6. Check docs/rfc/pkits.txt section prose for relying-party practice on the same point.
7. Classify each finding as GOVERNING, ANALOGOUS, or UNSPECIFIED, and say why. A MUST in a profile for one artifact (for example OCSP) is ANALOGOUS for another (for example CRLs) unless the base text ties them.
8. Deliver: the verbatim governing sentences with document, section, and line; a plain-language explanation; and the list of documents you searched. Do not add your own policy reasoning on top of the text. If the text is silent, say so.

Read .json and other configuration-shaped files through `envctl redact` (`envctl redact < file`, or `<cmd> | envctl redact`), never raw.
```

## Do not

- Grep a single RFC because it is the one you expect. The census comes first.
- Treat a 6-line window as "the spec". Read the section.
- Pipe a context-rich search into a second `grep`, `head`, or `tail`.
- Cite a profile's MUST as governing a different artifact. RFC 5019 and 9919 govern OCSP responses, not CRLs.
- Justify a recommendation from your own reasoning when spec text decides it. Cite the text. If the text is silent, say "unspecified" and name the nearest governing and analogous text honestly.
- Soften a spec-backed position under pushback unless the spec itself is softer.
- Read `.json` or other configuration-shaped files raw. Pipe them through `envctl redact` (`envctl redact < file`, or `<cmd> | envctl redact`); reading them that way is fine.

## Worked example (2026-09-12)

Question: is revocation checking a required step of path validation, and how
must a CRL without `nextUpdate` be treated.

A 5280-only grep would have found §5.1.2.5 ("client behavior ... is not
specified") and stopped. The census over `docs/` surfaced RFC 9608 ("No
Revocation Available", updates 5280), ITU-T X.509 2023 Corrigendum 2, PKITS
§4.4, and RFC 6960 §4.2.2.1. Those decided it:

- RFC 5280 §6.1.3(a): the certificate "MUST satisfy ... (3) At the current
  time, the certificate is not revoked."
- RFC 9608 §4: "If the noRevAvail ... or the ocsp-nocheck certificate
  extension is present, then Step (a)(3) is skipped. Otherwise, revocation
  status determination of the certificate is performed."
- RFC 6960 §4.2.2.1: the interval "corresponds to the {thisUpdate,
  nextUpdate} interval in CRLs", and "If nextUpdate is not set, the
  responder is indicating that newer revocation information is available
  all the time."
- PKITS §4.4: a max age from `thisUpdate` is the configurable local-policy
  override for staleness.
- RFC 9919 §4 ("MUST reject" when `nextUpdate` is absent) is an OCSP
  profile: analogous for CRLs, not governing.

Conclusion the text supports: revocation determination is the default with
`noRevAvail`/`ocsp-nocheck`/explicit local policy as the only exemptions, and
an absent `nextUpdate` means "no validity window", not "valid forever".
