---
name: spec-lookup
description: Use before answering, reviewing, or implementing a claim about RFC, ITU-T, W3C, WHATWG, or NIST PKITS requirements. Delegate to the spec-lookup agent for complete corpus discovery, dated status checks, whole-section reading, and cited governing/analogous/unspecified conclusions.
---

# spec-lookup

This file is the canonical research procedure. The agent definition delegates
here rather than maintaining another copy. CLI behavior and output contracts
are documented in `docs/SPEC-TOOLING.md`.

A plausible standards claim is not evidence. Research what governs the exact
artifact, operation, profile, and edition before changing code or advising a
caller. Do not pick a document merely because it supports an expected answer.

## Delegation and boundaries

Delegate standards questions with a short request:

```text
Agent(subagent_type: "spec-lookup", prompt: "QUESTION: <exact question, artifact and operation>. CONTEXT: <review claim, suspected documents, project scope or compatibility constraints>.")
```

The lookup agent reads this file in full, expands the research scope itself,
and returns the evidence contract below. Callers must not reproduce this
procedure in their prompts. The lookup may fetch standards and cache status
metadata; it must not edit source, tests, configuration, or authored project
policy, and must not commit. Do not run a source writer concurrently in the
same worktree when a lookup is fetching documents.

The hook routes supported corpus reads to `spec-lookup` to protect the coding
agent's context. It is a workflow guard, not an OS sandbox or a guarantee
against arbitrary shell code. Comments such as `# spec-intent: ...` do not
exempt a command. Metadata operations (`list`, `status`, `fetch`, help) remain
available to callers; the research procedure remains mandatory for conclusions.

## Corpus and scope

- `docs/rfc/rfc<n>.txt`: immutable RFC Editor text.
- `docs/rfc/pkits.txt`: NIST PKITS documentation and relying-party test policy.
- `docs/itu/**/*.txt`: local ITU-T Recommendations, amendments and corrigenda.
  Never commit this corpus or quote it verbatim in tracked/public output;
  paraphrase and cite the edition, clause, and source range instead.
- `docs/w3c/<spec>/*.txt`: rendered WebCrypto and Web IDL specifications.
- `docs/PKIX-SCOPE.md`: authored project scope; read separately, not as a standard.

`bun spec list` inventories the indexed text formats. It does not recursively
search arbitrary files under `docs/`. Check authored scope and any relevant
unindexed material separately. Report missing or unreadable evidence explicitly.

## Procedure

1. **Frame the question and vocabulary.** Identify the artifact, operation,
   profile, and compatibility constraints. Derive 3–6 independent concepts,
   synonyms, field names, or grammar productions; do not collapse them into
   one guessed phrase. Record suspected base specifications and profiles
   without treating that list as exhaustive.
2. **Discover broadly.** Run `bun spec list`, then
   `bun spec census <concept> <concept> ... --samples 1 --json` across every
   indexed document. Each quoted argument is a separate regex; matching is
   case-insensitive by default. Inspect zero-hit queries and expand vocabulary
   where necessary. Sample limits never limit the documents scanned.
   `search` supplies bounded excerpts, not a complete census. Read
   `docs/PKIX-SCOPE.md` separately before proposing a support change.
3. **Establish presence and currency.** For RFC candidates, run
   `bun spec status <rfc> ... --refresh --json`. Inspect both relationship
   directions, missing vendored texts, dated metadata and errata provenance,
   and every relevant erratum's published status. A cache within its age limit
   is a recent observation, not proof that no later update exists. `--offline`
   is explicitly cached evidence; say that currency was not rechecked online.
   An unavailable status check is not evidence of no updates or no errata.
4. **Fetch missing evidence and repeat discovery.** Use
   `bun spec fetch rfc <number>`, `bun spec fetch itu <item-id>`, or
   `bun spec fetch w3c <name>`. Obtain ITU item IDs from the official
   Recommendation catalogue, not a guessed edition; inspect amendments and
   corrigenda. Use `bun spec fetch w3c --help` for supported sources and check
   their publication status. Fetching a draft does not make it normative.
   Repeat the census after adding relevant documents. For every successor
   that might govern the question, check its own status and text too: `status`
   reports direct edges, not a transitive closure.
5. **Read whole regions.** Outline with `bun spec headings <id> --depth 4`,
   then `bun spec read <id> <section> --lines`. Read parent scope/conditions,
   referenced definitions, exceptions, and relevant successor sections, not
   merely the matching sentence. Use `--json` for source mappings and
   `--raw --lines` to verify exact wording. Raw file reads are a fallback for
   formats the section reader cannot handle, not a substitute for context.
6. **Resolve applicability.** Distinguish base text, profile restrictions,
   amendments, informative examples, and intentionally pinned legacy text.
   An updater changes the clauses it addresses; it does not replace the
   entire base document. An obsoleting document does not automatically undo a
   deliberate legacy compatibility contract. Inspect the actual text rather
   than using publication date as a universal precedence rule. Cross-check
   ITU-T X.509 and its corrigenda, and PKITS section prose, when they address
   the same concept; record not-applicable cases rather than forcing analogies.
7. **Classify and report.** Apply the evidence contract below. Do not promote
   a profile's MUST to a different artifact, a Reported erratum to a verified
   correction, a test-suite policy to a universal requirement, or project
   policy to a standards obligation. Preserve a supported conclusion under
   pushback, but revise it when the governing evidence changes.

## Evidence contract

Return a compact answer, not the whole corpus:

- **Conclusion and applicability:** the exact artifact, operation, profile,
  edition and project constraints to which it applies.
- **Evidence:** classify each material finding as GOVERNING, ANALOGOUS, or
  UNSPECIFIED, with a reason. Cite document ID, edition/status where relevant,
  section, local path and original line range. Quote only the necessary RFC
  or other redistributable sentence; paraphrase ITU-T text. De-wrapped output
  is for reading; verify verbatim quotations against original source lines.
- **Coverage and currency:** independent search expressions, documents read,
  fetched additions, update edges followed, relevant errata and their statuses,
  and observation timestamps/cache state. Identify unindexed or absent sources.
- **Limits:** distinguish silence in governing text from missing evidence,
  failed network access, parser limitations, or an incomplete search. Do not
  label an unavailable document UNSPECIFIED. Separate implementation advice
  and local policy from what the evidence actually requires.

The coding agent implements and tests after receiving this answer. The lookup
agent does not silently turn a research conclusion into a code or policy change.
