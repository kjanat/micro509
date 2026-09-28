# Standards tooling: source and environment failures

The research procedure lives in [the spec-lookup skill](https://github.com/kjanat/micro509/blob/master/.claude/skills/spec-lookup/SKILL.md).
This guide describes operational limits; it does not replace the procedure.

## Official character-set sources and network restrictions

The indexed corpus is not a network allowlist. Character-set investigations
may also require the [ISO-IR registration authority](https://itscj.ipsj.or.jp/),
[ECMA-35](https://ecma-international.org/publications-and-standards/standards/ecma-35/),
[ECMA-48](https://ecma-international.org/publications-and-standards/standards/ecma-48/),
[Unicode](https://www.unicode.org/standard/standard.html), and
[ISO's standards catalogue](https://www.iso.org/standards.html).
Select the edition the governing specification references. Do not silently
substitute a modern edition or infer a registered character name from memory.

The tracked `.claude/settings.json` registers the corpus hook; it does not
configure an outbound host allowlist or a secret/config-file hook. Restrictions
from a user's global configuration, a sandbox or an administrator remain
external. Relevant hosts include `itscj.ipsj.or.jp`, `ecma-international.org`,
`www.ecma-international.org`, `unicode.org`, `www.unicode.org`, `iso.org` and
`www.iso.org`. This PR does not disable those controls or add blanket shell
permissions. Report the exact denied source rather than treating it as absent
from the standard.

## ITU item discovery, scans and conversion defects

`bun spec fetch itu` accepts recommendation series beyond X, including
`T-REC-T.61-198811-S!!PDF-E`. To obtain an item ID, first open
`https://www.itu.int/rec/T-REC-T.61`, follow the selected edition to its `/en`
page, then copy the PDF download item's ID. Edition IDs and item IDs differ.
The fetcher still prefers the available Word item and falls back to PDF.

The original `.docx` or `.pdf` is retained alongside its `.txt` under the
already gitignored `docs/itu/` directory. Fetch JSON adds `sourcePath` and
`diagnostics`; it still reports the actual reader `id` and text `path`.
PDF pages with little extractable text are flagged with one-based page numbers.
This is a warning, not an OCR result: a page with substantial prose can still
contain an image-only table. Render and inspect the original page whenever
a required figure, table or note is absent from the extraction. Cite its
edition, clause/table and PDF page; do not invent a text-line citation.

`BROKEN_REFERENCE` flags literal unresolved Word cross-reference fields.
The converted text is not silently repaired. Compare the retained original
and an independently published representation before blaming either the
source or converter. If neither supplies the clause number, report the gap.
Automatic OCR and guessed replacements are deliberately not part of fetching.

## Bundled text identities and outlines

An arbitrary archive name such as `X6901.txt` does not establish an edition.
For non-`T-REC-` filenames, discovery uses explicit recommendation and edition
information from the cover when available. Thus an X.691 document inside an
X.680 bundle can be indexed under its own recommendation instead of the parent
folder's name. Without sufficient cover evidence, the fallback identifier
remains and the edition is unknown; the tool does not guess a date.

Independent representations can have different line numbers. Collision
suffixes keep both paths addressable; always cite the `path` returned with
the ID. Do not delete one representation just because its title resembles
another. Refetching may change text and therefore invalidate old line citations.

Numbered body paragraphs remain addressable by clause number, but are omitted
from the outline instead of being printed as enormous titles. Reading such a
clause retains its first body line, and search labels use its clause number.
Numbered clause depth follows the number rather than a Word style level.
The distinction is a bounded text heuristic, not a semantic parse of every
standard; original source remains authoritative.

## Bounded reading and page seams

Whole sections, including their subsections, remain the default. For a large
region:

```sh
bun spec read itu-x520-2019 6 --offset 0 --limit 20 --raw --lines
bun spec read itu-x520-2019 6 --offset 20 --limit 20 --json
```

`offset` is zero-based within the section's retained source lines; `limit`
counts those lines, not terminal wraps or normalized paragraphs. JSON includes
`selection.offset`, `totalLines`, `returnedLines`, `truncated` and `nextOffset`.
The original line numbers in `sourceLines` and `blocks` are unchanged. A partial
window is labelled, and must not be represented as the whole governing region.
A window may start or end midway through a paragraph; continue as needed.

Search context that crosses removed page furniture stays attached to a match
and its section label. A `--` within that block marks a source-line gap; it is
not a new unlabelled search hit.

## Errata and maintenance

Batch initial currency checks with `bun spec status 5280 3261 --refresh --json`.
Use `bun spec status <new-rfc> --json` afterward: the shared errata download is
cached under `node_modules/.cache/spec-status`, with validated timestamps.
Do not repeatedly download the full index into a project-root JSON file or
run `jq` over it just to obtain the CLI's already-filtered result. An external
secret/config-file hook is not altered by the repository's corpus gate.

`git add docs/rfc`, including `git -C <worktree> add -- docs/rfc`, is index
bookkeeping and does not trigger corpus delegation. Interactive `git add -p`,
`git show`, `git grep` and a subsequent `cat docs/rfc/...` still receive the
appropriate corpus checks. Allowing staging does not authorize publication
of redistribution-restricted files.

The formatter regression exercises an authored root `Errata.md` in an isolated
project with this repository's dprint configuration. No source standard or
user's existing errata document is rewritten by that test.
