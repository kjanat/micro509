# Standards research tooling

`bun spec` is the entry point for the local standards corpus and its evidence.
The [spec-lookup skill](https://github.com/kjanat/micro509/blob/master/.claude/skills/spec-lookup/SKILL.md)
owns the research procedure. This page owns CLI behavior, output contracts
and operational limits; it is not a second research checklist.

Install the locked dependencies with `bun install --frozen-lockfile` first.
Use `bun spec --help` or nested `--help` for syntax. Global JSON mode is `--json`.

## Discovery

`list` inventories recognized RFC and PKITS text in `docs/rfc/`, and text one
directory below `docs/itu/`, `docs/w3c/` and `docs/ms/`. RFC reverse relations
come from vendored headers, not live status. Microsoft entries include the
document name, version and release date. It does not index arbitrary Markdown,
IDNA tables or generated documentation: inspect `PKIX-SCOPE.md` separately.

```sh
bun spec list --json
bun spec census REAL NR3 mantissa "decimal encoding" --samples 1 --json
bun spec search nextUpdate --doc rfc5280 --context 2
```

`census` takes independent regexes as separate arguments, case-insensitive
unless `--case-sensitive` is supplied. It scans every indexed document, counts
matching lines for each expression, and retains zero-hit queries and documents
in JSON. `--samples <n>` (default 1; 0 allowed) limits examples per query per
document, never the scan. Samples include original lines and enclosing sections.
Microsoft documents use the same discovered corpus and participate too.

JSON contains `searched`, `caseSensitive`, aggregate `queries`, every entry in
`documents`, and `truncated: false`. Missing documents are not zero-hit entries;
compare with `list` and report absent evidence. A complete local scan is not
proof that the corpus or vocabulary covers every relevant standard.

`search` keeps its existing contract: arguments join into one regex; matching
is case-sensitive unless `-i` is supplied; `--limit` defaults to 200. When it
truncates, later files may be unsearched. Use `census` for complete discovery,
not an arbitrary larger excerpt limit. Neither replaces whole-section reading.

## RFC status and errata

```sh
bun spec status 5280 3261 --refresh --json
bun spec status 5280 --offline --max-age 86400
```

`status` accepts RFC identifiers or bare positive numbers, even when not
vendored. It queries RFC Editor per-document JSON and the published
`https://www.rfc-editor.org/errata.json` feed. Both human and JSON output report
`updates`, `obsoletes`, `updatedBy` and `obsoletedBy`, direct successors' local
presence, and erratum IDs, published statuses, types, sections and links.
Reported, Verified, Held for Document Update, Rejected and unfamiliar statuses
remain distinct. Reports are not automatically applied as normative patches.

Only direct relationships are reported. Check each relevant successor's status
and text; the command does not decide normative precedence or recursively fetch
standards. ITU-T, W3C, WHATWG and Microsoft currency still requires checking the
official source, edition, revision and applicable amendments.

Metadata and errata are cached separately under
`node_modules/.cache/spec-status/`, keyed by the SHA-256 hash of the source URL.
`--cache-dir` selects another directory; relative paths use the caller's CWD.
Each envelope binds a version, URL, retrieval timestamp and validated payload.
Writes use unique temporary files and atomic replacement. Corrupt, wrong-source,
future-dated or structurally invalid envelopes are not usable.

The default maximum age is 86,400 seconds. `--refresh` bypasses usable caches;
`--max-age 0` requires a network observation outside offline mode. `--offline`
makes no requests and may return valid stale evidence, explicitly labelled.
`--offline --refresh` is an error. Missing offline evidence, HTTP failure or an
invalid response produces an error, not an empty successful report. Online
failure never silently falls back to stale evidence. Cache-write failure keeps
the validated network result and reports a warning.

Each resource carries `url`, `fetchedAt`, `source` (`network` or `cache`) and
`fresh`; freshness describes cache age, not permanent currency. Top-level JSON
contains `offline`, `documents`, `errataProvenance` and `warnings`. Success is
emitted only after every requested resource validates. Requests time out after
30 seconds each.

This is separate from `test/rfc/rfc-status.test.ts` and its XML-index cache.
That test still owns the citation/vendoring gate and explicit legacy pins.

## Whole sections and source provenance

```sh
bun spec headings rfc5280 --depth 4
bun spec read rfc5280 5.1.2.5 --lines
bun spec read rfc5280 5.1.2.5 --raw --lines
bun spec read rfc5280 5.1.2.5 --json
```

`read` keeps the existing de-wrapped output. `--raw` preserves original line
breaks and indentation after page furniture is removed. `--lines` labels each
paragraph or preformatted block with its original source range; with `--raw`,
it labels each retained line. This works for Microsoft sections too.

JSON preserves `doc`, `path`, `section`, `raw` and `body`, adding `blocks` and
`sourceLines`. A block carries `text`, `startLine`, `endLine` and the exact
retained `sourceLines` that produced it. A paragraph spanning a page break can
have non-contiguous source lines: removed headers are not evidence. Verify
verbatim quotations against those lines, not normalized text. Record the edition
or retrieval provenance for changing documents; ranges describe the local copy.

## Fetching and compatibility

```sh
bun spec fetch rfc 5280
bun spec fetch itu 'T-REC-X.509-201910-I!!PDF-E'
bun spec fetch w3c webcrypto-rec-2017
bun spec fetch ms MS-WCCE
bun spec fetch ms --help
```

All four legacy aliases remain: `bun rfc`, `bun itu`, `bun w3c`, `bun ms`.
The shared fetcher is import-safe; importing it never runs a second CLI.
Corpus and converter-cache paths are rooted at the repository rather than the
caller's CWD. JSON successes identify `kind`, `id`, repository-relative `path`
and source `url`.

RFCs are fetched verbatim. ITU fetching prefers the Word item, using the pinned,
GitHub-verified pandoc release and existing Lua converter; PDF fallback requires
`pdftotext`. Word output retains `~~struck~~`, `__underlined__` and `#` heading
markers. W3C/WHATWG conversion uses `w3m`, requires source license links and
retains source/retrieval/license provenance.

Microsoft fetching keeps the existing current-PDF download, PDF validation,
`pdftotext -layout` conversion and required version extraction. It stores
`docs/ms/<DOC>/<DOC>-v<date>.txt`; JSON identifies it as `ms-<name>-<date>`
(for example `ms-wcce-20260824`), matching the corpus identifier. Keep Microsoft
and ITU source local and gitignored under the project's existing rules. Fetching
does not commit documents or modify library source or authored project policy.

## Agent gate

The hook delegates supported reads, outlines, excerpt search and census to the
`spec-lookup` subagent, including the Microsoft corpus. It recognizes supported
wrapped invocations and global flags; the agent exemption comes from the hook
payload, never a shell comment. The former `# spec-intent: ...` escape is gone.
Metadata, status, fetching and scoped source-code searches remain available.

The gate is a workflow/context guard, not a security boundary against arbitrary
interpreters, generated paths, unknown tools or agents that can edit the hook.
`env -S` split strings remain unsupported: their second interpretation layer
is not the shell tokenizer or dreamcli's already-separated argv parser. Fetches
and metadata do not waive the skill's applicability and whole-section rules.

## Regression checks

```sh
bun test test/spec-reader.test.ts test/spec-lookup-gate.test.ts test/spec-research.test.ts test/spec-ms-research.test.ts
bun run typecheck:other
bun run typecheck:regular
```

The path-filtered, read-only `Spec tooling` workflow runs these suites and both
typechecks. Research tests use real loopback HTTP servers and temporary files,
not fetch/filesystem mocks or live RFC Editor availability. Microsoft integration
runs the actual CLI in an isolated fixture corpus, tests source mappings and
complete scans past the excerpt limit, and checks both fetch entry points.
The existing reader and Microsoft gate cases remain in the regression set.
