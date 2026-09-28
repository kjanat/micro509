# Standards research tooling

`bun spec` is the entry point for the standards corpus and its evidence.
The research procedure lives in
[the spec-lookup skill](../.claude/skills/spec-lookup/SKILL.md); this document
owns command behavior, output contracts, and operational limits.

## A lookup from start to finish

```sh
bun spec list
bun spec census REAL NR3 mantissa "decimal encoding" --samples 1 --json
bun spec status rfc5280 rfc3261 --refresh --json
bun spec headings rfc5280 --depth 4
bun spec read rfc5280 5.1.2.5 --lines
bun spec read rfc5280 5.1.2.5 --raw --lines
```

These illustrate separate discovery, currency and reading operations, not a
claim that those RFCs answer the REAL question. Select documents from the
census and applicability analysis. Check `PKIX-SCOPE.md` separately for the
library's support contract.

Run `bun install --frozen-lockfile` before using the commands or their tests.
The package scripts use the project's Bun and dreamcli dependency. Root help
and nested help are available through `bun spec --help` and
`bun spec fetch --help`; global JSON mode remains `--json`.

## Discovery: `list`, `census`, and `search`

`list` inventories recognized RFC and PKITS text under `docs/rfc/`, and text
one directory below `docs/itu/` and `docs/w3c/`. Its reverse RFC relationships
are derived from the **vendored** headers, not a live currency check. It does
not index arbitrary authored Markdown, IDNA tables or generated documentation.

`census` takes independent regular expressions as separate arguments. Matching
is case-insensitive unless `--case-sensitive` is given. It always scans every
indexed document, counts matching lines for each expression, and retains
zero-hit queries and documents in JSON. `--samples <n>` (default 1; 0 allowed)
limits only examples per expression per document, never scan coverage.
Examples include their enclosing section and original source line.

```sh
bun spec census nextUpdate freshness "revocation status" --samples 0 --json
bun spec search nextUpdate --doc rfc5280 --context 2
```

The census JSON has `searched`, `caseSensitive`, aggregate `queries`, every
scanned entry in `documents`, and `truncated: false`. A complete scan of the
local index is not proof that the corpus or vocabulary covers every relevant
standard. Missing files do not become zero-hit documents; compare against
`list` and report any missing evidence.

`search` retains its existing behavior: arguments are joined into one regex,
matching is case-sensitive unless `-i` is supplied, and `--limit` defaults to 200. Its `truncated` flag describes a bounded excerpt search. When that limit
is hit, later documents may not have been searched. Use `census`, not a larger
arbitrary excerpt limit, for complete document discovery. Neither command's
hit lines replace reading the full governing section.

## Currency: `status`

```sh
bun spec status 5280 3261
bun spec status rfc5280 --refresh --json
bun spec status 5280 --offline --max-age 86400 --json
```

This command accepts RFC identifiers or bare positive numbers, including ones
not yet vendored. It queries RFC Editor per-document JSON and the published
`https://www.rfc-editor.org/errata.json` feed. It reports forward and reverse
Updates/Obsoletes relationships, direct successors' presence in the local
corpus, and erratum IDs, published statuses, types, sections and links.
Reported, Verified, Held for Document Update, Rejected, and unfamiliar status
values remain distinct. No report is silently applied as a normative patch.

Relationships are **direct**. Inspect each relevant successor's status and
text to follow a chain; the command neither recursively fetches standards nor
decides which profile governs. A missing updater is a research lead, not an
automatic change to project policy. No certificate behavior changes merely
because metadata changed online.

Metadata and the shared errata feed are separately cached under
`node_modules/.cache/spec-status/`, keyed by a SHA-256 hash of the URL.
`--cache-dir <directory>` selects an alternate cache (relative paths use the
caller's working directory), useful for isolated runs and diagnostics. Each
versioned cache record binds the source URL, retrieval timestamp and validated
payload. Writes use unique temporary files and atomic replacement. A corrupt,
wrong-source, future-dated or structurally invalid record is not usable.

The default maximum age is 86,400 seconds. `--refresh` bypasses usable caches;
`--max-age 0` requires a network observation outside offline mode. `--offline`
never accesses the network and may return valid stale evidence, clearly marked.
`--offline --refresh` is an error. No usable offline cache, failed HTTP request,
or invalid response is an error, not an empty status result. Online failures
never silently fall back to stale evidence. A cache write failure preserves
the successfully validated network result and emits a warning.

Each metadata result and the shared errata result carry `url`, `fetchedAt`,
`source` (`network` or `cache`) and `fresh`. `fresh` means the observation is
within the requested cache age, not that the RFC remains unchanged forever.
The top-level JSON has `offline`, `documents`, `errataProvenance` and `warnings`.
Nothing is emitted as a successful status report until all requested resources
have been validated. Network timeouts are 30 seconds per request.

This CLI's per-document JSON cache is separate from the existing
`test/rfc/rfc-status.test.ts` XML-index cache. That test remains the repository's
citation/vendoring guard; `status` is an interactive evidence report, not a
replacement for that gate or its explicit legacy pins.

## Reading and citation provenance

`read <doc> <section>` keeps the existing de-wrapped output. `--raw` keeps
original line breaks and indentation after page furniture has been removed.
`--lines` labels each rendered paragraph or preformatted block with its original
source range; combined with `--raw`, it labels each retained source line.

```sh
bun spec read 5280 5.1.2.5 --lines
bun spec read 5280 5.1.2.5 --raw --lines
bun spec read 5280 5.1.2.5 --json
```

JSON preserves `doc`, `path`, `section`, `raw` and `body`, and adds `blocks`
and `sourceLines`. Each block has `text`, `startLine`, `endLine` and the exact
retained `sourceLines` used to render it. A paragraph spanning a page break
may have a non-contiguous source mapping: removed headers are not evidence.
Use the mapping, not an invented normalized line number, for exact citations.

De-wrapping changes whitespace, and line ranges are tied to the local file
version. Verify verbatim quotations against the retained source lines and
record the edition or retrieval provenance for changing documents. `--lines`
is a human rendering choice; JSON always carries the source mapping.

## Fetching and compatibility

```sh
bun spec fetch rfc 5280
bun spec fetch itu 'T-REC-X.509-201910-I!!PDF-E'
bun spec fetch w3c webcrypto-rec-2017
bun spec fetch w3c --help
```

The old `bun rfc`, `bun itu` and `bun w3c` package scripts remain compatible.
The fetcher is import-safe, so the research CLI composes its subcommands rather
than launching another CLI during import. Corpus and converter-cache paths
are rooted at the repository, not the caller's working directory. JSON success
output identifies `kind`, `id`, repository-relative `path` and source `url`.

RFCs are fetched verbatim. ITU fetching prefers the Word item, converted with
the pinned, GitHub-verified pandoc release and the existing Lua conversion;
PDF fallback requires `pdftotext`. Those reference files remain gitignored.
W3C/WHATWG conversion requires `w3m`, rejects sources without license links,
and retains source/retrieval/license provenance. Do not guess ITU item IDs,
commit restricted source, or turn a living draft into a claimed Recommendation.
Fetching writes the corpus; it does not commit it or edit library source.

## Agent gate and maintenance

The hook delegates supported corpus reads, section outlines, excerpt search
and census to the `spec-lookup` subagent. It recognizes reader subcommands even
with global flags before them. Comment text, including the former
`# spec-intent: ...` marker, cannot grant a read exception. Corpus metadata,
status and fetching remain available, as do scoped source-code searches.

This is a context/workflow guard around known tools and command shapes, not a
security boundary against arbitrary interpreters, runtime-generated paths,
unknown tools, or agents that can edit the hook. Do not advertise it as complete
isolation. Fetches and status checks are not a substitute for the skill's
whole-section and applicability requirements. The subagent and short delegation
prompt both refer to the one canonical skill instead of duplicating its policy.

## Regression checks

```sh
bun test test/spec-reader.test.ts test/spec-lookup-gate.test.ts test/spec-research.test.ts
bun run typecheck:other
bun run typecheck:regular
bun run check:biome
bunx --no-install dprint check
```

The path-filtered `Spec tooling` pull-request workflow runs these three Bun
suites and both typechecks. It has read-only repository permissions.

The research suite exercises real local HTTP servers and temporary filesystem
caches, not global fetch mocks or live RFC Editor availability. It covers
response validation, cached/fresh/stale/offline behavior, failed refreshes,
atomic writes, complete census counts, zero-hit concepts, source mappings,
CLI option failures and nested fetch help. Existing reader and gate suites
remain part of the regression set.
