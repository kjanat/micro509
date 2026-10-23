# Content-blocker snapshots

The LiveCode browser gate loads the complete EasyPrivacy and uBlock privacy lists
through the pinned `@gorhill/ubo-core` development dependency. This includes generic
path filters, hostname filters and exceptions. No filter subscription is fetched
at test time. `manifest.json` records the upstream commit, paths and SHA-256 hashes.
The harness rejects modified snapshots and errors reported by the network-filter
compiler. uBO Core ignores unsupported filters. Review engine compatibility when
refreshing the lists, especially newly introduced filter options.

The public suffix list is also pinned so first-party matching handles domains such
as `example.co.uk` correctly. It is initialized from text because this uBO Core
release cannot restore its bundled serialized suffix data.

The engine evaluates list conditionals for desktop Chromium with uBlock Origin.
It applies network blocking decisions to Playwright requests, including request
types, first/third-party restrictions, domain exclusions, regular expressions and
exception precedence. Blocked requests are aborted and reported as test failures.
Cosmetic filtering, scriptlets, response-header filtering and response rewriting
are outside this request gate. Redirect rules that produce a blocking decision
are aborted, without fetching a replacement resource.

To update, clone `uBlockOrigin/uAssets` with `gh repo clone`, choose a full commit
SHA, then run:

```sh
node scripts/update-content-blocker.mjs /path/to/uAssets COMMIT_SHA
node --test scripts/site-content-blocker.test.mjs
bun run site:live-examples
```

Commit the filter lists, public suffix snapshot and manifest together. The updater copies exact upstream
bytes. Compilation and checksum validation happen whenever the matcher loads.
`ubo-core` normalizes matching rule text in diagnostics, including `domain=` to
`from=`.

## Attribution and licensing

These filter snapshots are third-party data, distributed under GPL version 3 or
later. The accompanying `LICENSE` is copied from the pinned uAssets revision.
EasyPrivacy is authored by the EasyList authors. The uBlock privacy list is authored
by the uBlock Origin contributors. Their original comments and attribution are in
the snapshots. The upstream repository is <https://github.com/uBlockOrigin/uAssets>.
The public suffix snapshot is licensed under MPL 2.0, as stated in its header.
The GPL license applies to the filter snapshots, independently of micro509's
MIT license. uBlock Core is a GPL-3.0-or-later development dependency and is not
bundled into the published library or documentation site.
