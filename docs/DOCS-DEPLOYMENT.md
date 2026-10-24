# Documentation deployment

Production documentation is served from Cloudflare at
<https://micro509.kjanat.dev>. GitHub Actions builds the static files and
publishes them to the generated `docs-site` branch. Cloudflare's existing
deploy hook then deploys that branch's prebuilt tree; Cloudflare does not
render the version history.

The complete history with per-symbol API pages exceeds 20,000 files. Deploying
it requires Workers Paid, whose limit is 100,000 assets per Worker version,
and Wrangler 4.34.0 or newer. See
[Cloudflare's static asset limits](https://developers.cloudflare.com/workers/platform/limits/#static-assets).
Incremental builds reduce rendering work, but the deployed tree still contains
every archived version.

## Build one tree locally

With no channel set, `site:build` builds a PR-style preview of the checked-out
tree, offline from release discovery:

```sh
bun run site:build
```

Set a channel to inspect a production target. Release targets must match the
version in their source `package.json`; an archive can use an extracted tag
source root when rebuilding historical documentation.

```sh
DOCS_CHANNEL=next bun run site:build
DOCS_CHANNEL=archive DOCS_VERSION=v0.15.0 bun run site:build
DOCS_CHANNEL=latest DOCS_VERSION=v0.15.0 bun run site:build
DOCS_CHANNEL=archive DOCS_VERSION=v0.14.0 DOCS_SOURCE_ROOT=/tmp/micro509-v0.14.0 bun run site:build
```

These commands write one site's files to `site/.vitepress/dist`. They do not
update `docs-site` or deploy the site. `DOCS_CHANNEL=all` invokes the previous
full-history renderer for diagnosis.

## Production flow

The `Deploy Site` workflow serializes changes to `docs-site` with one
concurrency group. It restores the current published tree, applies the new
build, publishes a new orphan commit, then runs a separate Cloudflare deploy
job.

| Trigger                       | Build                                           | Published tree change                                                     |
| ----------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------- |
| Push to `master`              | `next` from the checked-out tree                | Replace `/next/` and refresh the version catalog                          |
| Stable release from `Publish` | `archive` and `latest` from the release tag     | Add immutable `/vX.Y.Z/`, then replace root files and refresh the catalog |
| Pull request preview          | Default `preview` build of the checked-out tree | No `docs-site` change                                                     |

Archive builds refuse to replace an existing version. The root and `/next/`
builds preserve every archived directory. The global `versions.json` includes
each version's page inventory, so the version switcher can use current
navigation metadata without rebuilding old snapshots.

The build driver can apply those same updates to a local tree. `--output`
selects the persistent publish directory:

```sh
node scripts/docs-build.mjs --channel next --output .publish
node scripts/docs-build.mjs --channel release --version v0.15.0 --output .publish
```

Exercise the assembled site's runnable examples, symbol navigation, search,
and cross-version library imports with:

```sh
SITE_DIST=.publish bun run site:live-examples
```

On Cloudflare's master build, `scripts/site-build.mjs` clones `docs-site` and
copies its files into the configured assets directory. The workflow's deploy
job calls the existing Cloudflare deploy hook after publishing the branch. If
publishing succeeds but the hook fails, rerun the failed deploy job to retry
the hook without rebuilding or republishing the tree.

## Bootstrap and repair

When `docs-site` does not exist, a master deployment bootstraps it with the current
tree and every stable release found in the npm package catalog. Release and repair
runs require that bootstrap first. This is the
only routine that builds the full history. The resulting branch contains a
single generated snapshot commit rather than accumulated build history.

For a manual bootstrap, dispatch `Deploy Site` from `master` with `channel=bootstrap`. The
equivalent local assembler command is:

```sh
node scripts/docs-build.mjs --channel bootstrap --output .publish
```

If the branch already exists, a bootstrap dispatch stops with an error. To
rebuild one archive, dispatch the workflow with `channel=repair` and
`version=vX.Y.Z`. The workflow restores `docs-site`, fetches the selected tag
source and replaces only that archive. The local command, when `.publish`
already contains the generated tree, is:

```sh
node scripts/docs-build.mjs --channel repair --version v0.14.0 --output .publish
```

Repair is explicit because archive URLs are immutable during ordinary
publishing. The workflow dispatch also supports `channel=next`; stable
releases normally invoke the same workflow through `Publish` after the
release has been created.

Do not edit `docs-site` directly. Change the source documentation, then use the
workflow so the generated tree and Cloudflare deployment stay in step.
