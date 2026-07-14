# `@micro509/deno-import-map`

Generate an explicit [Deno import map] from a `package.json`-style `imports`
map.

Node understands subpath patterns such as `#lib/*` → `./src/lib/*.ts`.
Some Deno consumers, notably `deno doc`, need those patterns expanded into
one entry per source file. This package performs that expansion and writes a
deterministically sorted import-map file.

This is a private workspace package, not a published registry package. The
examples assume the consuming package declares it as a workspace dependency:

```json
{
  "devDependencies": {
    "@micro509/deno-import-map": "workspace:*"
  }
}
```

[Deno import map]: https://docs.deno.com/runtime/fundamentals/modules/#differentiating-between-imports-or-importmap-in-deno.json-and---import-map-option

## What it generates

Given this manifest:

```json
{
  "imports": {
    "#config": "./src/config.ts",
    "#lib/*": "./src/lib/*.ts"
  }
}
```

and these files:

```text
src/
├── config.ts
└── lib/
    ├── bytes.ts
    └── codecs/
        └── hex.ts
```

the generated map is:

```json
{
  "imports": {
    "#config": "./src/config.ts",
    "#lib/bytes": "./src/lib/bytes.ts",
    "#lib/bytes.ts": "./src/lib/bytes.ts",
    "#lib/codecs/hex": "./src/lib/codecs/hex.ts",
    "#lib/codecs/hex.ts": "./src/lib/codecs/hex.ts"
  }
}
```

Exact entries are copied as written unless they collide with an expanded
pattern entry. Each pattern match produces specifiers with and without the
target extension, so both `#lib/bytes` and `#lib/bytes.ts` resolve.

## API

The package exports one synchronous function and its options type:

```ts
import path from 'node:path';
import { writeDenoImportMap } from '@micro509/deno-import-map';

const importMap = writeDenoImportMap({
  root: path.resolve(import.meta.dirname, '..'),
  out: 'deno.import_map.json',
  additionalImports: {
    'bun:test': './node_modules/bun-types/test.d.ts',
  },
});

console.log(importMap); // absolute because root is absolute
```

`writeDenoImportMap` overwrites the output file and returns
`path.join(root, out)`. Pass an absolute `root` when the returned path must be
absolute.

| Option              | Meaning                                                             |
| ------------------- | ------------------------------------------------------------------- |
| `root`              | Base directory for manifest, source targets, and output paths.      |
| `manifest`          | Optional manifest path relative to `root`. Default: `package.json`. |
| `out`               | Output path relative to `root`.                                     |
| `additionalImports` | Extra import-map entries. These override generated keys.            |

Missing output directories are created recursively. When the manifest uses
relative targets, write the import map beside the manifest: the function copies
target values without rebasing them relative to a nested output directory.
Additional imports are merged after manifest expansion and participate in the
same sorted output.

### A generator script

The package is a library and does not install a command-line executable. A
small project-local wrapper makes generation available from a shell, package
script, editor task, or CI job:

```ts
#!/usr/bin/env bun
import path from 'node:path';
import { writeDenoImportMap } from '@micro509/deno-import-map';

const target = writeDenoImportMap({
  root: path.resolve(import.meta.dirname, '..'),
  out: 'deno.import_map.json',
});

Bun.stderr.write(`Wrote ${target}\n`);
```

```bash
bun scripts/generate-deno-import-map.ts
```

The module uses Node filesystem APIs and can also run through another
TypeScript toolchain that supports the package's `.ts` workspace export.

### Generate maps for other source trees

All paths are supplied by the caller, so a build tool can generate a map for
each checkout, extracted archive, worktree, or release tag it processes:

```ts
import { writeDenoImportMap } from '@micro509/deno-import-map';

export function prepareSourceTree(root: string): string {
  return writeDenoImportMap({
    root,
    out: 'deno.import_map.json',
  });
}
```

## Use the generated map

The generated JSON is a standard external import map. It can be supplied to
the Deno CLI, selected from `deno.json`, passed to APIs that embed Deno tooling,
or configured in an editor's Deno language server.

### Deno CLI

Pass the file to any Deno subcommand that accepts `--import-map`. For example:

```bash
deno doc --import-map=deno.import_map.json src/index.ts
deno doc --import-map=deno.import_map.json --json src/index.ts
deno doc --import-map=deno.import_map.json --html --output=docs/api src/index.ts

deno check --import-map=deno.import_map.json src/
deno run --import-map=deno.import_map.json src/main.ts
deno test --import-map=deno.import_map.json
deno bench --import-map=deno.import_map.json
deno compile --import-map=deno.import_map.json src/main.ts
```

The map can also be passed when spawning Deno from Node or Bun. Using the
absolute path returned by `writeDenoImportMap` avoids working-directory
ambiguity:

```ts
import { execFileSync } from 'node:child_process';
import { writeDenoImportMap } from '@micro509/deno-import-map';

const root = '/path/to/source-tree';
const importMap = writeDenoImportMap({
  root,
  out: 'deno.import_map.json',
});

const nodes = execFileSync('deno', ['doc', '--import-map', importMap, '--json', 'src/index.ts'], {
  cwd: root,
  encoding: 'utf8',
});
```

### `deno.json`

Reference the generated file once in `deno.json` or `deno.jsonc` instead of
repeating `--import-map` on each command:

```json
{
  "importMap": "./deno.import_map.json"
}
```

Deno then applies it when that configuration file is active. `importMap` is an
alternative to defining `imports` and `scopes` directly in the same
`deno.json`.

### Zed

Enable the Deno language server and give it the generated map in
`.zed/settings.json`:

```json
{
  "languages": {
    "TypeScript": {
      "language_servers": ["deno", "!typescript-language-server", "!vtsls"]
    }
  },
  "lsp": {
    "deno": {
      "settings": {
        "deno": {
          "enable": true,
          "importMap": "./deno.import_map.json"
        }
      }
    }
  }
}
```

In a mixed-runtime repository, restrict Deno to the relevant directories:

```json
{
  "lsp": {
    "deno": {
      "settings": {
        "deno": {
          "enable": true,
          "enablePaths": ["./src", "./scripts"],
          "importMap": "./deno.import_map.json"
        }
      }
    }
  }
}
```

The same `deno.importMap` workspace setting can be passed by other LSP clients
that expose Deno language-server initialization options.

### `@deno/doc`

The `@deno/doc` API accepts the import map as a file URL:

```ts
import { doc } from 'jsr:@deno/doc@0.199.0';

const entries = [new URL('./src/index.ts', import.meta.url).href];
const importMap = new URL('./deno.import_map.json', import.meta.url).href;
const nodes = await doc(entries, {
  importMap,
  printImportMapDiagnostics: false,
});
```

## Keep it current

Pattern entries are expanded from the files present when the function runs.
Regenerate the map after adding, moving, or removing matching files, and after
changing the manifest's `imports` field.

Common places to run the wrapper are:

- an install or prepare lifecycle;
- before documentation, type-check, test, or build commands that consume it;
- an editor task after changing the source tree;
- a CI step before Deno tooling runs.

Generated maps can be committed when consumers need them immediately after
checkout, or ignored when installation and CI always regenerate them.

## Scope and constraints

- Only the manifest's top-level `imports` field is read.
- Import targets must be strings. Conditional target objects are not supported.
- Expandable pattern targets must point to local files beneath `root`; package
  names and URLs are not scanned.
- Pattern keys and targets must both contain `*`.
- Suffixless keys such as `#lib/*` are the supported form for generating the
  with-extension alias. A key suffix such as `#lib/*.js` is also appended to
  the full matched filename and can produce an unwanted key such as
  `#lib/file.ts.js`.
- Target directories are scanned recursively.
- Files are included only when their relative path matches the target suffix.
- Missing pattern directories produce no entries.
- If exact and expanded entries produce the same key, the later manifest entry
  wins. Avoid overlapping keys when declaration order should not affect
  resolution.
- Relative target values are not rebased. Keep the generated map beside the
  manifest unless its targets are already valid relative to another location.
- Missing output directories are created recursively.
- Existing output files are replaced synchronously.
- Output entries are sorted for stable diffs.

[Deno's import-map documentation] describes the behavior of the generated
file. [Deno's LSP settings] documents the `deno.importMap` and
`deno.enablePaths` options used by editor integrations.

[Deno's import-map documentation]: https://docs.deno.com/runtime/fundamentals/modules/#differentiating-between-imports-or-importmap-in-deno.json-and---import-map-option
[Deno's LSP settings]: https://docs.deno.com/runtime/reference/lsp_integration/#settings
